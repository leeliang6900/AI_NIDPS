import os
import time
import math
import json
import csv
import ctypes
import logging
import struct
import socket
import ipaddress
import threading
import uuid
import re
import sys
from dataclasses import dataclass
from collections import defaultdict, deque
from typing import Dict, Tuple, List, Optional
from datetime import datetime, timedelta

import joblib
import pandas as pd
import paramiko

from arp_resolver import ArpResolver
from file_lock_utils import exclusive_lock, resilient_write_text
from online_models import (
    ATTACK_ONLINE_MODEL_PATH,
    MALWARE_ONLINE_MODEL_PATH,
    MissingRiverDependency,
    load_online_models,
    predict_online_scores,
)
from online_schema import OnlineSample
from online_control import load_control_state
from online_store import OnlineSampleStore
from router_ssh import build_router_ssh_client

logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
RUNTIME_METRICS_JSON = os.path.join(LOGS_DIR, "runtime_metrics.json")
RUNTIME_METRICS_HISTORY_JSON = os.path.join(LOGS_DIR, "runtime_metrics_history.jsonl")
RUNTIME_METRICS_RETENTION_SEC = 30 * 60
RUNTIME_METRICS_LOCK = os.path.join(LOGS_DIR, "runtime_metrics.json.lock")
RUNTIME_METRICS_HISTORY_LOCK = os.path.join(LOGS_DIR, "runtime_metrics_history.jsonl.lock")

# ===================== OUTPUT =====================
PRINT_START_BANNER = True
PRINT_BLOCK_EVENTS = True
PRINT_UNBLOCK_EVENTS = True
PRINT_NONBLOCKED_ALERTS = True
PRINT_HEARTBEAT = False
PRINT_ALERT_DETAILS = True
PRINT_PRETTY_BLOCK = True
AUTO_GENERATE_REPORT_ON_EXIT = True


# ===================== CONFIG =====================
MODEL_ATTACK_PATH = os.path.join(MODELS_DIR, "model_attack.joblib")   # DO NOT TOUCH
MODEL_MALWARE_PATH = os.path.join(MODELS_DIR, "model_malware.joblib") # re-trained

WINDOW_SEC = 30

ROUTER_IP = os.getenv("NIDPS_ROUTER_IP", "192.168.88.1")
ROUTER_USER = os.getenv("NIDPS_ROUTER_USER", "")
ROUTER_PASS = os.getenv("NIDPS_ROUTER_PASS", "")

if not ROUTER_USER or not ROUTER_PASS:
    raise RuntimeError(
        "Missing router credentials. Please set NIDPS_ROUTER_USER and NIDPS_ROUTER_PASS environment variables."
    )

WINDOWS_IP = "192.168.88.254"
SSH_TRUSTED_SOURCE_IPS = {
    ip.strip()
    for ip in os.getenv("NIDPS_SSH_TRUSTED_SOURCES", WINDOWS_IP).split(",")
    if ip.strip()
}

DEFAULT_MONITORED_CIDRS = ["192.168.88.0/24", "192.168.89.0/24"]
MONITORED_CIDRS = [c.strip() for c in os.getenv("NIDPS_MONITORED_CIDRS", ",".join(DEFAULT_MONITORED_CIDRS)).split(",") if c.strip()]
MONITORED_NETWORKS = [ipaddress.ip_network(c, strict=False) for c in MONITORED_CIDRS]
ROUTER_INTERFACE_IPS = {ip.strip() for ip in os.getenv("NIDPS_ROUTER_INTERFACE_IPS", "").split(",") if ip.strip()}
if not ROUTER_INTERFACE_IPS:
    ROUTER_INTERFACE_IPS = {ROUTER_IP}
    for net in MONITORED_NETWORKS:
        if isinstance(net, ipaddress.IPv4Network) and net.num_addresses >= 4:
            ROUTER_INTERFACE_IPS.add(str(ipaddress.ip_address(int(net.network_address) + 1)))
PROTECTED_TARGETS = set(ROUTER_INTERFACE_IPS) | {WINDOWS_IP}
NEVER_BLOCK_IPS = set(ROUTER_INTERFACE_IPS) | {WINDOWS_IP}
IGNORE_UNMONITORED_PRIVATE_DST = True
IGNORE_BROADCAST_AND_MULTICAST = True

NETFLOW_LISTEN_IP = "0.0.0.0"
NETFLOW_PORT = 2055

BLOCK_LIST = "blocked"
BLOCK_TIMEOUT = ""  # empty means permanent block
HONEYPOT_BRUTEFORCE_LIST = os.getenv("NIDPS_HONEYPOT_BRUTEFORCE_LIST", "honeypot_bruteforce")
HONEYPOT_REDIRECT_RULES = {"SSH_BRUTE_FORCE"}
HONEYPOT_TARGET_IPS = {ip.strip() for ip in os.getenv("NIDPS_HONEYPOT_TARGET_IPS", "192.168.88.100").split(",") if ip.strip()}

# After an unblock, clear the stale runtime state once and keep a short
# marker so the reset happens only once for the same source.
UNBLOCK_COOLDOWN_SEC = 3
recent_unblocked: Dict[str, float] = {}
recent_unblocked_needs_reset: Dict[str, bool] = {}

ONLY_PROTECTED_DST = False
FILTER_EXPORT_FLOW = True

# ===================== Victim-safe blocking =====================
VICTIM_SAFE_MODE = True
REVERSE_SUPPRESS_SEC = 90
INITIATOR_TTL_SEC = 300
CONNTRACK_LOOKUP_TTL_SEC = 5.0
SERVICE_PORT_MAX = 1024
# Cover both Windows (49152+) and common Linux ephemeral ports (32768+).
DYNAMIC_PORT_MIN = 32768
KNOWN_SERVER_PORTS = {21, 22, 23, 53, 80, 88, 123, 135, 139, 389, 443, 445, 636, 993, 995, 1433, 3306, 3389, 5432, 5985, 5986, 8080, 8291, 9001, 3333, 4444, 5555, 14444}

ATTACK_RULES = {
    "ICMP_FLOOD", "HTTP_FLOOD", "TCP_FLOOD", "UDP_FLOOD", "CONN_FLOOD",
    "PORT_SCAN",
    "SSH_BRUTE_FORCE", "FTP_BRUTE_FORCE", "TELNET_BRUTE_FORCE", "RDP_BRUTE_FORCE", "WINBOX_BRUTE_FORCE",
    "SUSP_HIGH_PORT",
}
# Malware 缂備緡鍋傜槐顔炬娴兼潙绀傚ù锝囩摂閸?attack 闂佸憡鐟ラ崐椋庣箔瀹€鍕櫖闁割偅绮庣粙鎴濃槈閺傛鍎忓褏濮烽幏鐘靛鐎ｎ剛鐣?malware 婵炴垶姊婚崰鎰ｉ崫銉х＞闁瑰濮烽幑鏇㈡煛閳ь剛鎷犻幓鎺撶槚闂佹眹鍔岀€氼亞绮╅幘顔界劸闁靛鍎遍悗濠氭煥?
MAL_BEHAVIORS = {"C2_BEACON", "DNS_TUNNEL", "DATA_EXFIL", "CRYPTO_MINER", "C2_BACKDOOR", "RANSOMWARE_PRECHECK"}

BRUTE_RULES = {"SSH_BRUTE_FORCE", "FTP_BRUTE_FORCE", "TELNET_BRUTE_FORCE", "RDP_BRUTE_FORCE", "WINBOX_BRUTE_FORCE"}
OBSERVED_RULES = {"OBS_PING", "OBS_SSH", "OBS_FTP", "OBS_TELNET", "OBS_RDP", "OBS_WINBOX", "OBS_NMAP_SCAN", "OBS_UNKNOWN"}
DELAYED_LOW_VALUE_OBSERVED_RULES = {"OBS_PING", "OBS_SSH", "OBS_FTP", "OBS_TELNET", "OBS_RDP", "OBS_WINBOX"}
OBSERVE_UNKNOWN_TRAFFIC = True
BACKGROUND_INFRA_PORTS = {53, 67, 68, 123}
BACKGROUND_PUBLIC_SERVICE_PORTS = {80, 443}
ROUTER_BACKGROUND_SERVICE_PORTS = BACKGROUND_INFRA_PORTS | BACKGROUND_PUBLIC_SERVICE_PORTS | {8291}
BACKGROUND_INFRA_MAX_FLOWS = 30
BACKGROUND_INFRA_MAX_UNIQ_DPORTS = 4
BACKGROUND_PUBLIC_MAX_FLOWS = 120
BACKGROUND_PUBLIC_MAX_UNIQ_DPORTS = 6
SILENT_BASELINE_MAX_ATTACK_SCORE = 0.18
SILENT_BASELINE_MAX_MALWARE_SCORE = 0.18
QUIET_OBSERVED_BACKGROUND_MAX_ATTACK_SCORE = 0.55
QUIET_OBSERVED_BACKGROUND_MAX_MALWARE_SCORE = 0.55
QUIET_PUBLIC_WEB_MAX_FLOWS = 8
QUIET_PUBLIC_WEB_MAX_PKTS = 128
QUIET_PUBLIC_WEB_MAX_SBYTES = 16384
UNKNOWN_OBSERVED_MIN_ATTACK_SCORE = 0.70
UNKNOWN_OBSERVED_MIN_MALWARE_SCORE = 0.65
UNKNOWN_OBSERVED_SUSPICIOUS_SCORE = 0.55
UNKNOWN_OBSERVED_STRONG_SCORE = 0.90
UNKNOWN_OBSERVED_MIN_FLOWS = 12
UNKNOWN_OBSERVED_MIN_UNIQ_DPORTS = 8
UNKNOWN_OBSERVED_MIN_SBYTES = 16384
ROUTER_BRUTE_CONFIRM_PORTS = {22: "ssh", 21: "ftp", 23: "telnet", 8291: "winbox"}
ROUTER_BRUTE_REQUIRE_CONFIRM = False
ROUTER_BRUTE_CONFIRM_MIN_FAILS = 8
ROUTER_BRUTE_CONFIRM_CACHE_TTL_SEC = 1.0
ROUTER_BRUTE_LOG_LOOKBACK = 50
ROUTER_BRUTE_LOG_WINDOW_SEC = 30
ROUTER_SSH_HONEYPOT_LOG_WATCHER_POLL_SEC = 0.25

# ===== AI thresholds =====
THR_ATTACK = {
    # Flood families usually calibrate near 1.0 on real attacks, so low-0.7s keeps noise out.
    "ICMP_FLOOD": 0.55,
    "HTTP_FLOOD": 0.72,
    "TCP_FLOOD": 0.72,
    "UDP_FLOOD": 0.72,
    "CONN_FLOOD": 0.74,

    # Port scan is strongly separated already, so 0.60 gives a safe margin.
    "PORT_SCAN": 0.60,

    # Brute-force windows are much more compressed in your current model/logs.
    # Keep the whole brute family aligned so SSH/FTP/TELNET/RDP/WINBOX behave similarly.
    "SSH_BRUTE_FORCE": 0.50,
    "FTP_BRUTE_FORCE": 0.50,
    "TELNET_BRUTE_FORCE": 0.50,
    "RDP_BRUTE_FORCE": 0.50,
    "WINBOX_BRUTE_FORCE": 0.50,

    # Behavioral attack rules should stay a bit stricter.
    "DNS_TUNNEL": 0.70,
    "DATA_EXFIL": 0.72,
    "SUSP_HIGH_PORT": 0.70,
    "C2_BEACON": 0.75,

    # MAL_BEHAVIORS still block on THR_MAL below; these are kept for display consistency.
    "CRYPTO_MINER": 0.70,
    "C2_BACKDOOR": 0.70,
    "RANSOMWARE_PRECHECK": 0.70,
}
THR_MAL = {
    # Malware windows in your logs already cluster high after calibration, so 0.60-0.65 is a stable band.
    "C2_BEACON": 0.60,
    "DNS_TUNNEL": 0.65,
    "DATA_EXFIL": 0.65,

    "CRYPTO_MINER": 0.60,
    "C2_BACKDOOR": 0.60,
    "RANSOMWARE_PRECHECK": 0.60,
}
THR_ATTACK_DEFAULT = 0.70
THR_MAL_DEFAULT = 0.65

RANSOMWARE_PRECHECK_RAW_PASS_MAL = 0.230
BLOCK_VERIFY_RETRIES = 8
BLOCK_VERIFY_RETRY_SEC = 0.5
DROP_RULE_VERIFY_RETRIES = 4
DROP_RULE_VERIFY_RETRY_SEC = 0.5
BLOCK_RULE_READY_RETRIES = 2
SSH_RECONNECT_ATTEMPTS = 2
BLOCK_LIST_CACHE_TTL_SEC = 1.0

# ===================== Anti-flapping =====================
REQUIRED_CONSECUTIVE_HITS = {"SSH_BRUTE_FORCE": 1}
REQUIRED_CONSECUTIVE_HITS_DEFAULT = 1

# ===================== RULE HEURISTICS =====================
BRUTE_PORTS = {
    22: "SSH_BRUTE_FORCE",
    21: "FTP_BRUTE_FORCE",
    23: "TELNET_BRUTE_FORCE",
    3389: "RDP_BRUTE_FORCE",
    8291: "WINBOX_BRUTE_FORCE",
}
# Keep brute-force detection on the same 30s AI window, but allow it to fire
# within a single window for slower tools such as Hydra instead of waiting for
# 20+ attempts to accumulate.
BRUTE_GATE_MIN_FLOWS = 5
BRUTE_MIN_FLOWS = 5
BRUTE_MIN_PKTS = 24
BRUTE_MAX_UNIQ_DPORTS = 3
BRUTE_MAX_SBYTES = 800_000
SSH_HONEYPOT_FASTPATH_RECHECK_SEC = 0.25
SSH_HONEYPOT_FASTPATH_MIN_FLOWS = 2
SSH_HONEYPOT_FASTPATH_MIN_PKTS = 8
# For SSH->honeypot we still want to avoid trapping a legitimate admin who
# mistypes a password a couple of times. Keep log-first redirect fast, but do
# not fire on 1-3 isolated failures.
SSH_HONEYPOT_FASTPATH_MIN_ROUTER_FAILS = 2
SSH_HONEYPOT_REDIRECT_COOLDOWN_SEC = 45.0
SSH_HONEYPOT_EVENT_DEDUP_SEC = 10.0
SSH_ROUTER_LOG_MAC_RETRY_DELAY_SEC = 0.12

MIN_FLOWS_TO_CONSIDER = 15
MIN_PKTS_TO_CONSIDER = 60

PORT_SCAN_UNIQ_DPORTS = 25

ICMP_FLOOD_PKTS = 300

HTTP_FLOOD_FLOWS = 120
TCP_FLOOD_FLOWS = 160
UDP_FLOOD_FLOWS = 180

CONN_FLOOD_FLOWS = 250
CONN_FLOOD_PKTS = 900

BEACON_MIN_WINDOWS = 4
BEACON_MAX_FLOWS_PER_WIN = 10
BEACON_MAX_SBYTES_PER_WIN = 10_000
BEACON_MAX_UNIQ_DPORTS = 2

DNS_TUNNEL_DPORT = 53
DNS_TUNNEL_FLOWS = 60
DNS_TUNNEL_SBYTES = 120_000

DATA_EXFIL_SBYTES = 900_000
DATA_EXFIL_DBYTES_MAX = 50_000

HIGH_PORT_MIN = 1024
SUSP_HIGH_PORT_FLOWS = 250

OBS_PING_MAX_PKTS = 120
OBS_PING_MAX_FLOWS = 8
OBS_BRUTE_MAX_FLOWS = 4
OBS_BRUTE_MAX_UNIQ_DPORTS = 2
OBS_BRUTE_MAX_SBYTES = 400_000
OBS_BRUTE_SUPPRESS_SEC = WINDOW_SEC + 5
LOW_VALUE_OBSERVED_SUPPRESS_SEC = WINDOW_SEC + 5
OBS_NMAP_MIN_UNIQ_DPORTS = 3
OBS_NMAP_MIN_FLOWS = 3
OBS_NMAP_MAX_UNIQ_DPORTS = PORT_SCAN_UNIQ_DPORTS - 1
OBS_NMAP_MAX_TOP_RATIO = 0.70
OBS_NMAP_MAX_SBYTES = 300_000

OBSERVED_BRUTE_RULES = {
    22: "OBS_SSH",
    21: "OBS_FTP",
    23: "OBS_TELNET",
    3389: "OBS_RDP",
    8291: "OBS_WINBOX",
}
OBSERVED_BRUTE_RULE_NAMES = set(OBSERVED_BRUTE_RULES.values())

# ===================== Malware-ish ports (Fix overlap) =====================
# 闂佺绻戞繛濠囧极椤撶喓鈹嶆い鏃傗拡濡插鏌ㄥ☉娆戠叝缂佹顦遍幉鐗堢瑹閳ь剟宕抽幖浣哥煑闁绘瑥鎳愮粈澶愭煕濮樺墽鐣遍柛?backdoor 闂?4444 婵炴潙鍚嬫穱娲綖?miner 闂佺缈伴崹濂告憘?
MINER_PORTS = {3333, 14444, 5555}       # miner 闁汇埄鍨遍悺鏇綖?
BACKDOOR_PORTS = {4444, 1337, 9001}     # backdoor 闁汇埄鍨遍悺鏇綖?

MINER_MIN_FLOWS = 25
MINER_MIN_PKTS = 120

BACKDOOR_MIN_FLOWS = 12
BACKDOOR_MAX_SBYTES = 200_000
BACKDOOR_MAX_UNIQ_DPORTS = 2

# ===================== BLOCKING / MUTE =====================
MUTE_UNTIL_UNBLOCK = True
CHECK_UNBLOCK_EVERY_SEC = 1

CSV_LOG = os.path.join(LOGS_DIR, "nidps_events.csv")
JSONL_LOG = os.path.join(LOGS_DIR, "nidps_events.jsonl")
HONEYPOT_SAMPLES_LOG = os.path.join(LOGS_DIR, "honeypot_samples.jsonl")
HONEYPOT_SAMPLES_LOCK = os.path.join(LOGS_DIR, "honeypot_samples.jsonl.lock")
CSV_COLUMNS = [
    "event_id", "ts", "category", "rule", "src", "src_mac", "dst", "dst_mac",
    "flows", "spkts", "dpkts", "sbytes", "dbytes", "uniq_dports", "proto", "top_dport",
    "atk", "mal", "shadow_atk", "shadow_mal", "atk_thr", "mal_thr", "decision"
]
ONLINE_STORE = OnlineSampleStore()

_block_list_cache: Dict[str, Tuple[float, bool]] = {}
_block_list_cache_lock = threading.Lock()
_router_brute_confirm_cache: Dict[Tuple[str, str], Tuple[float, int]] = {}
_router_brute_confirm_cache_lock = threading.Lock()
_recent_honeypot_redirects: Dict[str, float] = {}
_recent_honeypot_redirects_lock = threading.Lock()
_recent_ssh_honeypot_events: Dict[Tuple[str, str], float] = {}
_recent_ssh_honeypot_events_lock = threading.Lock()

# ===================== MAC / ARP =====================
ARP_CACHE_TTL_SEC = 180
MAC_RESOLVE_MODE = "table"  # "table" or "single"
ARP_REFRESH_SEC = 10
ARP_REFRESH_ON_MISS_MIN_SEC = 3
ARP_NEGATIVE_CACHE_TTL_SEC = 1
ARP_DEBUG = False



# ===================== NetFlow v9 =====================
@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    bytes: int
    packets: int
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None


class NetFlowV9Parser:
    def __init__(self):
        self.templates = {}  # template_id -> list of (field_type, field_len)

    def parse_packet(self, data: bytes) -> List[Flow]:
        if len(data) < 20:
            return []
        version, _count = struct.unpack("!HH", data[:4])
        if version != 9:
            return []
        offset = 20
        flows: List[Flow] = []

        while offset + 4 <= len(data):
            flowset_id, length = struct.unpack("!HH", data[offset:offset + 4])
            if length < 4 or offset + length > len(data):
                break
            fs = data[offset:offset + length]
            if flowset_id == 0:
                self._parse_templates(fs)
            elif flowset_id == 1:
                pass
            elif flowset_id >= 256:
                flows.extend(self._parse_data_flowset(flowset_id, fs))
            offset += length

        return flows

    def _parse_templates(self, fs: bytes) -> None:
        offset = 4
        while offset + 4 <= len(fs):
            template_id, field_count = struct.unpack("!HH", fs[offset:offset + 4])
            offset += 4
            fields = []
            for _ in range(field_count):
                if offset + 4 > len(fs):
                    break
                f_type, f_len = struct.unpack("!HH", fs[offset:offset + 4])
                offset += 4
                fields.append((f_type, f_len))
            if fields:
                self.templates[template_id] = fields

    def _parse_data_flowset(self, template_id: int, fs: bytes) -> List[Flow]:
        fields = self.templates.get(template_id)
        if not fields:
            return []
        rec_len = sum(f_len for _, f_len in fields)
        if rec_len <= 0:
            return []
        offset = 4
        out: List[Flow] = []

        while offset + rec_len <= len(fs):
            rec = fs[offset:offset + rec_len]
            offset += rec_len
            d = self._decode_record(fields, rec)
            if not d:
                continue
            f = Flow(
                src_ip=d.get("src_ip", ""),
                dst_ip=d.get("dst_ip", ""),
                src_port=int(d.get("src_port", 0)),
                dst_port=int(d.get("dst_port", 0)),
                proto=int(d.get("proto", 0)),
                bytes=int(d.get("bytes", 0)),
                packets=int(d.get("packets", 0)),
                icmp_type=d.get("icmp_type"),
                icmp_code=d.get("icmp_code"),
            )
            if f.src_ip and f.dst_ip:
                out.append(f)
        return out

    def _decode_record(self, fields, rec: bytes) -> dict:
        offset = 0
        d = {}
        for f_type, f_len in fields:
            val = rec[offset:offset + f_len]
            offset += f_len

            if f_type == 8 and f_len == 4:
                d["src_ip"] = socket.inet_ntoa(val)
            elif f_type == 12 and f_len == 4:
                d["dst_ip"] = socket.inet_ntoa(val)
            elif f_type == 7 and f_len == 2:
                d["src_port"] = struct.unpack("!H", val)[0]
            elif f_type == 11 and f_len == 2:
                d["dst_port"] = struct.unpack("!H", val)[0]
            elif f_type == 32 and f_len in (1, 2, 4):
                raw_icmp = int.from_bytes(val, "big")
                if f_len == 1:
                    d["icmp_type"] = raw_icmp & 0xFF
                    d["icmp_code"] = 0
                else:
                    d["icmp_type"] = (raw_icmp >> 8) & 0xFF
                    d["icmp_code"] = raw_icmp & 0xFF
            elif f_type == 4 and f_len == 1:
                d["proto"] = val[0]
            elif f_type == 1 and f_len in (4, 8):
                d["bytes"] = int.from_bytes(val, "big")
            elif f_type == 2 and f_len in (4, 8):
                d["packets"] = int.from_bytes(val, "big")
        return d


# ===================== MikroTik SSH =====================
class MikroTikSSH:
    def __init__(self, host: str, user: str, password: str):
        self.host = host
        self.user = user
        self.password = password
        self._client: Optional[paramiko.SSHClient] = None
        self._lock = threading.Lock()

    def _open_client(self, timeout: int) -> paramiko.SSHClient:
        client = build_router_ssh_client()
        client.connect(
            hostname=self.host,
            username=self.user,
            password=self.password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        try:
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(15)
        except Exception:
            pass
        return client

    def _close_unlocked(self) -> None:
        client, self._client = self._client, None
        if client is None:
            return
        try:
            client.close()
        except KeyboardInterrupt:
            pass
        except Exception:
            pass

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()

    def _ensure_connected(self, timeout: int) -> paramiko.SSHClient:
        client = self._client
        if client is not None:
            try:
                transport = client.get_transport()
            except Exception:
                transport = None
            if transport is not None and transport.is_active():
                return client
            self._close_unlocked()
        self._client = self._open_client(timeout)
        return self._client

    def run(self, command: str, timeout: int = 12) -> str:
        with self._lock:
            last_exc: Optional[Exception] = None
            for _ in range(SSH_RECONNECT_ATTEMPTS):
                try:
                    client = self._ensure_connected(timeout)
                    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
                    out = stdout.read().decode("utf-8", errors="ignore")
                    err = stderr.read().decode("utf-8", errors="ignore")
                    return out + ("\n" + err if err else "")
                except Exception as exc:
                    last_exc = exc
                    self._close_unlocked()
            raise RuntimeError(f"SSH command failed: {last_exc}")


def ensure_drop_rules(ssh: MikroTikSSH) -> bool:
    rules = [
        (
            "AI raw drop blocked (prerouting)",
            f'/ip firewall raw add chain=prerouting src-address-list={BLOCK_LIST} action=drop place-before=0 comment="AI raw drop blocked (prerouting)"',
        ),
        (
            "AI raw drop blocked return (output)",
            f'/ip firewall raw add chain=output dst-address-list={BLOCK_LIST} action=drop place-before=0 comment="AI raw drop blocked return (output)"',
        ),
        (
            "AI drop blocked (input)",
            f'/ip firewall filter add chain=input src-address-list={BLOCK_LIST} action=drop place-before=0 comment="AI drop blocked (input)"',
        ),
        (
            "AI drop blocked (forward)",
            f'/ip firewall filter add chain=forward src-address-list={BLOCK_LIST} action=drop place-before=0 comment="AI drop blocked (forward)"',
        ),
        (
            "AI drop blocked return (forward)",
            f'/ip firewall filter add chain=forward dst-address-list={BLOCK_LIST} action=drop place-before=0 comment="AI drop blocked return (forward)"',
        ),
        (
            "AI drop blocked return (output)",
            f'/ip firewall filter add chain=output dst-address-list={BLOCK_LIST} action=drop place-before=0 comment="AI drop blocked return (output)"',
        ),
    ]
    if _verify_drop_rules_with_retry(ssh):
        return True

    for marker, cmd in rules:
        table = "raw" if "raw" in marker.lower() else "filter"
        try:
            ssh.run(f'/ip firewall {table} remove [find where comment="{marker}"]')
        except Exception:
            pass
        try:
            ssh.run(cmd)
        except Exception:
            pass

    return _verify_drop_rules_with_retry(ssh)


def _parse_first_int(text: str) -> Optional[int]:
    # router sometimes returns extra spaces/newlines; be robust
    s = (text or "").strip()
    if not s:
        return None
    digits = []
    for ch in s:
        if ch.isdigit():
            digits.append(ch)
        elif digits:
            break
    if not digits:
        return None
    try:
        return int("".join(digits))
    except Exception:
        return None


def _router_output_has_error(text: str) -> bool:
    low = (text or "").lower()
    return ("failure" in low) or ("error" in low) or ("invalid" in low) or ("denied" in low)


def _rule_exists_by_comment(ssh: MikroTikSSH, comment: str) -> Tuple[bool, bool]:
    table = "raw" if "raw" in comment.lower() else "filter"
    out = ssh.run(f'/ip firewall {table} print count-only where comment="{comment}"')
    if _router_output_has_error(out):
        return (False, False)
    n = _parse_first_int(out)
    if n is None:
        return (False, False)
    return (True, n > 0)


def verify_drop_rules(ssh: MikroTikSSH) -> Tuple[bool, bool]:
    required_comments = (
        "AI raw drop blocked (prerouting)",
        "AI raw drop blocked return (output)",
        "AI drop blocked (input)",
        "AI drop blocked (forward)",
        "AI drop blocked return (forward)",
        "AI drop blocked return (output)",
    )
    all_queries_ok = True
    all_found = True
    for comment in required_comments:
        ok, found = _rule_exists_by_comment(ssh, comment)
        if not ok:
            all_queries_ok = False
        if not found:
            all_found = False
    return (all_queries_ok, all_found)


def _verify_drop_rules_with_retry(ssh: MikroTikSSH) -> bool:
    for attempt in range(max(DROP_RULE_VERIFY_RETRIES, 1)):
        try:
            verified_ok, verified_found = verify_drop_rules(ssh)
        except Exception:
            verified_ok, verified_found = (False, False)
        if verified_ok and verified_found:
            return True
        if attempt + 1 < max(DROP_RULE_VERIFY_RETRIES, 1):
            time.sleep(DROP_RULE_VERIFY_RETRY_SEC)
    return False


def _get_block_list_cache(ip: str) -> Optional[bool]:
    now = time.time()
    with _block_list_cache_lock:
        cached = _block_list_cache.get(ip)
        if cached is None:
            return None
        ts, found = cached
        if (now - ts) > BLOCK_LIST_CACHE_TTL_SEC:
            _block_list_cache.pop(ip, None)
            return None
        return found


def _set_block_list_cache(ip: str, found: bool) -> None:
    with _block_list_cache_lock:
        _block_list_cache[ip] = (time.time(), bool(found))


def _invalidate_block_list_cache(ip: str) -> None:
    with _block_list_cache_lock:
        _block_list_cache.pop(ip, None)


def _get_router_brute_confirm_cache(src_ip: str, service: str) -> Optional[int]:
    now = time.time()
    with _router_brute_confirm_cache_lock:
        cached = _router_brute_confirm_cache.get((src_ip, service))
        if cached is None:
            return None
        ts, count = cached
        if (now - ts) > ROUTER_BRUTE_CONFIRM_CACHE_TTL_SEC:
            _router_brute_confirm_cache.pop((src_ip, service), None)
            return None
        return count


def _set_router_brute_confirm_cache(src_ip: str, service: str, count: int) -> None:
    with _router_brute_confirm_cache_lock:
        _router_brute_confirm_cache[(src_ip, service)] = (time.time(), int(count))


def _mark_recent_honeypot_redirect(src_ip: str, now_ts: Optional[float] = None) -> None:
    with _recent_honeypot_redirects_lock:
        _recent_honeypot_redirects[str(src_ip)] = float(now_ts or time.time())


def _clear_recent_honeypot_redirect(src_ip: str) -> None:
    with _recent_honeypot_redirects_lock:
        _recent_honeypot_redirects.pop(str(src_ip), None)


def _was_recently_honeypot_redirected(src_ip: str, now_ts: Optional[float] = None) -> bool:
    now_value = float(now_ts or time.time())
    with _recent_honeypot_redirects_lock:
        ts = _recent_honeypot_redirects.get(str(src_ip))
        if ts is None:
            return False
        if (now_value - ts) > SSH_HONEYPOT_REDIRECT_COOLDOWN_SEC:
            _recent_honeypot_redirects.pop(str(src_ip), None)
            return False
        return True


def _reserve_ssh_honeypot_event(src_ip: str, dst_ip: str, now_ts: Optional[float] = None) -> bool:
    now_value = float(now_ts or time.time())
    key = (str(src_ip), str(dst_ip))
    with _recent_ssh_honeypot_events_lock:
        expired = [
            event_key
            for event_key, event_ts in _recent_ssh_honeypot_events.items()
            if (now_value - event_ts) > SSH_HONEYPOT_EVENT_DEDUP_SEC
        ]
        for event_key in expired:
            _recent_ssh_honeypot_events.pop(event_key, None)
        last_ts = _recent_ssh_honeypot_events.get(key)
        if last_ts is not None and (now_value - last_ts) <= SSH_HONEYPOT_EVENT_DEDUP_SEC:
            return False
        _recent_ssh_honeypot_events[key] = now_value
        return True


def _parse_router_log_timestamp(raw_line: str, now_ts: float) -> Optional[float]:
    line = (raw_line or "").strip()
    if not line:
        return None

    now_dt = datetime.fromtimestamp(now_ts)
    patterns = (
        (r"(?:^|\s)time=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\s|$)", "%Y-%m-%d %H:%M:%S", "absolute"),
        (r"(?:^|\s)time=([A-Za-z]{3}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2})(?:\s|$)", "%b/%d/%Y %H:%M:%S", "absolute"),
        (r"(?:^|\s)time=([A-Za-z]{3}/\d{1,2} \d{2}:\d{2}:\d{2})(?:\s|$)", "%b/%d %H:%M:%S", "month_day"),
        (r"(?:^|\s)time=(\d{2}:\d{2}:\d{2})(?:\s|$)", "%H:%M:%S", "time_only"),
        (r"^\d+\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\s|$)", "%Y-%m-%d %H:%M:%S", "absolute"),
        (r"^\d+\s+([A-Za-z]{3}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2})(?:\s|$)", "%b/%d/%Y %H:%M:%S", "absolute"),
        (r"^\d+\s+([A-Za-z]{3}/\d{1,2} \d{2}:\d{2}:\d{2})(?:\s|$)", "%b/%d %H:%M:%S", "month_day"),
        (r"^\d+\s+(\d{2}:\d{2}:\d{2})(?:\s|$)", "%H:%M:%S", "time_only"),
        (r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\s|$)", "%Y-%m-%d %H:%M:%S", "absolute"),
        (r"^([A-Za-z]{3}/\d{1,2}/\d{4} \d{2}:\d{2}:\d{2})(?:\s|$)", "%b/%d/%Y %H:%M:%S", "absolute"),
        (r"^([A-Za-z]{3}/\d{1,2} \d{2}:\d{2}:\d{2})(?:\s|$)", "%b/%d %H:%M:%S", "month_day"),
        (r"^(\d{2}:\d{2}:\d{2})(?:\s|$)", "%H:%M:%S", "time_only"),
    )

    for pattern, fmt, kind in patterns:
        m = re.search(pattern, line)
        if not m:
            continue
        raw_ts = m.group(1)
        normalized_ts = raw_ts.title() if "%b" in fmt else raw_ts
        try:
            if kind == "month_day":
                parsed = datetime.strptime(f"{now_dt.year} {normalized_ts}", f"%Y {fmt}")
            else:
                parsed = datetime.strptime(normalized_ts, fmt)
        except Exception:
            continue

        if kind == "absolute":
            dt = parsed
        elif kind == "month_day":
            dt = parsed
            if dt > now_dt + timedelta(minutes=1):
                dt = dt.replace(year=now_dt.year - 1)
        else:
            dt = datetime.combine(now_dt.date(), parsed.time())
            if dt > now_dt + timedelta(minutes=1):
                dt = dt - timedelta(days=1)

        return dt.timestamp()

    return None


def _iter_router_log_entries(log_text: str) -> List[str]:
    entries: List[str] = []
    current: List[str] = []

    for raw_line in (log_text or "").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        starts_new_entry = bool(re.match(r"^\d+\s", stripped)) or ("time=" in stripped)
        if starts_new_entry and current:
            entries.append(" ".join(current))
            current = [stripped]
        else:
            current.append(stripped)

    if current:
        entries.append(" ".join(current))

    return entries


def _count_router_login_failures(log_text: str, src_ip: str, service: str, now_ts: float) -> int:
    if not log_text:
        return 0

    service_tokens = {service.lower()}
    if service == "ssh":
        service_tokens.update({"ssh", "password"})
    elif service == "ftp":
        service_tokens.update({"ftp"})
    elif service == "telnet":
        service_tokens.update({"telnet"})
    elif service == "winbox":
        service_tokens.update({"winbox"})

    failure_tokens = {
        "failure",
        "failed",
        "invalid",
        "denied",
        "authentication failed",
        "login failure",
    }

    count = 0
    window_start = now_ts - ROUTER_BRUTE_LOG_WINDOW_SEC
    candidate_lines = _iter_router_log_entries(log_text)[-ROUTER_BRUTE_LOG_LOOKBACK:]
    matched_lines = 0
    parsed_matches = 0

    for raw_line in candidate_lines:
        line = raw_line.strip().lower()
        if not line or src_ip not in line:
            continue
        if not any(tok in line for tok in service_tokens):
            continue
        if not any(tok in line for tok in failure_tokens):
            continue
        matched_lines += 1
        line_ts = _parse_router_log_timestamp(raw_line, now_ts)
        if line_ts is None:
            continue
        parsed_matches += 1
        if line_ts < window_start:
            continue
        count += 1

    if matched_lines > 0 and parsed_matches == 0:
        fallback_count = 0
        for raw_line in candidate_lines:
            line = raw_line.strip().lower()
            if not line or src_ip not in line:
                continue
            if not any(tok in line for tok in service_tokens):
                continue
            if not any(tok in line for tok in failure_tokens):
                continue
            fallback_count += 1
        return fallback_count

    return count


def _build_router_service_tokens(service: str) -> set[str]:
    service_tokens = {service.lower()}
    if service == "ssh":
        service_tokens.update({"ssh", "password"})
    elif service == "ftp":
        service_tokens.update({"ftp"})
    elif service == "telnet":
        service_tokens.update({"telnet"})
    elif service == "winbox":
        service_tokens.update({"winbox"})
    return service_tokens


ROUTER_FAILURE_TOKENS = {
    "failure",
    "failed",
    "invalid",
    "denied",
    "authentication failed",
    "login failure",
}


def _extract_router_log_source_ip(raw_line: str) -> str:
    candidates: List[str] = []
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_line or ""):
        try:
            ipaddress.ip_address(match)
        except Exception:
            continue
        if match in ROUTER_INTERFACE_IPS or match == WINDOWS_IP:
            continue
        candidates.append(match)

    for candidate in candidates:
        if _is_in_monitored_networks(candidate):
            return candidate
    return candidates[0] if candidates else ""


def get_router_failed_login_sources(
    ssh: MikroTikSSH,
    service: str,
) -> Dict[str, Tuple[int, float]]:
    now_ts = time.time()
    # Use the recent detail log buffer instead of a service-only query because
    # some RouterOS builds keep the source IP or auth failure marker outside the
    # simple message filter we were previously relying on.
    out = ssh.run("/log print detail without-paging")
    service_tokens = _build_router_service_tokens(service)
    window_start = now_ts - ROUTER_BRUTE_LOG_WINDOW_SEC
    counts: Dict[str, int] = defaultdict(int)
    latest_ts_by_src: Dict[str, float] = {}

    for raw_line in _iter_router_log_entries(out)[-ROUTER_BRUTE_LOG_LOOKBACK:]:
        line = raw_line.strip().lower()
        if not line:
            continue
        if not any(tok in line for tok in service_tokens):
            continue
        if not any(tok in line for tok in ROUTER_FAILURE_TOKENS):
            continue

        src_ip = _extract_router_log_source_ip(raw_line)
        if not src_ip:
            continue

        line_ts = _parse_router_log_timestamp(raw_line, now_ts)
        if line_ts is None:
            line_ts = now_ts
        if line_ts < window_start:
            continue

        counts[src_ip] += 1
        latest_ts_by_src[src_ip] = max(latest_ts_by_src.get(src_ip, 0.0), line_ts)

    return {src: (count, latest_ts_by_src.get(src, now_ts)) for src, count in counts.items()}


def get_router_failed_login_count(
    ssh: MikroTikSSH,
    src_ip: str,
    service: str,
    force_refresh: bool = False,
) -> int:
    if not force_refresh:
        cached = _get_router_brute_confirm_cache(src_ip, service)
        if cached is not None:
            return cached

    now_ts = time.time()
    # Use detail output so RouterOS emits stable key=value fields such as time=...
    out = ssh.run(f'/log print detail without-paging where message~"{src_ip}"')
    count = _count_router_login_failures(out, src_ip, service, now_ts)
    _set_router_brute_confirm_cache(src_ip, service, count)
    return count


def get_router_brute_confirm_service(rule: str, dst_ip: str, top_dport: int) -> str:
    if rule not in BRUTE_RULES:
        return ""
    if dst_ip not in ROUTER_INTERFACE_IPS:
        return ""
    return ROUTER_BRUTE_CONFIRM_PORTS.get(int(top_dport or 0), "")


def is_in_list(ssh: MikroTikSSH, ip: str, force_refresh: bool = False) -> Tuple[bool, bool]:
    """
    return (found, ok)
    ok=False means query failed -> do NOT treat as unblock
    """
    if not force_refresh:
        cached = _get_block_list_cache(ip)
        if cached is not None:
            return (cached, True)

    cmd = f'/ip firewall address-list print count-only where list={BLOCK_LIST} and address="{ip}"'
    out = ssh.run(cmd)
    if _router_output_has_error(out):
        return (False, False)

    n = _parse_first_int(out)
    if n is None:
        return (False, False)

    found = (n > 0)
    _set_block_list_cache(ip, found)
    return (found, True)


def is_in_address_list(ssh: MikroTikSSH, list_name: str, ip: str) -> Tuple[bool, bool]:
    cmd = f'/ip firewall address-list print count-only where list={list_name} and address="{ip}"'
    out = ssh.run(cmd)
    if _router_output_has_error(out):
        return (False, False)
    n = _parse_first_int(out)
    if n is None:
        return (False, False)
    return ((n > 0), True)


def add_ip_to_list(
    ssh: MikroTikSSH,
    ip: str,
    list_name: str,
    comment: str = "",
    timeout: str = "",
) -> str:
    if ip in NEVER_BLOCK_IPS:
        return "skipped"

    found, ok = is_in_address_list(ssh, list_name, ip)
    if ok and found:
        return "already_listed"

    safe_comment = (comment or "AI")[:60]
    timeout_clause = f" timeout={timeout}" if timeout else ""
    add_out = ssh.run(
        f'/ip firewall address-list add list={list_name} address={ip}{timeout_clause} comment="{safe_comment}"'
    )
    if _router_output_has_error(add_out):
        return "failed"

    saw_query_success = False
    for _ in range(BLOCK_VERIFY_RETRIES):
        try:
            found_after, ok_after = is_in_address_list(ssh, list_name, ip)
        except Exception:
            found_after, ok_after = (False, False)
        if ok_after:
            saw_query_success = True
            if found_after:
                return "added"
        time.sleep(BLOCK_VERIFY_RETRY_SEC)

    if not saw_query_success:
        return "added_unverified"
    return "failed"


def clear_honeypot_redirect_connections(ssh: MikroTikSSH, src_ip: str) -> None:
    try:
        ssh.run(f"/ip firewall connection remove [find where src-address={src_ip} and protocol=tcp and dst-port=22]")
    except Exception:
        pass


def remove_ip_from_list(ssh: MikroTikSSH, ip: str, list_name: str) -> str:
    found, ok = is_in_address_list(ssh, list_name, ip)
    if ok and not found:
        return "not_found"

    out = ssh.run(f'/ip firewall address-list remove [find where list={list_name} and address="{ip}"]')
    if _router_output_has_error(out):
        return "failed"

    saw_query_success = False
    for _ in range(BLOCK_VERIFY_RETRIES):
        try:
            found_after, ok_after = is_in_address_list(ssh, list_name, ip)
        except Exception:
            found_after, ok_after = (False, False)
        if ok_after:
            saw_query_success = True
            if not found_after:
                return "removed"
        time.sleep(BLOCK_VERIFY_RETRY_SEC)

    if not saw_query_success:
        return "removed_unverified"
    return "failed"


def format_block_timeout_label() -> str:
    return BLOCK_TIMEOUT if BLOCK_TIMEOUT else "permanent"


def block_ip(ssh: MikroTikSSH, ip: str, reason: str = "") -> str:
    if ip in NEVER_BLOCK_IPS:
        return "skipped"

    rules_ready = False
    for attempt in range(max(BLOCK_RULE_READY_RETRIES, 1)):
        try:
            rules_ready = ensure_drop_rules(ssh)
        except Exception:
            rules_ready = False
        if rules_ready:
            break
        if attempt + 1 < max(BLOCK_RULE_READY_RETRIES, 1):
            time.sleep(BLOCK_VERIFY_RETRY_SEC)
    if not rules_ready:
        return "failed"

    found, ok = is_in_list(ssh, ip)
    if ok and found:
        return "already_blocked"

    comment = f"AI:{reason}"[:60] if reason else "AI"
    timeout_clause = f" timeout={BLOCK_TIMEOUT}" if BLOCK_TIMEOUT else ""
    add_out = ssh.run(f'/ip firewall address-list add list={BLOCK_LIST} address={ip}{timeout_clause} comment="{comment}"')
    if _router_output_has_error(add_out):
        return "failed"

    _invalidate_block_list_cache(ip)

    for conn_cmd in (
        f"/ip firewall connection remove [find src-address={ip}]",
        f"/ip firewall connection remove [find dst-address={ip}]",
        f"/ip firewall connection remove [find reply-dst-address={ip}]",
        f"/ip firewall connection remove [find reply-src-address={ip}]",
    ):
        try:
            ssh.run(conn_cmd)
        except Exception:
            pass

    saw_query_success = False
    for _ in range(BLOCK_VERIFY_RETRIES):
        try:
            found_after, ok_after = is_in_list(ssh, ip, force_refresh=True)
        except Exception:
            found_after, ok_after = (False, False)
        if ok_after:
            saw_query_success = True
            if found_after:
                _set_block_list_cache(ip, True)
                return "blocked"
        time.sleep(BLOCK_VERIFY_RETRY_SEC)

    if not saw_query_success:
        _set_block_list_cache(ip, True)
        return "blocked_unverified"
    _invalidate_block_list_cache(ip)
    return "failed"


# ===================== MAC / ARP =====================
def _extract_first_mac(text: str) -> str:
    t = text.replace("\r", " ").replace("\n", " ").upper()
    toks = t.split()
    for tok in toks:
        if "MAC-ADDRESS=" in tok:
            tok = tok.split("MAC-ADDRESS=", 1)[1]
        tok = tok.strip()
        if tok.count(":") == 5 and len(tok) >= 17:
            mac = tok[:17]
            if all(c in "0123456789ABCDEF:" for c in mac):
                return mac
    for i in range(len(t) - 17):
        seg = t[i:i + 17]
        if seg.count(":") == 5 and all(c in "0123456789ABCDEF:" for c in seg):
            return seg
    return "??"


def get_router_mac(ssh: MikroTikSSH) -> str:
    for cmd in ("/interface bridge print detail without-paging",
                "/interface print detail without-paging"):
        try:
            out = ssh.run(cmd)
            mac = _extract_first_mac(out)
            if mac != "??":
                return mac
        except Exception:
            pass
    return "??"


def resolve_endpoint_mac(ip: str, macr, router_mac: str) -> str:
    if ip in ROUTER_INTERFACE_IPS:
        return router_mac
    return macr.get(ip)


def resolve_endpoint_mac_strict(ip: str, macr, router_mac: str) -> str:
    mac = resolve_endpoint_mac(ip, macr, router_mac)
    if mac != "??":
        return mac

    arp = getattr(macr, "arp", None)
    if arp is not None and hasattr(arp, "lookup_ip"):
        try:
            strict_mac = arp.lookup_ip(ip, min_interval_sec=0.0)
            if strict_mac:
                cache = getattr(macr, "cache", None)
                if isinstance(cache, dict):
                    cache[ip] = (time.time(), strict_mac)
                return strict_mac
        except Exception:
            pass

    ssh_fallback = getattr(macr, "ssh", None)
    if ssh_fallback is not None:
        for cmd in (
            f"/ip arp print without-paging terse where address={ip}",
            f"/ip dhcp-server lease print without-paging terse where address={ip}",
        ):
            try:
                strict_mac = _extract_first_mac(ssh_fallback.run(cmd))
                if strict_mac != "??":
                    cache = getattr(macr, "cache", None)
                    if isinstance(cache, dict):
                        cache[ip] = (time.time(), strict_mac)
                    return strict_mac
            except Exception:
                pass
    return mac


def resolve_endpoint_mac_strict_retry(ip: str, macr, router_mac: str, retry_delay_sec: float = SSH_ROUTER_LOG_MAC_RETRY_DELAY_SEC) -> str:
    for attempt in range(3):
        mac = resolve_endpoint_mac_strict(ip, macr, router_mac)
        if mac != "??":
            return mac
        if attempt < 2 and retry_delay_sec > 0:
            try:
                time.sleep(retry_delay_sec)
            except Exception:
                pass
    return "??"


class MacResolverSingle:
    def __init__(self, ssh: MikroTikSSH, ttl_sec: int = 30):
        self.ssh = ssh
        self.ttl_sec = ttl_sec
        self.cache: Dict[str, Tuple[float, str]] = {}

    def get(self, ip: str) -> str:
        now = time.time()
        cached = self.cache.get(ip)
        if cached is not None:
            ts, mac = cached
            if now - ts <= self.ttl_sec and mac != "??":
                return mac

        out = self.ssh.run(f"/ip arp print without-paging terse where address={ip}")
        mac = _extract_first_mac(out)
        self.cache[ip] = (now, mac if mac else "??")
        return mac if mac else "??"


class MacResolverTable:
    def __init__(self, arp: ArpResolver, ttl_sec: int = 180, miss_ttl_sec: int = 3, refresh_on_miss_min_sec: float = 3.0):
        self.arp = arp
        self.ttl_sec = ttl_sec
        self.miss_ttl_sec = miss_ttl_sec
        self.refresh_on_miss_min_sec = refresh_on_miss_min_sec
        self.cache: Dict[str, Tuple[float, str]] = {}

    def get(self, ip: str) -> str:
        now = time.time()
        cached = self.cache.get(ip)
        if cached is not None:
            ts, mac = cached
            age = now - ts
            if mac != "??" and age <= self.ttl_sec:
                return mac
            if mac == "??" and age <= self.miss_ttl_sec:
                return "??"

        mac = self.arp.mac_of(ip)
        if mac:
            self.cache[ip] = (now, mac)
            return mac

        self.arp.refresh_if_stale(self.refresh_on_miss_min_sec)
        mac = self.arp.mac_of(ip)
        if mac:
            self.cache[ip] = (time.time(), mac)
            return mac

        direct_mac = self.arp.lookup_ip(ip, min_interval_sec=self.refresh_on_miss_min_sec)
        if direct_mac:
            self.cache[ip] = (time.time(), direct_mac)
            return direct_mac

        self.cache[ip] = (time.time(), "??")
        return "??"


# ===================== ML helpers =====================
def load_model_bundle(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file not found: {path}")

    obj = joblib.load(path)

    if not isinstance(obj, dict):
        features = _normalize_feature_names(getattr(obj, "feature_names_in_", None))
        if features is None:
            get_booster = getattr(obj, "get_booster", None)
            if callable(get_booster):
                try:
                    features = _normalize_feature_names(get_booster().feature_names)
                except Exception:
                    features = None
        if features is None:
            raise RuntimeError(
                f"Unsupported legacy model file without feature metadata: {path}. "
                "Re-save it as {'model': ..., 'feature_columns': ...}."
            )
        print(f"[!] Warning: {path} is a direct model object; using embedded feature names")
        return obj, features

    if "model" not in obj:
        raise RuntimeError(f"Bad model file: {path}")

    features = _normalize_feature_names(obj.get("feature_columns") or obj.get("features"))
    if features is None:
        raise RuntimeError(f"Model file missing feature columns: {path}")

    return obj["model"], features


def predict_probs(model, feats: List[str], row: Dict[str, float]):
    X = pd.DataFrame([[row.get(f, 0.0) for f in feats]], columns=feats)
    probs = model.predict_proba(X)[0]
    cls_list = list(getattr(model, "classes_", []))
    return {int(c): float(p) for c, p in zip(cls_list, probs)}


def _normalize_feature_names(features) -> Optional[List[str]]:
    if features is None:
        return None
    try:
        names = [str(f) for f in list(features)]
    except Exception:
        return None
    return names or None


def build_row_features(window_sec: int, a) -> Dict[str, float]:
    flows = float(a.flows)
    total = flows if flows > 0 else 1.0

    uniq_dports = float(a.uniq_dports())
    proto_mode = float(a.top_proto())

    Spkts = float(a.s_pkts)
    Dpkts = float(a.d_pkts)
    sbytes = float(a.s_bytes)
    dbytes = float(a.d_bytes)

    pkts_rate = (Spkts + Dpkts) / float(window_sec)
    bytes_rate = (sbytes + dbytes) / float(window_sec)

    sbytes_per_pkt = sbytes / (Spkts + 1.0)
    dbytes_per_pkt = dbytes / (Dpkts + 1.0)
    flow_ratio = Spkts / (Dpkts + 1.0)
    byte_ratio = sbytes / (dbytes + 1.0)
    icmp_is_proto = 1.0 if proto_mode == 1.0 else 0.0
    icmp_pkt_per_flow = Spkts / (flows + 1.0)
    dcounts = a.dport_counts if hasattr(a, "dport_counts") else {}

    if dcounts:
        top_cnt = max(dcounts.values())
        top_ports = [p for p, c in dcounts.items() if c == top_cnt]
        top_port = int(min(top_ports)) if top_ports else 0
    else:
        top_cnt = 0
        top_port = 0

    top_port_ratio = float(top_cnt) / total

    well_known_cnt = sum(int(c) for p, c in dcounts.items() if int(p) <= 1024)
    high_port_cnt = sum(int(c) for p, c in dcounts.items() if int(p) >= 49152)

    well_known_ratio = float(well_known_cnt) / total
    high_port_ratio = float(high_port_cnt) / total

    entropy = 0.0
    for c in dcounts.values():
        p = float(c) / total
        if p > 0:
            entropy -= p * math.log2(p)

    top_is_22 = 1.0 if top_port == 22 else 0.0
    top_is_53 = 1.0 if top_port == 53 else 0.0
    top_is_67 = 1.0 if top_port == 67 else 0.0
    top_is_68 = 1.0 if top_port == 68 else 0.0
    top_is_80 = 1.0 if top_port == 80 else 0.0
    top_is_123 = 1.0 if top_port == 123 else 0.0
    top_is_443 = 1.0 if top_port == 443 else 0.0
    top_is_445 = 1.0 if top_port == 445 else 0.0
    top_is_8291 = 1.0 if top_port == 8291 else 0.0

    top_is_well_known = 1.0 if top_port <= 1024 else 0.0
    top_is_registered = 1.0 if (1025 <= top_port <= 49151) else 0.0
    top_is_dynamic = 1.0 if (top_port >= 49152) else 0.0

    # 闂?MUST MATCH train_malware_plus.py (闂佺懓鐡ㄩ崹宕囨崲濮樿埖鍋╂繛鍡楁捣缁嬫垿鏌ｉ妸銉ヮ仼闁烩姍鍐ｆ灁缁炬澘顦辩粈澶娒归敐鍛棤妞ゅ浚鍓熷畷锝夋晲婢跺鍋侀梺鍛婅壘閻楀懐绮径鎰厒鐎广儱鎳庣紞?
    top_is_3333 = 1.0 if top_port == 3333 else 0.0
    top_is_4444 = 1.0 if top_port == 4444 else 0.0
    top_is_5555 = 1.0 if top_port == 5555 else 0.0
    top_is_9001 = 1.0 if top_port == 9001 else 0.0
    top_is_1337 = 1.0 if top_port == 1337 else 0.0
    top_is_14444 = 1.0 if top_port == 14444 else 0.0

    top_is_miner = 1.0 if top_port in MINER_PORTS else 0.0
    top_is_backdoor = 1.0 if top_port in BACKDOOR_PORTS else 0.0

    return {
        "dur_sum": float(window_sec),
        "flows": flows,
        "uniq_dports": uniq_dports,
        "proto_mode": proto_mode,
        "Spkts": Spkts,
        "Dpkts": Dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,

        "pkts_rate": pkts_rate,
        "bytes_rate": bytes_rate,
        "sbytes_per_pkt": sbytes_per_pkt,
        "dbytes_per_pkt": dbytes_per_pkt,
        "flow_ratio": flow_ratio,
        "byte_ratio": byte_ratio,

        "top_port_ratio": top_port_ratio,
        "well_known_ratio": well_known_ratio,
        "high_port_ratio": high_port_ratio,
        "dport_entropy": entropy,

        "top_is_22": top_is_22,
        "top_is_53": top_is_53,
        "top_is_67": top_is_67,
        "top_is_68": top_is_68,
        "top_is_80": top_is_80,
        "top_is_123": top_is_123,
        "top_is_443": top_is_443,
        "top_is_445": top_is_445,
        "top_is_8291": top_is_8291,
        "top_is_well_known": top_is_well_known,
        "top_is_registered": top_is_registered,
        "top_is_dynamic": top_is_dynamic,
        "icmp_is_proto": icmp_is_proto,
        "icmp_pkt_per_flow": icmp_pkt_per_flow,

        "top_is_3333": top_is_3333,
        "top_is_4444": top_is_4444,
        "top_is_5555": top_is_5555,
        "top_is_9001": top_is_9001,
        "top_is_1337": top_is_1337,
        "top_is_14444": top_is_14444,
        "top_is_miner": top_is_miner,
        "top_is_backdoor": top_is_backdoor,
    }


# ===================== Aggregation =====================
class Agg:
    def __init__(self):
        self.flows = 0
        self.s_pkts = 0
        self.s_bytes = 0
        self.d_pkts = 0
        self.d_bytes = 0
        self.sport_counts = defaultdict(int)
        self.dport_counts = defaultdict(int)
        self.proto_counts = defaultdict(int)
        self.unique_sports = set()
        self.unique_dports = set()

    def add_forward(self, f: Flow):
        self.flows += 1
        self.s_pkts += int(f.packets)
        self.s_bytes += int(f.bytes)
        self.sport_counts[int(f.src_port)] += 1
        self.dport_counts[int(f.dst_port)] += 1
        self.proto_counts[int(f.proto)] += 1
        self.unique_sports.add(int(f.src_port))
        self.unique_dports.add(int(f.dst_port))

    def top_sport(self) -> int:
        return max(self.sport_counts.items(), key=lambda x: x[1])[0] if self.sport_counts else 0

    def top_dport(self) -> int:
        return max(self.dport_counts.items(), key=lambda x: x[1])[0] if self.dport_counts else 0

    def top_proto(self) -> int:
        return max(self.proto_counts.items(), key=lambda x: x[1])[0] if self.proto_counts else 0

    def uniq_dports(self) -> int:
        return len(self.unique_dports)


def build_eval_agg(a: 'Agg', reverse: Optional['Agg']) -> 'Agg':
    view = Agg()
    view.flows = a.flows
    view.s_pkts = a.s_pkts
    view.s_bytes = a.s_bytes
    view.d_pkts = reverse.s_pkts if reverse is not None else 0
    view.d_bytes = reverse.s_bytes if reverse is not None else 0
    view.sport_counts = defaultdict(int, a.sport_counts)
    view.dport_counts = defaultdict(int, a.dport_counts)
    view.proto_counts = defaultdict(int, a.proto_counts)
    view.unique_sports = set(a.unique_sports)
    view.unique_dports = set(a.unique_dports)
    return view


def build_router_log_ssh_agg(fail_count: int) -> "Agg":
    a = Agg()
    flows = max(int(fail_count), SSH_HONEYPOT_FASTPATH_MIN_FLOWS)
    pkts = max(int(fail_count) * 4, SSH_HONEYPOT_FASTPATH_MIN_PKTS)
    sbytes = max(pkts * 150, 1200)
    a.flows = flows
    a.s_pkts = pkts
    a.s_bytes = sbytes
    a.sport_counts[0] = flows
    a.dport_counts[22] = flows
    a.proto_counts[6] = flows
    a.unique_dports.add(22)
    return a


def build_router_log_ssh_display_agg(current_agg: Optional["Agg"], fail_count: int) -> "Agg":
    if current_agg is not None:
        try:
            if int(current_agg.top_proto()) == 6 and int(current_agg.top_dport()) == 22:
                return current_agg
        except Exception:
            pass
    return build_router_log_ssh_agg(fail_count)

# ===================== Detection =====================
def detect_rule_type(a: Agg) -> Optional[str]:
    uniq = a.uniq_dports()
    flows = a.flows
    pkts = a.s_pkts
    sbytes = a.s_bytes
    dbytes = a.d_bytes
    top_dp = a.top_dport()
    top_pr = a.top_proto()

    # ---------- behavior indicators (port distribution) ----------
    total = float(flows if flows > 0 else 1.0)
    dcounts = a.dport_counts if hasattr(a, "dport_counts") else {}
    top_cnt = max(dcounts.values()) if dcounts else 0
    top_ratio = float(top_cnt) / total  # how concentrated traffic is on the top port

    # ---------- RANSOMWARE_PRECHECK (lateral-movement precheck) ----------
    # 婵炴垶鎸哥粔鎾疮閳ь剛绱撴担鐟扮仸妞?445闂佹寧绋掑銊╁极閵堝鐏虫繝濠傚▕椤撱垹瑙﹂柟瀵稿閳哄懎绀夐柕濞垮劤閸╂鎮峰▎搴ｅ妽婵犫偓閸ヮ剙绀夐柨娑樺娴煎倿鏌涘▎娆戝埌闁规枼鍓濈粙?+ 闁荤偞绋戞總鏃傛嫻閻斿吋鍋嬮柣鐔稿缁愭瑩鏌嶉妷锔剧畺婵炶偐鏁诲畷姘跺Χ閸℃鍔?
    LATERAL_PORTS = {135, 139, 445, 3389, 5985, 5986, 88, 389, 636}
    lateral_hits = sum(int(dcounts.get(p, 0)) for p in LATERAL_PORTS)
    lateral_ratio = float(lateral_hits) / total

    # 闂佽鍨伴幊搴ㄥ窗鐎涘鏌ㄥ☉娆掑闁活煈鍨跺顐﹀箥椤曞懍绱撻梺鍛婄懕缂嶅洨妲?=5闂佹寧绋戦ˇ顖烆敋椤斿槈鐔碱敂閸曨剙鈧崵绱掗弮鎴濈仩鐟滅増绋掑璇测槈濠婂孩鏂€婵°倕鍊归敃銏ゃ€傞崼鏇炵闁靛骏绱曢妶鎾煥濞戞澧斿ù婊勫浮瀹曟粌顓奸崟顓犵崶闁?TCP_FLOOD 闂佺缈伴崹濂告憘鐎ｎ喗鏅?
    lateral_ports_hit = sum(1 for p in LATERAL_PORTS if int(dcounts.get(p, 0)) > 0)

    if top_pr == 6 and flows >= 40 and uniq <= 12 and lateral_ports_hit >= 3:
        return "RANSOMWARE_PRECHECK"

    # 闂佽鍨伴幊搴ㄥ窗鐎涘﹪鏌ㄥ☉娆掑闁稿孩宀搁獮宥夘敃閿濆懍绱熼梺鎸庣☉濠㈠攳iq婵°倕鍊归敃顐ゆ濮橆厽濯撮柛鈩冣棨椤撱垹瑙﹂柟瀵稿娴煎倿鏌涘▎娆戝埌闁规枼鍓濈粙澶愵敇閻斿壊娼犻梺鍝勫閹锋繄妲愬▎鎰枖鐎广儱妫欑瑧缂備胶铏庨崹璺衡枔閵忋倕瀚夐柣鎴灻ˉ鍥╃磼閺冩垵鐏犵憸鐗堢洴閺?
    # 婵☆偆澧楃换鍌炈囬懡銈嗗暫濞达絽婀卞﹢?top_ratio 婵炴垶鎸哥粔鐑姐€呴敂钘夌窞妞ゅ繐鐗忚ぐ顖炴煥濞戞鐒稿ù灏栨櫊瀹曟顓奸崱妞⑩晠鏌涘Δ浣圭妞ゅ浚鍓熷畷?flood 閻熸粎澧楅幐濠氬垂?ransomware
    if uniq >= PORT_SCAN_UNIQ_DPORTS and flows >= MIN_FLOWS_TO_CONSIDER:
        if (lateral_hits >= 30 or lateral_ratio >= 0.20) and top_ratio <= 0.35:
            return "RANSOMWARE_PRECHECK"

    # brute force
    if top_dp in BRUTE_PORTS:
        if flows >= BRUTE_MIN_FLOWS and pkts >= BRUTE_MIN_PKTS and uniq <= BRUTE_MAX_UNIQ_DPORTS and sbytes <= BRUTE_MAX_SBYTES:
            return BRUTE_PORTS[top_dp]

    # 闂?Backdoor / Miner (Backdoor 婵炴潙鍚嬮敋闁告ɑ鐩弫宥囦沪閼测晝鎳嶇紓浣规閸ㄦ媽銇愬☉娆戔枖鐎广儱顦▍銏ゆ煕?
    if top_dp in BACKDOOR_PORTS:
        if flows >= BACKDOOR_MIN_FLOWS and sbytes <= BACKDOOR_MAX_SBYTES and uniq <= BACKDOOR_MAX_UNIQ_DPORTS:
            return "C2_BACKDOOR"

    if top_dp in MINER_PORTS and flows >= MINER_MIN_FLOWS and pkts >= MINER_MIN_PKTS:
        return "CRYPTO_MINER"

    # ---------- PORT_SCAN ----------
    # 闂佸憡鐟禍婵嗭耿娴ｈ櫣鍗氭い鏍ㄨ壘缂嶆捇鏌涢幒鎴烆棞缂佹棃顥撻幖楣冨礃瀹割喗顎嶉梺鐐藉劜缁矂宕规惔銊ユ瀬闁挎繂鍊甸崑鎾斥攽閹惧墎顦﹖op_ratio婵炶揪绲介崙鐣屾濮樿泛绠ョ€广儱鎳庡?scan闂佹寧绋戦懟顖炲闯閾忛€涚剨?flood/闂佽浜介崹铏圭矈鐎靛憡瀚氭い鏍ㄨ壘閻?
    if uniq >= PORT_SCAN_UNIQ_DPORTS and flows >= MIN_FLOWS_TO_CONSIDER and top_ratio <= 0.25:
        return "PORT_SCAN"

    # icmp flood
    if top_pr == 1 and pkts >= ICMP_FLOOD_PKTS:
        return "ICMP_FLOOD"

    # http/tcp/udp flood
    if top_dp in (80, 443) and flows >= HTTP_FLOOD_FLOWS:
        return "HTTP_FLOOD"

    if top_pr == 6 and flows >= TCP_FLOOD_FLOWS and uniq <= 3:
        return "TCP_FLOOD"

    if top_pr == 17 and flows >= UDP_FLOOD_FLOWS and uniq <= 5:
        return "UDP_FLOOD"

    # conn flood
    if flows >= CONN_FLOOD_FLOWS and uniq <= 3:
        return "CONN_FLOOD"

    # dns tunnel
    if top_dp == DNS_TUNNEL_DPORT and flows >= DNS_TUNNEL_FLOWS and sbytes >= DNS_TUNNEL_SBYTES:
        return "DNS_TUNNEL"

    # suspicious high port burst
    if top_dp >= HIGH_PORT_MIN and flows >= SUSP_HIGH_PORT_FLOWS:
        return "SUSP_HIGH_PORT"

    # 闂?DATA_EXFIL 闂佽　鍋撻柟顖嗗啰鍘?flood 闂佸憡鑹鹃柊锝咁焽娴煎瓨鏅€光偓閸曨亞绱氶梺绋跨箰缁夊瓨瀵奸弮鍫濆唨闁搞儮鏅╅崝顕€鏌ㄥ☉娆戔槈闁哥啿鍋撻梺鍛婃⒒婵鈧濞婂鍫曟偄闂傚绱氶梺绋跨箰缁夌兘顢氶妶澶婄?flood/scan
    if sbytes >= DATA_EXFIL_SBYTES and dbytes <= DATA_EXFIL_DBYTES_MAX:
        # 闂佸湱鍎ょ敮鈥斥枍?flood 闂佹眹鍔岀€氫即鎮?flow / scan 闂佹眹鍔岀€氫即鎮?uniq_dports
        if flows <= 300 and uniq <= 40:
            return "DATA_EXFIL"

    return None


def detect_observed_type(a: Agg) -> Optional[str]:
    uniq = a.uniq_dports()
    flows = a.flows
    pkts = a.s_pkts
    sbytes = a.s_bytes
    top_dp = a.top_dport()
    top_pr = a.top_proto()

    total = float(flows if flows > 0 else 1.0)
    dcounts = a.dport_counts if hasattr(a, "dport_counts") else {}
    top_cnt = max(dcounts.values()) if dcounts else 0
    top_ratio = float(top_cnt) / total

    if top_pr == 1 and 0 < pkts < ICMP_FLOOD_PKTS and flows <= OBS_PING_MAX_FLOWS:
        return "OBS_PING"

    if top_pr == 6 and top_dp in OBSERVED_BRUTE_RULES:
        if uniq <= OBS_BRUTE_MAX_UNIQ_DPORTS and sbytes <= OBS_BRUTE_MAX_SBYTES:
            return OBSERVED_BRUTE_RULES[int(top_dp)]

    if top_pr == 6 and flows >= OBS_NMAP_MIN_FLOWS and OBS_NMAP_MIN_UNIQ_DPORTS <= uniq <= OBS_NMAP_MAX_UNIQ_DPORTS:
        if top_ratio <= OBS_NMAP_MAX_TOP_RATIO and sbytes <= OBS_NMAP_MAX_SBYTES:
            return "OBS_NMAP_SCAN"

    if OBSERVE_UNKNOWN_TRAFFIC and flows > 0:
        return "OBS_UNKNOWN"

    return None


def event_category_for_rule(rule: str) -> str:
    if rule in ATTACK_RULES:
        return "ATTACK"
    if rule in MAL_BEHAVIORS:
        return "MALWARE"
    if rule in OBSERVED_RULES:
        return "OBSERVED"
    return "OTHER"


def _ip_obj(value: str):
    try:
        return ipaddress.ip_address(str(value))
    except Exception:
        return None


def _is_private_ip(ip: str) -> bool:
    addr = _ip_obj(ip)
    return bool(addr and addr.is_private)


def _is_public_ip(ip: str) -> bool:
    addr = _ip_obj(ip)
    if addr is None:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    )


def _is_in_monitored_networks(ip: str) -> bool:
    addr = _ip_obj(ip)
    if addr is None:
        return False
    return any(addr in net for net in MONITORED_NETWORKS)


def _is_ignored_special_ip(addr) -> bool:
    if addr is None:
        return False
    if getattr(addr, 'is_multicast', False):
        return True
    if str(addr) == '255.255.255.255':
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        for net in MONITORED_NETWORKS:
            if not isinstance(net, ipaddress.IPv4Network):
                continue
            if addr == net.network_address or addr == net.broadcast_address:
                return True
    return False


def should_ignore_flow_scope(src: str, dst: str) -> bool:
    if src in HONEYPOT_TARGET_IPS or dst in HONEYPOT_TARGET_IPS:
        return True

    src_addr = _ip_obj(src)
    dst_addr = _ip_obj(dst)

    if IGNORE_BROADCAST_AND_MULTICAST:
        if _is_ignored_special_ip(src_addr) or _is_ignored_special_ip(dst_addr):
            return True

    if not IGNORE_UNMONITORED_PRIVATE_DST:
        return False

    # Ignore any flow that involves a private endpoint outside the monitored lab ranges.
    for addr, ip_text in ((src_addr, src), (dst_addr, dst)):
        if addr is not None and addr.is_private and not _is_in_monitored_networks(ip_text):
            return True

    # If neither endpoint belongs to the monitored lab ranges, this flow is out of scope.
    if _is_in_monitored_networks(src) or _is_in_monitored_networks(dst):
        return False
    return True


def is_trusted_ssh_source(src: str) -> bool:
    return str(src) in SSH_TRUSTED_SOURCE_IPS or str(src) in NEVER_BLOCK_IPS


def should_skip_beacon_heuristic(src: str, dst: str, a: "Agg") -> bool:
    top_dp = int(a.top_dport())
    if src in ROUTER_INTERFACE_IPS or dst in ROUTER_INTERFACE_IPS:
        return True
    if top_dp in BACKGROUND_INFRA_PORTS:
        return True
    if _is_public_ip(dst) and top_dp in BACKGROUND_PUBLIC_SERVICE_PORTS:
        return True
    return False


def should_suppress_observed_event(rule: str, src: str, dst: str, a: "Agg") -> bool:
    if rule != "OBS_UNKNOWN":
        return False

    top_dp = int(a.top_dport())
    top_pr = int(a.top_proto())
    flows = int(a.flows)
    uniq = int(a.uniq_dports())

    src_private = _is_private_ip(src)
    dst_private = _is_private_ip(dst)
    dst_public = _is_public_ip(dst)

    if dst in ROUTER_INTERFACE_IPS and top_dp in ROUTER_BACKGROUND_SERVICE_PORTS:
        return True

    if top_pr == 17 and top_dp in {67, 68} and src_private and dst_private:
        return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= 2

    if top_dp == 53 and (src_private or dst_private):
        return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= BACKGROUND_INFRA_MAX_UNIQ_DPORTS

    if top_pr == 17 and top_dp == 123:
        return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= 2

    if dst_public and top_dp in BACKGROUND_PUBLIC_SERVICE_PORTS:
        return flows <= BACKGROUND_PUBLIC_MAX_FLOWS and uniq <= BACKGROUND_PUBLIC_MAX_UNIQ_DPORTS

    if dst_public and top_dp == 123:
        return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= BACKGROUND_INFRA_MAX_UNIQ_DPORTS

    return False


def _silent_baseline_scores_are_safe(attack_score, malware_score) -> bool:
    attack_value = _optional_float(attack_score)
    malware_value = _optional_float(malware_score)
    if attack_value is None or malware_value is None:
        return False
    return (
        attack_value <= SILENT_BASELINE_MAX_ATTACK_SCORE
        and malware_value <= SILENT_BASELINE_MAX_MALWARE_SCORE
    )


def should_capture_suppressed_observed_baseline(src: str, dst: str, a: "Agg", attack_score=None, malware_score=None) -> bool:
    top_dp = int(a.top_dport())
    top_pr = int(a.top_proto())
    flows = int(a.flows)
    uniq = int(a.uniq_dports())

    src_private = _is_private_ip(src)
    dst_private = _is_private_ip(dst)
    dst_public = _is_public_ip(dst)

    if not _silent_baseline_scores_are_safe(attack_score, malware_score):
        return False

    if top_pr == 17 and top_dp in {67, 68} and src_private and dst_private:
        return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= 2

    if top_dp == 53 and (src_private or dst_private):
        return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= BACKGROUND_INFRA_MAX_UNIQ_DPORTS

    if top_pr == 17 and top_dp == 123:
        if src_private and dst_private:
            return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= 2
        if dst_public:
            return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= BACKGROUND_INFRA_MAX_UNIQ_DPORTS

    return False


def should_quiet_suppressed_observed_noise(src: str, dst: str, a: "Agg", attack_score=None, malware_score=None) -> bool:
    top_dp = int(a.top_dport())
    top_pr = int(a.top_proto())
    flows = int(a.flows)
    uniq = int(a.uniq_dports())
    spkts = int(a.s_pkts)
    sbytes = int(a.s_bytes)

    src_private = _is_private_ip(src)
    dst_private = _is_private_ip(dst)
    dst_public = _is_public_ip(dst)

    if dst_public and top_dp in BACKGROUND_PUBLIC_SERVICE_PORTS:
        return (
            flows <= QUIET_PUBLIC_WEB_MAX_FLOWS
            and uniq <= 2
            and spkts <= QUIET_PUBLIC_WEB_MAX_PKTS
            and sbytes <= QUIET_PUBLIC_WEB_MAX_SBYTES
        )

    attack_value = _optional_float(attack_score)
    malware_value = _optional_float(malware_score)
    if attack_value is None or malware_value is None:
        return False
    if (
        attack_value > QUIET_OBSERVED_BACKGROUND_MAX_ATTACK_SCORE
        or malware_value > QUIET_OBSERVED_BACKGROUND_MAX_MALWARE_SCORE
    ):
        return False

    if top_pr == 17 and top_dp in {67, 68} and src_private and dst_private:
        return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= 2

    if top_dp == 53 and (src_private or dst_private):
        return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= BACKGROUND_INFRA_MAX_UNIQ_DPORTS

    if top_pr == 17 and top_dp == 123:
        if src_private and dst_private:
            return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= 2
        if dst_public:
            return flows <= BACKGROUND_INFRA_MAX_FLOWS and uniq <= BACKGROUND_INFRA_MAX_UNIQ_DPORTS

    return False


def should_capture_router_web_unknown_silently(src: str, dst: str, a: "Agg", attack_score=None, malware_score=None) -> bool:
    top_dp = int(a.top_dport())
    top_pr = int(a.top_proto())

    if dst not in ROUTER_INTERFACE_IPS:
        return False
    if top_pr != 6:
        return False
    if top_dp not in BACKGROUND_PUBLIC_SERVICE_PORTS:
        return False
    return True


def should_emit_unknown_observed_threat(src: str, dst: str, a: "Agg", attack_score=None, malware_score=None) -> bool:
    attack_value = _optional_float(attack_score)
    malware_value = _optional_float(malware_score)
    if attack_value is None or malware_value is None:
        return False

    dst_public = _is_public_ip(dst)
    top_dp = int(a.top_dport())
    flows = int(a.flows)
    uniq = int(a.uniq_dports())
    spkts = int(a.s_pkts)
    sbytes = int(a.s_bytes)
    max_score = max(attack_value, malware_value)

    # Keep demo output clean: background infrastructure ports should never surface
    # as generic OBS_UNKNOWN. If they are truly malicious they should match a
    # stronger named rule such as DNS_TUNNEL instead of falling through here.
    if top_dp in BACKGROUND_INFRA_PORTS:
        return False

    # For demo and operator clarity, generic unknown traffic on public web ports
    # should stay silent. If it is truly malicious it should match a stronger
    # named rule (for example DATA_EXFIL or C2_BEACON) instead of surfacing as
    # noisy OBS_UNKNOWN background traffic.
    if dst_public and top_dp in BACKGROUND_PUBLIC_SERVICE_PORTS:
        return False

    if attack_value >= UNKNOWN_OBSERVED_MIN_ATTACK_SCORE:
        return True
    if malware_value >= UNKNOWN_OBSERVED_MIN_MALWARE_SCORE:
        return True

    if max_score < UNKNOWN_OBSERVED_SUSPICIOUS_SCORE:
        return False

    if top_dp in (BACKDOOR_PORTS | MINER_PORTS):
        return True
    if uniq >= UNKNOWN_OBSERVED_MIN_UNIQ_DPORTS:
        return True
    if flows >= UNKNOWN_OBSERVED_MIN_FLOWS:
        return True
    if sbytes >= UNKNOWN_OBSERVED_MIN_SBYTES:
        return True

    return False


def _port_is_service(port: int) -> bool:
    return int(port) > 0 and (int(port) <= SERVICE_PORT_MAX or int(port) in KNOWN_SERVER_PORTS)


def _port_is_dynamic(port: int) -> bool:
    return int(port) >= DYNAMIC_PORT_MIN


def _pair_key(proto: int, src: str, dst: str) -> Tuple[int, str, str]:
    a, b = sorted((str(src), str(dst)))
    return int(proto), a, b


PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}

ICMP_REQUEST_TYPES = {8, 13, 15, 17}
ICMP_RESPONSE_TYPES = {0, 3, 4, 5, 11, 12, 14, 16, 18}
ICMP_KNOWN_TYPES = ICMP_REQUEST_TYPES | ICMP_RESPONSE_TYPES


def _addr_ip_only(text: str) -> str:
    s = (text or "").strip().strip('"')
    if not s:
        return ""
    if "/" in s:
        s = s.split("/", 1)[0]
    if ":" in s and s.count(":") == 1:
        head, tail = s.rsplit(":", 1)
        if tail.isdigit():
            s = head
    return s


def _parse_conntrack_records(text: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "failure" in line.lower() or "error" in line.lower():
            continue
        parts = line.replace(";", " ").split()
        rec: Dict[str, str] = {}
        for part in parts:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            rec[key.strip()] = value.strip()
        if rec:
            records.append(rec)
    return records


def lookup_pair_initiator_from_conntrack(
    ssh: MikroTikSSH,
    src: str,
    dst: str,
    proto: int,
    cache: Dict[Tuple[int, str, str], Tuple[Optional[str], float]],
    now_ts: float,
) -> Optional[str]:
    key = _pair_key(proto, src, dst)
    cached = cache.get(key)
    if cached is not None and (now_ts - cached[1]) <= CONNTRACK_LOOKUP_TTL_SEC:
        return cached[0]

    # Keep conntrack lookups narrowly scoped. TCP/UDP already have usable
    # port-role heuristics, while protocol-wide conntrack dumps are heavy under
    # scans/floods and can perturb the router.
    if int(proto) != 1:
        cache[key] = (None, now_ts)
        return None

    queries = [
        (str(src), str(dst), str(src)),
        (str(dst), str(src), str(dst)),
    ]
    for q_src, q_dst, initiator in queries:
        cmd = (
            "/ip firewall connection print terse without-paging "
            f'where protocol=icmp and src-address~"{q_src}" and dst-address~"{q_dst}"'
        )
        try:
            out = ssh.run(cmd)
        except Exception:
            continue
        for rec in _parse_conntrack_records(out):
            orig_src = _addr_ip_only(rec.get("src-address", ""))
            orig_dst = _addr_ip_only(rec.get("dst-address", ""))
            if orig_src == q_src and orig_dst == q_dst:
                cache[key] = (initiator, now_ts)
                return initiator

    cache[key] = (None, now_ts)
    return None


def maybe_refresh_pair_initiator_from_conntrack(
    ssh: MikroTikSSH,
    src: str,
    dst: str,
    proto: int,
    initiators: Dict[Tuple[int, str, str], Tuple[str, float]],
    cache: Dict[Tuple[int, str, str], Tuple[Optional[str], float]],
    now_ts: float,
) -> Optional[str]:
    existing = get_pair_initiator(proto, src, dst, initiators)
    if existing is not None:
        return existing

    if int(proto) != 1:
        return None

    initiator = lookup_pair_initiator_from_conntrack(ssh, src, dst, proto, cache, now_ts)
    if initiator is not None:
        initiators[_pair_key(proto, src, dst)] = (initiator, now_ts)
    return initiator


def _flow_icmp_type_code(flow: Flow) -> Tuple[Optional[int], Optional[int]]:
    if int(flow.proto) != 1:
        return (None, None)

    if flow.icmp_type is not None:
        return (int(flow.icmp_type), int(flow.icmp_code or 0))

    for raw in (int(flow.dst_port), int(flow.src_port)):
        if raw > 255:
            icmp_type = (raw >> 8) & 0xFF
            icmp_code = raw & 0xFF
            if icmp_type in ICMP_KNOWN_TYPES:
                return (icmp_type, icmp_code)

    src_hint = int(flow.src_port)
    dst_hint = int(flow.dst_port)
    if 0 <= src_hint <= 255 and 0 <= dst_hint <= 255:
        # A plain 0/0 port pair is ambiguous in NetFlow v9 exports and often
        # just means "ICMP with no L4 ports", not necessarily echo-reply.
        # Only trust low-byte hints when a non-zero side looks like a known
        # ICMP type.
        if src_hint != 0 and src_hint in ICMP_KNOWN_TYPES:
            return (src_hint, dst_hint)
        if dst_hint != 0 and dst_hint in ICMP_KNOWN_TYPES:
            return (dst_hint, src_hint)

    return (None, None)


def infer_flow_initiator(flow: Flow) -> Optional[str]:
    if int(flow.proto) == 1:
        icmp_type, _icmp_code = _flow_icmp_type_code(flow)
        if icmp_type in ICMP_REQUEST_TYPES:
            return flow.src_ip
        if icmp_type in ICMP_RESPONSE_TYPES:
            return flow.dst_ip

    if _port_is_dynamic(flow.src_port) and _port_is_service(flow.dst_port):
        return flow.src_ip
    if _port_is_service(flow.src_port) and _port_is_dynamic(flow.dst_port):
        return flow.dst_ip
    return None


def remember_initiator(flow: Flow, initiators: Dict[Tuple[int, str, str], Tuple[str, float]], now_ts: float) -> None:
    key = _pair_key(flow.proto, flow.src_ip, flow.dst_ip)
    inferred = infer_flow_initiator(flow)
    if inferred is not None:
        initiators[key] = (inferred, now_ts)
        return

    if int(flow.proto) == 1:
        rec = initiators.get(key)
        if rec is not None:
            initiators[key] = (rec[0], now_ts)
        return

    if key not in initiators:
        initiators[key] = (flow.src_ip, now_ts)
    else:
        first_src, _old_ts = initiators[key]
        initiators[key] = (first_src, now_ts)


def get_pair_initiator(proto: int, src: str, dst: str, initiators: Dict[Tuple[int, str, str], Tuple[str, float]]) -> Optional[str]:
    rec = initiators.get(_pair_key(proto, src, dst))
    if rec is None:
        return None
    return rec[0]


def infer_flow_role(src, dst, a, initiators):
    proto = int(a.top_proto())
    initiator = get_pair_initiator(proto, src, dst, initiators)

    if initiator == src:
        return "initiator"

    if initiator == dst:
        return "responder"

    sport = a.top_sport()
    dport = a.top_dport()

    # service port rule
    if _port_is_service(dport) and _port_is_dynamic(sport):
        return "initiator"

    if _port_is_service(sport) and _port_is_dynamic(dport):
        return "responder"

    return "unknown"


def should_suppress_victim_leg(src: str, dst: str, a: Agg, initiators: Dict[Tuple[int, str, str], Tuple[str, float]]) -> bool:
    if not VICTIM_SAFE_MODE:
        return False
    return infer_flow_role(src, dst, a, initiators) != "initiator"


def is_ambiguous_icmp_leg(src: str, dst: str, a: Agg, initiators: Dict[Tuple[int, str, str], Tuple[str, float]]) -> bool:
    if int(a.top_proto()) != 1:
        return False
    return get_pair_initiator(1, src, dst, initiators) is None


def should_emit_ambiguous_icmp(src: str, dst: str, reverse: Optional['Agg']) -> bool:
    if reverse is None:
        return True
    a_ip, b_ip = sorted((str(src), str(dst)))
    return str(src) == a_ip and str(dst) == b_ip


def remember_attack_pair(
    src: str,
    dst: str,
    a: Agg,
    rule: str,
    recent_pairs: Dict[Tuple[str, str], float],
    now_ts: float,
) -> None:
    recent_pairs[(src, dst)] = now_ts
    drop_pending_observed_brute(src, dst)
    drop_pending_low_value_observed(src, dst, drop_related=True)


def has_recent_named_threat_context(src: str, dst: str, recent_pairs: Dict[Tuple[str, str], float]) -> bool:
    src = str(src)
    dst = str(dst)
    for pair_src, pair_dst in recent_pairs.keys():
        if src == pair_src and dst == pair_dst:
            return True
        if src == pair_dst and dst == pair_src:
            return True
        if src == pair_src or src == pair_dst:
            return True
        if dst == pair_src or dst == pair_dst:
            return True
    return False


def has_window_named_threat_context(src: str, dst: str, named_pairs: set[Tuple[str, str]]) -> bool:
    src = str(src)
    dst = str(dst)
    for pair_src, pair_dst in named_pairs:
        if src == pair_src and dst == pair_dst:
            return True
        if src == pair_dst and dst == pair_src:
            return True
        if src == pair_src or src == pair_dst:
            return True
        if dst == pair_src or dst == pair_dst:
            return True
    return False


def has_exact_named_threat_pair(src: str, dst: str, pairs) -> bool:
    src = str(src)
    dst = str(dst)
    for pair_src, pair_dst in pairs:
        if src == pair_src and dst == pair_dst:
            return True
        if src == pair_dst and dst == pair_src:
            return True
    return False


def should_suppress_unknown_console_in_attack_context(
    src: str,
    a: "Agg",
    attack_score,
    malware_score,
    named_sources: set[str],
    named_ports_by_src: Dict[str, set[int]],
) -> bool:
    src_key = str(src)
    if src_key not in named_sources:
        return False

    top_dp = int(a.top_dport())
    named_ports = named_ports_by_src.get(src_key, set())
    if named_ports and top_dp in named_ports:
        return False

    if top_dp in (BACKDOOR_PORTS | MINER_PORTS):
        return False

    attack_value = _optional_float(attack_score)
    malware_value = _optional_float(malware_score)
    if attack_value is not None and attack_value >= UNKNOWN_OBSERVED_MIN_ATTACK_SCORE:
        return False
    if malware_value is not None and malware_value >= UNKNOWN_OBSERVED_MIN_MALWARE_SCORE:
        return False
    max_score = max(
        attack_value if attack_value is not None else 0.0,
        malware_value if malware_value is not None else 0.0,
    )
    if max_score >= UNKNOWN_OBSERVED_STRONG_SCORE:
        return False

    if int(a.uniq_dports()) >= UNKNOWN_OBSERVED_MIN_UNIQ_DPORTS:
        return False
    if int(a.flows) >= UNKNOWN_OBSERVED_MIN_FLOWS:
        return False
    if int(a.s_bytes) >= UNKNOWN_OBSERVED_MIN_SBYTES:
        return False

    return True


def prune_recent_pairs(recent_pairs: Dict[Tuple[str, str], float], now_ts: float) -> None:
    stale = [k for k, ts in recent_pairs.items() if (now_ts - ts) > REVERSE_SUPPRESS_SEC]
    for k in stale:
        recent_pairs.pop(k, None)


def prune_initiators(initiators: Dict[Tuple[int, str, str], Tuple[str, float]], now_ts: float) -> None:
    stale = [k for k, (_src, ts) in initiators.items() if (now_ts - ts) > INITIATOR_TTL_SEC]
    for k in stale:
        initiators.pop(k, None)


def prune_conntrack_cache(cache: Dict[Tuple[int, str, str], Tuple[Optional[str], float]], now_ts: float) -> None:
    stale = [k for k, (_value, ts) in cache.items() if (now_ts - ts) > CONNTRACK_LOOKUP_TTL_SEC]
    for k in stale:
        cache.pop(k, None)


STATE_TTL_SEC = max(WINDOW_SEC * 30, 900)


def prune_history(history: Dict[Tuple[str, str], deque], now_ts: float) -> None:
    stale = []
    for key, entries in history.items():
        while entries and (now_ts - entries[0][0]) > STATE_TTL_SEC:
            entries.popleft()
        if not entries:
            stale.append(key)
    for key in stale:
        history.pop(key, None)


def prune_recent_unblocked(now_ts: float) -> None:
    stale = [ip for ip, ts in recent_unblocked.items() if (now_ts - ts) > UNBLOCK_COOLDOWN_SEC]
    for ip in stale:
        recent_unblocked.pop(ip, None)
        recent_unblocked_needs_reset.pop(ip, None)


def in_unblock_grace(src: str, now_ts: float) -> bool:
    ts = recent_unblocked.get(src)
    if ts is None:
        return False
    return (now_ts - ts) < UNBLOCK_COOLDOWN_SEC


def clear_src_runtime_state(src: str,
                            aggs: Dict[Tuple[str, str], 'Agg'],
                            history: Dict[Tuple[str, str], deque],
                            consecutive_hits: Dict[Tuple[str, str], int],
                            recent_pairs: Dict[Tuple[str, str], float]) -> None:
    pair_keys = [key for key in aggs.keys() if src in key]
    for key in pair_keys:
        aggs.pop(key, None)

    hist_keys = [key for key in history.keys() if src in key]
    for key in hist_keys:
        history.pop(key, None)

    hit_keys = [key for key in consecutive_hits.keys() if key[0] == src]
    for key in hit_keys:
        consecutive_hits.pop(key, None)

    recent_keys = [key for key in recent_pairs.keys() if src in key]
    for key in recent_keys:
        recent_pairs.pop(key, None)

    ema_keys = [key for key in _ema_scores.keys() if key[0] == src]
    for key in ema_keys:
        _ema_scores.pop(key, None)
        _ema_last_seen.pop(key, None)

    display_keys = [key for key in _ssh_display_scores.keys() if key[0] == src]
    for key in display_keys:
        _ssh_display_scores.pop(key, None)
        _ssh_display_last_seen.pop(key, None)

    pending_keys = [key for key in _pending_observed_brute_events.keys() if key[0] == src]
    for key in pending_keys:
        _pending_observed_brute_events.pop(key, None)

    pending_low_value_keys = [key for key in _pending_low_value_observed_events.keys() if key[0] == src]
    for key in pending_low_value_keys:
        _pending_low_value_observed_events.pop(key, None)


# ===================== Smoothing =====================
ENABLE_SCORE_SMOOTHING = True
SCORE_SMOOTH_ALPHA = 0.35
_ema_scores: Dict[Tuple[str, str], Tuple[float, float]] = {}
_ema_last_seen: Dict[Tuple[str, str], float] = {}
SSH_DISPLAY_SCORE_STICKY_SEC = max(WINDOW_SEC * 2, 45)
SSH_DISPLAY_SCORE_RISE_ALPHA = 0.55
SSH_DISPLAY_SCORE_FALL_ALPHA = 0.18
_ssh_display_scores: Dict[Tuple[str, str], float] = {}
_ssh_display_last_seen: Dict[Tuple[str, str], float] = {}


def prune_ema_scores(now_ts: float) -> None:
    stale = [key for key, ts in _ema_last_seen.items() if (now_ts - ts) > STATE_TTL_SEC]
    for key in stale:
        _ema_last_seen.pop(key, None)
        _ema_scores.pop(key, None)


def prune_ssh_display_scores(now_ts: float) -> None:
    stale = [key for key, ts in _ssh_display_last_seen.items() if (now_ts - ts) > SSH_DISPLAY_SCORE_STICKY_SEC]
    for key in stale:
        _ssh_display_last_seen.pop(key, None)
        _ssh_display_scores.pop(key, None)


def apply_smoothing(src: str, rule: str, atk: float, mal: float) -> Tuple[float, float]:
    if not ENABLE_SCORE_SMOOTHING:
        return atk, mal
    if rule == "RANSOMWARE_PRECHECK":
        return atk, mal
    key = (src, rule)
    _ema_last_seen[key] = time.time()
    prev = _ema_scores.get(key)
    if prev is None:
        _ema_scores[key] = (atk, mal)
        return atk, mal
    pa, pm = prev
    a = float(SCORE_SMOOTH_ALPHA)
    sa = (a * atk) + ((1.0 - a) * pa)
    sm = (a * mal) + ((1.0 - a) * pm)
    _ema_scores[key] = (sa, sm)
    return sa, sm


def stabilize_display_score(src: str, rule: str, atk, now_ts: Optional[float] = None):
    if rule != "SSH_BRUTE_FORCE" or atk in (None, ""):
        return atk
    now_val = float(now_ts or time.time())
    key = (str(src), str(rule))
    current = float(atk)
    prev = _ssh_display_scores.get(key)
    prev_ts = _ssh_display_last_seen.get(key)
    if prev is None or prev_ts is None or (now_val - prev_ts) > SSH_DISPLAY_SCORE_STICKY_SEC:
        stable = current
    else:
        alpha = SSH_DISPLAY_SCORE_RISE_ALPHA if current >= prev else SSH_DISPLAY_SCORE_FALL_ALPHA
        stable = (alpha * current) + ((1.0 - alpha) * prev)
    stable = max(0.0, min(1.0, float(stable)))
    _ssh_display_scores[key] = stable
    _ssh_display_last_seen[key] = now_val
    return stable


def calibrated_exp_score(raw_score: float, threshold: float, raw_pass_score: float) -> float:
    raw = min(max(float(raw_score), 0.0), 1.0)
    thr = min(max(float(threshold), 1e-6), 0.999999)
    pass_raw = max(float(raw_pass_score), 1e-6)
    scale = -math.log(1.0 - thr) / pass_raw
    return 1.0 - math.exp(-scale * raw)


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


# ===================== Logging =====================
def _write_csv_header(path: str) -> None:
    ensure_parent_dir(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_COLUMNS)


def _migrate_csv_schema(path: str) -> None:
    ensure_parent_dir(path)
    rows = []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames:
                rows = list(reader)
    except Exception:
        rows = []

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            out = {}
            for col in CSV_COLUMNS:
                default = "0" if col in {"dpkts", "dbytes"} else ""
                out[col] = row.get(col, default)
            writer.writerow(out)


def init_csv(path: str):
    ensure_parent_dir(path)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        try:
            with open(path, newline="", encoding="utf-8") as f:
                first_row = next(csv.reader(f), [])
        except Exception:
            first_row = []
        if first_row == CSV_COLUMNS:
            return
        _migrate_csv_schema(path)
        return
    _write_csv_header(path)


def _fmt_optional_float(value, digits: int) -> str:
    if value in (None, ""):
        return ""
    try:
        return f"{float(value):.{digits}f}"
    except Exception:
        return ""


def score_text(value, digits: int = 3) -> str:
    rendered = _fmt_optional_float(value, digits)
    return rendered if rendered else "-"


def configure_console_streams() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(line_buffering=True, write_through=True)
        except Exception:
            continue


def disable_windows_quick_edit() -> None:
    if os.name != "nt":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        stdin_handle = kernel32.GetStdHandle(-10)
        if stdin_handle in (0, -1):
            return
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(stdin_handle, ctypes.byref(mode)) == 0:
            return
        ENABLE_QUICK_EDIT_MODE = 0x0040
        ENABLE_EXTENDED_FLAGS = 0x0080
        new_mode = (mode.value | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE
        kernel32.SetConsoleMode(stdin_handle, new_mode)
    except Exception:
        return


def build_event_id(ts_text: str, category: str, rule: str, src: str, dst: str) -> str:
    return f"{ts_text}|{category}|{rule}|{src}|{dst}|{uuid.uuid4().hex[:12]}"


def _optional_float(value):
    if value in (None, ""):
        return None
    try:
        return float(value)
    except Exception:
        return None


@dataclass
class PendingObservedEvent:
    emit_at: float
    pretty_text: str
    evt: dict
    category: str
    rule: str
    src: str
    dst: str
    row_feat: Optional[Dict[str, float]]


_pending_observed_brute_events: Dict[Tuple[str, str], PendingObservedEvent] = {}
_pending_low_value_observed_events: Dict[Tuple[str, str, str], PendingObservedEvent] = {}
_shadow_online_cache_lock = threading.Lock()
_shadow_online_cache = {
    "attack_stamp": None,
    "malware_stamp": None,
    "models": None,
    "error": None,
}


def _shadow_model_stamp(path) -> float | None:
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def load_shadow_online_models_optional(force: bool = False):
    attack_stamp = _shadow_model_stamp(ATTACK_ONLINE_MODEL_PATH)
    malware_stamp = _shadow_model_stamp(MALWARE_ONLINE_MODEL_PATH)
    with _shadow_online_cache_lock:
        if (
            not force
            and _shadow_online_cache["attack_stamp"] == attack_stamp
            and _shadow_online_cache["malware_stamp"] == malware_stamp
        ):
            return _shadow_online_cache["models"]
    try:
        models = load_online_models()
        error = None
    except MissingRiverDependency as exc:
        models = None
        error = str(exc)
    except Exception as exc:
        models = None
        error = str(exc)

    if models is not None:
        attack_stamp = _shadow_model_stamp(ATTACK_ONLINE_MODEL_PATH)
        malware_stamp = _shadow_model_stamp(MALWARE_ONLINE_MODEL_PATH)

    with _shadow_online_cache_lock:
        previous_error = _shadow_online_cache["error"]
        _shadow_online_cache["attack_stamp"] = attack_stamp
        _shadow_online_cache["malware_stamp"] = malware_stamp
        _shadow_online_cache["models"] = models
        _shadow_online_cache["error"] = error

    if error and error != previous_error:
        print(f"[!] ShadowOnline disabled: {error}")
    return models


def score_shadow_event(row_feat: Optional[Dict[str, float]]):
    online_models = load_shadow_online_models_optional()
    if online_models is None or not row_feat:
        return "", ""
    try:
        shadow_atk, shadow_mal = predict_online_scores(online_models, row_feat)
        return float(shadow_atk), float(shadow_mal)
    except Exception:
        return "", ""


def get_live_decision_source() -> str:
    try:
        state = load_control_state()
        source = str(state.get("liveDecisionSource", "production") or "production").strip().lower()
        return "shadow" if source == "shadow" else "production"
    except Exception:
        return "production"


def capture_online_sample_payload(
    payload: dict,
    category: str,
    rule: str,
    src: str,
    dst: str,
    row_feat: Optional[Dict[str, float]] = None,
) -> None:
    if row_feat is None or category not in {"ATTACK", "MALWARE", "OBSERVED"}:
        return
    if payload.get("decision") == "SUPPRESSED_VICTIM_LEG":
        return
    try:
        control_state = load_control_state()
    except Exception:
        control_state = {"shadowCaptureEnabled": True}
    if not control_state.get("shadowCaptureEnabled", True):
        return

    try:
        sample = OnlineSample(
            event_id=str(payload["event_id"]),
            ts=str(payload.get("ts", "")),
            src=str(payload.get("src", src)),
            dst=str(payload.get("dst", dst)),
            rule=str(payload.get("rule", rule)),
            category=category,
            features={str(k): float(v) for k, v in row_feat.items()},
            xgb_attack_score=_optional_float(payload.get("prod_atk", payload.get("atk"))),
            xgb_malware_score=_optional_float(payload.get("prod_mal", payload.get("mal"))),
            current_attack_score=_optional_float(payload.get("atk", payload.get("prod_atk"))),
            current_malware_score=_optional_float(payload.get("mal", payload.get("prod_mal"))),
            online_attack_score=_optional_float(payload.get("shadow_atk")),
            online_malware_score=_optional_float(payload.get("shadow_mal")),
            decision=str(payload.get("decision", "")),
        )
        ONLINE_STORE.append(sample)
    except Exception as exc:
        print(f"[shadow-capture] {exc}")


def finalize_event(evt: dict, category: str, rule: str, src: str, dst: str, row_feat: Optional[Dict[str, float]] = None):
    payload = dict(evt)
    payload.setdefault("event_id", build_event_id(str(payload.get("ts", "")), category, rule, src, dst))
    payload.setdefault("shadow_atk", "")
    payload.setdefault("shadow_mal", "")

    log_csv(payload, CSV_LOG)
    log_jsonl(payload, JSONL_LOG)
    capture_online_sample_payload(payload, category, rule, src, dst, row_feat)


def build_honeypot_sample_payload(
    action: str,
    rule: str,
    category: str,
    src: str,
    src_mac: str,
    dst: str,
    dst_mac: str,
    a: "Agg",
    atk,
    mal,
    shadow_atk,
    shadow_mal,
    decision_source: str,
    row_feat: Optional[Dict[str, float]] = None,
    extra: Optional[Dict[str, object]] = None,
) -> dict:
    payload = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "action": str(action),
        "rule": str(rule),
        "category": str(category),
        "src_ip": str(src),
        "dst_ip": str(dst),
        "src_mac": str(src_mac or "??"),
        "dst_mac": str(dst_mac or "??"),
        "attack_score": _optional_float(atk),
        "malware_score": _optional_float(mal),
        "shadow_attack_score": _optional_float(shadow_atk),
        "shadow_malware_score": _optional_float(shadow_mal),
        "decision_source": str(decision_source or "production"),
        "window_seconds": WINDOW_SEC,
        "aggregate": {
            "flows": int(a.flows),
            "spkts": int(a.s_pkts),
            "dpkts": int(a.d_pkts),
            "sbytes": int(a.s_bytes),
            "dbytes": int(a.d_bytes),
            "uniq_dports": int(a.uniq_dports()),
            "proto": int(a.top_proto()),
            "top_dport": int(a.top_dport()),
        },
        "features": {str(k): float(v) for k, v in (row_feat or {}).items()},
    }
    if extra:
        payload.update(extra)
    return payload


def log_honeypot_sample(payload: dict) -> None:
    ensure_parent_dir(HONEYPOT_SAMPLES_LOG)
    with exclusive_lock(HONEYPOT_SAMPLES_LOCK):
        with open(HONEYPOT_SAMPLES_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def build_block_reason(rule: str, atk, mal) -> str:
    parts = [rule]
    if rule in MAL_BEHAVIORS:
        if mal not in (None, ""):
            parts.append(f"mal={score_text(mal)}")
    else:
        parts.append(f"atk={score_text(atk)}")
    return " ".join(parts)


def log_csv(evt: dict, path: str):
    ensure_parent_dir(path)
    row = {col: evt.get(col, "") for col in CSV_COLUMNS}
    row["dpkts"] = row.get("dpkts", 0)
    row["dbytes"] = row.get("dbytes", 0)
    row["atk"] = _fmt_optional_float(evt.get("atk", ""), 6)
    row["mal"] = _fmt_optional_float(evt.get("mal", ""), 6)
    row["shadow_atk"] = _fmt_optional_float(evt.get("shadow_atk", ""), 6)
    row["shadow_mal"] = _fmt_optional_float(evt.get("shadow_mal", ""), 6)
    row["atk_thr"] = _fmt_optional_float(evt.get("atk_thr", ""), 3)
    row["mal_thr"] = _fmt_optional_float(evt.get("mal_thr", ""), 3)
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writerow(row)


def log_jsonl(evt: dict, path: str):
    ensure_parent_dir(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(evt, ensure_ascii=False) + "\n")


def write_runtime_metrics(path: str, payload: dict):
    ensure_parent_dir(path)
    with exclusive_lock(RUNTIME_METRICS_LOCK):
        resilient_write_text(path, json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def append_runtime_metrics_history(path: str, payload: dict, retention_sec: int, now_ts: float | None = None):
    ensure_parent_dir(path)
    _ = retention_sec, now_ts
    line = json.dumps(payload, ensure_ascii=False) + "\n"
    with exclusive_lock(RUNTIME_METRICS_HISTORY_LOCK):
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)


# ===================== Pretty print =====================
def render_pretty_block(rule: str, src: str, src_mac: str, dst: str, dst_mac: str,
                        a: 'Agg', atk, mal, atk_thr, mal_thr,
                        decision: str, extra: str = "", directional: bool = True) -> str:
    if not PRINT_PRETTY_BLOCK:
        return ""

    arrow = "->" if directional else "<->"
    category = event_category_for_rule(rule)
    banner = "OBSERVED" if category == "OBSERVED" else "ALERT"

    if not PRINT_ALERT_DETAILS:
        if category == "ATTACK":
            if atk in (None, ""):
                return f"[{decision}] {rule} src={src}({src_mac}) {arrow} dst={dst}({dst_mac}) | router-log confirmed{extra}\n"
            return f"[{decision}] {rule} src={src}({src_mac}) {arrow} dst={dst}({dst_mac}) | attack={score_text(atk)}/{score_text(atk_thr)}{extra}\n"
        if category == "MALWARE":
            return f"[{decision}] {rule} src={src}({src_mac}) {arrow} dst={dst}({dst_mac}) | malware={score_text(mal)}/{score_text(mal_thr)}{extra}\n"
        return f"[{decision}] {rule} src={src}({src_mac}) {arrow} dst={dst}({dst_mac}) | observed traffic{extra}\n"

    lines = []
    lines.append(f"[{banner}] {rule} window={WINDOW_SEC}s")
    if directional:
        lines.append(f"src={src}({src_mac}) {arrow} dst={dst}({dst_mac})")
    else:
        lines.append(f"pair={src}({src_mac}) {arrow} {dst}({dst_mac})")
    lines.append(f"flows={a.flows} Spkts={a.s_pkts} Dpkts={a.d_pkts} sbytes={a.s_bytes} dbytes={a.d_bytes} uniq_dports={a.uniq_dports()} proto={a.top_proto()} top_dport={a.top_dport()}")

    if category == "ATTACK":
        if atk in (None, ""):
            lines.append("[INFO] router-log confirmed (AI score pending)")
        else:
            lines.append(f"[AI] attack={score_text(atk)} thr={score_text(atk_thr)}")
    elif category == "MALWARE":
        lines.append(f"[AI] malware={score_text(mal)} thr={score_text(mal_thr)}")
    else:
        lines.append("[INFO] observed traffic (no AI scoring)")

    lines.append(f"[ACTION] {decision}{extra}")
    return "\n".join(lines) + "\n"


def pretty_block(rule: str, src: str, src_mac: str, dst: str, dst_mac: str,
                 a: 'Agg', atk, mal, atk_thr, mal_thr,
                 decision: str, extra: str = "", directional: bool = True):
    rendered = render_pretty_block(rule, src, src_mac, dst, dst_mac, a, atk, mal, atk_thr, mal_thr, decision, extra=extra, directional=directional)
    if rendered:
        print(rendered, flush=True)


def queue_pending_observed_brute(emit_at: float, pretty_text: str, evt: dict, category: str, rule: str, src: str, dst: str, row_feat: Optional[Dict[str, float]]) -> None:
    _pending_observed_brute_events[(str(src), str(dst))] = PendingObservedEvent(
        emit_at=emit_at,
        pretty_text=pretty_text,
        evt=dict(evt),
        category=str(category),
        rule=str(rule),
        src=str(src),
        dst=str(dst),
        row_feat=row_feat.copy() if row_feat else None,
    )


def queue_pending_low_value_observed(emit_at: float, pretty_text: str, evt: dict, category: str, rule: str, src: str, dst: str, row_feat: Optional[Dict[str, float]]) -> None:
    _pending_low_value_observed_events[(str(src), str(dst), str(rule))] = PendingObservedEvent(
        emit_at=emit_at,
        pretty_text=pretty_text,
        evt=dict(evt),
        category=str(category),
        rule=str(rule),
        src=str(src),
        dst=str(dst),
        row_feat=row_feat.copy() if row_feat else None,
    )


def drop_pending_observed_brute(src: str, dst: str) -> None:
    _pending_observed_brute_events.pop((str(src), str(dst)), None)


def drop_pending_low_value_observed(src: str, dst: str, drop_related: bool = False) -> None:
    src = str(src)
    dst = str(dst)
    stale_keys = []
    for key in _pending_low_value_observed_events.keys():
        key_src, key_dst, _key_rule = key
        if (key_src == src and key_dst == dst) or (drop_related and (key_src == src or key_dst == dst or key_src == dst or key_dst == src)):
            stale_keys.append(key)
    for key in stale_keys:
        _pending_low_value_observed_events.pop(key, None)


def flush_pending_observed_brute(now_ts: float, force: bool = False) -> None:
    due_keys = [
        key for key, pending in _pending_observed_brute_events.items()
        if force or pending.emit_at <= now_ts
    ]
    for key in due_keys:
        pending = _pending_observed_brute_events.pop(key, None)
        if pending is None:
            continue
        if pending.pretty_text:
            print(pending.pretty_text, flush=True)
        finalize_event(pending.evt, pending.category, pending.rule, pending.src, pending.dst, pending.row_feat)


def flush_pending_low_value_observed(now_ts: float, force: bool = False) -> None:
    due_keys = [
        key for key, pending in _pending_low_value_observed_events.items()
        if force or pending.emit_at <= now_ts
    ]
    for key in due_keys:
        pending = _pending_low_value_observed_events.pop(key, None)
        if pending is None:
            continue
        if pending.pretty_text:
            print(pending.pretty_text, flush=True)
        finalize_event(pending.evt, pending.category, pending.rule, pending.src, pending.dst, pending.row_feat)


# ===================== Unblock watcher (Fix fake UNBLOCK) =====================
def unblock_watcher(stop_evt: threading.Event, ssh: MikroTikSSH,
                    muted: Dict[Tuple[str, str], bool], lock: threading.Lock):
    miss_count: Dict[Tuple[str, str], int] = {}

    while not stop_evt.is_set():
        time.sleep(CHECK_UNBLOCK_EVERY_SEC)
        with lock:
            keys = list(muted.keys())

        for (src, dst) in keys:
            try:
                found, ok = is_in_list(ssh, src, force_refresh=True)
            except Exception:
                continue

            # 闂佸搫琚崕鎾敋濡や礁绶為弶鍫亯琚濋梺鎸庣⊕閻喚绮径鎰；婵﹩鍓欓弸鈧柣搴ゎ潐閻旑剛妲愬▎鎾寸劶闁割煈鍠栫敮鎶芥煕?UNBLOCK闂?
            if not ok:
                continue

            if found:
                miss_count[(src, dst)] = 0
                continue

            miss_count[(src, dst)] = miss_count.get((src, dst), 0) + 1
            if miss_count[(src, dst)] >= 2:
                with lock:
                    muted.pop((src, dst), None)
                    recent_unblocked[src] = time.time()
                    recent_unblocked_needs_reset[src] = True
                _set_block_list_cache(src, False)
                miss_count.pop((src, dst), None)

                if PRINT_UNBLOCK_EVENTS:
                    print(f"[UNBLOCK] {src} (expired/removed from address-list)")
                    print()


def honeypot_release_watcher(
    stop_evt: threading.Event,
    ssh: MikroTikSSH,
    redirected: Dict[Tuple[str, str], bool],
    lock: threading.Lock,
    router_log_seen_ssh_failures: Optional[Dict[str, float]] = None,
    router_log_seen_lock: Optional[threading.Lock] = None,
):
    miss_count: Dict[Tuple[str, str], int] = {}

    while not stop_evt.is_set():
        time.sleep(CHECK_UNBLOCK_EVERY_SEC)
        with lock:
            keys = list(redirected.keys())

        for (src, dst) in keys:
            try:
                found, ok = is_in_address_list(ssh, HONEYPOT_BRUTEFORCE_LIST, src)
            except Exception:
                continue

            if not ok:
                continue

            if found:
                miss_count[(src, dst)] = 0
                continue

            miss_count[(src, dst)] = miss_count.get((src, dst), 0) + 1
            if miss_count[(src, dst)] >= 2:
                with lock:
                    redirected.pop((src, dst), None)
                    recent_unblocked[src] = time.time()
                    recent_unblocked_needs_reset[src] = True
                _clear_recent_honeypot_redirect(src)
                if router_log_seen_ssh_failures is not None:
                    if router_log_seen_lock is not None:
                        with router_log_seen_lock:
                            router_log_seen_ssh_failures[src] = time.time()
                    else:
                        router_log_seen_ssh_failures[src] = time.time()
                miss_count.pop((src, dst), None)

                if PRINT_UNBLOCK_EVENTS:
                    print(f"[HONEYPOT_RELEASED] {src} (removed from {HONEYPOT_BRUTEFORCE_LIST})")
                    print()


# ===================== MAIN =====================
def main():
    configure_console_streams()
    disable_windows_quick_edit()
    init_csv(CSV_LOG)

    if PRINT_START_BANNER:
        print("[+] AI-NIDPS booting...", flush=True)
        print(f"[+] NetFlow v9 UDP {NETFLOW_PORT} | window={WINDOW_SEC}s", flush=True)
        print("[+] Initializing router context, MAC resolver, and models...", flush=True)

    ssh = MikroTikSSH(ROUTER_IP, ROUTER_USER, ROUTER_PASS)
    router_log_ssh = MikroTikSSH(ROUTER_IP, ROUTER_USER, ROUTER_PASS)
    try:
        ensure_drop_rules(ssh)
    except Exception:
        pass

    try:
        router_mac = get_router_mac(ssh)
    except Exception:
        router_mac = "??"

    arp_thread = None
    if MAC_RESOLVE_MODE == "table":
        arp_thread = ArpResolver(ROUTER_IP, ROUTER_USER, ROUTER_PASS, refresh_sec=ARP_REFRESH_SEC, debug=ARP_DEBUG)
        arp_thread.refresh_now()
        arp_thread.start()
        macr = MacResolverTable(
            arp_thread,
            ttl_sec=ARP_CACHE_TTL_SEC,
            miss_ttl_sec=ARP_NEGATIVE_CACHE_TTL_SEC,
            refresh_on_miss_min_sec=ARP_REFRESH_ON_MISS_MIN_SEC,
        )
    else:
        macr = MacResolverSingle(ssh, ttl_sec=ARP_CACHE_TTL_SEC)

    model_attack, feats_attack = load_model_bundle(MODEL_ATTACK_PATH)
    model_mal, feats_mal = load_model_bundle(MODEL_MALWARE_PATH)
    shadow_models = load_shadow_online_models_optional(force=True)

    if PRINT_START_BANNER:
        print("[+] AI-NIDPS started", flush=True)
        if shadow_models is not None:
            try:
                capture_state = load_control_state()
            except Exception:
                capture_state = {"shadowCaptureEnabled": True}
            capture_label = "enabled" if capture_state.get("shadowCaptureEnabled", True) else "paused"
            print(f"[+] ShadowOnline={capture_label} | Store={ONLINE_STORE.path}", flush=True)
        else:
            print("[+] ShadowOnline=disabled", flush=True)
        print(flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((NETFLOW_LISTEN_IP, NETFLOW_PORT))
    sock.settimeout(1.0)

    parser = NetFlowV9Parser()

    aggs: Dict[Tuple[str, str], Agg] = {}
    history: Dict[Tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=30))

    consecutive_hits: Dict[Tuple[str, str], int] = defaultdict(int)
    recent_attack_pairs: Dict[Tuple[str, str], float] = {}
    pair_initiators: Dict[Tuple[int, str, str], Tuple[str, float]] = {}
    conntrack_initiators: Dict[Tuple[int, str, str], Tuple[Optional[str], float]] = {}

    muted: Dict[Tuple[str, str], bool] = {}
    muted_lock = threading.Lock()
    honeypot_redirected: Dict[Tuple[str, str], bool] = {}
    honeypot_lock = threading.Lock()
    fast_ssh_honeypot_eval: Dict[Tuple[str, str], float] = {}
    router_log_seen_ssh_failures: Dict[str, float] = {}
    router_log_seen_lock = threading.Lock()
    stop_evt = threading.Event()

    def mark_router_log_seen(src: str, seen_ts: Optional[float] = None) -> None:
        with router_log_seen_lock:
            router_log_seen_ssh_failures[str(src)] = float(seen_ts or time.time())

    def get_router_log_seen(src: str) -> float:
        with router_log_seen_lock:
            return float(router_log_seen_ssh_failures.get(str(src), 0.0))

    if MUTE_UNTIL_UNBLOCK:
        threading.Thread(target=unblock_watcher, args=(stop_evt, ssh, muted, muted_lock), daemon=True).start()
    threading.Thread(
        target=honeypot_release_watcher,
        args=(stop_evt, ssh, honeypot_redirected, honeypot_lock, router_log_seen_ssh_failures, router_log_seen_lock),
        daemon=True,
    ).start()

    window_start = time.time()

    recv_pkts = 0
    parsed_flows = 0
    last_hb = time.time()
    last_runtime_metrics_write = 0.0
    last_runtime_metrics_packets = 0
    last_runtime_metrics_flows = 0

    def maybe_fast_redirect_ssh_honeypot(src: str, dst: str, now_ts: float) -> bool:
        key = (str(src), str(dst))
        if _was_recently_honeypot_redirected(src, now_ts):
            return True
        last_eval = fast_ssh_honeypot_eval.get(key, 0.0)
        if (now_ts - last_eval) < SSH_HONEYPOT_FASTPATH_RECHECK_SEC:
            return False
        fast_ssh_honeypot_eval[key] = now_ts
        with honeypot_lock:
            if key in honeypot_redirected:
                return True

        if dst not in ROUTER_INTERFACE_IPS:
            return False
        if is_trusted_ssh_source(src):
            return False
        if should_ignore_flow_scope(src, dst):
            return False

        with muted_lock:
            if (src, dst) in muted:
                return False

        try:
            found_blocked, ok_blocked = is_in_list(ssh, src)
        except Exception:
            found_blocked, ok_blocked = (False, False)
        if ok_blocked and found_blocked:
            return False

        try:
            in_honeypot, honeypot_ok = is_in_address_list(ssh, HONEYPOT_BRUTEFORCE_LIST, src)
        except Exception:
            in_honeypot, honeypot_ok = (False, False)
        if honeypot_ok and in_honeypot:
            _mark_recent_honeypot_redirect(src, now_ts)
            mark_router_log_seen(src)
            drop_pending_observed_brute(src, dst)
            drop_pending_low_value_observed(src, dst, drop_related=True)
            clear_honeypot_redirect_connections(ssh, src)
            aggs.pop((src, dst), None)
            history.pop((src, dst), None)
            consecutive_hits.pop((src, "SSH_BRUTE_FORCE"), None)
            with honeypot_lock:
                honeypot_redirected[key] = True
            return True

        a = aggs.get((src, dst))
        router_fail_count = 0
        try:
            router_fail_count = get_router_failed_login_count(
                ssh,
                src,
                "ssh",
                force_refresh=False,
            )
        except Exception:
            router_fail_count = 0
        fast_confirmed = router_fail_count >= SSH_HONEYPOT_FASTPATH_MIN_ROUTER_FAILS

        if fast_confirmed:
            src_mac = resolve_endpoint_mac_strict_retry(src, macr, router_mac)
            dst_mac = resolve_endpoint_mac_strict(dst, macr, router_mac)
            agg = build_router_log_ssh_display_agg(a, router_fail_count)
            row_feat = build_row_features(WINDOW_SEC, agg)
            shadow_atk, shadow_mal = score_shadow_event(row_feat)
            decision_source = get_live_decision_source()
            prod_atk = float(predict_probs(model_attack, feats_attack, row_feat).get(1, 0.0))
            atk = prod_atk
            shadow_attack_value = _optional_float(shadow_atk)
            if decision_source == "shadow" and shadow_attack_value is not None:
                atk = float(shadow_attack_value)
            else:
                decision_source = "production"
            atk, _ignored_mal = apply_smoothing(src, "SSH_BRUTE_FORCE", atk, 0.0)
            atk_thr = THR_ATTACK.get("SSH_BRUTE_FORCE", THR_ATTACK_DEFAULT)
            display_atk = stabilize_display_score(src, "SSH_BRUTE_FORCE", atk, now_ts)
            display_atk_thr = atk_thr

            redirect_result = add_ip_to_list(
                ssh,
                src,
                HONEYPOT_BRUTEFORCE_LIST,
                comment="AI:SSH_BRUTE_FORCE",
            )
            if redirect_result not in {"added", "added_unverified", "already_listed"}:
                return False

            _mark_recent_honeypot_redirect(src, now_ts)
            mark_router_log_seen(src)
            drop_pending_observed_brute(src, dst)
            drop_pending_low_value_observed(src, dst, drop_related=True)
            clear_honeypot_redirect_connections(ssh, src)
            remember_attack_pair(src, dst, agg, "SSH_BRUTE_FORCE", recent_attack_pairs, now_ts)
            aggs.pop((src, dst), None)
            history.pop((src, dst), None)
            consecutive_hits.pop((src, "SSH_BRUTE_FORCE"), None)
            with honeypot_lock:
                honeypot_redirected[key] = True

            if redirect_result == "already_listed":
                return True

            should_emit_event = _reserve_ssh_honeypot_event(src, dst, now_ts)
            if should_emit_event:
                pretty_block(
                    "SSH_BRUTE_FORCE",
                    src,
                    src_mac,
                    dst,
                    dst_mac,
                    agg,
                    display_atk,
                    "",
                    display_atk_thr,
                    "",
                    "REDIRECTED_TO_HONEYPOT",
                    extra=f" {src} list={HONEYPOT_BRUTEFORCE_LIST} (fast-confirm {router_fail_count} fails)",
                )

            evt = {
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "category": "ATTACK",
                "rule": "SSH_BRUTE_FORCE",
                "src": src,
                "src_mac": src_mac,
                "dst": dst,
                "dst_mac": dst_mac,
                "flows": agg.flows,
                "spkts": agg.s_pkts,
                "dpkts": agg.d_pkts,
                "sbytes": agg.s_bytes,
                "dbytes": agg.d_bytes,
                "uniq_dports": agg.uniq_dports(),
                "proto": agg.top_proto(),
                "top_dport": agg.top_dport(),
                "atk": display_atk,
                "prod_atk": prod_atk,
                "mal": "",
                "prod_mal": "",
                "shadow_atk": shadow_atk,
                "shadow_mal": shadow_mal,
                "atk_thr": display_atk_thr,
                "mal_thr": "",
                "decision_source": f"router_confirm_{decision_source}",
                "decision": "REDIRECTED_TO_HONEYPOT",
            }
            if should_emit_event:
                finalize_event(evt, "ATTACK", "SSH_BRUTE_FORCE", src, dst, row_feat)

            try:
                log_honeypot_sample(
                    build_honeypot_sample_payload(
                        action="REDIRECTED_TO_HONEYPOT",
                        rule="SSH_BRUTE_FORCE",
                        category="ATTACK",
                        src=src,
                        src_mac=src_mac,
                        dst=dst,
                        dst_mac=dst_mac,
                        a=agg,
                        atk=atk,
                        mal="",
                        shadow_atk=shadow_atk,
                        shadow_mal=shadow_mal,
                        decision_source=f"router_confirm_{decision_source}",
                        row_feat=row_feat,
                        extra={
                            "router_address_list": HONEYPOT_BRUTEFORCE_LIST,
                            "router_failures": int(router_fail_count),
                            "fast_confirm": True,
                        },
                    )
                )
            except Exception as exc:
                print(f"[honeypot-sample] {exc}")
            return True

        if a is None:
            return False
        else:
            if int(a.top_proto()) != 6 or int(a.top_dport()) != 22:
                return False
            else:
                reverse_a = aggs.get((dst, src))
                a_eval = build_eval_agg(a, reverse_a)

        if (
            a_eval.flows < SSH_HONEYPOT_FASTPATH_MIN_FLOWS
            or a_eval.s_pkts < SSH_HONEYPOT_FASTPATH_MIN_PKTS
            or a_eval.uniq_dports() > BRUTE_MAX_UNIQ_DPORTS
            or a_eval.s_bytes > BRUTE_MAX_SBYTES
        ):
            return False
        rule = "SSH_BRUTE_FORCE"

        row_feat = build_row_features(WINDOW_SEC, a_eval)
        shadow_atk, shadow_mal = score_shadow_event(row_feat)
        decision_source = get_live_decision_source()
        prod_atk = float(predict_probs(model_attack, feats_attack, row_feat).get(1, 0.0))
        atk = prod_atk
        shadow_attack_value = _optional_float(shadow_atk)
        if decision_source == "shadow" and shadow_attack_value is not None:
            atk = float(shadow_attack_value)
        else:
            decision_source = "production"

        atk, _ignored_mal = apply_smoothing(src, rule, atk, 0.0)
        atk_thr = THR_ATTACK.get(rule, THR_ATTACK_DEFAULT)
        # For router-targeted, untrusted SSH traffic that already matches the
        # brute-force rule on the live aggregate, do not wait for the model
        # score to cross threshold again. This path exists specifically to keep
        # SSH honeypot redirection responsive even when RouterOS log
        # confirmation is delayed or sparse.
        display_atk = stabilize_display_score(src, rule, max(float(atk), float(atk_thr)), now_ts)
        display_atk_thr = atk_thr

        src_mac = resolve_endpoint_mac_strict_retry(src, macr, router_mac)
        dst_mac = resolve_endpoint_mac_strict(dst, macr, router_mac)
        redirect_result = add_ip_to_list(
            ssh,
            src,
            HONEYPOT_BRUTEFORCE_LIST,
            comment=f"AI:{rule}",
        )
        if redirect_result not in {"added", "added_unverified", "already_listed"}:
            return False

        _mark_recent_honeypot_redirect(src, now_ts)
        mark_router_log_seen(src)
        remember_attack_pair(src, dst, a if a is not None else a_eval, rule, recent_attack_pairs, now_ts)
        drop_pending_observed_brute(src, dst)
        drop_pending_low_value_observed(src, dst, drop_related=True)
        clear_honeypot_redirect_connections(ssh, src)
        aggs.pop((src, dst), None)
        history.pop((src, dst), None)
        consecutive_hits.pop((src, rule), None)
        with honeypot_lock:
            honeypot_redirected[key] = True

        if redirect_result == "already_listed":
            return True

        should_emit_event = _reserve_ssh_honeypot_event(src, dst, now_ts)
        if should_emit_event and (PRINT_BLOCK_EVENTS or PRINT_NONBLOCKED_ALERTS):
            pretty_block(
                rule,
                src,
                src_mac,
                dst,
                dst_mac,
                a_eval,
                display_atk,
                "",
                display_atk_thr,
                "",
                "REDIRECTED_TO_HONEYPOT",
                extra=f" {src} list={HONEYPOT_BRUTEFORCE_LIST} (fast-path)",
            )

        evt = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "category": "ATTACK",
            "rule": rule,
            "src": src,
            "src_mac": src_mac,
            "dst": dst,
            "dst_mac": dst_mac,
            "flows": a_eval.flows,
            "spkts": a_eval.s_pkts,
            "dpkts": a_eval.d_pkts,
            "sbytes": a_eval.s_bytes,
            "dbytes": a_eval.d_bytes,
            "uniq_dports": a_eval.uniq_dports(),
            "proto": a_eval.top_proto(),
            "top_dport": a_eval.top_dport(),
            "atk": display_atk,
            "prod_atk": prod_atk,
            "mal": "",
            "prod_mal": "",
            "shadow_atk": shadow_atk,
            "shadow_mal": shadow_mal,
            "atk_thr": display_atk_thr,
            "mal_thr": "",
            "decision_source": decision_source,
            "decision": "REDIRECTED_TO_HONEYPOT",
        }
        if should_emit_event:
            finalize_event(evt, "ATTACK", rule, src, dst, row_feat)

        try:
            log_honeypot_sample(
                build_honeypot_sample_payload(
                    action="REDIRECTED_TO_HONEYPOT",
                    rule=rule,
                    category="ATTACK",
                    src=src,
                    src_mac=src_mac,
                    dst=dst,
                    dst_mac=dst_mac,
                    a=a_eval,
                    atk=atk,
                    mal="",
                    shadow_atk=shadow_atk,
                    shadow_mal=shadow_mal,
                    decision_source=decision_source,
                    row_feat=row_feat,
                    extra={"router_address_list": HONEYPOT_BRUTEFORCE_LIST, "fast_path": True},
                )
            )
        except Exception as exc:
            print(f"[honeypot-sample] {exc}")
        return True

    def router_log_ssh_honeypot_watcher() -> None:
        while not stop_evt.is_set():
            time.sleep(ROUTER_SSH_HONEYPOT_LOG_WATCHER_POLL_SEC)
            try:
                recent_sources = get_router_failed_login_sources(router_log_ssh, "ssh")
            except Exception:
                continue

            for src, (fail_count, latest_failure_ts) in recent_sources.items():
                _set_router_brute_confirm_cache(src, "ssh", fail_count)
                if fail_count < SSH_HONEYPOT_FASTPATH_MIN_ROUTER_FAILS:
                    continue
                if is_trusted_ssh_source(src):
                    continue
                if not _is_in_monitored_networks(src):
                    continue
                if _was_recently_honeypot_redirected(src, time.time()):
                    mark_router_log_seen(src, latest_failure_ts)
                    continue
                with honeypot_lock:
                    if (src, ROUTER_IP) in honeypot_redirected:
                        mark_router_log_seen(src, latest_failure_ts)
                        continue

                last_seen = get_router_log_seen(src)
                if latest_failure_ts <= last_seen:
                    continue

                try:
                    found_blocked, ok_blocked = is_in_list(router_log_ssh, src)
                except Exception:
                    found_blocked, ok_blocked = (False, False)
                if ok_blocked and found_blocked:
                    mark_router_log_seen(src, latest_failure_ts)
                    continue

                try:
                    in_honeypot, honeypot_ok = is_in_address_list(router_log_ssh, HONEYPOT_BRUTEFORCE_LIST, src)
                except Exception:
                    in_honeypot, honeypot_ok = (False, False)
                if honeypot_ok and in_honeypot:
                    mark_router_log_seen(src, latest_failure_ts)
                    continue

                src_mac = resolve_endpoint_mac_strict_retry(src, macr, router_mac)
                dst_mac = resolve_endpoint_mac_strict(ROUTER_IP, macr, router_mac)
                agg = build_router_log_ssh_display_agg(aggs.get((src, ROUTER_IP)), fail_count)

                row_feat = build_row_features(WINDOW_SEC, agg)
                shadow_atk, shadow_mal = score_shadow_event(row_feat)
                decision_source = get_live_decision_source()
                prod_atk = float(predict_probs(model_attack, feats_attack, row_feat).get(1, 0.0))
                atk = prod_atk
                shadow_attack_value = _optional_float(shadow_atk)
                if decision_source == "shadow" and shadow_attack_value is not None:
                    atk = float(shadow_attack_value)
                else:
                    decision_source = "production"
                atk, _ignored_mal = apply_smoothing(src, "SSH_BRUTE_FORCE", atk, 0.0)
                atk_thr = THR_ATTACK.get("SSH_BRUTE_FORCE", THR_ATTACK_DEFAULT)
                display_atk = stabilize_display_score(src, "SSH_BRUTE_FORCE", atk, latest_failure_ts)
                display_atk_thr = atk_thr

                redirect_result = add_ip_to_list(
                    router_log_ssh,
                    src,
                    HONEYPOT_BRUTEFORCE_LIST,
                    comment="AI:SSH_BRUTE_FORCE",
                )
                if redirect_result not in {"added", "added_unverified", "already_listed"}:
                    continue

                try:
                    blocked_after, blocked_after_ok = is_in_list(router_log_ssh, src, force_refresh=True)
                except Exception:
                    blocked_after, blocked_after_ok = (False, False)
                if blocked_after_ok and blocked_after:
                    try:
                        remove_ip_from_list(router_log_ssh, src, HONEYPOT_BRUTEFORCE_LIST)
                    except Exception:
                        pass
                    with honeypot_lock:
                        honeypot_redirected.pop((src, ROUTER_IP), None)
                    _clear_recent_honeypot_redirect(src)
                    mark_router_log_seen(src, latest_failure_ts)
                    continue

                _mark_recent_honeypot_redirect(src, time.time())
                mark_router_log_seen(src, latest_failure_ts)
                drop_pending_observed_brute(src, ROUTER_IP)
                drop_pending_low_value_observed(src, ROUTER_IP, drop_related=True)
                clear_honeypot_redirect_connections(ssh, src)
                remember_attack_pair(src, ROUTER_IP, agg, "SSH_BRUTE_FORCE", recent_attack_pairs, time.time())
                aggs.pop((src, ROUTER_IP), None)
                history.pop((src, ROUTER_IP), None)
                consecutive_hits.pop((src, "SSH_BRUTE_FORCE"), None)
                with honeypot_lock:
                    honeypot_redirected[(src, ROUTER_IP)] = True

                if redirect_result == "already_listed":
                    continue

                should_emit_event = _reserve_ssh_honeypot_event(src, ROUTER_IP, latest_failure_ts)
                if should_emit_event:
                    pretty_block(
                        "SSH_BRUTE_FORCE",
                        src,
                        src_mac,
                        ROUTER_IP,
                        dst_mac,
                        agg,
                        display_atk,
                        "",
                        display_atk_thr,
                        "",
                        "REDIRECTED_TO_HONEYPOT",
                        extra=f" {src} list={HONEYPOT_BRUTEFORCE_LIST} (router-log watcher {fail_count} fails)",
                    )

                evt = {
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "category": "ATTACK",
                    "rule": "SSH_BRUTE_FORCE",
                    "src": src,
                    "src_mac": src_mac,
                    "dst": ROUTER_IP,
                    "dst_mac": dst_mac,
                    "flows": agg.flows,
                    "spkts": agg.s_pkts,
                    "dpkts": agg.d_pkts,
                    "sbytes": agg.s_bytes,
                    "dbytes": agg.d_bytes,
                    "uniq_dports": agg.uniq_dports(),
                    "proto": agg.top_proto(),
                    "top_dport": agg.top_dport(),
                    "atk": display_atk,
                    "prod_atk": prod_atk,
                    "mal": "",
                    "prod_mal": "",
                    "shadow_atk": shadow_atk,
                    "shadow_mal": shadow_mal,
                    "atk_thr": display_atk_thr,
                    "mal_thr": "",
                    "decision_source": f"router_log_{decision_source}",
                    "decision": "REDIRECTED_TO_HONEYPOT",
                }
                if should_emit_event:
                    finalize_event(evt, "ATTACK", "SSH_BRUTE_FORCE", src, ROUTER_IP, row_feat)

                try:
                    log_honeypot_sample(
                        build_honeypot_sample_payload(
                            action="REDIRECTED_TO_HONEYPOT",
                            rule="SSH_BRUTE_FORCE",
                            category="ATTACK",
                            src=src,
                            src_mac=src_mac,
                            dst=ROUTER_IP,
                            dst_mac=dst_mac,
                            a=agg,
                            atk=atk,
                            mal="",
                            shadow_atk=shadow_atk,
                            shadow_mal=shadow_mal,
                            decision_source=f"router_log_{decision_source}",
                            row_feat=row_feat,
                            extra={
                                "router_address_list": HONEYPOT_BRUTEFORCE_LIST,
                                "router_failures": int(fail_count),
                                "router_log_trigger": True,
                            },
                        )
                    )
                except Exception as exc:
                    print(f"[honeypot-sample] {exc}")

    threading.Thread(target=router_log_ssh_honeypot_watcher, daemon=True).start()

    interrupted = False
    try:
        while True:
            now = time.time()
            flush_pending_observed_brute(now)
            flush_pending_low_value_observed(now)
            prune_recent_pairs(recent_attack_pairs, now)
            prune_initiators(pair_initiators, now)
            prune_conntrack_cache(conntrack_initiators, now)
            prune_history(history, now)
            prune_recent_unblocked(now)
            prune_ema_scores(now)
            prune_ssh_display_scores(now)

            for grace_src in list(recent_unblocked.keys()):
                if in_unblock_grace(grace_src, now) and recent_unblocked_needs_reset.pop(grace_src, False):
                    clear_src_runtime_state(grace_src, aggs, history, consecutive_hits, recent_attack_pairs)

            if now - window_start >= WINDOW_SEC:
                if aggs:
                    window_named_threat_pairs: set[Tuple[str, str]] = set()
                    window_named_threat_sources: set[str] = set()
                    window_named_threat_ports_by_src: Dict[str, set[int]] = defaultdict(set)
                    for (probe_src, probe_dst), probe_a in list(aggs.items()):
                        if ONLY_PROTECTED_DST and probe_dst not in PROTECTED_TARGETS:
                            continue
                        if should_ignore_flow_scope(probe_src, probe_dst):
                            continue
                        if probe_src in NEVER_BLOCK_IPS:
                            continue

                        probe_basic_gate_pass = False
                        if probe_a.top_proto() == 1:
                            probe_basic_gate_pass = (probe_a.s_pkts >= 10)
                        else:
                            probe_top_dp = probe_a.top_dport()
                            if probe_top_dp in BRUTE_PORTS:
                                probe_basic_gate_pass = (probe_a.flows >= BRUTE_GATE_MIN_FLOWS and probe_a.s_pkts >= BRUTE_MIN_PKTS)
                            else:
                                probe_basic_gate_pass = (probe_a.flows >= MIN_FLOWS_TO_CONSIDER and probe_a.s_pkts >= MIN_PKTS_TO_CONSIDER)

                        if not probe_basic_gate_pass:
                            continue

                        probe_reverse = aggs.get((probe_dst, probe_src))
                        probe_eval = build_eval_agg(probe_a, probe_reverse)
                        probe_rule = detect_rule_type(probe_eval)
                        if probe_rule in ATTACK_RULES or probe_rule in MAL_BEHAVIORS:
                            window_named_threat_pairs.add((str(probe_src), str(probe_dst)))
                            window_named_threat_sources.add(str(probe_src))
                            window_named_threat_ports_by_src[str(probe_src)].add(int(probe_eval.top_dport()))

                    for (src, dst), a in list(aggs.items()):
                        if ONLY_PROTECTED_DST and dst not in PROTECTED_TARGETS:
                            continue
                        if should_ignore_flow_scope(src, dst):
                            continue
                        if src in NEVER_BLOCK_IPS:
                            continue

                        # basic gate (beacon windows are allowed to build history even when they stay below the main gate)
                        basic_gate_pass = False
                        if a.top_proto() == 1:
                            basic_gate_pass = (a.s_pkts >= 10)
                        else:
                            top_dp = a.top_dport()
                            if top_dp in BRUTE_PORTS:
                                basic_gate_pass = (a.flows >= BRUTE_GATE_MIN_FLOWS and a.s_pkts >= BRUTE_MIN_PKTS)
                            else:
                                basic_gate_pass = (a.flows >= MIN_FLOWS_TO_CONSIDER and a.s_pkts >= MIN_PKTS_TO_CONSIDER)

                        with muted_lock:
                            if (src, dst) in muted:
                                continue

                        try:
                            found, ok = is_in_list(ssh, src)
                        except Exception:
                            found, ok = (False, False)
                        if ok and found:
                            continue

                        history[(src, dst)].append((now, a.flows, a.s_bytes, a.uniq_dports()))

                        # victim response protection
                        if (dst, src) in recent_attack_pairs:
                            continue

                        reverse_a = aggs.get((dst, src))
                        a_eval = build_eval_agg(a, reverse_a)
                        proto_eval = int(a_eval.top_proto())
                        if proto_eval == 1:
                            maybe_refresh_pair_initiator_from_conntrack(
                                ssh, src, dst, proto_eval, pair_initiators, conntrack_initiators, now
                            )
                        rule = detect_rule_type(a_eval) if basic_gate_pass else None
                        suppress_low_value_observed_display = False
                        suppress_unknown_console_only = False
                        suppress_unknown_live_alert_only = False

                        if rule is None:
                            hist = list(history[(src, dst)])
                            if len(hist) >= BEACON_MIN_WINDOWS and not should_skip_beacon_heuristic(src, dst, a_eval):
                                last = hist[-BEACON_MIN_WINDOWS:]
                                ok = all(
                                    (flows <= BEACON_MAX_FLOWS_PER_WIN and sbytes <= BEACON_MAX_SBYTES_PER_WIN and uniq <= BEACON_MAX_UNIQ_DPORTS)
                                    for (_t, flows, sbytes, uniq) in last
                                )
                                if ok:
                                    rule = "C2_BEACON"

                        if rule is None:
                            observed_rule = detect_observed_type(a_eval)
                            if observed_rule is None:
                                continue
                            exact_named_threat_context = (
                                has_exact_named_threat_pair(src, dst, recent_attack_pairs.keys())
                                or has_exact_named_threat_pair(src, dst, window_named_threat_pairs)
                            )
                            suppress_low_value_observed_display = bool(
                                observed_rule in DELAYED_LOW_VALUE_OBSERVED_RULES and exact_named_threat_context
                            )
                            observed_row_feat = None
                            observed_prod_atk = None
                            observed_prod_mal = None
                            if observed_rule == "OBS_UNKNOWN":
                                observed_row_feat = build_row_features(WINDOW_SEC, a_eval)
                                observed_prod_atk = float(predict_probs(model_attack, feats_attack, observed_row_feat).get(1, 0.0))
                                observed_prod_mal = float(predict_probs(model_mal, feats_mal, observed_row_feat).get(1, 0.0))
                            if should_suppress_observed_event(observed_rule, src, dst, a_eval):
                                row_feat = observed_row_feat or build_row_features(WINDOW_SEC, a_eval)
                                prod_atk = observed_prod_atk if observed_prod_atk is not None else float(predict_probs(model_attack, feats_attack, row_feat).get(1, 0.0))
                                prod_mal = observed_prod_mal if observed_prod_mal is not None else float(predict_probs(model_mal, feats_mal, row_feat).get(1, 0.0))
                                if should_capture_suppressed_observed_baseline(src, dst, a_eval, prod_atk, prod_mal):
                                    src_mac = resolve_endpoint_mac(src, macr, router_mac)
                                    dst_mac = resolve_endpoint_mac(dst, macr, router_mac)
                                    shadow_atk, shadow_mal = score_shadow_event(row_feat)
                                    decision_source = get_live_decision_source()
                                    evt = {
                                        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                        "category": "OBSERVED",
                                        "rule": observed_rule,
                                        "src": src,
                                        "src_mac": src_mac,
                                        "dst": dst,
                                        "dst_mac": dst_mac,
                                        "flows": a_eval.flows,
                                        "spkts": a_eval.s_pkts,
                                        "dpkts": a_eval.d_pkts,
                                        "sbytes": a_eval.s_bytes,
                                        "dbytes": a_eval.d_bytes,
                                        "uniq_dports": a_eval.uniq_dports(),
                                        "proto": a_eval.top_proto(),
                                        "top_dport": a_eval.top_dport(),
                                        "atk": prod_atk,
                                        "prod_atk": prod_atk,
                                        "mal": prod_mal,
                                        "prod_mal": prod_mal,
                                        "shadow_atk": shadow_atk,
                                        "shadow_mal": shadow_mal,
                                        "atk_thr": "",
                                        "mal_thr": "",
                                        "decision_source": decision_source,
                                        "decision": "OBSERVED",
                                    }
                                    evt["event_id"] = build_event_id(evt["ts"], "OBSERVED", observed_rule, src, dst)
                                    capture_online_sample_payload(evt, "OBSERVED", observed_rule, src, dst, row_feat)
                                    continue
                                if should_quiet_suppressed_observed_noise(src, dst, a_eval, prod_atk, prod_mal):
                                    continue
                            if observed_rule == "OBS_UNKNOWN":
                                prod_atk = observed_prod_atk if observed_prod_atk is not None else 0.0
                                prod_mal = observed_prod_mal if observed_prod_mal is not None else 0.0
                                suppress_unknown_live_alert_only = should_capture_router_web_unknown_silently(
                                    src,
                                    dst,
                                    a_eval,
                                    prod_atk,
                                    prod_mal,
                                )
                                if not should_emit_unknown_observed_threat(src, dst, a_eval, prod_atk, prod_mal):
                                    if not suppress_unknown_live_alert_only:
                                        continue
                                suppress_unknown_console_only = should_suppress_unknown_console_in_attack_context(
                                    src,
                                    a_eval,
                                    prod_atk,
                                    prod_mal,
                                    window_named_threat_sources,
                                    window_named_threat_ports_by_src,
                                )
                            rule = observed_rule

                        if rule in BRUTE_RULES:
                            drop_pending_observed_brute(src, dst)
                            drop_pending_low_value_observed(src, dst, drop_related=True)

                        if (
                            rule == "OBS_SSH"
                            and dst in ROUTER_INTERFACE_IPS
                            and not is_trusted_ssh_source(src)
                        ):
                            evt = {
                                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "category": "OBSERVED",
                                "rule": rule,
                                "src": src,
                                "src_mac": resolve_endpoint_mac_strict_retry(src, macr, router_mac),
                                "dst": dst,
                                "dst_mac": resolve_endpoint_mac_strict(dst, macr, router_mac),
                                "flows": a_eval.flows,
                                "spkts": a_eval.s_pkts,
                                "dpkts": a_eval.d_pkts,
                                "sbytes": a_eval.s_bytes,
                                "dbytes": a_eval.d_bytes,
                                "uniq_dports": a_eval.uniq_dports(),
                                "proto": a_eval.top_proto(),
                                "top_dport": a_eval.top_dport(),
                                "atk": "",
                                "prod_atk": "",
                                "mal": "",
                                "prod_mal": "",
                                "shadow_atk": "",
                                "shadow_mal": "",
                                "atk_thr": "",
                                "mal_thr": "",
                                "decision_source": "suppressed_router_ssh_observed",
                                "decision": "OBSERVED_SUPPRESSED",
                            }
                            evt["event_id"] = build_event_id(evt["ts"], "OBSERVED", rule, src, dst)
                            row_feat = build_row_features(WINDOW_SEC, a_eval)
                            capture_online_sample_payload(evt, "OBSERVED", rule, src, dst, row_feat)
                            aggs.pop((src, dst), None)
                            history.pop((src, dst), None)
                            consecutive_hits.pop((src, rule), None)
                            continue

                        if rule in {"SSH_BRUTE_FORCE", "OBS_SSH"} and _was_recently_honeypot_redirected(src, now):
                            drop_pending_observed_brute(src, dst)
                            drop_pending_low_value_observed(src, dst, drop_related=True)
                            aggs.pop((src, dst), None)
                            history.pop((src, dst), None)
                            consecutive_hits.pop((src, rule), None)
                            continue

                        if rule in OBSERVED_BRUTE_RULE_NAMES:
                            redirected_now = False
                            with honeypot_lock:
                                redirected_now = ((src, dst) in honeypot_redirected) or ((src, ROUTER_IP) in honeypot_redirected)
                            if not redirected_now and dst in ROUTER_INTERFACE_IPS:
                                try:
                                    in_honeypot_obs, honeypot_ok_obs = is_in_address_list(ssh, HONEYPOT_BRUTEFORCE_LIST, src)
                                except Exception:
                                    in_honeypot_obs, honeypot_ok_obs = (False, False)
                                redirected_now = bool(honeypot_ok_obs and in_honeypot_obs)
                            if redirected_now:
                                drop_pending_observed_brute(src, dst)
                                drop_pending_low_value_observed(src, dst, drop_related=True)
                                aggs.pop((src, dst), None)
                                history.pop((src, dst), None)
                                consecutive_hits.pop((src, rule), None)
                                continue

                        if rule in HONEYPOT_REDIRECT_RULES:
                            try:
                                in_honeypot, honeypot_ok = is_in_address_list(ssh, HONEYPOT_BRUTEFORCE_LIST, src)
                            except Exception:
                                in_honeypot, honeypot_ok = (False, False)
                            if honeypot_ok and in_honeypot:
                                drop_pending_observed_brute(src, dst)
                                drop_pending_low_value_observed(src, dst, drop_related=True)
                                clear_honeypot_redirect_connections(ssh, src)
                                aggs.pop((src, dst), None)
                                history.pop((src, dst), None)
                                consecutive_hits.pop((src, rule), None)
                                continue

                        router_brute_service = get_router_brute_confirm_service(rule, dst, a_eval.top_dport())
                        category = event_category_for_rule(rule)
                        ambiguous_icmp = (rule == "ICMP_FLOOD" and is_ambiguous_icmp_leg(src, dst, a_eval, pair_initiators))
                        ambiguous_observed_ping = (rule == "OBS_PING" and is_ambiguous_icmp_leg(src, dst, a_eval, pair_initiators))
                        if (ambiguous_icmp or ambiguous_observed_ping) and not should_emit_ambiguous_icmp(src, dst, reverse_a):
                            continue

                        if (not ambiguous_icmp) and (not ambiguous_observed_ping) and should_suppress_victim_leg(src, dst, a_eval, pair_initiators):
                            evt = {
                                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "category": category,
                                "rule": rule,
                                "src": src,
                                "src_mac": resolve_endpoint_mac(src, macr, router_mac),
                                "dst": dst,
                                "dst_mac": resolve_endpoint_mac(dst, macr, router_mac),
                                "flows": a_eval.flows,
                                "spkts": a_eval.s_pkts,
                                "dpkts": a_eval.d_pkts,
                                "sbytes": a_eval.s_bytes,
                                "dbytes": a_eval.d_bytes,
                                "uniq_dports": a_eval.uniq_dports(),
                                "proto": a_eval.top_proto(),
                                "top_dport": a_eval.top_dport(),
                                "atk": "",
                                "mal": "",
                                "shadow_atk": "",
                                "shadow_mal": "",
                                "atk_thr": "",
                                "mal_thr": "",
                                "decision": "SUPPRESSED_VICTIM_LEG"
                            }
                            finalize_event(evt, category, rule, src, dst)
                            continue

                        if rule == "SSH_BRUTE_FORCE":
                            src_mac = resolve_endpoint_mac_strict_retry(src, macr, router_mac)
                            dst_mac = resolve_endpoint_mac_strict(dst, macr, router_mac)
                        else:
                            src_mac = resolve_endpoint_mac(src, macr, router_mac)
                            dst_mac = resolve_endpoint_mac(dst, macr, router_mac)

                        atk = ""
                        mal = ""
                        shadow_atk = ""
                        shadow_mal = ""
                        prod_atk = ""
                        prod_mal = ""
                        decision_source = "production"
                        atk_thr = ""
                        mal_thr = ""
                        row_feat = None
                        router_fail_count = 0

                        if category in {"ATTACK", "MALWARE", "OBSERVED"}:
                            row_feat = build_row_features(WINDOW_SEC, a_eval)
                            shadow_atk, shadow_mal = score_shadow_event(row_feat)
                            decision_source = get_live_decision_source()

                        if category in {"ATTACK", "MALWARE"}:
                            prod_atk = float(predict_probs(model_attack, feats_attack, row_feat).get(1, 0.0))
                            atk = prod_atk

                            if category == "MALWARE":
                                prod_mal = float(predict_probs(model_mal, feats_mal, row_feat).get(1, 0.0))
                                mal = prod_mal

                            if ambiguous_icmp and reverse_a is not None:
                                reverse_eval = build_eval_agg(reverse_a, a)
                                reverse_feat = build_row_features(WINDOW_SEC, reverse_eval)
                                prod_atk = max(prod_atk, float(predict_probs(model_attack, feats_attack, reverse_feat).get(1, 0.0)))
                                atk = prod_atk

                            if decision_source == "shadow":
                                shadow_attack_value = _optional_float(shadow_atk)
                                shadow_malware_value = _optional_float(shadow_mal)
                                if category == "ATTACK":
                                    if shadow_attack_value is not None:
                                        atk = float(shadow_attack_value)
                                    else:
                                        decision_source = "production"
                                elif category == "MALWARE":
                                    if shadow_attack_value is not None and shadow_malware_value is not None:
                                        atk = float(shadow_attack_value)
                                        mal = float(shadow_malware_value)
                                    else:
                                        decision_source = "production"

                            if router_brute_service:
                                try:
                                    router_fail_count = get_router_failed_login_count(
                                        ssh,
                                        src,
                                        router_brute_service,
                                        force_refresh=False,
                                    )
                                except Exception:
                                    router_fail_count = 0

                            if rule == "RANSOMWARE_PRECHECK" and category == "MALWARE":
                                mal = calibrated_exp_score(mal, THR_MAL.get(rule, THR_MAL_DEFAULT), RANSOMWARE_PRECHECK_RAW_PASS_MAL)

                            if not ambiguous_icmp:
                                if category == "ATTACK":
                                    atk, _ignored_mal = apply_smoothing(src, rule, atk, 0.0)
                                else:
                                    atk, mal = apply_smoothing(src, rule, atk, mal)

                            atk_thr = THR_ATTACK.get(rule, THR_ATTACK_DEFAULT)
                            if category == "MALWARE":
                                mal_thr = THR_MAL.get(rule, THR_MAL_DEFAULT)

                        display_atk = atk
                        if category == "ATTACK" and rule == "SSH_BRUTE_FORCE" and atk not in (None, ""):
                            display_atk = stabilize_display_score(src, rule, atk, now)

                        if ambiguous_icmp:
                            decision = "NOT_BLOCKED_DIRECTION_UNKNOWN"
                            if PRINT_NONBLOCKED_ALERTS:
                                pretty_block(rule, src, src_mac, dst, dst_mac, a_eval, display_atk, "", atk_thr, "", "Not blocked", extra=" (ICMP direction unknown)", directional=False)
                            evt = {
                                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "category": category,
                                "rule": rule,
                                "src": src,
                                "src_mac": src_mac,
                                "dst": dst,
                                "dst_mac": dst_mac,
                                "flows": a_eval.flows,
                                "spkts": a_eval.s_pkts,
                                "dpkts": a_eval.d_pkts,
                                "sbytes": a_eval.s_bytes,
                                "dbytes": a_eval.d_bytes,
                                "uniq_dports": a_eval.uniq_dports(),
                                "proto": a_eval.top_proto(),
                                "top_dport": a_eval.top_dport(),
                                "atk": display_atk,
                                "prod_atk": prod_atk,
                                "mal": "",
                                "prod_mal": "",
                                "shadow_atk": shadow_atk,
                                "shadow_mal": shadow_mal,
                                "atk_thr": atk_thr,
                                "mal_thr": "",
                                "decision_source": decision_source,
                                "decision": decision
                            }
                            finalize_event(evt, category, rule, src, dst, row_feat)
                            continue

                        if ambiguous_observed_ping:
                            decision = "OBSERVED"
                            if PRINT_NONBLOCKED_ALERTS:
                                pretty_block(rule, src, src_mac, dst, dst_mac, a_eval, "", "", "", "", decision, extra=" (ICMP direction unknown)", directional=False)
                            evt = {
                                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "category": category,
                                "rule": rule,
                                "src": src,
                                "src_mac": src_mac,
                                "dst": dst,
                                "dst_mac": dst_mac,
                                "flows": a_eval.flows,
                                "spkts": a_eval.s_pkts,
                                "dpkts": a_eval.d_pkts,
                                "sbytes": a_eval.s_bytes,
                                "dbytes": a_eval.d_bytes,
                                "uniq_dports": a_eval.uniq_dports(),
                                "proto": a_eval.top_proto(),
                                "top_dport": a_eval.top_dport(),
                                "atk": "",
                                "prod_atk": "",
                                "mal": "",
                                "prod_mal": "",
                                "shadow_atk": shadow_atk,
                                "shadow_mal": shadow_mal,
                                "atk_thr": "",
                                "mal_thr": "",
                                "decision_source": decision_source,
                                "decision": decision
                            }
                            finalize_event(evt, category, rule, src, dst, row_feat)
                            continue

                        if category == "OBSERVED":
                            decision = "OBSERVED"
                            evt = {
                                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "category": category,
                                "rule": rule,
                                "src": src,
                                "src_mac": src_mac,
                                "dst": dst,
                                "dst_mac": dst_mac,
                                "flows": a_eval.flows,
                                "spkts": a_eval.s_pkts,
                                "dpkts": a_eval.d_pkts,
                                "sbytes": a_eval.s_bytes,
                                "dbytes": a_eval.d_bytes,
                                "uniq_dports": a_eval.uniq_dports(),
                                "proto": a_eval.top_proto(),
                                "top_dport": a_eval.top_dport(),
                                "atk": "",
                                "prod_atk": "",
                                "mal": "",
                                "prod_mal": "",
                                "shadow_atk": shadow_atk,
                                "shadow_mal": shadow_mal,
                                "atk_thr": "",
                                "mal_thr": "",
                                "decision_source": decision_source,
                                "decision": decision
                            }
                            if suppress_low_value_observed_display and rule in DELAYED_LOW_VALUE_OBSERVED_RULES:
                                evt["event_id"] = build_event_id(evt["ts"], category, rule, src, dst)
                                capture_online_sample_payload(evt, category, rule, src, dst, row_feat)
                            elif rule == "OBS_UNKNOWN" and suppress_unknown_live_alert_only:
                                evt["event_id"] = build_event_id(evt["ts"], category, rule, src, dst)
                                capture_online_sample_payload(evt, category, rule, src, dst, row_feat)
                            elif rule == "OBS_UNKNOWN" and suppress_unknown_console_only:
                                finalize_event(evt, category, rule, src, dst, row_feat)
                            elif rule in OBSERVED_BRUTE_RULE_NAMES:
                                pretty_text = ""
                                if PRINT_NONBLOCKED_ALERTS:
                                    pretty_text = render_pretty_block(rule, src, src_mac, dst, dst_mac, a_eval, "", "", "", "", decision)
                                queue_pending_observed_brute(now + OBS_BRUTE_SUPPRESS_SEC, pretty_text, evt, category, rule, src, dst, row_feat)
                            else:
                                if PRINT_NONBLOCKED_ALERTS:
                                    pretty_block(rule, src, src_mac, dst, dst_mac, a_eval, "", "", "", "", decision)
                                finalize_event(evt, category, rule, src, dst, row_feat)
                            continue

                        if category == "ATTACK":
                            ai_raw = (atk >= atk_thr)
                        elif category == "MALWARE":
                            ai_raw = (mal >= mal_thr)
                        else:
                            ai_raw = False

                        need = REQUIRED_CONSECUTIVE_HITS.get(rule, REQUIRED_CONSECUTIVE_HITS_DEFAULT)
                        key_hit = (src, rule)
                        if ai_raw:
                            consecutive_hits[key_hit] += 1
                        else:
                            consecutive_hits[key_hit] = 0

                        ai_pass = (consecutive_hits[key_hit] >= need)
                        should_block = ai_pass
                        decision = "NOT_BLOCKED"
                        emit_redirect_event = True

                        if router_brute_service:
                            should_block = ai_pass
                            if ROUTER_BRUTE_REQUIRE_CONFIRM:
                                should_block = ai_pass and (router_fail_count >= ROUTER_BRUTE_CONFIRM_MIN_FAILS)
                                if not ai_pass:
                                    decision = "NOT_BLOCKED"
                                elif router_fail_count < ROUTER_BRUTE_CONFIRM_MIN_FAILS:
                                    decision = "NOT_BLOCKED_ROUTER_BRUTE_UNCONFIRMED"

                        if should_block:
                            try:
                                if rule in HONEYPOT_REDIRECT_RULES:
                                    if rule == "SSH_BRUTE_FORCE":
                                        if _was_recently_honeypot_redirected(src, now):
                                            aggs.pop((src, dst), None)
                                            history.pop((src, dst), None)
                                            consecutive_hits.pop((src, rule), None)
                                            continue
                                    redirect_result = add_ip_to_list(
                                        ssh,
                                        src,
                                        HONEYPOT_BRUTEFORCE_LIST,
                                        comment=f"AI:{rule}",
                                    )
                                    if redirect_result in {"added", "added_unverified"}:
                                        remember_attack_pair(src, dst, a, rule, recent_attack_pairs, now)
                                        decision = "REDIRECTED_TO_HONEYPOT"
                                        _mark_recent_honeypot_redirect(src, now)
                                        mark_router_log_seen(src)
                                        drop_pending_observed_brute(src, dst)
                                        drop_pending_low_value_observed(src, dst, drop_related=True)
                                        clear_honeypot_redirect_connections(ssh, src)
                                        aggs.pop((src, dst), None)
                                        history.pop((src, dst), None)
                                        consecutive_hits.pop((src, rule), None)
                                        with honeypot_lock:
                                            honeypot_redirected[(src, dst)] = True
                                        if rule == "SSH_BRUTE_FORCE":
                                            emit_redirect_event = _reserve_ssh_honeypot_event(src, dst, now)
                                        if emit_redirect_event and (PRINT_BLOCK_EVENTS or PRINT_NONBLOCKED_ALERTS):
                                            pretty_block(
                                                rule,
                                                src,
                                                src_mac,
                                                dst,
                                                dst_mac,
                                                a_eval,
                                                display_atk,
                                                mal if category == "MALWARE" else "",
                                                atk_thr,
                                                mal_thr if category == "MALWARE" else "",
                                                "REDIRECTED_TO_HONEYPOT",
                                                extra=f" {src} list={HONEYPOT_BRUTEFORCE_LIST}",
                                            )
                                        try:
                                            log_honeypot_sample(
                                                build_honeypot_sample_payload(
                                                    action="REDIRECTED_TO_HONEYPOT",
                                                    rule=rule,
                                                    category=category,
                                                    src=src,
                                                    src_mac=src_mac,
                                                    dst=dst,
                                                    dst_mac=dst_mac,
                                                    a=a_eval,
                                                    atk=atk,
                                                    mal=mal,
                                                    shadow_atk=shadow_atk,
                                                    shadow_mal=shadow_mal,
                                                    decision_source=decision_source,
                                                    row_feat=row_feat,
                                                    extra={"router_address_list": HONEYPOT_BRUTEFORCE_LIST},
                                                )
                                            )
                                        except Exception as exc:
                                            print(f"[honeypot-sample] {exc}")
                                    elif redirect_result == "already_listed":
                                        remember_attack_pair(src, dst, a, rule, recent_attack_pairs, now)
                                        decision = "ALREADY_REDIRECTED_TO_HONEYPOT"
                                        _mark_recent_honeypot_redirect(src, now)
                                        mark_router_log_seen(src)
                                        drop_pending_observed_brute(src, dst)
                                        drop_pending_low_value_observed(src, dst, drop_related=True)
                                        clear_honeypot_redirect_connections(ssh, src)
                                        aggs.pop((src, dst), None)
                                        history.pop((src, dst), None)
                                        consecutive_hits.pop((src, rule), None)
                                        with honeypot_lock:
                                            honeypot_redirected[(src, dst)] = True
                                        if rule == "SSH_BRUTE_FORCE":
                                            emit_redirect_event = _reserve_ssh_honeypot_event(src, dst, now)
                                        if emit_redirect_event and PRINT_NONBLOCKED_ALERTS:
                                            pretty_block(
                                                rule,
                                                src,
                                                src_mac,
                                                dst,
                                                dst_mac,
                                                a_eval,
                                                display_atk,
                                                mal if category == "MALWARE" else "",
                                                atk_thr,
                                                mal_thr if category == "MALWARE" else "",
                                                "REDIRECTED_TO_HONEYPOT",
                                                extra=f" {src} list={HONEYPOT_BRUTEFORCE_LIST} (already listed)",
                                            )
                                    else:
                                        decision = "HONEYPOT_REDIRECT_FAILED"
                                        if PRINT_NONBLOCKED_ALERTS:
                                            pretty_block(
                                                rule,
                                                src,
                                                src_mac,
                                                dst,
                                                dst_mac,
                                                a_eval,
                                                display_atk,
                                                mal if category == "MALWARE" else "",
                                                atk_thr,
                                                mal_thr if category == "MALWARE" else "",
                                                "HONEYPOT_REDIRECT_FAILED",
                                            )
                                else:
                                    in_honeypot, honeypot_ok = is_in_address_list(ssh, HONEYPOT_BRUTEFORCE_LIST, src)
                                    honeypot_escalation = bool(honeypot_ok and in_honeypot)
                                    block_result = block_ip(ssh, src, reason=build_block_reason(rule, atk, mal))
                                    if block_result in {"blocked", "blocked_unverified"}:
                                        remember_attack_pair(src, dst, a, rule, recent_attack_pairs, now)
                                        honeypot_remove_result = "not_checked"
                                        try:
                                            honeypot_remove_result = remove_ip_from_list(ssh, src, HONEYPOT_BRUTEFORCE_LIST)
                                        except Exception:
                                            honeypot_remove_result = "failed"
                                        if honeypot_remove_result in {"removed", "removed_unverified"}:
                                            honeypot_escalation = True
                                        if honeypot_remove_result in {"removed", "removed_unverified", "not_found"}:
                                            with honeypot_lock:
                                                for key in [key for key in honeypot_redirected.keys() if key[0] == src]:
                                                    honeypot_redirected.pop(key, None)
                                            _clear_recent_honeypot_redirect(src)
                                        decision = (
                                            "BLOCKED_ESCALATED_TO_BLOCK"
                                            if honeypot_escalation and block_result == "blocked"
                                            else "BLOCKED_UNVERIFIED_ESCALATED_TO_BLOCK"
                                            if honeypot_escalation
                                            else "BLOCKED"
                                            if block_result == "blocked"
                                            else "BLOCKED_UNVERIFIED"
                                        )
                                        aggs.pop((src, dst), None)
                                        history.pop((src, dst), None)
                                        consecutive_hits.pop((src, rule), None)
                                        if honeypot_escalation:
                                            try:
                                                log_honeypot_sample(
                                                    build_honeypot_sample_payload(
                                                        action="ESCALATED_TO_BLOCK",
                                                        rule=rule,
                                                        category=category,
                                                        src=src,
                                                            src_mac=src_mac,
                                                            dst=dst,
                                                            dst_mac=dst_mac,
                                                            a=a_eval,
                                                            atk=atk,
                                                        mal=mal,
                                                        shadow_atk=shadow_atk,
                                                        shadow_mal=shadow_mal,
                                                        decision_source=decision_source,
                                                        row_feat=row_feat,
                                                        extra={
                                                            "router_address_list": HONEYPOT_BRUTEFORCE_LIST,
                                                            "escalated_from_honeypot": True,
                                                        },
                                                    )
                                                )
                                            except Exception as exc:
                                                print(f"[honeypot-sample] {exc}")
                                        if PRINT_BLOCK_EVENTS:
                                            router_extra = ""
                                            if router_brute_service and (router_fail_count > 0 or ROUTER_BRUTE_REQUIRE_CONFIRM):
                                                router_extra = f" | router_failures={router_fail_count}/{ROUTER_BRUTE_CONFIRM_MIN_FAILS}"
                                            if honeypot_escalation:
                                                router_extra += f" | removed_from={HONEYPOT_BRUTEFORCE_LIST}"
                                            pretty_action = "ESCALATED_TO_BLOCK" if honeypot_escalation else ("BLOCKED" if block_result == "blocked" else "BLOCKED_UNVERIFIED")
                                            pretty_block(rule, src, src_mac, dst, dst_mac, a_eval, display_atk, mal if category == "MALWARE" else "", atk_thr, mal_thr if category == "MALWARE" else "", pretty_action, extra=f" {src} timeout={format_block_timeout_label()}{router_extra}")
                                        if MUTE_UNTIL_UNBLOCK:
                                            with muted_lock:
                                                muted[(src, dst)] = True
                                    elif block_result == "already_blocked":
                                        remember_attack_pair(src, dst, a, rule, recent_attack_pairs, now)
                                        honeypot_remove_result = "not_checked"
                                        try:
                                            honeypot_remove_result = remove_ip_from_list(ssh, src, HONEYPOT_BRUTEFORCE_LIST)
                                        except Exception:
                                            honeypot_remove_result = "failed"
                                        if honeypot_remove_result in {"removed", "removed_unverified"}:
                                            honeypot_escalation = True
                                        if honeypot_remove_result in {"removed", "removed_unverified", "not_found"}:
                                            with honeypot_lock:
                                                for key in [key for key in honeypot_redirected.keys() if key[0] == src]:
                                                    honeypot_redirected.pop(key, None)
                                            _clear_recent_honeypot_redirect(src)
                                        decision = "ALREADY_BLOCKED_OR_NEVER"
                                        if MUTE_UNTIL_UNBLOCK:
                                            with muted_lock:
                                                muted[(src, dst)] = True
                                    else:
                                        decision = "BLOCK_FAILED"
                            except Exception as e:
                                decision = f"BLOCK_FAILED: {e}"
                        else:
                            if PRINT_NONBLOCKED_ALERTS:
                                if decision == "NOT_BLOCKED_ROUTER_BRUTE_UNCONFIRMED":
                                    extra = f" (awaiting router login-failure confirmation {router_fail_count}/{ROUTER_BRUTE_CONFIRM_MIN_FAILS})"
                                else:
                                    extra = " (AI below threshold)"
                                pretty_block(rule, src, src_mac, dst, dst_mac, a_eval, display_atk, mal if category == "MALWARE" else "", atk_thr, mal_thr if category == "MALWARE" else "", "Not blocked", extra=extra)

                        evt = {
                            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "category": category,
                            "rule": rule,
                            "src": src,
                            "src_mac": src_mac,
                            "dst": dst,
                            "dst_mac": dst_mac,
                            "flows": a_eval.flows,
                            "spkts": a_eval.s_pkts,
                            "dpkts": a_eval.d_pkts,
                            "sbytes": a_eval.s_bytes,
                            "dbytes": a_eval.d_bytes,
                            "uniq_dports": a_eval.uniq_dports(),
                            "proto": a_eval.top_proto(),
                            "top_dport": a_eval.top_dport(),
                            "atk": "" if category == "MALWARE" else display_atk,
                            "prod_atk": prod_atk,
                            "mal": mal if category == "MALWARE" else "",
                            "prod_mal": prod_mal if category == "MALWARE" else "",
                            "shadow_atk": shadow_atk,
                            "shadow_mal": shadow_mal,
                            "atk_thr": "" if category == "MALWARE" else atk_thr,
                            "mal_thr": mal_thr if category == "MALWARE" else "",
                            "decision_source": decision_source,
                            "decision": decision
                        }
                        if not (
                            rule == "SSH_BRUTE_FORCE"
                            and decision in {"REDIRECTED_TO_HONEYPOT", "ALREADY_REDIRECTED_TO_HONEYPOT"}
                            and not emit_redirect_event
                        ):
                            finalize_event(evt, category, rule, src, dst, row_feat)

                aggs.clear()
                window_start = now

            # recv netflow
            try:
                data, _addr = sock.recvfrom(65535)
                recv_pkts += 1
                flows = parser.parse_packet(data)
                parsed_flows += len(flows)
                for f in flows:
                    if FILTER_EXPORT_FLOW:
                        if f.src_ip in ROUTER_INTERFACE_IPS and f.dst_ip == WINDOWS_IP and f.dst_port == NETFLOW_PORT:
                            continue

                    if ONLY_PROTECTED_DST and f.dst_ip not in PROTECTED_TARGETS:
                        continue

                    if should_ignore_flow_scope(f.src_ip, f.dst_ip):
                        continue

                    remember_initiator(f, pair_initiators, now)

                    key = (f.src_ip, f.dst_ip)
                    if key not in aggs:
                        aggs[key] = Agg()
                    aggs[key].add_forward(f)

                    if (
                        int(f.proto) == 6
                        and int(f.dst_port) == 22
                        and f.dst_ip in ROUTER_INTERFACE_IPS
                    ):
                        maybe_fast_redirect_ssh_honeypot(f.src_ip, f.dst_ip, now)

            except socket.timeout:
                pass

            if now - last_runtime_metrics_write >= 1.0:
                last_runtime_metrics_write = now
                try:
                    metrics_payload = {
                        "updatedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "updatedAtEpoch": round(now, 3),
                        "recvPacketsDelta": max(recv_pkts - last_runtime_metrics_packets, 0),
                        "recvPackets": recv_pkts,
                        "parsedFlowsDelta": max(parsed_flows - last_runtime_metrics_flows, 0),
                        "parsedFlows": parsed_flows,
                        "activeAggregates": len(aggs),
                        "windowSeconds": WINDOW_SEC,
                    }
                    last_runtime_metrics_packets = recv_pkts
                    last_runtime_metrics_flows = parsed_flows
                    write_runtime_metrics(RUNTIME_METRICS_JSON, metrics_payload)
                    append_runtime_metrics_history(
                        RUNTIME_METRICS_HISTORY_JSON,
                        metrics_payload,
                        retention_sec=RUNTIME_METRICS_RETENTION_SEC,
                        now_ts=now,
                    )
                except Exception as exc:
                    print(f"[runtime-metrics] {exc}")

            if PRINT_HEARTBEAT and (time.time() - last_hb >= 5):
                last_hb = time.time()
                print(f"[HB] recv_pkts={recv_pkts} parsed_flows={parsed_flows} aggs={len(aggs)}")
                print()

    except KeyboardInterrupt:
        interrupted = True
        pass
    finally:
        flush_pending_observed_brute(time.time(), force=True)
        flush_pending_low_value_observed(time.time(), force=True)
        stop_evt.set()
        try:
            sock.close()
        except Exception:
            pass
        try:
            if arp_thread:
                arp_thread.stop()
        except KeyboardInterrupt:
            pass
        except Exception:
            pass
        try:
            ssh.close()
        except KeyboardInterrupt:
            pass
        except Exception:
            pass
        try:
            router_log_ssh.close()
        except KeyboardInterrupt:
            pass
        except Exception:
            pass
        if AUTO_GENERATE_REPORT_ON_EXIT:
            try:
                jsonl_path = os.path.abspath(JSONL_LOG)
                csv_path = os.path.abspath(CSV_LOG)
                report_input = None
                if os.path.exists(jsonl_path) and os.path.getsize(jsonl_path) > 0:
                    report_input = jsonl_path
                elif os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
                    report_input = csv_path
                if report_input is not None:
                    try:
                        from make_report import generate_report
                        result = generate_report(report_input)
                        print(f"[REPORT] Generated: {result['output_path']}")
                    except KeyboardInterrupt:
                        print("[REPORT] Skipped: interrupted during report generation")
            except KeyboardInterrupt:
                print("[REPORT] Skipped: interrupted during report generation")
            except Exception as e:
                print(f"[REPORT] Failed: {e}")


if __name__ == "__main__":
    main()
