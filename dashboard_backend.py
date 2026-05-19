from datetime import datetime
from pathlib import Path
from functools import wraps
import ipaddress
import json
import math
import os
import secrets
import shlex
import subprocess
import threading
import time

from flask import Flask, jsonify, request
from flask_cors import CORS

from file_lock_utils import exclusive_lock
from online_control import (
    load_control_state,
    restore_shadow_checkpoint,
    set_auto_train_enabled,
    set_live_decision_source,
    set_shadow_capture_enabled,
    update_auto_train_stats,
)
from online_models import (
    ATTACK_ONLINE_MODEL_PATH,
    MALWARE_ONLINE_MODEL_PATH,
    MissingRiverDependency,
    load_online_models,
    predict_online_scores,
)
from online_store import OnlineSampleStore, UNSET
from online_auto_label import auto_label_pending
from online_trainer import can_auto_train_single_tail_sample, list_distinct_trainable_samples, train_ready_samples
from router_ssh import build_router_ssh_client

ADMIN_TOKEN_HEADER = "X-NIDPS-API-Token"
DEFAULT_DASHBOARD_CORS_ORIGINS = (
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:4173",
    "http://localhost:4173",
    "http://127.0.0.1:5000",
    "http://localhost:5000",
)


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if not normalized:
        return default
    return normalized not in {"0", "false", "no", "off"}


def _env_csv(name: str, default: tuple[str, ...]) -> list[str] | str:
    value = os.getenv(name)
    if value is None:
        return list(default)
    normalized = str(value).strip()
    if not normalized:
        return list(default)
    if normalized == "*":
        return "*"
    return [item.strip() for item in normalized.split(",") if item.strip()]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)) or default)
    except Exception:
        return default


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
MODELS_DIR = BASE_DIR / "models"
JSONL_FILE = LOGS_DIR / "nidps_events.jsonl"
RUNTIME_METRICS_FILE = LOGS_DIR / "runtime_metrics.json"
RUNTIME_METRICS_HISTORY_FILE = LOGS_DIR / "runtime_metrics_history.jsonl"
RUNTIME_METRICS_RETENTION_SEC = 30 * 60
RUNTIME_METRICS_LOCK = LOGS_DIR / "runtime_metrics.json.lock"
RUNTIME_METRICS_HISTORY_LOCK = LOGS_DIR / "runtime_metrics_history.jsonl.lock"
BLOCK_LIST = "blocked"
HONEYPOT_BRUTEFORCE_LIST = os.getenv("NIDPS_HONEYPOT_BRUTEFORCE_LIST", "honeypot_bruteforce").strip() or "honeypot_bruteforce"
HONEYPOT_SSH_HOST = os.getenv("NIDPS_HONEYPOT_HOST", "192.168.88.100").strip()
HONEYPOT_SSH_USER = os.getenv("NIDPS_HONEYPOT_SSH_USER", "cowrie").strip()
HONEYPOT_SSH_PORT = _env_int("NIDPS_HONEYPOT_SSH_PORT", 22)
HONEYPOT_COWRIE_JSON_PATH = os.getenv("NIDPS_HONEYPOT_COWRIE_JSON_PATH", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json").strip()
HONEYPOT_LOG_LOOKBACK = max(_env_int("NIDPS_HONEYPOT_LOG_LOOKBACK", 400), 50)
CURRENT_ATTACK_MODEL_PATH = MODELS_DIR / "model_attack.joblib"
CURRENT_MALWARE_MODEL_PATH = MODELS_DIR / "model_malware.joblib"
ONLINE_STORE = OnlineSampleStore()
ADMIN_API_TOKEN = os.getenv("NIDPS_ADMIN_TOKEN", "").strip()
LOCAL_BOOTSTRAP_ADMIN_TOKEN = secrets.token_urlsafe(32)
DASHBOARD_HOST = os.getenv("NIDPS_DASHBOARD_HOST", "127.0.0.1").strip() or "127.0.0.1"
DASHBOARD_PORT = _env_int("NIDPS_DASHBOARD_PORT", 5000)
DASHBOARD_DEBUG = _env_flag("NIDPS_DASHBOARD_DEBUG", False)
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": _env_csv("NIDPS_DASHBOARD_CORS_ORIGINS", DEFAULT_DASHBOARD_CORS_ORIGINS),
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", ADMIN_TOKEN_HEADER],
        }
    },
)

ONLINE_LOCK = threading.Lock()
AUTO_TRAIN_POLL_SEC = 8
ROUTER_STATUS_LOCK = threading.Lock()
ROUTER_STATUS_CACHE = {
    "fetchedAt": 0.0,
    "payload": None,
}
ROUTER_STATUS_POLL_SEC = max(float(os.getenv("NIDPS_ROUTER_STATUS_POLL_SEC", "5.0") or 5.0), 1.0)
ROUTER_STATIC_REFRESH_SEC = max(float(os.getenv("NIDPS_ROUTER_STATIC_REFRESH_SEC", "60.0") or 60.0), ROUTER_STATUS_POLL_SEC)
EVENT_CACHE_LOCK = threading.Lock()
EVENT_CACHE = {
    "stamp": None,
    "events": [],
}
EVENT_SUMMARY_CACHE_LOCK = threading.Lock()
EVENT_SUMMARY_CACHE = {
    "stamp": None,
    "sample_stamp": None,
    "liveAlerts": 0,
    "threatOverviewItems": [],
    "threatOverviewTotal": 0,
}
ONLINE_SAMPLE_CACHE_LOCK = threading.Lock()
ONLINE_SAMPLE_CACHE = {
    "stamp": None,
    "samples": [],
}
ONLINE_MODEL_CACHE_LOCK = threading.Lock()
ONLINE_MODEL_CACHE = {
    "attack_stamp": None,
    "malware_stamp": None,
    "models": None,
}
RUNTIME_HISTORY_CACHE_LOCK = threading.Lock()
RUNTIME_HISTORY_CACHE = {
    "stamp": None,
    "offset": 0,
    "items": [],
}

DISPLAY_THR_ATTACK = {
    "ICMP_FLOOD": 0.55,
    "HTTP_FLOOD": 0.72,
    "TCP_FLOOD": 0.72,
    "UDP_FLOOD": 0.72,
    "CONN_FLOOD": 0.74,
    "PORT_SCAN": 0.60,
    "SSH_BRUTE_FORCE": 0.50,
    "FTP_BRUTE_FORCE": 0.50,
    "TELNET_BRUTE_FORCE": 0.50,
    "RDP_BRUTE_FORCE": 0.50,
    "WINBOX_BRUTE_FORCE": 0.50,
    "DNS_TUNNEL": 0.70,
    "DATA_EXFIL": 0.72,
    "SUSP_HIGH_PORT": 0.70,
    "C2_BEACON": 0.75,
    "CRYPTO_MINER": 0.70,
    "C2_BACKDOOR": 0.70,
    "RANSOMWARE_PRECHECK": 0.70,
}
DISPLAY_THR_MAL = {
    "C2_BEACON": 0.60,
    "DNS_TUNNEL": 0.65,
    "DATA_EXFIL": 0.65,
    "CRYPTO_MINER": 0.60,
    "C2_BACKDOOR": 0.60,
    "RANSOMWARE_PRECHECK": 0.60,
}
DISPLAY_THR_ATTACK_DEFAULT = 0.70
DISPLAY_THR_MAL_DEFAULT = 0.65
DISPLAY_RANSOMWARE_PRECHECK_RAW_PASS_MAL = 0.230


def _request_remote_addr() -> str:
    return str(request.remote_addr or "").strip()


def _is_loopback_request() -> bool:
    remote_addr = _request_remote_addr()
    if not remote_addr:
        return False
    try:
        return ipaddress.ip_address(remote_addr).is_loopback
    except ValueError:
        return False


def _expected_admin_token() -> str:
    return ADMIN_API_TOKEN or LOCAL_BOOTSTRAP_ADMIN_TOKEN


def _admin_token_error() -> str:
    if ADMIN_API_TOKEN:
        return f"Missing or invalid admin token. Provide it in the {ADMIN_TOKEN_HEADER} header."
    return (
        f"Missing or invalid admin token. Open the local dashboard to fetch a bootstrap token, "
        f"or set NIDPS_ADMIN_TOKEN and send it in the {ADMIN_TOKEN_HEADER} header."
    )


def require_admin_access(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        provided_token = str(request.headers.get(ADMIN_TOKEN_HEADER, "") or "")
        expected_token = _expected_admin_token()
        if not provided_token or not secrets.compare_digest(provided_token, expected_token):
            return jsonify({
                "ok": False,
                "error": _admin_token_error(),
            }), 401

        return view_func(*args, **kwargs)

    return wrapped


def parse_ip_literal(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError as exc:
        raise ValueError("Invalid IP address.") from exc


def run_auto_label_with_lock(limit: int = 0) -> dict:
    with ONLINE_LOCK:
        return auto_label_pending(limit=max(limit, 0))


def run_train_with_lock(limit: int = 0, checkpoint: bool = False) -> dict:
    with ONLINE_LOCK:
        state = load_control_state()
        return train_ready_samples(
            limit=max(limit, 0),
            checkpoint=checkpoint,
            min_reference_samples=int(state.get("shadowEvalMinReferenceSamples", 5) or 5),
            min_samples=int(state.get("autoTrainMinBatchSamples", 1) or 1),
        )


def run_shadow_automation_cycle() -> dict | None:
    state = load_control_state()
    auto_label_result = run_auto_label_with_lock(limit=0)
    ready_samples = list_distinct_trainable_samples()
    tail_batch_allowed = can_auto_train_single_tail_sample(ready_samples)
    if not state.get("autoTrainEnabled", True):
        learning = summarize_online_learning()
        ready = int(learning.get("readyForTraining", 0) or 0)
        ready_weight = float(learning.get("readyWeight", 0.0) or 0.0)
        min_weight = max(float(state.get("autoTrainMinWeight", 24.0) or 24.0), 0.5)
        return {
            "autoLabel": auto_label_result,
            "trained": None,
            "ready": ready,
            "readyWeight": ready_weight,
            "minWeight": min_weight,
            "tailBatchAllowed": tail_batch_allowed,
        }

    learning = summarize_online_learning()
    ready = int(learning.get("readyForTraining", 0) or 0)
    ready_weight = float(learning.get("readyWeight", 0.0) or 0.0)
    min_weight = max(float(state.get("autoTrainMinWeight", 24.0) or 24.0), 0.5)
    checkpoint_weight = max(float(state.get("autoCheckpointMinWeight", 24.0) or 24.0), min_weight)
    batch_weight = max(float(state.get("autoTrainBatchWeight", 36.0) or 36.0), min_weight)
    batch_samples = max(int(state.get("autoTrainMaxBatchSamples", 4) or 4), 1)
    min_batch_samples = max(int(state.get("autoTrainMinBatchSamples", 3) or 3), 1)
    min_reference = max(int(state.get("shadowEvalMinReferenceSamples", 8) or 8), 0)

    if (ready_weight < min_weight or ready < min_batch_samples) and not tail_batch_allowed:
        return {
            "autoLabel": auto_label_result,
            "trained": None,
            "ready": ready,
            "readyWeight": ready_weight,
            "minWeight": min_weight,
            "minBatchSamples": min_batch_samples,
            "tailBatchAllowed": tail_batch_allowed,
        }

    with ONLINE_LOCK:
        result = train_ready_samples(
            limit=0,
            checkpoint=ready_weight >= checkpoint_weight,
            max_weight=batch_weight,
            max_samples=batch_samples,
            min_reference_samples=min_reference,
            min_samples=1 if tail_batch_allowed else min_batch_samples,
        )
    trained_count = int(result.get("trained", 0) or 0)
    if trained_count > 0:
        update_auto_train_stats(trained_count, float(result.get("trained_weight", 0.0) or 0.0))
    return {
        "autoLabel": auto_label_result,
        "trained": result,
        "ready": ready,
        "readyWeight": ready_weight,
        "minWeight": min_weight,
        "batchWeight": batch_weight,
        "batchSamples": batch_samples,
        "tailBatchAllowed": tail_batch_allowed,
    }


def shadow_automation_worker() -> None:
    while True:
        try:
            run_shadow_automation_cycle()
        except Exception as exc:
            print(f"[shadow-auto] {exc}")
        time.sleep(AUTO_TRAIN_POLL_SEC)


def start_shadow_automation_worker() -> None:
    worker = threading.Thread(target=shadow_automation_worker, name="shadow-auto-train", daemon=True)
    worker.start()


def refresh_router_snapshot() -> dict:
    configured = bool(ROUTER_USER and ROUTER_PASS)
    base_payload = {
        "routerIp": ROUTER_IP,
        "configured": configured,
        "reachable": False,
        "identity": None,
        "version": None,
        "uptime": None,
        "architecture": None,
        "cpuLoad": None,
        "memoryUsagePercent": None,
        "totalMemoryMb": None,
        "freeMemoryMb": None,
        "usedMemoryMb": None,
        "blockedCount": 0,
        "blockedIps": [],
        "honeypotCount": 0,
        "honeypotIps": [],
        "activeConnectionCount": 0,
        "trackedThreatSources": 0,
        "lastCheckedAt": None,
        "status": "Not configured" if not configured else "Offline",
        "error": None,
    }

    if not configured:
        with ROUTER_STATUS_LOCK:
            ROUTER_STATUS_CACHE["fetchedAt"] = time.time()
            ROUTER_STATUS_CACHE["payload"] = dict(base_payload)
        return base_payload

    now = time.time()
    with ROUTER_STATUS_LOCK:
        previous_payload = dict(ROUTER_STATUS_CACHE.get("payload") or base_payload)
        previous_fetched_at = float(ROUTER_STATUS_CACHE.get("fetchedAt", 0.0) or 0.0)

    payload = dict(previous_payload)
    payload.update({
        "routerIp": ROUTER_IP,
        "configured": True,
        "lastCheckedAt": fmt_ts(now),
        "status": "Offline",
        "error": None,
    })

    try:
        commands = {
            "resource": '/system resource print without-paging',
            "blocks": f'/ip firewall address-list print terse without-paging where list={BLOCK_LIST}',
            "honeypot": f'/ip firewall address-list print terse without-paging where list={HONEYPOT_BRUTEFORCE_LIST}',
            "connections": '/ip firewall connection print count-only',
        }
        should_refresh_static = (
            not previous_payload.get("identity")
            or not previous_payload.get("version")
            or not previous_fetched_at
            or (now - previous_fetched_at) >= ROUTER_STATIC_REFRESH_SEC
        )
        if should_refresh_static:
            commands["identity"] = '/system identity print without-paging'

        results = run_router_commands(commands)
        resource_data = _parse_router_kv_output(results["resource"][0])
        identity_data = _parse_router_kv_output(results["identity"][0]) if "identity" in results else {}
        blocked_ips = _extract_blocked_addresses(results["blocks"][0])
        honeypot_ips = _extract_blocked_addresses(results["honeypot"][0])
        active_connection_count = _safe_int((results.get("connections") or ("0", ""))[0].strip(), 0)

        payload.update({
            "reachable": True,
            "identity": identity_data.get("name") or previous_payload.get("identity"),
            "version": resource_data.get("version") or previous_payload.get("version"),
            "uptime": resource_data.get("uptime"),
            "architecture": resource_data.get("architecture-name") or previous_payload.get("architecture"),
            "cpuLoad": resource_data.get("cpu-load"),
            "totalMemoryMb": _router_size_to_mb(resource_data.get("total-memory")),
            "freeMemoryMb": _router_size_to_mb(resource_data.get("free-memory")),
            "blockedCount": len(blocked_ips),
            "blockedIps": blocked_ips,
            "honeypotCount": len(honeypot_ips),
            "honeypotIps": honeypot_ips,
            "activeConnectionCount": active_connection_count,
            "trackedThreatSources": len(set(blocked_ips + honeypot_ips)),
            "status": "Online",
            "error": None,
        })
        total_memory_mb = payload.get("totalMemoryMb")
        free_memory_mb = payload.get("freeMemoryMb")
        if total_memory_mb is not None and free_memory_mb is not None and total_memory_mb > 0:
            used_memory_mb = max(float(total_memory_mb) - float(free_memory_mb), 0.0)
            payload["usedMemoryMb"] = round(used_memory_mb, 1)
            payload["memoryUsagePercent"] = round((used_memory_mb / float(total_memory_mb)) * 100, 1)
    except Exception as exc:
        payload.update({
            "reachable": False,
            "status": "Offline",
            "error": str(exc),
        })

    with ROUTER_STATUS_LOCK:
        ROUTER_STATUS_CACHE["fetchedAt"] = now
        ROUTER_STATUS_CACHE["payload"] = dict(payload)
    return payload


def router_status_worker() -> None:
    while True:
        try:
            refresh_router_snapshot()
        except Exception as exc:
            print(f"[router-status] {exc}")
        time.sleep(ROUTER_STATUS_POLL_SEC)


def start_router_status_worker() -> None:
    worker = threading.Thread(target=router_status_worker, name="router-status-worker", daemon=True)
    worker.start()

ROUTER_IP = os.getenv("NIDPS_ROUTER_IP", "192.168.88.1")
ROUTER_USER = os.getenv("NIDPS_ROUTER_USER", "")
ROUTER_PASS = os.getenv("NIDPS_ROUTER_PASS", "")


def fmt_ts(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def describe_file(path: Path) -> dict:
    exists = path.exists()
    return {
        "path": str(path),
        "name": path.name,
        "exists": exists,
        "size": path.stat().st_size if exists else 0,
        "updatedAt": fmt_ts(path.stat().st_mtime) if exists else None,
    }


def latest_timestamp(*paths: Path) -> str | None:
    mtimes = [path.stat().st_mtime for path in paths if path.exists()]
    return fmt_ts(max(mtimes)) if mtimes else None


def _file_stamp(path: Path):
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return (int(stat.st_mtime_ns), int(stat.st_size))


def _read_jsonl_dicts(path: Path) -> list[dict]:
    if not path.exists():
        return []
    items: list[dict] = []
    with path.open("r", encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.lstrip("\ufeff").strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if isinstance(payload, dict):
                items.append(payload)
    return items


def _get_cached_events() -> list[dict]:
    stamp = _file_stamp(JSONL_FILE)
    with EVENT_CACHE_LOCK:
        if stamp == EVENT_CACHE["stamp"]:
            return list(EVENT_CACHE["events"])

    events = _read_jsonl_dicts(JSONL_FILE)
    with EVENT_CACHE_LOCK:
        EVENT_CACHE["stamp"] = stamp
        EVENT_CACHE["events"] = events
    return list(events)


def _humanize_rule(rule: str) -> str:
    normalized = str(rule or "").strip().upper()
    if normalized == "OBS_UNKNOWN":
        return "Unknown Traffic"
    return str(rule or "").replace("_", " ").title() or "Unknown Threat"


def _infer_threat_category(event: dict, sample=None) -> str:
    category = str((event or {}).get("category", "")).upper()
    if category in {"ATTACK", "MALWARE"}:
        return category
    family_label = str(
        (event or {}).get("family_label")
        or getattr(sample, "family_label", None)
        or ""
    ).lower()
    if family_label.startswith("attack."):
        return "ATTACK"
    if family_label.startswith("malware."):
        return "MALWARE"
    return ""


def _canonical_threat_title(event: dict, sample=None) -> str:
    display_label = str(
        (event or {}).get("display_label")
        or getattr(sample, "display_label", None)
        or ""
    ).strip()
    if display_label:
        return display_label
    return _humanize_rule((event or {}).get("rule", ""))


def _get_cached_event_summaries() -> dict:
    stamp = _file_stamp(JSONL_FILE)
    sample_stamp = _file_stamp(ONLINE_STORE.path)
    with EVENT_SUMMARY_CACHE_LOCK:
        if stamp == EVENT_SUMMARY_CACHE["stamp"] and sample_stamp == EVENT_SUMMARY_CACHE["sample_stamp"]:
            return {
                "liveAlerts": int(EVENT_SUMMARY_CACHE["liveAlerts"]),
                "threatOverviewItems": list(EVENT_SUMMARY_CACHE["threatOverviewItems"]),
                "threatOverviewTotal": int(EVENT_SUMMARY_CACHE["threatOverviewTotal"]),
            }

    live_alerts = 0
    grouped: dict[str, dict] = {}
    sample_map = {
        sample.event_id: sample
        for sample in _get_cached_online_samples()
        if str(getattr(sample, "event_id", "") or "").strip()
    }
    for event in _get_cached_events():
        if not isinstance(event, dict) or is_suppressed_decision(event.get("decision")):
            continue
        live_alerts += 1
        sample = sample_map.get(str(event.get("event_id", "")).strip())
        category = _infer_threat_category(event, sample=sample)
        if category not in {"ATTACK", "MALWARE"}:
            continue
        title = _canonical_threat_title(event, sample=sample)
        key = f"{category}:{title.lower()}"
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = {
                "key": key,
                "title": title,
                "count": 1,
                "category": category,
            }
        else:
            existing["count"] += 1

    items = sorted(grouped.values(), key=lambda item: (-int(item["count"]), item["title"].lower()))
    total = sum(int(item["count"]) for item in items)

    with EVENT_SUMMARY_CACHE_LOCK:
        EVENT_SUMMARY_CACHE["stamp"] = stamp
        EVENT_SUMMARY_CACHE["sample_stamp"] = sample_stamp
        EVENT_SUMMARY_CACHE["liveAlerts"] = live_alerts
        EVENT_SUMMARY_CACHE["threatOverviewItems"] = items
        EVENT_SUMMARY_CACHE["threatOverviewTotal"] = total
    return {
        "liveAlerts": live_alerts,
        "threatOverviewItems": list(items),
        "threatOverviewTotal": total,
    }


def _get_cached_cumulative_live_alert_count() -> int:
    return int(_get_cached_event_summaries()["liveAlerts"])


def _get_cached_online_samples():
    stamp = _file_stamp(ONLINE_STORE.path)
    with ONLINE_SAMPLE_CACHE_LOCK:
        if stamp == ONLINE_SAMPLE_CACHE["stamp"]:
            return list(ONLINE_SAMPLE_CACHE["samples"])

    try:
        samples = ONLINE_STORE.list_samples()
    except OSError:
        with ONLINE_SAMPLE_CACHE_LOCK:
            return list(ONLINE_SAMPLE_CACHE["samples"])
    with ONLINE_SAMPLE_CACHE_LOCK:
        ONLINE_SAMPLE_CACHE["stamp"] = stamp
        ONLINE_SAMPLE_CACHE["samples"] = samples
    return list(samples)


def _safe_list_distinct_trainable_samples():
    try:
        return list_distinct_trainable_samples()
    except OSError:
        return []


def _get_cached_online_models_if_ready():
    attack_stamp = _file_stamp(ATTACK_ONLINE_MODEL_PATH)
    malware_stamp = _file_stamp(MALWARE_ONLINE_MODEL_PATH)
    if attack_stamp is None or malware_stamp is None:
        with ONLINE_MODEL_CACHE_LOCK:
            ONLINE_MODEL_CACHE["attack_stamp"] = attack_stamp
            ONLINE_MODEL_CACHE["malware_stamp"] = malware_stamp
            ONLINE_MODEL_CACHE["models"] = None
        return None

    with ONLINE_MODEL_CACHE_LOCK:
        if (
            ONLINE_MODEL_CACHE["attack_stamp"] == attack_stamp
            and ONLINE_MODEL_CACHE["malware_stamp"] == malware_stamp
        ):
            return ONLINE_MODEL_CACHE["models"]

    models = load_online_models()
    with ONLINE_MODEL_CACHE_LOCK:
        ONLINE_MODEL_CACHE["attack_stamp"] = attack_stamp
        ONLINE_MODEL_CACHE["malware_stamp"] = malware_stamp
        ONLINE_MODEL_CACHE["models"] = models
    return models


def read_latest_events(limit: int = 100):
    events = _get_cached_events()
    return events[-limit:]


def read_all_events():
    return _get_cached_events()


def _get_cached_event_map() -> dict[str, dict]:
    event_map: dict[str, dict] = {}
    for event in _get_cached_events():
        event_id = str((event or {}).get("event_id", "")).strip()
        if not event_id:
            continue
        event_map[event_id] = event
    return event_map


def normalize_event_scores_for_display(event: dict, sample=None) -> dict:
    payload = dict(event or {})
    category = str(payload.get("category", "")).upper()

    if sample is not None:
        payload["display_label"] = getattr(sample, "display_label", None)
        payload["family_label"] = getattr(sample, "family_label", None)
        payload["family_confidence"] = getattr(sample, "family_confidence", None)
        payload["novelty_score"] = getattr(sample, "novelty_score", None)
        payload["auto_label_source"] = getattr(sample, "label_source", None)

    if category == "ATTACK":
        payload["mal"] = ""
        payload["shadow_mal"] = ""
    elif category == "MALWARE":
        payload["atk"] = ""
        payload["shadow_atk"] = ""
    elif category == "OBSERVED":
        payload["atk"] = ""
        payload["mal"] = ""
        payload["shadow_atk"] = ""
        payload["shadow_mal"] = ""

    return payload


def is_blocked_decision(decision: str) -> bool:
    d = str(decision or "").upper()
    return d.startswith("BLOCKED")


def is_honeypot_decision(decision: str) -> bool:
    d = str(decision or "").upper()
    return "HONEYPOT" in d


def is_suppressed_decision(decision: str) -> bool:
    return str(decision or "").upper() == "SUPPRESSED_VICTIM_LEG"


def _event_ts_value(event: dict) -> str:
    return str((event or {}).get("ts", ""))


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _event_window_key(event: dict, window_seconds: int = 30) -> str:
    ts_text = _event_ts_value(event)
    if not ts_text:
        return ""
    try:
        dt = datetime.strptime(ts_text, "%Y-%m-%d %H:%M:%S")
        epoch = int(dt.timestamp())
        floored = epoch - (epoch % max(window_seconds, 1))
        return datetime.fromtimestamp(floored).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_text


def merge_observed_events_for_display(events: list[dict], window_seconds: int = 30) -> list[dict]:
    merged: list[dict] = []
    grouped: dict[tuple[str, str, str, str, str], dict] = {}

    for event in events or []:
        payload = dict(event or {})
        decision = str(payload.get("decision", "")).upper()
        category = str(payload.get("category", "")).upper()
        if decision != "OBSERVED" or category != "OBSERVED":
            merged.append(payload)
            continue

        key = (
            _event_window_key(payload, window_seconds),
            str(payload.get("rule", "")),
            str(payload.get("src", "")),
            str(payload.get("dst", "")),
            decision,
        )
        existing = grouped.get(key)
        if existing is None:
            payload["merged_count"] = 1
            grouped[key] = payload
            merged.append(payload)
            continue

        existing["merged_count"] = _safe_int(existing.get("merged_count", 1), 1) + 1
        for field in ("flows", "spkts", "dpkts", "sbytes", "dbytes"):
            existing[field] = _safe_int(existing.get(field, 0), 0) + _safe_int(payload.get(field, 0), 0)
        existing["uniq_dports"] = max(_safe_int(existing.get("uniq_dports", 0), 0), _safe_int(payload.get("uniq_dports", 0), 0))
        existing["ts"] = max(str(existing.get("ts", "")), str(payload.get("ts", "")))

    return merged


def _parse_router_kv_output(raw: str) -> dict:
    data = {}
    for line in (raw or '').splitlines():
        line = line.strip()
        if not line or ':' not in line:
            continue
        key, value = line.split(':', 1)
        data[key.strip()] = value.strip()
    return data


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _optional_float(value):
    try:
        if value in (None, ""):
            return None
        return float(value)
    except Exception:
        return None


def _optional_int(value):
    try:
        if value in (None, ""):
            return None
        return int(float(value))
    except Exception:
        return None


def _protocol_label(value) -> str | None:
    proto = _optional_int(value)
    if proto is None:
        return None
    return {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }.get(proto, str(proto))


def _infer_top_dport(features: dict | None) -> int | None:
    feat = features or {}
    known_ports = (
        (22, "top_is_22"),
        (53, "top_is_53"),
        (67, "top_is_67"),
        (68, "top_is_68"),
        (80, "top_is_80"),
        (123, "top_is_123"),
        (443, "top_is_443"),
        (445, "top_is_445"),
        (8291, "top_is_8291"),
        (3333, "top_is_3333"),
        (4444, "top_is_4444"),
        (5555, "top_is_5555"),
        (9001, "top_is_9001"),
        (1337, "top_is_1337"),
        (14444, "top_is_14444"),
    )
    for port, key in known_ports:
        if _safe_float(feat.get(key), 0.0) >= 1.0:
            return port
    return None


def _extract_sample_observation(sample, event_payload: dict | None = None) -> dict:
    feat = sample.features or {}
    flows = _optional_int(event_payload.get("flows") if event_payload else None)
    if flows is None:
        flows = _optional_int(feat.get("flows"))

    spkts = _optional_int(event_payload.get("spkts") if event_payload else None)
    if spkts is None:
        spkts = _optional_int(feat.get("Spkts"))

    dpkts = _optional_int(event_payload.get("dpkts") if event_payload else None)
    if dpkts is None:
        dpkts = _optional_int(feat.get("Dpkts"))

    sbytes = _optional_int(event_payload.get("sbytes") if event_payload else None)
    if sbytes is None:
        sbytes = _optional_int(feat.get("sbytes"))

    dbytes = _optional_int(event_payload.get("dbytes") if event_payload else None)
    if dbytes is None:
        dbytes = _optional_int(feat.get("dbytes"))

    uniq_dports = _optional_int(event_payload.get("uniq_dports") if event_payload else None)
    if uniq_dports is None:
        uniq_dports = _optional_int(feat.get("uniq_dports"))

    proto = _optional_int(event_payload.get("proto") if event_payload else None)
    if proto is None:
        proto = _optional_int(feat.get("proto_mode"))

    top_dport = _optional_int(event_payload.get("top_dport") if event_payload else None)
    if top_dport is None:
        top_dport = _infer_top_dport(feat)

    total_pkts = None if spkts is None and dpkts is None else int((spkts or 0) + (dpkts or 0))
    total_bytes = None if sbytes is None and dbytes is None else int((sbytes or 0) + (dbytes or 0))

    return {
        "flows": flows,
        "spkts": spkts,
        "dpkts": dpkts,
        "total_pkts": total_pkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "total_bytes": total_bytes,
        "uniq_dports": uniq_dports,
        "proto": proto,
        "proto_label": _protocol_label(proto),
        "top_dport": top_dport,
    }


def _calibrated_exp_score(raw_score: float, threshold: float, raw_pass_score: float) -> float:
    raw = min(max(float(raw_score), 0.0), 1.0)
    thr = min(max(float(threshold), 1e-6), 0.999999)
    pass_raw = max(float(raw_pass_score), 1e-6)
    scale = -math.log(1.0 - thr) / pass_raw
    return 1.0 - math.exp(-scale * raw)


def _shadow_display_score(rule: str, category: str, attack_score, malware_score) -> tuple[float | None, float | None]:
    normalized_rule = str(rule or "").upper()
    normalized_category = str(category or "").upper()
    attack_value = _optional_float(attack_score)
    malware_value = _optional_float(malware_score)

    display_attack = None
    display_malware = None

    if attack_value is not None and normalized_category in {"ATTACK", "MALWARE"}:
        attack_thr = DISPLAY_THR_ATTACK.get(normalized_rule, DISPLAY_THR_ATTACK_DEFAULT)
        display_attack = round(_calibrated_exp_score(attack_value, attack_thr, attack_thr), 4)

    if malware_value is not None and normalized_category == "MALWARE":
        malware_thr = DISPLAY_THR_MAL.get(normalized_rule, DISPLAY_THR_MAL_DEFAULT)
        raw_pass = (
            DISPLAY_RANSOMWARE_PRECHECK_RAW_PASS_MAL
            if normalized_rule == "RANSOMWARE_PRECHECK"
            else malware_thr
        )
        display_malware = round(_calibrated_exp_score(malware_value, malware_thr, raw_pass), 4)

    return display_attack, display_malware


def _bytes_to_mb(value) -> float:
    return round(_safe_float(value, 0.0) / (1024 * 1024), 1)


def _router_size_to_mb(value):
    if value in (None, ""):
        return None

    text = str(value).strip()
    if not text:
        return None

    normalized = text.replace("iB", "ib").replace("IB", "ib").replace(" ", "")
    units = [
        ("gib", 1024),
        ("gb", 1024),
        ("mib", 1),
        ("mb", 1),
        ("kib", 1 / 1024),
        ("kb", 1 / 1024),
        ("b", 1 / (1024 * 1024)),
    ]
    normalized_lower = normalized.lower()
    for suffix, multiplier in units:
        if normalized_lower.endswith(suffix):
            number = normalized[:-len(suffix)]
            try:
                return round(float(number) * multiplier, 1)
            except Exception:
                return None

    try:
        raw_value = float(normalized)
    except Exception:
        return None

    if raw_value > 1024 * 1024:
        return round(raw_value / (1024 * 1024), 1)
    return round(raw_value, 1)


def summarize_flow_metrics(limit: int = 500) -> dict:
    events = read_latest_events(limit)
    packets_parsed = 0
    flow_records = 0
    for event in events:
        packets_parsed += _safe_int(event.get("spkts"), 0) + _safe_int(event.get("dpkts"), 0)
        flow_records += _safe_int(event.get("flows"), 0)

    return {
        "packetsParsed": packets_parsed,
        "flowRecords": flow_records,
        "metricsWindowEvents": len(events),
    }


def read_runtime_metrics() -> dict:
    if not RUNTIME_METRICS_FILE.exists():
        return {}
    try:
        with exclusive_lock(RUNTIME_METRICS_LOCK):
            with RUNTIME_METRICS_FILE.open("r", encoding="utf-8-sig") as fh:
                return json.load(fh) or {}
    except Exception:
        return {}


def read_runtime_metrics_history() -> list[dict]:
    if not RUNTIME_METRICS_HISTORY_FILE.exists():
        with RUNTIME_HISTORY_CACHE_LOCK:
            RUNTIME_HISTORY_CACHE["stamp"] = None
            RUNTIME_HISTORY_CACHE["offset"] = 0
            RUNTIME_HISTORY_CACHE["items"] = []
        return []
    cutoff_ts = time.time() - RUNTIME_METRICS_RETENTION_SEC
    stamp = _file_stamp(RUNTIME_METRICS_HISTORY_FILE)
    if stamp is None:
        return []

    with RUNTIME_HISTORY_CACHE_LOCK:
        cached_stamp = RUNTIME_HISTORY_CACHE["stamp"]
        cached_offset = int(RUNTIME_HISTORY_CACHE["offset"] or 0)
        cached_items = list(RUNTIME_HISTORY_CACHE["items"])

    if cached_stamp == stamp:
        filtered = [item for item in cached_items if _safe_float(item.get("updatedAtEpoch"), 0.0) >= cutoff_ts]
        if len(filtered) != len(cached_items):
            with RUNTIME_HISTORY_CACHE_LOCK:
                RUNTIME_HISTORY_CACHE["items"] = filtered
        return filtered

    size = int(stamp[1])
    needs_full_reload = cached_stamp is None or size < cached_offset
    if needs_full_reload:
        items: list[dict] = []
        start_offset = 0
    else:
        items = [item for item in cached_items if _safe_float(item.get("updatedAtEpoch"), 0.0) >= cutoff_ts]
        start_offset = cached_offset

    try:
        with exclusive_lock(RUNTIME_METRICS_HISTORY_LOCK):
            with RUNTIME_METRICS_HISTORY_FILE.open("r", encoding="utf-8-sig") as fh:
                if start_offset > 0:
                    fh.seek(start_offset)
                for line in fh:
                    line = line.lstrip("\ufeff").strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(payload, dict):
                        continue
                    item_ts = _safe_float(payload.get("updatedAtEpoch"), 0.0)
                    if item_ts and item_ts < cutoff_ts:
                        continue
                    items.append(payload)
                end_offset = fh.tell()
    except Exception:
        return [item for item in cached_items if _safe_float(item.get("updatedAtEpoch"), 0.0) >= cutoff_ts]

    with RUNTIME_HISTORY_CACHE_LOCK:
        RUNTIME_HISTORY_CACHE["stamp"] = stamp
        RUNTIME_HISTORY_CACHE["offset"] = end_offset
        RUNTIME_HISTORY_CACHE["items"] = items
    return items


def build_runtime_metrics_payload() -> dict:
    runtime_metrics = read_runtime_metrics()
    history = read_runtime_metrics_history()
    latest = history[-1] if history else runtime_metrics
    earliest = history[0] if history else runtime_metrics

    latest_packets = _safe_int((latest or {}).get("recvPackets"), _safe_int(runtime_metrics.get("recvPackets"), 0))
    earliest_packets = _safe_int((earliest or {}).get("recvPackets"), latest_packets)
    latest_flows = _safe_int((latest or {}).get("parsedFlows"), _safe_int(runtime_metrics.get("parsedFlows"), 0))
    earliest_flows = _safe_int((earliest or {}).get("parsedFlows"), latest_flows)

    has_packet_deltas = any("recvPacketsDelta" in item for item in history)
    has_flow_deltas = any("parsedFlowsDelta" in item for item in history)

    if has_packet_deltas:
        packets_last_30m = sum(max(_safe_int(item.get("recvPacketsDelta"), 0), 0) for item in history)
    else:
        packets_last_30m = latest_packets - earliest_packets
        if packets_last_30m < 0:
            packets_last_30m = latest_packets

    if has_flow_deltas:
        flow_records_last_30m = sum(max(_safe_int(item.get("parsedFlowsDelta"), 0), 0) for item in history)
    else:
        flow_records_last_30m = latest_flows - earliest_flows
        if flow_records_last_30m < 0:
            flow_records_last_30m = latest_flows

    history_span_seconds = 0
    latest_epoch = _safe_float((latest or {}).get("updatedAtEpoch"), 0.0)
    earliest_epoch = _safe_float((earliest or {}).get("updatedAtEpoch"), 0.0)
    if latest_epoch > 0 and earliest_epoch > 0 and latest_epoch >= earliest_epoch:
        history_span_seconds = int(latest_epoch - earliest_epoch)

    cumulative_packets = _safe_int((latest or {}).get("recvPackets"), _safe_int(runtime_metrics.get("recvPackets"), 0))
    cumulative_flows = _safe_int((latest or {}).get("parsedFlows"), _safe_int(runtime_metrics.get("parsedFlows"), 0))
    packet_rate = _safe_int((latest or {}).get("recvPacketsDelta"), _safe_int(runtime_metrics.get("recvPacketsDelta"), 0))
    flow_rate = _safe_int((latest or {}).get("parsedFlowsDelta"), _safe_int(runtime_metrics.get("parsedFlowsDelta"), 0))

    return {
        "packetsParsed": cumulative_packets,
        "flowRecords": cumulative_flows,
        "packetsParsedRate": packet_rate,
        "flowRecordsRate": flow_rate,
        "packetsParsedRolling30m": packets_last_30m,
        "flowRecordsRolling30m": flow_records_last_30m,
        "activeAggregates": _safe_int((latest or {}).get("activeAggregates"), _safe_int(runtime_metrics.get("activeAggregates"), 0)),
        "runtimeMetricsUpdatedAt": (latest or {}).get("updatedAt") or runtime_metrics.get("updatedAt"),
        "metricsWindowEvents": len(history),
        "windowSeconds": _safe_int(runtime_metrics.get("windowSeconds"), 30),
        "historySpanSeconds": history_span_seconds,
    }


def _extract_blocked_addresses(router_output: str) -> list[str]:
    addresses = []
    seen = set()
    for line in (router_output or "").splitlines():
        for token in line.split():
            if token.startswith("address="):
                addr = token.split("=", 1)[1].strip()
                if addr and addr not in seen:
                    seen.add(addr)
                    addresses.append(addr)
    return addresses


def get_current_blocked_ips() -> list[str]:
    snapshot = get_cached_router_snapshot()
    blocked_ips = snapshot.get("blockedIps")
    if isinstance(blocked_ips, list):
        return [str(ip) for ip in blocked_ips if str(ip)]
    return []


def get_current_honeypot_ips() -> list[str]:
    snapshot = get_cached_router_snapshot()
    honeypot_ips = snapshot.get("honeypotIps")
    if isinstance(honeypot_ips, list):
        return [str(ip) for ip in honeypot_ips if str(ip)]
    return []


def get_cached_router_snapshot() -> dict:
    with ROUTER_STATUS_LOCK:
        cached_payload = ROUTER_STATUS_CACHE.get("payload")
        if cached_payload:
            return dict(cached_payload)

    return refresh_router_snapshot()


def _connect_router_client():
    if not ROUTER_USER or not ROUTER_PASS:
        raise RuntimeError("Missing router credentials in environment variables.")

    ssh = build_router_ssh_client()
    ssh.connect(
        ROUTER_IP,
        username=ROUTER_USER,
        password=ROUTER_PASS,
        look_for_keys=False,
        allow_agent=False,
        timeout=8,
        banner_timeout=8,
        auth_timeout=8,
    )
    return ssh


def _exec_router_command(ssh, command: str):
    stdin, stdout, stderr = ssh.exec_command(command, timeout=8)
    out = stdout.read().decode(errors="ignore").strip()
    err = stderr.read().decode(errors="ignore").strip()
    return out, err


def run_router_commands(commands: dict[str, str]) -> dict[str, tuple[str, str]]:
    ssh = _connect_router_client()
    try:
        return {key: _exec_router_command(ssh, command) for key, command in commands.items()}
    finally:
        ssh.close()


def router_exec(command: str):
    ssh = _connect_router_client()
    try:
        return _exec_router_command(ssh, command)
    finally:
        ssh.close()


def _run_honeypot_ssh(command: str) -> str:
    if not HONEYPOT_SSH_HOST or not HONEYPOT_SSH_USER:
        raise RuntimeError("Honeypot SSH host/user is not configured.")

    ssh_target = f"{HONEYPOT_SSH_USER}@{HONEYPOT_SSH_HOST}"
    ssh_cmd = [
        "ssh",
        "-p",
        str(HONEYPOT_SSH_PORT),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        ssh_target,
        command,
    ]
    try:
        completed = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("OpenSSH client was not found on the NIDPS host.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Timed out while reading honeypot logs over SSH.") from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(stderr or "Failed to read honeypot logs over SSH.")
    return completed.stdout


def _format_honeypot_log_entry(entry: dict) -> dict:
    details = []
    event_id = str(entry.get("eventid", "") or "")
    message = str(entry.get("message", "") or "")
    username = str(entry.get("username", "") or "")
    password = str(entry.get("password", "") or "")
    command_input = str(entry.get("input", "") or "")

    if message:
        details.append(message)
    if username:
        details.append(f"user={username}")
    if password:
        details.append(f"pass={password}")
    if command_input:
        details.append(f"input={command_input}")

    return {
        "kind": "honeypot",
        "ts": entry.get("timestamp") or "-",
        "eventid": event_id or "cowrie.event",
        "src": str(entry.get("src_ip", "") or ""),
        "dst": str(entry.get("dst_ip", "") or HONEYPOT_SSH_HOST or ""),
        "username": username or "-",
        "password": password or "-",
        "input": command_input or "-",
        "session": str(entry.get("session", "") or "-"),
        "message": " | ".join(details) if details else "-",
    }


def read_honeypot_logs(src_ip: str, limit: int = 50) -> list[dict]:
    safe_limit = max(1, min(limit, 100))
    quoted_path = shlex.quote(HONEYPOT_COWRIE_JSON_PATH)
    command = f"tail -n {HONEYPOT_LOG_LOOKBACK} {quoted_path}"
    raw_output = _run_honeypot_ssh(command)

    matched_entries = []
    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except Exception:
            continue
        if str(entry.get("src_ip", "") or "") != src_ip:
            continue
        matched_entries.append(_format_honeypot_log_entry(entry))

    matched_entries = matched_entries[-safe_limit:]
    matched_entries.reverse()
    return matched_entries


def summarize_online_learning() -> dict:
    total = 0
    pending = 0
    candidate = 0
    labeled = 0
    trained = 0
    trainable_ready = _safe_list_distinct_trainable_samples()
    trainable_ids = {sample.event_id for sample in trainable_ready}
    ready_weight = 0.0
    control = load_control_state()

    for sample in _get_cached_online_samples():
        total += 1
        if sample.trained:
            trained += 1
        if sample.label_status == "pending":
            pending += 1
        elif sample.label_status == "candidate":
            candidate += 1
        elif sample.label_status == "labeled" and not sample.trained:
            if sample.event_id in trainable_ids:
                labeled += 1
                ready_weight += float(getattr(sample, "learn_weight", 0.0) or 0.0)

    return {
        "storePath": str(ONLINE_STORE.path),
        "totalSamples": total,
        "pendingLabels": pending,
        "reviewCandidates": candidate,
        "readyForTraining": labeled,
        "readyWeight": round(ready_weight, 2),
        "retryLimit": 3,
        "trainedSamples": trained,
        "shadowCaptureEnabled": bool(control.get("shadowCaptureEnabled", True)),
        "autoTrainEnabled": bool(control.get("autoTrainEnabled", True)),
        "liveDecisionSource": str(control.get("liveDecisionSource", "production") or "production"),
        "lastDecisionSourceSwitchAt": control.get("lastDecisionSourceSwitchAt"),
        "autoTrainMinWeight": float(control.get("autoTrainMinWeight", 24.0) or 24.0),
        "autoTrainBatchWeight": float(control.get("autoTrainBatchWeight", 36.0) or 36.0),
        "autoTrainMaxBatchSamples": int(control.get("autoTrainMaxBatchSamples", 4) or 4),
        "autoTrainMinBatchSamples": int(control.get("autoTrainMinBatchSamples", 3) or 3),
        "autoTrainTailSingleSampleEnabled": True,
        "autoCheckpointMinTrain": int(control.get("autoCheckpointMinTrain", 50) or 50),
        "autoCheckpointMinWeight": float(control.get("autoCheckpointMinWeight", 24.0) or 24.0),
        "shadowEvalMinReferenceSamples": int(control.get("shadowEvalMinReferenceSamples", 8) or 8),
        "lastAutoTrainAt": control.get("lastAutoTrainAt"),
        "lastAutoTrainCount": int(control.get("lastAutoTrainCount", 0) or 0),
        "lastAutoTrainWeight": float(control.get("lastAutoTrainWeight", 0.0) or 0.0),
        "lastShadowEvalAt": control.get("lastShadowEvalAt"),
        "lastShadowEvalStatus": control.get("lastShadowEvalStatus"),
        "lastShadowEvalReason": control.get("lastShadowEvalReason"),
        "lastShadowEvalReferenceSamples": int(control.get("lastShadowEvalReferenceSamples", 0) or 0),
        "lastShadowEvalBatchSamples": int(control.get("lastShadowEvalBatchSamples", 0) or 0),
        "lastShadowEvalMetrics": control.get("lastShadowEvalMetrics") or {},
        "lastCheckpointAt": control.get("lastCheckpointAt"),
        "lastCheckpointDir": control.get("lastCheckpointDir"),
        "lastRollbackAt": control.get("lastRollbackAt"),
        "lastRollbackDir": control.get("lastRollbackDir"),
        "lastRollbackReason": control.get("lastRollbackReason"),
    }


def normalize_optional_label(value):
    if value in (None, '', 'null'):
        return None
    try:
        ivalue = int(value)
    except Exception:
        raise ValueError('Labels must be 0, 1, or null.')
    if ivalue not in (0, 1):
        raise ValueError('Labels must be 0 or 1.')
    return ivalue


def serialize_online_sample(sample, event_payload: dict | None = None, refresh_shadow_scores: bool = True) -> dict:
    latest_shadow_attack = getattr(sample, 'online_attack_score', None)
    latest_shadow_malware = getattr(sample, 'online_malware_score', None)
    current_attack = getattr(sample, 'current_attack_score', None)
    current_malware = getattr(sample, 'current_malware_score', None)

    if event_payload:
        if current_attack in (None, ''):
            current_attack = event_payload.get('atk', event_payload.get('prod_atk'))
        if current_malware in (None, ''):
            current_malware = event_payload.get('mal', event_payload.get('prod_mal'))

    try:
        features = {str(k): float(v) for k, v in (sample.features or {}).items()}
        if refresh_shadow_scores and features:
            models = _get_cached_online_models_if_ready()
            if models is not None:
                latest_shadow_attack, latest_shadow_malware = predict_online_scores(models, features)
    except MissingRiverDependency:
        pass
    except Exception:
        pass

    display_online_attack, display_online_malware = _shadow_display_score(
        sample.rule,
        sample.category,
        sample.online_attack_score,
        sample.online_malware_score,
    )
    display_latest_online_attack, display_latest_online_malware = _shadow_display_score(
        sample.rule,
        sample.category,
        latest_shadow_attack,
        latest_shadow_malware,
    )
    observation = _extract_sample_observation(sample, event_payload=event_payload)

    return {
        'event_id': sample.event_id,
        'ts': sample.ts,
        'src': sample.src,
        'dst': sample.dst,
        'rule': sample.rule,
        'category': sample.category,
        'decision': sample.decision,
        'xgb_attack_score': sample.xgb_attack_score,
        'xgb_malware_score': sample.xgb_malware_score,
        'current_attack_score': current_attack,
        'current_malware_score': current_malware,
        'online_attack_score': sample.online_attack_score,
        'online_malware_score': sample.online_malware_score,
        'latest_online_attack_score': latest_shadow_attack,
        'latest_online_malware_score': latest_shadow_malware,
        'display_online_attack_score': display_online_attack,
        'display_online_malware_score': display_online_malware,
        'display_latest_online_attack_score': display_latest_online_attack,
        'display_latest_online_malware_score': display_latest_online_malware,
        'attack_label': sample.attack_label,
        'malware_label': sample.malware_label,
        'family_label': getattr(sample, 'family_label', None),
        'display_label': getattr(sample, 'display_label', None),
        'family_confidence': getattr(sample, 'family_confidence', None),
        'family_source': getattr(sample, 'family_source', None),
        'novelty_score': getattr(sample, 'novelty_score', None),
        'flows': observation["flows"],
        'spkts': observation["spkts"],
        'dpkts': observation["dpkts"],
        'total_pkts': observation["total_pkts"],
        'sbytes': observation["sbytes"],
        'dbytes': observation["dbytes"],
        'total_bytes': observation["total_bytes"],
        'uniq_dports': observation["uniq_dports"],
        'proto': observation["proto"],
        'proto_label': observation["proto_label"],
        'top_dport': observation["top_dport"],
        'learn_eligible': getattr(sample, 'learn_eligible', False),
        'learn_weight': float(getattr(sample, 'learn_weight', 0.0) or 0.0),
        'learn_reason': getattr(sample, 'learn_reason', None),
        'learn_signature': getattr(sample, 'learn_signature', None),
        'reject_count': int(getattr(sample, 'reject_count', 0) or 0),
        'train_attempt_count': int(getattr(sample, 'train_attempt_count', 0) or 0),
        'last_train_attempt_at': getattr(sample, 'last_train_attempt_at', None),
        'last_rejected_at': getattr(sample, 'last_rejected_at', None),
        'last_reject_reason': getattr(sample, 'last_reject_reason', None),
        'features': sample.features or {},
        'label_status': sample.label_status,
        'label_source': sample.label_source,
        'trained': sample.trained,
    }


def _is_private_ip_text(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value or "").strip()).is_private
    except Exception:
        return False


def _network_scope_text(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "-"
    try:
        ip = ipaddress.ip_address(text)
    except Exception:
        return text
    if ip.version == 4 and ip.is_private:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return f"{network.network_address}/24"
    if ip.version == 6 and ip.is_private:
        return f"{ip.exploded[:19]}::/64"
    return "public"


def _review_risk_rank(level: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(str(level or "").lower(), 0)


def _review_risk_details(sample: dict) -> tuple[str, float, str]:
    rule = str(sample.get("rule", "") or "").upper()
    family = str(sample.get("family_label", "") or "").lower()
    decision = str(sample.get("decision", "") or "").upper()
    label_source = str(sample.get("label_source", "") or "").lower()
    family_source = str(sample.get("family_source", "") or "").lower()
    confidence = str(sample.get("family_confidence", "") or "").lower()

    attack_score = _optional_float(sample.get("current_attack_score"))
    if attack_score is None:
        attack_score = _optional_float(sample.get("xgb_attack_score"))
    malware_score = _optional_float(sample.get("current_malware_score"))
    if malware_score is None:
        malware_score = _optional_float(sample.get("xgb_malware_score"))
    novelty = _optional_float(sample.get("novelty_score")) or 0.0
    flows = _optional_int(sample.get("flows")) or 0
    uniq_dports = _optional_int(sample.get("uniq_dports")) or 0
    total_bytes = _optional_int(sample.get("total_bytes")) or 0
    top_dport = _optional_int(sample.get("top_dport")) or 0

    max_model_score = max(attack_score or 0.0, malware_score or 0.0)
    score = (max_model_score * 1.5) + (novelty * 0.9)
    reasons: list[str] = []

    if decision.startswith("BLOCKED"):
        score += 1.0
        reasons.append("live decision already blocked it")
    if confidence == "high":
        score += 0.4
        reasons.append("family confidence is high")
    elif confidence == "medium":
        score += 0.2
        reasons.append("family confidence is medium")
    if family_source in {"behavior_heuristic", "unknown", "unknown_family"}:
        score += 0.25
        reasons.append("it came from heuristic unknown-family matching")
    if flows >= 10:
        score += 0.3
        reasons.append("it repeats across many flows")
    elif flows >= 5:
        score += 0.15
        reasons.append("it appears more than once")
    if uniq_dports >= 5:
        score += 0.35
        reasons.append("it touches many destination ports")
    elif uniq_dports >= 3:
        score += 0.15
        reasons.append("it spans several destination ports")
    if total_bytes >= 4096:
        score += 0.25
        reasons.append("it moved a noticeable amount of data")
    elif total_bytes >= 1024:
        score += 0.1
        reasons.append("it is not just a tiny one-off packet")

    attack_tokens = ("FLOOD", "SCAN", "BRUTE_FORCE", "SUSP_HIGH_PORT")
    malware_tokens = ("CRYPTO_MINER", "C2_BACKDOOR", "DNS_TUNNEL", "DATA_EXFIL", "C2_BEACON", "RANSOMWARE_PRECHECK")
    suspicious_ports = {3333, 4444, 5555, 9001, 1337, 14444}

    if any(token in rule for token in attack_tokens) or family.startswith("attack."):
        score += 0.45
        reasons.append("its rule/family looks attack-like")
    if any(token in rule for token in malware_tokens) or any(token in family for token in ("backdoor", "miner", "tunnel", "beacon", "exfil")):
        score += 0.55
        reasons.append("its rule/family looks malware-like")
    if top_dport in suspicious_ports:
        score += 0.35
        reasons.append(f"it uses a suspicious service port ({top_dport})")

    safe_sources = {
        "auto_local_observed_safe",
        "auto_local_victim_leg_safe",
        "auto_family_infrastructure_safe",
        "auto_family_broadcast_safe",
    }
    if label_source in safe_sources:
        score -= 0.9
        reasons = ["it matches a trusted safe baseline pattern"]

    if decision == "OBSERVED" and _is_private_ip_text(sample.get("src", "")) and _is_private_ip_text(sample.get("dst", "")) and top_dport in {53, 67, 68, 123}:
        score -= 0.45
        if not reasons:
            reasons.append("it still looks like low-volume internal infrastructure traffic")

    level = "low"
    if decision.startswith("BLOCKED") or max_model_score >= 0.9 or score >= 2.2:
        level = "high"
    elif max_model_score >= 0.65 or score >= 1.2:
        level = "medium"

    unique_reasons: list[str] = []
    for reason in reasons:
        if reason and reason not in unique_reasons:
            unique_reasons.append(reason)
        if len(unique_reasons) >= 3:
            break
    if not unique_reasons:
        unique_reasons.append("there is not enough repeated evidence yet")

    return level, round(score, 2), "; ".join(unique_reasons)


def _review_cluster_key(sample: dict) -> str:
    family_key = str(sample.get("family_label") or sample.get("rule") or "-").strip().lower()
    proto_key = str(sample.get("proto_label") or sample.get("proto") or "-").strip().upper()
    dport_key = str(sample.get("top_dport") or "-").strip()
    decision_key = str(sample.get("decision") or "-").strip().upper()
    src_key = _network_scope_text(sample.get("src", ""))
    dst_text = str(sample.get("dst", "") or "").strip()
    dst_key = dst_text if _is_private_ip_text(dst_text) else ("external" if dst_text else "-")
    return "|".join([family_key, proto_key, dport_key, decision_key, src_key, dst_key])


def build_review_clusters(limit: int, risk: str = "high") -> dict:
    risk_mode = "all" if str(risk or "").lower() == "all" else "high"
    event_map = _get_cached_event_map()
    candidate_samples = [
        sample for sample in _get_cached_online_samples()
        if getattr(sample, "label_status", "") == "candidate"
    ]

    clusters: dict[str, dict] = {}
    for sample in candidate_samples:
        serialized = serialize_online_sample(sample, event_payload=event_map.get(sample.event_id), refresh_shadow_scores=False)
        risk_level, risk_score, risk_reason = _review_risk_details(serialized)
        serialized["review_risk_level"] = risk_level
        serialized["review_risk_score"] = risk_score
        serialized["review_risk_reason"] = risk_reason
        cluster_key = _review_cluster_key(serialized)
        current = clusters.get(cluster_key)
        if current is None:
            clusters[cluster_key] = {
                "representative": serialized,
                "event_ids": [serialized["event_id"]],
                "srcs": {str(serialized.get("src", "") or "")} - {""},
                "dsts": {str(serialized.get("dst", "") or "")} - {""},
                "first_ts": str(serialized.get("ts", "") or ""),
                "last_ts": str(serialized.get("ts", "") or ""),
                "total_flows": _optional_int(serialized.get("flows")) or 0,
                "total_pkts": _optional_int(serialized.get("total_pkts")) or 0,
                "total_bytes": _optional_int(serialized.get("total_bytes")) or 0,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "risk_reason": risk_reason,
            }
            continue

        current["event_ids"].append(serialized["event_id"])
        if serialized.get("src"):
            current["srcs"].add(str(serialized["src"]))
        if serialized.get("dst"):
            current["dsts"].add(str(serialized["dst"]))
        current["first_ts"] = min(current["first_ts"], str(serialized.get("ts", "") or ""))
        current["last_ts"] = max(current["last_ts"], str(serialized.get("ts", "") or ""))
        current["total_flows"] += _optional_int(serialized.get("flows")) or 0
        current["total_pkts"] += _optional_int(serialized.get("total_pkts")) or 0
        current["total_bytes"] += _optional_int(serialized.get("total_bytes")) or 0

        replace_rep = False
        if _review_risk_rank(risk_level) > _review_risk_rank(current["risk_level"]):
            replace_rep = True
        elif risk_level == current["risk_level"] and risk_score > current["risk_score"]:
            replace_rep = True
        elif risk_level == current["risk_level"] and risk_score == current["risk_score"] and str(serialized.get("ts", "") or "") > str(current["representative"].get("ts", "") or ""):
            replace_rep = True

        if replace_rep:
            current["representative"] = serialized
            current["risk_level"] = risk_level
            current["risk_score"] = risk_score
            current["risk_reason"] = risk_reason

    items = []
    for cluster_key, cluster in clusters.items():
        representative = dict(cluster["representative"])
        representative.update({
            "cluster_key": cluster_key,
            "cluster_event_ids": list(cluster["event_ids"]),
            "cluster_sample_count": len(cluster["event_ids"]),
            "cluster_unique_src_count": len(cluster["srcs"]),
            "cluster_unique_dst_count": len(cluster["dsts"]),
            "cluster_first_ts": cluster["first_ts"] or representative.get("ts"),
            "cluster_last_ts": cluster["last_ts"] or representative.get("ts"),
            "cluster_total_flows": cluster["total_flows"] or representative.get("flows"),
            "cluster_total_pkts": cluster["total_pkts"] or representative.get("total_pkts"),
            "cluster_total_bytes": cluster["total_bytes"] or representative.get("total_bytes"),
            "cluster_preview_srcs": sorted(cluster["srcs"])[:3],
            "cluster_preview_dsts": sorted(cluster["dsts"])[:3],
            "review_risk_level": cluster["risk_level"],
            "review_risk_score": cluster["risk_score"],
            "review_risk_reason": cluster["risk_reason"],
        })
        items.append(representative)

    items.sort(
        key=lambda item: (
            -_review_risk_rank(item.get("review_risk_level", "")),
            -float(item.get("review_risk_score", 0.0) or 0.0),
            -int(item.get("cluster_sample_count", 0) or 0),
            str(item.get("cluster_last_ts", "") or ""),
        )
    )

    filtered_items = items if risk_mode == "all" else [item for item in items if item.get("review_risk_level") == "high"]
    visible_items = filtered_items[:limit] if limit > 0 else filtered_items
    hidden_items = [] if risk_mode == "all" else [item for item in items if item.get("review_risk_level") != "high"]

    return {
        "items": visible_items,
        "summary": {
            "risk": risk_mode,
            "totalSamples": len(candidate_samples),
            "totalClusters": len(items),
            "matchingClusters": len(filtered_items),
            "visibleClusters": len(visible_items),
            "hiddenClusters": len(hidden_items),
            "hiddenSamples": sum(int(item.get("cluster_sample_count", 0) or 0) for item in hidden_items),
        },
    }


def filter_online_samples(status: str, limit: int) -> list[dict]:
    status = (status or 'pending').lower()
    if status not in {'pending', 'candidate', 'ready', 'trained'}:
        status = 'pending'
    samples = []
    event_map = _get_cached_event_map()
    trainable_ids = set()
    if status == 'ready':
        trainable_ids = {sample.event_id for sample in _safe_list_distinct_trainable_samples()}
    for sample in _get_cached_online_samples():
        if status == 'pending' and sample.label_status != 'pending':
            continue
        if status == 'candidate' and sample.label_status != 'candidate':
            continue
        if status == 'ready' and sample.event_id not in trainable_ids:
            continue
        if status == 'trained' and not sample.trained:
            continue
        samples.append(sample)
    if limit > 0:
        samples = samples[-limit:]
    samples.reverse()
    return [serialize_online_sample(sample, event_payload=event_map.get(sample.event_id)) for sample in samples]


def build_model_overview() -> dict:
    current_attack = describe_file(CURRENT_ATTACK_MODEL_PATH)
    current_malware = describe_file(CURRENT_MALWARE_MODEL_PATH)
    shadow_attack = describe_file(ATTACK_ONLINE_MODEL_PATH)
    shadow_malware = describe_file(MALWARE_ONLINE_MODEL_PATH)
    learning = summarize_online_learning()

    current_ready = current_attack["exists"] and current_malware["exists"]
    shadow_ready = shadow_attack["exists"] and shadow_malware["exists"]
    live_source = str(learning.get("liveDecisionSource", "production") or "production")

    current = {
        "name": "Current Production Model",
        "engine": "XGBoost",
        "mode": "production",
        "status": "Ready" if current_ready else "Missing",
        "participatesInBlock": live_source == "production",
        "eventScoring": "Live alert and block decisions",
        "note": "This is the active production model pair used by nidps_monitor.py." if live_source == "production" else "This production model pair is available, but live decisions are currently using the online shadow scorer.",
        "lastUpdated": latest_timestamp(CURRENT_ATTACK_MODEL_PATH, CURRENT_MALWARE_MODEL_PATH),
        "attackModel": current_attack,
        "malwareModel": current_malware,
    }

    shadow = {
        "name": "Shadow Online Model",
        "engine": "River",
        "mode": "shadow",
        "status": "Ready" if shadow_ready else "Missing bootstrap",
        "participatesInBlock": live_source == "shadow",
        "eventScoring": "Live decision scoring" if live_source == "shadow" else "Per-event shadow scoring (no block)",
        "note": "Live decisions are currently using the online shadow scorer. Switch back to production if the online model behaves poorly." if live_source == "shadow" else "Shadow model scores are recorded for events and online samples, but they do not participate in block decisions. Promote is disabled because the production and online models use different runtimes.",
        "lastUpdated": latest_timestamp(ATTACK_ONLINE_MODEL_PATH, MALWARE_ONLINE_MODEL_PATH),
        "attackModel": shadow_attack,
        "malwareModel": shadow_malware,
        "canPromote": False,
    }

    summary_status = f"Current {current['status']} | Shadow {shadow['status']}"
    return {
        "summaryStatus": summary_status,
        "current": current,
        "shadow": shadow,
        "learning": learning,
    }


@app.route("/api/online-samples")
def get_online_samples():
    status = request.args.get('status', 'pending')
    try:
        limit = int(request.args.get('limit', '10'))
    except Exception:
        limit = 10
    limit = max(limit, 1)
    return jsonify(filter_online_samples(status, limit))


@app.route("/api/online-review-clusters")
def get_online_review_clusters():
    try:
        limit = int(request.args.get('limit', '12'))
    except Exception:
        limit = 12
    limit = max(limit, 1)
    risk = str(request.args.get('risk', 'high') or 'high')
    return jsonify(build_review_clusters(limit=limit, risk=risk))


@app.route("/api/online-label", methods=["POST"])
@require_admin_access
def label_online_sample():
    data = request.get_json(silent=True) or {}
    event_id = str(data.get('event_id', '')).strip()
    raw_event_ids = data.get('event_ids')
    event_ids = []
    if isinstance(raw_event_ids, list):
        event_ids = [str(item).strip() for item in raw_event_ids if str(item).strip()]
    elif event_id:
        event_ids = [event_id]
    source = str(data.get('source', 'dashboard')).strip() or 'dashboard'
    if not event_ids:
        return jsonify({'ok': False, 'error': 'Missing event_id or event_ids'}), 400
    try:
        attack_label = normalize_optional_label(data['attack']) if 'attack' in data else UNSET
        malware_label = normalize_optional_label(data['malware']) if 'malware' in data else UNSET
    except ValueError as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400
    if attack_label is UNSET and malware_label is UNSET:
        return jsonify({'ok': False, 'error': 'Provide at least one label.'}), 400

    updated = ONLINE_STORE.update_labels_batch(event_ids, attack_label, malware_label, source)
    if not updated:
        return jsonify({'ok': False, 'error': 'Event not found.'}), 404
    return jsonify({'ok': True, 'event_id': event_ids[0], 'event_ids': event_ids, 'updated': updated})


@app.route("/api/online-auto-label", methods=["POST"])
@require_admin_access
def run_auto_label():
    data = request.get_json(silent=True) or {}
    try:
        limit = int(data.get('limit', 0) or 0)
    except Exception:
        return jsonify({'ok': False, 'error': 'limit must be an integer'}), 400
    try:
        result = run_auto_label_with_lock(limit=max(limit, 0))
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500
    return jsonify({'ok': True, 'result': result})


@app.route("/api/online-train", methods=["POST"])
@require_admin_access
def train_online_samples():
    data = request.get_json(silent=True) or {}
    try:
        limit = int(data.get('limit', 0) or 0)
    except Exception:
        return jsonify({'ok': False, 'error': 'limit must be an integer'}), 400
    checkpoint = bool(data.get('checkpoint', False))
    try:
        result = run_train_with_lock(limit=max(limit, 0), checkpoint=checkpoint)
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500
    return jsonify({'ok': True, 'result': result})


@app.route("/api/model-overview")
def get_model_overview():
    return jsonify(build_model_overview())


@app.route("/api/admin-bootstrap-token")
def get_admin_bootstrap_token():
    if ADMIN_API_TOKEN:
        return jsonify({
            "ok": False,
            "error": "Bootstrap token is disabled because NIDPS_ADMIN_TOKEN is configured.",
        }), 409
    if not _is_loopback_request():
        return jsonify({
            "ok": False,
            "error": "Bootstrap token is only available from loopback clients.",
        }), 403

    response = jsonify({
        "ok": True,
        "token": LOCAL_BOOTSTRAP_ADMIN_TOKEN,
        "header": ADMIN_TOKEN_HEADER,
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/shadow-auto-train", methods=["POST"])
@require_admin_access
def update_shadow_auto_train():
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", True))
    state = set_auto_train_enabled(enabled)
    return jsonify({"ok": True, "state": state})


@app.route("/api/live-decision-source", methods=["POST"])
@require_admin_access
def update_live_decision_source():
    data = request.get_json(silent=True) or {}
    try:
        state = set_live_decision_source(str(data.get("source", "production") or "production"))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "state": state})


@app.route("/api/shadow-capture", methods=["POST"])
@require_admin_access
def update_shadow_capture():
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", True))
    state = set_shadow_capture_enabled(enabled)
    return jsonify({"ok": True, "state": state})

# ===================== Shadow Rollback =====================
@app.route("/api/shadow-rollback", methods=["POST"])
@require_admin_access
def rollback_shadow():
    data = request.get_json(silent=True) or {}
    requested_dir = str(data.get("checkpointDir", "") or "").strip()
    try:
        state = load_control_state()
        checkpoint_dir = requested_dir or str(state.get("lastCheckpointDir", "") or "").strip()
        if not checkpoint_dir:
            return jsonify({"ok": False, "error": "No checkpoint is available for rollback yet."}), 400
        with ONLINE_LOCK:
            result = restore_shadow_checkpoint(
                checkpoint_dir,
                reason=str(data.get("reason", "") or "manual rollback from dashboard"),
            )
        return jsonify({"ok": True, "rollback": result})
    except FileNotFoundError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/shadow-promote", methods=["POST"])
@require_admin_access
def promote_shadow_placeholder():
    return jsonify({
        "ok": False,
        "error": "Promote is not enabled yet. Current production uses XGBoost joblib models while online learning uses River pickle models, so they cannot be swapped directly.",
    }), 409

# ===================== Live ALerts =====================
@app.route("/api/events")
def get_events():
    events = read_latest_events(100)
    events = [event for event in events if not is_suppressed_decision(event.get("decision"))]
    events = merge_observed_events_for_display(events)
    events.reverse()
    wanted_event_ids = {
        str(event.get("event_id", "")).strip()
        for event in events
        if str(event.get("event_id", "")).strip()
    }
    sample_map = {
        sample.event_id: sample
        for sample in _get_cached_online_samples()
        if sample.event_id in wanted_event_ids
    }
    return jsonify([
        normalize_event_scores_for_display(
            event,
            sample=sample_map.get(str(event.get("event_id", "")).strip()),
        )
        for event in events
    ])
# ===================== ENd=====================

@app.route("/api/stats")
def get_stats():
    overview = build_model_overview()
    _, manual_counts = build_manual_response_cards(limit=10)
    event_summaries = _get_cached_event_summaries()
    live_alerts = int(event_summaries.get("liveAlerts", 0) or 0)
    blocked_ips = int(manual_counts.get("active", 0) or 0)
    honeypot_redirects = int(manual_counts.get("honeypot", 0) or 0)

    return jsonify({
        "liveAlerts": live_alerts,
        "blockedIps": blocked_ips,
        "honeypotRedirects": honeypot_redirects,
        "modelStatus": overview["summaryStatus"],
        "threatOverviewItems": event_summaries.get("threatOverviewItems", []),
        "threatOverviewTotal": int(event_summaries.get("threatOverviewTotal", 0) or 0),
    })


@app.route("/api/router-status")
def get_router_status():
    snapshot = get_cached_router_snapshot()
    return jsonify(snapshot)


@app.route("/api/runtime-metrics")
def get_runtime_metrics():
    return jsonify(build_runtime_metrics_payload())


def build_manual_response_cards(limit: int | None = 10) -> tuple[list[dict], dict]:
    events = read_latest_events(500)

    latest_by_src = {}
    for event in events:
        src = event.get("src")
        if not src:
            continue
        latest_by_src[src] = event

    current_blocked = set(get_current_blocked_ips())
    current_honeypot = set(get_current_honeypot_ips())
    cards = []
    seen = set()

    def build_card(src: str, event: dict | None, forced_status: str | None = None) -> dict:
        event = event or {}
        decision = str(event.get("decision", ""))
        decision_upper = decision.upper()
        rule = str(event.get("rule", "Unknown"))
        timeout = "Unknown"
        status = forced_status or "Ignore"

        if forced_status == "Active" or src in current_blocked:
            status = "Active"
            timeout = "Permanent"
        elif forced_status == "Honeypot" or src in current_honeypot:
            status = "Honeypot"
            timeout = "Manual review"
        elif decision_upper.startswith("NOT_BLOCKED") or "FAILED" in decision_upper:
            status = "Review"
            timeout = "Monitoring"

        return {
            "ip": src,
            "reason": rule.replace("_", " ").title(),
            "timeout": timeout,
            "status": status,
            "ts": _event_ts_value(event),
        }

    for src in current_blocked:
        cards.append(build_card(src, latest_by_src.get(src), forced_status="Active"))
        seen.add(src)

    for src in current_honeypot:
        if src in seen:
            continue
        cards.append(build_card(src, latest_by_src.get(src), forced_status="Honeypot"))
        seen.add(src)

    sorted_events = sorted(latest_by_src.items(), key=lambda item: _event_ts_value(item[1]), reverse=True)
    for src, event in sorted_events:
        if src in seen:
            continue
        card = build_card(src, event)
        if card["status"] not in {"Honeypot"}:
            continue
        cards.append(card)
        seen.add(src)

    active_cards = sorted([c for c in cards if c["status"] == "Active"], key=lambda c: c.get("ts", ""), reverse=True)
    honeypot_cards = sorted([c for c in cards if c["status"] == "Honeypot"], key=lambda c: c.get("ts", ""), reverse=True)
    result = active_cards + honeypot_cards
    counts = {
        "active": len(active_cards),
        "honeypot": len(honeypot_cards),
        "totalOpen": len(result),
    }

    if limit is None:
        items = result
    else:
        items = result[: max(int(limit), 0)]

    sanitized_items = []
    for card in items:
        next_card = dict(card)
        next_card.pop("ts", None)
        sanitized_items.append(next_card)

    return sanitized_items, counts

# ===================== Manual Response =====================
@app.route("/api/manual-response")
def get_manual_response():
    items, counts = build_manual_response_cards(limit=10)
    return jsonify({
        "items": items,
        "counts": counts,
    })
# ===================== ENd =====================

# ===================== TimeLine =====================
@app.route("/api/timeline")
def get_timeline():
    events = read_latest_events(20)
    events = [event for event in events if not is_suppressed_decision(event.get("decision"))]
    events = merge_observed_events_for_display(events)
    events.reverse()

    timeline = []
    for event in events[:6]:
        ts = str(event.get("ts", ""))
        rule = str(event.get("rule", "Unknown")).replace("_", " ").title()
        decision = str(event.get("decision", "")).upper()

        if decision.startswith("BLOCKED"):
            action_text = "blocked"
            state = "blocked"
        elif "HONEYPOT" in decision:
            action_text = "redirected to honeypot"
            state = "honeypot"
        elif decision == "OBSERVED":
            action_text = "alert-only"
            state = "observed"
        else:
            action_text = "flagged for review"
            state = "review"

        timeline.append({
            "time": ts,
            "event": f"{rule} {action_text}",
            "state": state,
        })

    return jsonify(timeline)
# ===================== End =====================

# =====================IP Log=====================
@app.route("/api/logs")
def get_logs():
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify([])

    events = read_all_events()
    filtered = [
        event for event in events
        if str(event.get("src", "")) == ip or str(event.get("dst", "")) == ip
    ]

    filtered = filtered[-50:]
    filtered.reverse()
    return jsonify([normalize_event_scores_for_display(event) for event in filtered])
# ===================== End =====================

# ===================== HoneyPot Log =====================
@app.route("/api/honeypot-logs")
@require_admin_access
def get_honeypot_logs():
    raw_ip = request.args.get("ip", "").strip()
    if not raw_ip:
        return jsonify({"ok": False, "error": "Missing IP"}), 400

    try:
        ip = parse_ip_literal(raw_ip)
        items = read_honeypot_logs(ip)
        return jsonify({"ok": True, "items": items})
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
# ===================== End =====================

# ===================== Unblock =====================
@app.route("/api/unblock", methods=["POST"])
@require_admin_access
def unblock_ip():
    data = request.get_json(silent=True) or {}
    raw_ip = str(data.get("ip", "")).strip()

    if not raw_ip:
        return jsonify({"ok": False, "error": "Missing IP"}), 400

    try:
        ip = parse_ip_literal(raw_ip)
        managed_lists = (BLOCK_LIST, HONEYPOT_BRUTEFORCE_LIST)
        verify_failures = []
        for list_name in managed_lists:
            remove_cmd = f'/ip firewall address-list remove [find list={list_name} and address="{ip}"]'
            router_exec(remove_cmd)

            verify_cmd = f'/ip firewall address-list print count-only where list={list_name} and address="{ip}"'
            out, err = router_exec(verify_cmd)

            still_present = False
            try:
                still_present = int(out.strip() or "0") > 0
            except Exception:
                still_present = False

            if still_present:
                verify_failures.append({
                    "list": list_name,
                    "stdout": out,
                    "stderr": err,
                })

        if verify_failures:
            first_failure = verify_failures[0]
            return jsonify({
                "ok": False,
                "error": f'IP is still present in address-list "{first_failure["list"]}" after unblock attempt.',
                "stdout": first_failure.get("stdout", ""),
                "stderr": first_failure.get("stderr", ""),
            }), 500

        with ROUTER_STATUS_LOCK:
            cached_payload = dict(ROUTER_STATUS_CACHE.get("payload") or {})
            blocked_ips = [
                str(address)
                for address in cached_payload.get("blockedIps", [])
                if str(address) and str(address) != ip
            ]
            honeypot_ips = [
                str(address)
                for address in cached_payload.get("honeypotIps", [])
                if str(address) and str(address) != ip
            ]
            if cached_payload:
                cached_payload["blockedIps"] = blocked_ips
                cached_payload["blockedCount"] = len(blocked_ips)
                cached_payload["honeypotIps"] = honeypot_ips
                cached_payload["honeypotCount"] = len(honeypot_ips)
                ROUTER_STATUS_CACHE["payload"] = cached_payload

        return jsonify({"ok": True, "ip": ip})
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
# ===================== End =====================

if __name__ == "__main__":
    start_shadow_automation_worker()
    start_router_status_worker()
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=DASHBOARD_DEBUG, use_reloader=False)
