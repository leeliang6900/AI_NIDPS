import os
import socket
import struct
import time
import threading
from typing import Dict, List, Tuple, Any, Optional

from router_ssh import build_router_ssh_client

UDP_PORT = 2055

ROUTER_IP = os.getenv("NIDPS_ROUTER_IP", "192.168.88.1")
ROUTER_USER = os.getenv("NIDPS_ROUTER_USER", "")
ROUTER_PASS = os.getenv("NIDPS_ROUTER_PASS", "")

if not ROUTER_USER or not ROUTER_PASS:
    raise RuntimeError(
        "Missing router credentials. Please set NIDPS_ROUTER_IP, NIDPS_ROUTER_USER, and NIDPS_ROUTER_PASS environment variables."
    )

ARP_REFRESH_SEC = 10

SHOW_STARTUP_LOG = True
PRINT_LIMIT_PER_SEC = 60


def _parse_mikrotik_arp_terse(text: str) -> Dict[str, str]:
    ip_mac: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "address=" not in line or "mac-address=" not in line:
            continue

        addr = None
        mac = None
        for token in line.split():
            if token.startswith("address="):
                addr = token.split("=", 1)[1]
            elif token.startswith("mac-address="):
                mac = token.split("=", 1)[1]

        if addr and mac and mac != "00:00:00:00:00:00":
            ip_mac[addr] = mac.upper()
    return ip_mac


def fetch_arp_table_paramiko(host: str, username: str, password: str, timeout: int = 15) -> Dict[str, str]:
    cmd = "/ip arp print without-paging terse\n"
    client = build_router_ssh_client()
    try:
        client.connect(
            hostname=host,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, _ = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="ignore")
        return _parse_mikrotik_arp_terse(out)
    finally:
        try:
            client.close()
        except Exception:
            pass


def fetch_arp_table(host: str, username: str, password: str) -> Dict[str, str]:
    try:
        return fetch_arp_table_paramiko(host, username, password)
    except Exception as exc:
        raise RuntimeError(f"paramiko ARP fetch failed: {exc}") from exc


class ArpResolver:
    def __init__(self, host: str, username: str, password: str, refresh_sec: int = 10):
        self.host = host
        self.username = username
        self.password = password
        self.refresh_sec = refresh_sec

        self._lock = threading.Lock()
        self._map: Dict[str, str] = {}
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop = True
        self._thread.join(timeout=1)

    def _loop(self) -> None:
        while not self._stop:
            try:
                new_map = fetch_arp_table(self.host, self.username, self.password)
                with self._lock:
                    self._map = new_map
            except Exception:
                pass
            time.sleep(self.refresh_sec)

    def mac_of(self, ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        with self._lock:
            return self._map.get(ip)


templates: Dict[int, List[Tuple[int, int]]] = {}


def parse_v9_header(data: bytes) -> Tuple[int, bytes]:
    if len(data) < 20:
        raise ValueError("packet too short")
    version, _count, _sys_uptime, _unix_secs, _seq, _src_id = struct.unpack("!HHLLLL", data[:20])
    return version, data[20:]


def parse_template_flowset(body: bytes) -> None:
    offset = 0
    while offset + 4 <= len(body):
        template_id, field_count = struct.unpack("!HH", body[offset:offset + 4])
        offset += 4

        fields: List[Tuple[int, int]] = []
        for _ in range(field_count):
            if offset + 4 > len(body):
                break
            field_type, field_len = struct.unpack("!HH", body[offset:offset + 4])
            offset += 4
            fields.append((field_type, field_len))

        if fields:
            templates[template_id] = fields


def parse_data_flowset(flowset_id: int, body: bytes) -> List[Dict[str, Any]]:
    if flowset_id not in templates:
        return []

    fields = templates[flowset_id]
    record_len = sum(fl for _, fl in fields)
    if record_len <= 0:
        return []

    records: List[Dict[str, Any]] = []
    offset = 0

    while offset + record_len <= len(body):
        rec: Dict[str, Any] = {}
        pos = offset

        for field_type, field_len in fields:
            raw = body[pos:pos + field_len]
            pos += field_len

            if field_type == 8 and field_len == 4:
                rec["src_ip"] = socket.inet_ntoa(raw)
            elif field_type == 12 and field_len == 4:
                rec["dst_ip"] = socket.inet_ntoa(raw)
            elif field_type == 7:
                rec["src_port"] = int.from_bytes(raw, "big")
            elif field_type == 11:
                rec["dst_port"] = int.from_bytes(raw, "big")
            elif field_type == 4:
                rec["proto"] = int.from_bytes(raw, "big")
            elif field_type == 2:
                rec["packets"] = int.from_bytes(raw, "big")
            elif field_type == 1:
                rec["bytes"] = int.from_bytes(raw, "big")

        rec.setdefault("src_ip", None)
        rec.setdefault("dst_ip", None)
        rec.setdefault("src_port", None)
        rec.setdefault("dst_port", None)
        rec.setdefault("proto", None)
        rec.setdefault("packets", 0)
        rec.setdefault("bytes", 0)

        records.append(rec)
        offset += record_len

    return records


def parse_netflow_v9_packet(data: bytes) -> List[Dict[str, Any]]:
    version, payload = parse_v9_header(data)
    if version != 9:
        return []

    offset = 0
    out: List[Dict[str, Any]] = []

    while offset + 4 <= len(payload):
        flowset_id, length = struct.unpack("!HH", payload[offset:offset + 4])
        if length < 4 or offset + length > len(payload):
            break

        body = payload[offset + 4: offset + length]

        if flowset_id == 0:
            parse_template_flowset(body)
        elif flowset_id > 255:
            out.extend(parse_data_flowset(flowset_id, body))

        offset += length

    return out


def main():
    arp = ArpResolver(ROUTER_IP, ROUTER_USER, ROUTER_PASS, refresh_sec=ARP_REFRESH_SEC)
    arp.start()

    if SHOW_STARTUP_LOG:
        print(f"[+] NetFlow v9 receiver started (UDP {UDP_PORT})")
        print(f"[+] Router={ROUTER_IP} | ARP refresh={ARP_REFRESH_SEC}s | print_limit={PRINT_LIMIT_PER_SEC}/s")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", UDP_PORT))

    last = time.time()
    printed = 0

    try:
        while True:
            data, _addr = sock.recvfrom(8192)
            records = parse_netflow_v9_packet(data)

            for r in records:
                r["src_mac"] = arp.mac_of(r.get("src_ip"))
                r["dst_mac"] = arp.mac_of(r.get("dst_ip"))

                now = time.time()
                if now - last >= 1.0:
                    last = now
                    printed = 0

                if printed < PRINT_LIMIT_PER_SEC:
                    print(r)
                    printed += 1

    except KeyboardInterrupt:
        if SHOW_STARTUP_LOG:
            print("\n[+] NetFlow receiver stopped by user (Ctrl+C)")
    finally:
        arp.stop()


if __name__ == "__main__":
    main()
