import ipaddress
import os
import threading
import time
from typing import Dict, Optional, Tuple

from router_ssh import build_router_ssh_client


DEFAULT_ROUTER_IP = "192.168.88.1"


def _resolve_router_auth(host: Optional[str], username: Optional[str], password: Optional[str]) -> Tuple[str, str, str]:
    host = host or os.getenv("NIDPS_ROUTER_IP", DEFAULT_ROUTER_IP)
    username = username or os.getenv("NIDPS_ROUTER_USER", "")
    password = password or os.getenv("NIDPS_ROUTER_PASS", "")
    if not username or not password:
        raise RuntimeError(
            "Missing router credentials. Please set NIDPS_ROUTER_USER and NIDPS_ROUTER_PASS environment variables."
        )
    return host, username, password


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


def fetch_arp_table_paramiko(host: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, timeout: int = 15) -> Dict[str, str]:
    host, username, password = _resolve_router_auth(host, username, password)
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
        _, stdout, _ = client.exec_command("/ip arp print without-paging terse\n", timeout=timeout)
        out = stdout.read().decode("utf-8", errors="ignore")
        return _parse_mikrotik_arp_terse(out)
    finally:
        try:
            client.close()
        except Exception:
            pass


def fetch_arp_table(host: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, timeout: int = 15) -> Dict[str, str]:
    try:
        return fetch_arp_table_paramiko(host, username, password, timeout=timeout)
    except Exception as exc:
        raise RuntimeError(f"paramiko ARP fetch failed: {exc}") from exc


def fetch_arp_ip_paramiko(ip: str, host: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, timeout: int = 10) -> Optional[str]:
    host, username, password = _resolve_router_auth(host, username, password)
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
        _, stdout, _ = client.exec_command(f"/ip arp print without-paging terse where address={ip}\n", timeout=timeout)
        out = stdout.read().decode("utf-8", errors="ignore")
        return _parse_mikrotik_arp_terse(out).get(ip)
    finally:
        try:
            client.close()
        except Exception:
            pass


def fetch_dhcp_lease_mac_paramiko(ip: str, host: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, timeout: int = 10) -> Optional[str]:
    host, username, password = _resolve_router_auth(host, username, password)
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
        _, stdout, _ = client.exec_command(
            f"/ip dhcp-server lease print without-paging terse where address={ip}\n",
            timeout=timeout,
        )
        out = stdout.read().decode("utf-8", errors="ignore")
        return _parse_mikrotik_arp_terse(out).get(ip)
    finally:
        try:
            client.close()
        except Exception:
            pass


def warmup_ip_paramiko(ip: str, host: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, timeout: int = 10) -> None:
    host, username, password = _resolve_router_auth(host, username, password)
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
        client.exec_command(f"/ping address={ip} count=1 interval=200ms\n", timeout=timeout)
    finally:
        try:
            client.close()
        except Exception:
            pass


class ArpResolver:
    def __init__(self, host: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, refresh_sec: int = 10, debug: bool = False):
        host, username, password = _resolve_router_auth(host, username, password)
        self.host = host
        self.username = username
        self.password = password
        self.refresh_sec = refresh_sec
        self.debug = debug

        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._map: Dict[str, str] = {}
        self._last_refresh_ts = 0.0
        self._last_lookup_ts: Dict[str, float] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.refresh_now()
            self._stop.wait(self.refresh_sec)

    def _refresh_now_locked(self) -> bool:
        try:
            new_map = fetch_arp_table(self.host, self.username, self.password, timeout=15)
            with self._lock:
                self._map.update(new_map)
            self._last_refresh_ts = time.time()
            if self.debug:
                sample = next(iter(new_map.items()), None)
                print(f"[ARP] entries(new)={len(new_map)} merged_total={len(self._map)} sample={sample}")
            return True
        except Exception as exc:
            if self.debug:
                print(f"[ARP] refresh failed: {exc}")
            return False

    def refresh_now(self) -> bool:
        with self._refresh_lock:
            return self._refresh_now_locked()

    def refresh_if_stale(self, min_interval_sec: float = 3.0) -> bool:
        now = time.time()
        with self._refresh_lock:
            if now - self._last_refresh_ts < min_interval_sec:
                return False
            return self._refresh_now_locked()

    def warmup_ip(self, ip: str, count: int = 1) -> None:
        try:
            warmup_ip_paramiko(ip, self.host, self.username, self.password, timeout=10)
        except Exception as exc:
            if self.debug:
                print(f"[ARP] warmup failed for {ip}: {exc}")

    def mac_of(self, ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        with self._lock:
            return self._map.get(ip)

    def lookup_ip(self, ip: Optional[str], min_interval_sec: float = 3.0) -> Optional[str]:
        if not ip:
            return None
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        if (
            not isinstance(ip_obj, ipaddress.IPv4Address)
            or not ip_obj.is_private
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or ip_obj.is_loopback
            or ip.endswith(".255")
        ):
            return None

        now = time.time()
        with self._refresh_lock:
            last_lookup = self._last_lookup_ts.get(ip, 0.0)
            if now - last_lookup < min_interval_sec:
                return self.mac_of(ip)
            self._last_lookup_ts[ip] = now

        try:
            mac = fetch_arp_ip_paramiko(ip, self.host, self.username, self.password, timeout=10)
            if mac:
                with self._lock:
                    self._map[ip] = mac
                return mac
        except Exception as exc:
            if self.debug:
                print(f"[ARP] direct lookup failed for {ip}: {exc}")

        self.warmup_ip(ip, count=1)
        try:
            mac = fetch_arp_ip_paramiko(ip, self.host, self.username, self.password, timeout=10)
            if mac:
                with self._lock:
                    self._map[ip] = mac
                return mac
        except Exception as exc:
            if self.debug:
                print(f"[ARP] post-warmup lookup failed for {ip}: {exc}")

        try:
            mac = fetch_dhcp_lease_mac_paramiko(ip, self.host, self.username, self.password, timeout=10)
            if mac:
                with self._lock:
                    self._map[ip] = mac
                return mac
        except Exception as exc:
            if self.debug:
                print(f"[ARP] dhcp lease lookup failed for {ip}: {exc}")
        return None
