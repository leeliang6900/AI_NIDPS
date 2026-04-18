import os
from pathlib import Path

import paramiko


BASE_DIR = Path(__file__).resolve().parent
SECURITY_DIR = BASE_DIR / "security"
DEFAULT_KNOWN_HOSTS_FILE = "mikrotik_known_hosts"


def resolve_router_known_hosts() -> Path:
    override = os.getenv("NIDPS_SSH_KNOWN_HOSTS", "").strip()
    if override:
        return Path(override).expanduser()
    return SECURITY_DIR / DEFAULT_KNOWN_HOSTS_FILE


def build_router_ssh_client() -> paramiko.SSHClient:
    known_hosts = resolve_router_known_hosts()
    if not known_hosts.exists():
        raise RuntimeError(
            f"Missing Router SSH host key file: {known_hosts}. "
            "Set NIDPS_SSH_KNOWN_HOSTS or place mikrotik_known_hosts in the project security directory."
        )

    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
    except Exception:
        pass
    client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    return client
