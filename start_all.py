from __future__ import annotations

from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser


BASE_DIR = Path(__file__).resolve().parent
PYTHON_EXE = BASE_DIR / "venv" / "Scripts" / "python.exe"
BACKEND_SCRIPT = BASE_DIR / "dashboard_backend.py"
MONITOR_SCRIPT = BASE_DIR / "nidps_monitor.py"
FRONTEND_DIST_DIR = BASE_DIR / "AI_NIDPS_DashBoard" / "dist"

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 5000
FRONTEND_HOST = "127.0.0.1"
FRONTEND_PORT = 4173

BACKEND_URL = f"http://{BACKEND_HOST}:{BACKEND_PORT}/api/stats"
FRONTEND_URL = f"http://{FRONTEND_HOST}:{FRONTEND_PORT}"


def is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def wait_for_url(url: str, timeout_sec: int = 30) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return True
        except Exception:
            time.sleep(1)
    return False


def stop_process(proc: subprocess.Popen | None, name: str) -> None:
    if proc is None or proc.poll() is not None:
        return

    print(f"[launcher] stopping {name} ...", flush=True)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        print(f"[launcher] force killing {name} ...", flush=True)
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def start_process(command: list[str], name: str) -> subprocess.Popen:
    print(f"[launcher] starting {name} ...", flush=True)
    proc = subprocess.Popen(command, cwd=str(BASE_DIR))
    time.sleep(1.5)
    if proc.poll() is not None:
        raise RuntimeError(f"{name} exited early")
    return proc


def main() -> int:
    if not PYTHON_EXE.exists():
        print(f"[launcher] python not found: {PYTHON_EXE}", flush=True)
        return 1
    if not BACKEND_SCRIPT.exists():
        print(f"[launcher] backend script not found: {BACKEND_SCRIPT}", flush=True)
        return 1
    if not MONITOR_SCRIPT.exists():
        print(f"[launcher] monitor script not found: {MONITOR_SCRIPT}", flush=True)
        return 1
    if not FRONTEND_DIST_DIR.exists():
        print(f"[launcher] frontend dist not found: {FRONTEND_DIST_DIR}", flush=True)
        print("[launcher] build the dashboard first with: npm run build", flush=True)
        return 1

    if is_port_open(BACKEND_HOST, BACKEND_PORT):
        print(f"[launcher] backend port already in use: {BACKEND_HOST}:{BACKEND_PORT}", flush=True)
        return 1
    if is_port_open(FRONTEND_HOST, FRONTEND_PORT):
        print(f"[launcher] frontend port already in use: {FRONTEND_HOST}:{FRONTEND_PORT}", flush=True)
        return 1

    backend_proc: subprocess.Popen | None = None
    monitor_proc: subprocess.Popen | None = None
    frontend_proc: subprocess.Popen | None = None

    try:
        browser_frontend_url = f"{FRONTEND_URL}/?v={int(time.time())}"

        backend_proc = start_process(
            [str(PYTHON_EXE), str(BACKEND_SCRIPT)],
            "dashboard backend",
        )
        monitor_proc = start_process(
            [str(PYTHON_EXE), str(MONITOR_SCRIPT)],
            "nidps monitor",
        )
        frontend_proc = start_process(
            [
                str(PYTHON_EXE),
                "-m",
                "http.server",
                str(FRONTEND_PORT),
                "--bind",
                FRONTEND_HOST,
                "--directory",
                str(FRONTEND_DIST_DIR),
            ],
            "dashboard static server",
        )

        print("[launcher] waiting for dashboard backend ...", flush=True)
        backend_ready = wait_for_url(BACKEND_URL, timeout_sec=30)
        print("[launcher] waiting for dashboard page ...", flush=True)
        frontend_ready = wait_for_url(FRONTEND_URL, timeout_sec=30)

        if backend_ready and frontend_ready:
            print(f"[launcher] opening dashboard: {browser_frontend_url}", flush=True)
            webbrowser.open(browser_frontend_url)
        else:
            if not backend_ready:
                print(f"[launcher] backend did not respond in time: {BACKEND_URL}", flush=True)
            if not frontend_ready:
                print(f"[launcher] frontend did not respond in time: {FRONTEND_URL}", flush=True)

        print("[launcher] AI-NIDPS is running. Press Ctrl+C to stop all.", flush=True)

        while True:
            time.sleep(1)
            if backend_proc.poll() is not None:
                print("[launcher] dashboard backend stopped", flush=True)
                break
            if monitor_proc.poll() is not None:
                print("[launcher] nidps monitor stopped", flush=True)
                break
            if frontend_proc.poll() is not None:
                print("[launcher] dashboard static server stopped", flush=True)
                break

    except KeyboardInterrupt:
        print("\n[launcher] shutdown requested", flush=True)
    except Exception as exc:
        print(f"[launcher] {exc}", flush=True)
        return_code = 1
    else:
        return_code = 0
    finally:
        stop_process(frontend_proc, "dashboard static server")
        stop_process(monitor_proc, "nidps monitor")
        stop_process(backend_proc, "dashboard backend")

    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
