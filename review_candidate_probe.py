from __future__ import annotations

import argparse
import os
import random
import socket
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a small amount of suspicious traffic to test Review Candidates. "
            "Default settings are tuned to stay below the known C2_BACKDOOR threshold."
        )
    )
    parser.add_argument("--target", required=True, help="Target IP address to contact.")
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="Destination port. 4444/9001/1337 are good choices for review testing.",
    )
    parser.add_argument(
        "--proto",
        choices=["udp", "tcp"],
        default="udp",
        help="Transport protocol to use.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=8,
        help="How many short connections/messages to send. Keep this below 12 for port 4444.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="Delay between sends in seconds.",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=24,
        help="Payload size in bytes for each send.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.4,
        help="Socket timeout in seconds.",
    )
    return parser.parse_args()


def random_payload(size: int) -> bytes:
    size = max(1, int(size))
    return os.urandom(size)


def send_udp(target: str, port: int, payload: bytes, timeout: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (target, port))
    finally:
        sock.close()


def send_tcp(target: str, port: int, payload: bytes, timeout: float) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect_ex((target, port))
        try:
            sock.sendall(payload)
        except OSError:
            pass
    finally:
        sock.close()


def main() -> None:
    args = parse_args()
    send = send_udp if args.proto == "udp" else send_tcp

    print(
        f"Sending {args.count} small {args.proto.upper()} probes to "
        f"{args.target}:{args.port} with {args.payload_size}B payloads..."
    )
    print("Tip: wait for one 30s window, then check Review Candidates in the dashboard.")

    for i in range(args.count):
        payload = random_payload(args.payload_size)
        send(args.target, args.port, payload, args.timeout)
        print(f"[{i + 1}/{args.count}] sent")
        time.sleep(max(0.0, args.delay + random.uniform(0.0, 0.06)))

    print("Done.")
    print("If this became a known alert instead of a review sample, reduce --count or change --port.")


if __name__ == "__main__":
    main()
