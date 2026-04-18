from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import time
import uuid

if os.name == "nt":
    import msvcrt
else:
    import fcntl


@contextmanager
def exclusive_lock(lock_path: Path | str):
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)

    with lock_path.open("r+b") as lock_fh:
        if lock_path.stat().st_size == 0:
            lock_fh.seek(0)
            lock_fh.write(b"0")
            lock_fh.flush()
        lock_fh.seek(0)
        if os.name == "nt":
            msvcrt.locking(lock_fh.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            lock_fh.seek(0)
            if os.name == "nt":
                msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def atomic_write_bytes(path: Path | str, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(f"{path.suffix}.{uuid.uuid4().hex}.tmp")
    with tmp_path.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, path)


def atomic_write_text(path: Path | str, text: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(Path(path), text.encode(encoding))


def write_text_in_place(path: Path | str, text: str, encoding: str = "utf-8") -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding=encoding) as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())


def resilient_write_text(
    path: Path | str,
    text: str,
    encoding: str = "utf-8",
    replace_retries: int = 5,
    retry_delay_sec: float = 0.05,
) -> None:
    last_error: Exception | None = None
    for _ in range(max(int(replace_retries or 1), 1)):
        try:
            atomic_write_text(path, text, encoding=encoding)
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(max(float(retry_delay_sec or 0.0), 0.0))

    try:
        write_text_in_place(path, text, encoding=encoding)
        return
    except PermissionError as exc:
        last_error = exc

    if last_error is not None:
        raise last_error
