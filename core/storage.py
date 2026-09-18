#!/usr/bin/env python3
"""core/storage.py — crash-safe persistence primitives.

Single place for atomic writes, cross-process locked appends, and tolerant
JSONL reads. Stdlib only (fcntl/flock is POSIX; callers degrade to unlocked
appends when locking is unavailable).
"""
from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from typing import Any, Iterator

try:  # POSIX locking; Windows would need msvcrt — not a target platform
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


def ensure_dir(path: str, mode: int = 0o700) -> str:
    """Create a directory (and parents) with restrictive permissions."""
    if not os.path.isdir(path):
        os.makedirs(path, mode=mode, exist_ok=True)
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    return path


def atomic_write_text(path: str, text: str) -> None:
    """Write text via temp file + fsync + os.replace (readers never see partial data)."""
    directory = os.path.dirname(os.path.abspath(path))
    ensure_dir(directory)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_write_json(path: str, data: Any) -> None:
    """Serialize `data` to JSON and write it atomically."""
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2))


@contextmanager
def file_lock(path: str) -> Iterator[None]:
    """Exclusive cross-process lock scoped to `path` (uses a sidecar .lock file)."""
    if fcntl is None:
        yield
        return
    lock_path = f"{path}.lock"
    ensure_dir(os.path.dirname(os.path.abspath(lock_path)))
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _append_line(path: str, line: str, fsync: bool) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
        if fsync:
            os.fsync(fh.fileno())


def append_jsonl(path: str, record: dict, *, fsync: bool = True, lock: bool = True) -> None:
    """Append one JSON record as a line, optionally under an exclusive lock."""
    line = json.dumps(record, ensure_ascii=False) + "\n"
    ensure_dir(os.path.dirname(os.path.abspath(path)))
    if lock:
        with file_lock(path):
            _append_line(path, line, fsync)
    else:
        _append_line(path, line, fsync)


def read_jsonl(path: str, *, tolerate_corrupt: bool = True) -> list[dict]:
    """Read a JSONL file, skipping malformed lines unless strict mode is requested."""
    if not os.path.exists(path):
        return []
    records: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                if not tolerate_corrupt:
                    raise
    return records
