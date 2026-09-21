#!/usr/bin/env python3
"""core/signals.py — Graceful Signal & Process Termination Handler for LONLY.

Ensures:
- SIGINT / SIGTERM cleanly terminate active child processes (process group kill).
- Active SessionContext and AuditLedger are flushed and closed before exiting.
- Prevents WAL truncation or corrupted session JSONL logs on sudden aborts.
"""

from __future__ import annotations

import os
import signal
import sys
from typing import Callable, List, Set

from core.config import get_logger

logger = get_logger("signals")

_CLEANUP_CALLBACKS: List[Callable[[], None]] = []
_ACTIVE_PIDS: Set[int] = set()
_HANDLERS_INSTALLED = False


def register_cleanup_callback(fn: Callable[[], None]) -> None:
    """Register a zero-arg callback to execute during graceful termination."""
    if fn not in _CLEANUP_CALLBACKS:
        _CLEANUP_CALLBACKS.append(fn)


def unregister_cleanup_callback(fn: Callable[[], None]) -> None:
    """Remove a previously registered cleanup callback."""
    if fn in _CLEANUP_CALLBACKS:
        _CLEANUP_CALLBACKS.remove(fn)


def register_child_pid(pid: int) -> None:
    """Register an active child process PID for tracking."""
    if pid > 0:
        _ACTIVE_PIDS.add(pid)


def unregister_child_pid(pid: int) -> None:
    """Unregister a terminated child process PID."""
    _ACTIVE_PIDS.discard(pid)


def terminate_active_children() -> None:
    """Signal all registered active child processes to terminate."""
    for pid in list(_ACTIVE_PIDS):
        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
    _ACTIVE_PIDS.clear()


def run_cleanups() -> None:
    """Execute all registered cleanup callbacks safely."""
    for fn in list(_CLEANUP_CALLBACKS):
        try:
            fn()
        except Exception as e:
            logger.warning("Error during signal cleanup callback: %s", e)


def handle_shutdown_signal(signum: int, frame) -> None:
    """Signal handler for SIGINT and SIGTERM."""
    sig_name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
    logger.info("Received %s — initiating graceful system shutdown...", sig_name)

    # 1. Terminate running subprocesses
    terminate_active_children()

    # 2. Flush and persist session & audit stores
    run_cleanups()

    # 3. Exit cleanly
    exit_code = 128 + signum
    logger.info("Shutdown complete. Exiting with status %d.", exit_code)
    sys.exit(exit_code)


def install_signal_handlers() -> None:
    """Install SIGINT and SIGTERM handlers if not already configured."""
    global _HANDLERS_INSTALLED
    if not _HANDLERS_INSTALLED:
        try:
            signal.signal(signal.SIGINT, handle_shutdown_signal)
            signal.signal(signal.SIGTERM, handle_shutdown_signal)
            _HANDLERS_INSTALLED = True
            logger.debug("Signal handlers for SIGINT/SIGTERM installed.")
        except (ValueError, AttributeError) as e:
            logger.debug("Signal handlers could not be installed (e.g. non-main thread): %s", e)
