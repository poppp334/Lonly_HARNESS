#!/usr/bin/env python3
"""tools/base.py — Core subprocess execution wrapper and output truncation for LONLY tools.

Safe, controllable command runner with configurable timeout and output limits.
Stdlib only.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from typing import Callable, Optional

from core.broker import DEFAULT_BROKER, ExecutionBroker
from core.parser import TOOL_FAILURE_PATTERNS
from core.tool_context import current_approval

# Explicit injection seam for tests and embedding hosts. When set, run_argv
# delegates to this executor instead of the broker. This replaces the former
# implicit sys.modules["pentest_agent"] lookup (adapter -> application
# dependency).
_EXECUTOR: Optional[Callable[..., str]] = None


def set_executor(fn: Optional[Callable[..., str]]) -> None:
    """Install a custom executor used instead of the broker (None resets)."""
    global _EXECUTOR
    _EXECUTOR = fn


def reset_executor() -> None:
    """Restore broker-backed execution."""
    global _EXECUTOR
    _EXECUTOR = None


def clean_target(target: str) -> str:
    """Sanitize target host/IP string by stripping protocols and path segments.

    CIDR prefixes are preserved: `10.0.0.0/24` is a network target, while
    `10.0.0.5/admin` is a host with an accidental URL path.
    """
    if not target:
        return ""
    t = target.strip()
    # Strip protocol prefix e.g. http://, https://, smb://
    t = re.sub(r"^[a-zA-Z0-9+.-]+://", "", t)
    # Strip Windows share prefix \\
    t = t.lstrip("\\/")
    if "/" in t:
        head, _, suffix = t.partition("/")
        suffix_clean = suffix.split("?")[0].split("#")[0].strip()
        if head.strip() and suffix_clean.isdigit():
            try:
                ipaddress.ip_network(f"{head.strip()}/{suffix_clean}", strict=False)
                return f"{head.strip().lower()}/{suffix_clean}"
            except ValueError:
                pass
    # Strip URL paths or queries if accidentally passed to host tools
    t = t.split("/")[0].split("?")[0].strip()
    return t


def ensure_url(url: str, default_scheme: str = "http://") -> str:
    """Ensure a URL has a valid http/https scheme."""
    if not url:
        return ""
    u = url.strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        u = default_scheme + u
    return u


def find_wordlist(preferred: str, fallbacks: list[str] | None = None) -> str:
    """Returns the first existing wordlist path, falling back gracefully."""
    candidates = [preferred] + (fallbacks or [])
    for p in candidates:
        if os.path.exists(p) and os.path.isfile(p):
            return p
    return preferred


def run_argv(
    executable: str,
    argv: list[str],
    target: Optional[str] = None,
    timeout: int = 120,
    max_output: int = 4000,
    approved: Optional[bool] = None,
    capability: Optional[str] = None,
    broker: Optional[ExecutionBroker] = None,
) -> str:
    """Execute a tool via structured argv vector without shell (shell=False).

    `approved` defaults to the current tool-call approval context (set by the
    agent's ToolCallExecutor); `capability` pins the authorization identity for
    wrappers whose executable name differs from their capability (shell_exec,
    linpeas, impacket, NetExec).
    """
    resolved_approved = current_approval() if approved is None else bool(approved)
    if _EXECUTOR is not None:
        return _EXECUTOR(
            executable,
            argv,
            target=target,
            timeout=timeout,
            max_output=max_output,
            approved=resolved_approved,
            capability=capability,
            broker=broker,
        )

    b = broker or DEFAULT_BROKER
    res = b.execute(
        executable=executable,
        argv=argv,
        target=target,
        timeout=timeout,
        max_output=max_output,
        approved=resolved_approved,
        capability=capability,
    )
    return res.output


def run_cmd(cmd: str, timeout: int = 120, max_output: int = 4000) -> str:
    """Tokenize command string safely with shlex and execute via ExecutionBroker (shell=False)."""
    parts = shlex.split(cmd)
    if not parts:
        return "[ERROR] Empty command"
    executable = parts[0]
    argv = parts[1:]
    return run_argv(executable, argv, timeout=timeout, max_output=max_output)


# Backward compatibility alias
_exec_cmd = run_cmd
