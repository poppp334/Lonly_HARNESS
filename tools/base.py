#!/usr/bin/env python3
"""tools/base.py — Core subprocess execution wrapper and output truncation for LONLY tools.

Safe, controllable command runner with configurable timeout and output limits.
Stdlib only.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from typing import Optional

from core.broker import DEFAULT_BROKER, ExecutionBroker, ExecutionResult

# Patterns that unambiguously indicate a tool call failed.
TOOL_FAILURE_PATTERNS = [
    "[ERROR]",
    "[TIMEOUT]",
    "[TOOL ERROR]",
    "[SCOPE BLOCKED]",
    "not found",
    "command not found",
    "No such file or directory",
    "Permission denied",
]


def clean_target(target: str) -> str:
    """Sanitize target host/IP string by stripping protocols and path segments."""
    if not target:
        return ""
    t = target.strip()
    # Strip protocol prefix e.g. http://, https://, smb://
    t = re.sub(r"^[a-zA-Z0-9+.-]+://", "", t)
    # Strip Windows share prefix \\
    t = t.lstrip("\\/")
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
    broker: Optional[ExecutionBroker] = None,
) -> str:
    """Execute a tool via structured argv vector without shell (shell=False).

    Delegates to pentest_agent.run_cmd/run_argv if monkeypatched by test harnesses.
    """
    pa = sys.modules.get("pentest_agent")
    if pa is not None and hasattr(pa, "run_cmd"):
        pa_fn = getattr(pa, "run_cmd")
        if callable(pa_fn) and pa_fn is not run_cmd:
            # If monkeypatched with single string signature
            cmd_str = f"{executable} {' '.join(str(a) for a in argv)}"
            return pa_fn(cmd_str, timeout=timeout, max_output=max_output)

    b = broker or DEFAULT_BROKER
    res = b.execute(
        executable=executable,
        argv=argv,
        target=target,
        timeout=timeout,
        max_output=max_output,
    )
    return res.output


def run_cmd(cmd: str, timeout: int = 120, max_output: int = 4000) -> str:
    """Tokenize command string safely with shlex and execute via ExecutionBroker (shell=False)."""
    pa = sys.modules.get("pentest_agent")
    if pa is not None and hasattr(pa, "run_cmd"):
        pa_fn = getattr(pa, "run_cmd")
        if callable(pa_fn) and pa_fn is not run_cmd:
            return pa_fn(cmd, timeout=timeout, max_output=max_output)

    parts = shlex.split(cmd)
    if not parts:
        return "[ERROR] Empty command"
    executable = parts[0]
    argv = parts[1:]
    return run_argv(executable, argv, timeout=timeout, max_output=max_output)


# Backward compatibility alias
_exec_cmd = run_cmd
