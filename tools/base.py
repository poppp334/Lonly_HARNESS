#!/usr/bin/env python3
"""tools/base.py — Core subprocess execution wrapper and output truncation for LONLY tools.

Safe, controllable command runner with configurable timeout and output limits.
Stdlib only.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

# Patterns that unambiguously indicate a tool call failed.
TOOL_FAILURE_PATTERNS = [
    "[ERROR]",
    "[TIMEOUT]",
    "[TOOL ERROR]",
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


def _exec_cmd(cmd: str, timeout: int = 120, max_output: int = 4000) -> str:
    """Underlying subprocess execution with length truncation."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        if len(output) > max_output:
            output = output[:max_output] + "\n... [OUTPUT TRUNCATED]"
        return output.strip() or "[Command executed successfully with no output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s limit: {cmd}"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def run_cmd(cmd: str, timeout: int = 120, max_output: int = 4000) -> str:
    """Execute a shell command with timeout and length truncation.

    Delegates to pentest_agent.run_cmd if monkeypatched by test harnesses.
    """
    pa = sys.modules.get("pentest_agent")
    if pa is not None and hasattr(pa, "run_cmd"):
        pa_fn = getattr(pa, "run_cmd")
        if pa_fn is not run_cmd and callable(pa_fn):
            return pa_fn(cmd, timeout=timeout, max_output=max_output)
    return _exec_cmd(cmd, timeout=timeout, max_output=max_output)
