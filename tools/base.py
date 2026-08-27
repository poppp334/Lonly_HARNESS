#!/usr/bin/env python3
"""tools/base.py — Core subprocess execution wrapper and output truncation for LONLY tools.

Safe, controllable command runner with configurable timeout and output limits.
Stdlib only.
"""

from __future__ import annotations

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
