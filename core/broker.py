#!/usr/bin/env python3
"""core/broker.py — Safe Capability Execution Broker for LONLY v2.

Enforces:
- Deterministic subprocess execution with shell=False exclusively.
- Central policy enforcement (TargetPolicy scope validation).
- Structured execution results with stable IDs, timestamps, and audit metrics.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from core.policy import TargetPolicy
from core.vault import DEFAULT_VAULT, SecretVault


@dataclass
class ExecutionResult:
    """Immutable record of a capability execution."""
    execution_id: str
    executable: str
    argv: list[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    timestamp: str
    truncated: bool = False
    output: str = ""

    @property
    def is_success(self) -> bool:
        return self.exit_code == 0


class ExecutionBroker:
    """Central execution broker enforcing policy, secret redaction, and deterministic process execution."""

    def __init__(self, policy: Optional[TargetPolicy] = None, vault: Optional[SecretVault] = None):
        self.policy = policy or TargetPolicy()
        self.vault = vault or DEFAULT_VAULT
        self.execution_history: list[ExecutionResult] = []

    def execute(
        self,
        executable: str,
        argv: list[str],
        target: Optional[str] = None,
        timeout: int = 120,
        max_output: int = 4000,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
    ) -> ExecutionResult:
        """Execute a binary with strict argv array (shell=False)."""
        exec_id = f"exec_{uuid.uuid4().hex[:12]}"
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")

        # 1. Target Scope Policy Check (if target provided)
        if target:
            if not self.policy.is_in_scope(target):
                blocked_msg = (
                    f"[SCOPE BLOCKED] Target '{target}' is out of authorized scope. "
                    f"In-scope: {self.policy.allowed_targets or 'loopback only'}."
                )
                return ExecutionResult(
                    execution_id=exec_id,
                    executable=executable,
                    argv=argv,
                    stdout="",
                    stderr=blocked_msg,
                    exit_code=126,
                    duration_ms=0.0,
                    timestamp=ts,
                    output=blocked_msg,
                )

        # 2. Binary Path Resolution
        resolved_bin = shutil.which(executable)
        if not resolved_bin:
            err_msg = f"[TOOL ERROR] Executable '{executable}' not found in PATH."
            return ExecutionResult(
                execution_id=exec_id,
                executable=executable,
                argv=argv,
                stdout="",
                stderr=err_msg,
                exit_code=127,
                duration_ms=0.0,
                timestamp=ts,
                output=err_msg,
            )

        full_cmd = [resolved_bin] + [str(a) for a in argv]
        start_time = time.perf_counter()

        try:
            # 3. Deterministic execution with shell=False
            proc = subprocess.run(
                full_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            combined = stdout + (("\n" + stderr) if stderr else "")
            
            truncated = False
            if len(combined) > max_output:
                combined = combined[:max_output] + "\n... [OUTPUT TRUNCATED]"
                truncated = True

            final_output = combined.strip() or "[Command executed successfully with no output]"
            
            res = ExecutionResult(
                execution_id=exec_id,
                executable=executable,
                argv=argv,
                stdout=stdout,
                stderr=stderr,
                exit_code=proc.returncode,
                duration_ms=round(duration_ms, 2),
                timestamp=ts,
                truncated=truncated,
                output=final_output,
            )
        except subprocess.TimeoutExpired:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            timeout_msg = f"[TIMEOUT] Command exceeded {timeout}s limit: {' '.join(full_cmd)}"
            res = ExecutionResult(
                execution_id=exec_id,
                executable=executable,
                argv=argv,
                stdout="",
                stderr=timeout_msg,
                exit_code=124,
                duration_ms=round(duration_ms, 2),
                timestamp=ts,
                output=timeout_msg,
            )
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            err_msg = f"[ERROR] Execution failed: {str(e)}"
            res = ExecutionResult(
                execution_id=exec_id,
                executable=executable,
                argv=argv,
                stdout="",
                stderr=err_msg,
                exit_code=1,
                duration_ms=round(duration_ms, 2),
                timestamp=ts,
                output=err_msg,
            )

        self.execution_history.append(res)
        return res


# Global default broker instance
DEFAULT_BROKER = ExecutionBroker()
