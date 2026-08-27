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

from core.audit import AuditEventType, AuditLedger, DEFAULT_AUDIT_LEDGER
from core.guardrails import ALLOWED_TARGETS
from core.policy import DEFAULT_CAPABILITY_POLICY, CapabilityPolicy, TargetPolicy
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

    def __init__(
        self,
        policy: Optional[TargetPolicy] = None,
        vault: Optional[SecretVault] = None,
        capability_policy: Optional[CapabilityPolicy] = None,
        audit_ledger: Optional[AuditLedger] = None,
    ):
        if policy is not None:
            self.policy = policy
        else:
            self.policy = TargetPolicy(allowed_targets=ALLOWED_TARGETS)
        self.vault = vault or DEFAULT_VAULT
        self.capability_policy = capability_policy or DEFAULT_CAPABILITY_POLICY
        self.audit_ledger = audit_ledger or DEFAULT_AUDIT_LEDGER
        self.execution_history: list[ExecutionResult] = []

    def execute(
        self,
        executable: str,
        argv: list[str],
        target: Optional[str] = None,
        timeout: int = 120,
        max_output: int = 4000,
        approved: bool = False,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
    ) -> ExecutionResult:
        """Execute a binary with strict argv array (shell=False) under policy authorization."""
        exec_id = f"exec_{uuid.uuid4().hex[:12]}"
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")

        # 1. Capability Policy Authorization Check
        allowed, reason = self.capability_policy.authorize(executable, has_operator_approval=approved)
        if not allowed:
            return ExecutionResult(
                execution_id=exec_id,
                executable=executable,
                argv=argv,
                stdout="",
                stderr=reason,
                exit_code=126,
                duration_ms=0.0,
                timestamp=ts,
                output=reason,
            )

        # 2. Target Scope Policy Check (if target provided)
        if target:
            if isinstance(target, str):
                resolved_target = self.policy.resolve_destination(target)
            else:
                resolved_target = target
            if not resolved_target.is_authorized:
                blocked_msg = (
                    f"[SCOPE BLOCKED] {resolved_target.rejection_reason or f'Target {target} is out of authorized scope.'} "
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

        # 3. Binary Path Resolution (resolve capability executable if manifested)
        manifest = self.capability_policy.get(executable)
        bin_name = manifest.executable if (manifest and manifest.executable) else executable
        resolved_bin = shutil.which(bin_name)
        if not resolved_bin:
            err_msg = f"[TOOL ERROR] Executable '{bin_name}' not found in PATH."
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

        # Record execution outcome into cryptographic audit ledger
        self.audit_ledger.record_event(
            AuditEventType.PROCESS_END,
            {
                "execution_id": res.execution_id,
                "executable": res.executable,
                "exit_code": res.exit_code,
                "duration_ms": res.duration_ms,
                "target": target,
                "approved": approved,
            },
        )
        self.execution_history.append(res)
        return res


# Global default broker instance
DEFAULT_BROKER = ExecutionBroker()
