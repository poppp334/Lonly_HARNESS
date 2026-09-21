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
import signal
import subprocess
import sys
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from core.audit import AuditEventType, AuditLedger, DEFAULT_AUDIT_LEDGER
from core.guardrails import ALLOWED_TARGETS
from core.policy import DEFAULT_CAPABILITY_POLICY, CapabilityPolicy, TargetPolicy
from core.ratelimit import RateLimiter
from core.sandbox import SandboxManager, profile_for
from core.signals import register_child_pid, unregister_child_pid
from core.vault import DEFAULT_VAULT, SecretVault

SAFE_ENV_ALLOWLIST: frozenset[str] = frozenset({
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "TZ",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "DISPLAY",
    "SHLVL",
})

FORBIDDEN_ENV_KEYS: frozenset[str] = frozenset({
    "LONLY_AUDIT_KEY",
    "LONLY_PRIVESC_PASSWORD",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
})


def sanitize_child_env(
    explicit_env: Optional[dict[str, str]] = None,
    venv_bin: Optional[str] = None,
) -> dict[str, str]:
    """Scrub sensitive environment variables and enforce allowlist for child processes."""
    if explicit_env is not None:
        child_env = dict(explicit_env)
    else:
        child_env = {k: v for k, v in os.environ.items() if k in SAFE_ENV_ALLOWLIST}

    # Ensure forbidden keys or sensitive prefixes are purged unconditionally
    for key in list(child_env.keys()):
        key_upper = key.upper()
        if (
            key in FORBIDDEN_ENV_KEYS
            or key_upper.startswith("LONLY_AUDIT_")
            or key_upper.startswith("LONLY_PRIVESC_")
            or key_upper.startswith("LONLY_VAULT_")
            or "SECRET" in key_upper
            or "PASSWORD" in key_upper
            or "TOKEN" in key_upper
        ):
            del child_env[key]

    # Prepend venv_bin to PATH if given
    if venv_bin:
        current_path = child_env.get("PATH", "")
        path_parts = current_path.split(os.pathsep) if current_path else []
        if venv_bin not in path_parts:
            child_env["PATH"] = f"{venv_bin}{os.pathsep}{current_path}" if current_path else venv_bin

    return child_env


def _managed_run(
    cmd: list[str],
    *,
    shell: bool = False,
    capture_output: bool = True,
    text: bool = True,
    timeout: Optional[float] = None,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    preexec_fn: Optional[Callable] = None,
) -> subprocess.CompletedProcess:
    """Execute process tree with PID tracking, process group termination, and partial output recovery on timeout."""
    stdout_pipe = subprocess.PIPE if capture_output else None
    stderr_pipe = subprocess.PIPE if capture_output else None

    proc = subprocess.Popen(
        cmd,
        shell=shell,
        stdout=stdout_pipe,
        stderr=stderr_pipe,
        text=text,
        cwd=cwd,
        env=env,
        preexec_fn=preexec_fn,
    )
    register_child_pid(proc.pid)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        retcode = proc.poll()
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=retcode if retcode is not None else 0,
            stdout=stdout,
            stderr=stderr,
        )
    except subprocess.TimeoutExpired:
        # B6: Terminate entire process tree (process group kill)
        SandboxManager.terminate_process_tree(proc.pid, sig=signal.SIGTERM)
        time.sleep(0.1)
        if proc.poll() is None:
            SandboxManager.terminate_process_tree(proc.pid, sig=signal.SIGKILL)

        # Salvage partial stdout/stderr produced before timeout
        try:
            partial_stdout, partial_stderr = proc.communicate(timeout=0.5)
        except Exception:
            partial_stdout, partial_stderr = "", ""

        raise subprocess.TimeoutExpired(
            cmd=cmd,
            timeout=timeout if timeout is not None else 0,
            output=partial_stdout,
            stderr=partial_stderr,
        )
    finally:
        unregister_child_pid(proc.pid)


# Wire _managed_run as the broker module's execution runner (preserves patch interface)
subprocess.run = _managed_run


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
        rate_limiter: Optional[RateLimiter] = None,
        rate_limit_enabled: bool = True,
        max_history: Optional[int] = None,
    ):
        if policy is not None:
            self.policy = policy
        else:
            self.policy = TargetPolicy(allowed_targets=ALLOWED_TARGETS)
        self.vault = vault or DEFAULT_VAULT
        self.capability_policy = capability_policy or DEFAULT_CAPABILITY_POLICY
        self.audit_ledger = audit_ledger or DEFAULT_AUDIT_LEDGER
        self.rate_limiter = rate_limiter if rate_limiter is not None else RateLimiter()
        self.rate_limit_enabled = rate_limit_enabled and (
            os.environ.get("LONLY_RATE_LIMIT", "true").lower() in ("1", "true", "yes")
        )
        self.rate_limit_max_wait = float(os.environ.get("LONLY_RATE_LIMIT_MAX_WAIT", "5.0"))
        self.max_history = max_history if max_history is not None else int(
            os.environ.get("LONLY_BROKER_MAX_HISTORY", "1000")
        )
        self.execution_history: deque[ExecutionResult] = deque(maxlen=self.max_history)

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
        capability: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute a binary with strict argv array (shell=False) under policy authorization.

        `capability` pins the authorization identity when the executable name
        differs from the capability id (e.g. `sh` for linpeas, `nxc` for
        crackmapexec, arbitrary binaries for shell_exec).
        """
        exec_id = f"exec_{uuid.uuid4().hex[:12]}"
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        auth_name = capability or executable

        # 1. Capability Policy Authorization Check
        allowed, reason = self.capability_policy.authorize(auth_name, has_operator_approval=approved)
        if not allowed:
            self.audit_ledger.record_event(
                AuditEventType.DECISION,
                {
                    "execution_id": exec_id,
                    "capability": auth_name,
                    "executable": executable,
                    "allowed": False,
                    "reason": reason,
                },
            )
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
                self.audit_ledger.record_event(
                    AuditEventType.DECISION,
                    {
                        "execution_id": exec_id,
                        "capability": executable,
                        "target": target,
                        "allowed": False,
                        "reason": blocked_msg,
                    },
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

        # 3. Rate Limiting Check
        manifest = self.capability_policy.get(auth_name)
        if self.rate_limit_enabled:
            rate = manifest.rate_limit_per_min if manifest else 60
            target_str = target if isinstance(target, str) else (target.canonical_host if target else "")
            acquired = self.rate_limiter.acquire(
                capability=auth_name,
                target=target_str,
                rate_per_min=rate,
                max_wait=self.rate_limit_max_wait,
            )
            if not acquired:
                rate_msg = f"[RATE LIMITED] Capability '{auth_name}' exceeded rate limit of {rate}/min for target '{target_str}'."
                self.audit_ledger.record_event(
                    AuditEventType.DECISION,
                    {
                        "execution_id": exec_id,
                        "capability": auth_name,
                        "executable": executable,
                        "target": target_str,
                        "allowed": False,
                        "reason": rate_msg,
                    },
                )
                return ExecutionResult(
                    execution_id=exec_id,
                    executable=executable,
                    argv=argv,
                    stdout="",
                    stderr=rate_msg,
                    exit_code=126,
                    duration_ms=0.0,
                    timestamp=ts,
                    output=rate_msg,
                )

        # 4. Binary Path Resolution (resolve capability executable if manifested)
        if capability:
            # Explicit capability: execute the requested binary as given.
            bin_name = executable
        else:
            bin_name = manifest.executable if (manifest and manifest.executable) else executable
        venv_bin = os.path.join(sys.prefix, "bin")
        search_path = os.environ.get("PATH", "")
        if venv_bin not in search_path.split(os.pathsep):
            search_path = f"{venv_bin}{os.pathsep}{search_path}"

        resolved_bin = shutil.which(bin_name, path=search_path)
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

        # 3. Sandbox containment profile from the capability manifest
        sandbox_profile = profile_for(manifest.sandbox_profile if manifest else "default")
        preexec_fn = SandboxManager.get_preexec_fn(sandbox_profile)

        # 4. Cryptographic audit: pre-execution provenance
        self.audit_ledger.record_event(
            AuditEventType.BROKER_CALL,
            {
                "execution_id": exec_id,
                "executable": executable,
                "capability": auth_name,
                "argv": [str(a) for a in argv],
                "target": target,
                "approved": approved,
                "sandbox_profile": sandbox_profile.name,
            },
        )
        if approved:
            self.audit_ledger.record_event(
                AuditEventType.APPROVAL,
                {"execution_id": exec_id, "capability": auth_name, "approved": True},
            )
        self.audit_ledger.record_event(
            AuditEventType.PROCESS_START,
            {
                "execution_id": exec_id,
                "executable": executable,
                "resolved_bin": resolved_bin,
                "target": target,
            },
        )

        # Build scrubbed child execution environment with venv bin (A7 isolation)
        run_env = sanitize_child_env(explicit_env=env, venv_bin=venv_bin)

        try:
            # 5. Deterministic execution with shell=False + sandbox containment
            proc = subprocess.run(
                full_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=run_env,
                preexec_fn=preexec_fn,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            combined = stdout + (("\n" + stderr) if stderr else "")
            
            truncated = False
            if len(combined) > max_output:
                combined = combined[:max_output] + "\n... [OUTPUT TRUNCATED]"
                truncated = True

            raw_final = combined.strip()
            if not raw_final:
                if proc.returncode != 0:
                    raw_final = (
                        f"[ERROR] Command exited with code {proc.returncode} "
                        f"and produced no output: {' '.join(full_cmd)}"
                    )
                else:
                    raw_final = "[Command executed successfully with no output]"
            final_output = self.vault.redact(raw_final)
            
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
        except subprocess.TimeoutExpired as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            timeout_msg = f"[TIMEOUT] Command exceeded {timeout}s limit: {' '.join(full_cmd)}"
            salvaged_stdout = exc.output or ""
            if isinstance(salvaged_stdout, bytes):
                salvaged_stdout = salvaged_stdout.decode("utf-8", errors="replace")
            salvaged_stderr = exc.stderr or ""
            if isinstance(salvaged_stderr, bytes):
                salvaged_stderr = salvaged_stderr.decode("utf-8", errors="replace")
            combined_salvaged = (salvaged_stdout + ("\n" + salvaged_stderr if salvaged_stderr else "")).strip()
            final_timeout_output = (
                f"{timeout_msg}\n[PARTIAL OUTPUT SALVAGED]:\n{combined_salvaged}"
                if combined_salvaged
                else timeout_msg
            )
            final_timeout_output = self.vault.redact(final_timeout_output)
            res = ExecutionResult(
                execution_id=exec_id,
                executable=executable,
                argv=argv,
                stdout=salvaged_stdout,
                stderr=salvaged_stderr or timeout_msg,
                exit_code=124,
                duration_ms=round(duration_ms, 2),
                timestamp=ts,
                output=final_timeout_output,
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
                "capability": auth_name,
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
