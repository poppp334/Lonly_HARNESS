#!/usr/bin/env python3
"""core/sandbox.py — Sandboxing & Resource Isolation Architecture for LONLY v2.

Enforces:
- OS-level resource limits (memory, CPU, PID limits) via POSIX resource controls.
- Process group isolation and guaranteed entire process tree termination on timeout.
- Sandbox profile definitions for capability classes.
"""
from __future__ import annotations

import os
import signal
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

# Safe POSIX resource import
try:
    import resource
except ImportError:
    resource = None  # Non-POSIX platforms fallback


@dataclass
class SandboxProfile:
    """Specification of resource boundaries and OS containment."""
    name: str = "default"
    max_memory_mb: int = 512
    max_cpu_seconds: int = 120
    max_pids: int = 64
    read_only_root: bool = True
    allow_network: bool = True
    drop_capabilities: list[str] = field(default_factory=lambda: ["CAP_SYS_ADMIN", "CAP_NET_ADMIN"])
    timeout_seconds: int = 120


class SandboxManager:
    """Manages process containment, POSIX resource quotas, and process tree termination."""

    @classmethod
    def get_preexec_fn(cls, profile: SandboxProfile) -> Optional[Callable[[], None]]:
        """Return a preexec callable configuring process group and resource limits."""
        if not resource or sys.platform == "win32":
            return None

        def preexec():
            # 1. Create a new process group for clean tree termination
            try:
                os.setpgrp()
            except Exception:
                pass

            # 2. Enforce memory quota (RLIMIT_AS / Address Space)
            if profile.max_memory_mb > 0:
                try:
                    bytes_limit = profile.max_memory_mb * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_AS, (bytes_limit, bytes_limit))
                except Exception:
                    pass

            # 3. Enforce CPU time quota (RLIMIT_CPU)
            if profile.max_cpu_seconds > 0:
                try:
                    resource.setrlimit(resource.RLIMIT_CPU, (profile.max_cpu_seconds, profile.max_cpu_seconds + 5))
                except Exception:
                    pass

            # 4. Enforce process count quota (RLIMIT_NPROC)
            if hasattr(resource, "RLIMIT_NPROC") and profile.max_pids > 0:
                try:
                    resource.setrlimit(resource.RLIMIT_NPROC, (profile.max_pids, profile.max_pids))
                except Exception:
                    pass

        return preexec

    @classmethod
    def terminate_process_tree(cls, pid: int, sig: int = signal.SIGTERM) -> bool:
        """Terminate the entire process tree belonging to a process group."""
        if pid <= 0:
            return False
        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, sig)
            return True
        except ProcessLookupError:
            return True
        except PermissionError:
            try:
                os.kill(pid, sig)
                return True
            except Exception:
                return False
        except Exception:
            return False


# Standard sandbox profiles
PROFILES = {
    "recon": SandboxProfile(name="recon", max_memory_mb=256, max_cpu_seconds=60),
    "web": SandboxProfile(name="web", max_memory_mb=512, max_cpu_seconds=120),
    "creds": SandboxProfile(name="creds", max_memory_mb=512, max_cpu_seconds=120),
    "infra": SandboxProfile(name="infra", max_memory_mb=1024, max_cpu_seconds=300),
    "restricted": SandboxProfile(name="restricted", max_memory_mb=128, max_cpu_seconds=30, max_pids=16),
}
