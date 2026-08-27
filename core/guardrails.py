#!/usr/bin/env python3
"""core/guardrails.py — LONLY safety-policy single source of truth (N1).

Imported by pentest_agent.py (enforcement) and eval/ (verification). Stdlib
only. Every gate the agent enforces is declared here, so the eval harness can
assert the policy contract without importing the whole agent.
"""

from __future__ import annotations

import ipaddress

from core.policy import TargetPolicy

# ---------------------------------------------------------------------------
# Scope control (deny-by-default; PhantomRed consent-first + CSA guidance).
# Entries: exact IP, CIDR, hostname, or domain suffix (".lab").
# Empty list => lab-safe default: loopback only.
# ---------------------------------------------------------------------------
ALLOWED_TARGETS: list[str] = []

TARGET_ARG_KEYS = (
    "target", "targets", "host", "hosts", "ip", "ip_address", "url", "target_url",
    "target_host", "target_ip", "domain", "hostname", "smb_host", "ldap_server", "rhost",
)


def target_in_scope(target: str) -> bool:
    """True if the target string is within ALLOWED_TARGETS using RFC-compliant TargetPolicy."""
    policy = TargetPolicy(allowed_targets=ALLOWED_TARGETS)
    return policy.is_in_scope(target)


def extract_targets_from_args(tool_args: dict) -> list[str]:
    """Best-effort extraction of host targets from tool arguments."""
    found = []
    for key in TARGET_ARG_KEYS:
        if key not in tool_args:
            continue
        val = tool_args[key]
        if isinstance(val, str):
            found.append(val)
        elif isinstance(val, (list, tuple)):
            found.extend(str(v) for v in val)
    return found


# ---------------------------------------------------------------------------
# Tool gating policy (research lesson: every surveyed framework gates arbitrary
# execution strictly; shell_exec was ungated in the original design).
# ---------------------------------------------------------------------------
DANGEROUS_TOOLS = [
    "sqlmap_vulnerability_assessment",
    "nikto_web_scan",
    "enum4linux_smb_audit",
]

CONFIRM_REQUIRED_TOOLS = [
    "crackmapexec",
    "hydra_brute_force",
    "metasploit_auxiliary_scanner",
    "shell_exec",
]

RISK_DESCRIPTIONS = {
    "crackmapexec": "credential spraying / remote command execution",
    "hydra_brute_force": "network service brute-forcing",
    "metasploit_auxiliary_scanner": (
        "runs an arbitrary Metasploit module — verify it's actually an "
        "auxiliary/ scan module, not an exploit"
    ),
    "shell_exec": (
        "arbitrary host shell command execution — verify the command is "
        "scoped, non-destructive, and targets an in-scope host"
    ),
}

# Risk accounting (loop-coupled; kept here so eval can assert the contract)
RISK_POINTS = {
    "confirm_required_tool": 2,
    "dangerous_tool_blocked": 1,
    "regular_tool": 1,
    "fabrication": 3,
    "overclaim": 3,
    "placeholder_answer": 3,
}
RISK_CHECKPOINT_THRESHOLD = 5
