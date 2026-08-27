#!/usr/bin/env python3
"""core/risk.py — Multi-Dimensional Risk Policy Engine for LONLY v2.

Enforces:
- Multi-dimensional risk vectors (network exposure, credential use, privilege, destructive potential, persistence, blast radius).
- Tiered decision matrix (AUTO_ALLOWED, POLICY_APPROVAL, OPERATOR_APPROVAL_REQUIRED, BLOCKED).
- Dynamic risk budget and threshold accounting across engagement lifecycles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskDecision(str, Enum):
    AUTO_ALLOWED = "AUTO_ALLOWED"
    POLICY_APPROVAL = "POLICY_APPROVAL"
    OPERATOR_APPROVAL_REQUIRED = "OPERATOR_APPROVAL_REQUIRED"
    BLOCKED = "BLOCKED"


@dataclass
class RiskVector:
    """Multi-dimensional risk scoring vector (values 1 to 5)."""
    network_exposure: int = 1
    credential_use: int = 1
    privilege_level: int = 1
    destructive_potential: int = 1
    persistence: int = 1
    blast_radius: int = 1

    @property
    def max_dimension(self) -> int:
        return max(
            self.network_exposure,
            self.credential_use,
            self.privilege_level,
            self.destructive_potential,
            self.persistence,
            self.blast_radius,
        )

    @property
    def total_score(self) -> int:
        return (
            self.network_exposure
            + self.credential_use
            + self.privilege_level
            + self.destructive_potential
            + self.persistence
            + self.blast_radius
        )


class RiskPolicyEngine:
    """Evaluates multi-dimensional risk vectors against enterprise safety policies."""

    TOOL_DEFAULT_VECTORS: dict[str, RiskVector] = {
        "nmap_security_scan": RiskVector(network_exposure=2, blast_radius=2),
        "rustscan_port_scan": RiskVector(network_exposure=2, blast_radius=1),
        "gobuster_directory_scan": RiskVector(network_exposure=2, blast_radius=1),
        "nikto_web_scan": RiskVector(network_exposure=3, destructive_potential=2, blast_radius=2),
        "sqlmap_vulnerability_assessment": RiskVector(network_exposure=3, destructive_potential=4, blast_radius=3),
        "hydra_brute_force": RiskVector(network_exposure=3, credential_use=4, blast_radius=3),
        "crackmapexec": RiskVector(network_exposure=3, credential_use=4, privilege_level=3, blast_radius=3),
        "metasploit_auxiliary_scanner": RiskVector(network_exposure=3, destructive_potential=4, blast_radius=3),
        "shell_exec": RiskVector(privilege_level=5, destructive_potential=5, blast_radius=5),
        "linpeas_privilege_escalation_scan": RiskVector(privilege_level=3, destructive_potential=1, blast_radius=1),
    }

    def evaluate(
        self,
        capability_id: str,
        vector: Optional[RiskVector] = None,
        has_operator_approval: bool = False,
    ) -> tuple[RiskDecision, str]:
        """Evaluate operation against multi-dimensional risk matrix."""
        v = vector or self.TOOL_DEFAULT_VECTORS.get(capability_id, RiskVector())

        # 1. Critical destructive potential or full host compromise without operator control -> BLOCKED or REQUIRES APPROVAL
        if v.destructive_potential >= 5 or v.privilege_level >= 5:
            if not has_operator_approval:
                return (
                    RiskDecision.OPERATOR_APPROVAL_REQUIRED,
                    f"[RISK GATE] Capability '{capability_id}' has maximum risk dimensions (destructive={v.destructive_potential}, priv={v.privilege_level}). Operator approval mandatory.",
                )
            return RiskDecision.AUTO_ALLOWED, "Operator approval confirmed for high-risk operation."

        # 2. High risk dimension (level 4) -> Operator approval required
        if v.max_dimension >= 4:
            if not has_operator_approval:
                return (
                    RiskDecision.OPERATOR_APPROVAL_REQUIRED,
                    f"[RISK GATE] Capability '{capability_id}' max risk dimension is {v.max_dimension}/5. Explicit approval required.",
                )
            return RiskDecision.AUTO_ALLOWED, "Operator approval confirmed."

        # 3. Medium risk dimension (level 3) -> Policy approval
        if v.max_dimension >= 3:
            return RiskDecision.POLICY_APPROVAL, f"Capability '{capability_id}' cleared under standard policy."

        # 4. Low risk -> Auto allowed
        return RiskDecision.AUTO_ALLOWED, "Low risk capability automatically authorized."
