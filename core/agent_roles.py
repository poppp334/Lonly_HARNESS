#!/usr/bin/env python3
"""core/agent_roles.py — Formal Model Boundary & Role Separation for LONLY v2.

Enforces:
- Strict decoupling: Planner (Strategy) -> Specialist (Hypothesis) -> Deterministic Policy (Authorization) -> Verifier (Evidence Proof).
- No LLM component owns authorization or raw execution capabilities.
- Formal interfaces for model inputs and structured outputs.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional
from core.evidence import ClaimType, ClaimVerifier, EvidenceGraph, TypedClaim
from core.policy import TargetPolicy


@dataclass
class ProposedActionPlan:
    """Structured plan output from Planner model."""
    phase: str
    recommended_capability: str
    target: str
    rationale: str
    parameters: dict = field(default_factory=dict)


@dataclass
class SpecialistHypothesis:
    """Hypothesis proposed by Specialist model (e.g. privesc, auth bypass)."""
    specialist_domain: str  # "privesc", "web", "ad"
    hypothesis: str
    proposed_capability: str
    target: str
    payload_parameters: dict = field(default_factory=dict)


@dataclass
class ModelVerificationVerdict:
    """Cryptographic claim validation verdict from Verifier."""
    claim: TypedClaim
    is_valid: bool
    proof_hashes: list[str] = field(default_factory=list)
    rejection_reason: str = ""


class PlannerRole:
    """Planner determines 'What should we investigate next?' without execution authority."""

    @classmethod
    def create_proposal(
        cls,
        phase: str,
        target: str,
        recommended_capability: str,
        rationale: str,
        parameters: Optional[dict] = None,
    ) -> ProposedActionPlan:
        return ProposedActionPlan(
            phase=phase,
            recommended_capability=recommended_capability,
            target=target,
            rationale=rationale,
            parameters=parameters or {},
        )


class SpecialistRole:
    """Specialist determines 'What hypothesis should we test?'."""

    @classmethod
    def create_hypothesis(
        cls,
        domain: str,
        hypothesis: str,
        proposed_capability: str,
        target: str,
        parameters: Optional[dict] = None,
    ) -> SpecialistHypothesis:
        return SpecialistHypothesis(
            specialist_domain=domain,
            hypothesis=hypothesis,
            proposed_capability=proposed_capability,
            target=target,
            payload_parameters=parameters or {},
        )


class VerifierRole:
    """Verifier determines 'Is the claim actually supported by evidence?'."""

    def __init__(self, evidence_graph: EvidenceGraph):
        self.evidence_graph = evidence_graph
        self.claim_verifier = ClaimVerifier(evidence_graph)

    def verify_security_claim(self, claim: TypedClaim) -> ModelVerificationVerdict:
        is_ok = self.claim_verifier.verify_claim(claim)
        return ModelVerificationVerdict(
            claim=claim,
            is_valid=is_ok,
            proof_hashes=list(claim.evidence_hashes),
            rejection_reason=claim.rejection_reason,
        )
