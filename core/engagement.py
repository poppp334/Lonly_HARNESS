#!/usr/bin/env python3
"""core/engagement.py — First-Class Engagement & Multi-Entity Model for LONLY v2.

Enforces:
- Formal hierarchy: Organization -> User -> Engagement -> Scope -> Run -> Task -> Execution -> Finding.
- Multi-run lifecycle management and persistent engagement metadata.
- Structured authorization and approval tracking across operators.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    LEAD_PENTESTER = "LEAD_PENTESTER"
    OPERATOR = "OPERATOR"
    AUDITOR = "AUDITOR"


class EngagementStatus(str, Enum):
    PLANNING = "PLANNING"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"


@dataclass
class Organization:
    """Organization / client boundary."""
    org_id: str
    name: str
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))


@dataclass
class OperatorUser:
    """Operator identity and authorization role."""
    user_id: str
    username: str
    role: UserRole | str = UserRole.OPERATOR


@dataclass
class Engagement:
    """First-class engagement boundary."""
    engagement_id: str
    org_id: str
    title: str
    scope_targets: list[str] = field(default_factory=list)
    status: EngagementStatus | str = EngagementStatus.PLANNING
    lead_operator_id: str = "operator_1"
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))


@dataclass
class RunRecord:
    """Single execution run within an engagement."""
    run_id: str
    engagement_id: str
    status: str = "RUNNING"
    start_time: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    end_time: Optional[str] = None


@dataclass
class TaskRecord:
    """Specific task execution within a run."""
    task_id: str
    run_id: str
    phase: str
    target: str
    status: str = "PENDING"
    risk_score: int = 0


@dataclass
class ApprovalRecord:
    """Explicit human-in-the-loop operator approval grant."""
    approval_id: str
    engagement_id: str
    capability_id: str
    operator_id: str
    granted: bool
    justification: str = ""
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))


class EngagementManager:
    """Central engagement registry and multi-run coordinator."""

    def __init__(self):
        self.organizations: dict[str, Organization] = {}
        self.users: dict[str, OperatorUser] = {}
        self.engagements: dict[str, Engagement] = {}
        self.runs: dict[str, RunRecord] = {}
        self.tasks: dict[str, TaskRecord] = {}
        self.approvals: dict[str, ApprovalRecord] = {}

    def create_organization(self, name: str) -> Organization:
        org_id = f"org_{uuid.uuid4().hex[:8]}"
        org = Organization(org_id=org_id, name=name)
        self.organizations[org_id] = org
        return org

    def create_user(self, username: str, role: UserRole | str = UserRole.OPERATOR) -> OperatorUser:
        user_id = f"usr_{uuid.uuid4().hex[:8]}"
        user = OperatorUser(user_id=user_id, username=username, role=role)
        self.users[user_id] = user
        return user

    def create_engagement(
        self,
        org_id: str,
        title: str,
        scope_targets: list[str],
        lead_operator_id: str = "operator_1",
    ) -> Engagement:
        eng_id = f"ENG-{time.strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"
        eng = Engagement(
            engagement_id=eng_id,
            org_id=org_id,
            title=title,
            scope_targets=scope_targets,
            status=EngagementStatus.ACTIVE,
            lead_operator_id=lead_operator_id,
        )
        self.engagements[eng_id] = eng
        return eng

    def start_run(self, engagement_id: str) -> RunRecord:
        run_id = f"run_{uuid.uuid4().hex[:8]}"
        run = RunRecord(run_id=run_id, engagement_id=engagement_id, status="ACTIVE")
        self.runs[run_id] = run
        return run

    def create_task(self, run_id: str, phase: str, target: str) -> TaskRecord:
        task_id = f"task_{uuid.uuid4().hex[:8]}"
        task = TaskRecord(task_id=task_id, run_id=run_id, phase=phase, target=target, status="ACTIVE")
        self.tasks[task_id] = task
        return task

    def record_approval(
        self,
        engagement_id: str,
        capability_id: str,
        operator_id: str,
        granted: bool,
        justification: str = "",
    ) -> ApprovalRecord:
        appr_id = f"appr_{uuid.uuid4().hex[:8]}"
        appr = ApprovalRecord(
            approval_id=appr_id,
            engagement_id=engagement_id,
            capability_id=capability_id,
            operator_id=operator_id,
            granted=granted,
            justification=justification,
        )
        self.approvals[appr_id] = appr
        return appr

    def get_engagement_summary(self, engagement_id: str) -> dict:
        if engagement_id not in self.engagements:
            return {}
        eng = self.engagements[engagement_id]
        runs = [r for r in self.runs.values() if r.engagement_id == engagement_id]
        approvals = [a for a in self.approvals.values() if a.engagement_id == engagement_id]
        return {
            "engagement": asdict(eng),
            "total_runs": len(runs),
            "total_approvals": len(approvals),
            "approved_count": sum(1 for a in approvals if a.granted),
        }
