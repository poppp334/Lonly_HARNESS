#!/usr/bin/env python3
"""core/session_context.py — per-engagement state container.

Replaces the agent's module-level mutable globals so concurrent sessions (or
embedded runs) cannot share chat history, scope, risk budget, findings,
evidence, duplicate-call state, or tool routing.

Each context owns:
  * a scope list and a matching ExecutionBroker (per-session target policy),
  * a ToolCallExecutor bound to that broker and the context's evidence graph,
  * chat history, carryover/in-task risk events, task number, seen calls,
  * FindingsLog, TaskTree, and EvidenceGraph instances.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.broker import ExecutionBroker
from core.evidence import EvidenceGraph
from core.policy import CapabilityPolicy, TargetPolicy
from core.ports import ScopePort, ToolInvokerPort
from core.session import SessionState
from core.state import FindingsLog, TaskTree
from core.tool_dispatch import ToolCallExecutor


class ContextScopePort(ScopePort):
    """ScopePort backed by one session context's allowlist."""

    def __init__(self, context: "SessionContext"):
        self._context = context

    @property
    def allowed_targets(self) -> list[str]:
        return self._context.scope

    def is_in_scope(self, target: str) -> bool:
        return TargetPolicy(allowed_targets=self._context.scope).is_in_scope(target)


@dataclass
class SessionContext:
    """All mutable per-engagement state, isolated from other contexts."""

    session: SessionState
    invoker: ToolInvokerPort
    scope: list[str] = field(default_factory=list)
    chat_history: list = field(default_factory=list)
    carryover_event_log: list[dict] = field(default_factory=list)
    in_task_risk_events: list[dict] = field(default_factory=list)
    task_number: int = 1
    seen_calls: set = field(default_factory=set)
    findings_log: FindingsLog = field(default_factory=FindingsLog)
    task_tree: TaskTree = field(default_factory=TaskTree)
    evidence_graph: EvidenceGraph = field(default_factory=EvidenceGraph)
    broker: Optional[ExecutionBroker] = None
    tool_executor: Optional[ToolCallExecutor] = None

    def __post_init__(self) -> None:
        self.rebuild_executor()

    def rebuild_executor(self) -> None:
        """(Re)build the per-context broker and tool executor."""
        self.broker = ExecutionBroker(
            policy=TargetPolicy(allowed_targets=self.scope),
            capability_policy=CapabilityPolicy(),
        )
        self.tool_executor = ToolCallExecutor(
            invoker=self.invoker,
            evidence_sink=self.evidence_graph,
            broker=self.broker,
        )

    @property
    def scope_port(self) -> ScopePort:
        return ContextScopePort(self)

    def flush(self) -> None:
        """Persist findings and evidence snapshots to disk."""
        if self.evidence_graph and hasattr(self.evidence_graph, "save"):
            try:
                self.evidence_graph.save()
            except Exception:
                pass

