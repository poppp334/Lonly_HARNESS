#!/usr/bin/env python3
"""core/orchestrator.py — DAG Task Graph Orchestrator for LONLY v2.

Enforces:
- Directed Acyclic Graph (DAG) task dependency and branching engine.
- Parallel and conditional multi-protocol workflow execution (Discovery -> Web/SMB/SSH -> Privesc).
- Dynamic task readiness evaluation and state transitions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class DAGTaskNode:
    """Node in the task execution DAG."""
    task_id: str
    title: str
    phase: str
    target: str
    capability_id: str = ""
    status: TaskStatus | str = TaskStatus.PENDING
    dependencies: list[str] = field(default_factory=list)
    result: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class TaskGraphDAG:
    """Directed Acyclic Graph orchestrator for multi-branch pentest engagements."""

    def __init__(self):
        self.nodes: dict[str, DAGTaskNode] = {}

    def add_task(
        self,
        task_id: str,
        title: str,
        phase: str,
        target: str,
        capability_id: str = "",
        dependencies: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> DAGTaskNode:
        """Add a task node with optional dependency links."""
        deps = dependencies or []
        # Cycle detection
        for dep in deps:
            if dep == task_id or (dep in self.nodes and task_id in self.nodes[dep].dependencies):
                raise ValueError(f"Cycle detected between task '{task_id}' and '{dep}'")

        initial_status = TaskStatus.READY if not deps else TaskStatus.PENDING
        node = DAGTaskNode(
            task_id=task_id,
            title=title,
            phase=phase,
            target=target,
            capability_id=capability_id,
            status=initial_status,
            dependencies=deps,
            metadata=metadata or {},
        )
        self.nodes[task_id] = node
        return node

    def get_ready_tasks(self) -> list[DAGTaskNode]:
        """Return all tasks whose prerequisite dependencies are COMPLETED."""
        ready: list[DAGTaskNode] = []
        for node in self.nodes.values():
            if node.status == TaskStatus.READY:
                ready.append(node)
            elif node.status == TaskStatus.PENDING:
                all_deps_done = all(
                    self.nodes[dep].status == TaskStatus.COMPLETED
                    for dep in node.dependencies
                    if dep in self.nodes
                )
                if all_deps_done and node.dependencies:
                    node.status = TaskStatus.READY
                    ready.append(node)
        return ready

    def mark_completed(self, task_id: str, result: Optional[dict] = None) -> bool:
        """Mark a task as completed and update downstream task readiness."""
        if task_id not in self.nodes:
            return False
        node = self.nodes[task_id]
        node.status = TaskStatus.COMPLETED
        node.result = result or {}
        # Update downstream
        self.get_ready_tasks()
        return True

    def mark_failed(self, task_id: str, error: str = "") -> bool:
        """Mark a task as failed and cascade skip to dependent children."""
        if task_id not in self.nodes:
            return False
        node = self.nodes[task_id]
        node.status = TaskStatus.FAILED
        node.result = {"error": error}
        # Cascade skip to dependent tasks
        for child in self.nodes.values():
            if task_id in child.dependencies and child.status in (TaskStatus.PENDING, TaskStatus.READY):
                child.status = TaskStatus.SKIPPED
        return True

    def is_finished(self) -> bool:
        """True if all tasks are in a terminal state (COMPLETED, FAILED, SKIPPED)."""
        return all(
            n.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED)
            for n in self.nodes.values()
        )

    def to_dict(self) -> dict:
        return {tid: node.to_dict() for tid, node in self.nodes.items()}
