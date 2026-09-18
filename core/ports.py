#!/usr/bin/env python3
"""core/ports.py — Abstract boundaries between LONLY orchestration and infrastructure.

Ports are stdlib-only Protocols. Adapters live at the composition root
(pentest_agent.py) or in tools/, so dependencies always point inward:

    orchestration (use cases) -> ports <- adapters (LLM, broker, CLI, filesystem)

No port imports a framework, a model client, or a subprocess module.
"""
from __future__ import annotations

from typing import Any, Protocol, Sequence


class LLMPort(Protocol):
    """Language-model generation boundary."""

    def invoke(self, messages: Sequence[Any]) -> Any:
        """Return a model response object exposing a `.content` attribute."""


class ToolInvokerPort(Protocol):
    """Executes a named capability with parsed arguments; returns raw text output."""

    def invoke_tool(self, tool_name: str, tool_args: dict) -> str:
        ...


class EvidenceSinkPort(Protocol):
    """Append-only evidence recording boundary (implemented by core.evidence.EvidenceGraph)."""

    def add_command_artifact(
        self, executable: str, argv: list[str], target: str, **kwargs: Any
    ) -> Any:
        ...

    def add_output_artifact(
        self,
        raw_output: str,
        source_tool: str,
        target: str,
        command_hash: str = "",
        **kwargs: Any,
    ) -> Any:
        ...

    def add_finding_artifact(
        self,
        finding_detail: str,
        source_tool: str,
        target: str,
        evidence_hashes: tuple = (),
        severity: str = "info",
        **kwargs: Any,
    ) -> Any:
        ...


class ApprovalPort(Protocol):
    """Interactive operator approval boundary."""

    def request(self, prompt: str) -> str:
        ...


class ScopePort(Protocol):
    """Authorized-target scope boundary."""

    @property
    def allowed_targets(self) -> list[str]:
        ...

    def is_in_scope(self, target: str) -> bool:
        ...
