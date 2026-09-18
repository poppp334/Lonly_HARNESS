#!/usr/bin/env python3
"""core/tool_dispatch.py — Tool-call policy gate and brokered execution use case.

Separates orchestration (pentest_agent.py) from tool-call authorization and
evidence recording:

  * evaluate_tool_call() is a pure policy snapshot over injected ports
    (scope, seen-call set, risk budget) using the single-source guardrail
    configuration in core/guardrails.py.
  * ToolCallExecutor invokes a tool through an injected ToolInvokerPort and
    records command/output/finding artifacts through an EvidenceSinkPort.

Neither function reads module globals or imports the agent loop.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.guardrails import (
    CONFIRM_REQUIRED_TOOLS,
    DANGEROUS_TOOLS,
    RISK_POINTS,
    extract_targets_from_args,
)
from core.parser import has_positive_finding, is_tool_failure
from core.ports import EvidenceSinkPort, ScopePort, ToolInvokerPort
from core.tool_context import approval_context, broker_context


@dataclass(frozen=True)
class ToolCallEvaluation:
    """Deterministic policy snapshot for a single proposed tool call."""

    call_key: tuple
    checkpoint_required: bool = False
    is_dangerous: bool = False
    requires_confirmation: bool = False
    is_duplicate: bool = False
    out_of_scope: tuple[str, ...] = ()
    risk_delta: int = 0


def evaluate_tool_call(
    tool_name: str,
    tool_args: dict,
    *,
    scope: ScopePort,
    seen_calls: set,
    risk_score: int,
    threshold: int,
) -> ToolCallEvaluation:
    """Evaluate a proposed tool call against scope, risk, and duplicate policy.

    Gate order mirrors the production loop:
    checkpoint > dangerous > confirmation > duplicate > scope.
    `risk_delta` is the budget to apply for the dangerous/confirmation
    categories; the caller applies it at the matching branch.
    """
    args = tool_args if isinstance(tool_args, dict) else {}
    call_key = (tool_name, tuple(sorted(args.items())))
    out_of_scope = tuple(
        t for t in extract_targets_from_args(args) if t and not scope.is_in_scope(t)
    )

    if tool_name in DANGEROUS_TOOLS:
        risk_delta = RISK_POINTS["dangerous_tool_blocked"]
    elif tool_name in CONFIRM_REQUIRED_TOOLS:
        risk_delta = RISK_POINTS["confirm_required_tool"]
    else:
        risk_delta = 0

    return ToolCallEvaluation(
        call_key=call_key,
        checkpoint_required=risk_score >= threshold,
        is_dangerous=tool_name in DANGEROUS_TOOLS,
        requires_confirmation=tool_name in CONFIRM_REQUIRED_TOOLS,
        is_duplicate=call_key in seen_calls,
        out_of_scope=out_of_scope,
        risk_delta=risk_delta,
    )


@dataclass
class ToolExecutionResult:
    """Outcome of one brokered tool invocation."""

    output: str = ""
    raw_output: str = ""
    is_failure: bool = False
    has_finding: bool = False
    command_sha256: str = ""
    output_sha256: str = ""
    error: str = ""


class _CallableInvoker:
    """Adapter that exposes a plain callable as a ToolInvokerPort."""

    def __init__(self, fn):
        self._fn = fn

    def invoke_tool(self, tool_name: str, tool_args: dict) -> str:
        return self._fn(tool_name, tool_args)


class ToolCallExecutor:
    """Invoke a tool through an injected invoker and record its evidence trail.

    The executor never decides whether a call is allowed — that is the gate's
    job. It records the command artifact before execution and the raw output
    artifact afterwards, then classifies failure/finding with core.parser.
    """

    def __init__(
        self,
        invoker: ToolInvokerPort,
        evidence_sink: Optional[EvidenceSinkPort] = None,
        max_inline_output: int = 4000,
        broker=None,
    ):
        self._invoker = (
            invoker if hasattr(invoker, "invoke_tool") else _CallableInvoker(invoker)
        )
        self._evidence = evidence_sink
        self.max_inline_output = max_inline_output
        self._broker = broker

    def execute(
        self,
        tool_name: str,
        tool_args: dict,
        target: str = "",
        approved: bool = False,
    ) -> ToolExecutionResult:
        args = tool_args if isinstance(tool_args, dict) else {}

        command_sha = ""
        if self._evidence is not None:
            cmd_node = self._evidence.add_command_artifact(
                executable=tool_name,
                argv=[f"{k}={v}" for k, v in sorted(args.items())],
                target=target,
            )
            command_sha = getattr(cmd_node, "sha256", "")

        error = ""
        try:
            with approval_context(approved):
                if self._broker is not None:
                    with broker_context(self._broker):
                        raw_output = self._invoker.invoke_tool(tool_name, args)
                else:
                    raw_output = self._invoker.invoke_tool(tool_name, args)
            if not isinstance(raw_output, str):
                raw_output = str(raw_output)
        except Exception as exc:  # noqa: BLE001 — tool failures are observations
            error = f"{type(exc).__name__}: {exc}"
            raw_output = f"[TOOL ERROR] {error}"

        output = raw_output
        if len(output) > self.max_inline_output:
            output = output[: self.max_inline_output] + "\n... [TRUNCATED]"

        output_sha = ""
        if self._evidence is not None:
            out_node = self._evidence.add_output_artifact(
                raw_output=raw_output,
                source_tool=tool_name,
                target=target,
                command_hash=command_sha,
            )
            output_sha = getattr(out_node, "sha256", "")

        has_finding = has_positive_finding(tool_name, raw_output)
        if has_finding and self._evidence is not None:
            self._evidence.add_finding_artifact(
                finding_detail=f"{tool_name}: {output[:200]}",
                source_tool=tool_name,
                target=target,
                evidence_hashes=(output_sha,) if output_sha else (),
                severity="info",
            )

        return ToolExecutionResult(
            output=output,
            raw_output=raw_output,
            is_failure=is_tool_failure(output),
            has_finding=has_finding,
            command_sha256=command_sha,
            output_sha256=output_sha,
            error=error,
        )
