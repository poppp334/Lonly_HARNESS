#!/usr/bin/env python3
"""core/telemetry.py — First-Class Observability & Distributed Tracing for LONLY v2.

Enforces:
- W3C-compatible correlation across Trace, Engagement, Run, Task, Execution, Model, and Decision IDs.
- End-to-end root cause and reasoning provenance traversal ("Why did LONLY run this action?").
- Structured span hierarchy and execution timing tracking.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Iterator, Optional


@dataclass
class SpanRecord:
    """A distributed execution span."""
    trace_id: str
    span_id: str
    name: str
    parent_span_id: Optional[str] = None
    attributes: dict = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    status: str = "OK"

    def to_dict(self) -> dict:
        return asdict(self)


class TelemetryTracer:
    """Distributed tracing coordinator and provenance correlation engine."""

    def __init__(self):
        self._spans: dict[str, SpanRecord] = {}
        self._trace_map: dict[str, list[str]] = {}

    def start_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        attributes: Optional[dict] = None,
    ) -> SpanRecord:
        """Create and register an active tracing span."""
        t_id = trace_id or f"trace_{uuid.uuid4().hex[:12]}"
        s_id = f"span_{uuid.uuid4().hex[:8]}"
        span = SpanRecord(
            trace_id=t_id,
            span_id=s_id,
            name=name,
            parent_span_id=parent_span_id,
            attributes=attributes or {},
        )
        self._spans[s_id] = span
        if t_id not in self._trace_map:
            self._trace_map[t_id] = []
        self._trace_map[t_id].append(s_id)
        return span

    def finish_span(self, span_id: str, status: str = "OK") -> None:
        if span_id in self._spans:
            span = self._spans[span_id]
            span.end_time = time.time()
            span.status = status

    def get_trace_spans(self, trace_id: str) -> list[SpanRecord]:
        """Return all spans in a trace."""
        span_ids = self._trace_map.get(trace_id, [])
        return [self._spans[sid] for sid in span_ids if sid in self._spans]

    def query_action_provenance(self, execution_id: str) -> dict:
        """Answer 'Why did LONLY run this action?' by correlating span lineage."""
        matching_spans = [
            s for s in self._spans.values()
            if s.attributes.get("execution_id") == execution_id
        ]
        if not matching_spans:
            return {"found": False, "reason": "No span associated with execution_id"}

        target_span = matching_spans[0]
        # Traverse parent chain
        chain = [target_span]
        curr = target_span
        while curr.parent_span_id and curr.parent_span_id in self._spans:
            curr = self._spans[curr.parent_span_id]
            chain.append(curr)

        return {
            "found": True,
            "execution_id": execution_id,
            "trace_id": target_span.trace_id,
            "action": target_span.name,
            "target": target_span.attributes.get("target", ""),
            "decision_id": target_span.attributes.get("decision_id", ""),
            "approval_id": target_span.attributes.get("approval_id", ""),
            "operator": target_span.attributes.get("operator", ""),
            "lineage_depth": len(chain),
            "ancestors": [s.name for s in chain[1:]],
        }


# Global tracer instance
GLOBAL_TRACER = TelemetryTracer()
