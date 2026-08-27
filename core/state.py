#!/usr/bin/env python3
"""core/state.py — LONLY structured state nodes (N2 + N3).

Two debt-free, stdlib-only data structures that fix the two biggest loop
weaknesses identified in docs/cybersecurity-harness-research.md:

  N2 FindingsLog — structured findings store, independent of the 20-message
      chat window. Persisted to runs/<ts>/findings.json; injected into the
      prompt every turn so discovered facts survive history truncation.

  N3 TaskTree    — sub-goal stack over the flat ReAct loop (PentestGPT's PTT,
      simplified). The loop reasons about ONE sub-task at a time, preventing
      drift on small local models.

Both are plain-Python, importable standalone (no langchain deps), and JSON-safe.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# Canonical pentest phase order (config, not code — reorder to taste)
DEFAULT_PHASES = ("recon", "enumerate", "vuln_check", "privesc", "report")

# Phase -> model routing table (N3). Data, not code: swap models by editing this.
PHASE_MODEL_MAP = {
    "recon": "gemma3:4b",
    "enumerate": "gemma3:4b",
    "vuln_check": "gemma3:4b",
    "privesc": "privesc-llm-rl:4b",
    "report": "gemma3:4b",
}


# ---------------------------------------------------------------------------
# N2: FindingsLog
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One confirmed finding. Every field must trace to tool evidence."""

    kind: str                  # e.g. "open_port", "service", "vuln", "credential"
    target: str
    detail: str                # human-readable one-liner
    evidence: str              # command + truncated output that proves it
    tool: str = ""
    port: Optional[str] = None
    service: Optional[str] = None
    severity: str = "info"     # info | low | medium | high | critical


class FindingsLog:
    """Append-only structured findings store with JSON persistence."""

    def __init__(self, run_dir: str | None = None):
        self.findings: list[Finding] = []
        self.run_dir = run_dir or os.path.join(
            "runs", time.strftime("%Y%m%dT%H%M%S")
        )
        os.makedirs(self.run_dir, exist_ok=True)
        self.path = os.path.join(self.run_dir, "findings.json")

    def add(self, finding: Finding) -> None:
        if not any(f.kind == finding.kind and f.target == finding.target
                   and f.detail == finding.detail for f in self.findings):
            self.findings.append(finding)
            self.save()

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(
                {"findings": [f.__dict__ for f in self.findings]},
                fh, ensure_ascii=False, indent=2,
            )

    def prompt_block(self, max_findings: int = 20) -> str:
        """Compact block injected into the prompt each turn."""
        if not self.findings:
            return "[FINDINGS SO FAR] none"
        lines = [f"- [{f.severity}] {f.kind} @ {f.target}"
                 + (f":{f.port}" if f.port else "")
                 + (f" ({f.service})" if f.service else "")
                 + f" — {f.detail}" for f in self.findings[:max_findings]]
        return "[FINDINGS SO FAR]\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# N3: TaskTree
# ---------------------------------------------------------------------------

@dataclass
class TaskTree:
    """Sub-goal stack over the flat ReAct loop.

    The active sub-goal is injected into the prompt; the loop never reasons
    about the whole engagement at once (drift control for 4B models).
    """

    phases: list[str] = field(default_factory=lambda: list(DEFAULT_PHASES))
    index: int = 0
    done: bool = False

    @property
    def current(self) -> str:
        if self.done:
            return "done"
        return self.phases[self.index]

    @property
    def next(self) -> Optional[str]:
        if self.index + 1 < len(self.phases):
            return self.phases[self.index + 1]
        return None

    def prompt_block(self) -> str:
        if self.done:
            return "[CURRENT SUB-GOAL] done — deliver the Final Answer."
        remaining = ", ".join(self.phases[self.index + 1:])
        return (
            f"[CURRENT SUB-GOAL] {self.current}"
            + (f" | remaining: {remaining}" if remaining else "")
        )

    def advance(self) -> None:
        """Move to the next sub-goal; never regresses (findings log keeps history)."""
        if self.done:
            return
        self.index += 1
        if self.index >= len(self.phases):
            self.done = True

    def to_dict(self) -> dict[str, Any]:
        return {"phases": self.phases, "index": self.index, "done": self.done}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TaskTree":
        return cls(phases=list(data.get("phases", DEFAULT_PHASES)),
                   index=int(data.get("index", 0)), done=bool(data.get("done", False)))
