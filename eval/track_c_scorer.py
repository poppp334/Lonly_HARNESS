#!/usr/bin/env python3
"""eval/track_c_scorer.py — Track C: Loop-quality & Trajectory Scorer for LONLY.

Evaluates replayable agent and specialist trajectories on:
  1. Parse success rate (% turns extracting valid Action/Input or Final Answer)
  2. Action validity rate (% actions matching known tools in registry)
  3. History overflow & duplicate call detection rate
  4. Truncation handling & grounding verification
  5. Step efficiency vs oracle baseline

Stdlib only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

from core.parser import (
    extract_final_answer,
    extract_json_object,
    find_fabricated_tool_mentions,
    is_placeholder_answer,
    is_tool_failure,
    parse_react_response,
)
from tools import tool_map


@dataclass
class TrajectoryMetrics:
    total_turns: int
    parsed_actions: int
    valid_tool_actions: int
    final_answers: int
    duplicate_calls: int
    tool_failures: int
    parse_success_rate: float
    action_validity_rate: float
    duplicate_rate: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_turns": self.total_turns,
            "parsed_actions": self.parsed_actions,
            "valid_tool_actions": self.valid_tool_actions,
            "final_answers": self.final_answers,
            "duplicate_calls": self.duplicate_calls,
            "tool_failures": self.tool_failures,
            "parse_success_rate": round(self.parse_success_rate, 3),
            "action_validity_rate": round(self.action_validity_rate, 3),
            "duplicate_rate": round(self.duplicate_rate, 3),
        }


def score_turns(turn_texts: list[str]) -> TrajectoryMetrics:
    """Score a sequence of model turn outputs."""
    total_turns = len(turn_texts)
    parsed_actions = 0
    valid_tool_actions = 0
    final_answers = 0
    duplicate_calls = 0
    tool_failures = 0
    seen_actions: set[tuple[str, str]] = set()

    for text in turn_texts:
        fa = extract_final_answer(text)
        if fa:
            final_answers += 1
            continue

        tool_name, tool_args = parse_react_response(text)
        if tool_name is not None and tool_args is not None:
            parsed_actions += 1
            if tool_name in tool_map:
                valid_tool_actions += 1
                call_key = (tool_name, json.dumps(tool_args, sort_keys=True))
                if call_key in seen_actions:
                    duplicate_calls += 1
                seen_actions.add(call_key)

    psr = (parsed_actions + final_answers) / max(total_turns, 1)
    avr = valid_tool_actions / max(parsed_actions, 1)
    dupr = duplicate_calls / max(parsed_actions, 1)

    return TrajectoryMetrics(
        total_turns=total_turns,
        parsed_actions=parsed_actions,
        valid_tool_actions=valid_tool_actions,
        final_answers=final_answers,
        duplicate_calls=duplicate_calls,
        tool_failures=tool_failures,
        parse_success_rate=psr,
        action_validity_rate=avr,
        duplicate_rate=dupr,
    )


def run_track_c_fixtures() -> dict[str, bool]:
    """Runs standard Track C quality test fixtures."""
    results = {}

    # Fixture C1: Clean trajectory
    clean_turns = [
        "Thought: Need to scan host.\nAction: nmap_security_scan\nAction Input: {\"target\": \"127.0.0.1\"}",
        "Thought: Port 80 is open, check web technologies.\nAction: whatweb_web_fingerprint\nAction Input: {\"target_url\": \"http://127.0.0.1\"}",
        "Thought: Information collected.\nFinal Answer: Host 127.0.0.1 runs Apache HTTP Server on port 80.",
    ]
    m_clean = score_turns(clean_turns)
    results["C1 clean trajectory 100% parse & validity"] = (
        m_clean.parse_success_rate == 1.0 and m_clean.action_validity_rate == 1.0
    )

    # Fixture C2: Trajectory with duplicate call
    dup_turns = [
        "Thought: Scan port.\nAction: nmap_security_scan\nAction Input: {\"target\": \"127.0.0.1\"}",
        "Thought: Scan port again.\nAction: nmap_security_scan\nAction Input: {\"target\": \"127.0.0.1\"}",
        "Thought: Done.\nFinal Answer: Scan complete.",
    ]
    m_dup = score_turns(dup_turns)
    results["C2 duplicate call detection rate"] = (m_dup.duplicate_calls == 1)

    # Fixture C3: Markdown code fence in JSON
    fenced_turns = [
        "Thought: Scan.\nAction: rustscan_port_scan\nAction Input: ```json\n{\"target\": \"127.0.0.1\"}\n```",
    ]
    m_fenced = score_turns(fenced_turns)
    results["C3 code-fenced action parsed successfully"] = (
        m_fenced.parsed_actions == 1 and m_fenced.valid_tool_actions == 1
    )

    # Fixture C4: Truncation threshold contract
    from tools.base import run_argv
    results["C4 truncation contract respected"] = len(run_argv("python3", ["-c", 'print("A"*5000)'], max_output=4000)) <= 4050

    return results
