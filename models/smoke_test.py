#!/usr/bin/env python3
"""Smoke test: does the served privesc-llm model speak the expected protocol?

Uses a fake backend (never grants root). Verifies:
  1. the model emits <tool_call> blocks with valid JSON,
  2. the loop dispatches them to the backend and keeps going,
  3. run() terminates cleanly (stall or turn cap).

Usage: ./smoke_test.py [model]   (default: privesc-llm-rl:4b)
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privesc_protocol import PrivescSpecialist, ToolResult  # noqa: E402


class FakeBackend:
    """Harmless stand-in: echoes commands, credentials never validate."""

    def exec_command(self, command: str) -> ToolResult:
        return ToolResult(
            False,
            f"fake:~$ {command}\nfake: command executed (no root), got_root=false",
        )

    def test_credentials(self, user: str, password: str) -> ToolResult:
        return ToolResult(False, f"fake: login for '{user}' failed (wrong password)")


def main() -> int:
    model = sys.argv[1] if len(sys.argv) > 1 else "privesc-llm-rl:4b"
    spec = PrivescSpecialist(
        FakeBackend(),
        model=model,
        user="alice",
        password="alice",
        max_turns=3,
    )
    result = spec.run()
    print("== run summary ==")
    print(json.dumps(
        {k: result[k] for k in ("success", "turns", "reason", "tool_calls")},
        indent=2,
    ))
    for msg in result["messages"]:
        if msg["role"] == "assistant":
            print("== first assistant turn (excerpt) ==")
            print(msg["content"][:1500])
            break
    ok = result["tool_calls"] >= 1 and result["reason"] in ("turn limit reached", "stalled: no tool calls")
    print("SMOKE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
