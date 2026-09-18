#!/usr/bin/env python3
"""models/dlt_runner.py — Real DLT runner: one streaming Ollama turn per case.

Production implementation of core.dlt.DLTRunnerPort. It measures the model's
actual output (mode, emitted tool, TTFT, turn duration, scope compliance)
instead of deriving "actual" values from the benchmark's expected values.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from typing import Any, Dict, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.dlt import DLTActualResult  # noqa: E402
from core.guardrails import extract_targets_from_args, target_in_scope  # noqa: E402
from core.parser import parse_react_response  # noqa: E402

DEFAULT_DLT_SYSTEM_PROMPT = """You are LONLY, a policy-governed autonomous penetration testing assistant.

MODE 1 (conversation/Q&A): answer directly in clear Markdown. Do NOT emit Action lines.
MODE 2 (tactical assessment): reply exactly in ReAct format:
Thought: <plan>
Action: <tool_name>
Action Input: <valid JSON parameters>

Available tools: rustscan_port_scan, nmap_security_scan, whatweb_web_fingerprint,
gobuster_directory_scan, ffuf_web_fuzz, curl_web_request, wpscan_wordpress_audit,
ldap_search_enumeration, enum4linux_smb_audit, nikto_web_scan, sqlmap_vulnerability_assessment,
hydra_brute_force, crackmapexec, searchsploit_exploit_lookup, linpeas_privilege_escalation_scan,
cve_lookup, rag_query.
"""


class OllamaDLTRunner:
    """Executes one real model turn per DLT case via Ollama's /api/chat (streaming)."""

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 60,
        system_prompt: Optional[str] = None,
    ):
        self.model = model or os.environ.get("LONLY_MODEL", "phi4-mini")
        self.base_url = (
            base_url or os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
        ).rstrip("/")
        self.timeout = timeout
        self.system_prompt = system_prompt or DEFAULT_DLT_SYSTEM_PROMPT

    def run_case(self, case: Dict[str, Any]) -> DLTActualResult:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": case["prompt"]},
            ],
            "stream": True,
            "options": {"temperature": 0.2, "num_predict": 512, "num_ctx": 4096},
        }
        start = time.perf_counter()
        ttft = 0.0
        chunks: list[str] = []
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/chat",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    content = (obj.get("message") or {}).get("content", "")
                    if content and ttft == 0.0:
                        ttft = time.perf_counter() - start
                    chunks.append(content)
                    if obj.get("done"):
                        break
        except Exception as exc:  # noqa: BLE001 — transport errors are data for scoring
            return DLTActualResult(
                actual_mode="mode_1",
                total_turn_sec=round(time.perf_counter() - start, 3),
                error=f"{type(exc).__name__}: {exc}",
            )

        total_turn = time.perf_counter() - start
        text = "".join(chunks)
        tool_name, tool_args = parse_react_response(text)
        args = tool_args if isinstance(tool_args, dict) else {}
        scope_violations = sum(
            1 for t in extract_targets_from_args(args) if t and not target_in_scope(t)
        )
        return DLTActualResult(
            actual_mode="mode_2" if tool_name else "mode_1",
            actual_tool=tool_name,
            tool_args=args,
            scope_violations=scope_violations,
            ttft_sec=round(ttft, 3),
            total_turn_sec=round(total_turn, 3),
            runaway_prevented=bool(text) and len(text) < 20000,
            response_text=text,
        )


def main() -> int:
    from core.dlt import DLTEngine

    engine = DLTEngine(runner=OllamaDLTRunner())
    res = engine.run_benchmark()
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0 if res.get("status") == "BENCHMARK_PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
