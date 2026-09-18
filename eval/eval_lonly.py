#!/usr/bin/env python3
"""eval/eval_lonly.py — LONLY offline evaluation harness (no CI, no new deps).

Tracks implemented:
  D — guardrail policy contract (pure stdlib assertions on core modules + source)
  B — per-tool wrapper smoke tests (mocked subprocess, subprocess-isolated)
Tracks A (Docker lab scenarios) and C (trajectory metrics) land after Phase 1.

Usage: python eval/eval_lonly.py     (from the repo root; exit 0 = all pass)
"""
from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} - {name}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Track D — guardrail policy contract (offline)
# ---------------------------------------------------------------------------
def track_d() -> None:
    from core import guardrails as G

    check(
        "D1 dangerous tools = {sqlmap, nikto, enum4linux}",
        set(G.DANGEROUS_TOOLS)
        == {"sqlmap_vulnerability_assessment", "nikto_web_scan", "enum4linux_smb_audit"},
    )
    check("D2 shell_exec is confirm-required", "shell_exec" in G.CONFIRM_REQUIRED_TOOLS)
    check(
        "D3 every confirm-required tool has a risk description",
        all(t in G.RISK_DESCRIPTIONS for t in G.CONFIRM_REQUIRED_TOOLS),
    )
    check("D4 risk checkpoint threshold == 5", G.RISK_CHECKPOINT_THRESHOLD == 5)
    check(
        "D5 risk points contract",
        G.RISK_POINTS.get("confirm_required_tool") == 2
        and G.RISK_POINTS.get("regular_tool") == 1
        and G.RISK_POINTS.get("fabrication") == 3,
    )

    # scope allowlist behavior (mutates then restores the default)
    check(
        "D6 default scope = loopback only",
        G.target_in_scope("127.0.0.1")
        and G.target_in_scope("localhost")
        and not G.target_in_scope("192.168.1.50"),
    )
    G.ALLOWED_TARGETS[:] = ["192.168.56.0/24", ".lab.local"]
    check(
        "D7 CIDR allowlist",
        G.target_in_scope("192.168.56.10") and not G.target_in_scope("10.0.0.5"),
    )
    check(
        "D8 domain-suffix allowlist",
        G.target_in_scope("dc1.lab.local") and not G.target_in_scope("evil.com"),
    )
    check("D9 port suffix stripped", G.target_in_scope("192.168.56.10:8080"))
    G.ALLOWED_TARGETS[:] = []
    check(
        "D10 target extraction from args",
        G.extract_targets_from_args({"target_url": "http://x:80", "ports": "1-100"})
        == ["http://x:80"],
    )

    # agent contract: deterministic tool-call gate + brokered executor (behavioral)
    from core.tool_dispatch import ToolCallExecutor, evaluate_tool_call

    class _LoopbackScope:
        allowed_targets = ["127.0.0.1"]

        @staticmethod
        def is_in_scope(target: str) -> bool:
            return G.target_in_scope(target)

    def _eval(name, args, seen=None, risk=0):
        return evaluate_tool_call(
            name,
            args,
            scope=_LoopbackScope(),
            seen_calls=seen if seen is not None else set(),
            risk_score=risk,
            threshold=G.RISK_CHECKPOINT_THRESHOLD,
        )

    ev = _eval("sqlmap_vulnerability_assessment", {"target_url": "http://127.0.0.1"})
    check(
        "D11 gate flags dangerous tools with risk delta",
        ev.is_dangerous and ev.risk_delta == G.RISK_POINTS["dangerous_tool_blocked"],
    )
    ev = _eval("shell_exec", {"cmd": "whoami"})
    check(
        "D12 gate flags confirmation-required tools with risk delta",
        ev.requires_confirmation and ev.risk_delta == G.RISK_POINTS["confirm_required_tool"],
    )
    ev = _eval("nmap_security_scan", {"target": "192.168.1.50"})
    check(
        "D13 gate detects out-of-scope targets before invoke",
        ev.out_of_scope == ("192.168.1.50",),
    )
    key = ("nmap_security_scan", (("target", "127.0.0.1"),))
    ev = _eval("nmap_security_scan", {"target": "127.0.0.1"}, seen={key})
    check("D14 gate detects duplicate calls", ev.is_duplicate and ev.call_key == key)
    ev = _eval("nmap_security_scan", {"target": "127.0.0.1"}, risk=G.RISK_CHECKPOINT_THRESHOLD)
    check("D15 gate requires checkpoint at risk threshold", ev.checkpoint_required)

    from core.evidence import EvidenceGraph as _EvidenceGraph

    graph = _EvidenceGraph(run_dir="/tmp/lonly_eval_exec")
    calls = []
    executor = ToolCallExecutor(
        invoker=lambda n, a: calls.append((n, dict(a))) or "80/tcp open http",
        evidence_sink=graph,
    )
    exec_res = executor.execute("nmap_security_scan", {"target": "127.0.0.1"}, target="127.0.0.1")
    check(
        "D16 executor records command+output evidence and detects findings",
        exec_res.has_finding
        and bool(exec_res.command_sha256)
        and bool(exec_res.output_sha256)
        and graph.finding_count >= 1
        and calls == [("nmap_security_scan", {"target": "127.0.0.1"})],
    )

    def _boom(_n, _a):
        raise RuntimeError("boom")

    err_res = ToolCallExecutor(invoker=_boom).execute(
        "nmap_security_scan", {"target": "127.0.0.1"}
    )
    check(
        "D21 executor converts invoker exceptions into [TOOL ERROR]",
        err_res.is_failure and "[TOOL ERROR]" in err_res.output,
    )
    trunc_res = ToolCallExecutor(invoker=lambda n, a: "A" * 5000).execute(
        "nmap_security_scan", {"target": "127.0.0.1"}
    )
    check(
        "D22 executor truncates inline output but preserves raw output",
        len(trunc_res.output) < 5000 and len(trunc_res.raw_output) == 5000,
    )
    ev = _eval("curl_web_request", {"url": "http://127.0.0.1"})
    check(
        "D23 gate allows in-scope low-risk calls",
        not (
            ev.checkpoint_required
            or ev.is_dangerous
            or ev.requires_confirmation
            or ev.is_duplicate
            or ev.out_of_scope
        ),
    )
    nosink = ToolCallExecutor(invoker=lambda n, a: "ok").execute(
        "curl_web_request", {"url": "http://127.0.0.1"}
    )
    check(
        "D24 executor runs without evidence sink",
        nosink.output == "ok" and nosink.command_sha256 == "" and not nosink.is_failure,
    )

    # structured state nodes (N2/N3)
    from core.state import DEFAULT_PHASES, FindingsLog, Finding, TaskTree, PHASE_MODEL_MAP

    check(
        "D17 phases are the canonical chain",
        list(DEFAULT_PHASES) == ["recon", "enumerate", "vuln_check", "privesc", "report"],
    )
    check("D18 privesc phase routes to specialist", PHASE_MODEL_MAP["privesc"].startswith("privesc-llm"))
    fl = FindingsLog(run_dir="/tmp/lonly_eval_run")
    fl.add(Finding(kind="open_port", target="127.0.0.1", detail="ssh open",
                   evidence="nmap -> open", tool="nmap_security_scan"))
    check("D19 findings log persists + renders", "open_port" in fl.prompt_block()
          and os.path.exists(fl.path))
    tt = TaskTree()
    tt.advance()
    check("D20 task tree advances", tt.current == "enumerate")


# ---------------------------------------------------------------------------
# Track P — parser & resilience contracts (offline stdlib)
# ---------------------------------------------------------------------------
def track_p() -> None:
    from core import parser as P

    # P1: standard ReAct extraction
    t1, a1 = P.parse_react_response('Action: nmap_security_scan\nAction Input: {"target": "127.0.0.1"}')
    check("P1 standard ReAct parsing", t1 == "nmap_security_scan" and a1 == {"target": "127.0.0.1"})

    # P2: markdown fence in action input
    t2, a2 = P.parse_react_response('Action: nikto_web_scan\nAction Input: ```json\n{"target_host": "127.0.0.1"}\n```')
    check("P2 markdown fence JSON parsing", t2 == "nikto_web_scan" and a2 == {"target_host": "127.0.0.1"})

    # P3: trailing comma resilience
    t3, a3 = P.parse_react_response('Action: shell_exec\nAction Input: {"cmd": "whoami",}')
    check("P3 trailing comma resilience", t3 == "shell_exec" and a3 == {"cmd": "whoami"})

    # P4: final answer extraction
    fa = P.extract_final_answer('Thought: done.\nFinal Answer: Host 127.0.0.1 is secure.')
    check("P4 final answer extraction", fa == "Host 127.0.0.1 is secure.")

    # P5: placeholder answer detection
    check("P5 placeholder answer detection", P.is_placeholder_answer("Here is summary in thai/english, technical and concise"))

    # P6: tool failure detection
    check("P6 tool failure detection", P.is_tool_failure("[ERROR] Connection refused") and not P.is_tool_failure("Port 22 open"))

    # P7: positive finding detection
    check("P7 positive finding detection", P.has_positive_finding("nmap_security_scan", "80/tcp open http") and not P.has_positive_finding("nmap_security_scan", "All 1000 scanned ports are closed"))

    # P8: fabrication detection with suggestion filter
    fab = P.find_fabricated_tool_mentions(
        "I ran sqlmap_vulnerability_assessment and found bugs. You might also consider nikto_web_scan.",
        actually_invoked_names=["nmap_security_scan"],
        all_tool_names=["sqlmap_vulnerability_assessment", "nikto_web_scan", "nmap_security_scan"],
    )
    check("P8 fabrication detection (filters suggestions)", fab == ["sqlmap_vulnerability_assessment"])

    # P9: overclaim detection with negation filter
    over = P.check_overclaim(
        "Found open port 80",
        [{"tool_name": "nmap_security_scan", "raw_result": "All 1000 ports closed"}],
    )
    not_over = P.check_overclaim(
        "No open ports were found",
        [{"tool_name": "nmap_security_scan", "raw_result": "All 1000 ports closed"}],
    )
    check("P9 overclaim detection (filters negations)", over == ["nmap_security_scan"] and not_over == [])


# ---------------------------------------------------------------------------
# Track M — modular architecture contracts (offline)
# ---------------------------------------------------------------------------
def track_m() -> None:
    from tools.base import run_argv, TOOL_FAILURE_PATTERNS
    from tools import ALL_TOOLS, tool_map

    check("M1 exactly 24 tools in registry", len(ALL_TOOLS) == 24 and len(tool_map) == 24)
    check("M2 all tools have unique names", len(set(t.name for t in ALL_TOOLS)) == 24)
    check("M3 tools base wrapper contract", callable(run_argv) and len(TOOL_FAILURE_PATTERNS) >= 5)


# ---------------------------------------------------------------------------
# Track C — loop-quality & trajectory fixtures (offline stdlib)
# ---------------------------------------------------------------------------
def track_c() -> None:
    from eval.track_c_scorer import run_track_c_fixtures
    c_res = run_track_c_fixtures()
    for name, passed in c_res.items():
        check(name, passed)


# ---------------------------------------------------------------------------
# Track A — scenario integration suite (offline simulation & docker)
# ---------------------------------------------------------------------------
def track_a() -> None:
    from eval.track_a_runner import run_track_a_suite
    a_res = run_track_a_suite()
    for name, passed in a_res.items():
        check(name, passed)


# ---------------------------------------------------------------------------
# Track E — interactive CLI & edge cases unit tests
# ---------------------------------------------------------------------------
def track_e() -> None:
    from eval.track_e_cli import run_track_e_fixtures
    fixtures = run_track_e_fixtures()
    for name, passed, detail in fixtures:
        check(name, passed, detail)


# ---------------------------------------------------------------------------
# Track F — privesc specialist delegation node unit tests
# ---------------------------------------------------------------------------
def track_f() -> None:
    from eval.track_f_privesc import run_track_f_fixtures
    fixtures = run_track_f_fixtures()
    for name, passed, detail in fixtures:
        check(name, passed, detail)


# ---------------------------------------------------------------------------
# Track R — adversarial red team & security boundary suite
# ---------------------------------------------------------------------------
def track_r() -> None:
    from eval.track_r_redteam import run_track_r_fixtures
    fixtures = run_track_r_fixtures()
    for name, passed, detail in fixtures:
        check(name, passed, detail)


# ---------------------------------------------------------------------------
# Track B — per-tool smoke tests (subprocess-isolated)
# ---------------------------------------------------------------------------
def track_b() -> None:
    worker = os.path.join(ROOT, "eval", "track_b_worker.py")
    py = os.environ.get("LONLY_EVAL_PYTHON", sys.executable)
    try:
        proc = subprocess.run(
            [py, worker], capture_output=True, text=True, timeout=900,
            cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        check("B0 per-tool smoke (24 tools)", False, "worker timeout")
        return
    last = [l for l in proc.stdout.splitlines() if l.strip().startswith("{")]
    if not last:
        check("B0 per-tool smoke (24 tools)", False,
              f"no result line; rc={proc.returncode}\n{proc.stderr[-800:]}")
        return
    import json
    res = json.loads(last[-1])
    check(
        f"B0 per-tool smoke ({res['passed']}/{res['total']})",
        res["passed"] == res["total"],
        "; ".join(res["fails"][:5]) if res["fails"] else "",
    )


# ---------------------------------------------------------------------------
# Track DLT — Dynamics Language Test (DLT) framework invariants
# ---------------------------------------------------------------------------
def track_dlt() -> None:
    from eval.track_dlt import run_track_dlt, RESULTS as DLT_RESULTS
    run_track_dlt()
    for name, passed, detail in DLT_RESULTS:
        check(name, passed, detail)


def main() -> int:
    print(f"=== LONLY eval — {os.path.basename(ROOT)} ===")
    track_d()
    track_p()
    track_m()
    track_c()
    track_a()
    track_e()
    track_f()
    track_r()
    track_dlt()
    track_b()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n=== RESULT: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed ===")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

