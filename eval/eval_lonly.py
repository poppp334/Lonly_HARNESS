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

    # agent source contract: the loop must actually USE the policy
    src = open(os.path.join(ROOT, "pentest_agent.py"), encoding="utf-8").read()
    check("D11 loop enforces DANGEROUS_TOOLS", "if tool_name in DANGEROUS_TOOLS:" in src)
    check(
        "D12 loop enforces CONFIRM_REQUIRED_TOOLS",
        "if tool_name in CONFIRM_REQUIRED_TOOLS:" in src,
    )
    check(
        "D13 scope check runs before invoke",
        "out_of_scope = [" in src and "[SCOPE BLOCKED]" in src,
    )
    check(
        "D14 findings log injected per turn",
        "_findings_log.prompt_block()" in src and "messages[0] = SystemMessage(" in src,
    )
    check(
        "D15 privesc specialist hook wired",
        "_run_privesc_specialist()" in src and "privesc_attempted" in src,
    )
    check("D16 evidence gate on final answer", "[EVIDENCE LOG]" in src)

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
    from tools.base import run_cmd, TOOL_FAILURE_PATTERNS
    from tools import ALL_TOOLS, tool_map

    check("M1 exactly 24 tools in registry", len(ALL_TOOLS) == 24 and len(tool_map) == 24)
    check("M2 all tools have unique names", len(set(t.name for t in ALL_TOOLS)) == 24)
    check("M3 tools base wrapper contract", callable(run_cmd) and len(TOOL_FAILURE_PATTERNS) >= 5)


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


def main() -> int:
    print(f"=== LONLY eval — {os.path.basename(ROOT)} ===")
    track_d()
    track_p()
    track_m()
    track_c()
    track_a()
    track_e()
    track_b()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n=== RESULT: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed ===")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
