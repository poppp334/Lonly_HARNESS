#!/usr/bin/env python3
"""Phase 1c — analyze benchmark ladder results vs the paper.

Reads completed-run JSON lines from a ladder log (and/or summary.json files in
runs/benchmark_*) and prints:
  - per-model success rate (primary metric: success within 20 rounds),
  - per-scenario x per-model table,
  - turn-efficiency stats (mean turns on successes),
  - comparison line vs the paper's reported 93.3% (PrivEsc-LLM 4B, RL).

Usage:
  python analyze_benchmark.py --log /tmp/ladder_full.log
  python analyze_benchmark.py --dirs runs/benchmark_20260824T060143
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from benchmark_runner import MODELS  # noqa: E402  (single source of truth for model names)

PAPER_RL_RATE = 93.3  # PrivEsc-LLM 4B, 12 static scenarios, 10 runs each, 20 rounds

# `[!] 01_vuln_suid_gtfo base run 1 FAILED: HTTP Error 400: Bad Request`
_FAILED_RE = re.compile(r"^\[!\]\s+(\S+)\s+(\S+)\s+run\s+(\d+)\s+FAILED:\s*(.*)$")


def load_entries(logs: list[str], dirs: list[str]) -> list[dict]:
    entries: dict[tuple, dict] = {}
    sources: list[str] = []
    for d in dirs:
        sources += glob.glob(os.path.join(d, "summary.json"))
        sources += glob.glob(os.path.join(d, "*.jsonl"))
        sources += glob.glob(os.path.join(d, "*.log"))
    for f in logs + sources:
        if not os.path.exists(f):
            continue
        if f.endswith(".json") and os.path.basename(f) == "summary.json":
            for e in json.load(open(f)):
                entries[(e["scenario"], e["model"], e.get("run", 0))] = e
        else:
            run_idx = 0
            base_name = os.path.splitext(os.path.basename(f))[0]
            for line in open(f, encoding="utf-8", errors="replace"):
                line = line.strip()
                if line.startswith("{"):
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if {"scenario", "model", "success"} <= set(e):
                        entries[(e["scenario"], e["model"], e.get("run", 0))] = e
                    elif "trajectory" in e and "success" in e:
                        # Trajectory JSONL record
                        run_idx += 1
                        model = e.get("model", "")
                        # Try to extract scenario from filename: <scenario>_<model>
                        scenario = base_name
                        for m_key, m_val in MODELS.items():
                            if base_name.endswith(m_val):
                                scenario = base_name[: -(len(m_val) + 1)]
                                break
                            elif base_name.endswith(m_key):
                                scenario = base_name[: -(len(m_key) + 1)]
                                break
                        traj = e.get("trajectory", [])
                        turns = max((t.get("turn", 1) for t in traj), default=1)
                        entry = {
                            "scenario": scenario,
                            "model": model or base_name,
                            "run": run_idx,
                            "success": bool(e.get("success")),
                            "turns": turns,
                            "tool_calls": len(traj),
                            "reason": "got_root" if e.get("success") else "failed",
                        }
                        entries[(scenario, model or base_name, run_idx)] = entry
                m = _FAILED_RE.match(line)
                if m:
                    scenario, key, run, reason = m.groups()
                    model = MODELS.get(key, key)
                    e = {"scenario": scenario, "model": model, "run": int(run),
                         "success": False, "turns": 0, "tool_calls": 0,
                         "reason": f"exception: {reason}"}
                    # never overwrite a real result with a synthetic failure
                    entries.setdefault((scenario, model, int(run)), e)
    return list(entries.values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", action="append", default=[])
    ap.add_argument("--dirs", action="append", default=[])
    args = ap.parse_args()
    entries = load_entries(args.log, args.dirs)
    if not entries:
        print("[!] no completed runs found")
        return 1

    by_model: dict[str, list[dict]] = defaultdict(list)
    by_scenario: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for e in entries:
        by_model[e["model"]].append(e)
        by_scenario[e["scenario"]][e["model"]].append(e)

    print(f"=== {len(entries)} completed runs ===")
    print(f"{'model':28s} {'succ/runs':>10s} {'rate':>7s} {'mean turns (successes)':>24s}")
    for model, rows in sorted(by_model.items()):
        ok = [r for r in rows if r["success"]]
        rate = 100 * len(ok) / len(rows)
        mean_t = sum(r["turns"] for r in ok) / len(ok) if ok else float("nan")
        print(f"{model:28s} {f'{len(ok)}/{len(rows)}':>10s} {f'{rate:5.1f}%':>7s} {mean_t:>24.1f}")

    print("\n=== per-scenario success (runs: succ/total) ===")
    scenarios = sorted(by_scenario)
    models = sorted({e["model"] for e in entries})
    header = f"{'scenario':36s}" + "".join(f"{m.split(':')[0]:>22s}" for m in models)
    print(header)
    print("-" * len(header))
    for sc in scenarios:
        row = f"{sc:36s}"
        for m in models:
            rows = by_scenario[sc].get(m, [])
            ok = sum(1 for r in rows if r["success"])
            row += f"{f'{ok}/{len(rows)}':>22s}"
        print(row)

    rl_rows = [r for r in entries if "rl" in r["model"]]
    if rl_rows:
        rl_ok = sum(1 for r in rl_rows if r["success"])
        rl_rate = 100 * rl_ok / len(rl_rows)
        delta = PAPER_RL_RATE - rl_rate
        print(f"\n=== vs paper ===\nRL (this run): {rl_rate:.1f}% over {len(rl_rows)} runs "
              f"(paper: {PAPER_RL_RATE}%) — delta {delta:+.1f} points "
              f"(Q4_K_M quantization + Ollama serving + heuristic got_root detection vs paper's bf16/vLLM protocol)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
