# LONLY architecture upgrade map — research → implementation

Source: `docs/cybersecurity-harness-research.md` (frameworks + eval harnesses) and
`docs/privesc-model-plan.md` (specialist model). Principle: every upgrade is a
small, self-contained node — no frameworks, no new heavy deps, every node has a
machine-checkable acceptance test in `eval/`.

## Target architecture

```
                        ┌────────────────────────────────────────┐
                        │  LONLY agent loop (pentest_agent.py)    │
                        │  task tree   ── phase routing ──┐       │
                        │  findings log (persisted JSON)  │       │
                        │  guardrails: scope allowlist,   │       │
                        │  risk budget, confirm gates,    │       │
                        │  evidence gate                  │       │
                        └──────────────┬──────────────────┼───────┘
                                       │                  │
                     gemma3:4b         │                  │ privesc phase
                     (generalist)      │                  ▼
                     recon/enum/web/   │        ┌──────────────────────┐
                     report phases     │        │ PrivescSpecialist    │
                                       │        │ (models/privesc_     │
                                       │        │  protocol.py)        │
                                       │        │ privesc-llm-rl:4b    │
                                       │        │ exec_command /       │
                                       │        │ test_credentials     │
                                       │        └──────────────────────┘
                                       ▼
                        ┌────────────────────────────────────────┐
                        │  eval/ harness (eval_lonly.py)          │
                        │  Track B: per-tool smoke (mocked)       │
                        │  Track D: guardrail checks (offline)    │
                        │  Track A: Docker lab scenarios (later)  │
                        └────────────────────────────────────────┘
```

## Nodes (implementation order)

### N1 — Safety gates (2 × ~10 lines in pentest_agent.py)
- `shell_exec` → **confirm-required** list (`pentest_agent.py:930`). Today it is
  in neither list — the biggest safety gap (research lesson #4, CSA guidance).
- **Scope allowlist**: config `allowed_targets` (hosts/CIDRs); deny-by-default
  check in the tool-call dispatch path; out-of-scope → clear refusal message.
  Accept: `eval/` Track D asserts refusal, and N5 flags gate-bypass-via-shell.

### N2 — Findings log (new `core/state.py`, ~60 lines, stdlib JSON)
- Structured findings store: `{target, host, port, service, vuln, evidence}`.
- Written on every confirmed tool result; **injected into the prompt each turn**,
  independent of the 20-message sliding window (`pentest_agent.py:1103`).
- Persisted to `runs/<ts>/findings.json` — survives crashes, feeds the report.
- Accept: history-overflow rate → 0 in `eval/` Track C fixture.

### N3 — Task tree + phase routing (extend `core/state.py`, ~30 lines)
- Stack of sub-goals: recon → enumerate → vuln-check → **privesc** → report
  (PentestGPT's PTT, simplified). The loop pops/peeks the current sub-goal; the
  LLM reasons about one sub-task at a time.
- **Phase routing**: when the active sub-goal is `privesc`, delegate to
  `PrivescSpecialist` (models/privesc_protocol.py) with a guardrail-wrapped
  backend (scope allowlist + risk-budget accounting apply to its `exec_command`).
  All other phases stay on `gemma3:4b`. Routing decision is data, not code
  (`PHASE_MODEL_MAP` dict) — swapping models later is a config change.
- Accept: `eval/` Track A S2 (privesc box) runs the specialist; Track C measures
  step efficiency vs oracle.

### N4 — Evidence gate (small diff in `extract_final_answer`, pentest_agent.py:150)
- A finding is reportable only if it cites a concrete command + its truncated
  output (host/port/banner/CVE) present in the findings log — "prove a breach,
  don't claim one" (XBOW/Vulnhuntr pattern), extending the existing overclaim
  detector from answer-level to evidence-level.
- Accept: `eval/` Track D fabrication fixture — empty tool output must trip the
  gate; honest answers must not (FP rate ≈ 0).

### N5 — eval/ harness (`eval/eval_lonly.py`, stdlib only, no CI)
- **Track B**: 24 mocked-subprocess per-tool smoke tests (args, truncation
  limits 4000/5000/3000, exit codes, empty stdout).
- **Track D**: guardrail checks — dangerous-tool soft-blocks, confirm gates,
  risk-budget checkpoint at 5, scope-allowlist refusal, prompt-injection
  mini-suite (ASR target 0), `shell_exec` audit coverage 100% + gate-bypass rate.
- **Track C**: trajectory metrics (parse success, action validity, steps-vs-oracle,
  history overflow, truncation miss).
- **Track A** (later, Docker): 6 scenarios from the research plan; S2 privesc box
  doubles as the specialist's verifiable-reward environment.
- Accept: `python eval/eval_lonly.py` exits 0 and prints the consolidated metric
  table (research doc §4).

### N6 — Phase 1 verification (privesc model, `models/`)
- Reproduce the 12-scenario static benchmark ladder (base/SFT/RL) in local Docker
  (ipa-lab/benchmark-privesc-linux), 20-round success metric — validates the Q4
  GGUF against the paper's 93.3% before LONLY depends on it.
- **Status: implemented** — `models/benchmark_runner.py` (Docker `local_docker`
  backend, per-run container reset, JSON summaries + trajectory JSONL);
  `qwen3-4b-base:4b` / `privesc-llm-sft:4b` / `privesc-llm-rl:4b` served via
  Ollama; scenario images built; analyzer `models/analyze_benchmark.py` supports
  trajectory parsing and comparative tables.

### N7 — Modular tool subsystem & parser resilience (`tools/`, `core/parser.py`)
- Decoupled 24 tool wrappers and schemas into domain modules under `tools/`
  (`recon.py`, `web.py`, `creds.py`, `infra.py`, `base.py`) with central registry
  in `tools/__init__.py`.
- Hardened ReAct response parsing (`core/parser.py`) for 4B models: markdown code
  fences, trailing comma resilience, placeholder and fabrication detection.
- Hardened `PrivescSpecialist._chat` with retry backoff and error handling.
- Acceptance: `eval/eval_lonly.py` Tracks D, P, M, B (**33/33 checks passing**).

## Debt policy (enforced by eval/)

1. No new runtime dependency; stdlib + existing venv only.
2. Every node is importable standalone (no circular imports with the agent loop).
3. Every node has an acceptance test in `eval/` before it is "done".
4. Model/prompt/gate changes are config values, not scattered string edits.
5. `models/` and `eval/` stay independent of each other (the specialist is
   testable without Docker; the harness is runnable without Ollama).
