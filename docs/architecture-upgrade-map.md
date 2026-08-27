# LONLY architecture upgrade map — research → implementation

Source: `docs/cybersecurity-harness-research.md` (frameworks + eval harnesses) and
PrivEsc specialist design (`models/README.md`). Principle: every upgrade is a
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
                        │  Track D: guardrail checks (offline)    │
                        │  Track P: parser resilience (4B models) │
                        │  Track M: modular tool contracts        │
                        │  Track C: trajectory & loop metrics     │
                        │  Track A: scenario integration lifecycle│
                        │  Track E: CLI edge-case unit tests      │
                        │  Track B: per-tool smoke (mocked 24/24) │
                        └────────────────────────────────────────┘
```

## Implemented Nodes

### N1 — Safety gates (`core/guardrails.py`) [Implemented & Verified]
- `shell_exec` → **confirm-required** list along with `crackmapexec`, `hydra`, and `metasploit`.
- **Scope allowlist**: config `allowed_targets` (IPs, CIDRs, domains); deny-by-default check in tool-call dispatch path.
- **Risk budget**: 5-point threshold pause for operator review (`continue`, `stop`, `redirect`).

### N2 — Findings log (`core/state.py`) [Implemented & Verified]
- Structured findings store: `{target, host, port, service, vuln, evidence}`.
- Written on confirmed tool results; **injected into prompt each turn**, independent of the 20-message sliding window.
- Persisted to `runs/<ts>/findings.json`.

### N3 — Task tree + phase routing (`core/state.py`) [Implemented & Verified]
- Stack of sub-goals: `recon` → `enumerate` → `vuln_check` → `privesc` → `report`.
- **Phase routing**: `privesc` phase routes dynamically to `PrivescSpecialist` (`models/privesc_protocol.py`).
- All other phases route to generalist (`gemma3:4b`). Config-driven via `PHASE_MODEL_MAP`.

### N4 — Evidence gate (`core/parser.py`) [Implemented & Verified]
- Findings reportable only when citing machine-logged command + output proof via `[EVIDENCE LOG]`.
- Fabrication detector catches uninvoked tools; overclaim detector catches phantom positive findings.

### N5 — Offline eval harness (`eval/eval_lonly.py`) [Implemented & Verified]
- **Track D (D1–D20)**: Guardrail and policy assertions.
- **Track P (P1–P9)**: Multi-pass JSON and ReAct parser resilience.
- **Track M (M1–M3)**: Modular tool registry contracts.
- **Track C (C1–C4)**: Trajectory loop quality and truncation bounds.
- **Track A (A1–A3)**: Scenario lifecycle integration.
- **Track E (E1–E5)**: CLI interaction and edge cases.
- **Track B (B0)**: Subprocess-isolated tool smokes (24/24).
- Total: **45/45 checks passing (100%)**.

### N6 — Specialist verification & flywheel (`models/`) [Implemented & Verified]
- Specialist protocol adherence (`models/privesc_protocol.py`, `models/smoke_test.py`).
- Benchmark scenario runner (`models/benchmark_runner.py`, `models/analyze_benchmark.py`).
- Local SFT training flywheel (`models/sft/train_lonly_sft.py`, `models/sft/merge_adapter.py`, `models/sft/serve_sft.sh`).

### N7 — Modular tool subsystem (`tools/`) [Implemented & Verified]
- 24 tools decoupled into `recon.py`, `web.py`, `creds.py`, `infra.py`, `base.py`.
- Smart parameter sanitization (`clean_target`, `ensure_url`, `find_wordlist`, `_format_rustscan_ports`).

## Debt policy (enforced by eval/)

1. No new runtime dependency; stdlib + existing venv only.
2. Every node is importable standalone (no circular imports with the agent loop).
3. Every node has an acceptance test in `eval/` before it is "done".
4. Model/prompt/gate changes are config values, not scattered string edits.
5. `models/` and `eval/` stay independent of each other.
