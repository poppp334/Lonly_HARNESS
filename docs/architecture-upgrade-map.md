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
                     phi4-mini         │                  │ privesc phase
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
- All other phases route to generalist (`phi4-mini`). Config-driven via `PHASE_MODEL_MAP`.

### N4 — Evidence gate (`core/parser.py`) [Implemented & Verified]
- Findings reportable only when citing machine-logged command + output proof via `[EVIDENCE LOG]`.
- Fabrication detector catches uninvoked tools; overclaim detector catches phantom positive findings.

### N5 — Offline eval harness (`eval/eval_lonly.py`) [Implemented & Verified]
- **Track D (D1–D24)**: Guardrail and policy assertions + tool-call gate/executor contracts.
- **Track P (P1–P9)**: Multi-pass JSON and ReAct parser resilience.
- **Track M (M1–M3)**: Modular tool registry contracts.
- **Track C (C1–C4)**: Trajectory loop quality and truncation bounds.
- **Track A (A1–A3)**: Scenario lifecycle integration.
- **Track E (E1–E8)**: CLI interaction and edge cases (scope gate, evidence gate, prompt state).
- **Track F (F1–F10)**: PrivEsc specialist delegation node.
- **Track DLT (DLT1–DLT15)**: DLT scoring, runner port, no-fabrication guard, negative control.
- **Track R (R1–R76)**: Adversarial red team & security boundaries.
- **Track B (B0)**: Subprocess-isolated tool smokes (24/24).
- Total: **153/153 checks passing (100%)**.

### N6 — Specialist verification & flywheel (`models/`) [Implemented & Verified]
- Specialist protocol adherence (`models/privesc_protocol.py`, `models/smoke_test.py`).
- Benchmark scenario runner (`models/benchmark_runner.py`, `models/analyze_benchmark.py`).
- Local SFT training flywheel (`models/sft/train_lonly_sft.py`, `models/sft/merge_adapter.py`, `models/sft/serve_sft.sh`).

### N7 — Modular tool subsystem (`tools/`) [Implemented & Verified]
- 24 tools decoupled into `recon.py`, `web.py`, `creds.py`, `infra.py`, `base.py`.
- Smart parameter sanitization (`clean_target`, `ensure_url`, `find_wordlist`, `_format_rustscan_ports`).

### N8 — Deterministic ExecutionBroker & TargetPolicy (`core/broker.py`, `core/policy.py`) [Implemented & Verified]
- `shell=False` process execution strictly enforced across all 24 tools.
- RFC-compliant URL parsing and IPv4/IPv6/CIDR host canonicalization.
- Security authorization enforced at the broker boundary (below the agent loop).

### N9 — SecretVault & Sensitive Data Redaction (`core/vault.py`) [Implemented & Verified]
- Opaque reference tokens (`cred_<sha256>`) preventing plaintext credentials in prompts.
- Deterministic session log and SFT trajectory secret redaction.
- Structured `CapabilityDescriptor` configuration.

### N10 — Immutable Evidence Graph & Provenance Fencing (`core/evidence.py`) [Implemented & Verified]
- SHA-256 content-addressable artifact DAG (`command` → `raw_output` → `finding`).
- Tamper-evident graph integrity verification.
- `<untrusted_observation>` boundary tags mitigating indirect prompt injection.

### N11 — Cryptographic Claim Verification & Report Engine (`core/evidence.py`) [Implemented & Verified]
- `ClaimVerifier` automated claim-to-evidence cross-referencing.
- Automated engagement report generator with SHA-256 cryptographic proof hashes.
- CLI first-class `report` command.

### N12 — Broker Sandbox & Full Audit Lifecycle (`core/broker.py`, `core/sandbox.py`, `core/audit.py`) [Implemented & Verified]
- `subprocess.run` receives `SandboxManager.get_preexec_fn()` from the capability manifest's profile (process group, CPU/PID quotas; memory limits opt-in).
- Broker records `BROKER_CALL`, `PROCESS_START`, `DECISION` (deny), `APPROVAL`, and `PROCESS_END` events in the HMAC-SHA256 WAL.
- `DEFAULT_AUDIT_LEDGER` persists to `~/.lonly/audit.wal` (override via `LONLY_AUDIT_LEDGER`), verifiable offline via `python -m core.audit verify`.

### N13 — Honest DLT Runner Port (`core/dlt.py`, `models/dlt_runner.py`) [Implemented & Verified]
- `DLTEngine` scores only injected `DLTRunnerPort` observations; no runner returns `NO_RUNNER` instead of a fabricated score.
- `OllamaDLTRunner` executes one real streaming model turn per case and measures mode, emitted tool, TTFT, and turn duration.
- Negative-control test proves runner violations fail the benchmark (composite < 90).

### N14 — Application Ports & Tool Dispatch (`core/ports.py`, `core/tool_dispatch.py`) [Implemented & Verified]
- `LLMPort`, `ToolInvokerPort`, `EvidenceSinkPort`, `ApprovalPort`, `ScopePort` define the inward-facing boundaries; adapters live at the composition root (`pentest_agent.py`).
- `evaluate_tool_call()` is a pure gate snapshot (checkpoint/dangerous/confirm/duplicate/scope) over injected ports.
- `ToolCallExecutor` records command/output/finding evidence through the sink and classifies failures/findings without touching agent globals.
- `tools/base.py` exposes an explicit `set_executor` seam; the former `sys.modules["pentest_agent"]` upward dependency is removed.

### N15 — Per-Session Context (`core/session_context.py`) [Implemented & Verified]
- `SessionContext` owns scope, chat history, risk events, task number, seen calls, findings, task tree, evidence, and a per-session `ExecutionBroker` + `ToolCallExecutor`.
- `core/tool_context.broker_context` routes `run_argv` to the context broker (explicit broker > context broker > default broker), so scope is enforced per engagement.
- Legacy module-level names (`chat_history`, `_findings_log`, …) resolve to the default context via PEP 562 `__getattr__`; `core/storage.py` provides atomic writes, locked JSONL appends, and 0700 directories.
- History is token-bounded (`_trim_history`), the audit WAL rotates at a size cap, and sessions are pruned at `LONLY_MAX_SESSIONS`.

### N16 — Throughput, Concurrency & Model Resilience (`core/model_client.py`, `core/ratelimit.py`, `core/tool_pool.py`) [Implemented & Verified]
- `ResilientLLM` wraps any `LLMPort` with bounded invocation timeouts, exponential backoff retries, and a 3-state circuit breaker (`CircuitOpenError`).
- `RateLimiter` and `TokenBucket` enforce manifest-defined rates per capability and target inside `ExecutionBroker.execute()`. Burst overages return `[RATE LIMITED]` and exit code 126.
- `parallel_map` provides order-preserving, exception-safe thread-pool concurrency for batch jobs.
- `DLTEngine.run_benchmark` evaluates test cases concurrently using bounded worker threads and scores empty responses honestly with `0.0` fluency.
- `PrivescSpecialist` supports non-blocking cooperative cancellation via `cancel_event`.

## Debt policy (enforced by eval/)

1. No new runtime dependency; stdlib + existing venv only.
2. Every node is importable standalone (no circular imports with the agent loop).
3. Every node has an acceptance test in `eval/` before it is "done".
4. Model/prompt/gate changes are config values, not scattered string edits.
5. `models/` and `eval/` stay independent of each other.
