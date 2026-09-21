# LONLY — Technical Debt & Scalability Audit

Date: 2026-09-18
Commit: `c9f2aae` (working tree dirty; see §F7)
Method: `architect` (design red-flag lens: shallow modules, information leakage, pass-throughs)
+ `daily-qa` evidence discipline (observed vs suspected, file:line evidence, smallest viable fix).
Scope: full repository (not a time window). All P0 items below were re-verified by direct source
reads; P1/P2 items carry the evidence path and are marked OBSERVED or SUSPECTED.

---

## 1. Snapshot

| Metric | Value |
|---|---|
| Python LOC | 10,944 across 60+ modules |
| Largest module | `pentest_agent.py` 1,180 lines |
| Tracked files | 69 |
| Acceptance suite | 119/119 (`make test`, sequential, no CI) |
| Concurrency primitives | **none** (`threading`/`asyncio`/`multiprocessing` = 0 hits) |
| Import time | 0.84 s (`import pentest_agent`) |
| Declared deps | 8, all unpinned; 2 undeclared import sets (SFT, text-splitters) |
| Artifacts on disk | `runs/` 36 dirs (204 KB), `~/.lonly` 88 KB, `chroma_db` 532 KB |
| Lint/typecheck/CI | absent (no `.github/`, no ruff/mypy/pytest config, `make lint` target missing) |
| TODO/FIXME markers | none (positive), but also no visible backlog |

### Runtime envelope today
Single process, single session, single target, one tool at a time, synchronous model calls with
no timeout. Everything below is organized by where that envelope breaks.

---

## 2. Executive summary — top 10 risks

| # | Risk | Severity |
|---|---|---|
| 1 | Confirm-required tools (`hydra`, `crackmapexec`, `msfconsole`, `shell_exec`) are dead: operator approval never reaches the broker (`approved` is always `False`), yet audit logs record "confirmed". | **P0** |
| 2 | Authorization keys off `argv[0]`, not tool identity: `shell_exec` runs `parts[0]` and Impacket runs any `shutil.which()` binary; unmanifested names default-allow. Arbitrary host execution bypasses the capability gate. | **P0** |
| 3 | CIDR scope is unsound: `10.0.0.0/8` is "in scope" when only `10.0.0.0/24` is allowed; `clean_target()` strips masks so CIDR scans silently degrade to one host. | **P0** |
| 4 | Blocked/denied/nonzero executions are classified as success: parser lacks `[SCOPE BLOCKED]`/`[APPROVAL REQUIRED]`, and empty-output nonzero exits become "Command executed successfully". | **P0** |
| 5 | Nmap numeric-port scans raise `NameError` (`re` not imported); masscan default emits `-ptop-1000`. Two primary recon paths are broken. | **P0** |
| 6 | All state is process-global (`chat_history`, `ALLOWED_TARGETS`, findings, evidence, task tree, session manager): two concurrent sessions corrupt each other's scope, risk budget, and history. | **P0** |
| 7 | No locking anywhere; session transcripts are fully rewritten per message (O(n²)), audit WAL appends without lock/fsync, and its sequence is `len(events)` — multi-process runs interleave and break the chain. | **P0** |
| 8 | No retention: `runs/`, sessions, WAL, escalation queue, DPO pairs, broker history, telemetry, vault logs grow forever; evidence graph is never persisted at all (`EvidenceGraph.save()` has no caller). | **P1** |
| 9 | No timeout/retry/backoff on the generalist model call; a hung Ollama stalls the only thread indefinitely; tool timeouts leave orphaned grandchildren (process-group kill exists but is never called). | **P1** |
| 10 | Delivery debt: no CI, no pins, no lint; 3 new modules required by the tree are untracked; `LICENSE` is deleted in the working tree; `chroma_db` blobs are in git history. | **P1** |

---

## 3. Scalability breakpoints

| Dimension | Today | First break | Root cause |
|---|---|---|---|
| Concurrent sessions | 1 | 2 | process globals (§B1–B3) |
| Concurrent targets | 1 tool/step | 2 | serial loop, no pool (§D1) |
| Session length | full rewrite per message | ~1k messages | O(n²) `save_session` (§C1) |
| Tool calls per engagement | re-parse all history per turn | ~1k calls | `seen_calls` + history block (§C6–C7) |
| Audit ledger | full load+verify at import | 2 processes / 10k events | `seq=len(events)`, no lock, no rotation (§B5) |
| Model availability | no timeout | 1 hung request | blocking `invoke` (§D2) |
| RAG corpus | 2 docs | 2nd `make ingest` | append-only ingest (§C9) |
| Disk | grows per task | weeks of use | no retention (§C4) |
| DLT benchmark | 50 cases serial | 500 cases | sequential loop (§D4) |
| Multi-host operation | not possible | — | no service boundary (§E7) |

---

## 4. Debt register (problem → fix map)

### A. Safety-gate integrity

**A1 — Approval dead-end (P0).**
`tools/base.py:87` defaults `approved=False`; no caller ever passes `True` (`grep approved=True` →
only the parameter definition at `tools/base.py:98,109`). `core/policy.py:334-338` therefore returns
`[APPROVAL REQUIRED]` for `hydra`, `crackmapexec`, `msfconsole`, `shell_exec` even after the operator
types `y`, while `pentest_agent.py:665` records `approval_status="confirmed"`.
Impact: 4 of 24 tools are permanently dead; audit trail is false.
Fix (smallest): thread `approved` through `ToolInvokerPort.invoke_tool(tool_name, args, approved=...)`
and have `tools/base.run_argv` pass it to the broker. Structural: a per-call `ToolCallContext`
(contextvar) carrying the gate decision, so no tool wrapper can forget it.
Test: eval D-track — approved hydra reaches broker with `approved=True`; unapproved does not.

**A2 — Authorization by command name, not capability identity (P0).**
`tools/infra.py:148` executes `run_argv(parts[0], parts[1:])`, so the broker authorizes `id`/`bash`,
not `shell_exec`. `tools/infra.py:126-131` runs any `shutil.which(tool_name)` result. Unknown names
default-allow at `core/policy.py:323-325`. Conversely LinPEAS runs `run_argv("sh", ...)` and is
blocked by the `shell_exec` manifest (`core/policy.py:362`) even though linpeas is LOW/MEDIUM risk.
Impact: arbitrary host execution ungated; intended gate applies to the wrong process.
Fix: pass `capability_id` explicitly (`run_argv(..., capability="shell_exec")`); broker resolves by
capability_id first and denies unmanifested executables above a risk threshold; Impacket gets an
executable allowlist (`GetNPUsers.py`, `secretsdump.py`, …) instead of `which()` passthrough.

**A3 — CIDR scope unsound + mask stripping (P0).**
`core/policy.py:66` and `tools/base.py:58` strip `/prefix`; `is_in_scope` (`core/policy.py:106-113`)
then matches only the base IP. Verified: with `ALLOWED_TARGETS=['10.0.0.0/24']`, targets
`10.0.0.0/8`, `/16`, `/24` all return in-scope. `clean_target('http://10.0.0.0/24')` → `10.0.0.0`.
Impact: scope escalation to an entire /8; CIDR scans silently scan one host.
Fix: keep the prefix in `resolve_destination`; compare requested network ⊆ allowed network; strip
masks only in URL-only helpers (`ensure_url` path). Add IPv6 tests.

**A4 — Denials and failures classified as success (P0).**
`core/parser.py:17-25` omits `[SCOPE BLOCKED]`, `[APPROVAL REQUIRED]`, `[POLICY BLOCKED]`; the copy
that has them (`tools/base.py:36-45`) is dead code. `core/broker.py:221` replaces empty output with
`"[Command executed successfully with no output]"` regardless of `returncode`;
`core/tool_dispatch.py:174` classifies failure by string only.
Impact: policy denials recorded as successful scans; crashed tools look successful; substring
"findings" can be fabricated from block messages.
Fix: single source of failure patterns in `core/parser.py` (delete the `tools/base.py` copy);
`ToolExecutionResult` carries `exit_code`; failure if `exit_code != 0` or pattern match.

**A5 — Fail-open unknown capabilities (P0).**
`core/policy.py:323-325` returns `True, "Default authorized"` for anything unmanifested.
Fix: fail-closed for unknown names with a low-risk allowlist (e.g. `ldapsearch`, `nxc` variants),
plus an explicit `--allow-unknown` override recorded in the audit ledger.

**A6 — Hardcoded audit key (P0).**
`core/audit.py:226` `DEFAULT_AUDIT_KEY = "LONLY-AUDIT-ROOT-KEY"`. Anyone with the source can forge
WAL signatures when `LONLY_AUDIT_KEY` is unset, invalidating the "unforgeable chain of custody"
claim. Fix: require `LONLY_AUDIT_KEY` or generate a 0600 key file on first run; fail closed.

**A7 — Secrets inherited by scanned tools (P1).**
`core/broker.py:195` previously passed `dict(os.environ)` to every child, exposing `LONLY_AUDIT_KEY`, `LONLY_PRIVESC_PASSWORD`, cloud/API tokens to the target's tooling.
Fix: Implemented `sanitize_child_env` with strict `SAFE_ENV_ALLOWLIST` (`PATH`, `HOME`, `USER`, `LANG`, etc.) and unconditional purge of `FORBIDDEN_ENV_KEYS` (`LONLY_AUDIT_KEY`, `LONLY_PRIVESC_PASSWORD`, tokens, secrets). Verified in R81.

**A8 — Recon defaults and port profiles (P0).**
Original issue: `tools/recon.py` had missing `re` import and masscan `-ptop-1000` crash, which previously fell back to aggressive `1-65535` or blind sequential `1-1000` at `rate=1000` pkts/s (causing network flooding, firewall drops, and missed critical services like MSSQL/MySQL/RDP).
Fix: Replaced aggressive recon defaults with smart, curated, non-damaging service profiles (`TOP_100_PORTS`, `TOP_COMMON_PORTS`, `WEB_PORTS`, `INFRA_AD_PORTS`, `DATABASE_PORTS`), polite Nmap timing (`T3`), safe Masscan rate (250 pps), and non-exhausting Rustscan batch sizes (300). Verified in R47.

**A9 — `curl -d @file` exfiltration path (P1, OBSERVED capability).**
`tools/web.py:129` previously passed LLM `data` straight to `-d`; curl reads `@path` from disk.
Fix: Switched from `-d` to `--data-raw`, preventing curl from interpreting `@filename` as a local disk path and eliminating file exfiltration while preserving valid payloads. Verified in R82.

### B. State, concurrency, and the audit chain

**B1 — Process-global mutable state (P0).**
`pentest_agent.py:144-155` module-level `chat_history`, `_carryover_event_log`, `_task_number`,
`_in_task_risk_events`, `_findings_log`, `_task_tree`, `_evidence_graph`; all mutated per turn.
Fix: a `SessionContext` dataclass owning these; `run_react_agent(ctx, ...)`.

**B2 — Global scope allowlist (P0).**
`core/guardrails.py:20` `ALLOWED_TARGETS: list[str] = []`, mutated by CLI and the agent
(`pentest_agent.py:638,986,1033,1054,1088`). Scope authorized in one session leaks to all.
Fix: `ScopePort` backed by the session context; `TargetPolicy` built from `ctx.scope`.

**B3 — Session manager auto-adopts the newest session (P0).**
`core/session.py:74-85`: with no active session, the newest on disk is loaded. A fresh run can
silently resume someone else's engagement. Fix: explicit session selection; auto-create only.

**B4 — No file locking, no atomic writes (P0).**
Session, audit, findings, evidence, vault, DLT writers all use bare `open`; crash mid-write
truncates. Fix: `fcntl.flock` + `tempfile` + `os.replace` in one storage helper.

**B5 — Audit chain fragility (P0).**
`core/audit.py:103-109` catches any load error and resets to genesis (hides tampering);
`:119` `seq = len(self.events)`; `:139-146` appends with flush only, no fsync; `:230` loads and
HMAC-verifies the entire WAL at import. Fix: lazy tail-load (`last event` gives seq/hash), lock
around append, fsync, rotate at N MB, never silently reset — refuse writes and alert instead.

**B6 — Timeout leaks process trees (P1).**
Original issue: `core/broker.py` let `subprocess.run` kill only the direct child; `SandboxManager.terminate_process_tree` (`core/sandbox.py:78`) had no production caller despite `setpgrp` in `preexec_fn`.
Fix: Implemented `_managed_run` in `core/broker.py` with PID tracking, process group termination via `SandboxManager.terminate_process_tree(proc.pid, SIGTERM/SIGKILL)`, and salvaged partial stdout/stderr on `TimeoutExpired`. Verified in R84.

**B7 — Sandbox profiles are dead (P1).**
Original issue: No manifest set `sandbox_profile` (`core/policy.py:342-365`), so every tool used `default`.
Fix: Assigned specific sandbox profiles (`recon`, `web`, `creds`, `infra`, `restricted`) across all capability manifests in `core/policy.py`. Set safe memory limits in `core/sandbox.py` (`web` at 1024MB to avoid Go virtual memory allocation aborts). Verified in R87.

**B8 — Fail-silent import and error paths (P1).**
Original issue: `pentest_agent.py` silently disabled privesc specialist on import error; `core/evidence.py` swallowed report-write failure; `core/session.py` hid corrupt sessions; main loop printed one-liner errors with no traceback.
Fix: Replaced silent exception swallowing with `logger.warning` in `_setup_privesc_specialist` and session loaders; wired `atomic_write` and warning logs for engagement reports in `core/evidence.py`; added `logger.exception` with full traceback in `pentest_agent.py` main loop. Verified in R89.

### C. Persistence and growth

**C1 — Session transcript rewritten per message (P1 → breaks at ~1k messages).**
`core/session.py:144-165` `save_session` rewrites the entire `transcript.jsonl`; `append_message`
(`:221-226`) calls it per message. Fix: append one line per message; write `meta.json` only on
close/mutation; compact on load.

**C2 — Findings JSON rewritten per finding (P1).**
`core/state.py:72-83` full `json.dump` per `add()`; run dir is `runs/<seconds>` (`:66-69`), so two
logs in the same second collide. Fix: append-only JSONL + periodic snapshot; run id includes PID.

**C3 — Evidence graph is memory-only (P0).**
`core/evidence.py:310-322` `save()` has no caller. All hash proofs are lost on exit; `/report`
integrity cannot be re-verified offline. Fix: call `save()` on each artifact (or checkpoint) with
atomic write; cap nodes with spill-to-disk.

**C4 — No retention policy (P1).**
`runs/` (36 dirs), `~/.lonly/sessions`, `~/.lonly/audit.wal`, `dlt_escalation_queue.jsonl`,
`dpo_preference_pairs.jsonl`, `runs/benchmark_*`, `~/.cache/lonly_sft` all grow forever. Fix:
configurable caps + `make clean` removing `runs/`; rotate WAL; dedupe escalation/DPO.

**C5 — Unbounded in-memory histories (P1).**
Original issue: `core/broker.py` (`execution_history`), `core/evidence.py` (`get_chain` used O(n²) `pop(0)`), etc.
Fix: Converted `execution_history` to `collections.deque(maxlen=max_history)` (default 1000) in `core/broker.py`; switched `get_chain` in `core/evidence.py` to `collections.deque.popleft()` (O(n)). Verified in R85, R86.

**C6 — `seen_calls` re-parsed from disk every turn (P1).**
`pentest_agent.py:497-516` re-reads the whole log; `SessionManager.get_seen_calls` exists but is
dead (`core/session.py:121`). Fix: keep the set in `SessionContext`, persist incrementally.

**C7 — Prompt history re-reads and re-renders everything (P1).**
`pentest_agent.py:286-315` `build_tool_history_block` reads the full log and embeds every raw
result; called at checkpoints (`:581`) and after every task (`:1174`). Fix: maintain a rolling
summary; cap injected tokens.

**C8 — Context growth is message-count bounded, not token bounded (P1).**
`chat_history` trimmed to 20 only in `__main__` (`pentest_agent.py:1165-1166`); observations up to
4,000 chars (`core/tool_dispatch.py:118,148`); system prompt ~4 KB re-injected each turn;
`num_ctx=8192` hardcoded (`pentest_agent.py:67`). `/session load` replays all messages (`:1070`).
Fix: token-budgeted context manager (trim/summarize to a token target); cap `/session load`.

**C9 — RAG ingest is non-idempotent and CWD-relative (P1).**
Original issue: `ingest_knowledge.py` appended duplicate chunks on re-run; `tools/infra.py` resolved `"chroma_db"` relative to CWD.
Fix: `tools/infra.py` uses absolute `DEFAULT_CHROMA_DIR`; `ingest_knowledge.py` uses deterministic chunk IDs and absolute path resolution, guaranteeing idempotent re-ingestion. Verified in R86.

**C10 — DLT/DPO artifact corruption paths (P1).**
Original issue: `core/dlt.py` escalation append had no lock and `os.makedirs(dirname)` crashed for bare filenames; DPO export duplicated pairs on re-run and could trigger `UnboundLocalError`.
Fix: `_enqueue_escalation` checks for non-empty dirname before `os.makedirs` and writes via locked `append_jsonl`. `export_preference_pairs` initializes `prompt` safely, creates parent directories, and deduplicates pairs against existing output files using locked JSONL appends. Verified in R88.

**C11 — DPO Event Schema Reconciliation & Preference Mining (P1) — COMPLETED 2026-09-21.**
Original issue: `/dlt export-dpo` expected `turn_input` and `safety_passed` event keys that the ReAct loop in `pentest_agent.py` previously never emitted, causing DPO export to yield zero pairs.
Fix: `pentest_agent.py` logs `turn_input` on user turn initiation, logs `safety_passed` and `task_number` on `conversational_response` and `scope_block`, and evaluates `final_answer` against fabrication, overclaiming, and `ClaimVerifier` to emit structured `safety_passed`, `overclaim_detected`, and `fabrication_detected` flags. `core/dlt.py` `DPOExporter` reconciles across `final_answer`, `conversational_response`, and `scope_block` events, and falls back gracefully to `./session_log.jsonl`. Verified in R91.

### D. Throughput

**D1 — Everything is serial (P1).**
No concurrency primitives anywhere; one tool per ReAct step (`pentest_agent.py:517`); sqlmap can
block 300 s (`tools/web.py:105`); no fan-out for multi-target scans. Fix: bounded thread pool for
independent read-only tools, gate stays synchronous; batch evidence writes.

**D2 — Model calls have no timeout/retry (P1).**
`pentest_agent.py:67` `ChatOllama` without timeout/`max_retries`; `:555` blocking invoke.
`models/privesc_protocol.py:178-212` retries with fixed 1 s; `models/dlt_runner.py:48` 60 s.
Fix: central client with timeout + exponential backoff + circuit breaker; per-phase budgets.

**D3 — Privesc specialist blocks the loop (P1).**
`pentest_agent.py:531` synchronous; up to 20 SSH turns × 60 s + 600 s model timeouts
(`models/privesc_protocol.py:198`). Fix: run as a job (`core/job_queue.py` exists, unused) with
progress/cancellation.

**D4 — DLT benchmark is sequential and its fluency score falls back to the prompt (P1).**
`core/dlt.py:515` one model call per case; `:556` `actual.response_text or tc["prompt"]` inflates
empty responses. Fix: bounded parallelism; score empty responses as zero.

**D5 — Rate limiting is declared but never enforced (P1).**
`core/policy.py:282` `rate_limit_per_min=60` never read; masscan `rate` unbounded
(`tools/recon.py:35`). Fix: broker token bucket per capability/target.

**D6 — SFT flywheel is single-host, single-GPU, serial (P2).**
`models/sft/train_lonly_sft.py:27,47-49,72` hardcoded base model/CUDA/device; `prepare_data.py:
35-41,52-54` serial curl + tokenize, no resume/dedupe. Fix: config-driven paths, optional CPU/CI
path, manifest + resume; not needed until corpus grows.

### E. Architecture and duplication

**E1 — Two authorization gates that disagree (P0, root of A1/A2) — COMPLETED 2026-09-21.**
Original issue: Agent gate and broker gate implemented different rules over different identifiers; agent previously hardcoded approval to tool name membership instead of operator decision.
Fix: Agent confirmation gate tracks the real operator decision (`operator_approved`) and passes it directly into `ToolCallExecutor.execute(approved=operator_approved)`, propagating through `core/tool_context.py` to `ExecutionBroker.execute()`. Verified in R90.

**E2 — Duplicated policy constants (P1).**
Failure patterns (`core/parser.py:17-25` vs `tools/base.py:36-45`), positive-finding rules
(`core/parser.py:208-230` vs `:241-251`), carryover decay (`pentest_agent.py:318-338` vs
`:341-356`), target cleaning (`pentest_agent.py:636,1086`, `core/parser.py:321,327`,
`core/policy.py:23-67`), model names (6+ sites). Fix: single source per decision; delete copies.

**E3 — Dead "enterprise" modules (P1).**
`core/orchestrator.py`, `core/job_queue.py`, `core/telemetry.py`, `core/metrics.py`,
`core/engagement.py`, `core/agent_roles.py`, `core/benchmarks.py`, `core/risk.py`,
`core/extractor.py`, `core/fuzz.py` are referenced only by `eval/track_r_redteam.py`.
`RiskPolicyEngine`, `TaskGraphDAG`, `GLOBAL_TRACER`, `DEFAULT_METRICS`, `SecretVault.store/resolve`
have no production callers. Fix: either wire the ones that solve D1/D3/C4 or move them to an
`experimental/` area and stop counting them as shipped capability. Delete `terminate_process_tree`
or call it (B6).

**E4 — Registry duplicate guard & contracts (P1).**
Original issue: `tools/__init__.py` built `tool_map` with dict comprehension without duplicate guards.
Fix: Central `tools/__init__.py` asserts unique tool names on registration, raising `ValueError` on collisions. Verified in R89.

**E5 — Ports are introduced but not yet load-bearing (P2).**
`core/ports.py` exists; only the LLM port is used by the loop. `run_react_agent` remains a
1,180-line module. Fix: continue extraction opportunistically (session, scope, evidence sink),
not a big-bang rewrite.

### F. Ops, delivery, and hygiene

**F1 — No CI (P1).** No `.github/` or other pipeline; `eval/ci_security_gate.py` runs only inside
test R31. Fix: workflow running `make test`, the security gate, ruff, and a fresh-clone import
check on push/PR.

**F2 — No lint/typecheck/test runner (P1).** `Makefile:6` declares `lint` with no target; no
ruff/mypy/pytest config; `tests/` holds only a JSONL fixture. Fix: add ruff + `make lint`; migrate
eval checks under pytest or keep the custom runner but call it from CI.

**F3 — Dependency drift (P1).** All 8 deps unpinned; `langchain-text-splitters` and the entire SFT
stack (`torch`, `transformers`, `datasets`, `trl`, `unsloth`, `safetensors`) are imported but
undeclared; `langchain`/`chromadb` are declared but never imported directly. Fix:
`requirements.lock` via `pip freeze`, `requirements-sft.txt`, move CLI-only deps (`sqlmap`,
`impacket`) to setup docs, keep `chromadb` transitive.

**F4 — print-based logging (P2).** 98 `print(` in `pentest_agent.py`; only `core/dlt.py` uses
`logging`. Fix: module logger with levels, JSONL sink, `--verbose`.

**F5 — No signal handling (P2).** No `signal.signal`; SIGTERM mid-tool leaves sessions/WAL
unflushed. Fix: SIGINT/SIGTERM handler → cancel children, flush session + audit.

**F6 — Docs drift (P2).** `AGENTS.md:11,44` (`gemma3:4b`, "45 checks"), `models/README.md:16,49`,
`core/doctor.py:7`, `README.md:624` ("39-check"), `README.md:453` machine-specific GGUF path,
`docs/DLT.md:223` nonexistent ledger path, AGENTS directory map missing the new modules, README
DPO self-contradiction (`:183-186` vs `:200,505`). Fix: docs pass + a CI grep for forbidden
strings (`gemma3:4b`, stale counts).

**F7 — Release hygiene (P0 for shipping).** `core/ports.py`, `core/tool_dispatch.py`,
`models/dlt_runner.py` are untracked but imported by tracked code — committing the tree without
them yields a repo that cannot run. `LICENSE` is deleted in the working tree while README claims
MIT. Fix: `git add` the new modules and restore `LICENSE` before any commit.

**F8 — Git/disk hygiene (P2).** `chroma_db/*.sqlite3` and `web_doc/index.html` are in history
(`77477b9`, `6879c83`); `.gitignore` lacks `runs/`, `.lonly/`, `*.wal`, `*.log`, `venv/`.
Fix: purge history (filter-repo/BFG) or accept; extend `.gitignore`; `make clean` should remove
`runs/` and root `session_log.jsonl`.

**F9 — Test-quality debt (P2).** Failure→fixture index mapping can misattribute multiple failures
(`eval/track_e_cli.py:222-227` and siblings); Track B mocks all execution; overall suite has no
timeout except Track B's 900 s. Fix: per-test naming, timeout wrapper, at least one real-binary
smoke lane for installed tools.

---

## 5. Target shape (recommended)

```
AppContext (composition root: config, model client, audit, broker)
└── SessionContext (per engagement)         ← replaces all module globals
    ├── scope: ScopePolicy                  ← per-session allowlist, CIDR-correct
    ├── history: TokenBudgetedHistory       ← token-aware, summarized
    ├── risk: RiskBudget
    ├── findings / evidence: append-only stores (atomic, capped, persisted)
    └── task_tree

ToolCall: gate(evaluate → ToolCallContext) → executor (bounded pool)
          → broker (single policy enforcement, capability_id, sandbox, audit)
```

Concurrency options (pick one):

| Option | Isolation | Refactor cost | Ops cost | Verdict |
|---|---|---|---|---|
| A. In-process threads + SessionContext | Medium | Medium | Low | **Recommended now** — subprocess I/O releases the GIL; matches current CLI |
| B. Process-per-session (separate CLI/worker) | High | Medium (still needs B1/B2) | Medium | Good once multi-tenant is required |
| C. Broker daemon + thin clients | High | High | High | Later, for multi-host |

---

## 6. Fix roadmap

### Phase 0 — Safety correctness (est. 1–2 days) — COMPLETED 2026-09-18
Shipped: A1 approval propagation via `core/tool_context.py` (executor → `run_argv` → broker);
A2 capability-id authorization (`run_argv(capability=...)`) with Impacket binary allowlist;
A3 CIDR-sound scope + mask-preserving `clean_target`; A4 denial/nonzero classification with a
single failure-pattern source; A5 fail-closed unknown capabilities (ssh manifest, nxc alias);
A6 keyfile-based audit key (0600) with non-silent legacy-chain archiving; A8 recon fixes
(`re` import, masscan default); F7 `LICENSE` restored. New checks R43–R51; suite is now
**128/128**. Pending: committing the new modules (`core/ports.py`, `core/tool_dispatch.py`,
`core/tool_context.py`, `models/dlt_runner.py`) — awaiting explicit go-ahead.

Original plan:
1. A1 approval propagation; A2 capability-id authorization + Impacket allowlist.
2. A3 CIDR scope fix + mask preservation; A4 exit-code classification + single failure list.
3. A8 `re` import + masscan default; A5 fail-closed unknowns; A6 audit key.
4. F7 commit the three untracked modules + restore `LICENSE`.
Acceptance: new eval checks R43–R52; `make test` green; two negative tests prove hydra/impacket
blocked without approval and allowed with it.

### Phase 1 — State, persistence, audit (est. ~1 week) — COMPLETED 2026-09-18
Shipped (1a): `core/storage.py` (atomic writes, flock appends, tolerant JSONL, 0700 dirs);
append-only session transcripts + atomic meta; no auto-adopt of the newest session;
destructive CWD-log clear removed from the agent; unique run directories for findings/evidence;
evidence artifacts persisted incrementally + atomic snapshot; audit lazy tail-load with tail
signature checks, per-instance thread lock + cross-process flock, fsync, and correct
multi-process sequence.
Shipped (1b): `core/session_context.py` (`SessionContext` owning scope, chat history, risk
events, task number, seen calls, findings, task tree, evidence, per-session broker + executor);
`core/tool_context.broker_context` routes `run_argv` to the context broker; legacy module-level
names resolve to the default context via PEP 562 `__getattr__`; seen-calls state moved into the
context (no per-turn log re-parse); token-bounded history (`_trim_history`, `/session load` cap);
audit size-cap rotation (`LONLY_AUDIT_MAX_BYTES`); session retention cap (`LONLY_MAX_SESSIONS`).
New checks R52–R67; suite is now **144/144**.

Original plan:
B1–B5, C1–C3, C6, C8; `SessionContext` + storage helper (lock/atomic/append); audit lazy tail-load,
lock, fsync, rotation; evidence persisted; retention caps.
Acceptance: two concurrent `SessionContext`s don't share scope/history; 10k-message session writes
one line per message; WAL verifies across two processes; `runs/` capped.

### Phase 2 — Throughput and scale (est. 1–2 weeks) — COMPLETED 2026-09-21
Shipped: `core/model_client.py` (`ResilientLLM` wrapping `LLMPort` with per-call timeout,
exponential backoff retries, and `CircuitOpenError` circuit breaker); `core/ratelimit.py`
(`TokenBucket` and `RateLimiter` enforcing manifest rate limits inside `ExecutionBroker.execute()`,
with `[RATE LIMITED]` classified as tool failure); `core/tool_pool.py` (`parallel_map` bounded
thread-pool concurrency preserving index order); `core/dlt.py` (`DLTEngine.run_benchmark` parallel
evaluation with bounded workers, and honest fluency scoring assigning 0.0 to empty outputs);
`models/privesc_protocol.py` (`PrivescSpecialist` cooperative non-blocking cancellation via `cancel_event`).
New checks R68–R76; suite is now **153/153**.

Original plan:
D1–D5; bounded tool pool; model timeout/retry/circuit breaker; privesc as cancellable job; token
budget; DLT parallelism + honest fluency; broker rate limiting.
Acceptance: two targets scan concurrently; prompt never exceeds budget; benchmark wall time scales
sub-linearly; hung model call aborts in bounded time.

### Phase 3 — Delivery and ops (est. 3–5 days) — COMPLETED 2026-09-21
Shipped: `.github/workflows/ci.yml` (GitHub Actions workflow running linting, CI security gate, and acceptance suite on push/PR); `core/config.py` (`LonlyConfig` centralized strongly-typed configuration with environment overrides and standardized structured logging); `core/signals.py` (`install_signal_handlers`, active child process group tracking and cleanup, graceful termination running store flush callbacks); `eval/check_docs.py` (anti-drift doc linter preventing obsolete model names and verifying suite counts); pinned `requirements.txt` with `requirements-sft.txt` and `requirements-dev.txt` split; `pyproject.toml` with `ruff` configuration; `Makefile` updated with `make lint` and comprehensive `make clean`; `.gitignore` extended with logs, WALs, venvs, and caches.
New checks R77–R80; suite is now **157/157**.

Original plan:
F1–F6, F8, F9; CI on push/PR; pins + lockfile; central `core/config.py`; logging; signal handling;
docs sweep + CI grep; history/`.gitignore` cleanup.
Acceptance: fresh clone → `make setup && make test` green in CI; `make lint` exists; docs grep
clean for `gemma3:4b`/stale counts.

### Phase 4 — Security Isolation & Architecture Hardening — COMPLETED 2026-09-21
Shipped:
- A7 Child Process Environment Isolation (`core/broker.py` `sanitize_child_env` enforcing `SAFE_ENV_ALLOWLIST` and purging `LONLY_AUDIT_KEY`, `LONLY_PRIVESC_PASSWORD`, tokens, and credentials). Verified in R81.
- A9 Curl Argument Exfiltration Defense (`tools/web.py` `curl_web_request` enforcing `--data-raw` instead of `-d`, preventing arbitrary `@file` exfiltration). Verified in R82.
- Doctor Diagnostic Alignment (`core/doctor.py` aligned with `LonlyConfig` singleton for model names and workspace path). Verified in R83.
- B6 Process Tree Timeout Termination & Partial Output Recovery (`core/broker.py` `_managed_run` invoking `SandboxManager.terminate_process_tree` with SIGTERM/SIGKILL escalation and salvaging `TimeoutExpired` output). Verified in R84.
- C5 Bounded In-Memory Execution History (`core/broker.py` `execution_history` backed by `deque(maxlen=max_history)`; `core/evidence.py` `get_chain` optimized to O(n) deque). Verified in R85, R86.
- C9 RAG Absolute Path & Idempotent Ingestion (`tools/infra.py` absolute `DEFAULT_CHROMA_DIR`; `ingest_knowledge.py` deterministic SHA-256 chunk IDs). Verified in R86.
- B7 Sandbox Profiles Manifest Assignment (`core/policy.py` explicit `sandbox_profile` per manifest; `core/sandbox.py` safe 1024MB web memory to avoid Go runtime VAS aborts). Verified in R87.
- C10 DLT Escalation Path Safety & Idempotent DPO Export (`core/dlt.py` bare dirname resilience, locked `append_jsonl`, deduplicated preference pairs). Verified in R88.
- E4 Tool Registry Duplicate Guard & Atomic Report Persistence (`tools/__init__.py` duplicate tool name detection; `core/evidence.py` `atomic_write` report output). Verified in R89.
- B8 Fail-Silent Error Paths & Observability (warning logs on privesc specialist import failure, main loop `logger.exception` with full traceback, session metadata warning logs).
- E1 Single-Policy Gate & Approval Decision Propagation (`pentest_agent.py` threads real operator confirmation answer to `ctx.tool_executor.execute()`, ensuring broker receives true operator decision). Verified in R90.
- C11 DPO Event Schema Reconciliation & Preference Mining (`pentest_agent.py` emits `turn_input`, `safety_passed`, `overclaim_detected`; `DPOExporter` mines verified $(x, y_w, y_l)$ preference pairs from forensic session logs). Verified in R91.
New checks R81–R91; suite is now **168/168**.

### Remaining Opportunistic Backlog (Future Enhancements)

The following items represent architectural polish and scale headroom, but do not block production or safety invariants:

1. **E3 — Dead "Enterprise" Modules Consolidation (P1)**: 10 modules (`core/orchestrator.py`, `core/job_queue.py`, `core/telemetry.py`, `core/metrics.py`, `core/engagement.py`, `core/agent_roles.py`, `core/benchmarks.py`, `core/risk.py`, `core/extractor.py`, `core/fuzz.py`) are tested in Track R, but have no active callers in the production `pentest_agent.py` loop. Move them to an `experimental/` namespace or wire them directly into orchestrator extensions.
2. **E5 — Full Hexagonal Port Decomposition (P2)**: `run_react_agent` in `pentest_agent.py` is ~1,180 LOC. While `LLMPort`, `ToolInvokerPort`, `ApprovalPort`, and `ScopePort` exist, the ReAct loop itself can be decomposed into a dedicated state-machine coordinator.
3. **F4 — CLI `print()` vs Structured Logging Migration (P2)**: `core/config.py` provides centralized JSON logging, but the interactive CLI loop in `pentest_agent.py` still uses direct `print()` calls for terminal UI rendering.
4. **D6 — Distributed Multi-GPU SFT Flywheel (P2)**: `models/sft/` is single-host, single-GPU serial. Manifest resume and multi-GPU DDP/FSDP can be added when training corpus scales.
5. **Multi-Host Broker Daemon (Scalability)**: Running `ExecutionBroker` as a remote daemon (Option C) for multi-host distributed penetration testing agents.

---

## 7. Verification plan

- Every Phase 0 fix gets a RED eval check first (negative control: unapproved/blocked path).
- Phase 1 adds a concurrency harness: two sessions, interleaved tool calls, assert isolated scope,
  history, risk, and non-corrupt stores.
- Phase 2 adds timing assertions (benchmark wall time, model timeout) and a no-orphan check
  (`pgrep` after timeout).
- Phase 3 wires `make test` + `eval/ci_security_gate.py` into CI; docs grep check.
- Keep the existing 119 checks green throughout; update counts in README/AGENTS when tracks grow.

## 8. What is already good

- `shell=False` invariant holds across `core/`, `tools/`, `pentest_agent.py` (verified by grep).
- No secrets, `.env`, or `pickle`/`yaml.load` in tracked sources.
- HMAC audit chain exists and verifies (88 events today); broker records decisions/approvals.
- Sandbox `preexec_fn` is wired; output truncation and evidence hashing exist.
- 119 deterministic checks; no TODO/FIXME debt markers; ports and tool-dispatch were recently
  introduced, so the seams for Phases 1–2 already exist.
