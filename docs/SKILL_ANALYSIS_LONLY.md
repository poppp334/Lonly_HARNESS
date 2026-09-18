# SKILL_ANALYSIS_LONLY.md — Skill Mapping & Clean Architecture Assessment

**Analysis date:** 2026-09-18
**Repository:** Lonly_HARNESS (branch `main`, HEAD `c9f2aae`)
**Core invariant under evaluation:** *"The LLM proposes. Deterministic code authorizes. The broker executes. Evidence proves."*

---

## 1. Project Overview

LONLY is an autonomous penetration-testing agent harness with two runtime modes:

- **Mode 1 — Conversational/Advisory:** direct LLM answers, no tool execution.
- **Mode 2 — Tactical ReAct:** a multi-turn loop (`run_react_agent`) that proposes tool calls, passes deterministic scope/confirmation/risk gates, executes 24 brokered tools, records evidence, and gates the final answer on evidence.

**Stack:** Python 3.10+, LangChain + `langchain-ollama` (generalist `phi4-mini`), a local PrivEsc specialist (`privesc-llm-rl:4b`), ChromaDB + `nomic-embed-text` for RAG, and stdlib-only core security modules. No web framework; CLI-first.

**Architectural intent (as documented):** four separated roles — Planner (proposes), Specialist (hypotheses), Deterministic Runtime (authorizes), Verifier (proves) — plus a cryptographic audit ledger, content-addressable evidence DAG, secret vault, and a DLT self-tuning framework.

**Reality check (summary of Section 4):** the deterministic boundary (broker + policy + evidence + audit) is real and well-tested at the module level. The main architectural debt is a 1,143-line entrypoint that mixes router, use cases, adapters, and UI; ten `core/` modules with no production call site; and verification gaps where "closed-loop" claims are self-graded simulations rather than measured runs.

---

## 2. Current Architecture Diagram

```
                           ┌──────────────────────────────────────────────────────────┐
                           │  pentest_agent.py  (1,143 lines — entrypoint + monolith) │
                           │  globals: chat_history, _findings_log, _task_tree,       │
                           │           _evidence_graph, ALLOWED_TARGETS, _task_number │
                           │  ChatOllama instantiated at import (line 66)             │
                           │                                                          │
                           │  Dual-mode router │ ReAct loop │ risk gates │ CLI shell  │
                           └───────┬───────────────────┬──────────────────┬───────────┘
                                   │                   │                  │
             tools/*.py (24 LangChain @tool)      core/state.py      core/session.py
             recon web creds infra base           FindingsLog        SessionManager
                                   │              TaskTree           (~/.lonly)
                                   │                   │
                                   ▼                   │
                     ┌──────────────────────────┐      │
                     │ tools/base.py run_argv   │      │
                     │  (also: sys.modules      │      │
                     │   ["pentest_agent"] hook │      │
                     │   — upward dependency)   │      │
                     └────────────┬─────────────┘      │
                                  ▼                    │
                 ┌─────────────────────────────────┐   │
                 │ core/broker.py ExecutionBroker  │   │
                 │  capability_policy.authorize()  │   │
                 │  policy.resolve_destination()   │   │
                 │  subprocess.run(shell=False)    │   │
                 │  vault.redact()                 │   │
                 │  audit_ledger.record_event()    │   │
                 └───┬───────────┬───────────┬─────┘   │
                     │           │           │         │
          core/policy.py   core/vault.py  core/audit.py │
          TargetPolicy     SecretVault    HMAC-SHA256   │
          CapabilityPolicy (singleton)    WAL (singleton,
                     ▲                    in-memory by  │
                     │                    default)      │
          core/guardrails.py  ALLOWED_TARGETS (mutable global, aliased into broker)
                     ▲
                     │
   ┌─────────────────┴──────────────────────────────────────────────────────┐
   │ ORPHAN / UNWIRED CORE MODULES (no production call site; only Track R)   │
   │ agent_roles  orchestrator  risk  sandbox  job_queue  metrics            │
   │ telemetry    benchmarks    fuzz  engagement                             │
   └─────────────────────────────────────────────────────────────────────────┘

   core/evidence.py (EvidenceGraph, ClaimVerifier, report) ← written by pentest_agent only
   core/parser.py, core/dlt.py, core/embeddings.py, core/doctor.py, core/extractor.py, core/cli_reader.py
   models/ (specialist protocol, SFT, benchmark runner) — separate from broker path
   eval/ (106 checks across tracks A/B/C/D/DLT/E/F/M/P/R)
```

Dependency direction that is correct: `tools → tools.base → core.broker → core.policy/audit/vault`; most `core/` modules are stdlib-only and importable standalone.
Dependency direction that is violated: `tools/base.py → pentest_agent` (adapter → application); `core/broker.py → core.guardrails.ALLOWED_TARGETS` (domain policy → ambient mutable global).

---

## 3. Skill Mapping Table

Skill availability was checked against the installed skill set. `trust-no-agent` and `Verigent` are **not installed** under those names; nearest installed equivalents are noted.

| Skill | Applies To | How It Helps | Priority |
|-------|-----------|--------------|----------|
| **pstack** (`poteto-mode` / `pstack-tdd` installed) | `pentest_agent.py:389-822` monolith; the 10 unwired `core/` modules | Route the use-case extraction as a planned workflow: architect ports → TDD slices → review checkpoints. Keeps the refactor incremental so `make test` stays green. | **High** |
| **TDD Skill** (`tdd`, `test-driven-development`, `expect-fail`, `pstack-tdd` installed) | `run_react_agent`, `ExecutionBroker.execute`, `DLTEngine.run_benchmark`, `DPOExporter` | Write characterization tests with fake LLM/broker first (RED), then extract services (GREEN), then simplify. Directly fixes the source-string tests in `eval/eval_lonly.py:77-95` (D11-D16) that assert text, not behavior. | **High** |
| **senior-security** | `core/broker.py`, `core/policy.py`, `core/audit.py`, `core/vault.py`, `core/sandbox.py` | STRIDE/DREAD threat model of the deterministic boundary; secret scanning; review of the hardcoded HMAC default key (`core/audit.py:96`), caller-asserted `approved` flag (`core/broker.py:71-80`), and the unwired sandbox. | **High** |
| **security-advisor** | Prompt-injection path (`core/evidence.py:337` fencing), `ClaimVerifier` substring logic (`core/evidence.py:407-492`), scope-global mutation (`pentest_agent.py:575`) | Build concrete attack paths: indirect prompt injection bypassing provenance fencing, evidence-echo claim forgery, forged WAL entries with the known default key, cross-session scope bleed. | **High** |
| **trust-no-agent** — *not installed; nearest:* `receipts`, `verify`, `verification-before-completion` | README/docs claims; DLT benchmark; DPO export; sandbox containment | Force fresh evidence for every "done" claim: run `make test` and reconcile the real count (106, not README's 96 / AGENTS.md's 45); prove whether `run_benchmark` exercises a model; count real DPO pairs. | **High** |
| **Verigent** — *not installed; nearest:* `aip-identity` | Evidence/report signing; audit-ledger key lifecycle; multi-model role identity | Replace the shared hardcoded HMAC secret with managed keys and externally verifiable signatures; sign reports; give Planner/Specialist/Verifier distinct verifiable identities. | Medium |
| **CSTCloud aip-identity** (`aip-identity` installed) | `core/agent_roles.py` (Planner/Specialist/Verifier), `/report` output, skill provenance | Agent identity + Ed25519 signatures for role separation, report provenance, and trust graph between specialist and orchestrator. Pairs with `Verigent` goals. | Medium |

**Additional installed skills with high leverage (not in the requested list):**

| Skill | Applies To | Why |
|-------|-----------|-----|
| `architect` | Layer extraction from `pentest_agent.py`; defining ports (LLMPort, BrokerPort, EvidenceSinkPort, ApprovalPort) | Prevents a rushed refactor from swapping one monolith for coupled services. |
| `clean-code` | Whole diff after extraction | Removes duplication between `guardrails.RISK_POINTS` and `core/risk.py`, and the two parallel evidence systems. |
| `test-coverage` | `run_react_agent` branch coverage; DLT/DPO paths | Adds the missing edge-case tests (timeouts, scope denial, fabricated claims, DPO schema). |
| `roast-my-code` | Any refactor branch | Three-axis review (standards/spec/security) before merge. |
| `network-pentest` / `pentest` | Validating that extracted services preserve offensive semantics | Domain-correctness review of tool routing and scope behavior. |

---

## 4. Clean Architecture Assessment

### 4.1 Dependency Rule

| # | Violation | Location | Impact |
|---|-----------|----------|--------|
| V1 | Interface adapter reaches into the application entrypoint via `sys.modules["pentest_agent"]` | `tools/base.py:77-86` (and `run_cmd` at `100-113`) | Circular conceptual dependency; production code contains a test seam; import order affects behavior. |
| V2 | Policy engine depends on a mutable module-level global `ALLOWED_TARGETS`, aliased into the broker | `core/guardrails.py:20`, `core/broker.py:21,58`; mutated at `pentest_agent.py:575,952,998,1018-1020,1050-1051,1059` | Scope synchronization is an aliasing side effect, not an explicit API; per-session scope isolation is fragile; no single authority owns scope. |
| V3 | Domain state reads infrastructure config at import | `core/state.py:30-31` (`LONLY_MODEL`, `LONLY_SPECIALIST_MODEL`), `PHASE_MODEL_MAP` at `34-40` | Import-time environment coupling; model routing is not injectable. |
| V4 | Infrastructure constructed in the entrypoint with no port interface | `pentest_agent.py:66` (`ChatOllama`), `204-251` (specialist HTTP + SSH) | Cannot substitute a fake LLM without monkeypatching the module; import has side effects. |
| V5 | Domain internals leak; use case (report generation) lives in the domain module | `core/evidence.py:415,423,519` (`graph._nodes`), `533` (`generate_engagement_report`) | ClaimVerifier depends on private dict; report format changes force domain edits. |
| V6 | Broken type annotation / style | `core/policy.py:128` uses `Any` without importing it (latent, masked by `from __future__ import annotations`); `from enum import Enum` mid-file at `241` | Tooling (`get_type_hints`, mypy) will fail; signals missing lint gate. |

**Correct direction already present:** `tools/*` → `tools.base` → `core.broker` → `core.policy`/`core.audit`/`core.vault`; `core/` modules are mostly stdlib-only; `models/` is decoupled from the runtime; `eval/` imports production modules rather than the reverse.

### 4.2 Layer Separation

| Layer | Intended | Actual Location | Verdict |
|-------|----------|-----------------|---------|
| Domain | Scope rules, capability manifests, evidence, audit crypto | `core/policy.py`, `core/guardrails.py`, `core/evidence.py`, `core/audit.py`, `core/state.py`, `core/vault.py`, `core/risk.py` | Mostly clean, but `state.py` leaks env config and `evidence.py` hosts reporting. |
| Use Cases | Planner/Specialist coordination, risk gating, final-answer verification | Embedded in `pentest_agent.py:389-822`; `core/orchestrator.py`, `core/agent_roles.py`, `core/dlt.py` declared but unwired | **Main gap.** No injectable application service; all coordination reads module globals. |
| Interface Adapters | Broker, tool wrappers, CLI, session persistence | `core/broker.py`, `tools/*`, `core/cli_reader.py`, `core/session.py`, `core/parser.py` | Broker is a de-facto adapter in `core/` (acceptable), but it imports the global scope and has no ports. |
| Infrastructure | LLM client, subprocess, filesystem, vector DB | `ChatOllama` (entrypoint), `subprocess` (`broker.py:150`), file I/O (`audit.py:136`, `evidence.py:321`, `state.py:79`), `core/embeddings.py`, Ollama HTTP (`models/privesc_protocol.py`) | Subprocess is properly centralized in the broker; LLM and persistence are not behind interfaces. |

**Orphan modules (verified by import graph):** `core/agent_roles.py`, `core/orchestrator.py`, `core/risk.py`, `core/job_queue.py`, `core/metrics.py`, `core/telemetry.py`, `core/sandbox.py`, `core/benchmarks.py`, `core/fuzz.py`, `core/engagement.py` are imported **only** by `eval/track_r_redteam.py` — not by `pentest_agent.py` or any production module. `core/extractor.py` is imported only by `core/fuzz.py`. This is a parallel "spec layer" that tests validate but the product does not use (e.g., `SandboxManager.get_preexec_fn` is never passed to `subprocess.run` in `core/broker.py:150-158`).

### 4.3 Testability

**Strengths**
- `core/` modules are importable standalone (no LangChain dependency): `policy`, `guardrails`, `evidence`, `audit`, `vault`, `parser`, `state`, `risk`, `orchestrator`.
- Track B isolates all 24 tool wrappers in a subprocess with a mocked executor (`eval/track_b_worker.py:63-72`).
- Tracks D/P/M/C/A/E/F/R/DLT total **106 checks** (D20 + P9 + M3 + C4 + A3 + E5 + F10 + R39 + DLT12 + B1), consistent with README line 468 and inconsistent with README lines 32/270/291 (96) and AGENTS.md line 75 (45).

**Weaknesses**
- The orchestration loop is testable only by importing the monolith and patching module globals: `patch("pentest_agent.run_argv", ...)` (`eval/track_e_cli.py:63,80,93,104,133`; `eval/track_f_privesc.py:95-97,170`).
- Import-time side effects: `FindingsLog()` and `EvidenceGraph()` create `runs/<timestamp>/` directories at import (`pentest_agent.py:152-154`; `core/state.py:69`; `core/evidence.py:99-100`), and `ChatOllama` is constructed at import (`pentest_agent.py:66`).
- Track D checks D11-D16 assert **source substrings** (`eval/eval_lonly.py:77-95`), e.g. `"if tool_name in DANGEROUS_TOOLS:" in src`. These are change-detector tests that pass if the string exists in a comment.
- Track R validates unwired modules, so `R25` (sandbox) passes while production execution is unsandboxed — false confidence.
- No test asserts `DLTEngine.run_benchmark` actually calls a model, or that `DPOExporter` matches the event schema written by the agent.

### 4.4 Agent-Friendliness

**Strengths**
- Every module has a purposeful docstring; tool wrappers share one shape (`args_schema` + `run_argv`); `tool_map` is a single registry; `AGENTS.md` and `docs/` exist.

**Risks for AI agents navigating/modifying this repo**
- `pentest_agent.py` (1,143 lines) holds router, loop, gates, evidence writes, verification, CLI, and banner. A change to any concern requires understanding all of them.
- Global mutable state (`chat_history`, `_findings_log`, `_task_tree`, `_evidence_graph`, `ALLOWED_TARGETS`, `_task_number`, `_carryover_event_log`) makes edits order-dependent and hard to isolate.
- Ten unwired modules look load-bearing to a reader; an agent may "fix" code that is never executed or assume the runtime is safer than it is.
- Documentation drift: `AGENTS.md` (45 checks, `gemma3:4b`), `README.md` (96 checks; also 106 at line 468), `docs/architecture-upgrade-map.md` (61/61, `gemma3:4b`), actual code (`phi4-mini`, 106 checks). Agents will trust whichever file they read first.

### 4.5 Verification

**Strengths**
- SHA-256 content-addressable evidence DAG with parent links (`core/evidence.py:102-161`), tamper detection (`281-288`).
- HMAC-SHA256 chained WAL with offline verifier (`core/audit.py:162-210`, CLI at `221-245`).
- Provenance fencing of untrusted tool output (`core/evidence.py:337-355`).
- Secret redaction in the vault and in every session log write (`core/vault.py:147-167`; `pentest_agent.py:263`).
- CI security gate (`eval/ci_security_gate.py`) enforcing no `shell=True`, `os.system`, `os.popen`, and `subprocess.run` only in `core/broker.py`.

**Gaps (each is a claim that does not survive fresh verification)**

| # | Gap | Evidence |
|---|-----|----------|
| G1 | `DLTEngine.run_benchmark` is a self-graded simulation, not a closed loop | `core/dlt.py:468-472` derives `actual_mode` from `expected_mode`; line `478` passes `exp_tool` as both expected and actual; line `477` hardcodes safety 100; line `479` hardcodes 0.4s/1.8s latency. It never invokes the LLM or a tool. |
| G2 | `/dlt export-dpo` cannot produce pairs from real logs | `core/dlt.py:396` reads `turn_input` events that are never written; `400-401` read `safety_passed`/`overclaim_detected` keys that `pentest_agent.py:751-756` never logs. Actual logged types: `tool_call`, `final_answer`, `scope_block`, `placeholder_detected`, `fabrication_warning`, `unverified_claim`, `privesc_specialist`, `conversational_response`. |
| G3 | Sandbox containment is declared, not enforced | `core/sandbox.py:99-104` defines profiles; `core/broker.py:150-158` calls `subprocess.run` with no `preexec_fn`/resource limits. |
| G4 | Multi-dimensional risk engine unused | `core/risk.py:56-103` never imported in production; risk is inline constants in `core/guardrails.py:79-87` consumed at `pentest_agent.py:505-537,683`. |
| G5 | Audit defaults are weak | Hardcoded default key `"LONLY-AUDIT-ROOT-KEY"` (`core/audit.py:96`); `DEFAULT_AUDIT_LEDGER = AuditLedger()` has no path (`core/audit.py:218`) so broker events are in-memory only; broker records only `PROCESS_END` (`core/broker.py:214-224`), never `PROCESS_START`/`BROKER_CALL`/`DECISION`/`APPROVAL`. |
| G6 | Approval is caller-asserted, not recorded | `core/broker.py:71,80` trusts `approved: bool`; `core/engagement.py` (approval data structures) is unused by the loop. |
| G7 | Claim verification is substring matching, port-only in the final gate | `core/evidence.py:433-492`; `verify_final_answer` extracts only ports (`500-530`). Echoing evidence text can satisfy a claim. |
| G8 | Evidence DAG and audit WAL are not cross-linked | Command artifact uses the tool name as `executable` and `k=v` strings as `argv` (`pentest_agent.py:614-618`); the broker's real `execution_id` is not attached to the evidence node. |
| G9 | Track R's 39 passes prove module behavior, not runtime wiring | Orphan-module import graph (Section 4.2); sandbox R25 example. |
| G10 | Doc/claim drift | `AGENTS.md:75` (45), `README.md:32,270,291,317,597` (96), `README.md:468` (106), `docs/architecture-upgrade-map.md:73` (61), actual 106. |

---

## 5. Recommended Actions

Prioritized. Each action names the skill that should execute it.

### P0 — Truth and containment (small, high impact)

1. **Wire sandbox, risk, and full audit events into the broker.** Pass `SandboxManager.get_preexec_fn(profile)` to `subprocess.run` in `core/broker.py:150`; record `PROCESS_START`, `BROKER_CALL`, `DECISION`, `APPROVAL`; give `DEFAULT_AUDIT_LEDGER` a real path.
   *Skills: `tdd` (regression tests first), `receipts` (verify enforcement with a real subprocess), `senior-security` (validate limits).*
2. **Make DLT honest.** Inject a runner port into `DLTEngine` so `run_benchmark` executes the real agent against the 50-case baseline; delete hardcoded safety/latency values; add a negative-control case that must score below 100.
   *Skills: `tdd` + `receipts`; `root-cause` if the runner port exposes more wiring bugs.*
3. **Reconcile the DPO event schema.** Either emit `turn_input` + `safety_passed`/`overclaim_detected` from the loop, or update `DPOExporter` to the real event names; add a fixture test that exports > 0 pairs from a synthetic log.
   *Skills: `tdd`, `test-coverage`.*
4. **Harden the audit ledger key and link evidence to executions.** Require a key from env/keyfile (no default), persist per-run, and attach the broker `execution_id` to the evidence command node.
   *Skills: `senior-security`, `aip-identity` (managed identity/key lifecycle).*

### P1 — Layer extraction and test honesty

5. **Extract an application service layer from `pentest_agent.py`.** Define ports (`LLMPort`, `BrokerPort`, `EvidenceSinkPort`, `ApprovalPort`, `ScopePort`), move the ReAct loop into `core/` services, and leave the CLI as a thin adapter. Do this behind characterization tests so `make test` stays at 106/106.
   *Skills: `architect` (ports/ownership first), then `pstack`/`poteto-mode` + `tdd` for execution, `clean-code` for the diff.*
6. **Remove the upward dependency in `tools/base.py`.** Delete the `sys.modules["pentest_agent"]` seam and inject the executor/broker (or a test double) through the tool wrappers.
   *Skills: `architect`, `clean-code`, `tdd`.*
7. **Replace global `ALLOWED_TARGETS` with an explicit `ScopeManager`** owned by the session and injected into the broker and CLI; make session load/save operate on it atomically.
   *Skills: `architect`, `tdd`; `security-advisor` to probe cross-session scope bleed.*
8. **Replace source-string tests D11-D16 with behavioral tests** using a fake LLM + fake broker; add an architecture test asserting every `core/` module is reachable from the entrypoint (this would have caught the ten orphans).
   *Skills: `test-coverage`, `tdd`.*
9. **Threat-model the deterministic boundary.** STRIDE/DREAD on broker, policy, vault, audit, plus the prompt-injection path and ClaimVerifier bypasses; DREAD-score the findings and file them as tickets.
   *Skills: `senior-security` (model), `security-advisor` (attack paths), `roast-my-code` (pre-merge review of fixes).*

### P2 — Hygiene and strategic trust

10. **Single-source the architecture docs.** Generate `docs/ARCHITECTURE.md` from a module registry with a status field (`wired` / `declared`), update `AGENTS.md` and `README.md` counts, and fix `docs/architecture-upgrade-map.md` (`gemma3:4b` → `phi4-mini`).
    *Skills: `technical-writing`, `repomap`.*
11. **Sign reports and role identities.** Move from a shared HMAC secret to per-role identities (Planner/Specialist/Verifier) and externally verifiable signatures on `/report` output.
    *Skills: `aip-identity`; `Verigent` if/when installed.*
12. **Run the full quality gate on the extracted architecture.** `qa-full` or `clean-code` + `roast-my-code` after P1 lands; keep `eval/ci_security_gate.py` in the loop.
    *Skills: `qa-full`, `roast-my-code`, `clean-code`.*

---

## 6. Skill Invocation Examples (Top 3)

Top 3 actions: (1) broker containment/audit wiring, (2) honest DLT + DPO verification, (3) monolith extraction.

```bash
# 1. Security: threat-model the deterministic boundary and unwired containment
opencode run @senior-security "STRIDE/DREAD threat-model core/broker.py, core/policy.py, core/audit.py, core/vault.py, and core/sandbox.py. Include: hardcoded HMAC default key at core/audit.py:96, caller-asserted approved flag at core/broker.py:71-80, sandbox profiles never passed to subprocess.run at core/broker.py:150, and ClaimVerifier substring bypasses at core/evidence.py:433-492."

# 2. Verification: prove or falsify the DLT/DPO claims with fresh evidence
opencode run @receipts "Verify every README claim about the DLT framework. Run core/dlt.py run_benchmark and prove whether it ever invokes the LLM or a tool (see hardcoded scores at core/dlt.py:468-479). Then run DPOExporter.export_preference_pairs against ~/.lonly/sessions and report the actual pair count versus the 'turn_input' schema at core/dlt.py:396. Report raw command output, not summaries."

# 3. Refactor: extract the ReAct use case behind ports, test-first
opencode run @pstack "Plan and execute extraction of run_react_agent (pentest_agent.py:389-822) into injected application services behind ports (LLMPort, BrokerPort, EvidenceSinkPort, ApprovalPort, ScopePort). Write characterization tests with fake LLM/broker first, keep make test at 106/106, and remove the sys.modules['pentest_agent'] seam in tools/base.py:77-86 as part of the slice."
```

Notes:
- `@senior-security` and `@receipts` are installed. `@pstack` routes through `poteto-mode` / `pstack-tdd`; use `opencode run @poteto-mode "<same prompt>"` if `@pstack` is not resolvable in your OpenCode version.
- `trust-no-agent` is not installed; `receipts` (or `verification-before-completion`) provides the same evidence-first discipline. `Verigent` is not installed; `aip-identity` is the nearest cryptographic-identity skill.

---

## Appendix A — Method & Coverage

**Files analyzed (read in full or substantially):** `README.md`, `AGENTS.md`, `docs/architecture-upgrade-map.md`, `Makefile`, `requirements.txt`, `.gitignore`, `pentest_agent.py` (approx. lines 1-280 and 389-1143), `core/broker.py`, `core/policy.py`, `core/guardrails.py`, `core/agent_roles.py`, `core/orchestrator.py`, `core/state.py`, `core/audit.py`, `core/vault.py`, `core/evidence.py`, `core/sandbox.py`, `core/dlt.py` (approx. lines 1-120, 358-508), `tools/base.py`, `tools/__init__.py`, `eval/eval_lonly.py`, `eval/ci_security_gate.py`, `models/privesc_protocol.py` (top).

**Files scanned but not fully read (imports/definitions only):** `tools/recon.py`, `tools/web.py`, `tools/creds.py`, `tools/infra.py`, `core/parser.py`, `core/session.py`, `core/doctor.py`, `core/embeddings.py`, `core/extractor.py`, `core/fuzz.py`, `core/metrics.py`, `core/telemetry.py`, `core/risk.py`, `core/job_queue.py`, `core/engagement.py`, `core/benchmarks.py`, `core/cli_reader.py`, all `eval/track_*.py`, `models/*` (remaining), `models/sft/*`.

**Could not parse / issues found:**
- `core/policy.py:128` — annotation references `Any` which is not imported (masked by `from __future__ import annotations`).
- `LICENSE` is deleted in the working tree (`git status: D LICENSE`) while README claims MIT; either restore or update README.
- Config file scan for `*.toml/*.yaml/*.yml` returned no project files (none exist outside virtualenvs), so no CI/container config was available to review.
- `runs/` and `session_log.jsonl` exist locally but are gitignored (correct).

**Test suite counts (static):** D20, P9, M3, C4, A3, E5, F10, R39, DLT12, B1 = **106 checks**, matching `README.md:468`; `README.md:32/270/291/317/597` (96) and `AGENTS.md:75` (45) are stale.
