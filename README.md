# LONLY — Logically Optimized Network Logistics & Intelligence

An enterprise-grade, policy-governed autonomous penetration testing and vulnerability assessment harness for Linux and network environments. LONLY enforces the core invariant:

> **"The LLM proposes. Deterministic code authorizes. The broker executes. Evidence proves."**

---

## Legal & Compliance Disclaimer

This software is designed exclusively for authorized penetration testing, vulnerability assessment, and defensive security research.

Unauthorized access to computer systems, networks, or digital infrastructure is illegal under applicable cybercrime legislation (e.g., the Computer Fraud and Abuse Act in the US, Section 33 of the Thai Cybercrime Act, and equivalent international frameworks). Operators must obtain explicit, written authorization from asset owners before directing this software against any target. The developers and contributors accept no liability for damages resulting from improper or unauthorized use.

---

## Architecture Overview

LONLY v2 decouples probabilistic LLM reasoning from deterministic security, isolation, and audit controls:

1. **Dual-Mode Model Boundary (`core/agent_roles.py`, `pentest_agent.py`)**:
   - **Mode 1: Conversational Q&A / Strategy**: Answers greetings, inquiries, and security explanations in natural markdown without executing unwanted tools.
   - **Mode 2: Tactical Security Assessment**: Engages the ReAct execution loop when actionable target assessments are requested.
   - **Generalist Planner (`phi4-mini`, configurable via `LONLY_MODEL`)**: Proposes investigative strategy and target discovery without holding direct execution authority.
   - **Privilege Escalation Specialist (`privesc-llm-rl:4b`)**: Generates targeted exploitation hypotheses for Linux privilege vectors.
   - **Verifier Role**: Cryptographically validates security claims against stored artifacts.
2. **Policy Engine (`core/policy.py`, `core/risk.py`)**:
   - **Target Scope & Socket Destination Authorization**: Canonical hostname resolution, CIDR allowlists, and DNS rebinding defense via `ResolvedTarget`.
   - **Authoritative Capability Manifests**: Fine-grained per-tool permissions (`ActionClass`, `RiskClass`, `NetworkAccess`) and exit code `126` approval blocks.
   - **Multi-Dimensional Risk Matrix**: Multi-vector risk scoring (destructive potential, blast radius, credential exposure) with human-in-the-loop approval gates.
3. **Execution Broker & OS Containment (`core/broker.py`, `core/sandbox.py`)**:
   - **Strict Subprocess Invariant**: Static AST enforcement ensuring zero `shell=True`, `os.system`, or `os.popen`. All 24 tools pass discrete `argv` vectors to `run_argv()`.
   - **Resource Quotas & Process Group Isolation**: POSIX memory, CPU, PID limits (`SandboxProfile`), and clean process-tree termination on timeout.
   - **Automated Output Redaction**: Broker integrates directly with `SecretVault.redact()` to sanitize credentials from outputs before reaching logs or agent memory.
4. **Secret Management Boundary (`core/vault.py`)**:
   - Random opaque references (`cred_<hex>`), capability-scoped access, rotation, revocation, in-memory zeroization, and automatic log redaction.
5. **Persistent Session Workspaces & Memory (`core/session.py`)**:
   - Isolated per-session JSONL workspaces (`~/.lonly/sessions/<session_id>/`), rolling context window compaction, dynamic scope state isolation, and zero cross-session crosstalk.
6. **Forensic Evidence & Tamper-Evident Ledger (`core/evidence.py`, `core/audit.py`, `core/telemetry.py`)**:
   - **Content-Addressable DAG**: SHA-256 evidence graph tracking execution chains from report claims down to the exact operator and tool output with lazy persistence.
   - **Cryptographic Audit Ledger**: HMAC-SHA256 write-ahead log (WAL) hash chaining with offline mathematical integrity verification.
   - **Distributed Tracing**: Distributed spans answering *"Why did LONLY run this action?"* in a single provenance query.

```
                     ┌─────────────────────┐
                     │     Operator UI     │
                     │      REST / CLI     │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Session & Engagement│
                     │ (core/session, eng) │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Dual-Mode Runtime   │
                     │ Chat Q&A / ReAct    │
                     └──────────┬──────────┘
                                │ Structured Intent
                                ▼
                     ┌─────────────────────┐
                     │ Policy Engine (PDP) │
                     │  Scope & Manifests  │
                     │  Multi-Dim Risk     │
                     └──────────┬──────────┘
                                │ Authorized Descriptors
                                ▼
                     ┌─────────────────────┐
                     │  Execution Broker   │
                     │  (core/broker.py)   │
                     └──────────┬──────────┘
                                │ run_argv (shell=False)
                                ▼
                     ┌─────────────────────┐
                     │ Sandboxed Subprocess│
                     │  (Resource Limits)  │
                     └──────────┬──────────┘
                                │
                                ▼ Target
                     ┌─────────────────────┐
                     │ Cryptographic Audit │
                     │  Evidence DAG & WAL │
                     │  Telemetry Traces   │
                     └──────────┬──────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │ Signed Pentest Report│
                     └─────────────────────┘
```

---

## Tool Arsenal

LONLY exposes **24 domain-modularized tools** organized under `tools/` with all invocations brokered via discrete argument arrays:

### Reconnaissance & Port Scanning (`tools/recon.py`)
- `rustscan_port_scan` — Full-range TCP port discovery using RustScan.
- `masscan_port_scan` — Asynchronous high-rate network subnet scanner.
- `nmap_security_scan` — Service version, OS fingerprinting, and NSE script execution.
- `whatweb_web_fingerprint` — Web framework, CMS, and technology identifier.
- `enum4linux_smb_audit` — SMB, Samba, and NetBIOS security enumeration (gated).
- `ldap_search_enumeration` — Active Directory and OpenLDAP search client.
- `kerbrute_active_directory_assessment` — Kerberos user enumeration and password spraying.

### Web Application Assessment (`tools/web.py`)
- `gobuster_directory_scan` — Directory and file brute-forcing via wordlists.
- `ffuf_web_fuzz` — High-performance HTTP endpoint and parameter fuzzing.
- `nikto_web_scan` — Comprehensive web server vulnerability scanning (gated).
- `sqlmap_vulnerability_assessment` — Automated SQL injection assessment (gated).
- `wpscan_wordpress_audit` — WordPress core, plugin, and theme vulnerability audit.
- `curl_web_request` — Raw HTTP request crafting with header and body inspection.

### Credentials & Lateral Movement (`tools/creds.py`)
- `crackmapexec` — Protocol-level credential validation for SMB, WinRM, SSH, MSSQL (confirm-required).
- `hydra_brute_force` — Multi-protocol network authentication testing (confirm-required).
- `metasploit_auxiliary_scanner` — Execution of Metasploit auxiliary scanner modules (confirm-required).
- `reverse_shell_listener` — Local Netcat listener for reverse connection capture.

### Infrastructure & Intelligence (`tools/infra.py`)
- `searchsploit_exploit_lookup` — Local Exploit-DB archive search client.
- `linpeas_privilege_escalation_scan` — Automated Linux local enumeration script.
- `impacket_tool_execute` — Windows and Active Directory protocol tooling suite.
- `cve_lookup` — Real-time vulnerability intelligence via NVD API and Exploit-DB.
- `bloodhound_analyze` — Local SharpHound/BloodHound graph parsing using NetworkX.
- `rag_query` — Semantic retrieval against local ChromaDB pentest documentation.
- `shell_exec` — Safe host command runner with audit logging and confirmation gates.

---

## Evaluation & Adversarial Hardening Suite

LONLY v2 enforces zero technical debt and 100% deterministic safety verified by **84 acceptance checks** across 8 tracks:

- **Track D (D1–D20)**: Safety, Scope, Confirmation, State & Phase Invariants
- **Track P (P1–P9)**: ReAct, Markdown Fence, Evidence & Overclaim Interception
- **Track M (M1–M3)**: Tool Arsenal Registry, Schema & Isolation Contracts
- **Track C (C1–C4)**: Trajectory Quality, Duplication & Truncation Bounds
- **Track A (A1–A3)**: Scenario Replays (Web Recon, Privesc Specialist, 5-Phase Chain)
- **Track E (E1–E5)**: Live CLI Resilience, Unicode & Human-in-the-Loop Approval
- **Track R (R1–R39)**: Comprehensive Red Team Adversarial & Cryptographic Suite:
  - `R1–R5`: Shell injection, CIDR IPv6, URL spoofing & specialist broker isolation
  - `R6–R8`: SecretVault token opaque references, zeroization & credential redaction
  - `R9–R16`: SHA-256 DAG evidence graph & tamper detection
  - `R17`: Subprocess isolation static invariant (`shell=True` / `os.system` eliminated)
  - `R18`: Authoritative `CapabilityPolicy` security manifests & approval exit code `126`
  - `R19`: `ResolvedTarget` DNS rebinding & canonical socket authorization
  - `R20`: SecretVault capability-scoping, rotation & revocation
  - `R21`: Platform-wide forensic provenance traversal (`get_provenance_trail`)
  - `R22`: Cryptographic audit ledger with HMAC-SHA256 write-ahead log hash chaining
  - `R23`: Typed security claims (`TypedClaim`) and general `ClaimVerifier`
  - `R24`: Deterministic structured fact extraction (`StructuredFactExtractor`)
  - `R25`: OS sandbox profiles and process tree isolation (`SandboxManager`)
  - `R26`: First-class engagement model (`Organization`, `Engagement`, `RunRecord`, `ApprovalRecord`)
  - `R27`: DAG task graph orchestrator (`TaskGraphDAG`)
  - `R28`: Multi-dimensional risk policy engine (`RiskPolicyEngine`)
  - `R29`: Property-based fuzzing and zero-bypass invariants (`AdversarialFuzzer`)
  - `R30`: Operational metrics and zero-defect invariants (`MetricsCollector`)
  - `R31`: Automated CI/CD security gate (`CISecurityGate`)
  - `R32`: Lab ground-truth benchmark evaluator (`BenchmarkEvaluator`)
  - `R33`: Transactional job queue and circuit breaker (`JobQueue`)
  - `R34`: Distributed tracing and action provenance query (`TelemetryTracer`)
  - `R35`: Strict model boundary separation (`PlannerRole`, `SpecialistRole`, `VerifierRole`)
  - `R36`: Dual-mode conversation and persistent session workspaces (`SessionManager`)
  - `R37`: Target anchor extraction and placeholder sanitization
  - `R38`: Standard library CLI reader with arrow key history, line editing, and autocompletion
  - `R39`: Execution broker dynamic scope allowlist synchronization
- **Track B (B0)**: Per-tool subprocess smoke validation across all 24 tools

```bash
# Run complete verification harness (84/84 checks)
LONLY_EVAL_PYTHON=~/pentest_env/bin/python ~/pentest_env/bin/python eval/eval_lonly.py
```

---

## Installation & Setup

### Prerequisites
- Linux (Debian, Ubuntu, or Kali Linux recommended)
- Python 3.10+
- [Ollama](https://ollama.ai/) installed and running (`ollama serve`)

### Quick Start with Makefile & Setup Script
```bash
# 1. Clone Repository
git clone https://github.com/poppp334/Lonly_HARNESS.git
cd Lonly_HARNESS

# 2. Automated Bootstrap (installs dependencies, pulls models, builds RAG knowledge)
./setup.sh
# OR via Make:
make setup

# 3. System Diagnostic & Health Check
make doctor

# 4. Run Complete Acceptance Test Suite (84/84 Checks)
make test

# 5. Launch Interactive Dual-Mode CLI Shell
make run
```

### Interactive CLI Commands & Navigation
- **Real-Time Thinking & Status Indicators**: Real-time feedback (`[*] LONLY is analyzing and planning...`) during local LLM token generation, with post-processing that converts raw model tags into clean Markdown.
- **Arrow Key Navigation & History**: `↑` / `↓` cycle command history persisted in `~/.lonly/history` (1,000 commands), `←` / `→` in-line cursor editing decoupled from prompt headers.
- **Tab Autocompletion**: Autocompletes `/scope`, `/session`, `/report`, `/doctor`, `/clear`, `exit`, and session IDs.
- **Target Extraction**: RFC-compliant multi-level FQDN and IP extraction directly from conversational prompts (e.g., `webme-mu.vercel.app`).
- **Interactive Scope Gating**: Real-time human-in-the-loop authorization prompt before any tool accesses a new network host.
- **Session Scope Isolation**: Scope allowlists are strictly tied to active session workspaces and automatically cleared on `/clear` and `/session new`.

| Command | Action |
| :--- | :--- |
| `[Target Objective]` | e.g., `Scan 127.0.0.1 for open ports` or ask `Explain Kerberoasting` |
| `/scope add <target>` | Add IP, multi-level FQDN, or CIDR to authorized testing scope |
| `/scope list` | View all authorized target hosts and CIDRs in active session |
| `/scope reset` | Reset scope to default loopback only (`127.0.0.1`, `localhost`, `::1`) |
| `/session list` | List all stored conversation sessions with timestamp & message counts |
| `/session new [title]` | Create and switch to a fresh, isolated session workspace (clears scope) |
| `/session load <id>` | Restore a prior session workspace from `~/.lonly/sessions/<id>/` (restores scope) |
| `/report` | Generate cryptographically signed Markdown engagement report with SHA-256 evidence chain |
| `/doctor` | Run comprehensive system diagnostic & tool health suite |
| `/clear` | Reset active conversation memory, in-memory findings, and authorized scope |
| `exit` / `quit` | Safely shutdown LONLY |

---

## Project Structure

```
Lonly_HARNESS/
├── Makefile                  # Build, test, doctor, and setup automation
├── setup.sh                  # One-click system bootstrap & model pull script
├── requirements.txt          # Python runtime dependencies
├── AGENTS.md                 # Agent specifications, roles, and capability manifest
├── LICENSE                   # MIT License
├── pentest_agent.py          # Main interactive CLI & Dual-Mode ReAct loop
├── ingest_knowledge.py       # Knowledge ingestion pipeline into ChromaDB vector store
├── knowledge/                # Markdown pentest domain knowledge & playbooks
│   ├── kerberoasting.md      # Kerberoasting attack and defense guide
│   └── linux-privesc.md      # Linux privilege escalation heuristics
├── chroma_db/                # Local ChromaDB persistent vector database
├── core/                     # Core runtime & deterministic security boundary
│   ├── agent_roles.py        # Planner, Specialist, and Verifier model boundaries
│   ├── audit.py              # Cryptographic HMAC-SHA256 WAL audit ledger
│   ├── benchmarks.py         # Ground-truth lab benchmark evaluation engine
│   ├── broker.py             # ExecutionBroker & dynamic TargetPolicy synchronization
│   ├── cli_reader.py         # Readline arrow key history, editing & tab autocompleter
│   ├── doctor.py             # System diagnostic and dependency health checker
│   ├── engagement.py         # Organization, Engagement, Run, and Approval entities
│   ├── evidence.py           # Content-addressable DAG evidence graph & TypedClaims
│   ├── extractor.py          # Structured fact extractor for prompt context hygiene
│   ├── fuzz.py               # Property-based adversarial fuzzer
│   ├── guardrails.py         # Scope control, confirmation gates, risk budgeting
│   ├── job_queue.py          # Transactional job queue & circuit breaker
│   ├── metrics.py            # Operational metrics & zero-defect SLA engine
│   ├── orchestrator.py       # DAG task graph orchestrator
│   ├── parser.py             # Resilient ReAct/JSON parsing & FQDN target extraction
│   ├── policy.py             # TargetPolicy, CapabilityPolicy, ResolvedTarget
│   ├── risk.py               # Multi-dimensional risk matrix & decision gates
│   ├── sandbox.py            # OS sandbox profiles & process containment
│   ├── session.py            # Persistent session workspaces (~/.lonly/sessions/)
│   ├── state.py              # FindingsLog, TaskTree, phase routing table
│   ├── telemetry.py          # Distributed tracing & provenance query engine
│   └── vault.py              # Hardened SecretVault with scoping & rotation
├── tools/                    # Modular 24-tool subsystem (run_argv brokered)
│   ├── __init__.py           # Central tool registry and tool_map
│   ├── base.py               # Safe execution wrapper and output truncation
│   ├── recon.py              # Nmap, RustScan (--no-banner), Masscan, WhatWeb, Enum4linux, LDAP
│   ├── web.py                # Gobuster, Ffuf, Nikto, Sqlmap, WPScan, Curl
│   ├── creds.py              # CrackMapExec, Hydra, Metasploit, ReverseShell
│   └── infra.py              # LinPEAS, SearchSploit, Impacket, BloodHound, RAG
├── models/                   # Specialist integration & benchmark evaluation
│   ├── privesc_protocol.py   # Specialist protocol & Ollama dispatch
│   ├── benchmark_runner.py   # Privilege escalation benchmark executor
│   ├── analyze_benchmark.py  # Benchmark results statistical analyzer
│   ├── smoke_test.py         # Specialist verification smoke test
│   └── Modelfile.template    # Ollama specialist template
├── eval/                     # Test & Evaluation Harness
│   ├── eval_lonly.py         # Main acceptance runner (84/84 checks)
│   ├── ci_security_gate.py   # Automated CI/CD security gate & invariant checker
│   ├── track_a_runner.py     # Scenario integration suite (S1, S2, S4)
│   ├── track_b_worker.py     # Subprocess-isolated tool smoke worker (24/24 tools)
│   ├── track_c_scorer.py     # Trajectory and loop quality scorer
│   ├── track_e_cli.py        # CLI interactive & edge case test suite
│   └── track_r_redteam.py    # 39-check adversarial red team suite (R1–R39)
├── setup/                    # System tooling installation scripts
│   └── install-system-tools.sh
├── docs/                     # Technical specifications & roadmap
│   ├── Plan-implement.md     # Production hardening roadmap
│   ├── architecture-upgrade-map.md
│   └── cybersecurity-harness-research.md
└── README.md
```

---

## License

Distributed under the MIT License. See `LICENSE` for details.
