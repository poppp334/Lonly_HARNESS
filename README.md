# LONLY — Logically Optimized Network Logistics & Intelligence

An autonomous, multi-phase penetration testing and vulnerability assessment agent for Linux environments, combining a Generalist ReAct Orchestrator with a dedicated Privilege Escalation Specialist model.

---

## Legal & Compliance Disclaimer

This software is designed exclusively for authorized penetration testing, vulnerability assessment, and defensive security research.

Unauthorized access to computer systems, networks, or digital infrastructure is illegal under applicable cybercrime legislation (e.g., the Computer Fraud and Abuse Act in the US, Section 33 of the Thai Cybercrime Act, and equivalent international frameworks). Operators must obtain explicit, written authorization from asset owners before directing this software against any target. The developers and contributors accept no liability for damages resulting from improper or unauthorized use.

---

## Architecture Overview

LONLY implements a hybrid architecture combining high-level autonomous planning with domain-specialized execution:

1. **Generalist Orchestrator (`gemma3:4b`)**: Manages the overarching ReAct (Reasoning + Acting) loop, user interaction, reconnaissance, web vulnerability discovery, Active Directory inspection, and report generation.
2. **Privilege Escalation Specialist (`privesc-llm-rl:4b`)**: A specialized 4B parameter model trained via Reinforcement Learning on interactive Linux environments. It is dynamically routed when the Task Tree enters the `privesc` phase.
3. **Structured State Machine**:
   - **Task Tree (`core/state.py`)**: Canonical phase stack (`recon` -> `enumerate` -> `vuln_check` -> `privesc` -> `report`).
   - **Findings Log (`core/state.py`)**: Persistent JSON findings database injected into the system prompt each turn, ensuring critical target intel survives rolling conversation window truncation.
4. **Safety & Policy Guardrails (`core/guardrails.py`)**:
   - **Deny-by-Default Scope Enforcement**: Target IP, CIDR, and domain allowlists evaluated prior to any tool invocation.
   - **Multi-Tier Execution Gates**: Soft-blocks dangerous tools (`sqlmap`, `nikto`, `enum4linux`) and requires interactive human confirmation for high-impact tools (`crackmapexec`, `hydra`, `metasploit`, `shell_exec`).
   - **Cumulative Risk Budget**: Checkpoints execution at 5 risk points for operator review (continue, stop, or redirect).
5. **Evidence Grounding Gate (`core/parser.py`)**: Attaches an `[EVIDENCE LOG]` block citing verified command executions and raw outputs to prevent hallucinations and ungrounded breach claims.

```
                      +------------------------------------------+
                      |       Operator Objective / Request       |
                      +--------------------+---------------------+
                                           |
                                           v
+------------------------------------------------------------------------------------+
| LONLY Generalist Orchestrator (gemma3:4b)                                          |
|                                                                                    |
|  [Task Tree]               [Findings Store]             [Guardrail Engine]         |
|  Phase: recon/enum/vuln    runs/<ts>/findings.json      Scope Allowlist (IP/CIDR)  |
|                                                         Risk Checkpoint (max 5)    |
|                                                         Interactive Confirm Gate   |
+------------------------------------------+-----------------------------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v (recon / web / enum / report)               v (privesc phase)
+------------------------------------------+  +--------------------------------------+
| Modular Tool Arsenal (24 Tools)          |  | PrivEsc Specialist Node              |
|                                          |  | (privesc-llm-rl:4b)                  |
| tools/recon.py   tools/web.py            |  |                                      |
| tools/creds.py   tools/infra.py          |  | models/privesc_protocol.py           |
+-------------------+----------------------+  +-------------------+------------------+
                    |                                             |
                    +----------------------+----------------------+
                                           |
                                           v
+------------------------------------------------------------------------------------+
| Grounding & Evidence Validation (core/parser.py)                                   |
| - Fabrication & overclaim filtering                                                |
| - Machine-logged command + output proof ([EVIDENCE LOG])                           |
+------------------------------------------+-----------------------------------------+
                                           |
                                           v
                      +--------------------+---------------------+
                      | Verified Final Assessment & Report       |
                      +------------------------------------------+
```

---

## Tool Arsenal

LONLY exposes **24 domain-modularized tools** organized under `tools/`:

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

## Evaluation & Acceptance Harness

The repository includes an offline evaluation framework (`eval/eval_lonly.py`) with **67 acceptance checks**:

- **Track D (D1–D20)**: Guardrail policy verification, scope boundary enforcement, risk accounting, findings injection, and evidence gates.
- **Track P (P1–P9)**: 4B-model ReAct parser resilience, markdown fence stripping, trailing comma tolerance, placeholder rejection, and overclaim validation.
- **Track M (M1–M3)**: Modular architecture contracts, unique 24-tool registry integrity, and `run_argv` capability delegation.
- **Track C (C1–C4)**: Trajectory loop quality, duplicate invocation detection, and maximum output character truncation compliance.
- **Track A (A1–A3)**: Scenario integration suite simulating web reconnaissance, privilege escalation specialist routing, and full 5-phase lifecycle chains.
- **Track E (E1–E5)**: CLI interactive engine and edge-case unit tests (command parsing, denial/approval gates, risk checkpoint stop/redirect, fabrication intercept, and Unicode/Thai handling).
- **Track R (R1–R22)**: Adversarial red team security suite:
  - **R1**: Shell metacharacter injection resilience (`shell=False`)
  - **R2**: `TargetPolicy` IPv6, bracketed IPv6, and CIDR scope enforcement
  - **R3**: URL parser confusion & credential userinfo injection resistance
  - **R4**: `ExecutionBroker` below-agent authorization boundary
  - **R5**: Specialist SSH backend broker isolation & scope refusal
  - **R6**: `SecretVault` storage & opaque token generation
  - **R7**: `CapabilityPolicy` descriptor contracts
  - **R8**: Session log automatic secret redaction
  - **R9**: Content-addressable SHA-256 evidence graph
  - **R10**: Evidence graph DAG chain verification
  - **R11**: Provenance fencing indirect injection defense (`<untrusted_observation>`)
  - **R12**: Fenced observation parser resilience
  - **R13**: `ClaimVerifier` supported claim confirmation
  - **R14**: `ClaimVerifier` hallucinated claim interception
  - **R15**: Tamper-evident engagement report generation with SHA-256 proofs
  - **R16**: Corrupted evidence node tamper detection
  - **R17**: Static analysis invariant: zero `shell=True` / `os.system` / `os.popen`, `subprocess` isolated strictly to broker
  - **R18**: `CapabilityPolicy` manifest authorization gates and permanent blocking
  - **R19**: `ResolvedTarget` socket destination validation & DNS rebinding defense
  - **R20**: `SecretVault` per-capability scoping, rotation, revocation, and zeroization
  - **R21**: Forensic provenance trail correlation across full contextual IDs
  - **R22**: Cryptographic audit ledger (`core/audit.py`) HMAC hash chaining & tamper detection
- **Track B (B0)**: Subprocess-isolated smoke testing validating all 24 tools with zero side effects.

Run the test suite:
```bash
python eval/eval_lonly.py
```

---

## Local Models & Fine-Tuning Flywheel

LONLY operates on a dual-model production stack served via Ollama:
- `gemma3:4b` — Generalist ReAct Orchestrator.
- `privesc-llm-rl:4b` — Privilege Escalation Specialist.

### Local Fine-Tuning Pipeline (`models/sft/`)
To fine-tune models on engagement traces:
1. **Prepare Data**: `python models/sft/prepare_data.py` (formats transcripts to Qwen3 chat template).
2. **Train QLoRA**: `python models/sft/train_lonly_sft.py --data ~/.cache/lonly_sft/data_full.jsonl --out ~/models/lonly-sft-run`
3. **Merge & Quantize**: `bash models/sft/serve_sft.sh ~/models/lonly-sft-run/adapter lonly-sft:4b`

---

## Installation & Setup

### Prerequisites
- Linux (Debian, Ubuntu, or Kali Linux recommended)
- Python 3.10+
- [Ollama](https://ollama.ai/) installed and running

### 1. Clone Repository
```bash
git clone https://github.com/poppp334/Lonly_HARNESS.git
cd Lonly_HARNESS
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Pull Required Models
```bash
ollama pull gemma3:4b
```

## Evaluation & Adversarial Hardening Suite

LONLY v2 enforces zero technical debt and 100% deterministic safety verified by **80 acceptance checks** across 8 tracks:

- **Track D (1–20)**: Safety, Scope, Confirmation, State & Phase Invariants
- **Track P (1–9)**: ReAct, Markdown Fence, Evidence & Overclaim Interception
- **Track M (1–3)**: Tool Arsenal Registry, Schema & Isolation Contracts
- **Track C (1–4)**: Trajectory Quality, Duplication & Truncation Bounds
- **Track A (1–3)**: Scenario Replays (Web Recon, Privesc Specialist, 5-Phase Chain)
- **Track E (1–5)**: Live CLI Resilience, Unicode & Human-in-the-Loop Approval
- **Track R (1–35)**: Comprehensive Red Team Adversarial & Cryptographic Suite:
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
  - `R25`: OS sandbox profiles and process tree termination (`SandboxManager`)
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
- **Track B (B0)**: Per-tool subprocess smoke validation across all 24 tools

```bash
# Run complete verification harness
LONLY_EVAL_PYTHON=~/pentest_env/bin/python ~/pentest_env/bin/python eval/eval_lonly.py
```

---

## Project Structure

```
Lonly_HARNESS/
├── pentest_agent.py          # Main interactive CLI & ReAct agent loop
├── core/                     # Core runtime & deterministic security boundary
│   ├── agent_roles.py        # Planner, Specialist, and Verifier model boundaries
│   ├── audit.py              # Cryptographic HMAC-SHA256 WAL audit ledger
│   ├── benchmarks.py         # Ground-truth lab benchmark evaluation engine
│   ├── broker.py             # ExecutionBroker & CapabilityPolicy enforcement
│   ├── engagement.py         # Organization, Engagement, Run, and Approval entities
│   ├── evidence.py           # Content-addressable DAG evidence graph & TypedClaims
│   ├── extractor.py          # Structured fact extractor for prompt context hygiene
│   ├── fuzz.py               # Property-based adversarial fuzzer
│   ├── guardrails.py         # Scope control, confirmation gates, risk budgeting
│   ├── metrics.py            # Operational metrics & zero-defect SLA engine
│   ├── orchestrator.py       # DAG task graph orchestrator
│   ├── parser.py             # Resilient ReAct/JSON parsing & overclaim validators
│   ├── policy.py             # TargetPolicy, CapabilityPolicy, ResolvedTarget
│   ├── queue.py              # Transactional job queue & circuit breaker
│   ├── risk.py               # Multi-dimensional risk matrix & decision gates
│   ├── sandbox.py            # OS sandbox profiles & process containment
│   ├── state.py              # FindingsLog, TaskTree, phase routing table
│   ├── telemetry.py          # Distributed tracing & provenance query engine
│   └── vault.py              # Hardened SecretVault with scoping & rotation
├── tools/                    # Modular 24-tool subsystem (run_argv brokered)
│   ├── __init__.py           # Central tool registry and tool_map
│   ├── base.py               # Safe execution wrapper and output truncation
│   ├── recon.py              # Nmap, RustScan, Masscan, WhatWeb, Enum4linux, LDAP
│   ├── web.py                # Gobuster, Ffuf, Nikto, Sqlmap, WPScan, Curl
│   ├── creds.py              # CrackMapExec, Hydra, Metasploit, ReverseShell
│   └── infra.py              # LinPEAS, SearchSploit, Impacket, BloodHound, RAG
├── models/                   # Specialist integration & training
│   ├── privesc_protocol.py   # Specialist protocol & Ollama dispatch
│   └── smoke_test.py         # Specialist verification smoke test
├── eval/                     # Test & Evaluation Harness
│   ├── ci_security_gate.py   # Automated CI/CD security gate & invariant checker
│   ├── eval_lonly.py         # Main acceptance runner (80/80 checks)
│   ├── track_a_runner.py     # Scenario integration suite
│   ├── track_b_worker.py     # Subprocess-isolated tool smoke worker
│   ├── track_c_scorer.py     # Trajectory and loop quality scorer
│   └── track_r_redteam.py    # 35-check adversarial red team suite
├── docs/                     # Technical specifications & roadmap
│   ├── Plan-implement.md     # Production hardening roadmap
│   └── cybersecurity-harness-research.md
├── requirements.txt          # Python runtime dependencies
└── README.md
```

---

## License

Distributed under the MIT License. See `LICENSE` for details.
