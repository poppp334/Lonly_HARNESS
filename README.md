# LONLY — Logically Optimized Network Logistics & Intelligence

An enterprise-grade, policy-governed autonomous penetration testing and vulnerability assessment harness for Linux and network environments. LONLY enforces the core invariant:

> **"The LLM proposes. Deterministic code authorizes. The broker executes. Evidence proves."**

---

## Legal & Compliance Disclaimer

This software is designed exclusively for authorized penetration testing, vulnerability assessment, and defensive security research.

Unauthorized access to computer systems, networks, or digital infrastructure is illegal under applicable cybercrime legislation (e.g., the Computer Fraud and Abuse Act in the US, Section 33 of the Thai Cybercrime Act, and equivalent international frameworks). Operators must obtain explicit, written authorization from asset owners before directing this software against any target. The developers and contributors accept no liability for damages resulting from improper or unauthorized use.

---

## Table of Contents
1. [Legal & Compliance Disclaimer](#legal--compliance-disclaimer)
2. [Key Capabilities & Innovations](#key-capabilities--innovations)
3. [Architecture & Workflow](#architecture--workflow)
   - [End-to-End Execution Lifecycle](#end-to-end-execution-lifecycle)
   - [Multi-Model Role Separation](#multi-model-role-separation)
   - [Deterministic Security Boundaries](#deterministic-security-boundaries)
4. [Tool Arsenal (24 Brokered Tools)](#tool-arsenal-24-brokered-tools)
5. [Interactive CLI & Shell Interface](#interactive-cli--shell-interface)
6. [Forensic Evidence & Cryptographic Audit](#forensic-evidence--cryptographic-audit)
7. [Adversarial Hardening & Acceptance Suite (84/84 Checks)](#adversarial-hardening--acceptance-suite-8484-checks)
8. [Installation & Setup](#installation--setup)
9. [CLI Command Reference & Workflow Examples](#cli-command-reference--workflow-examples)
10. [Project Structure](#project-structure)
11. [License](#license)

---

## Key Capabilities & Innovations

- **Dual-Mode Autonomous Runtime**:
  - **Mode 1 (Conversational / Advisory)**: Directly answers cybersecurity inquiries, explains vulnerabilities, and discusses tactical plans without executing unwanted tools or triggering hallucinations.
  - **Mode 2 (Tactical ReAct Assessment)**: Engages a structured multi-turn loop to investigate authorized target IP addresses, FQDNs, and CIDR subnets using local offensive tooling.
- **Action Execution Precedence & Resilient Parsing**:
  - LLM tool actions always take precedence over simulated completions.
  - Multi-format parser seamlessly handles both standard ReAct (`Action:\nAction Input: {...}`) and single-line inline syntax (`Action: tool_name {...}`).
  - Dynamic type coercion and parameter normalization across all 24 tools prevent Pydantic validation failures.
- **Zero Shell Subprocess Invariant (`shell=False`)**:
  - Eliminates all shell metacharacter injection vectors (`;`, `&&`, `||`, `` ` ``, `$()`) via discrete `argv` execution and AST-level static verification.
- **Content-Addressable SHA-256 DAG Evidence Graph**:
  - Every finding reported in engagement summaries is cryptographically anchored to exact raw tool stdout hashes and execution provenance.
- **Provenance Fencing Against Indirect Prompt Injection**:
  - Raw tool outputs from scanned targets are strictly encapsulated within `<untrusted_observation>` XML provenance tags, preventing adversarial payload hijacking of LLM reasoning.
- **HMAC-SHA256 Write-Ahead Audit Ledger (WAL)**:
  - Cryptographically chained event log with offline mathematical integrity verification.
- **Human-in-the-Loop Risk Budget & Confirmation Gates**:
  - Intrusive tools (e.g., `hydra`, `metasploit`, `sqlmap`, `nikto`) require explicit operator authorization before execution.
  - Risk points accumulate per task; exceeding risk budget triggers mandatory interactive review checkpoints.

---

## Architecture & Workflow

### End-to-End Execution Lifecycle

```mermaid
flowchart TD
    User([Operator Input / CLI]) --> Router{Dual-Mode Router}
    
    Router -- "Conversational / Q&A" --> LLM_Chat["Generalist LLM (phi4-mini)\nMode 1 Natural Markdown"]
    LLM_Chat --> Response([Operator Response])
    
    Router -- "Target Assessment Request" --> ReActLoop["Mode 2: Multi-Turn ReAct Loop"]
    
    subgraph ReAct_Iteration ["ReAct Iteration Step"]
        ReActLoop --> LLM_Gen["LLM Plan & Tactical Action\n(Thought + Action)"]
        LLM_Gen --> Parser["Resilient Parser\n(Multi-line & Inline JSON)"]
        
        Parser --> ActionCheck{Action Proposed?}
        ActionCheck -- "No Action (Final Answer)" --> ClaimGate["ClaimVerifier & Evidence Gate\nVerify against Evidence DAG"]
        ClaimGate --> Response
        
        ActionCheck -- "Action Emitted" --> ScopePolicy{"TargetPolicy Check\n(Authorized Scope Allowlist)"}
        ScopePolicy -- "Out of Scope" --> PromptScope["Prompt Operator for Scope Approval"]
        PromptScope -- "Approved" --> ManifestCheck
        PromptScope -- "Denied" --> PolicyReject["[SCOPE BLOCKED] Observation"]
        PolicyReject --> ReActLoop
        
        ScopePolicy -- "In Scope" --> ManifestCheck{"CapabilityPolicy Check\n& Confirmation Gates"}
        ManifestCheck -- "Dangerous / Intrusive" --> OperatorConfirm{"Interactive Operator\nConfirmation [y/N]"}
        OperatorConfirm -- "Denied" --> ConfirmReject["[CONFIRMATION DENIED] Observation"]
        ConfirmReject --> ReActLoop
        
        ManifestCheck -- "Authorized" --> Broker["ExecutionBroker\n(run_argv, shell=False)"]
        OperatorConfirm -- "Approved" --> Broker
        
        Broker --> Sandbox["POSIX Sandbox Containment\n(Memory/CPU/PID Limits, Timeout)"]
        Sandbox --> Binary["Native Security Binary Execution\n(nmap, rustscan, gobuster, etc.)"]
        Binary --> Redactor["SecretVault.redact()\nSanitize Credentials & Tokens"]
        
        Redactor --> EvidenceGraph["EvidenceGraph.add_artifact()\n(SHA-256 Content-Addressed Node)"]
        EvidenceGraph --> Ledger["HMAC-SHA256 WAL Audit Ledger"]
        Ledger --> ProvenanceFence["Provenance Fencing\n<untrusted_observation>"]
        ProvenanceFence --> ReActLoop
    end
```

### Multi-Model Role Separation

LONLY enforces strict model boundaries defined in `core/agent_roles.py`:

| Role | Default Model / Backend | Responsibility | Authority Boundary |
| :--- | :--- | :--- | :--- |
| **Generalist Planner** | `phi4-mini` (configurable via `LONLY_MODEL`) | Formulates reconnaissance strategy, interprets observations, coordinates tool sequence. | Proposes tool calls; holds **zero** direct OS or socket execution authority. |
| **Privilege Escalation Specialist** | `privesc-llm-rl:4b` | Generates deep Linux privilege escalation hypotheses from LinPEAS / SUID artifacts. | Domain-restricted hypothesis generation; dispatched exclusively via broker. |
| **Verifier Role** | Deterministic Python Runtime (`core/evidence.py`) | Evaluates reported claims (`TypedClaim`) against the cryptographically stored evidence DAG. | Authoritative gatekeeper for all final answers and report generation. |
| **Semantic Intelligence** | `all-MiniLM-L6-v2` + `ChromaDB` | Fast local semantic search over curated offensive and defensive technical playbooks (`knowledge/`). | Read-only vector database retrieval. |

### Deterministic Security Boundaries

1. **Policy Enforcement Point (PEP) (`core/broker.py`)**:
   - Tools cannot be executed directly by the LLM. Every command is brokered through `ExecutionBroker.execute()`.
   - Targets are resolved through `ResolvedTarget` (`core/policy.py`) to prevent DNS rebinding attacks and enforce CIDR/IPv6 scope allowlists.
2. **Capability Manifests (`CapabilityPolicy`)**:
   - Every tool has an authoritative security manifest defining its `ActionClass` (Read, Probe, Mutate, Exploit), `RiskClass` (Low, Medium, High, Critical), and network requirements.
3. **Secret Vault Boundary (`core/vault.py`)**:
   - Ingested credentials are exchanged for opaque handles (`cred_<hex>`). Real secrets are injected only at execution time in isolated environment variables and zeroized in memory immediately following process termination.

---

## Tool Arsenal (24 Brokered Tools)

All 24 tools in `tools/` use discrete argument arrays (`argv`), strict timeout limits, and resilient parameter schemas:

| Category | Tool Identifier | Backing Binary | Primary Function | Authorization / Risk Level |
| :--- | :--- | :--- | :--- | :--- |
| **Reconnaissance** | `rustscan_port_scan` | `rustscan` | Fast TCP port discovery across 1–65535 | Low Risk (Standard Scope) |
| | `nmap_security_scan` | `nmap` | Service version detection, OS identification, NSE scripts | Low Risk (Standard Scope) |
| | `masscan_port_scan` | `masscan` | Asynchronous high-rate CIDR subnet scanning | Medium Risk (Scope Bound) |
| | `whatweb_web_fingerprint` | `whatweb` | Web server, CMS, and technology fingerprinting | Low Risk (Standard Scope) |
| | `enum4linux_smb_audit` | `enum4linux` | Windows/Samba SMB user and share enumeration | Medium Risk (Dangerous Gate) |
| | `ldap_search_enumeration` | `ldapsearch` | Active Directory and OpenLDAP query enumeration | Low Risk (Standard Scope) |
| | `kerbrute_active_directory_assessment` | `kerbrute` | Active Directory username enumeration and spraying | Medium Risk (Scope Bound) |
| **Web Assessment** | `gobuster_directory_scan` | `gobuster` | Directory and file path brute-forcing | Low Risk (Standard Scope) |
| | `ffuf_web_fuzz` | `ffuf` | High-speed HTTP parameter and endpoint fuzzing | Low Risk (Standard Scope) |
| | `nikto_web_scan` | `nikto` | Comprehensive web server vulnerability scan | High Risk (Dangerous Gate) |
| | `sqlmap_vulnerability_assessment` | `sqlmap` | Automated SQL injection detection and testing | High Risk (Dangerous Gate) |
| | `wpscan_wordpress_audit` | `wpscan` | WordPress plugin, theme, and user security audit | Low Risk (Standard Scope) |
| | `curl_web_request` | `curl` | Raw HTTP request crafting and response inspection | Low Risk (Standard Scope) |
| **Credentials & Lateral** | `crackmapexec` | `crackmapexec` / `nxc` | Protocol authentication testing (SMB, WinRM, SSH, MSSQL) | High Risk (Confirm-Required) |
| | `hydra_brute_force` | `hydra` | Multi-protocol network login brute-forcing | High Risk (Confirm-Required) |
| | `metasploit_auxiliary_scanner` | `msfconsole` | Execution of Metasploit auxiliary scanner modules | High Risk (Confirm-Required) |
| | `reverse_shell_listener` | `nc` | Local Netcat listener for reverse connection capture | Medium Risk (Local Bound) |
| **Infra & Intelligence** | `searchsploit_exploit_lookup` | `searchsploit` | Offline Exploit-DB vulnerability search | Low Risk (Offline) |
| | `linpeas_privilege_escalation_scan` | `linpeas.sh` | Automated Linux local privilege escalation assessment | Low Risk (Local Subprocess) |
| | `impacket_tool_execute` | `impacket-*` | Windows protocol assessment (secretsdump, etc.) | High Risk (Confirm-Required) |
| | `cve_lookup` | Python / NVD API | NVD CVE metadata query and local exploit cross-check | Low Risk (Offline/Online) |
| | `bloodhound_analyze` | NetworkX | Local directed-graph analysis of SharpHound data | Low Risk (Offline) |
| | `rag_query` | ChromaDB | Semantic retrieval over internal pentest playbooks | Low Risk (Offline) |
| | `shell_exec` | Subprocess Broker | Policy-monitored host command execution | Medium Risk (Confirm-Required) |

---

## Interactive CLI & Shell Interface

The LONLY command interface provides an operator-centric terminal experience:

```
  ██╗      ██████╗ ███╗   ██╗██╗  ██╗   ██╗
  ██║     ██╔═══██╗████╗  ██║██║  ╚██╗ ██╔╝
  ██║     ██║   ██║██╔██╗ ██║██║   ╚████╔╝ 
  ██║     ██║   ██║██║╚██╗██║██║    ╚██╔╝  
  ███████╗╚██████╔╝██║ ╚████║███████╗██║   
  ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝   

╭──────────────────────────────────────────────────────────────────────────╮
│ LONLY v2.1 -- Autonomous Penetration Testing Harness                     │
│ Policy-Governed Security * Subprocess Isolation * Audit Ledger           │
├──────────────────────────────────────────────────────────────────────────┤
│ Planner:    phi4-mini                          Specialist: privesc-llm-rl│
│ Scope:      127.0.0.1 (loopback only)          Tools:      24 Brokered   │
│ Session:    a1b2c3d4e5f6 (Default Session)                               │
╰──────────────────────────────────────────────────────────────────────────╯
  Type an objective (e.g. 'Scan 127.0.0.1') or /help for commands.

╭─ lonly [Default Session • target: 127.0.0.1]
╰─> 
```

### Key Interactive Features
- **Prompt Anchoring & Decoupled History**: Clean multi-line prompt rendering with ANSI styling. Command history persists in `~/.lonly/history` (1,000 commands) with arrow-key navigation (`↑`/`↓`) and in-line cursor movement (`←`/`→`).
- **Tab Autocompletion**: Auto-completes slash commands (`/scope`, `/session`, `/report`, `/doctor`, `/clear`), targets, and session IDs.
- **Conversational Target Extraction**: Automatically extracts RFC-compliant domains, hostnames, and IP addresses directly from user phrasing (e.g., `"can you do recon on https://webme-mu.vercel.app"` $\rightarrow$ auto-extracts `webme-mu.vercel.app`).
- **Real-Time Planning Indicators**: Clean visual status feedback (`[*] LONLY is analyzing and planning...`) during local LLM generation.
- **Session-Bound Scope Synchronization**: Target scope allowlists are isolated per session workspace (`~/.lonly/sessions/<session_id>/`) and automatically restored when switching sessions.

---

## Forensic Evidence & Cryptographic Audit

1. **Content-Addressable Evidence DAG (`core/evidence.py`)**:
   - Every tool output is hashed with SHA-256 into an `EvidenceArtifact`.
   - Security findings reference specific artifact hashes, establishing an unforgeable chain of custody from discovered open ports to final engagement reports.
2. **Cryptographic Write-Ahead Log Ledger (`core/audit.py`)**:
   - Every action, confirmation, policy decision, and tool execution is recorded in an HMAC-SHA256 write-ahead log (`audit.wal`).
   - Tampering with any log entry invalidates downstream hash pointers, detectable via offline mathematical audit (`verify_integrity()`).
3. **Signed Pentest Reports (`/report`)**:
   - Generates production-ready Markdown engagement summaries with machine-logged evidence blocks and cryptographic signature verification stamps.

---

## Adversarial Hardening & Acceptance Suite (84/84 Checks)

LONLY maintains an automated acceptance test suite verifying **84 production invariants**:

```bash
make test
```

### Test Tracks Summary
- **Track D (D1–D20)**: Safety, scope allowlists, confirmation gates, risk budgeting, and phase state machine.
- **Track P (P1–P9)**: ReAct parsing, markdown code fences, trailing commas, evidence gates, and overclaim interception.
- **Track M (M1–M3)**: 24-tool registry integrity, unique tool naming, and base wrapper contracts.
- **Track C (C1–C4)**: Trajectory quality, duplicate call suppression, and output truncation bounds.
- **Track A (A1–A3)**: Scenario integration (Web Reconnaissance, PrivEsc Specialist Integration, Full 5-Phase Assessment).
- **Track E (E1–E5)**: CLI findings summarization, confirmation denial flows, risk checkpoints, fabrication interception, and Thai Unicode resilience.
- **Track R (R1–R39)**: Adversarial Red Team Suite (Shell metacharacter injection, IPv6 scope bypass, URL spoofing, SecretVault token zeroization, Evidence DAG tamper detection, Static AST `shell=False` invariant, `CapabilityPolicy` manifests, `ResolvedTarget` rebinding defense, HMAC-SHA256 audit ledger, `ClaimVerifier` typed claims, OS sandbox profiles, DAG orchestrator, multi-dimensional risk matrix, property fuzzing, and telemetry distributed tracing).
- **Track B (B0)**: Per-tool subprocess smoke validation across all 24 security tools.

---

## Installation & Setup

### Prerequisites
- **Operating System**: Linux (Debian, Ubuntu, or Kali Linux recommended)
- **Python**: 3.10 or higher
- **Ollama**: Installed and active (`ollama serve`)

### Quick Setup

```bash
# 1. Clone the repository
git clone https://github.com/poppp334/Lonly_HARNESS.git
cd Lonly_HARNESS

# 2. Automated Bootstrap (virtualenv, dependencies, Ollama models, ChromaDB index)
./setup.sh
# OR via Makefile:
make setup

# 3. System Diagnostic & Health Verification
make doctor

# 4. Run Complete 84-Check Acceptance Suite
make test

# 5. Launch the Interactive LONLY Shell
make run
```

---

## CLI Command Reference & Workflow Examples

### Slash Commands

| Command | Usage | Description |
| :--- | :--- | :--- |
| `/scope add <target>` | `/scope add 10.0.0.5` | Adds an IP, multi-level FQDN, or CIDR to the authorized assessment scope. |
| `/scope list` | `/scope list` | Displays all authorized targets and CIDR subnets in the active session. |
| `/scope reset` | `/scope reset` | Resets the scope allowlist to loopback only (`127.0.0.1`, `::1`). |
| `/session list` | `/session list` | Lists all saved session workspaces with message counts and timestamps. |
| `/session new [title]`| `/session new "Internal Audit"` | Creates a new isolated session workspace with fresh scope and findings. |
| `/session load <id>`  | `/session load a1b2c3d4e5f6` | Restores an existing session workspace and its associated scope state. |
| `/report` | `/report` | Compiles a signed Markdown engagement report with SHA-256 evidence proofs. |
| `/doctor` | `/doctor` | Runs system diagnostics, tool binary detection, and Ollama model checks. |
| `/clear` | `/clear` | Clears active conversation memory and in-memory findings for the current session. |
| `exit` / `quit` | `exit` | Gracefully closes the session and exits LONLY. |

### Example 1: Conversational Q&A (Mode 1)
```text
╭─ lonly [Default Session • target: 127.0.0.1]
╰─> What are the primary attack vectors against Active Directory Kerberos?

=== LONLY ===
The primary attack vectors against Active Directory Kerberos include:
- Kerberoasting: Requesting TGS tickets for SPNs and cracking them offline.
- AS-REP Roasting: Requesting AS-REP responses for accounts without Kerberos pre-authentication.
- Golden / Silver Tickets: Forging TGTs using the KRBTGT hash or service tickets using service account keys.
- Delegation Abuse: Exploiting unconstrained, constrained, or resource-based constrained delegation.
```

### Example 2: Tactical Web Reconnaissance (Mode 2)
```text
╭─ lonly [Default Session • target: 127.0.0.1]
╰─> /scope add 10.0.0.5
[+] Scope added: 10.0.0.5

╭─ lonly [Default Session • target: 10.0.0.5]
╰─> Perform initial port discovery and fingerprint web services on 10.0.0.5

[*] LONLY is analyzing and planning...
[+] LONLY กำลังรัน Tool: nmap_security_scan -> {'target': '10.0.0.5', 'ports': '80,443,22', 'scan_type': 'Version', 'timing': 'T4'}
[=] ผลลัพธ์กลับมาแล้ว (ความยาว: 412 ตัวอักษร)

[*] LONLY is analyzing and planning...
[+] LONLY กำลังรัน Tool: whatweb_web_fingerprint -> {'target_url': 'http://10.0.0.5'}
[=] ผลลัพธ์กลับมาแล้ว (ความยาว: 198 ตัวอักษร)

=== LONLY ===
Reconnaissance on 10.0.0.5 completed:
- Port 22/tcp: Open (OpenSSH 8.9p1 Ubuntu)
- Port 80/tcp: Open (Apache 2.4.52)
- Port 443/tcp: Open (HTTPS / Apache)
- Web Fingerprint: Apache 2.4.52, PHP 8.1, WordPress 6.2 detected on port 80/443.

[EVIDENCE LOG]
- Tool: nmap_security_scan | Output Hash: a3f8... | Target: 10.0.0.5
- Tool: whatweb_web_fingerprint | Output Hash: b7c1... | Target: 10.0.0.5
```

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
