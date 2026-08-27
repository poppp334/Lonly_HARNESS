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

The repository includes an offline evaluation framework (`eval/eval_lonly.py`) with **40 acceptance checks**:

- **Track D (D1–D20)**: Guardrail policy verification, scope boundary enforcement, risk accounting, findings injection, and evidence gates.
- **Track P (P1–P9)**: 4B-model ReAct parser resilience, markdown fence stripping, trailing comma tolerance, placeholder rejection, and overclaim validation.
- **Track M (M1–M3)**: Modular architecture contracts, unique 24-tool registry integrity, and subprocess runner delegation.
- **Track C (C1–C4)**: Trajectory loop quality, duplicate invocation detection, and maximum output character truncation compliance.
- **Track A (A1–A3)**: Scenario integration suite simulating web reconnaissance, privilege escalation specialist routing, and full 5-phase lifecycle chains.
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

### 4. Run Acceptance Tests
```bash
python eval/eval_lonly.py
```

### 5. Launch LONLY
```bash
python pentest_agent.py
```

---

## Project Structure

```
Lonly_HARNESS/
├── pentest_agent.py          # Main interactive CLI & ReAct agent loop
├── core/                     # Core runtime subsystems
│   ├── guardrails.py         # Scope control, confirmation gates, risk budgeting
│   ├── parser.py             # Resilient ReAct/JSON parsing & overclaim validators
│   └── state.py              # FindingsLog, TaskTree, phase routing table
├── tools/                    # Modular 24-tool subsystem
│   ├── __init__.py           # Central tool registry and tool_map
│   ├── base.py               # Safe execution wrapper and output truncation
│   ├── recon.py              # Nmap, RustScan, Masscan, WhatWeb, Enum4linux, LDAP
│   ├── web.py                # Gobuster, Ffuf, Nikto, Sqlmap, WPScan, Curl
│   ├── creds.py              # CrackMapExec, Hydra, Metasploit, ReverseShell
│   └── infra.py              # LinPEAS, SearchSploit, Impacket, BloodHound, RAG
├── models/                   # Specialist integration & training
│   ├── privesc_protocol.py   # Specialist protocol & Ollama dispatch
│   ├── smoke_test.py         # Specialist verification smoke test
│   ├── benchmark_runner.py   # Scenario benchmark runner
│   ├── analyze_benchmark.py  # Benchmark log and trajectory analyzer
│   └── sft/                  # Local SFT training & GGUF quantization scripts
├── eval/                     # Test & Evaluation Harness
│   ├── eval_lonly.py         # Main runner (Tracks D, P, M, C, A, B)
│   ├── track_a_runner.py     # Scenario integration suite
│   ├── track_b_worker.py     # Subprocess-isolated tool smoke worker
│   └── track_c_scorer.py     # Trajectory and loop quality scorer
├── docs/                     # Technical specifications & research
│   ├── architecture-upgrade-map.md
│   └── cybersecurity-harness-research.md
├── requirements.txt          # Python runtime dependencies
└── README.md
```

---

## License

Distributed under the MIT License. See `LICENSE` for details.
