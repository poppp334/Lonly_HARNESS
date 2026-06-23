# 🤖 LONLY — Logically Optimized Network Logistics & Intelligence

> **An autonomous AI-powered penetration testing agent for Kali Linux, powered by a local LLM via Ollama.**

```
.-.   .----..-..-..-.   .-..-.
| |__ | || || .` || |__  >  / 
`----'`----'`-'`-'`----' `-'  
```

---

## ⚠️ Legal Disclaimer

> **This tool is intended for authorized security testing and educational purposes ONLY.**
> Using LONLY against systems you do not own or have explicit written permission to test is illegal and unethical.
> The author assumes no liability for misuse of this software.

---

## 📖 Overview

LONLY is an interactive, autonomous penetration testing AI agent that runs entirely on your local machine. It uses a **ReAct (Reasoning + Acting)** loop powered by a locally-hosted LLM via [Ollama](https://ollama.ai/) to intelligently plan and execute multi-phase security assessments — from reconnaissance through exploitation.

It wraps industry-standard Kali Linux tools into a unified AI-driven interface, intelligently deciding which tool to use, in what order, based on your natural-language objective.

---

## ✨ Key Features

- 🧠 **Autonomous ReAct Agent Loop** — The LLM reasons, selects a tool, observes the output, then decides the next step, with human-in-the-loop checkpoints for risk and safety
- 🛡️ **Safety Controls** — Two-tier gate: dangerous tools (SQLMap, Nikto, enum4linux) are blocked without permission; confirm-required tools (crackmapexec, hydra, metasploit) prompt y/n before execution
- 🗣️ **Natural Language Interface** — Give objectives in plain English or Thai; the agent handles the technical execution
- 📚 **RAG Knowledge Base** — Augments the LLM with a local ChromaDB vector store of penetration testing cheat sheets and documentation
- 🩸 **BloodHound Analysis** — Parses SharpHound collection ZIPs locally using NetworkX to find attack paths to Domain Admins
- 🔍 **Live CVE Lookup** — Queries the NVD API in real time and cross-references results with the local Exploit-DB via SearchSploit
- 🪟 **Sliding Window Memory** — Maintains a rolling chat history (last 20 messages) to preserve context without overflowing the LLM context window
- 🔄 **Risk-Budget Checkpoint** — Tool calls accumulate risk points; when the budget (5 pts) is exceeded, the operator reviews progress and decides to continue, stop, or redirect the task
- ⚖️ **Cross-Task Carryover** — Fabrication/overclaim/placeholder events decay across tasks (full previous task, half two tasks ago, expired after three), preventing degraded LLM behavior from silently compounding
- 🚨 **Fabrication Detection** — Scans Final Answer for tool names never actually invoked, with suggestion-context exemption to reduce false positives
- 📊 **Overclaim Detection** — Checks if the answer claims positive findings from a tool whose raw output contained none (currently registered for metasploit_auxiliary_scanner)
- 📝 **Placeholder Answer Detection** — Catches when the LLM copies format examples instead of writing real content, with one automatic retry
- 🔁 **Duplicate Call Prevention** — Blocks re-execution of identical (tool, args) pairs within a session
- 🪵 **Session Logging** — Every tool call and Final Answer is logged to `session_log.jsonl` with full raw output for auditability
- 💥 **Tool Failure Detection** — Shell errors, timeouts, and command-not-found results are flagged as failures so the LLM cannot mistake them for real findings

---

## 🛠️ Tool Arsenal

LONLY integrates **24 tools** covering the full penetration testing lifecycle:

### 🔍 Reconnaissance & Port Scanning
| Tool | Function |
|---|---|
| `rustscan_port_scan` | Ultra-fast full-port scan (1–65535) via RustScan |
| `masscan_port_scan` | High-speed asynchronous scanning for large CIDR ranges |
| `nmap_security_scan` | Detailed service/version/OS detection |

### 🌐 Web Application Assessment
| Tool | Function |
|---|---|
| `whatweb_web_fingerprint` | Identify web technologies and frameworks |
| `gobuster_directory_scan` | Brute-force directories and files |
| `ffuf_web_fuzz` | Advanced web fuzzing (requires `FUZZ` keyword in URL) |
| `nikto_web_scan` | ⚠️ Comprehensive web server vulnerability scan (requires permission) |
| `sqlmap_vulnerability_assessment` | ⚠️ Automated SQL injection detection and exploitation (requires permission) |
| `wpscan_wordpress_audit` | WordPress plugin, theme, and user enumeration |
| `curl_web_request` | Custom HTTP request crafting |

### 🏢 Active Directory & Network Services
| Tool | Function |
|---|---|
| `enum4linux_smb_audit` | ⚠️ SMB/Samba enumeration (requires permission) |
| `crackmapexec` | SMB/SSH/WinRM/MSSQL authentication testing and command execution |
| `ldap_search_enumeration` | Anonymous/simple-bind LDAP queries against Active Directory |
| `kerbrute_active_directory_assessment` | Kerberos user enumeration and password spraying |

### 💥 Exploitation & Post-Exploitation
| Tool | Function |
|---|---|
| `hydra_brute_force` | Network login brute-force across multiple protocols |
| `searchsploit_exploit_lookup` | Search local Exploit-DB archive |
| `metasploit_auxiliary_scanner` | Execute Metasploit auxiliary modules |
| `impacket_tool_execute` | Windows/AD assessment via Impacket suite (secretsdump, etc.) |
| `reverse_shell_listener` | Set up a Netcat listener for incoming reverse shells |
| `linpeas_privilege_escalation_scan` | Local privilege escalation enumeration via LinPEAS |

### 🧪 Intelligence & Analysis
| Tool | Function |
|---|---|
| `cve_lookup` | Real-time CVE details from NVD API + Exploit-DB cross-reference |
| `bloodhound_analyze` | Local BloodHound/SharpHound ZIP analysis using NetworkX graph |
| `rag_query` | Query internal ChromaDB knowledge base for pentest techniques |
| `shell_exec` | Execute arbitrary shell commands on the host |

---

## ⚙️ Architecture

```
User Input (Natural Language)
        │
        ▼
┌────────────────────────────────────┐
│  Messages: SysPrompt + History +   │
│            HumanMessage            │
└──────────────┬─────────────────────┘
               │
               ▼
┌──────────────────────┐
│    Ollama LLM        │
│    (gemma4)          │
└──────┬───────────────┘
       │  Thought → Action → Action Input
       ▼
┌──────────────────────┐
│  parse_react_response│
└──────┬───────────────┘
       │
       ▼
┌──────────────────────────────────────────────┐
│  Safety Controls                             │
│  • Dangerous tools → blocked (needs OK)      │
│  • Confirm tools → y/n prompt                │
│  • Duplicate calls → blocked                 │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Tool Execution (24 Tools)                   │
│  Nmap / RustScan / SQLMap / Hydra / ...     │
└──────────────────┬───────────────────────────┘
                   │ Observation + risk score
                   ▼
┌──────────────────────────────────────────────┐
│  Risk Checkpoint (≥5 → pause for c/s/r)     │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
            ┌───────────┐
            │ More      │ yes ────► back to LLM
            │ steps?    │
            └─────┬─────┘
                  │ no
                  ▼
┌──────────────────────────────────────────────┐
│  Final Answer Post-Processing                │
│  • Placeholder detection & retry             │
│  • Fabrication detection (unused tools)      │
│  • Overclaim detection (no real findings)    │
└──────────────────┬───────────────────────────┘
                   │
                   ▼
            Final Answer to User
```

---

## 📋 Requirements

### System
- Kali Linux (recommended) or any Debian-based distro with pentest tools installed
- Python 3.10+
- [Ollama](https://ollama.ai/) with `gemma4:e4b` model (or another capable model)

### Python Dependencies
```bash
pip install langchain langchain-core langchain-community langchain-ollama
pip install ollama chromadb sentence-transformers
pip install networkx pydantic requests
pip install huggingface-hub
```

### Kali Linux Tools (must be installed and in PATH)
```
nmap, rustscan, masscan, nikto, sqlmap, gobuster, ffuf,
whatweb, wpscan, enum4linux, crackmapexec, hydra, kerbrute,
ldap-utils, metasploit-framework, impacket-scripts,
searchsploit, netcat, linpeas (peass-ng)
```

Install common tools:
```bash
sudo apt update && sudo apt install -y nmap rustscan masscan nikto sqlmap \
  gobuster ffuf whatweb wpscan enum4linux crackmapexec hydra kerbrute \
  ldap-utils metasploit-framework impacket-scripts netcat-traditional
```
Note: `searchsploit` comes with the `exploitdb` package (`sudo apt install exploitdb`);
`linpeas` comes with `peass-ng` (`sudo apt install peass-ng`).

---

## 🚀 Installation & Setup

1. **Clone the repository**
```bash
git clone https://github.com/poppp334/Lonly_HARNESS.git
cd lonly-pentest-agent
```

2. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

3. **Pull the LLM model via Ollama**
```bash
ollama pull gemma4:e4b
```

4. **(Optional) Set up the RAG knowledge base**
```bash
# Place your pentest cheat sheets / markdown files in the knowledge/ folder
# Then run the ingestion script to populate ChromaDB
python ingest_knowledge.py
```

5. **Run LONLY**
```bash
python pentest_agent.py
```

---

## 💻 Usage

After launching, you'll be greeted by the LONLY banner and an interactive prompt:

```
>>> Scan 192.168.1.50 and find all open web ports
```

LONLY will autonomously:
1. Run RustScan for initial port discovery
2. Run Nmap for service/version detection on discovered ports
3. Run WhatWeb for web technology fingerprinting
4. Present a summary, then ask your permission before running intrusive/confirm-required tools

### Example Commands
```
>>> Perform a full reconnaissance on 10.10.10.100
>>> Check if 192.168.1.1 has any known CVEs
>>> Enumerate users on the Active Directory domain corp.local at 10.0.0.5
>>> Analyze my BloodHound data at /tmp/bloodhound.zip
```

### Interactive Commands
| Command | Description |
|---------|---|
| `exit` / `quit` | Shut down LONLY |
| `clear` | Wipe conversation memory and start fresh |
| `help` | Show usage tips |

### Checkpoint Prompts
When the risk budget is reached, LONLY pauses and shows a detailed breakdown:
```
=== Task 2 — Checkpoint (risk 5/5) ===
  Carryover: 3 pts [task 1: fabrication = 3 full]
  In-task:   2 pts [1 regular + 1 confirm required tool]
  In-task tools: nmap_security_scan, rustscan_port_scan
  Total:     5 >= 5 — paused for operator review.
[c]ontinue / [s]top task / [r]edirect:
```
- `c` — continue the current task (risk resets)
- `s` — stop the task and return to the main prompt
- `r` — redirect to a new objective (counts as a new task for carryover decay)

---

## 🔧 Configuration

### LLM Model
Edit `llm = ChatOllama(...)` at line 526 of `pentest_agent.py`:
```python
llm = ChatOllama(model="gemma4:e4b", temperature=0.2, num_ctx=8192)
```
Replace `"gemma4:e4b"` with any model available in your Ollama installation (e.g., `llama3`, `mistral`, `qwen2.5`). More capable models will produce better reasoning.

### Risk-Budget Checkpoint
The checkpoint system is tuned via named constants in `pentest_agent.py`:
- `RISK_CHECKPOINT_THRESHOLD = 5` — risk score that triggers operator review
- `RISK_POINTS` dict — per-event values: `regular_tool=1`, `confirm_required_tool=2`, `dangerous_tool_blocked=1`, `fabrication/overclaim/placeholder=3`

### Safety Controls
Intrusive tools (`sqlmap`, `nikto`, `enum4linux`) are blocked by default at line ~920 without operator permission. Tools requiring explicit confirmation (`crackmapexec`, `hydra`, `metasploit_auxiliary_scanner`) prompt `[y/n]` before execution.

---

## 🏗️ Project Structure

```
lonly-pentest-agent/
├── pentest_agent.py      # Main agent — ReAct loop, 24 tools, risk-budget checkpoint, CLI
├── ingest_knowledge.py   # ChromaDB ingestion from knowledge/*.md
├── knowledge/            # RAG source markdown (kerberoasting, linux-privesc, etc.)
├── chroma_db/            # ChromaDB vector store (auto-created by ingest_knowledge.py)
├── AGENTS.md             # Agent configuration guide for opencode / AI assistants
├── UPDATE.md             # Changelog tracking all modifications
├── requirements.txt      # Python dependencies
├── .gitignore            # Ignores __pycache__, chroma_db/, session_log.jsonl
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Ideas for improvement:
- Add more tools (e.g., `nuclei`, `feroxbuster`, `evil-winrm`)
- Build a proper document ingestion pipeline for the RAG knowledge base
- Add session logging / report generation
- Web UI frontend
- Multi-target campaign management

Please open an issue or pull request.

---

*Built for security professionals. Use responsibly.*
