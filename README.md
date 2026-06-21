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

- 🧠 **Autonomous ReAct Agent Loop** — The LLM reasons, selects a tool, observes the output, then decides the next step, all without manual intervention
- 🛡️ **Safety Controls** — Intrusive tools (SQLMap, Nikto, enum4linux) require explicit user permission before execution
- 🗣️ **Natural Language Interface** — Give objectives in plain English or Thai; the agent handles the technical execution
- 📚 **RAG Knowledge Base** — Augments the LLM with a local ChromaDB vector store of penetration testing cheat sheets and documentation
- 🩸 **BloodHound Analysis** — Parses SharpHound collection ZIPs locally using NetworkX to find attack paths to Domain Admins
- 🔍 **Live CVE Lookup** — Queries the NVD API in real time and cross-references results with the local Exploit-DB via SearchSploit
- 🪟 **Sliding Window Memory** — Maintains a rolling chat history (last 20 messages) to preserve context without overflowing the LLM context window
- 🔄 **Forced Summarization** — Prevents infinite loops by requiring a progress report every 3 tool calls

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
┌─────────────────────┐
│    ReAct Agent Loop │
│   (run_react_agent) │
└────────┬────────────┘
         │
         ▼
  ┌─────────────┐      ┌──────────────────────┐
  │  Ollama LLM │◄────►│   System Prompt +    │
  │  (gemma4)   │      │   Chat History       │
  └──────┬──────┘      └──────────────────────┘
         │  Thought → Action → Action Input
         ▼
  ┌─────────────┐
  │  Tool Map   │ (parse_react_response)
  │  Dispatcher │
  └──────┬──────┘
         │
         ▼
  ┌─────────────────────────────────────────┐
  │  Tool Execution (24 Tools)              │
  │  Nmap / RustScan / SQLMap / Hydra / ... │
  └──────────────────────┬──────────────────┘
                         │ Observation
                         ▼
                  Back to LLM Loop
                  (until Final Answer)
```

---

## 📋 Requirements

### System
- Kali Linux (recommended) or any Debian-based distro with pentest tools installed
- Python 3.10+
- [Ollama](https://ollama.ai/) with `gemma4:e4b` model (or another capable model)

### Python Dependencies
```bash
pip install langchain langchain-community langchain-ollama
pip install chromadb sentence-transformers
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
  gobuster ffuf whatweb wpscan enum4linux crackmapexec hydra \
  ldap-utils metasploit-framework netcat-traditional
```

---

## 🚀 Installation & Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/lonly-pentest-agent.git
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
4. Present a summary and **ask your permission** before running any intrusive scans

### Example Commands
```
>>> Perform a full reconnaissance on 10.10.10.100
>>> Check if 192.168.1.1 has any known CVEs
>>> Enumerate users on the Active Directory domain corp.local at 10.0.0.5
>>> Analyze my BloodHound data at /tmp/bloodhound.zip
```

### Shell Commands
| Command | Description |
|---|---|
| `exit` / `quit` | Shut down LONLY |
| `clear` | Wipe conversation memory and start fresh |
| `help` | Show usage tips |

---

## 🔧 Configuration

To change the LLM model, edit line 422 in `pentest_agent.py`:
```python
llm = ChatOllama(model="gemma4:e4b", temperature=0.2, num_ctx=8192)
```

Replace `"gemma4:e4b"` with any model available in your Ollama installation (e.g., `llama3`, `mistral`, `qwen2.5`). More capable models will produce better reasoning.

---

## 🏗️ Project Structure

```
lonly-pentest-agent/
├── pentest_agent.py      # Main agent — all tools, loop, and CLI
├── chroma_db/            # ChromaDB vector store for RAG (auto-created)
├── requirements.txt      # Python dependencies
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
