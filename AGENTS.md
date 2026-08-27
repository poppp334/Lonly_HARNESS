# LONLY Pentest Agent — Repo Guide

## Entrypoints & architecture
- **`python pentest_agent.py`** — single-file app: custom ReAct agent loop + 24 pentest tool wrappers + interactive CLI (~1112 lines). Everything lives in this one file.
- **`ingest_knowledge.py`** — populate ChromaDB from `knowledge/*.md` (run before first `rag_query` use).
- No tests, CI, formatter, linter, or typecheck config.

## Setup
- Activate venv before running: `source ~/pentest_env/bin/activate` (author's path — adjust to your own env).
- Then `python pentest_agent.py`.

## LLM config
- Default model `gemma3:4b` at `pentest_agent.py:526`:
  `llm = ChatOllama(model="gemma3:4b", temperature=0.2, num_ctx=8192)`
- Requires Ollama running locally with the chosen model pulled.

## RAG knowledge base
- Source markdown: `knowledge/` (kerberoasting.md, linux-privesc.md).
- Build vector store: `python ingest_knowledge.py` → persists to `chroma_db/`.
- `chroma_db/` is gitignored and regenerable; delete the dir and re-run ingestion to rebuild.

## Safety controls (enforced in the agent loop)
- **Dangerous tools** — soft-blocked (warning appended, tool does NOT run) — list at `pentest_agent.py:920`:
  - `sqlmap_vulnerability_assessment`
  - `nikto_web_scan`
  - `enum4linux_smb_audit`
- **Confirm-required tools** — blocking `[y/n]` prompt before execution — list at `pentest_agent.py:930`:
  - `crackmapexec`
  - `hydra_brute_force`
  - `metasploit_auxiliary_scanner`
- NOTE: `shell_exec` runs arbitrary host commands and is in NEITHER gate list — treat it as effectively unrestricted.

## Agent loop quirks
- Sliding window: chat history trimmed to last 20 messages in the CLI loop (`pentest_agent.py:1103`).
- Risk-budget checkpoint: tool calls accumulate points (`RISK_POINTS`, threshold `RISK_CHECKPOINT_THRESHOLD = 5` at `pentest_agent.py:87-95`); at threshold the loop pauses for `[c]ontinue / [s]top / [r]edirect` (`pentest_agent.py:903`).
- Response parsing is regex-based: `parse_react_response()` and `extract_final_answer()` (`pentest_agent.py:137, 150`).
- Tool output truncated: 4000 chars default (`run_cmd`), linpeas 5000, gobuster/ffuf/shell_exec 3000.
- Fabrication / overclaim / placeholder detection run on Final Answer before it is shown.

## Dependencies
- `pip install -r requirements.txt`
- Requires Kali tools in PATH: nmap, rustscan, masscan, nikto, sqlmap, gobuster, ffuf, whatweb, wpscan, enum4linux, crackmapexec (binary is `nxc`), hydra, ldap-utils, metasploit-framework, netcat, kerbrute, impacket-scripts, searchsploit, linpeas.
