# LONLY Pentest Agent — Repo Guide

## Change logging
Every time you (the agent) make a code or doc change in this repo — whether a bug fix, refactor, or feature — append an entry to `UPDATE.md` at the repo root. Create `UPDATE.md` if it doesn't exist. Each entry must include: date, what changed, which files were touched, and why. Append, never overwrite previous entries. Do this for every change in every session, without being asked.

## Entrypoints & architecture
- **`python pentest_agent.py`** — single-file app: ReAct agent loop + 24 pentest tool wrappers + interactive CLI. All in one file (~650 lines).
- **`ingest_knowledge.py`** — populate ChromaDB from `knowledge/*.md` (run before first `rag_query` usage).
- **`pact.py`** — personal LangChain practice file (typos like `JSONDecdoeError`, `extarct_final_awnser`). Irrelevant to the agent.
- No tests anywhere; no CI, formatter, linter, or typecheck config exists.

## Setup
- Activate venv before running: `source ~/pentest_env/bin/activate`
- Then `python pentest_agent.py`

## LLM config
- Default model: `gemma4:e4b` at `pentest_agent.py:422`. Change there or in `ChatOllama` init.
- Must have Ollama running locally with chosen model pulled.

## RAG knowledge base
- Source markdown: `knowledge/` directory (kerberoasting.md, linux-privesc.md).
- Build vector store: `python ingest_knowledge.py`.
- Persisted in `chroma_db/`. Delete that dir and re-run ingestion to rebuild.

## Safety controls (enforced in code)
Dangerous tools are blocked by the loop at `pentest_agent.py:527-532` without user permission:
- `sqlmap_vulnerability_assessment`
- `nikto_web_scan`
- `enum4linux_smb_audit`

## Agent loop quirks
- Sliding window: last 20 messages kept (`pentest_agent.py:490-491`, line 640).
- Forced summarization every 3 tool calls (`pentest_agent.py:517-521`).
- Response parsing: regex-based `parse_react_response` and `extract_final_answer`.
- Tool output truncated at 4000 chars; LinPEAS at 5000.

## Dependencies
```bash
pip install -r requirements.txt
```
Requires Kali Linux with system tools: nmap, rustscan, masscan, nikto, sqlmap, gobuster, ffuf, whatweb, wpscan, enum4linux, crackmapexec, hydra, ldap-utils, metasploit-framework, netcat, peass/linpeas.


