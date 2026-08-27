# LONLY Pentest Agent — Developer & Agent Guide

This document provides architectural guidance, subsystem organization, and conventions for AI pair programmers and subagents working in the LONLY repository.

---

## 1. System Architecture

LONLY is an autonomous penetration testing agent operating in a two-tier hybrid architecture:

* **Generalist Orchestrator (`gemma3:4b`)**: Handles natural language objectives, initial port discovery, web exploitation, Active Directory inspection, and report generation via an interactive ReAct loop in `pentest_agent.py`.
* **PrivEsc Specialist (`privesc-llm-rl:4b`)**: A specialized 4B model (trained via SFT + RLVR on Linux environments) invoked automatically when the `TaskTree` enters the `privesc` phase.
* **Core Subsystem (`core/`)**:
  * `core/guardrails.py`: Deny-by-default scope allowlists (`ALLOWED_TARGETS`), execution gates (`DANGEROUS_TOOLS`, `CONFIRM_REQUIRED_TOOLS`), and 5-point cumulative risk budget.
  * `core/state.py`: Structured `FindingsLog` and `TaskTree` phase routing table (`DEFAULT_PHASES = ("recon", "enumerate", "vuln_check", "privesc", "report")`).
  * `core/parser.py`: Multi-pass resilient JSON and ReAct parser with code-fence stripping, trailing comma tolerance, fabrication and overclaim detection.
* **Modular Tool Arsenal (`tools/`)**: 24 domain-modularized tool wrappers in `recon.py`, `web.py`, `creds.py`, `infra.py`, and `base.py`.

---

## 2. Directory Layout

```
Lonly_HARNESS/
├── pentest_agent.py          # Main CLI entrypoint & ReAct orchestrator loop
├── core/                     # Core runtime state, parsing, and guardrail policies
│   ├── guardrails.py         # Scope enforcement, confirm gates, risk budget
│   ├── parser.py             # 4B ReAct and JSON extraction
│   └── state.py              # FindingsLog, TaskTree, phase routing
├── tools/                    # 24 modular pentesting tools
│   ├── __init__.py           # Tool registry and tool_map
│   ├── base.py               # run_cmd wrapper, target cleaning, wordlist fallbacks
│   ├── recon.py              # RustScan, Nmap, Masscan, WhatWeb, Enum4linux, LDAP
│   ├── web.py                # Gobuster, Ffuf, Nikto, SQLMap, WPScan, Curl
│   ├── creds.py              # CrackMapExec/NetExec, Hydra, Metasploit, ReverseShell
│   └── infra.py              # LinPEAS, SearchSploit, Impacket, BloodHound, RAG, Shell
├── models/                   # Specialist node, protocols, benchmarks, and SFT
│   ├── privesc_protocol.py   # Specialist protocol aligned with arXiv:2603.17673
│   ├── smoke_test.py         # Format adherence verification
│   ├── benchmark_runner.py   # Benchmark evaluation runner
│   ├── analyze_benchmark.py  # Trajectory and benchmark log analyzer
│   └── sft/                  # Local SFT training flywheel (Unsloth QLoRA, GGUF merge)
├── eval/                     # Offline test and evaluation harness
│   ├── eval_lonly.py         # Consolidated 45-check test runner
│   ├── track_a_runner.py     # Scenario integration suite (S1, S2, S4)
│   ├── track_b_worker.py     # Subprocess-isolated tool smoke tests (24/24)
│   ├── track_c_scorer.py     # Trajectory and loop quality scorer
│   └── track_e_cli.py        # CLI interaction and edge-case unit tests
├── knowledge/                # Markdown cheat sheets for ChromaDB RAG
├── ingest_knowledge.py       # ChromaDB vector store ingestion script
├── requirements.txt          # Python dependencies
└── README.md                 # Production documentation
```

---

## 3. Environment & Execution

* **Runtime Python Environment**: `~/pentest_env`
  ```bash
  source ~/pentest_env/bin/activate
  python pentest_agent.py
  ```
* **Offline Acceptance Test Suite**:
  ```bash
  LONLY_EVAL_PYTHON=~/pentest_env/bin/python ~/pentest_env/bin/python eval/eval_lonly.py
  ```
* **Local SFT Training Environment**: `~/sft_env` (Unsloth + PyTorch CUDA)
* **Model Conversion Environment**: `~/ml_env` (Transformers + PEFT)

---

## 4. Engineering & Contribution Rules

1. **Zero Unverified Commits**: Run `eval/eval_lonly.py` before committing. All 45 checks must pass with exit code 0.
2. **Modular Tool Contracts**: Tools must be defined under `tools/` with strict Pydantic `args_schema` and registered in `tools/__init__.py`. Never place raw tool execution code directly in `pentest_agent.py`.
3. **Target Sanitization**: All host and URL parameters must pass through `clean_target()` or `ensure_url()` in `tools/base.py` to prevent formatting failures.
4. **Safety Gating**:
   * Dangerous tools (`sqlmap`, `nikto`, `enum4linux`) are soft-blocked unless explicitly overridden.
   * High-impact tools (`crackmapexec`, `hydra`, `metasploit_auxiliary_scanner`, `shell_exec`) require interactive confirmation `[y/n]`.
   * Out-of-scope targets are rejected by `target_in_scope()` before tool invocation.
5. **Clean Repository**: Do not commit local run logs (`runs/`), cached adapters, GGUF binaries, or temporary `.jsonl` session files. Keep `.gitignore` strictly enforced.
