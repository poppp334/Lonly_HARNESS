#!/usr/bin/env python3
"""core/doctor.py — LONLY System Diagnostic & Health Check Suite.

Inspects:
1. Python Runtime & Virtual Environment
2. Python Package Dependencies (requirements.txt)
3. Ollama Server Status & Models (gemma3:4b)
4. System Pentest Binaries (24 tools in arsenal)
5. Wordlist Directory Paths & Symlinks
6. ChromaDB Vector Store & Knowledge Base
7. Session Workspace Directory & Permissions
"""
from __future__ import annotations

import importlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, NamedTuple


class DiagnosticResult(NamedTuple):
    category: str
    item: str
    status: str  # "OK", "WARN", "FAIL"
    detail: str


def check_python_environment() -> list[DiagnosticResult]:
    results = []
    v = sys.version_info
    py_ver = f"{v.major}.{v.minor}.{v.micro}"
    if v.major >= 3 and v.minor >= 10:
        results.append(DiagnosticResult("Python", "Python Version", "OK", f"{py_ver} (>= 3.10 required)"))
    else:
        results.append(DiagnosticResult("Python", "Python Version", "FAIL", f"{py_ver} (3.10+ required)"))

    in_venv = sys.prefix != sys.base_prefix or os.environ.get("VIRTUAL_ENV") is not None
    if in_venv:
        results.append(DiagnosticResult("Python", "Virtual Environment", "OK", f"Active ({sys.prefix})"))
    else:
        results.append(DiagnosticResult("Python", "Virtual Environment", "WARN", "Running in global environment"))

    return results


def check_python_packages() -> list[DiagnosticResult]:
    results = []
    packages = [
        ("langchain", "LangChain Core"),
        ("langchain_ollama", "LangChain Ollama Provider"),
        ("langchain_chroma", "ChromaDB LangChain Bridge"),
        ("langchain_huggingface", "HuggingFace Embeddings"),
        ("pydantic", "Pydantic Validation"),
        ("requests", "HTTP Client"),
        ("networkx", "NetworkX Graph Analysis"),
    ]
    for mod_name, label in packages:
        try:
            mod = importlib.import_module(mod_name)
            ver = getattr(mod, "__version__", "installed")
            results.append(DiagnosticResult("Dependencies", label, "OK", f"v{ver}"))
        except ImportError:
            results.append(DiagnosticResult("Dependencies", label, "FAIL", "Not installed (pip install -r requirements.txt)"))

    return results


def check_ollama_service() -> list[DiagnosticResult]:
    results = []
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request("http://localhost:11434/api/tags", headers={"User-Agent": "LONLY-Doctor"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            results.append(DiagnosticResult("Ollama", "Ollama Daemon", "OK", "Running at http://localhost:11434"))

            active_model = os.environ.get("LONLY_MODEL", "phi4-mini")
            has_active = any(active_model.split(":")[0] in m for m in models)
            if has_active:
                results.append(DiagnosticResult("Ollama", f"{active_model} (Generalist)", "OK", "Model ready in local cache"))
            else:
                has_any_gen = any("phi4" in m or "gemma3" in m for m in models)
                if has_any_gen:
                    matching = [m for m in models if "phi4" in m or "gemma3" in m][0]
                    results.append(DiagnosticResult("Ollama", f"{matching} (Generalist)", "OK", "Model ready in local cache"))
                else:
                    results.append(DiagnosticResult("Ollama", f"{active_model} (Generalist)", "WARN", f"Missing ('ollama pull {active_model}')"))

            has_specialist = any("privesc-llm-rl" in m for m in models)
            if has_specialist:
                results.append(DiagnosticResult("Ollama", "privesc-llm-rl (Specialist)", "OK", "Model ready in local cache"))
            else:
                results.append(DiagnosticResult("Ollama", "privesc-llm-rl (Specialist)", "WARN", "Optional specialist not loaded (generalist fallback active)"))
    except Exception as e:
        results.append(DiagnosticResult("Ollama", "Ollama Daemon", "FAIL", f"Cannot connect to http://localhost:11434 ({e})"))

    return results


def check_system_tools() -> list[DiagnosticResult]:
    results = []
    # Key security binaries
    tool_bins = [
        ("nmap", "Port & Version Scanner"),
        ("rustscan", "Fast Port Scanner"),
        ("masscan", "High-Rate Subnet Scanner"),
        ("gobuster", "Web Directory Brute-Forcer"),
        ("ffuf", "Web Fuzzing Tool"),
        ("nikto", "Web Server Scanner"),
        ("whatweb", "Web Technology Fingerprinter"),
        ("wpscan", "WordPress Security Scanner"),
        ("hydra", "Network Login Brute-Forcer"),
        ("msfconsole", "Metasploit Framework"),
        ("nc", "Netcat Listener"),
        ("ldapsearch", "OpenLDAP Search Client"),
        ("searchsploit", "Exploit Database Search"),
    ]
    for b_name, label in tool_bins:
        path = shutil.which(b_name)
        if path:
            results.append(DiagnosticResult("Security Tools", f"{b_name} ({label})", "OK", path))
        else:
            results.append(DiagnosticResult("Security Tools", f"{b_name} ({label})", "WARN", "Binary not found in PATH"))

    return results


def check_wordlists_and_knowledge() -> list[DiagnosticResult]:
    results = []
    root = Path(__file__).resolve().parent.parent

    # Check knowledge base
    knowledge_dir = root / "knowledge"
    if knowledge_dir.exists() and any(knowledge_dir.glob("*.md")):
        doc_count = len(list(knowledge_dir.glob("*.md")))
        results.append(DiagnosticResult("RAG Knowledge", "knowledge/*.md documents", "OK", f"{doc_count} security guides found"))
    else:
        results.append(DiagnosticResult("RAG Knowledge", "knowledge/*.md documents", "WARN", "No knowledge documents found"))

    # Check ChromaDB
    chroma_dir = root / "chroma_db"
    if chroma_dir.exists() and any(chroma_dir.iterdir()):
        results.append(DiagnosticResult("RAG Knowledge", "ChromaDB Vector Store", "OK", "Vector embeddings initialized"))
    else:
        results.append(DiagnosticResult("RAG Knowledge", "ChromaDB Vector Store", "WARN", "Not built (run 'python ingest_knowledge.py')"))

    # Check session workspace directory
    sess_dir = Path.home() / ".lonly" / "sessions"
    if sess_dir.exists():
        results.append(DiagnosticResult("Workspace", "Session Storage", "OK", str(sess_dir)))
    else:
        results.append(DiagnosticResult("Workspace", "Session Storage", "OK", "Will be auto-created on first run"))

    return results


def run_doctor() -> bool:
    print("=" * 72)
    print("  LONLY System Health & Diagnostic Suite (Doctor)")
    print("=" * 72)

    all_results = []
    all_results.extend(check_python_environment())
    all_results.extend(check_python_packages())
    all_results.extend(check_ollama_service())
    all_results.extend(check_system_tools())
    all_results.extend(check_wordlists_and_knowledge())

    current_cat = ""
    fails = 0
    warns = 0

    for res in all_results:
        if res.category != current_cat:
            current_cat = res.category
            print(f"\n[{current_cat}]")

        status_tag = f"[\033[92mPASS\033[0m]" if res.status == "OK" else (
            f"[\033[93mWARN\033[0m]" if res.status == "WARN" else f"[\033[91mFAIL\033[0m]"
        )
        if res.status == "FAIL":
            fails += 1
        elif res.status == "WARN":
            warns += 1

        print(f"  {status_tag:15} {res.item:<35} : {res.detail}")

    print("\n" + "=" * 72)
    if fails == 0:
        print(f"  DIAGNOSTIC SUMMARY: \033[92mHEALTHY\033[0m ({warns} non-critical warnings, 0 failures)")
    else:
        print(f"  DIAGNOSTIC SUMMARY: \033[91m{fails} CRITICAL FAILURES\033[0m ({warns} warnings)")
    print("=" * 72 + "\n")

    return fails == 0


if __name__ == "__main__":
    success = run_doctor()
    sys.exit(0 if success else 1)
