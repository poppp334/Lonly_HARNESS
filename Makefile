# ============================================================================
# LONLY — Logically Optimized Network Logistics & Intelligence
# Production Task & Management Automation Makefile
# ============================================================================

.PHONY: help run test doctor ingest setup clean lint sessions

# Detect Python environment: preference to active venv, then ~/pentest_env, then system python3
VENV_DIR ?= $(HOME)/pentest_env
PYTHON := $(shell if [ -f $(VENV_DIR)/bin/python ]; then echo $(VENV_DIR)/bin/python; else which python3; fi)

help:
	@echo "========================================================================"
	@echo "  LONLY v2 — Management & Automation"
	@echo "========================================================================"
	@echo "  make run        : Launch LONLY interactive Dual-Mode CLI shell"
	@echo "  make test       : Run 83-check acceptance & security evaluation suite"
	@echo "  make doctor     : Run comprehensive system health and dependency check"
	@echo "  make ingest     : Build RAG vector knowledge base from knowledge/*.md"
	@echo "  make setup      : Install Python dependencies & pull Ollama model"
	@echo "  make sessions   : List stored conversation sessions"
	@echo "  make clean      : Remove bytecode caches, temporary logs, and locks"
	@echo "========================================================================"

run:
	@$(PYTHON) pentest_agent.py

test:
	@LONLY_EVAL_PYTHON=$(PYTHON) $(PYTHON) eval/eval_lonly.py

doctor:
	@$(PYTHON) core/doctor.py

ingest:
	@$(PYTHON) ingest_knowledge.py

setup:
	@echo "[+] Checking Python environment..."
	@$(PYTHON) -m pip install -r requirements.txt
	@echo "[+] Checking Ollama generalist model..."
	@ollama pull gemma3:4b || true
	@echo "[+] Ingesting RAG knowledge base..."
	@$(PYTHON) ingest_knowledge.py
	@echo "[+] Running LONLY Doctor diagnostic..."
	@$(PYTHON) core/doctor.py
	@echo "[+] Setup complete! Run 'make run' to start."

sessions:
	@$(PYTHON) -c "from core.session import SessionManager; sm = SessionManager(); print('\n=== Stored Sessions ==='); [print(f\"- {s['session_id']}: {s['title']} ({s['message_count']} msgs)\") for s in sm.list_sessions()]"

clean:
	@rm -rf __pycache__ core/__pycache__ tools/__pycache__ eval/__pycache__ models/__pycache__ models/sft/__pycache__
	@rm -rf unsloth_compiled_cache models/sft/unsloth_compiled_cache
	@rm -f session_log.jsonl
	@echo "[+] Cleaned temporary files and bytecode caches."
