#!/usr/bin/env bash
# Phase 0 - PrivEsc-LLM 4B: merge the paper's released LoRA adapters into Qwen3-4B.
# Thin wrapper over models/sft/merge_adapter.py (the generic, verified manual merge).
# Usage: ./merge_adapters.sh [rl|sft|all]
set -euo pipefail

ML_ENV="${ML_ENV:-$HOME/ml_env}"
BASE_DIR="${BASE_DIR:-$HOME/models/qwen3-4b-instruct-2507}"
ADAPTERS_DIR="${ADAPTERS_DIR:-$HOME/models/adapters}"
OUT_DIR="${OUT_DIR:-$HOME/models}"
PY="$ML_ENV/bin/python"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -x "$PY" ] || { echo "ml_env not found at $ML_ENV (torch CPU + transformers)"; exit 1; }

merge_one() {
  local variant="$1"   # rl_adapter | sft_adapter
  local out="$OUT_DIR/privesc-llm-4b-${variant%_adapter}-merged"
  echo "=== merging $variant -> $out ==="
  [ -d "$out" ] && { echo "exists, skipping"; return 0; }
  "$PY" "$HERE/sft/merge_adapter.py" "$ADAPTERS_DIR/$variant" "$BASE_DIR" "$out"
}

case "${1:-all}" in
  rl)  merge_one rl_adapter ;;
  sft) merge_one sft_adapter ;;
  all) merge_one rl_adapter; merge_one sft_adapter ;;
  *) echo "usage: $0 [rl|sft|all]"; exit 1 ;;
esac
