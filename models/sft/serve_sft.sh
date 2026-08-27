#!/usr/bin/env bash
# Flywheel serve: merge a locally-trained SFT adapter -> GGUF Q4_K_M -> Ollama.
# Usage: ./serve_sft.sh [ADAPTER_DIR] [OLLAMA_NAME]
set -euo pipefail

ML_ENV="${ML_ENV:-$HOME/ml_env}"
LLAMA_CPP="${LLAMA_CPP:-$HOME/llama.cpp}"
BASE_DIR="${BASE_DIR:-$HOME/models/qwen3-4b-instruct-2507}"
MODELS_DIR="${MODELS_DIR:-$HOME/models}"
ADAPTER_DIR="${1:-$HOME/models/lonly-sft-e1/adapter}"
NAME="${2:-lonly-sft:4b}"
HERE="$(cd "$(dirname "$0")" && pwd)"

STAMP="$(basename "$(dirname "$ADAPTER_DIR")")"
MERGED="$MODELS_DIR/lonly-sft-${STAMP}-merged"
GGUF_F16="$MODELS_DIR/lonly-sft-${STAMP}-f16.gguf"
GGUF_Q4="$MODELS_DIR/lonly-sft-${STAMP}-Q4_K_M.gguf"

[ -d "$ADAPTER_DIR" ] || { echo "adapter dir not found: $ADAPTER_DIR"; exit 1; }

if [ ! -d "$MERGED" ]; then
  "$ML_ENV/bin/python" "$HERE/merge_adapter.py" "$ADAPTER_DIR" "$BASE_DIR" "$MERGED"
fi
if [ ! -f "$GGUF_F16" ]; then
  "$ML_ENV/bin/python" "$LLAMA_CPP/convert_hf_to_gguf.py" "$MERGED" --outfile "$GGUF_F16" --outtype f16
fi
QUANTIZE_BIN="$LLAMA_CPP/llama-quantize"
[ -x "$QUANTIZE_BIN" ] || QUANTIZE_BIN="$LLAMA_CPP/build/bin/llama-quantize"
if [ ! -f "$GGUF_Q4" ]; then
  "$QUANTIZE_BIN" "$GGUF_F16" "$GGUF_Q4" Q4_K_M
fi

MODELFILE="$(mktemp)"
printf 'FROM %s\nPARAMETER temperature 0.7\nPARAMETER top_p 0.8\nPARAMETER top_k 20\nPARAMETER num_ctx 8192\nPARAMETER num_predict 2048\n' "$GGUF_Q4" > "$MODELFILE"
ollama create "$NAME" -f "$MODELFILE"
rm -f "$MODELFILE"
echo "=== served: $NAME (from $ADAPTER_DIR) ==="
