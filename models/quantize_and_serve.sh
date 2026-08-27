#!/usr/bin/env bash
# Phase 0 - PrivEsc-LLM 4B: convert merged HF model -> GGUF -> Q4_K_M -> Ollama.
# Usage: ./quantize_and_serve.sh [rl|sft]
set -euo pipefail

ML_ENV="${ML_ENV:-$HOME/ml_env}"
LLAMA_CPP="${LLAMA_CPP:-$HOME/llama.cpp}"
MODELS_DIR="${MODELS_DIR:-$HOME/models}"
VARIANT="${1:-rl}"

SRC="$MODELS_DIR/privesc-llm-4b-${VARIANT}-merged"
[ -d "$SRC" ] || { echo "merged model missing: $SRC (run merge_adapters.sh first)"; exit 1; }

GGUF_F16="$MODELS_DIR/privesc-llm-4b-${VARIANT}-f16.gguf"
GGUF_Q4="$MODELS_DIR/privesc-llm-4b-${VARIANT}-Q4_K_M.gguf"

# 1) HF -> F16 GGUF (embeds the Qwen3 chat template automatically)
if [ ! -f "$GGUF_F16" ]; then
  echo "=== convert_hf_to_gguf -> $GGUF_F16 ==="
  "$ML_ENV/bin/python" "$LLAMA_CPP/convert_hf_to_gguf.py" "$SRC" \
    --outfile "$GGUF_F16" --outtype f16
fi

# 2) F16 -> Q4_K_M (llama-quantize may live at repo root or build/bin)
QUANTIZE_BIN="$LLAMA_CPP/llama-quantize"
[ -x "$QUANTIZE_BIN" ] || QUANTIZE_BIN="$LLAMA_CPP/build/bin/llama-quantize"
[ -x "$QUANTIZE_BIN" ] || { echo "llama-quantize not found (build: cmake -B build && cmake --build build --target llama-quantize)"; exit 1; }
if [ ! -f "$GGUF_Q4" ]; then
  echo "=== quantize -> $GGUF_Q4 ==="
  "$QUANTIZE_BIN" "$GGUF_F16" "$GGUF_Q4" Q4_K_M
fi

ls -lh "$GGUF_F16" "$GGUF_Q4"

# 3) Ollama model (system prompt is injected per-target by the client; see Modelfile)
NAME="${PRIVESC_OLLAMA_NAME:-privesc-llm:4b}"
NAME="${NAME/:4b/}"
FULL_NAME="${NAME}-${VARIANT}:4b"
echo "=== ollama create $FULL_NAME ==="
MODELFILE="$(mktemp)"
sed "s|__GGUF__|$GGUF_Q4|" "$(dirname "$0")/Modelfile.template" > "$MODELFILE"
ollama create "$FULL_NAME" -f "$MODELFILE"
rm -f "$MODELFILE"
echo "=== done: ollama run $FULL_NAME ==="
