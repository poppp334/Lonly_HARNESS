#!/usr/bin/env python3
"""Generic manual LoRA merge: W' = W + (B @ A) * (alpha / r).

Deterministic and version-proof (no peft load path — the paper's adapters and
Unsloth's adapters use different key namespaces and peft's ensure_weight_tying
loader silently no-ops across versions). Normalizes both key formats:
  - Unsloth:          model.layers.N... / lm_head...
  - peft 0.18:        base_model.model.model.layers.N... / base_model.model.lm_head...
Both are stripped to raw model paths (Qwen3ForCausalLM: 'model.layers.N', 'lm_head').

Handles the tied-embedding base by loading untied and cloning embed->lm_head
before applying deltas (peft's documented procedure), then VERIFIES the merge
is not a no-op (fails loudly instead of shipping a base model).

Usage:
  python merge_adapter.py ADAPTER_DIR BASE_DIR OUT_DIR
"""
from __future__ import annotations

import json
import os
import sys

import torch
from safetensors.torch import load_file
from transformers import AutoModelForCausalLM, AutoTokenizer


def main() -> int:
    adapter_dir, base_dir, out_dir = sys.argv[1:4]
    cfg = json.load(open(os.path.join(adapter_dir, "adapter_config.json")))
    r = int(cfg.get("r", cfg.get("lora_r", 8)))
    alpha = float(cfg.get("lora_alpha", cfg.get("alpha", 32)))
    scale = alpha / r
    print(f"LoRA rank={r} alpha={alpha} scale={scale}")

    state = load_file(os.path.join(adapter_dir, "adapter_model.safetensors"))
    a_keys = sorted(k[: -len(".lora_A.weight")] for k in state if k.endswith(".lora_A.weight"))
    b_keys = sorted(k[: -len(".lora_B.weight")] for k in state if k.endswith(".lora_B.weight"))
    assert a_keys == b_keys, "lora_A/lora_B key mismatch"
    print(f"applying {len(a_keys)} LoRA deltas")

    model = AutoModelForCausalLM.from_pretrained(
        base_dir, torch_dtype=torch.bfloat16, low_cpu_mem_usage=True,
        tie_word_embeddings=False,
    )
    model.lm_head.weight.data = model.model.embed_tokens.weight.data.clone()

    applied = 0
    max_delta = 0.0
    for base_key in a_keys:
        a = state[base_key + ".lora_A.weight"].to(torch.float32)
        b = state[base_key + ".lora_B.weight"].to(torch.float32)
        delta = (b @ a) * scale
        max_delta = max(max_delta, delta.abs().max().item())
        path = base_key
        if path.startswith("base_model.model."):
            path = path[len("base_model.model."):]
        module = model.get_submodule(path)
        module.weight.data = (module.weight.data.to(torch.float32) + delta).to(module.weight.dtype)
        applied += 1

    assert applied == len(a_keys)
    assert max_delta > 0.0, "all deltas are zero - adapter is empty or merge broken!"
    lm_pairs = [k for k in a_keys if k.endswith("lm_head")]
    lm_zero = all(state[k + ".lora_B.weight"].abs().max().item() == 0 for k in lm_pairs)
    if not lm_zero:
        assert not torch.equal(model.lm_head.weight, model.model.embed_tokens.weight), \
            "lm_head delta missing!"
    print(f"applied {applied} deltas; max|delta|={max_delta:.6f}"
          + ("; lm_head delta zero (artifact property, kept tied)" if lm_zero else "; lm_head merged"))

    os.makedirs(out_dir, exist_ok=True)
    model.save_pretrained(out_dir)
    AutoTokenizer.from_pretrained(base_dir).save_pretrained(out_dir)
    print(f"done -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
