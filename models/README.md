# models/ — PrivEsc-LLM 4B specialist subsystem

LONLY's privilege-escalation specialist node, built from the open artifacts of
[arXiv:2603.17673](https://arxiv.org/abs/2603.17673) (PrivEsc-LLM, MIT).

The paper post-trains `Qwen3-4B-Instruct-2507` (Apache 2.0) with SFT + RLVR on
verifiable Linux privesc tasks: **93.3% success on the 12-scenario static
benchmark within 20 rounds**, second only to Claude Opus 4.7, ~80x cheaper.
Base `gemma3:4b` remains LONLY's generalist; this model is the privesc-phase
specialist (the "specialist agents" pattern from docs/cybersecurity-harness-research.md).

## Files

| File | Purpose |
|---|---|
| `privesc_protocol.py` | The specialist node: exact paper protocol (system prompt, 2 tools, `<tool_call>`/`<tool_response>`), Ollama HTTP chat (stdlib only), injected tool backend, JSONL trajectory logging (SFT flywheel) |
| `smoke_test.py` | Format-adherence smoke test against a fake backend (no root, no target) |
| `benchmark_runner.py` | Phase 1: ladder eval (base/SFT/RL) on the ipa-lab benchmark Docker scenarios |
| `sft/prepare_data.py` | Assemble the paper's SFT traces → chat-template-rendered JSONL for local training |
| `sft/train_lonly_sft.py` | Local QLoRA SFT (Unsloth, rank 8, sized for a 4 GB GPU) — the Phase 3a flywheel trainer |
| `sft/merge_adapter.py` | Generic verified manual LoRA merge (both adapter key formats; fails loudly on no-op) |
| `sft/serve_sft.sh` | Flywheel serve: merge local adapter → GGUF Q4_K_M → `ollama create` |
| `merge_adapters.sh` | Merge released LoRA adapters (`sailab-vienna/privesc-llm-4b`) into the base model → HF checkpoints in `~/models/` |
| `quantize_and_serve.sh` | HF → F16 GGUF → Q4_K_M GGUF (llama.cpp) → `ollama create` |
| `Modelfile.template` | Ollama Modelfile; system prompt is injected per-target by `privesc_protocol.py` (creds are scenario vars — baking them would be tech debt) |

## The protocol (must match training distribution — do not "improve" casually)

- System prompt: `privilege_escalation.jinja` render (user/password/turn limit/terminal dims) + the paper's exact HF tool-instructions block.
- Tools: `exec_command {command}`, `test_credentials {user, password}` — schemas byte-identical to the repo's `src/gym/tools.py`.
- Tool call: `<tool_call>{"name": ..., "arguments": {...}}</tool_call>` in the assistant message.
- Tool response: `<tool_response>{"got_root": ..., "output": ..., "timed_out": ...}</tool_response>` as a `tool`-role message.
- Success = `got_root: true` only (interactive root shell or root login). Printing `uid=0` does not count.
- Turn budget: 20 by default (the paper's primary metric); eval used a 60-round cap.

## How LONLY uses it

The specialist is a *phase-routed node*: LONLY's task tree (recon → enumerate →
vuln-check → **privesc** → report) invokes `PrivescSpecialist` for the privesc
phase only, with a backend that wraps LONLY's guardrails (scope allowlist,
risk-budget accounting, confirm gates) around `exec_command`/`test_credentials`
against the in-scope target. `gemma3:4b` keeps all other phases.

```python
from models.privesc_protocol import PrivescSpecialist

spec = PrivescSpecialist(
    backend=guarded_backend,        # LONLY guardrail-wrapped tool backend
    model="privesc-llm-rl:4b",
    user="alice", password="alice", # target context
    max_turns=20,
    trajectory_path="logs/privesc_trajectories.jsonl",  # SFT flywheel
)
result = spec.run()   # {"success": bool, "turns": int, "reason": str, ...}
```

## Reproduce from scratch

```bash
# ml_env: python3.12 venv with torch (CPU ok) + transformers + safetensors
models/merge_adapters.sh all          # manual LoRA merge (W += B@A * alpha/r), ~9GB RAM
# llama.cpp: cmake via pip into ml_env (no sudo): ~/ml_env/bin/pip install cmake
#   then: cmake -B build && cmake --build build --target llama-quantize -j4
models/quantize_and_serve.sh rl       # HF -> F16 GGUF -> Q4_K_M -> ollama create
models/quantize_and_serve.sh sft
models/smoke_test.py privesc-llm-rl:4b
```

Notes:
- The merge is a **manual LoRA merge** (not peft): the released adapters use two
  different key formats (rl = Unsloth, sft = peft namespace) and peft's
  `ensure_weight_tying` load path silently no-ops across versions. The script
  normalizes both formats and verifies deltas are non-zero — a no-op merge fails
  loudly instead of shipping a base model.
- The sft adapter's `lm_head.lora_B` is genuinely all-zero (artifact property),
  so its merged lm_head stays the tied clone — expected, not a bug.
- The GGUF conversion reports a Mistral-regex tokenizer warning inherited from
  the base model's `tokenizer_config.json`; tokenization fidelity vs the paper's
  vLLM serving is a Phase 1 verification item.

VRAM: Q4_K_M ≈ 2.6 GB + 8k-context KV cache — fits the 4 GB RTX 3050.
Only one 4B model is resident at a time; Ollama swaps gemma3 ↔ privesc in seconds.

## Scalability (Phase 3 flywheel)

Every `run()` appends a JSONL trajectory (state/action/observation + verifiable
`success`) to `trajectory_path`. Trajectories from real LONLY engagements feed
the SFT dataset; Docker scenario boxes supply machine-checkable rewards. Periodic
local re-training (Unsloth QLoRA, rank 8) compounds the model on our own
experience — see docs/privesc-model-plan.md.

## Flywheel (Phase 3a) — train your own specialist, all local

```bash
# 1. data: paper's 2000 SFT traces -> chat-template-rendered JSONL
python models/sft/prepare_data.py --max-traces 2000 --out ~/.cache/lonly_sft/data.jsonl

# 2. train (sft_env: Unsloth + CUDA; ~5.7 s/step at seq 4096 on the RTX 3050)
python models/sft/train_lonly_sft.py --data ~/.cache/lonly_sft/data.jsonl \
    --out ~/models/lonly-sft-e1 --epochs 1 --seq 8192 --batch 1 --grad-accum 4

# 3. merge + quantize + serve (CPU-safe; can run while Ollama serves the ladder)
models/sft/serve_sft.sh ~/models/lonly-sft-e1/adapter lonly-sft:4b
models/smoke_test.py lonly-sft:4b
```

Then benchmark it: `python models/benchmark_runner.py --models base,rl,sft --runs 10`
swap the model list for your own variant, and — the flywheel proper — append
LONLY's live privesc trajectories (`trajectory_path` JSONL, verifiable `success`
field) to the training JSONL and re-train. Same scripts, no new machinery.

## Phase 1 benchmark (verification ladder)

```bash
# one-time: build the 12 paper scenarios as Docker images
cd reference/benchmark-privesc-linux/docker && ./build.sh

# pilot: 1 scenario, 2 runs, all 3 models (primary metric: success within 20 rounds)
python models/benchmark_runner.py --scenarios 01_vuln_suid_gtfo --runs 2 --models rl,sft,base

# full paper reproduction: 12 scenarios × 10 runs × 3 models (overnight job)
python models/benchmark_runner.py --runs 10
```

Backend = the paper's `local_docker` mode (`docker exec` as `lowpriv`/`trustno1`;
no SSH). The runner restarts the container between runs for state isolation,
logs per-run JSON + per-model summary to `runs/benchmark_<ts>/`, and writes every
trajectory to JSONL (flywheel input). The paper's static set is 12 scenarios
(`04_vuln_sudo_gtfo_interactive` is excluded upstream).
