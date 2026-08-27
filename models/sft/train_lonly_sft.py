#!/usr/bin/env python3
"""models/sft/train_lonly_sft.py — local QLoRA SFT of Qwen3-4B on privesc traces.

Debt-free, config-driven (argparse), sized for a 4 GB GPU. Follows the paper's
recipe scaled down: LoRA rank 8 / alpha 32, lr 1.5e-4, full-sequence causal LM
on rendered chat transcripts. (Deviation: no lm_head LoRA / weight-tying games —
Unsloth's default Qwen3 targets only; seq length capped by VRAM.)

Usage:
  python train_lonly_sft.py --data ~/.cache/lonly_sft/data.jsonl \
      --out ~/models/lonly-sft-run --max-steps 30 --seq 4096
Outputs: adapter (saved at --out), loss log, and (optionally) a merged HF dir.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import torch
from datasets import load_dataset
from transformers import TrainingArguments
from trl import SFTTrainer
from unsloth import FastLanguageModel, is_bfloat16_supported

BASE_MODEL = os.path.expanduser("~/models/qwen3-4b-instruct-2507")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="JSONL of {'text': ...}")
    ap.add_argument("--out", default=os.path.expanduser("~/models/lonly-sft-run"))
    ap.add_argument("--base", default=BASE_MODEL)
    ap.add_argument("--seq", type=int, default=4096, help="max sequence length (VRAM)")
    ap.add_argument("--max-steps", type=int, default=0, help="0 = train full dataset once")
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--lr", type=float, default=1.5e-4)
    ap.add_argument("--batch", type=int, default=2)
    ap.add_argument("--grad-accum", type=int, default=4)
    ap.add_argument("--merge", action="store_true", help="merge adapter into base at the end")
    ap.add_argument("--max-traces", type=int, default=0, help="cap dataset size (smoke runs)")
    ap.add_argument("--save-steps", type=int, default=50, help="checkpoint every N steps (0 = never)")
    ap.add_argument("--resume", action="store_true", help="resume from checkpoint-* in --out")
    args = ap.parse_args()

    if not torch.cuda.is_available():
        print("[!] CUDA not available in this env — unsloth needs a CUDA torch")
        return 1

    model, tokenizer = FastLanguageModel.from_pretrained(
        args.base,
        max_seq_length=args.seq,
        load_in_4bit=True,
        dtype=None,
    )
    model = FastLanguageModel.get_peft_model(
        model, r=8, lora_alpha=32, lora_dropout=0.0,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth",
    )

    ds = load_dataset("json", data_files=args.data, split="train")
    if args.max_traces:
        ds = ds.select(range(min(args.max_traces, len(ds))))

    def _tokenize(batch: dict) -> dict:
        return tokenizer(batch["text"], truncation=True, max_length=args.seq)

    ds = ds.map(_tokenize, batched=True, remove_columns=ds.column_names)
    print(f"dataset: {len(ds)} samples; VRAM {torch.cuda.get_device_properties(0).total_memory/2**30:.1f} GB")

    trainer = SFTTrainer(
        model=model,
        args=TrainingArguments(
            output_dir=args.out,
            per_device_train_batch_size=args.batch,
            gradient_accumulation_steps=args.grad_accum,
            warmup_steps=10,
            max_steps=args.max_steps or -1,
            num_train_epochs=args.epochs if not args.max_steps else 1,
            learning_rate=args.lr,
            fp16=not is_bfloat16_supported(),
            bf16=is_bfloat16_supported(),
            logging_steps=5,
            save_steps=args.save_steps,
            save_strategy="steps" if args.save_steps else "no",
            save_total_limit=2,
            optim="adamw_8bit",
            seed=2026,
            report_to="none",
        ),
        processing_class=tokenizer,
        train_dataset=ds,
    )
    resume = bool(args.resume) and any(
        os.path.isdir(os.path.join(args.out, d)) and d.startswith("checkpoint-")
        for d in os.listdir(args.out)
    )
    if resume:
        print("[*] resuming from checkpoint")
    trainer.train(resume_from_checkpoint=resume)
    loss_log = trainer.state.log_history
    with open(os.path.join(args.out, "loss_log.json"), "w") as f:
        json.dump(loss_log, f, indent=2)

    model.save_pretrained(os.path.join(args.out, "adapter"))
    tokenizer.save_pretrained(os.path.join(args.out, "adapter"))
    print(f"[+] adapter saved -> {args.out}/adapter")

    if args.merge:
        merged = FastLanguageModel.merge_and_unload(model)
        merged_dir = os.path.join(args.out, "merged")
        merged.save_pretrained(merged_dir)
        tokenizer.save_pretrained(merged_dir)
        print(f"[+] merged model -> {merged_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
