#!/usr/bin/env python3
"""models/sft/prepare_data.py — assemble the paper SFT dataset for local training.

Downloads the training traces (sailab-vienna/privesc-llm-data), renders each
conversation to text with the EXACT Qwen3 chat template + tool block the paper
used (tokenizer.apply_chat_template(tools=...)), and writes a JSONL of
{"text": ...} ready for Unsloth SFTTrainer.

Usage:
  python prepare_data.py [--max-traces 2000] [--max-tokens 16384] [--out /tmp/sft_data.jsonl]
"""
from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys

HUB = "https://huggingface.co/datasets/sailab-vienna/privesc-llm-data"
TOOL_JSONS = [
    '{"name": "exec_command", "description": "Run a shell command as the current user. Use for info gathering or exploits. Returns output and got_root.", "parameters": {"properties": {"command": {"description": "The Bash command to execute.", "type": "string"}}, "required": ["command"], "type": "object"}}',
    '{"name": "test_credentials", "description": "Try logging in with a username and password. Call when you find credentials. Returns success and got_root.", "parameters": {"properties": {"user": {"description": "The username to try.", "type": "string"}, "password": {"description": "The password to try.", "type": "string"}}, "required": ["user", "password"], "type": "object"}}',
]
TOOLS = [{"type": "function", "function": json.loads(t)} for t in TOOL_JSONS]

GENERATORS = [
    "capabilities_gtfobins", "cron_wildcard", "cron_writable_script",
    "password_file", "password_history", "password_reuse", "plots",
    "ssh_key_reuse", "sudo_gtfobins", "suid_gtfobins", "weak_password",
]


def fetch_jsonl_lines(generator: str, split: str = "training") -> list[str]:
    url = f"{HUB}/resolve/main/paper_sft_dataset/{split}/{generator}/traces.jsonl?download=true"
    proc = subprocess.run(["curl", "-sL", "--retry", "3", url],
                          capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    return [line for line in proc.stdout.splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-traces", type=int, default=2000)
    ap.add_argument("--max-tokens", type=int, default=16384,
                    help="truncate rendered samples longer than this (paper: 32768)")
    ap.add_argument("--out", default=os.path.expanduser("~/.cache/lonly_sft/data.jsonl"))
    args = ap.parse_args()

    sys.path.insert(0, os.path.expanduser("~/models/qwen3-4b-instruct-2507"))
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(os.path.expanduser("~/models/qwen3-4b-instruct-2507"))

    written = 0
    dropped = 0
    total_seen = 0
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    out = open(args.out, "w", encoding="utf-8")
    for gen in GENERATORS:
        lines = fetch_jsonl_lines(gen)
        print(f"{gen}: {len(lines)} traces")
        for line in lines:
            total_seen += 1
            if written >= args.max_traces:
                break
            try:
                record = json.loads(line)
                messages = record["messages"]
                # normalize tool_call arguments (paper's normalize_chat_template_messages)
                for msg in messages:
                    for tc in msg.get("tool_calls") or []:
                        if isinstance(tc.get("arguments"), str):
                            try:
                                tc["arguments"] = json.loads(tc["arguments"])
                            except json.JSONDecodeError:
                                pass
                text = tok.apply_chat_template(
                    messages, tokenize=False, tools=TOOLS, add_generation_prompt=False,
                )
                n_tok = len(tok.encode(text))
                if n_tok > args.max_tokens:
                    dropped += 1
                    continue
                out.write(json.dumps({"text": text}, ensure_ascii=False) + "\n")
                written += 1
            except Exception as e:  # noqa: BLE001 — one bad trace must not kill the batch
                dropped += 1
                continue
        if written >= args.max_traces:
            break
    out.close()
    print(f"wrote {written} samples, dropped {dropped} (of {total_seen} seen) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
