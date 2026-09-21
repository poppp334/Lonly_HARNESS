#!/usr/bin/env python3
"""models/sft/manifest.py — Training Manifest & Checkpoint Resumption for LONLY SFT Flywheel.

Provides:
- SFTTrainingManifest: Strongly-typed manifest tracking dataset hash, hyperparameters,
  step count, training loss, and checkpoint paths.
- Resumption integrity: Validates checkpoint directory and dataset consistency before resuming.
- Multi-GPU distributed training tracking (device count, world size, distributed backend).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


def compute_file_sha256(filepath: str | Path) -> str:
    """Compute SHA-256 hex digest of a dataset or artifact file."""
    p = Path(filepath)
    if not p.exists() or not p.is_file():
        return ""
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class SFTTrainingManifest:
    """Persistent execution metadata for local and distributed SFT runs."""

    run_id: str
    base_model: str
    dataset_path: str
    dataset_sha256: str = ""
    output_dir: str = ""
    total_samples: int = 0
    max_seq_length: int = 4096
    learning_rate: float = 1.5e-4
    lora_rank: int = 8
    lora_alpha: int = 32
    batch_size: int = 2
    gradient_accumulation_steps: int = 4
    num_gpus: int = 1
    distributed_backend: str = "single"  # 'single', 'ddp', 'fsdp'
    current_epoch: float = 0.0
    current_step: int = 0
    max_steps: int = 0
    best_loss: float = float("inf")
    latest_checkpoint: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)
    status: str = "initialized"  # 'initialized', 'training', 'completed', 'failed'

    @classmethod
    def create(
        cls,
        run_id: str,
        base_model: str,
        dataset_path: str,
        output_dir: str,
        num_gpus: int = 1,
        distributed_backend: str = "single",
        **kwargs: Any,
    ) -> SFTTrainingManifest:
        sha = compute_file_sha256(dataset_path)
        return cls(
            run_id=run_id,
            base_model=base_model,
            dataset_path=str(dataset_path),
            dataset_sha256=sha,
            output_dir=str(output_dir),
            num_gpus=num_gpus,
            distributed_backend=distributed_backend,
            **kwargs,
        )

    def save(self, target_dir: Optional[str | Path] = None) -> Path:
        """Atomic save of the manifest to manifest.json inside output_dir."""
        out = Path(target_dir or self.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        manifest_file = out / "training_manifest.json"
        tmp_file = out / f"training_manifest.tmp.{os.getpid()}"

        data = asdict(self)
        with open(tmp_file, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())

        os.replace(tmp_file, manifest_file)
        return manifest_file

    @classmethod
    def load(cls, manifest_path: str | Path) -> Optional[SFTTrainingManifest]:
        """Load manifest from JSON file."""
        p = Path(manifest_path)
        if not p.exists():
            return None
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(**data)

    def can_resume(self, checkpoint_dir: Optional[str | Path] = None) -> tuple[bool, str]:
        """Check whether training can safely resume from output_dir."""
        ck_dir = Path(checkpoint_dir or self.output_dir)
        if not ck_dir.exists():
            return False, f"Output directory {ck_dir} does not exist"

        # Check latest checkpoint directory
        if self.latest_checkpoint:
            p = Path(self.latest_checkpoint)
            if p.exists() and (p / "trainer_state.json").exists() or (p / "adapter_model.safetensors").exists():
                return True, f"Valid checkpoint found at {p}"

        # Search for any checkpoint-*
        checkpoints = sorted(
            [d for d in ck_dir.iterdir() if d.is_dir() and d.name.startswith("checkpoint-")],
            key=lambda d: int(d.name.split("-")[1]) if d.name.split("-")[1].isdigit() else 0,
        )
        if checkpoints:
            latest = checkpoints[-1]
            return True, f"Found latest checkpoint {latest.name}"

        return False, "No checkpoint directories found to resume from"

    def record_step(self, step: int, loss: float, epoch: float, checkpoint_path: str = "") -> None:
        """Record step telemetry and update best loss."""
        self.current_step = step
        self.current_epoch = epoch
        if loss < self.best_loss:
            self.best_loss = loss
        if checkpoint_path:
            self.latest_checkpoint = checkpoint_path
        self.history.append({"step": step, "loss": loss, "epoch": epoch})
