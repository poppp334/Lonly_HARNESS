#!/usr/bin/env python3
"""models/sft/distributed_config.py — Distributed Multi-GPU Strategy & Accelerate Config.

Provides:
- DistributedEnvironment: Detects available CUDA devices and distributed runtime context
  (LOCAL_RANK, WORLD_SIZE, MASTER_ADDR, MASTER_PORT).
- generate_accelerate_config: Exports valid Accelerate configuration for DDP/FSDP training.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class DistributedEnvironment:
    """Detects and encapsulates multi-GPU distributed runtime attributes."""

    world_size: int = 1
    local_rank: int = 0
    rank: int = 0
    is_distributed: bool = False
    device_count: int = 0
    backend: str = "single"  # 'single', 'nccl', 'gloo'

    @classmethod
    def detect(cls) -> DistributedEnvironment:
        """Inspect environment variables and torch runtime to detect distributed topology."""
        device_count = 0
        try:
            import torch
            if torch.cuda.is_available():
                device_count = torch.cuda.device_count()
        except ImportError:
            pass

        world_size = int(os.environ.get("WORLD_SIZE", "1"))
        rank = int(os.environ.get("RANK", "0"))
        local_rank = int(os.environ.get("LOCAL_RANK", "0"))
        is_dist = world_size > 1 or device_count > 1

        backend = "single"
        if is_dist:
            backend = "nccl" if device_count > 0 else "gloo"

        return cls(
            world_size=world_size,
            local_rank=local_rank,
            rank=rank,
            is_distributed=is_dist,
            device_count=device_count,
            backend=backend,
        )


def generate_accelerate_config(
    output_path: str | Path,
    num_processes: Optional[int] = None,
    mixed_precision: str = "bf16",
    use_fsdp: bool = False,
) -> Path:
    """Generate YAML configuration for Accelerate distributed launcher."""
    env = DistributedEnvironment.detect()
    procs = num_processes or max(env.device_count, 1)

    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    dist_type = "FSDP" if use_fsdp else ("MULTI_GPU" if procs > 1 else "NO")

    config_yaml = f"""compute_environment: LOCAL_MACHINE
distributed_type: {dist_type}
downcast_bf16: 'no'
gpu_ids: all
machine_rank: 0
main_training_function: main
mixed_precision: {mixed_precision}
num_machines: 1
num_processes: {procs}
rdzv_backend: static
same_network: true
tpu_env: []
tpu_use_cluster: false
tpu_use_sudo: false
use_cpu: false
"""
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(config_yaml)

    return p
