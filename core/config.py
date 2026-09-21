#!/usr/bin/env python3
"""core/config.py — Centralized Configuration & Structured Logging for LONLY.

Provides:
- LonlyConfig: Typed system-wide configuration with environment overrides.
- get_config(): Singleton accessor for runtime configuration.
- get_logger(): Standardized logging facility with level and formatting control.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class LonlyConfig:
    """Centralized configuration values for LONLY runtime."""

    # Models
    model_name: str = field(
        default_factory=lambda: os.environ.get("LONLY_MODEL", "phi4-mini")
    )
    specialist_model_name: str = field(
        default_factory=lambda: os.environ.get("LONLY_SPECIALIST_MODEL", "privesc-llm-rl:4b")
    )
    embedding_model_name: str = field(
        default_factory=lambda: os.environ.get("LONLY_EMBEDDING_MODEL", "nomic-embed-text")
    )

    # LLM Resilience
    llm_timeout: float = field(
        default_factory=lambda: float(os.environ.get("LONLY_LLM_TIMEOUT", "120.0"))
    )
    llm_retries: int = field(
        default_factory=lambda: int(os.environ.get("LONLY_LLM_RETRIES", "2"))
    )
    llm_backoff: float = field(
        default_factory=lambda: float(os.environ.get("LONLY_LLM_BACKOFF", "1.5"))
    )

    # Storage & Audit
    workspace_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("LONLY_WORKSPACE_DIR", str(Path.home() / ".lonly")))
    )
    audit_max_bytes: int = field(
        default_factory=lambda: int(os.environ.get("LONLY_AUDIT_MAX_BYTES", str(10 * 1024 * 1024)))
    )
    max_sessions: int = field(
        default_factory=lambda: int(os.environ.get("LONLY_MAX_SESSIONS", "100"))
    )

    # Logging
    log_level: str = field(
        default_factory=lambda: os.environ.get("LONLY_LOG_LEVEL", "INFO").upper()
    )


_GLOBAL_CONFIG: Optional[LonlyConfig] = None


def get_config() -> LonlyConfig:
    """Return the global configuration instance, initialized on first call."""
    global _GLOBAL_CONFIG
    if _GLOBAL_CONFIG is None:
        _GLOBAL_CONFIG = LonlyConfig()
    return _GLOBAL_CONFIG


def reset_config() -> None:
    """Reset the global configuration singleton (useful for testing)."""
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG = None


def get_logger(name: str = "lonly") -> logging.Logger:
    """Get or configure a standardized logger for LONLY subsystems."""
    logger = logging.getLogger(name)
    cfg = get_config()

    level = getattr(logging, cfg.log_level, logging.INFO)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
