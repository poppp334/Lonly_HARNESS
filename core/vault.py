#!/usr/bin/env python3
"""core/vault.py — Secret Management & Sensitive Data Redaction for LONLY v2.

Enforces:
- Opaque credential references (cred_<id>) preventing plaintext secret leakage into prompts.
- Deterministic redaction of passwords, API keys, and hashes in logs and trajectories.
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional


class SecretVault:
    """In-memory secret vault for managing and resolving sensitive credentials."""

    def __init__(self):
        self._secrets: dict[str, tuple[str, str]] = {}  # token -> (raw_secret, label)

    def store(self, secret: str, label: str = "credential") -> str:
        """Store a secret and return an opaque reference token."""
        if not secret or not isinstance(secret, str):
            return ""
        # Token format: cred_<sha256_prefix>
        h = hashlib.sha256(secret.encode()).hexdigest()[:10]
        token = f"cred_{h}"
        self._secrets[token] = (secret, label)
        return token

    def resolve(self, token_or_val: str) -> str:
        """Resolve an opaque token to its raw secret value."""
        if not token_or_val or not isinstance(token_or_val, str):
            return token_or_val
        if token_or_val in self._secrets:
            return self._secrets[token_or_val][0]
        return token_or_val

    def redact(self, text: str) -> str:
        """Redact all stored secrets and sensitive credential patterns from text."""
        if not text or not isinstance(text, str):
            return text

        result = text
        # 1. Redact all registered vault secrets
        for token, (raw_secret, label) in self._secrets.items():
            if raw_secret and len(raw_secret) >= 3 and raw_secret in result:
                result = result.replace(raw_secret, f"[REDACTED_{label.upper()}_{token}]")

        # 2. Heuristic redaction for common key/value secret assignments
        result = re.sub(
            r'(password|passwd|pwd|secret|token|api_key)["\']?\s*[:=]\s*["\']([^"\'\s]{3,})["\']',
            r'\1: "[REDACTED_SECRET]"',
            result,
            flags=re.IGNORECASE,
        )

        return result


# Global default vault instance
DEFAULT_VAULT = SecretVault()
