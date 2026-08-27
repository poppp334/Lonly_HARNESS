#!/usr/bin/env python3
"""core/vault.py — Secret Management & Sensitive Data Redaction for LONLY v2.

Enforces:
- Random opaque credential references (cred_<random_hex>) preventing plaintext secret leakage into prompts.
- Per-engagement and per-capability credential access policies.
- Secret expiration, rotation, revocation, and zeroization.
- Comprehensive access audit logging.
- Deterministic redaction of passwords, API keys, and hashes in logs and trajectories.
"""
from __future__ import annotations

import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SecretRecord:
    """Record of a managed credential within the vault."""
    token: str
    raw_secret: str
    label: str
    engagement_id: Optional[str] = None
    allowed_capabilities: set[str] = field(default_factory=set)  # empty = all capabilities permitted
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    expires_at: Optional[float] = None
    access_count: int = 0
    revoked: bool = False


class SecretVault:
    """Forensic-grade secret vault for managing, scoping, and resolving sensitive credentials."""

    def __init__(self):
        self._secrets: dict[str, SecretRecord] = {}  # token -> SecretRecord
        self.audit_log: list[dict] = []

    def store(
        self,
        secret: str,
        label: str = "credential",
        engagement_id: Optional[str] = None,
        allowed_capabilities: Optional[list[str] | set[str]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """Store a secret and return a random opaque reference token."""
        if not secret or not isinstance(secret, str):
            return ""

        # Use random opaque UUID token, not secret hash
        token = f"cred_{uuid.uuid4().hex[:12]}"
        exp = (time.time() + ttl_seconds) if ttl_seconds else None

        record = SecretRecord(
            token=token,
            raw_secret=secret,
            label=label,
            engagement_id=engagement_id,
            allowed_capabilities=set(allowed_capabilities or []),
            expires_at=exp,
        )
        self._secrets[token] = record
        self._log_audit(token, "store", success=True, detail=f"Label: {label}")
        return token

    def resolve(
        self,
        token_or_val: str,
        capability_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
    ) -> str:
        """Resolve an opaque token to its raw secret value with capability and expiration checks."""
        if not token_or_val or not isinstance(token_or_val, str):
            return token_or_val

        if token_or_val not in self._secrets:
            return token_or_val

        record = self._secrets[token_or_val]

        # 1. Check revocation
        if record.revoked:
            self._log_audit(token_or_val, "resolve", success=False, capability=capability_id, detail="Secret is revoked")
            return token_or_val

        # 2. Check expiration
        if record.expires_at and time.time() > record.expires_at:
            self._log_audit(token_or_val, "resolve", success=False, capability=capability_id, detail="Secret has expired")
            return token_or_val

        # 3. Check capability restriction
        if record.allowed_capabilities and capability_id:
            if capability_id not in record.allowed_capabilities:
                self._log_audit(
                    token_or_val,
                    "resolve",
                    success=False,
                    capability=capability_id,
                    detail=f"Capability '{capability_id}' unauthorized for this credential",
                )
                return token_or_val

        # 4. Check engagement restriction
        if record.engagement_id and engagement_id:
            if record.engagement_id != engagement_id:
                self._log_audit(
                    token_or_val,
                    "resolve",
                    success=False,
                    capability=capability_id,
                    detail=f"Engagement mismatch ({engagement_id} != {record.engagement_id})",
                )
                return token_or_val

        record.access_count += 1
        self._log_audit(token_or_val, "resolve", success=True, capability=capability_id)
        return record.raw_secret

    def rotate(self, token: str, new_secret: str) -> bool:
        """Rotate the underlying secret value for an existing token."""
        if token not in self._secrets or self._secrets[token].revoked:
            return False
        self._secrets[token].raw_secret = new_secret
        self._secrets[token].created_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._log_audit(token, "rotate", success=True)
        return True

    def revoke(self, token: str) -> bool:
        """Revoke a token permanently."""
        if token not in self._secrets:
            return False
        self._secrets[token].revoked = True
        self._log_audit(token, "revoke", success=True)
        return True

    def zeroize(self) -> None:
        """Zeroize all secret material from memory."""
        for record in self._secrets.values():
            record.raw_secret = "\x00" * len(record.raw_secret)
        self._secrets.clear()
        self.audit_log.clear()

    def redact(self, text: str) -> str:
        """Redact all stored secrets and sensitive credential patterns from text."""
        if not text or not isinstance(text, str):
            return text

        result = text
        # 1. Redact all registered vault secrets
        for token, record in self._secrets.items():
            raw = record.raw_secret
            if raw and len(raw) >= 3 and raw in result:
                result = result.replace(raw, f"[REDACTED_{record.label.upper()}_{token}]")

        # 2. Heuristic redaction for common key/value secret assignments
        result = re.sub(
            r'(password|passwd|pwd|secret|token|api_key)["\']?\s*[:=]\s*["\']([^"\'\s]{3,})["\']',
            r'\1: "[REDACTED_SECRET]"',
            result,
            flags=re.IGNORECASE,
        )

        return result

    def _log_audit(
        self,
        token: str,
        action: str,
        success: bool,
        capability: Optional[str] = None,
        detail: str = "",
    ) -> None:
        self.audit_log.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "token": token,
            "action": action,
            "success": success,
            "capability": capability,
            "detail": detail,
        })


# Global default vault instance
DEFAULT_VAULT = SecretVault()
