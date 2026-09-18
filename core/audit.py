#!/usr/bin/env python3
"""core/audit.py — Cryptographic Append-Only Audit Ledger for LONLY v2.

Enforces:
- SHA-256 + HMAC cryptographic hash chaining across all engagement events.
- Tamper-evident sequence ordering (PROMPT, DECISION, APPROVAL, BROKER_CALL, PROCESS_START, PROCESS_END, ARTIFACT_RECORDED, CLAIM_ASSERTED, CLAIM_VERIFIED).
- Strict write-ahead log (WAL) persistence and verification engine.
- Instant offline mathematical tamper detection for reordered, altered, or deleted events.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional

from core.storage import file_lock


class AuditEventType(str, Enum):
    """Categorization of audit events for verifiable lifecycle tracking."""
    PROMPT = "PROMPT"
    DECISION = "DECISION"
    APPROVAL = "APPROVAL"
    BROKER_CALL = "BROKER_CALL"
    PROCESS_START = "PROCESS_START"
    PROCESS_END = "PROCESS_END"
    ARTIFACT_RECORDED = "ARTIFACT_RECORDED"
    CLAIM_ASSERTED = "CLAIM_ASSERTED"
    CLAIM_VERIFIED = "CLAIM_VERIFIED"


@dataclass(frozen=True)
class AuditEvent:
    """Immutable cryptographically chained audit record."""
    sequence: int
    timestamp: str
    event_type: str
    payload: dict
    payload_hash: str
    prev_hash: str
    event_hash: str
    signature: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> AuditEvent:
        return cls(**d)


def canonical_json(data: dict) -> str:
    """Serialize dictionary to canonical JSON for deterministic hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_payload_hash(payload: dict) -> str:
    """Compute SHA-256 digest of canonical payload JSON."""
    raw = canonical_json(payload)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def compute_event_hash(
    sequence: int,
    timestamp: str,
    event_type: str,
    payload_hash: str,
    prev_hash: str,
) -> str:
    """Compute SHA-256 digest of chained event parameters."""
    chained_repr = f"{sequence}:{timestamp}:{event_type}:{payload_hash}:{prev_hash}"
    return hashlib.sha256(chained_repr.encode("utf-8", errors="replace")).hexdigest()


def compute_signature(event_hash: str, secret_key: str) -> str:
    """Compute HMAC-SHA256 signature over event hash."""
    return hmac.new(
        secret_key.encode("utf-8"),
        event_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class AuditLedger:
    """Cryptographic append-only write-ahead ledger."""

    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        ledger_path: Optional[str] = None,
        secret_key: Optional[str] = None,
        lazy: bool = False,
    ):
        self.ledger_path = ledger_path
        self._secret_key = secret_key or os.environ.get("LONLY_AUDIT_KEY")
        self.events: list[AuditEvent] = []
        self.latest_hash: str = self.GENESIS_HASH
        self._next_seq: int = 0
        self._chain_error: str = ""
        self._lazy = bool(lazy)
        self._lock = threading.Lock()

        if self.ledger_path and os.path.exists(self.ledger_path):
            if self._lazy:
                self._load_tail()
                if self._chain_error:
                    print(
                        f"[!] Audit ledger tail unreadable ({self._chain_error}); "
                        f"next append will archive {self.ledger_path} and start a fresh chain.",
                        file=sys.stderr,
                    )
            else:
                try:
                    valid, reason, _ = self.load_and_verify()
                    if not valid:
                        self._chain_error = reason
                        print(
                            f"[!] Audit ledger failed verification ({reason}); "
                            f"next append will archive {self.ledger_path} and start a fresh chain.",
                            file=sys.stderr,
                        )
                except Exception as exc:  # unreadable ledger must not break startup
                    self._chain_error = f"unreadable ledger: {exc}"
                    self.events = []
                    self.latest_hash = self.GENESIS_HASH
                    self._next_seq = 0
                    print(
                        f"[!] Audit ledger unreadable ({exc}); "
                        f"next append will archive {self.ledger_path} and start a fresh chain.",
                        file=sys.stderr,
                    )

    def _load_tail(self) -> None:
        """Recover the chain head from the last valid line without a full scan."""
        try:
            with open(self.ledger_path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    return
                fh.seek(max(0, size - 65536))
                chunk = fh.read().decode("utf-8", errors="replace")
            lines = [ln for ln in chunk.splitlines() if ln.strip()]
            if not lines:
                self._chain_error = "ledger tail unreadable"
                return
            last = AuditEvent.from_dict(json.loads(lines[-1]))
            expected_event_hash = compute_event_hash(
                last.sequence, last.timestamp, last.event_type, last.payload_hash, last.prev_hash
            )
            if last.payload_hash != compute_payload_hash(last.payload):
                self._chain_error = f"payload altered at sequence {last.sequence}"
                return
            if last.event_hash != expected_event_hash:
                self._chain_error = f"event hash mismatch at sequence {last.sequence}"
                return
            if not hmac.compare_digest(
                last.signature, compute_signature(last.event_hash, self.secret_key)
            ):
                self._chain_error = f"signature verification failed at sequence {last.sequence}"
                return
            self.latest_hash = last.event_hash
            self._next_seq = last.sequence + 1
        except Exception as exc:
            self._chain_error = f"unreadable ledger tail: {exc}"

    @property
    def secret_key(self) -> str:
        """Ledger signing key: env override, then 0600 keyfile, else ephemeral."""
        if self._secret_key is None:
            self._secret_key = resolve_audit_key()
        return self._secret_key

    def _archive_ledger(self, reason: str) -> None:
        """Preserve an unverifiable ledger instead of silently reusing its chain."""
        archived = ""
        if self.ledger_path:
            archived = f"{self.ledger_path}.legacy-{time.strftime('%Y%m%dT%H%M%S')}"
            try:
                os.replace(self.ledger_path, archived)
            except OSError:
                archived = ""
        self.events = []
        self.latest_hash = self.GENESIS_HASH
        self._next_seq = 0
        self._chain_error = ""
        print(
            f"[!] Audit ledger chain could not be continued ({reason}). "
            f"Archived to {archived or 'n/a'}; starting a fresh chain.",
            file=sys.stderr,
        )

    def record_event(
        self,
        event_type: AuditEventType | str,
        payload: dict,
        timestamp: Optional[str] = None,
    ) -> AuditEvent:
        """Record and cryptographically seal an event to the ledger.

        Cross-process safe: the append holds an exclusive lock and re-reads the
        chain tail, so concurrent writers cannot duplicate sequence numbers or
        break the hash links.
        """
        if self.ledger_path:
            with self._lock, file_lock(self.ledger_path):
                return self._seal_event(event_type, payload, timestamp)
        with self._lock:
            return self._seal_event(event_type, payload, timestamp)

    def _seal_event(
        self,
        event_type: AuditEventType | str,
        payload: dict,
        timestamp: Optional[str] = None,
    ) -> AuditEvent:
        if self._chain_error:
            self._archive_ledger(self._chain_error)
        if self._lazy and self.ledger_path and os.path.exists(self.ledger_path):
            self.latest_hash = self.GENESIS_HASH
            self._next_seq = 0
            self._load_tail()
            if self._chain_error:
                self._archive_ledger(self._chain_error)
        ev_type = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
        seq = self._next_seq
        ts = timestamp or time.strftime("%Y-%m-%dT%H:%M:%S")
        p_hash = compute_payload_hash(payload)
        e_hash = compute_event_hash(seq, ts, ev_type, p_hash, self.latest_hash)
        sig = compute_signature(e_hash, self.secret_key)

        event = AuditEvent(
            sequence=seq,
            timestamp=ts,
            event_type=ev_type,
            payload=payload,
            payload_hash=p_hash,
            prev_hash=self.latest_hash,
            event_hash=e_hash,
            signature=sig,
        )

        self.events.append(event)
        self.latest_hash = e_hash
        self._next_seq = seq + 1

        if self.ledger_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.ledger_path)), exist_ok=True)
                with open(self.ledger_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:  # degrade to in-memory WAL; never break execution
                print(f"[!] Audit ledger write failed ({self.ledger_path}): {exc}", file=sys.stderr)

        return event

    def load_and_verify(self) -> tuple[bool, str, int]:
        """Load events from disk and verify cryptographic integrity."""
        if not self.ledger_path or not os.path.exists(self.ledger_path):
            return False, "Ledger file does not exist", 0

        loaded_events: list[AuditEvent] = []
        with open(self.ledger_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    loaded_events.append(AuditEvent.from_dict(json.loads(line)))

        self.events = loaded_events
        self._next_seq = len(loaded_events)
        if loaded_events:
            self.latest_hash = loaded_events[-1].event_hash
        else:
            self.latest_hash = self.GENESIS_HASH

        return self.verify_integrity()

    def verify_integrity(self) -> tuple[bool, str, int]:
        """Verify the cryptographic chain of all events in the ledger."""
        expected_prev = self.GENESIS_HASH

        for i, event in enumerate(self.events):
            # 1. Sequence check
            if event.sequence != i:
                return False, f"Sequence discontinuity at index {i}: expected {i}, got {event.sequence}", i

            # 2. Previous hash link check
            if event.prev_hash != expected_prev:
                return (
                    False,
                    f"Hash link broken at sequence {i}: expected prev_hash '{expected_prev}', got '{event.prev_hash}'",
                    i,
                )

            # 3. Payload hash integrity
            expected_payload_hash = compute_payload_hash(event.payload)
            if event.payload_hash != expected_payload_hash:
                return (
                    False,
                    f"Payload altered at sequence {i}: expected payload_hash '{expected_payload_hash}', got '{event.payload_hash}'",
                    i,
                )

            # 4. Event hash integrity
            expected_event_hash = compute_event_hash(
                event.sequence,
                event.timestamp,
                event.event_type,
                event.payload_hash,
                event.prev_hash,
            )
            if event.event_hash != expected_event_hash:
                return (
                    False,
                    f"Event hash mismatch at sequence {i}: expected '{expected_event_hash}', got '{event.event_hash}'",
                    i,
                )

            # 5. HMAC signature verification
            expected_sig = compute_signature(event.event_hash, self.secret_key)
            if not hmac.compare_digest(event.signature, expected_sig):
                return False, f"Signature verification failed at sequence {i}", i

            expected_prev = event.event_hash

        return True, f"Cryptographic integrity verified ({len(self.events)} events in chain)", len(self.events)

    def get_root_hash(self) -> str:
        """Return root state hash of the audit ledger."""
        return self.latest_hash


# Default process ledger instance (persisted write-ahead log)
DEFAULT_AUDIT_KEY_FILE = os.environ.get(
    "LONLY_AUDIT_KEY_FILE", os.path.expanduser("~/.lonly/audit.key")
)


def resolve_audit_key(key_file: Optional[str] = None) -> str:
    """Resolve the ledger signing key.

    Priority: LONLY_AUDIT_KEY env var, then a 0600 key file (generated on
    first use), then an ephemeral key when the key file is unavailable.
    """
    env_key = os.environ.get("LONLY_AUDIT_KEY")
    if env_key:
        return env_key
    path = key_file or os.environ.get("LONLY_AUDIT_KEY_FILE", DEFAULT_AUDIT_KEY_FILE)
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                existing = fh.read().strip()
            if existing:
                return existing
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        key = secrets.token_hex(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(key)
        return key
    except OSError as exc:
        print(
            f"[!] Audit key file unavailable ({path}): {exc}; using an ephemeral key",
            file=sys.stderr,
        )
        return secrets.token_hex(32)


DEFAULT_AUDIT_LEDGER_PATH = os.environ.get(
    "LONLY_AUDIT_LEDGER", os.path.expanduser("~/.lonly/audit.wal")
)
DEFAULT_AUDIT_LEDGER = AuditLedger(ledger_path=DEFAULT_AUDIT_LEDGER_PATH, lazy=True)


def main():
    """CLI tool for verifying audit ledger files."""
    if len(sys.argv) < 3 or sys.argv[1] != "verify":
        print("Usage: python -m core.audit verify <ledger_path_or_dir> [--key <secret_key>]")
        sys.exit(1)

    target_path = sys.argv[2]
    key = resolve_audit_key()
    if "--key" in sys.argv:
        k_idx = sys.argv.index("--key")
        if k_idx + 1 < len(sys.argv):
            key = sys.argv[k_idx + 1]

    if os.path.isdir(target_path):
        target_path = os.path.join(target_path, "audit_ledger.jsonl")

    ledger = AuditLedger(ledger_path=target_path, secret_key=key)
    valid, reason, count = ledger.load_and_verify()
    if valid:
        print(f"[+] AUDIT INTEGRITY: PASS — {reason}")
        print(f"    Root Chain Digest: {ledger.get_root_hash()}")
        sys.exit(0)
    else:
        print(f"[-] AUDIT INTEGRITY: FAIL — {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
