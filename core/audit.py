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
import sys
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


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
        secret_key: str = "LONLY-AUDIT-ROOT-KEY",
    ):
        self.ledger_path = ledger_path
        self.secret_key = secret_key
        self.events: list[AuditEvent] = []
        self.latest_hash: str = self.GENESIS_HASH

        if self.ledger_path and os.path.exists(self.ledger_path):
            self.load_and_verify()

    def record_event(
        self,
        event_type: AuditEventType | str,
        payload: dict,
        timestamp: Optional[str] = None,
    ) -> AuditEvent:
        """Record and cryptographically seal an event to the ledger."""
        ev_type = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
        seq = len(self.events)
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

        if self.ledger_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.ledger_path)), exist_ok=True)
            with open(self.ledger_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
                fh.flush()

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


# Default process ledger instance
DEFAULT_AUDIT_LEDGER = AuditLedger()


def main():
    """CLI tool for verifying audit ledger files."""
    if len(sys.argv) < 3 or sys.argv[1] != "verify":
        print("Usage: python -m core.audit verify <ledger_path_or_dir> [--key <secret_key>]")
        sys.exit(1)

    target_path = sys.argv[2]
    key = "LONLY-AUDIT-ROOT-KEY"
    if "--key" in sys.argv:
        k_idx = sys.argv.index("--key")
        if k_idx + 1 < len(sys.argv):
            key = sys.argv[k_idx + 1]

    if os.path.isdir(target_path):
        target_path = os.path.join(target_path, "audit_ledger.jsonl")

    ledger = AuditLedger(ledger_path=target_path, secret_key=key)
    valid, reason, count = ledger.verify_integrity()
    if valid:
        print(f"[+] AUDIT INTEGRITY: PASS — {reason}")
        print(f"    Root Chain Digest: {ledger.get_root_hash()}")
        sys.exit(0)
    else:
        print(f"[-] AUDIT INTEGRITY: FAIL — {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
