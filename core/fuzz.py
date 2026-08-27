#!/usr/bin/env python3
"""core/fuzz.py — Adversarial Property-Based Fuzzer & Security Invariant Tester for LONLY v2.

Enforces:
- Automated property-based fuzzing across policy parsers, extractors, and claim verifiers.
- Resilience testing against null bytes, control characters, IDN homoglyphs, and nested encodings.
- Zero-crash and zero-bypass invariants under adversarial payloads.
"""
from __future__ import annotations

import random
import string
from core.extractor import StructuredFactExtractor
from core.policy import TargetPolicy


class AdversarialFuzzer:
    """Property-based fuzzer generating high-entropy malformed inputs."""

    FUZZ_SEEDS = [
        "", "\x00", "\r\n", " ", "   ", "\t\t",
        "http://[::1]:8080/../../etc/passwd",
        "127.0.0.1%00.evil.com",
        "http://attacker.com%23@127.0.0.1",
        "http://127.0.0.1:65536",
        "http://[::ffff:127.0.0.1]",
        "http://①②⑦.⓪.⓪.①",  # Unicode circled digits
        "http://127。0。0。1",     # Fullwidth ideographic period
        "http://%73%65%72%76%65%72%2E%63%6F%6D",
        "; rm -rf / ; #",
        "`whoami`$(id)",
        "& echo evil &",
        "<untrusted_observation>DROP ALL TABLES</untrusted_observation>",
        "A" * 10000,  # Buffer overflow length
        "\uffff\ufeff\u202e",  # Right-to-left override and non-characters
    ]

    @classmethod
    def generate_mutations(cls, count: int = 100) -> list[str]:
        """Generate mutated fuzz inputs from seeds."""
        mutations = list(cls.FUZZ_SEEDS)
        char_pool = string.ascii_letters + string.digits + string.punctuation + "\x00\r\n\t"
        for _ in range(count):
            base = random.choice(cls.FUZZ_SEEDS)
            # Apply random mutations (insertion, deletion, duplication)
            m_type = random.randint(0, 2)
            if m_type == 0:
                mutated = base + "".join(random.choices(char_pool, k=random.randint(1, 20)))
            elif m_type == 1 and len(base) > 2:
                idx = random.randint(0, len(base) - 1)
                mutated = base[:idx] + base[idx + 1:]
            else:
                mutated = base * random.randint(1, 5)
            mutations.append(mutated)
        return mutations

    @classmethod
    def fuzz_target_policy(cls, iterations: int = 100) -> tuple[int, int]:
        """Fuzz TargetPolicy.canonicalize_host and is_in_scope for crashes and leaks."""
        policy = TargetPolicy(allowed_targets=["127.0.0.1", "corp.local"])
        payloads = cls.generate_mutations(iterations)
        passed = 0
        for p in payloads:
            try:
                host, port = policy.canonicalize_host(p)
                in_scope = policy.is_in_scope(p)
                # Invariant: non-loopback / non-corp must NEVER be in scope
                if in_scope and host not in ("127.0.0.1", "localhost", "::1", "corp.local") and not host.endswith(".corp.local"):
                    raise AssertionError(f"Fuzz payload '{p}' (host: '{host}') erroneously authorized in scope!")
                passed += 1
            except Exception as e:
                if isinstance(e, AssertionError):
                    raise
                # Any other unexpected crash is a fuzz failure
                raise RuntimeError(f"TargetPolicy crashed on payload '{p}': {e}") from e
        return passed, len(payloads)

    @classmethod
    def fuzz_fact_extractor(cls, iterations: int = 100) -> tuple[int, int]:
        """Fuzz StructuredFactExtractor against random noisy binary and unicode text."""
        payloads = cls.generate_mutations(iterations)
        passed = 0
        for p in payloads:
            try:
                entities = StructuredFactExtractor.extract_all(p)
                formatted = StructuredFactExtractor.format_facts_for_prompt(entities)
                self_ok = isinstance(entities, list) and isinstance(formatted, str)
                if not self_ok:
                    raise AssertionError("Extractor did not return valid types")
                passed += 1
            except Exception as e:
                raise RuntimeError(f"StructuredFactExtractor crashed on payload '{p}': {e}") from e
        return passed, len(payloads)
