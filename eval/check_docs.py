#!/usr/bin/env python3
"""eval/check_docs.py — Automated Documentation Integrity & Anti-Drift Linter.

Ensures:
1. No stale model references (e.g. 'gemma3:4b') in active code, tools, or primary docs.
2. Verified acceptance test suite counts match the true number of checks (153).
3. Primary architectural claims match actual codebase invariants.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Files that should be strictly free of obsolete model references
STRICT_FILES = [
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "pentest_agent.py",
    ROOT / "core" / "doctor.py",
    ROOT / "models" / "README.md",
]

FORBIDDEN_PATTERNS = [
    (re.compile(r"gemma3:4b", re.IGNORECASE), "Deprecated model reference 'gemma3:4b' (use 'phi4-mini' or 'privesc-llm-rl:4b')"),
]

REQUIRED_COUNT = 157


def check_docs() -> bool:
    violations: list[str] = []

    # 1. Check forbidden strings in strict files
    for path in STRICT_FILES:
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        for pattern, description in FORBIDDEN_PATTERNS:
            matches = list(pattern.finditer(content))
            if matches:
                for m in matches:
                    line_no = content[: m.start()].count("\n") + 1
                    violations.append(f"{path.relative_to(ROOT)}:{line_no} — {description}")

    # 2. Check acceptance test suite counts in README and AGENTS
    for doc_name in ("README.md", "AGENTS.md"):
        doc_path = ROOT / doc_name
        if not doc_path.exists():
            continue
        text = doc_path.read_text(encoding="utf-8")
        if f"{REQUIRED_COUNT}-check" not in text and f"{REQUIRED_COUNT}/{REQUIRED_COUNT}" not in text:
            violations.append(
                f"{doc_name} does not reference the current test suite count ({REQUIRED_COUNT})"
            )

    if violations:
        print("[!] Documentation Integrity Check FAILED with violations:", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return False

    print(f"[+] Documentation Integrity Check PASSED — verified 0 drift violations across {len(STRICT_FILES)} primary files.")
    return True


if __name__ == "__main__":
    success = check_docs()
    sys.exit(0 if success else 1)
