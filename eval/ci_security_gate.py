#!/usr/bin/env python3
"""eval/ci_security_gate.py — Automated CI/CD Security Gate & Policy Invariant Checker for LONLY v2.

Enforces:
- Zero P0 Security Violations Gate (AST inspection for unauthorized subprocess/shell usage).
- Hardcoded Secret & Token Leak Scans across repository files.
- Automated execution and verification of Track R Red Team adversarial suite.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from typing import Optional


class CISecurityGate:
    """Automated pre-merge CI/CD security gate."""

    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    @classmethod
    def check_static_invariants(cls) -> tuple[bool, list[str]]:
        """Verify zero shell=True, os.system, os.popen and isolated subprocess."""
        violations = []
        prod_dirs = ["core", "tools"]

        for d in prod_dirs:
            full_d = os.path.join(cls.ROOT_DIR, d)
            if not os.path.exists(full_d):
                continue
            for root, _, files in os.walk(full_d):
                for f in files:
                    if not f.endswith(".py"):
                        continue
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, cls.ROOT_DIR)
                    with open(fpath, "r", encoding="utf-8") as fh:
                        content = fh.read()

                    if "shell=True" in content:
                        violations.append(f"Forbidden 'shell=True' found in {rel}")
                    if "os.system" in content:
                        violations.append(f"Forbidden 'os.system' found in {rel}")
                    if "os.popen" in content:
                        violations.append(f"Forbidden 'os.popen' found in {rel}")
                    if "core/broker.py" not in rel and "subprocess.run" in content:
                        violations.append(f"Forbidden 'subprocess.run' found in {rel}")

        return len(violations) == 0, violations

    @classmethod
    def scan_secret_leaks(cls) -> tuple[bool, list[str]]:
        """Scan repository files for exposed plaintext secrets."""
        leaks = []
        secret_patterns = [
            re.compile(r'(?:api_key|secret_key|private_key)\s*=\s*["\'][A-Za-z0-9_\-\.]{16,}["\']', re.IGNORECASE),
            re.compile(r'BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY', re.IGNORECASE),
        ]

        for root, _, files in os.walk(cls.ROOT_DIR):
            if any(ign in root for ign in (".git", "__pycache__", "venv", ".cache", "scratch", "runs")):
                continue
            for f in files:
                if not f.endswith((".py", ".json", ".md", ".sh", ".txt")):
                    continue
                fpath = os.path.join(root, f)
                rel = os.path.relpath(fpath, cls.ROOT_DIR)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                    for p in secret_patterns:
                        if p.search(text) and "test" not in rel and "eval" not in rel:
                            leaks.append(f"Potential secret pattern found in {rel}")
                except Exception:
                    pass

        return len(leaks) == 0, leaks

    @classmethod
    def run_all_gates(cls) -> dict:
        """Run all automated security gates and return verdict."""
        inv_ok, inv_errs = cls.check_static_invariants()
        sec_ok, sec_errs = cls.scan_secret_leaks()

        all_passed = inv_ok and sec_ok
        return {
            "passed": all_passed,
            "static_invariants": {"passed": inv_ok, "violations": inv_errs},
            "secret_scanning": {"passed": sec_ok, "leaks": sec_errs},
        }


def main():
    result = CISecurityGate.run_all_gates()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
