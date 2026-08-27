#!/usr/bin/env python3
"""eval/track_b_worker.py — Track B: per-tool smoke tests (mocked subprocess).

Imports pentest_agent (safe: RAG/embeddings init lazily, ChatOllama is a lazy
client) and monkeypatches run_cmd so NO real command executes. Runs in a
subprocess so the harness itself stays dependency-free.

Exit 0 iff every tool wrapper passes. Prints JSON result line.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pentest_agent as pa  # noqa: E402

# Representative in-scope arguments per tool (loopback only — nothing executes)
ARGS = {
    "nmap_security_scan": {"target": "127.0.0.1"},
    "rustscan_port_scan": {"target": "127.0.0.1"},
    "masscan_port_scan": {"target": "127.0.0.1"},
    "rag_query": {"query": "kerberoasting"},
    "whatweb_web_fingerprint": {"target_url": "http://127.0.0.1"},
    "gobuster_directory_scan": {"target_url": "http://127.0.0.1"},
    "ffuf_web_fuzz": {"target_url": "http://127.0.0.1"},
    "nikto_web_scan": {"target_host": "127.0.0.1"},
    "sqlmap_vulnerability_assessment": {"target_url": "http://127.0.0.1"},
    "wpscan_wordpress_audit": {"target_url": "http://127.0.0.1"},
    "enum4linux_smb_audit": {"target_ip": "127.0.0.1"},
    "crackmapexec": {"target": "127.0.0.1"},
    "ldap_search_enumeration": {"target_ip": "127.0.0.1", "base_dn": "dc=lab,dc=local"},
    "kerbrute_active_directory_assessment": {"domain": "lab.local", "dc_ip": "127.0.0.1"},
    "hydra_brute_force": {"target": "127.0.0.1", "service": "ssh"},
    "searchsploit_exploit_lookup": {"query": "openssh"},
    "metasploit_auxiliary_scanner": {"module": "auxiliary/scanner/portscan/tcp", "rhosts": "127.0.0.1"},
    "linpeas_privilege_escalation_scan": {"script_path": "/usr/share/peass-ng/linux/linpeas.sh"},
    "reverse_shell_listener": {"port": "4444"},
    "impacket_tool_execute": {"tool_name": "GetNPUsers.py", "target": "127.0.0.1",
                              "connection_string": "lab/user:pass", "extra_args": ""},
    "curl_web_request": {"url": "http://127.0.0.1"},
    "shell_exec": {"cmd": "echo hi"},
    "cve_lookup": {"query": "CVE-2021-3156"},
    "bloodhound_analyze": {"zip_path": "/tmp/none.zip"},
}

# Expected run_cmd max_output per tool (the wrapper truncation contract)
LIMITS = {
    "shell_exec": 3000,
    "gobuster_directory_scan": 3000,
    "ffuf_web_fuzz": 3000,
    "linpeas_privilege_escalation_scan": 5000,
}
DEFAULT_LIMIT = 4000


def main() -> int:
    calls: list[tuple[str, list[str], int]] = []

    def fake_run_argv(executable, argv, target=None, timeout=120, max_output=4000, broker=None):
        calls.append((executable, list(argv), max_output))
        return "FAKE OUTPUT\n" * 100

    def fake_run_cmd(cmd, timeout=120, max_output=4000):
        calls.append((cmd, [], max_output))
        return "FAKE OUTPUT\n" * 100

    pa.run_argv = fake_run_argv
    pa.run_cmd = fake_run_cmd
    fails = []
    for name in sorted(pa.tool_map.keys()):
        try:
            wrapper = pa.tool_map[name]
            args = ARGS.get(name)
            if args is None:
                fails.append(f"{name}: no test args defined")
                continue
            n_before = len(calls)
            out = wrapper.invoke(args)
            if not isinstance(out, str):
                fails.append(f"{name}: non-str return {type(out).__name__}")
                continue
            tool_calls = calls[n_before:]
            if tool_calls:  # argv-based wrapper: assert truncation contract
                expected = LIMITS.get(name, DEFAULT_LIMIT)
                limit_ok = any(mo == expected for _, _, mo in tool_calls)
                if not limit_ok:
                    got = [mo for _, _, mo in tool_calls]
                    fails.append(f"{name}: max_output contract {expected} not in {got}")
            # pure-Python wrapper (bloodhound/rag/cve): str return suffices
        except Exception as e:  # noqa: BLE001 — worker reports, harness aggregates
            fails.append(f"{name}: {type(e).__name__}: {e}")

    total = len(pa.tool_map)
    result = {
        "track": "B",
        "passed": total - len(fails),
        "total": total,
        "fails": fails,
    }
    print(json.dumps(result))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
