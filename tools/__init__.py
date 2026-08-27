#!/usr/bin/env python3
"""tools/__init__.py — Central registry and exports for all 24 LONLY tools.

Categorized into:
  - Recon: nmap, rustscan, masscan, whatweb, enum4linux, ldap, kerbrute
  - Web: gobuster, ffuf, nikto, sqlmap, wpscan, curl
  - Creds: crackmapexec, hydra, metasploit, reverse_shell_listener
  - Infra & Intel: searchsploit, linpeas, impacket, shell_exec, cve_lookup, bloodhound, rag_query
"""

from __future__ import annotations

from tools.base import run_cmd, TOOL_FAILURE_PATTERNS
from tools.recon import (
    NmapScanInput, nmap_security_scan,
    RustScanInput, rustscan_port_scan,
    MasscanInput, masscan_port_scan,
    WhatWebInput, whatweb_web_fingerprint,
    Enum4linuxInput, enum4linux_smb_audit,
    LdapSearchInput, ldap_search_enumeration,
    KerbruteInput, kerbrute_active_directory_assessment,
)
from tools.web import (
    GobusterDirInput, gobuster_directory_scan,
    FfufFuzzInput, ffuf_web_fuzz,
    NiktoScanInput, nikto_web_scan,
    SqlmapInput, sqlmap_vulnerability_assessment,
    WpScanInput, wpscan_wordpress_audit,
    CurlRequestInput, curl_web_request,
)
from tools.creds import (
    CrackMapExecInput, crackmapexec,
    HydraInput, hydra_brute_force,
    MetasploitAuxInput, metasploit_auxiliary_scanner,
    ReverseShellListenerInput, reverse_shell_listener,
)
from tools.infra import (
    SearchsploitInput, searchsploit_exploit_lookup,
    LinpeasScanInput, linpeas_privilege_escalation_scan,
    ImpacketToolInput, impacket_tool_execute,
    ShellExecInput, shell_exec,
    CVELookupInput, cve_lookup,
    BloodhoundAnalyzeInput, bloodhound_analyze,
    RAGQueryInput, rag_query,
)

ALL_TOOLS = [
    nmap_security_scan, rustscan_port_scan, masscan_port_scan,
    whatweb_web_fingerprint, gobuster_directory_scan, ffuf_web_fuzz,
    nikto_web_scan, sqlmap_vulnerability_assessment, wpscan_wordpress_audit,
    enum4linux_smb_audit, crackmapexec, ldap_search_enumeration, kerbrute_active_directory_assessment,
    hydra_brute_force, searchsploit_exploit_lookup, metasploit_auxiliary_scanner,
    linpeas_privilege_escalation_scan, reverse_shell_listener, impacket_tool_execute,
    curl_web_request, shell_exec, cve_lookup, bloodhound_analyze, rag_query,
]

tool_map = {t.name: t for t in ALL_TOOLS}
