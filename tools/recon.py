#!/usr/bin/env python3
"""tools/recon.py — Network discovery and reconnaissance tools for LONLY.

Wraps Nmap, Rustscan, Masscan, WhatWeb, Enum4linux, LDAP search, and Kerbrute.
"""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool

from tools.base import run_cmd


class NmapScanInput(BaseModel):
    target: str = Field(..., description="The target to scan. Can be a single IP, domain, or CIDR range. CRITICAL: Do NOT include protocol prefixes like 'http://'.")
    ports: Optional[str] = Field(default=None, description="Specific ports to scan, separated by commas (e.g., '80,443'). If None, scans top 1000 ports.")
    scan_type: Literal["SYN", "Connect", "Version", "OS", "Aggressive"] = Field(default="Version", description="Technical type of Nmap scan to execute.")
    timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = Field(default="T4", description="Nmap timing template for speed.")
    use_default_scripts: bool = Field(default=False, description="Set to True to enable default script scanning (-sC).")


class RustScanInput(BaseModel):
    target: str = Field(..., description="The target IP address or hostname to scan.")
    ports: Optional[str] = Field(default="1-65535", description="Port range (e.g., '1-65535', '80,443', '1-1000'). Default is '1-65535'.")
    scan_version: bool = Field(default=False, description="Set True to run deep Nmap version detection on discovered ports. Default is False for ultra-fast port discovery.")


class MasscanInput(BaseModel):
    target: str = Field(..., description="The target to scan (Single IP or CIDR range).")
    ports: str = Field(default="1-65535", description="Port range to scan.")
    rate: int = Field(default=1000, description="The packet transmission rate per second.")


class WhatWebInput(BaseModel):
    target_url: str = Field(..., description="The full target URL to fingerprint. Must include protocol prefix.")


class Enum4linuxInput(BaseModel):
    target_ip: str = Field(..., description="The target IP address or hostname of the SMB/Samba server.")


class LdapSearchInput(BaseModel):
    target_ip: str = Field(..., description="The IP address of the target LDAP or Active Directory server.")
    base_dn: str = Field(..., description="The Base Distinguished Name (DN) to start the search from.")
    search_filter: str = Field(default="(objectClass=*)", description="The LDAP search filter.")


class KerbruteInput(BaseModel):
    mode: str = Field(default="userenum", description="The operational mode for Kerbrute: 'userenum' or 'passwordspray'.")
    domain: str = Field(..., description="The target Active Directory domain name.")
    dc_ip: str = Field(..., description="The IP address of the target Domain Controller.")
    wordlist: str = Field(default="/usr/share/wordlists/seclists/Usernames/top-usernames-short.txt", description="Absolute path to the wordlist file.")


@tool(args_schema=NmapScanInput)
def nmap_security_scan(target: str, ports: Optional[str] = None, scan_type: str = "Version", timing: str = "T4", use_default_scripts: bool = False) -> str:
    """Use this tool to perform network exploration and vulnerability/port scanning using Nmap."""
    args = [f"-{timing}"]
    scan_type_map = {"SYN": "-sS", "Connect": "-sT", "Version": "-sV", "OS": "-O", "Aggressive": "-A"}
    args.append(scan_type_map.get(scan_type, "-sV"))
    if use_default_scripts and scan_type != "Aggressive":
        args.append("-sC")
    if ports:
        args.append(f"-p {ports}")
    args.append(target)
    cmd = f"nmap {' '.join(args)}"
    return run_cmd(cmd, timeout=180)


@tool(args_schema=RustScanInput)
def rustscan_port_scan(
    target: str,
    ports: Optional[str] = "1-65535",
    scan_version: bool = False,
    ulimit: Optional[int] = None,
    batch_size: Optional[int] = None,
) -> str:
    """Ultra-fast port scanner (RustScan). Best for discovering all open ports (1-65535) in seconds."""
    port_range = ports if ports else "1-65535"
    opts = []
    if ulimit:
        opts.append(f"--ulimit {ulimit}")
    if batch_size:
        opts.append(f"-b {batch_size}")
    opt_str = f" {' '.join(opts)}" if opts else ""
    nmap_flags = "-T4 -sV" if scan_version else "-T4"
    cmd = f"rustscan -a {target} -r {port_range}{opt_str} -- {nmap_flags}"
    return run_cmd(cmd, timeout=60)


@tool(args_schema=MasscanInput)
def masscan_port_scan(target: str, ports: str = "1-65535", rate: int = 1000) -> str:
    """Masscan for extremely fast asynchronous port scanning of large networks and CIDR blocks."""
    cmd = f"masscan {target} -p{ports} --rate={rate} --wait=0"
    return run_cmd(cmd, timeout=120)


@tool(args_schema=WhatWebInput)
def whatweb_web_fingerprint(target_url: str) -> str:
    """Identify and fingerprint web technologies using WhatWeb."""
    cmd = f"whatweb {target_url} --no-errors"
    return run_cmd(cmd, timeout=60)


@tool(args_schema=Enum4linuxInput)
def enum4linux_smb_audit(target_ip: str) -> str:
    """Enumerate information from Windows and Samba systems via SMB protocols using enum4linux."""
    cmd = f"enum4linux -a {target_ip}"
    return run_cmd(cmd, timeout=150)


@tool(args_schema=LdapSearchInput)
def ldap_search_enumeration(target_ip: str, base_dn: str, search_filter: str = "(objectClass=*)") -> str:
    """Perform anonymous or simple bind LDAP queries against an Active Directory server."""
    cmd = f"ldapsearch -x -h {target_ip} -b \"{base_dn}\" \"{search_filter}\""
    return run_cmd(cmd, timeout=90)


@tool(args_schema=KerbruteInput)
def kerbrute_active_directory_assessment(domain: str, dc_ip: str, mode: str = "userenum", wordlist: str = "/usr/share/wordlists/seclists/Usernames/top-usernames-short.txt") -> str:
    """Use Kerbrute to enumerate valid Active Directory usernames or perform password spraying."""
    validated_mode = "userenum" if mode not in ["userenum", "passwordspray"] else mode
    cmd = f"kerbrute {validated_mode} --dc {dc_ip} -d {domain} {wordlist}"
    return run_cmd(cmd, timeout=120)
