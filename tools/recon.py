#!/usr/bin/env python3
"""tools/recon.py — Network discovery and reconnaissance tools for LONLY.

Wraps Nmap, Rustscan, Masscan, WhatWeb, Enum4linux, LDAP search, and Kerbrute.
"""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool

from tools.base import run_argv, clean_target, ensure_url


class NmapScanInput(BaseModel):
    target: str = Field(..., description="The target IP, hostname, or CIDR subnet to scan.")
    ports: Optional[str] = Field(default=None, description="Specific ports to scan (e.g. '80,443', '1-1000'). If None, scans top 1000 ports.")
    scan_type: Literal["SYN", "Connect", "Version", "OS", "Aggressive"] = Field(default="Version", description="Nmap scan type.")
    timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = Field(default="T4", description="Nmap timing template.")
    use_default_scripts: bool = Field(default=False, description="Set True to enable default script scanning (-sC).")


class RustScanInput(BaseModel):
    target: str = Field(..., description="The target IP address or hostname to scan.")
    ports: Optional[str] = Field(default=None, description="Port range (e.g., '1-65535', '80,443', '1-1000'). If None, scans all 65535 ports.")
    scan_version: bool = Field(default=False, description="Set True to run deep Nmap version detection on discovered ports. Default is False.")


class MasscanInput(BaseModel):
    target: str = Field(..., description="The target IP address or CIDR range to scan.")
    ports: Optional[str] = Field(default="1-65535", description="Port range to scan (e.g. '1-65535', '80,443').")
    rate: int = Field(default=1000, description="Packet transmission rate per second.")


class WhatWebInput(BaseModel):
    target_url: str = Field(..., description="The target URL or domain to fingerprint.")


class Enum4linuxInput(BaseModel):
    target_ip: str = Field(..., description="Target IP address or hostname of the SMB/Samba server.")


class LdapSearchInput(BaseModel):
    target_ip: str = Field(..., description="The IP address of the target LDAP or Active Directory server.")
    base_dn: str = Field(..., description="The Base Distinguished Name (DN) to start the search from (e.g., 'dc=domain,dc=local').")
    search_filter: str = Field(default="(objectClass=*)", description="The LDAP search filter.")


class KerbruteInput(BaseModel):
    domain: str = Field(..., description="The target Active Directory domain name (e.g., 'corp.local').")
    dc_ip: str = Field(..., description="The IP address of the Domain Controller.")
    mode: str = Field(default="userenum", description="Mode: 'userenum' or 'passwordspray'.")
    wordlist: str = Field(default="/usr/share/wordlists/seclists/Usernames/top-usernames-short.txt", description="Wordlist path.")


@tool(args_schema=NmapScanInput)
def nmap_security_scan(target: str, ports: Optional[str] = None, scan_type: str = "Version", timing: str = "T4", use_default_scripts: bool = False) -> str:
    """Use this tool to perform network exploration and vulnerability/port scanning using Nmap."""
    host = clean_target(target)
    argv = [f"-{timing}"]
    scan_type_map = {"SYN": "-sS", "Connect": "-sT", "Version": "-sV", "OS": "-O", "Aggressive": "-A"}
    argv.append(scan_type_map.get(scan_type, "-sV"))
    if use_default_scripts and scan_type != "Aggressive":
        argv.append("-sC")
    if ports:
        clean_p = ports.strip()
        if clean_p.lower() in ("all", "1-65535", "full", "*"):
            argv.append("-p-")
        else:
            argv.extend(["-p", clean_p])
    argv.append(host)
    return run_argv("nmap", argv, target=host, timeout=180)


def _format_rustscan_ports(ports: Optional[str]) -> list[str]:
    """Intelligently maps LLM port inputs to the correct RustScan CLI argv arguments."""
    if not ports:
        return []
    p = ports.strip().lower()
    if p in ("all", "1-65535", "full", "65535", "none", "*"):
        return []  # RustScan default is full 1-65535 scan
    if p in ("top", "top1000", "top-1000", "top 1000"):
        return ["--top"]
    if "-" in p and "," not in p:
        return ["-r", p]
    # Single port or comma-separated list (e.g., '80,443' or '80')
    clean = ",".join(part.strip() for part in p.split(",") if part.strip())
    return ["-p", clean] if clean else []


@tool(args_schema=RustScanInput)
def rustscan_port_scan(
    target: str,
    ports: Optional[str] = None,
    scan_version: bool = False,
    ulimit: Optional[int] = None,
    batch_size: Optional[int] = None,
) -> str:
    """Ultra-fast port scanner (RustScan). Discovers open ports across 1-65535 in seconds."""
    host = clean_target(target)
    argv = ["--no-banner", "-a", host]
    argv.extend(_format_rustscan_ports(ports))
    if ulimit:
        argv.extend(["--ulimit", str(ulimit)])
    if batch_size:
        argv.extend(["-b", str(batch_size)])
    argv.append("--")
    if scan_version:
        argv.extend(["-T4", "-sV"])
    else:
        argv.append("-T4")
    return run_argv("rustscan", argv, target=host, timeout=60)


@tool(args_schema=MasscanInput)
def masscan_port_scan(target: str, ports: Optional[str] = "1-65535", rate: int = 1000) -> str:
    """Masscan for extremely fast asynchronous port scanning of large networks and CIDR blocks."""
    host = clean_target(target)
    p_val = ports if ports else "1-65535"
    if p_val.lower() in ("all", "full", "*"):
        p_val = "1-65535"
    argv = [host, f"-p{p_val}", f"--rate={rate}", "--wait=0"]
    return run_argv("masscan", argv, target=host, timeout=120)


@tool(args_schema=WhatWebInput)
def whatweb_web_fingerprint(target_url: str) -> str:
    """Identify and fingerprint web technologies using WhatWeb."""
    url = ensure_url(target_url)
    argv = [url, "--no-errors"]
    return run_argv("whatweb", argv, target=url, timeout=60)


@tool(args_schema=Enum4linuxInput)
def enum4linux_smb_audit(target_ip: str) -> str:
    """Enumerate information from Windows and Samba systems via SMB protocols using enum4linux."""
    host = clean_target(target_ip)
    argv = ["-a", host]
    return run_argv("enum4linux", argv, target=host, timeout=150)


@tool(args_schema=LdapSearchInput)
def ldap_search_enumeration(target_ip: str, base_dn: str, search_filter: str = "(objectClass=*)") -> str:
    """Perform anonymous or simple bind LDAP queries against an Active Directory server."""
    host = clean_target(target_ip)
    argv = ["-x", "-h", host, "-b", base_dn, search_filter]
    return run_argv("ldapsearch", argv, target=host, timeout=90)


@tool(args_schema=KerbruteInput)
def kerbrute_active_directory_assessment(domain: str, dc_ip: str, mode: str = "userenum", wordlist: str = "/usr/share/wordlists/seclists/Usernames/top-usernames-short.txt") -> str:
    """Use Kerbrute to enumerate valid Active Directory usernames or perform password spraying."""
    host = clean_target(dc_ip)
    validated_mode = "userenum" if mode not in ["userenum", "passwordspray"] else mode
    argv = [validated_mode, "--dc", host, "-d", domain, wordlist]
    return run_argv("kerbrute", argv, target=host, timeout=120)
