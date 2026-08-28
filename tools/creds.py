#!/usr/bin/env python3
"""tools/creds.py — Credential testing, brute-forcing, and Metasploit auxiliary tools for LONLY.

Wraps CrackMapExec (NetExec), Hydra, Metasploit auxiliary, and Reverse Shell listener.
"""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool

import shutil
from tools.base import run_argv, clean_target, find_wordlist


class CrackMapExecInput(BaseModel):
    target: str = Field(..., description="The target IP address, hostname, or CIDR range.")
    protocol: str = Field(default="smb", description="Protocol service to test: 'smb', 'ssh', 'winrm', 'mssql', 'ftp', 'ldap', 'rdp'.")
    username: str = Field(default="", description="Username for authentication testing.")
    password: str = Field(default="", description="Password or NTLM Hash for authentication testing.")
    exec_cmd: str = Field(default="", description="Remote command to execute upon successful authentication (e.g., 'whoami').")


class HydraInput(BaseModel):
    target: str = Field(..., description="The target IP address or hostname.")
    service: str = Field(..., description="The protocol service to brute-force (e.g., 'ssh', 'ftp', 'http-get', 'rdp', 'smb').")
    username: Optional[str] = Field(default=None, description="A single specific username to test.")
    user_list: Optional[str] = Field(default=None, description="Path to a username wordlist file.")
    password: Optional[str] = Field(default=None, description="A single specific password to test.")
    password_list: Optional[str] = Field(default=None, description="Path to a password wordlist file.")


class MetasploitAuxInput(BaseModel):
    module: str = Field(..., description="Metasploit auxiliary module path (e.g., 'scanner/smb/smb_version' or 'scanner/portscan/tcp').")
    rhosts: str = Field(..., description="The target IP address or network range.")


class ReverseShellListenerInput(BaseModel):
    port: int = Field(default=4444, description="The local port number to listen on.")
    listen_timeout: int = Field(default=60, description="Time in seconds to wait for an incoming connection.")


@tool(args_schema=CrackMapExecInput)
def crackmapexec(target: str, protocol: str = "smb", username: str = "", password: str = "", exec_cmd: str = "") -> str:
    """Network authentication testing, service scanning, and password validation via CrackMapExec / NetExec."""
    host = clean_target(target)
    bin_name = "nxc" if shutil.which("nxc") else "crackmapexec"
    proto_clean = str(protocol).strip().lower()
    proto_map = {
        "smb": "smb", "cifs": "smb", "windows": "smb",
        "ssh": "ssh", "winrm": "winrm", "mssql": "mssql",
        "ftp": "ftp", "ldap": "ldap", "rdp": "rdp",
    }
    valid_proto = proto_map.get(proto_clean, "smb")
    argv = [valid_proto, host]
    if username:
        argv.extend(["-u", username])
    if password:
        if len(password) == 32 and all(c in "0123456789abcdefABCDEF" for c in password):
            argv.extend(["-H", password])
        else:
            argv.extend(["-p", password])
    if exec_cmd:
        argv.extend(["-x", exec_cmd])
    return run_argv(bin_name, argv, target=host, timeout=180)


def _map_service_name(service: str) -> str:
    """Maps common port numbers or protocol aliases to Hydra service names."""
    s = service.strip().lower()
    port_map = {
        "21": "ftp", "22": "ssh", "23": "telnet", "25": "smtp",
        "80": "http-get", "443": "https-get", "110": "pop3",
        "143": "imap", "445": "smb", "3306": "mysql", "3389": "rdp",
        "5432": "postgres", "5900": "vnc", "8080": "http-get",
    }
    return port_map.get(s, s)


@tool(args_schema=HydraInput)
def hydra_brute_force(
    target: str,
    service: str,
    username: Optional[str] = None,
    user_list: Optional[str] = None,
    password: Optional[str] = None,
    password_list: Optional[str] = None,
) -> str:
    """Execute network login brute-forcing or dictionary attacks against various services using Hydra."""
    host = clean_target(target)
    svc = _map_service_name(service)
    argv = []
    if username:
        argv.extend(["-l", username])
    else:
        ul = find_wordlist(
            user_list or "/usr/share/wordlists/metasploit/namelist.txt",
            ["/usr/share/seclists/Usernames/top-usernames-short.txt", "/usr/share/wordlists/dirb/common.txt"],
        )
        argv.extend(["-L", ul])
    if password:
        argv.extend(["-p", password])
    else:
        pl = find_wordlist(
            password_list or "/usr/share/wordlists/dirb/common.txt",
            ["/usr/share/wordlists/fasttrack.txt", "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-passwords.txt"],
        )
        argv.extend(["-P", pl])
    argv.extend(["-t", "4", "-I", host, svc])
    return run_argv("hydra", argv, target=host, timeout=300)


@tool(args_schema=MetasploitAuxInput)
def metasploit_auxiliary_scanner(module: str, rhosts: str) -> str:
    """Execute a specific Metasploit Framework auxiliary module for scanning or verification."""
    host = clean_target(rhosts)
    clean_mod = module.strip()
    if clean_mod.startswith("auxiliary/"):
        clean_mod = clean_mod[len("auxiliary/"):]
    argv = ["-q", "-x", f"use auxiliary/{clean_mod}; set RHOSTS {host}; run; exit"]
    return run_argv("msfconsole", argv, target=host, timeout=180, max_output=4000)


@tool(args_schema=ReverseShellListenerInput)
def reverse_shell_listener(port: int, listen_timeout: int = 60) -> str:
    """Set up a local network listener using Netcat (nc) to capture incoming reverse shells."""
    try:
        clean_port = int(port)
    except (ValueError, TypeError):
        clean_port = 4444
    argv = ["-lvnp", str(clean_port), "-w", str(listen_timeout)]
    return run_argv("nc", argv, target="127.0.0.1", timeout=listen_timeout + 10)
