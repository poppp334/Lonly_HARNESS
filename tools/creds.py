#!/usr/bin/env python3
"""tools/creds.py — Credential testing, brute-forcing, and Metasploit auxiliary tools for LONLY.

Wraps CrackMapExec (NetExec), Hydra, Metasploit auxiliary, and Reverse Shell listener.
"""

from __future__ import annotations

from typing import Literal, Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool

from tools.base import run_cmd


class CrackMapExecInput(BaseModel):
    target: str = Field(description="เป้าหมายที่ต้องการทดสอบ เช่น IP, ช่วง IP หรือวงเครือข่าย CIDR")
    protocol: Literal["smb", "ssh", "winrm", "mssql", "ftp", "ldap"] = Field(default="smb", description="โปรโตคอล/บริการที่ต้องการตรวจสอบ")
    username: str = Field(default="", description="ชื่อผู้ใช้งานสำหรับการทดสอบสิทธิ์การเข้าถึง")
    password: str = Field(default="", description="รหัสผ่าน หรือ NTLM Hash")
    exec_cmd: str = Field(default="", description="Remote Command Execution หลังยึดสิทธิ์สำเร็จ (เช่น 'whoami')")


class HydraInput(BaseModel):
    target: str = Field(..., description="The target IP address or hostname.")
    service: str = Field(..., description="The protocol service to brute-force (e.g., 'ssh', 'ftp').")
    username: Optional[str] = Field(default=None, description="A single specific username to test.")
    user_list: str = Field(default="/usr/share/wordlists/metasploit/namelist.txt", description="Path to a username wordlist file.")
    password: Optional[str] = Field(default=None, description="A single specific password to test.")
    password_list: str = Field(default="/usr/share/wordlists/dirb/common.txt", description="Path to the password wordlist file.")


class MetasploitAuxInput(BaseModel):
    module: str = Field(..., description="The exact Metasploit auxiliary module path (e.g., 'scanner/smb/smb_version').")
    rhosts: str = Field(..., description="The target IP address or network range.")


class ReverseShellListenerInput(BaseModel):
    port: int = Field(..., description="The local port number on the attacker machine to listen on.")
    listen_timeout: int = Field(default=60, description="Time in seconds to wait for an incoming connection.")


@tool(args_schema=CrackMapExecInput)
def crackmapexec(target: str, protocol: str = "smb", username: str = "", password: str = "", exec_cmd: str = "") -> str:
    """CrackMapExec (CME) - เครื่องมือประเมินความปลอดภัยระบบเครือข่ายภายใน กวาดตรวจสอบพอร์ต บริการ และทดสอบเดารหัสผ่าน"""
    base_cmd = f"nxc {protocol} {target}"
    if username:
        base_cmd += f" -u '{username}'"
    if password:
        if len(password) == 32 and all(c in "0123456789abcdefABCDEF" for c in password):
            base_cmd += f" -H '{password}'"
        else:
            base_cmd += f" -p '{password}'"
    if exec_cmd:
        base_cmd += f" -x '{exec_cmd}'"
    return run_cmd(base_cmd, timeout=180)


@tool(args_schema=HydraInput)
def hydra_brute_force(target: str, service: str, username: Optional[str] = None, user_list: str = "/usr/share/wordlists/metasploit/namelist.txt", password: Optional[str] = None, password_list: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Execute network login brute-forcing or dictionary attacks against various services using Hydra."""
    args = ["hydra"]
    if username:
        args.extend(["-l", username])
    else:
        args.extend(["-L", user_list])
    if password:
        args.extend(["-p", password])
    else:
        args.extend(["-P", password_list])
    args.extend(["-t", "4", "-I", target, service])
    cmd = " ".join(args)
    return run_cmd(cmd, timeout=300)


@tool(args_schema=MetasploitAuxInput)
def metasploit_auxiliary_scanner(module: str, rhosts: str) -> str:
    """Execute a specific Metasploit Framework auxiliary module for scanning or verification."""
    cmd = f"msfconsole -q -x \"use auxiliary/{module}; set RHOSTS {rhosts}; run; exit\""
    return run_cmd(cmd, timeout=180, max_output=4000)


@tool(args_schema=ReverseShellListenerInput)
def reverse_shell_listener(port: int, listen_timeout: int = 60) -> str:
    """Set up a local network listener using Netcat (nc) to capture incoming reverse shells."""
    cmd = f"nc -lvnp {port} -w {listen_timeout}"
    return run_cmd(cmd, timeout=listen_timeout + 10)
