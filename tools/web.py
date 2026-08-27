#!/usr/bin/env python3
"""tools/web.py — Web application scanning and fuzzing tools for LONLY.

Wraps Gobuster, Ffuf, Nikto, SQLMap, WPScan, and Curl.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool

from tools.base import run_cmd


class GobusterDirInput(BaseModel):
    target_url: str = Field(..., description="The base URL of the target web server to brute-force.")
    wordlist: str = Field(default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", description="Absolute path to the wordlist file.")


class FfufFuzzInput(BaseModel):
    target_url: str = Field(..., description="The target URL to fuzz. Must explicitly include the keyword 'FUZZ'.")
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt", description="Absolute path to the wordlist file.")


class NiktoScanInput(BaseModel):
    target_host: str = Field(..., description="The target web server to scan. Do not include trailing slashes.")
    port: Optional[str] = Field(default=None, description="Specific HTTP/HTTPS port to scan.")
    use_ssl: bool = Field(default=False, description="Set to True if target web server uses HTTPS.")
    tuning: Optional[str] = Field(default=None, description="Scan tuning options (-Tuning) to specify test types.")


class SqlmapInput(BaseModel):
    target_url: str = Field(..., description="The target URL to test for SQL injection. Must include specific parameters.")
    level: int = Field(default=1, description="Level of tests to perform (1-5).")
    risk: int = Field(default=1, description="Risk of tests to perform (1-3).")


class WpScanInput(BaseModel):
    target_url: str = Field(..., description="The base URL of the WordPress site to audit.")
    enumerate_options: str = Field(default="vp,vt,u", description="Enumeration options for WPScan (-e flag).")


class CurlRequestInput(BaseModel):
    url: str = Field(..., description="The target URL to send the HTTP request to.")
    method: str = Field(default="GET", description="HTTP Method to use: GET, POST, etc.")
    data: str = Field(default="", description="Raw data string to send in the request body.")
    headers: str = Field(default="", description="Custom HTTP headers to include format: '-H \"Name: Value\"'")


@tool(args_schema=GobusterDirInput)
def gobuster_directory_scan(target_url: str, wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt") -> str:
    """Brute-force directories and files on a web server using Gobuster."""
    cmd = f"gobuster dir -u {target_url} -w {wordlist} -q -t 30 -x php,html,txt,bak,zip"
    return run_cmd(cmd, timeout=120, max_output=3000)


@tool(args_schema=FfufFuzzInput)
def ffuf_web_fuzz(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Advanced and flexible web fuzzer (FFUF). Ensure target_url contains 'FUZZ' keyword."""
    cmd = f"ffuf -u {target_url} -w {wordlist} -maxtime 120 -c -t 30"
    return run_cmd(cmd, timeout=130, max_output=3000)


@tool(args_schema=NiktoScanInput)
def nikto_web_scan(target_host: str, port: Optional[str] = None, use_ssl: bool = False, tuning: Optional[str] = None) -> str:
    """Use this tool to perform a comprehensive web server vulnerability scan using Nikto."""
    args = ["nikto", "-h", target_host]
    if port:
        args.extend(["-p", port])
    if use_ssl:
        args.append("-ssl")
    if tuning:
        args.extend(["-Tuning", tuning])
    cmd = " ".join(args)
    return run_cmd(cmd, timeout=180)


@tool(args_schema=SqlmapInput)
def sqlmap_vulnerability_assessment(target_url: str, level: int = 1, risk: int = 1) -> str:
    """Detect and exploit SQL injection vulnerabilities using SQLMap. Automatically runs in non-interactive mode."""
    cmd = f"sqlmap -u \"{target_url}\" --level={level} --risk={risk} --batch"
    return run_cmd(cmd, timeout=300)


@tool(args_schema=WpScanInput)
def wpscan_wordpress_audit(target_url: str, enumerate_options: str = "vp,vt,u") -> str:
    """Scan a WordPress website for vulnerable plugins, themes, and usernames using WPScan."""
    cmd = f"wpscan --url {target_url} -e {enumerate_options} --no-update --random-user-agent --format cli"
    return run_cmd(cmd, timeout=180)


@tool(args_schema=CurlRequestInput)
def curl_web_request(url: str, method: str = "GET", data: str = "", headers: str = "") -> str:
    """Execute custom HTTP requests using cURL."""
    args = ["curl", "-X", method.upper(), "-s"]
    if headers:
        args.append(headers)
    if data:
        args.extend(["-d", f"'{data}'"])
    args.append(f'"{url}"')
    cmd = " ".join(args)
    return run_cmd(cmd, timeout=60)
