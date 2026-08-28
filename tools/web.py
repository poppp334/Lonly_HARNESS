#!/usr/bin/env python3
"""tools/web.py — Web application scanning and fuzzing tools for LONLY.

Wraps Gobuster, Ffuf, Nikto, SQLMap, WPScan, and Curl.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool

from tools.base import run_argv, clean_target, ensure_url, find_wordlist


class GobusterDirInput(BaseModel):
    target_url: str = Field(..., description="The base URL of the target web server to brute-force.")
    wordlist: Optional[str] = Field(default=None, description="Path to wordlist file. If None, uses default wordlist.")


class FfufFuzzInput(BaseModel):
    target_url: str = Field(..., description="The target URL to fuzz. Will auto-append '/FUZZ' if omitted.")
    wordlist: Optional[str] = Field(default=None, description="Path to wordlist file. If None, uses default wordlist.")


class NiktoScanInput(BaseModel):
    target_host: str = Field(..., description="The target web server or IP to scan.")
    port: Optional[str] = Field(default=None, description="Specific HTTP/HTTPS port to scan.")
    use_ssl: bool = Field(default=False, description="Set True if target web server uses HTTPS.")
    tuning: Optional[str] = Field(default=None, description="Scan tuning options (-Tuning).")


class SqlmapInput(BaseModel):
    target_url: str = Field(..., description="The target URL to test for SQL injection.")
    level: int = Field(default=1, description="Level of tests to perform (1-5).")
    risk: int = Field(default=1, description="Risk of tests to perform (1-3).")


class WpScanInput(BaseModel):
    target_url: str = Field(..., description="The base URL of the WordPress site to audit.")
    enumerate_options: str = Field(default="vp,vt,u", description="Enumeration options for WPScan (-e flag).")


class CurlRequestInput(BaseModel):
    url: str = Field(..., description="The target URL to send the HTTP request to.")
    method: str = Field(default="GET", description="HTTP Method: GET, POST, PUT, DELETE, HEAD, etc.")
    data: str = Field(default="", description="Raw data string to send in request body.")
    headers: str = Field(default="", description="Custom HTTP headers e.g. 'Content-Type: application/json'")


@tool(args_schema=GobusterDirInput)
def gobuster_directory_scan(target_url: str, wordlist: Optional[str] = None) -> str:
    """Brute-force directories and files on a web server using Gobuster."""
    url = ensure_url(target_url)
    wl = find_wordlist(
        wordlist or "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        ["/usr/share/wordlists/dirb/common.txt", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"],
    )
    argv = ["dir", "-u", url, "-w", wl, "-q", "-t", "30", "-x", "php,html,txt,bak,zip"]
    return run_argv("gobuster", argv, target=url, timeout=120, max_output=3000)


@tool(args_schema=FfufFuzzInput)
def ffuf_web_fuzz(target_url: str, wordlist: Optional[str] = None) -> str:
    """Advanced and flexible web fuzzer (FFUF). Auto-appends '/FUZZ' if omitted."""
    url = ensure_url(target_url)
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    wl = find_wordlist(
        wordlist or "/usr/share/wordlists/dirb/common.txt",
        ["/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"],
    )
    argv = ["-u", url, "-w", wl, "-maxtime", "120", "-c", "-t", "30"]
    return run_argv("ffuf", argv, target=url, timeout=130, max_output=3000)


@tool(args_schema=NiktoScanInput)
def nikto_web_scan(target_host: str, port: Optional[str] = None, use_ssl: bool = False, tuning: Optional[str] = None) -> str:
    """Use this tool to perform a comprehensive web server vulnerability scan using Nikto."""
    is_https = str(target_host).strip().lower().startswith("https://") or str(use_ssl).strip().lower() in ("true", "1", "yes", "ssl", "https")
    host = clean_target(target_host)
    argv = ["-h", host]
    if port:
        argv.extend(["-p", str(port).strip()])
    if is_https:
        argv.append("-ssl")
    if tuning:
        argv.extend(["-Tuning", str(tuning).strip()])
    return run_argv("nikto", argv, target=host, timeout=180)


@tool(args_schema=SqlmapInput)
def sqlmap_vulnerability_assessment(target_url: str, level: int = 1, risk: int = 1) -> str:
    """Detect and exploit SQL injection vulnerabilities using SQLMap. Runs in non-interactive batch mode."""
    url = ensure_url(target_url)
    try:
        clean_level = max(1, min(int(level), 5))
    except (ValueError, TypeError):
        clean_level = 1
    try:
        clean_risk = max(1, min(int(risk), 3))
    except (ValueError, TypeError):
        clean_risk = 1
    argv = ["-u", url, f"--level={clean_level}", f"--risk={clean_risk}", "--batch", "--disable-coloring"]
    return run_argv("sqlmap", argv, target=url, timeout=300)


@tool(args_schema=WpScanInput)
def wpscan_wordpress_audit(target_url: str, enumerate_options: str = "vp,vt,u") -> str:
    """Scan a WordPress website for vulnerable plugins, themes, and usernames using WPScan."""
    url = ensure_url(target_url)
    enum_opt = str(enumerate_options).strip() if enumerate_options else "vp,vt,u"
    argv = ["--url", url, "-e", enum_opt, "--no-update", "--random-user-agent", "--format", "cli"]
    return run_argv("wpscan", argv, target=url, timeout=180)


@tool(args_schema=CurlRequestInput)
def curl_web_request(url: str, method: str = "GET", data: str = "", headers: str = "") -> str:
    """Execute custom HTTP requests using cURL."""
    target = ensure_url(url)
    http_method = str(method).strip().upper() if method else "GET"
    argv = ["-X", http_method, "-s"]
    if headers:
        clean_hdr = str(headers).strip()
        if clean_hdr.startswith("-H "):
            clean_hdr = clean_hdr[3:].strip().strip("'\"")
        argv.extend(["-H", clean_hdr])
    if data:
        argv.extend(["-d", str(data)])
    argv.append(target)
    return run_argv("curl", argv, target=target, timeout=60)
