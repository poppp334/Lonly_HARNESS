#!/usr/bin/env python3
"""core/parser.py — Resilient ReAct response parser and safety validators for LONLY.

Specifically designed for 4B local models (Gemma 3, Qwen 3) which occasionally
emit Markdown fences, trailing commas, or idiosyncratic Action/Input formatting.

Stdlib only. Independent of LangChain and agent loop.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

# Patterns that unambiguously indicate a tool call failed.
TOOL_FAILURE_PATTERNS = [
    "[ERROR]",
    "[TIMEOUT]",
    "[TOOL ERROR]",
    "not found",
    "command not found",
    "No such file or directory",
    "Permission denied",
]

# Patterns that indicate the LLM copied format example text instead of writing real content.
PLACEHOLDER_PATTERNS = [
    "summary in thai/english, technical and concise",
    "<your_summary_here>",
]

# Words/phrases that indicate a tool name is being SUGGESTED (future action),
# not claimed as actually used.
SUGGESTION_MARKERS = [
    "consider",
    "suggest",
    "recommend",
    "could run",
    "could try",
    "also try",
    "try running",
    "next step",
    "if you want",
    "you may want to",
    "attempting",
    "option is to",
]

OVERCLAIM_KEYWORDS = [
    "version", "gathered", "obtained",
    "identified", "confirmed", "found", "discovered",
    "open", "running", "active", "listening",
]

NEGATION_WORDS = [
    "no", "not", "none", "without", "failed", "error",
    "nothing", "unable", "could not", "did not", "does not",
]


def extract_json_object(raw_text: str) -> Optional[dict[str, Any]]:
    """Extract a dictionary from a string with defensive fallbacks for 4B quirks."""
    if not raw_text or not raw_text.strip():
        return None

    cleaned = raw_text.strip()
    # Strip markdown code fences if present
    if "```" in cleaned:
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        else:
            cleaned = re.sub(r"^```(?:json)?|```$", "", cleaned, flags=re.MULTILINE).strip()

    # 1. Direct JSON parse
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # 2. Match outermost { ... }
    bracket_match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
    if bracket_match:
        candidate = bracket_match.group(1).strip()
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except Exception:
            # Try removing trailing commas before closing braces
            try:
                fixed = re.sub(r",\s*([\}\]])", r"\1", candidate)
                data = json.loads(fixed)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass

    return None


def parse_react_response(text: str) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    """Extract Action and Action Input from LLM response with resilient parsing."""
    if not text:
        return None, None

    # Case 1: Standard ReAct with separate Action Input: line
    action_match = re.search(r"Action:\s*([a-zA-Z0-9_-]+)", text)
    if not action_match:
        return None, None

    tool_name = action_match.group(1).strip()

    # Find Action Input: ... section
    input_match = re.search(r"Action Input:\s*(.+?)(?=(?:\n\s*Action:|\n\s*Observation:|\n\s*Final Answer:|$))", text, re.DOTALL)
    if input_match:
        raw_input = input_match.group(1).strip()
        tool_args = extract_json_object(raw_input)
        if tool_args is not None:
            return tool_name, tool_args

    # Case 2: Inline Action + JSON (e.g. Action: whatweb_web_fingerprint {"target_url": "..."})
    action_line_match = re.search(r"Action:\s*([a-zA-Z0-9_-]+)\s*(\{.*?\})", text)
    if action_line_match:
        inline_tool = action_line_match.group(1).strip()
        inline_json = extract_json_object(action_line_match.group(2))
        if inline_json is not None:
            return inline_tool, inline_json

    # Case 3: Action followed by JSON block or code fence without explicit 'Action Input:' label
    trailing_text = text[action_match.end():]
    # Stop before next Action/Observation/Final Answer if present
    next_section = re.split(r"\n\s*(?:Action:|Observation:|Final Answer:)", trailing_text)[0]
    json_candidate = extract_json_object(next_section)
    if json_candidate is not None:
        return tool_name, json_candidate

    return None, None


def extract_final_answer(text: str) -> Optional[str]:
    """Extract Final Answer from LLM response."""
    if not text:
        return None
    match = re.search(r"Final Answer:\s*(.*)", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def clean_answer_text(text: str) -> str:
    """Format and strip raw XML tags from 4B generation into clean markdown."""
    if not text:
        return ""
    cleaned = text
    cleaned = re.sub(r"<\/?summary>", "", cleaned)
    cleaned = re.sub(r"<bullet>(.*?)</bullet>", r"- \1", cleaned)
    cleaned = re.sub(r"<\/?bullet>", "", cleaned)
    return cleaned.strip()


def is_tool_failure(result: str) -> bool:
    """True if tool execution result indicates an unambiguous error or failure."""
    if not result or not result.strip():
        return True
    for pattern in TOOL_FAILURE_PATTERNS:
        if pattern in result:
            return True
    return False


def is_placeholder_answer(text: str) -> bool:
    """True if text appears to copy placeholder/template instructions."""
    lowered = text.strip().lower()
    for pattern in PLACEHOLDER_PATTERNS:
        if pattern in lowered:
            return True
    return False


def find_fabricated_tool_mentions(
    final_answer_text: str, actually_invoked_names: list[str], all_tool_names: list[str]
) -> list[str]:
    """Find tools mentioned in final answer that were never actually executed."""
    fabricated = []
    text_lower = final_answer_text.lower()
    for tool_name in all_tool_names:
        if tool_name in actually_invoked_names:
            continue
        match = re.search(r"\b" + re.escape(tool_name) + r"\b", final_answer_text, re.IGNORECASE)
        if match:
            start = match.start()
            window_start = max(0, start - 150)
            window = text_lower[window_start:start]
            if any(marker in window for marker in SUGGESTION_MARKERS):
                continue
            fabricated.append(tool_name)
    return fabricated


def has_positive_finding(tool_name: str, result: str) -> bool:
    """Return True if tool output contains evidence of a positive finding."""
    if not result:
        return False
    if tool_name == "metasploit_auxiliary_scanner":
        return any(line.strip().startswith("[+]") for line in result.splitlines())
    elif tool_name in ("nmap_security_scan", "rustscan_port_scan"):
        return "open" in result.lower()
    elif tool_name == "crackmapexec":
        return "[+]" in result or ("(" in result and ")" in result and "SMB" in result)
    elif tool_name == "whatweb_web_fingerprint":
        return "http" in result.lower() and "200" in result
    elif tool_name in ("gobuster_directory_scan", "ffuf_web_fuzz"):
        return any(str(code) in result for code in (200, 201, 301, 302, 403))
    elif tool_name == "hydra_brute_force":
        return "[+]" in result or "login:" in result.lower()
    elif tool_name == "searchsploit_exploit_lookup":
        return "Exploit" in result and "No Results" not in result
    elif tool_name == "enum4linux_smb_audit":
        return "WORKGROUP" in result or "SERVER" in result or "SHARE" in result
    elif tool_name == "ldap_search_enumeration":
        return "dn:" in result.lower()
    return False


def check_overclaim(
    final_answer_text: str,
    actually_invoked_tools: list[dict],
    overclaim_signatures: Optional[dict[str, Any]] = None,
) -> list[str]:
    """Return list of tool_names whose raw results show no real finding, yet the Final Answer claims positive."""
    if overclaim_signatures is None:
        overclaim_signatures = {
            "nmap_security_scan": lambda r: "open" in r.lower(),
            "rustscan_port_scan": lambda r: "open" in r.lower(),
            "whatweb_web_fingerprint": lambda r: "http" in r.lower() and "200" in r,
            "gobuster_directory_scan": lambda r: any(str(c) in r for c in [200, 201, 301, 302, 403]),
            "ffuf_web_fuzz": lambda r: any(str(c) in r for c in [200, 201, 301, 302, 403]),
            "hydra_brute_force": lambda r: "[+]" in r or "login:" in r.lower(),
            "crackmapexec": lambda r: "[+]" in r,
            "metasploit_auxiliary_scanner": lambda r: any(l.strip().startswith("[+]") for l in r.splitlines()),
        }

    tool_results: dict[str, list[str]] = {}
    for entry in actually_invoked_tools:
        tn = entry.get("tool_name")
        if tn and tn in overclaim_signatures:
            tool_results.setdefault(tn, []).append(entry.get("raw_result", ""))

    if not tool_results:
        return []

    overclaimed = []
    text_lower = final_answer_text.lower()
    has_keyword = any(kw.lower() in text_lower for kw in OVERCLAIM_KEYWORDS)
    has_negation = any(neg in text_lower for neg in NEGATION_WORDS)

    for tool_name, raw_results in tool_results.items():
        check_fn = overclaim_signatures[tool_name]
        if any(check_fn(r) for r in raw_results):
            continue
        if has_keyword and not has_negation:
            overclaimed.append(tool_name)
    return overclaimed


def extract_explicit_targets_from_text(text: str) -> list[str]:
    """Deterministically extract explicit targets (URLs, IPs, domain names) from user text."""
    if not text:
        return []

    targets = []
    # 1. Full URLs e.g. https://webme-mu.vercel.app/
    urls = re.findall(r"https?://([a-zA-Z0-9.-]+)", text, re.IGNORECASE)
    for u in urls:
        clean = u.strip().strip("/")
        if clean and clean not in targets:
            targets.append(clean)

    # 2. IPv4 / CIDR e.g. 192.168.1.1 or 10.0.0.0/24
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", text)
    for ip in ips:
        if ip not in targets:
            targets.append(ip)

    # 3. Multi-level FQDNs / Domain names e.g. webme-mu.vercel.app, api.corp.local
    fqdn_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b",
        re.IGNORECASE
    )
    for d in fqdn_pattern.findall(text):
        clean = d.strip().lower()
        # Exclude common source code / document extensions
        if clean and clean not in targets and not clean.endswith((".py", ".md", ".sh", ".json", ".txt", ".bin", ".lock", ".log")):
            targets.append(clean)

    return targets


PLACEHOLDER_DOMAINS = {
    "example.com", "www.example.com", "target", "ip", "http://ip", "https://ip",
    "http://example.com", "https://example.com", "target_host", "target_ip", "http://target",
}


def sanitize_hallucinated_targets(tool_args: dict[str, Any], explicit_target: Optional[str]) -> dict[str, Any]:
    """Substitute hallucinated boilerplate or truncated parent domains with the user's explicit target."""
    if not explicit_target or not isinstance(tool_args, dict):
        return tool_args

    clean_target = explicit_target.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
    sanitized = dict(tool_args)

    for k, v in sanitized.items():
        if isinstance(v, str):
            v_lower = v.strip().lower()
            v_host = v_lower.split("://")[-1].split("/")[0].split(":")[0].strip()

            is_placeholder = v_lower in PLACEHOLDER_DOMAINS or v_host in PLACEHOLDER_DOMAINS
            is_truncated_parent = (
                clean_target != v_host 
                and clean_target.endswith("." + v_host) 
                and v_host not in ("localhost", "127.0.0.1", "::1")
            )

            if is_placeholder or is_truncated_parent:
                if k in ("target_url", "url"):
                    scheme = "https://" if "https" in v_lower else "http://"
                    sanitized[k] = f"{scheme}{clean_target}"
                elif k in ("target", "target_host", "target_ip", "host", "rhosts", "domain"):
                    sanitized[k] = clean_target

    return sanitized

