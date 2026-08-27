#!/usr/bin/env python3
"""tools/infra.py — Infrastructure, exploitation, privesc, and intelligence tools for LONLY.

Wraps Searchsploit, LinPEAS, Impacket, ShellExec, CVELookup, Bloodhound, and RAGQuery.
"""

from __future__ import annotations

import json
import zipfile
from typing import Optional
from pydantic import BaseModel, Field
from langchain_core.tools import tool
import networkx as nx
import requests

import os
import shlex
import shutil
from tools.base import run_argv, run_cmd, clean_target, find_wordlist

try:
    from langchain_huggingface import HuggingFaceEmbeddings
    from langchain_chroma import Chroma
except ImportError:
    HuggingFaceEmbeddings = None  # type: ignore
    Chroma = None  # type: ignore


class SearchsploitInput(BaseModel):
    query: str = Field(..., description="The search term for exploits, vulnerability names, or software versions.")


class LinpeasScanInput(BaseModel):
    script_path: Optional[str] = Field(default=None, description="Path to linpeas.sh script. If None, auto-locates.")


class ImpacketToolInput(BaseModel):
    tool_name: str = Field(..., description="The specific Impacket tool name (e.g., 'GetNPUsers.py', 'secretsdump.py').")
    target: str = Field(..., description="Target IP address or hostname.")
    connection_string: str = Field(..., description="Authentication string format: 'domain/username:password' or 'username:password'.")
    extra_args: str = Field(default="", description="Optional additional command flags.")


class ShellExecInput(BaseModel):
    cmd: str = Field(..., description="The exact shell command to execute on the local system.")
    timeout: int = Field(default=60, description="Execution timeout in seconds (5-300).")


class CVELookupInput(BaseModel):
    query: str = Field(..., description="The vulnerability identifier (e.g., 'CVE-2021-3156') or software keyword.")


class BloodhoundAnalyzeInput(BaseModel):
    zip_path: str = Field(..., description="Absolute file path to the SharpHound data collection .zip archive.")


class RAGQueryInput(BaseModel):
    query: str = Field(..., description="The specific cybersecurity topic or technique to retrieve.")


rag_vectorstore = None


@tool(args_schema=RAGQueryInput)
def rag_query(query: str) -> str:
    """Retrieve relevant penetration testing knowledge, documentation, and technical cheat sheets from internal knowledge base."""
    global rag_vectorstore
    if rag_vectorstore is None:
        if HuggingFaceEmbeddings is None or Chroma is None:
            return "RAG dependencies not installed."
        if not os.path.exists("chroma_db"):
            return "Knowledge base not initialized. Run python ingest_knowledge.py to build index."
        try:
            embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
            rag_vectorstore = Chroma(persist_directory="chroma_db", embedding_function=embeddings)
        except Exception as e:
            return f"RAG initialization failed: {e}"
    try:
        docs = rag_vectorstore.similarity_search(query, k=3)
        if not docs:
            return "No relevant knowledge found."
        results = []
        for d in docs:
            source = d.metadata.get("source", "unknown")
            results.append(f"[Source: {source}]\n{d.page_content}")
        return "\n\n---\n".join(results)
    except Exception as e:
        return f"RAG query error: {e}"


@tool(args_schema=SearchsploitInput)
def searchsploit_exploit_lookup(query: str) -> str:
    """Search the local Exploit-DB archive using Searchsploit to find known public exploits."""
    clean_q = query.strip()
    return run_argv("searchsploit", [clean_q], timeout=60)


@tool(args_schema=LinpeasScanInput)
def linpeas_privilege_escalation_scan(script_path: Optional[str] = None) -> str:
    """Run LinPEAS locally to discover system misconfigurations, SUID binaries, or stored credentials."""
    target_script = find_wordlist(
        script_path or "/usr/share/peass-ng/linux/linpeas.sh",
        [
            "/usr/share/peass/linpeas/linpeas.sh",
            "/usr/local/bin/linpeas.sh",
            "/opt/linpeas.sh",
            "/tmp/linpeas.sh",
        ],
    )
    if not (os.path.exists(target_script) and os.path.isfile(target_script)):
        return f"[TOOL ERROR] linpeas.sh script not found at {target_script}. Install with: sudo apt install peass-ng"
    return run_argv("sh", [target_script, "-s", "-q"], timeout=240, max_output=5000)


@tool(args_schema=ImpacketToolInput)
def impacket_tool_execute(tool_name: str, target: str, connection_string: str, extra_args: str = "") -> str:
    """Execute various Impacket framework tools for Windows/Active Directory assessment."""
    host = clean_target(target)
    bin_name = tool_name.strip()
    argv = [f"{connection_string}@{host}"]
    if extra_args:
        argv.extend(shlex.split(extra_args))
    return run_argv(bin_name, argv, target=host, timeout=180)


@tool(args_schema=ShellExecInput)
def shell_exec(cmd: str, timeout: int = 60) -> str:
    """Execute an arbitrary command on the host system. Use with extreme caution."""
    safe_timeout = max(5, min(int(timeout), 300))
    return run_cmd(cmd, timeout=safe_timeout, max_output=3000)


@tool(args_schema=CVELookupInput)
def cve_lookup(query: str) -> str:
    """Lookup vulnerability details from NVD API and check local Exploit-DB archive."""
    results = []
    clean_q = query.strip()
    try:
        if clean_q.upper().startswith("CVE-"):
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={clean_q.upper()}"
        else:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={requests.utils.quote(clean_q)}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", [])[:5]:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                desc = cve.get("descriptions", [{}])[0].get("value", "")[:250]
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                cvss = metrics[0].get("cvssData", {}).get("baseScore", "") if metrics else ""
                exploit_msg = "No public exploit found in local DB"
                try:
                    if shutil.which("searchsploit"):
                        ss_out = run_argv("searchsploit", ["--cve", cve_id, "-w"], timeout=10)
                        if "Exploit" in ss_out and "No Results" not in ss_out:
                            exploit_msg = "Public exploit available"
                except Exception:
                    pass
                results.append(f"{cve_id} | CVSS v3: {cvss} | Exploit: {exploit_msg}\n{desc}")
        else:
            return f"NVD API returned status code {resp.status_code}"
    except Exception as e:
        return f"CVE lookup failed: {str(e)}"
    return "\n\n".join(results) if results else f"No CVEs found for query '{clean_q}'."


@tool(args_schema=BloodhoundAnalyzeInput)
def bloodhound_analyze(zip_path: str) -> str:
    """Analyze a SharpHound collection zip file locally using an in-memory directed graph (NetworkX)."""
    if not (os.path.exists(zip_path) and os.path.isfile(zip_path)):
        return f"[TOOL ERROR] BloodHound zip file not found at '{zip_path}'"
    G = nx.DiGraph()
    try:
        with zipfile.ZipFile(zip_path, 'r') as zh:
            for fname in zh.namelist():
                if fname.endswith('.json'):
                    with zh.open(fname) as f:
                        data = json.load(f)
                    for obj in data.get("data", []):
                        oid = obj.get("ObjectIdentifier", "")
                        props = obj.get("Properties", {})
                        label = props.get("name", oid)
                        obj_type = props.get("objectclass", "") or obj.get("ObjectType", "")
                        if "User" in obj_type:
                            node = f"USER:{label}"
                        elif "Group" in obj_type:
                            node = f"GROUP:{label}"
                        elif "Computer" in obj_type:
                            node = f"COMPUTER:{label}"
                        else:
                            continue
                        G.add_node(node, raw_type=obj_type, sid=oid)
                        for member_of_sid in props.get("memberofsids", []):
                            G.add_edge(node, f"GROUP:{member_of_sid}", rel="MemberOf")
        da_nodes = [n for n in G.nodes if "DOMAIN ADMINS" in n.upper()]
        user_nodes = [n for n in G.nodes if n.startswith("USER:")]
        output = []
        for user in user_nodes[:10]:
            for da in da_nodes:
                try:
                    path = nx.shortest_path(G, source=user, target=da)
                    if len(path) <= 10:
                        output.append(" -> ".join(path))
                except nx.NetworkXNoPath:
                    pass
        return "Attack paths to Domain Admins:\n" + "\n".join(output[:5]) if output else "No path to Domain Admins found."
    except Exception as e:
        return f"BloodHound analysis failed: {str(e)}"
