#!/usr/bin/env python3
"""tools/infra.py — Infrastructure, exploitation, privesc, and intelligence tools for LONLY.

Wraps Searchsploit, LinPEAS, Impacket, ShellExec, CVELookup, Bloodhound, and RAGQuery.
"""

from __future__ import annotations

import json
import zipfile
from pydantic import BaseModel, Field
from langchain_core.tools import tool
import networkx as nx
import requests

from tools.base import run_cmd

try:
    from langchain_huggingface import HuggingFaceEmbeddings
    from langchain_chroma import Chroma
except ImportError:
    HuggingFaceEmbeddings = None  # type: ignore
    Chroma = None  # type: ignore


class SearchsploitInput(BaseModel):
    query: str = Field(..., description="The search term for exploits, vulnerability names, or software versions.")


class LinpeasScanInput(BaseModel):
    script_path: str = Field(default="/usr/share/peass/linpeas/linpeas.sh", description="The absolute path to the linpeas.sh script.")


class ImpacketToolInput(BaseModel):
    tool_name: str = Field(..., description="The specific Impacket tool script name (e.g., 'impacket-secretsdump').")
    target: str = Field(..., description="The target IP address or hostname of the Windows system.")
    connection_string: str = Field(..., description="The authentication identity string format: 'domain/username:password'.")
    extra_args: str = Field(default="", description="Optional additional command arguments.")


class ShellExecInput(BaseModel):
    cmd: str = Field(..., description="The exact and complete shell command to execute on the local environment.")
    timeout: int = Field(default=60, description="The maximum execution time allowed in seconds.")


class CVELookupInput(BaseModel):
    query: str = Field(..., description="The vulnerability identifier (CVE) or software detail to lookup.")


class BloodhoundAnalyzeInput(BaseModel):
    zip_path: str = Field(..., description="The absolute file path to the SharpHound data collection .zip archive.")


class RAGQueryInput(BaseModel):
    query: str = Field(..., description="The specific cybersecurity question or technique to search in knowledge base.")


rag_vectorstore = None


@tool(args_schema=RAGQueryInput)
def rag_query(query: str) -> str:
    """Retrieve relevant penetration testing knowledge, documentation, and technical cheat sheets from internal knowledge base."""
    global rag_vectorstore
    if rag_vectorstore is None:
        if HuggingFaceEmbeddings is None or Chroma is None:
            return "RAG dependencies not installed."
        try:
            embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
            rag_vectorstore = Chroma(persist_directory="chroma_db", embedding_function=embeddings)
        except Exception as e:
            return f"RAG initialization failed: {e}"
    docs = rag_vectorstore.similarity_search(query, k=3)
    if not docs:
        return "No relevant knowledge found."
    results = []
    for d in docs:
        source = d.metadata.get("source", "unknown")
        results.append(f"[Source: {source}]\n{d.page_content}")
    return "\n\n---\n".join(results)


@tool(args_schema=SearchsploitInput)
def searchsploit_exploit_lookup(query: str) -> str:
    """Search the local Exploit-DB archive using Searchsploit to find known public exploits."""
    cmd = f"searchsploit {query}"
    return run_cmd(cmd, timeout=60)


@tool(args_schema=LinpeasScanInput)
def linpeas_privilege_escalation_scan(script_path: str = "/usr/share/peass/linpeas/linpeas.sh") -> str:
    """Run LinPEAS locally to discover system misconfigurations or stored credentials."""
    cmd = f"sh {script_path} -s -q"
    return run_cmd(cmd, timeout=240, max_output=5000)


@tool(args_schema=ImpacketToolInput)
def impacket_tool_execute(tool_name: str, target: str, connection_string: str, extra_args: str = "") -> str:
    """Execute various Impacket framework tools for Windows/Active Directory assessment."""
    cmd = f"{tool_name} '{connection_string}'@{target} {extra_args}".strip()
    return run_cmd(cmd, timeout=180)


@tool(args_schema=ShellExecInput)
def shell_exec(cmd: str, timeout: int = 60) -> str:
    """Execute an arbitrary shell command on the host system. Use with extreme caution."""
    return run_cmd(cmd, timeout=timeout, max_output=3000)


@tool(args_schema=CVELookupInput)
def cve_lookup(query: str) -> str:
    """Lookup vulnerability details from NVD API and check local Exploit-DB archive."""
    results = []
    try:
        if query.upper().startswith("CVE-"):
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query}"
        else:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={requests.utils.quote(query)}"
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
                    ss_out = run_cmd(f"searchsploit --cve {cve_id} -w", timeout=10)
                    if "Exploit" in ss_out and "No Results" not in ss_out:
                        exploit_msg = "Public exploit available"
                except Exception:
                    pass
                results.append(f"{cve_id} | CVSS v3: {cvss} | Exploit: {exploit_msg}\n{desc}")
        else:
            return f"NVD API returned status code {resp.status_code}"
    except Exception as e:
        return f"CVE lookup failed: {str(e)}"
    return "\n\n".join(results) if results else "No CVEs found for this query."


@tool(args_schema=BloodhoundAnalyzeInput)
def bloodhound_analyze(zip_path: str) -> str:
    """Analyze a SharpHound collection zip file locally using an in-memory directed graph (NetworkX)."""
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
