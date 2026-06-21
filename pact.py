import cmd
import subprocess
import shlex
import os
import zipfile
import json
import requests
import time
import networkx as nx
import re
from pydantic import BaseModel, Field
from typing import Literal, Optional
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage,  ToolMessage

def run_cmd(cmd: str, timeout: int = 120, max_out: int = 4000) -> str:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        if len(output) > max_out:
            output = output[:max_out] + "\n... [OUTPUT TRUNCATED]"
        return output.strip() or "[Command executed sucecesssfully with no output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s limit: {cmd}"
    except Exception as e:
        return f"[ERROR] {str(e)}"

def parse_react_response(text: str):
    """Extarct Action and Action Input from LLM response."""
    action_match = re.search(f"Action:\s*(\w+)", text)
    input_match = re.search(r"Action Input:\s*(\{.*?\})", text, re.DOTALL)
    if action_match and input_match:
        tool_name = action_match.group(1)
        try:
            tool_args = json.loads(input_match.group(1))
            return tool_name, tool_args
        except json.JSONDecdoeError:
            return None, None
    return None, None

def extarct_final_awnser(text: str):
    """Extract Final Awnser from LLM response."""
    match = re.search(r"Final Awnser:\s*(.*)", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None

class NmapScanInput(BaseModel):
    target: str = Field(..., description="The target to scan. Can be a single IP, domain, or CIDR range. CRTICAL: Do Not include protocol prefixes like 'http://'.")
    port: Optional[str] = Field(default=None, description="Specific ports to scan, separated by commas (e.g., '80,443'). if None, scans top 1000 ports.")
    scan_type: Literal["SYN", "Connect", "Version", "OS", "Aggressive"] = Field(default="Version", description="Technical type of Nmap scan to execute.")
    timing: Literal["T0","T1","T2","T3","T4","T5"] = Field(default="Version", description="Nmap timing template for speed.")
    use_default_script: bool = Field(default=False, description="Set a True to enable default script scanning (-sC).")

class NiktoScanInput(BaseModel):
    target_host: str = Field(..., description="The target web server to scan. Do not include trailing slashes.")
    port: Optional[str] = Field(default=None, description="Specific HTTP/HTTPS port to scan.")
    use_ssl: bool = Field(default=False, description="Set to True if target web server users HTTPS.")
    tuning: Optional[str] = Field(default=None, description="Scan tuning optional (-Tuning) to specific test types.")

class CrackMapExecInput(BaseModel):
    target: str = Field(description="เป้าหมายที่ต้องการทดสอบ เช่น IP หรือวงเครือข่าย CIDR")
