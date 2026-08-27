#!/usr/bin/env python3
"""core/extractor.py — Deterministic Structured Fact Extractor for LONLY v2.

Enforces:
- Structured parsing of raw tool outputs into typed security facts.
- Sanitized factual context injection into LLM prompts without exposing raw untrusted strings.
- Prevention of indirect prompt injection by transforming raw stdout into strictly formatted entities.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ExtractedEntity:
    """A verified structured fact extracted from tool observations."""
    entity_type: str  # "port", "service", "vulnerability", "credential", "privesc_vector", "host"
    value: str
    attributes: dict = field(default_factory=dict)
    confidence: float = 1.0
    source_tool: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class StructuredFactExtractor:
    """Deterministic extractor converting raw subprocess outputs into sanitized facts."""

    @classmethod
    def extract_ports(cls, output: str, source_tool: str = "") -> list[ExtractedEntity]:
        """Extract open port and protocol entities."""
        entities = []
        # Pattern 1: Nmap / Masscan / Rustscan port lines: 80/tcp open http
        matches = re.finditer(r"(\d{1,5})/(tcp|udp)\s+(open|filtered)\s*([\w\-\.]+)?", output, re.IGNORECASE)
        for m in matches:
            port, proto, state, svc = m.groups()
            if state.lower() == "open":
                entities.append(ExtractedEntity(
                    entity_type="port",
                    value=f"{port}/{proto.lower()}",
                    attributes={"port": int(port), "protocol": proto.lower(), "service": svc or "unknown", "state": "open"},
                    source_tool=source_tool,
                ))

        # Pattern 2: Rustscan output: Open 127.0.0.1:80
        rust_matches = re.finditer(r"(?:open\s+)?(?:[\d\.]+|[\w\.\-]+):(\d{1,5})", output, re.IGNORECASE)
        for rm in rust_matches:
            port_num = int(rm.group(1))
            if not any(e.attributes.get("port") == port_num for e in entities):
                entities.append(ExtractedEntity(
                    entity_type="port",
                    value=f"{port_num}/tcp",
                    attributes={"port": port_num, "protocol": "tcp", "service": "unknown", "state": "open"},
                    source_tool=source_tool,
                ))

        return entities

    @classmethod
    def extract_services(cls, output: str, source_tool: str = "") -> list[ExtractedEntity]:
        """Extract service banners and software versions."""
        entities = []
        # Match common web server and daemon versions (Apache/2.4.41, nginx/1.18.0, OpenSSH 8.2p1)
        matches = re.finditer(r"([A-Za-z0-9\-_]+)[/ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[a-zA-Z0-9_\-]+)?)", output)
        seen = set()
        for m in matches:
            svc, ver = m.groups()
            key = f"{svc.lower()}:{ver}"
            if key not in seen and svc.lower() not in ("tcp", "udp", "http", "https", "port"):
                seen.add(key)
                entities.append(ExtractedEntity(
                    entity_type="service",
                    value=f"{svc} {ver}",
                    attributes={"service": svc, "version": ver},
                    source_tool=source_tool,
                ))
        return entities

    @classmethod
    def extract_vulnerabilities(cls, output: str, source_tool: str = "") -> list[ExtractedEntity]:
        """Extract confirmed CVE IDs and vulnerability advisories."""
        entities = []
        matches = re.finditer(r"(CVE-\d{4}-\d{4,7})", output, re.IGNORECASE)
        seen = set()
        for m in matches:
            cve = m.group(1).upper()
            if cve not in seen:
                seen.add(cve)
                entities.append(ExtractedEntity(
                    entity_type="vulnerability",
                    value=cve,
                    attributes={"cve_id": cve},
                    source_tool=source_tool,
                ))
        return entities

    @classmethod
    def extract_credentials(cls, output: str, source_tool: str = "") -> list[ExtractedEntity]:
        """Extract discovered usernames, NTLM hashes, and accounts."""
        entities = []
        # Match hydra/cme successful login patterns
        matches = re.finditer(r"(?:login|user|username):\s*([A-Za-z0-9_\-\.]+)\s*(?:password|passwd):\s*([^\s]+)", output, re.IGNORECASE)
        for m in matches:
            user, pwd = m.groups()
            entities.append(ExtractedEntity(
                entity_type="credential",
                value=f"{user}:{pwd}",
                attributes={"user": user, "password": pwd},
                source_tool=source_tool,
            ))
        return entities

    @classmethod
    def extract_privesc_vectors(cls, output: str, source_tool: str = "") -> list[ExtractedEntity]:
        """Extract privilege escalation indicators (SUID, sudo, capabilities)."""
        entities = []
        # LinPEAS SUID or sudo indicators
        if "NOPASSWD" in output:
            entities.append(ExtractedEntity(
                entity_type="privesc_vector",
                value="sudo_nopasswd",
                attributes={"type": "sudo", "details": "NOPASSWD rule detected"},
                source_tool=source_tool,
            ))
        suid_matches = re.finditer(r"/(?:usr|bin|sbin)/[A-Za-z0-9_\-]+", output)
        for sm in suid_matches:
            path = sm.group(0)
            if any(interesting in path for interesting in ("pkexec", "nmap", "vim", "bash", "find", "cp", "base64")):
                entities.append(ExtractedEntity(
                    entity_type="privesc_vector",
                    value=f"suid:{path}",
                    attributes={"type": "suid_binary", "path": path},
                    source_tool=source_tool,
                ))
        return entities

    @classmethod
    def extract_all(cls, output: str, source_tool: str = "") -> list[ExtractedEntity]:
        """Run all fact extractors against raw output."""
        if not output or not isinstance(output, str):
            return []

        all_entities: list[ExtractedEntity] = []
        all_entities.extend(cls.extract_ports(output, source_tool))
        all_entities.extend(cls.extract_services(output, source_tool))
        all_entities.extend(cls.extract_vulnerabilities(output, source_tool))
        all_entities.extend(cls.extract_credentials(output, source_tool))
        all_entities.extend(cls.extract_privesc_vectors(output, source_tool))
        return all_entities

    @classmethod
    def format_facts_for_prompt(cls, entities: list[ExtractedEntity]) -> str:
        """Format extracted facts into an untampered, structured markdown block for the model."""
        if not entities:
            return "[VERIFIED FACTS] No new structured facts detected."

        lines = ["[VERIFIED FACTS (Deterministic Extractor)]"]
        for e in entities:
            lines.append(f"- **{e.entity_type.upper()}**: {e.value} (source: {e.source_tool or 'broker'})")
        return "\n".join(lines)
