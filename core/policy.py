#!/usr/bin/env python3
"""core/policy.py — Deterministic Security & Target Policy Engine for LONLY v2.

Provides:
- TargetPolicy: RFC-compliant URL & IP (v4/v6) parser, CIDR evaluator, and scope validator.
- CapabilityPolicy: Structured capability authorization descriptors.
"""
from __future__ import annotations

import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TargetPolicy:
    """Enterprise-grade scope authorization policy engine."""
    allowed_targets: list[str] = field(default_factory=list)
    allowed_ports: set[int] = field(default_factory=set)  # empty = all in-scope ports allowed

    @staticmethod
    def canonicalize_host(target: str) -> tuple[str, Optional[int]]:
        """Extract canonical host and port from raw IP, domain, bracketed IPv6, or URL."""
        if not target or not isinstance(target, str):
            return "", None
        
        t = target.strip()
        
        # 1. URL parsing (if scheme present or starts with //)
        if "://" in t or t.startswith("//"):
            try:
                parsed = urllib.parse.urlsplit(t)
                hostname = parsed.hostname or ""
                port = parsed.port
                return hostname.lower().rstrip("."), port
            except Exception:
                pass

        # 2. Bracketed IPv6 e.g. [::1]:8080 or [::1]
        if t.startswith("["):
            end_bracket = t.find("]")
            if end_bracket != -1:
                host_part = t[1:end_bracket]
                port_part = t[end_bracket + 1:].lstrip(":")
                port = int(port_part) if port_part.isdigit() else None
                return host_part.lower(), port

        # 3. IPv4 with port or Hostname with port e.g. 192.168.1.1:80 or host:80
        # If it contains exactly one colon and looks like host:port
        if t.count(":") == 1:
            host_part, port_str = t.split(":", 1)
            if port_str.isdigit():
                return host_part.lower().rstrip("."), int(port_str)

        # 4. Pure IPv6 (multiple colons) e.g. ::1 or 2001:db8::1
        if ":" in t:
            try:
                ipaddress.IPv6Address(t)
                return t.lower(), None
            except ValueError:
                pass

        # 5. Pure IPv4 or Hostname
        # Strip any accidental path segments if URL was missing scheme (e.g. 127.0.0.1/admin)
        clean_host = t.split("/")[0].split("?")[0].split("#")[0].strip()
        return clean_host.lower().rstrip("."), None

    def is_in_scope(self, target: str) -> bool:
        """Determines if target is strictly within authorized scope."""
        host, port = self.canonicalize_host(target)
        if not host:
            return False

        # Port validation if restricted
        if self.allowed_ports and port is not None and port not in self.allowed_ports:
            return False

        # Lab-safe default (if allowed_targets is empty) -> loopback only
        if not self.allowed_targets:
            if host in ("localhost", "127.0.0.1", "::1"):
                return True
            try:
                ip_obj = ipaddress.ip_address(host)
                return ip_obj.is_loopback
            except ValueError:
                return False

        # Evaluate against allowed_targets entries
        for entry in self.allowed_targets:
            entry = entry.strip().lower().rstrip(".")
            
            # Exact hostname or IP match
            if entry == host:
                return True

            # Domain suffix match (e.g. '.lab.local' or 'lab.local')
            if entry.startswith(".") and (host.endswith(entry) or host == entry[1:]):
                return True
            if not entry.startswith(".") and (host == entry or host.endswith("." + entry)):
                # If entry is not an IP and looks like domain
                if not any(c.isdigit() for c in entry.split(".")):
                    return True

            # CIDR network match (IPv4 and IPv6)
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    ip_obj = ipaddress.ip_address(host)
                    if ip_obj in net:
                        return True
                except ValueError:
                    continue

            # Exact IP object match
            try:
                if ipaddress.ip_address(host) == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                pass

        return False


from enum import Enum


class ActionClass(str, Enum):
    """Categorization of tool action types for policy evaluation."""
    READ_ONLY = "READ_ONLY"
    ENUMERATION = "ENUMERATION"
    AUTHENTICATION_TEST = "AUTHENTICATION_TEST"
    EXPLOITATION = "EXPLOITATION"
    HOST_EXECUTION = "HOST_EXECUTION"


class RiskClass(str, Enum):
    """Multi-dimensional risk classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NetworkAccess(str, Enum):
    """Network directionality requirements."""
    NONE = "NONE"
    OUTBOUND = "OUTBOUND"
    INBOUND = "INBOUND"
    FULL = "FULL"


@dataclass
class CapabilityManifest:
    """Formal security manifest specifying tool execution parameters and authorization bounds."""
    capability_id: str = ""
    executable: str = ""
    action_class: ActionClass | str = ActionClass.READ_ONLY
    risk_class: RiskClass | str = RiskClass.LOW
    network_access: NetworkAccess | str = NetworkAccess.OUTBOUND
    credentials_required: bool = False
    requires_approval: bool = False
    is_blocked_by_default: bool = False
    max_duration: int = 120
    max_output: int = 4000
    rate_limit_per_min: int = 60
    sandbox_profile: str = "default"
    risk_points: int = 1
    risk_description: str = ""
    version: str = "1.0.0"
    name: str = ""
    requires_confirmation: bool = False

    def __post_init__(self):
        if not self.capability_id and self.name:
            self.capability_id = self.name
        if not self.name and self.capability_id:
            self.name = self.capability_id
        if self.requires_confirmation:
            self.requires_approval = True
        if self.requires_approval:
            self.requires_confirmation = True


# Backwards compatibility alias
CapabilityDescriptor = CapabilityManifest


class CapabilityPolicy:
    """Deterministic capability authorization policy engine."""

    def __init__(self, manifests: Optional[dict[str, CapabilityManifest]] = None):
        self._manifests: dict[str, CapabilityManifest] = manifests or self._default_manifests()

    def register(self, manifest: CapabilityManifest) -> None:
        self._manifests[manifest.capability_id] = manifest
        self._manifests[manifest.executable] = manifest

    def get(self, identifier: str) -> Optional[CapabilityManifest]:
        return self._manifests.get(identifier)

    def authorize(
        self, capability_name: str, has_operator_approval: bool = False
    ) -> tuple[bool, str]:
        """Authorize capability execution against policy."""
        manifest = self.get(capability_name)
        if manifest is None:
            # If not explicitly manifested, allow default LOW risk or require approval for dangerous names
            return True, "Default authorized"

        if manifest.is_blocked_by_default:
            return False, f"[POLICY BLOCKED] Capability '{manifest.capability_id}' is permanently blocked by policy."

        if manifest.requires_approval and not has_operator_approval:
            return False, (
                f"[APPROVAL REQUIRED] Capability '{manifest.capability_id}' requires explicit operator approval "
                f"({manifest.risk_description or manifest.risk_class})."
            )

        return True, "Authorized"

    @classmethod
    def _default_manifests(cls) -> dict[str, CapabilityManifest]:
        manifests: dict[str, CapabilityManifest] = {}
        defaults = [
            CapabilityManifest("nmap_security_scan", "nmap", ActionClass.ENUMERATION, RiskClass.LOW, risk_points=1),
            CapabilityManifest("rustscan_port_scan", "rustscan", ActionClass.ENUMERATION, RiskClass.LOW, risk_points=1),
            CapabilityManifest("masscan_port_scan", "masscan", ActionClass.ENUMERATION, RiskClass.LOW, risk_points=1),
            CapabilityManifest("whatweb_web_fingerprint", "whatweb", ActionClass.READ_ONLY, RiskClass.LOW, risk_points=1),
            CapabilityManifest("gobuster_directory_scan", "gobuster", ActionClass.ENUMERATION, RiskClass.LOW, max_output=3000, risk_points=1),
            CapabilityManifest("ffuf_web_fuzz", "ffuf", ActionClass.ENUMERATION, RiskClass.LOW, max_output=3000, risk_points=1),
            CapabilityManifest("nikto_web_scan", "nikto", ActionClass.ENUMERATION, RiskClass.MEDIUM, risk_points=1, risk_description="intrusive web vulnerability scan"),
            CapabilityManifest("sqlmap_vulnerability_assessment", "sqlmap", ActionClass.EXPLOITATION, RiskClass.HIGH, risk_points=1, risk_description="automated SQL injection testing"),
            CapabilityManifest("wpscan_wordpress_audit", "wpscan", ActionClass.ENUMERATION, RiskClass.LOW, risk_points=1),
            CapabilityManifest("enum4linux_smb_audit", "enum4linux", ActionClass.ENUMERATION, RiskClass.MEDIUM, risk_points=1, risk_description="SMB protocol enumeration"),
            CapabilityManifest("crackmapexec", "crackmapexec", ActionClass.AUTHENTICATION_TEST, RiskClass.HIGH, credentials_required=True, requires_approval=True, risk_points=2, risk_description="network authentication and credential spraying"),
            CapabilityManifest("ldap_search_enumeration", "ldapsearch", ActionClass.ENUMERATION, RiskClass.LOW, risk_points=1),
            CapabilityManifest("kerbrute_active_directory_assessment", "kerbrute", ActionClass.AUTHENTICATION_TEST, RiskClass.MEDIUM, risk_points=1),
            CapabilityManifest("hydra_brute_force", "hydra", ActionClass.AUTHENTICATION_TEST, RiskClass.HIGH, credentials_required=True, requires_approval=True, risk_points=2, risk_description="network service brute-forcing"),
            CapabilityManifest("searchsploit_exploit_lookup", "searchsploit", ActionClass.READ_ONLY, RiskClass.LOW, network_access=NetworkAccess.NONE, risk_points=1),
            CapabilityManifest("metasploit_auxiliary_scanner", "msfconsole", ActionClass.EXPLOITATION, RiskClass.HIGH, requires_approval=True, risk_points=2, risk_description="Metasploit auxiliary scanner execution"),
            CapabilityManifest("linpeas_privilege_escalation_scan", "linpeas.sh", ActionClass.ENUMERATION, RiskClass.MEDIUM, max_output=5000, risk_points=1),
            CapabilityManifest("reverse_shell_listener", "nc", ActionClass.HOST_EXECUTION, RiskClass.HIGH, network_access=NetworkAccess.INBOUND, risk_points=1),
            CapabilityManifest("impacket_tool_execute", "impacket", ActionClass.AUTHENTICATION_TEST, RiskClass.HIGH, credentials_required=True, risk_points=1),
            CapabilityManifest("curl_web_request", "curl", ActionClass.READ_ONLY, RiskClass.LOW, risk_points=1),
            CapabilityManifest("shell_exec", "sh", ActionClass.HOST_EXECUTION, RiskClass.CRITICAL, requires_approval=True, max_output=3000, risk_points=2, risk_description="arbitrary host system command execution"),
            CapabilityManifest("cve_lookup", "cve_lookup", ActionClass.READ_ONLY, RiskClass.LOW, risk_points=1),
            CapabilityManifest("bloodhound_analyze", "bloodhound", ActionClass.READ_ONLY, RiskClass.LOW, network_access=NetworkAccess.NONE, risk_points=1),
            CapabilityManifest("rag_query", "rag_query", ActionClass.READ_ONLY, RiskClass.LOW, network_access=NetworkAccess.NONE, risk_points=1),
        ]
        for m in defaults:
            manifests[m.capability_id] = m
            manifests[m.executable] = m
        return manifests


DEFAULT_CAPABILITY_POLICY = CapabilityPolicy()
