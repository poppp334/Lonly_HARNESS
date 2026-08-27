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


@dataclass
class CapabilityDescriptor:
    """Specification of an authorized security capability."""
    name: str
    executable: str
    action_class: str  # recon, web, creds, infra, privesc
    risk_points: int = 1
    requires_confirmation: bool = False
    is_blocked_by_default: bool = False
    risk_description: str = ""
