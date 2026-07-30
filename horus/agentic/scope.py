"""Scope enforcement.

This is the control that makes infrastructure testing safe to ship, and it is
exactly what the tool this capability was modelled on does not have. There,
"scope" is descriptive metadata that nothing checks. Here it is a gate: a run
against an infrastructure agent refuses to start unless the target resolves to
something you declared in writing.

The threat this defends against is not a malicious operator — it is a fat
finger. A homelab test that accidentally points at a public IP, a neighbour's
box, or a cloud metadata endpoint is how "just testing my own stuff" becomes an
incident. So the scope file is allowlist-first: nothing is in scope unless it
matches an allow rule, and an explicit deny always wins.

Scope is checked against the *resolved* address, not the hostname, because a
name you control can resolve to an address you do not. Private-by-default is
available as a coarse allow rule for a homelab, but the deny list still applies
on top of it so you can carve out, say, the router's management interface.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml


@dataclass
class ScopeResult:
    allowed: bool
    target: str
    resolved: str | None
    reason: str


@dataclass
class Scope:
    """An allowlist-first declaration of what may be tested."""

    allow_hosts: tuple[str, ...] = ()      # exact hostnames / IPs
    allow_cidrs: tuple[str, ...] = ()      # e.g. 10.0.0.0/8, 192.168.0.0/16
    allow_private: bool = False            # coarse allow: all RFC1918 + loopback
    deny_hosts: tuple[str, ...] = ()
    deny_cidrs: tuple[str, ...] = ()
    # Cloud metadata endpoints are denied unless you very deliberately allow
    # them: an agent tricked into reading 169.254.169.254 is a classic SSRF-to-
    # credential-theft chain, so the default posture is to refuse.
    deny_metadata: bool = True

    _METADATA = ("169.254.169.254", "fd00:ec2::254", "metadata.google.internal")

    @staticmethod
    def load(path: str | Path) -> "Scope":
        d = yaml.safe_load(Path(path).read_text()) or {}
        return Scope(
            allow_hosts=tuple(d.get("allow_hosts", [])),
            allow_cidrs=tuple(d.get("allow_cidrs", [])),
            allow_private=bool(d.get("allow_private", False)),
            deny_hosts=tuple(d.get("deny_hosts", [])),
            deny_cidrs=tuple(d.get("deny_cidrs", [])),
            deny_metadata=bool(d.get("deny_metadata", True)),
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _host_of(target: str) -> str:
        """Pull a hostname/IP out of a URL or a bare host[:port]."""
        if "://" in target:
            return urlparse(target).hostname or ""
        # bare host or host:port (but not an IPv6 literal without brackets)
        if target.count(":") == 1:
            return target.split(":")[0]
        return target

    @staticmethod
    def _resolve(host: str) -> str | None:
        try:
            ipaddress.ip_address(host)
            return host  # already an IP
        except ValueError:
            pass
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            return None

    def _in_any_cidr(self, ip: ipaddress._BaseAddress, cidrs) -> bool:
        for c in cidrs:
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def check(self, target: str) -> ScopeResult:
        host = self._host_of(target)
        if not host:
            return ScopeResult(False, target, None, "could not parse a host from target")

        resolved = self._resolve(host)
        if resolved is None:
            return ScopeResult(False, target, None, f"host {host!r} did not resolve")

        try:
            ip = ipaddress.ip_address(resolved)
        except ValueError:
            return ScopeResult(False, target, resolved, "resolved address is not an IP")

        # --- Denies win, always, and are evaluated first. ---
        if self.deny_metadata and (
            resolved in self._METADATA or host in self._METADATA
        ):
            return ScopeResult(False, target, resolved,
                               "cloud metadata endpoint is denied (SSRF guard)")
        if host in self.deny_hosts or resolved in self.deny_hosts:
            return ScopeResult(False, target, resolved, "target is on the deny list")
        if self._in_any_cidr(ip, self.deny_cidrs):
            return ScopeResult(False, target, resolved, "target is in a denied CIDR")

        # --- Then allows. Nothing is in scope unless something allows it. ---
        if host in self.allow_hosts or resolved in self.allow_hosts:
            return ScopeResult(True, target, resolved, "host explicitly allowed")
        if self._in_any_cidr(ip, self.allow_cidrs):
            return ScopeResult(True, target, resolved, "address in an allowed CIDR")
        if self.allow_private and (ip.is_private or ip.is_loopback):
            return ScopeResult(True, target, resolved, "private address, allow_private set")

        return ScopeResult(False, target, resolved,
                           "not matched by any allow rule (allowlist-first)")

    @property
    def is_configured(self) -> bool:
        return bool(
            self.allow_hosts or self.allow_cidrs or self.allow_private
        )
