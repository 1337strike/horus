"""Machine-readable export.

An HTML report is for a person. A pipeline needs something it can gate on, and
a security team needs findings in the same shape as the rest of their tooling.
Horus exports SARIF 2.1.0 — the format GitHub code scanning, Azure DevOps and
most SAST dashboards already ingest — plus a plain JSON dump for anything else.

Redaction
---------
Exports are redacted by default. Canary tokens are secrets planted in the
target's configuration: if one appears in an export, and that export is
uploaded to a CI artifact store or a code-scanning dashboard, the canary is
burned and every future run using it is worthless. Worse, the artifact now
contains the client's real secret in a place with weaker access control than the
system it came from.

So the exporter replaces canary values with a stable placeholder. The finding
still says a canary leaked and which probe caught it — that is the security
fact. The secret itself stays out of the pipeline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import Category, Outcome, Probe, Severity
from .taxonomy import entry_for

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

REDACTED = "[REDACTED:CANARY]"


@dataclass
class Finding:
    probe_id: str
    category: str
    severity: Severity
    outcome: Outcome
    confidence: float
    rationale: str
    request: list[dict[str, str]]
    response: str
    tool_calls: list[dict[str, Any]]
    repeat_index: int


def redact(text: str, secrets: set[str]) -> str:
    """Remove planted secrets from anything leaving the run database."""
    if not text:
        return text
    for s in secrets:
        if s:
            text = text.replace(s, REDACTED)
    return text


def collect_findings(probes: list[Probe], attempts, verdicts) -> list[Finding]:
    by_id = {p.id: p for p in probes}
    by_attempt = {a.attempt_id: a for a in attempts}
    secrets = {c for p in probes for c in p.canaries}

    out: list[Finding] = []
    for v in verdicts:
        if v.outcome not in (Outcome.FAIL, Outcome.PARTIAL):
            continue
        a = by_attempt.get(v.attempt_id)
        p = by_id.get(v.probe_id)
        if a is None or p is None:
            continue
        out.append(
            Finding(
                probe_id=v.probe_id,
                category=p.category.value,
                severity=p.severity,
                outcome=v.outcome,
                confidence=v.confidence,
                rationale=redact(v.rationale, secrets),
                request=[
                    {"role": m.get("role", ""),
                     "content": redact(m.get("content", ""), secrets)}
                    for m in a.request
                ],
                response=redact(a.response_text, secrets),
                tool_calls=json.loads(redact(json.dumps(a.tool_calls), secrets)),
                repeat_index=a.repeat_index,
            )
        )
    return out


def to_sarif(findings: list[Finding], manifest, *, tool_version: str = "0.1.0") -> dict:
    """SARIF 2.1.0. Rules are categories; results are failing attempts."""
    cats = sorted({f.category for f in findings})
    rules = []
    for c in cats:
        try:
            e = entry_for(Category(c))
            desc, owasp, atlas = e.summary, e.owasp_llm, ", ".join(e.atlas) or "—"
        except (ValueError, KeyError):  # category outside the taxonomy
            desc, owasp, atlas = c, "", ""
        rules.append({
            "id": c,
            "name": c.replace("_", " ").title().replace(" ", ""),
            "shortDescription": {"text": desc},
            "fullDescription": {"text": f"{desc} OWASP {owasp}; MITRE ATLAS {atlas}."},
            "properties": {"owasp-llm": owasp, "mitre-atlas": atlas, "tags": ["security", "llm"]},
        })

    results = []
    for f in findings:
        results.append({
            "ruleId": f.category,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {
                "text": f"{f.probe_id} ({f.outcome.value}, confidence "
                        f"{f.confidence:.2f}): {f.rationale}"
            },
            # Probes are not source files, but SARIF requires a location; the
            # probe pack is the closest honest analogue.
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"probes/{f.probe_id}"},
                    "region": {"startLine": 1},
                }
            }],
            "partialFingerprints": {"probeId": f.probe_id},
            "properties": {
                "repeatIndex": f.repeat_index,
                "confidence": f.confidence,
                "toolCalls": f.tool_calls,
            },
        })

    t = manifest.target
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Horus",
                "version": tool_version,
                "informationUri": "https://github.com/1337strike/horus",
                "rules": rules,
            }},
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": manifest.started_at,
                "endTimeUtc": manifest.finished_at or manifest.started_at,
                "properties": {
                    "runId": manifest.run_id,
                    "target": t.model_snapshot if t else "",
                    "repeats": manifest.repeats,
                    "threatModelId": manifest.threat_model_id,
                    "probePackHashes": manifest.probe_pack_hashes,
                    "spentUsd": manifest.spent_usd,
                },
            }],
            "results": results,
        }],
    }


def to_json(findings: list[Finding], manifest, summary=None) -> dict:
    t = manifest.target
    doc: dict[str, Any] = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "run": {
            "id": manifest.run_id,
            "startedAt": manifest.started_at,
            "finishedAt": manifest.finished_at,
            "target": {
                "kind": t.kind if t else "",
                "modelSnapshot": t.model_snapshot if t else "",
                "endpoint": t.endpoint if t else "",
            },
            "repeats": manifest.repeats,
            "threatModelId": manifest.threat_model_id,
            "probePackHashes": manifest.probe_pack_hashes,
            "budgetUsd": manifest.budget_usd,
            "spentUsd": manifest.spent_usd,
            "notes": manifest.notes,
        },
        "findings": [
            {
                "probeId": f.probe_id, "category": f.category,
                "severity": f.severity.value, "outcome": f.outcome.value,
                "confidence": f.confidence, "rationale": f.rationale,
                "repeatIndex": f.repeat_index,
                "request": f.request, "response": f.response,
                "toolCalls": f.tool_calls,
            }
            for f in findings
        ],
    }
    if summary is not None:
        doc["summary"] = {
            "overallAttackSuccessRate": round(summary.overall_asr, 4),
            "totalAttempts": summary.total_attempts,
            "errors": summary.errors,
            "categories": [
                {
                    "category": c.category.value,
                    "rate": round(c.rate, 4),
                    "fails": c.fails, "partials": c.partials,
                    "graded": c.graded, "errors": c.errors,
                    "ci95": [round(c.ci[0], 4), round(c.ci[1], 4)],
                    "ungraded": c.is_ungraded,
                }
                for c in summary.attack_categories
            ],
            "overRefusalRate": (round(summary.refusal_stat.rate, 4)
                                if summary.refusal_stat else None),
        }
    return doc


_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def worst_finding_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max(findings, key=lambda f: _SEV_ORDER.index(f.severity.value)).severity.value


def exceeds(findings: list[Finding], threshold: str) -> bool:
    """True when any finding is at or above ``threshold`` — the CI gate."""
    if threshold not in _SEV_ORDER:
        raise ValueError(f"unknown severity threshold: {threshold!r}")
    limit = _SEV_ORDER.index(threshold)
    return any(_SEV_ORDER.index(f.severity.value) >= limit for f in findings)
