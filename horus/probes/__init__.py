"""Probe pack loading.

Probe packs are authored in YAML (see ``packs/``) and loaded into immutable
``Probe`` objects. Each pack's content is hashed so a run manifest records
exactly which version of which pack was used — essential for reproducibility
and regression tracking.

Design boundary
---------------
The framework ships only a *small, illustrative* set of publicly-documented,
low-potency probes — enough to demonstrate every code path end-to-end. It is
built to be extended: operators supply their own packs, drawn from public
research, for the specific system they are authorised to test. The value of
this project is the harness, not a library of exploits.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from ..models import Category, JudgeKind, Probe, Severity, Turn


def _coerce_turns(raw: Any) -> tuple[Turn, ...]:
    # A probe may be a single string (one user turn) or a list of role/content.
    if isinstance(raw, str):
        return (Turn(role="user", content=raw),)
    turns = []
    for item in raw:
        turns.append(Turn(role=item.get("role", "user"), content=item["content"]))
    return tuple(turns)


def _probe_from_dict(d: dict[str, Any]) -> Probe:
    return Probe(
        id=d["id"],
        category=Category(d["category"]),
        severity=Severity(d.get("severity", "medium")),
        turns=_coerce_turns(d["prompt"]),
        expectation=d["expectation"],
        fail_regexes=tuple(d.get("fail_regexes", [])),
        canaries=tuple(d.get("canaries", [])),
        source=d.get("source", ""),
        tags=tuple(d.get("tags", [])),
        judge=JudgeKind(d.get("judge", "ensemble")),
    )


def load_pack(path: str | Path) -> tuple[list[Probe], str]:
    """Load one YAML pack. Returns (probes, sha256_hash_of_file)."""
    path = Path(path)
    raw_bytes = path.read_bytes()
    file_hash = hashlib.sha256(raw_bytes).hexdigest()[:16]
    data = yaml.safe_load(raw_bytes)
    probes = [_probe_from_dict(p) for p in data.get("probes", [])]
    return probes, file_hash


def load_packs(paths: list[str | Path]) -> tuple[list[Probe], dict[str, str]]:
    """Load several packs. Returns (all_probes, {pack_name: hash})."""
    all_probes: list[Probe] = []
    hashes: dict[str, str] = {}
    seen_ids: set[str] = set()
    for p in paths:
        probes, h = load_pack(p)
        for probe in probes:
            if probe.id in seen_ids:
                raise ValueError(f"Duplicate probe id across packs: {probe.id}")
            seen_ids.add(probe.id)
        all_probes.extend(probes)
        hashes[Path(p).name] = h
    return all_probes, hashes
