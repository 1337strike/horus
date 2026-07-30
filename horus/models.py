"""Core domain models for the Horus red-team framework.

These dataclasses are the shared vocabulary of the whole system. Every module
(targets, probes, evaluator, orchestrator, reporting) speaks in terms of these
types, so the contract between components is explicit and testable.

Design notes
------------
* A ``Probe`` describes *what* we send and *how to judge it*. It is data, not
  behaviour — probe packs are authored in YAML and loaded into these objects.
* An ``Attempt`` is a single execution of a probe against a target (one of N
  repeats). Red-teaming is stochastic, so a probe rarely maps to one attempt.
* A ``Verdict`` is the judge's decision about one attempt, carrying a
  calibrated confidence and enough provenance to audit it later.
* A ``RunManifest`` captures everything needed to reproduce a run: model
  snapshot, params, probe pack hashes, timestamps. Reproducibility is a
  first-class concern, not an afterthought.
"""

from __future__ import annotations

import hashlib
import platform
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Taxonomy
# --------------------------------------------------------------------------- #
class Category(str, Enum):
    """Attack categories, mapped to public frameworks in taxonomy.py.

    Keeping this a small, closed enum (rather than free-form strings) means the
    report can guarantee coverage numbers per category and the calibration
    harness can slice metrics by category.
    """

    JAILBREAK = "jailbreak"
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    DATA_LEAKAGE = "data_leakage"
    GUARDRAIL_BYPASS = "guardrail_bypass"
    TOOL_ABUSE = "tool_abuse"  # agentic targets: unauthorised tool/action use
    # Second axis of the assessment: does the model wrongly refuse safe input?
    OVER_REFUSAL = "over_refusal"


class Outcome(str, Enum):
    """The four outcomes a judge can return.

    PASS/FAIL are from the *defender's* point of view:
      * PASS  = the target behaved safely (attack blocked, or benign request served)
      * FAIL  = the target misbehaved (attack succeeded, or benign request refused)
    PARTIAL captures leaks that are real but incomplete. ERROR is an
    infrastructure failure (timeout, malformed response) and must never be
    silently counted as a PASS.
    """

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    ERROR = "error"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class JudgeKind(str, Enum):
    DETERMINISTIC = "deterministic"
    LLM = "llm"
    ENSEMBLE = "ensemble"
    HUMAN = "human"


# --------------------------------------------------------------------------- #
# Probe: what we send + how to judge it
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Turn:
    """A single message in a (possibly multi-turn) probe."""

    role: str  # "user" | "system" | "tool" | "document"
    content: str


@dataclass(frozen=True)
class Probe:
    """A single test case.

    ``expectation`` states, in plain language, what a *safe* response looks
    like. The LLM judge receives this as its rubric anchor so the same probe
    can be reused across targets with different policies.
    """

    id: str
    category: Category
    severity: Severity
    turns: tuple[Turn, ...]
    expectation: str
    # Deterministic signals. If any regex/string here is found in the output,
    # the deterministic judge can decide the outcome without an LLM.
    fail_regexes: tuple[str, ...] = ()
    canaries: tuple[str, ...] = ()  # secret tokens that must never surface
    # Free-form provenance so operators can cite public research per probe.
    source: str = ""
    tags: tuple[str, ...] = ()
    # Which judge should own the final call for this probe.
    judge: JudgeKind = JudgeKind.ENSEMBLE

    def content_hash(self) -> str:
        """Stable hash of the probe payload, for regression tracking."""
        blob = "|".join(f"{t.role}:{t.content}" for t in self.turns)
        blob += f"||{self.expectation}||{self.category.value}"
        return hashlib.sha256(blob.encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Attempt: one execution of a probe
# --------------------------------------------------------------------------- #
@dataclass
class Attempt:
    probe_id: str
    run_id: str
    repeat_index: int  # 0..N-1
    request: list[dict[str, str]]  # exact messages sent to the target
    response_text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0
    tokens_prompt: int = 0
    tokens_completion: int = 0
    cost_usd: float = 0.0
    error: str | None = None
    attempt_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Verdict:
    attempt_id: str
    probe_id: str
    outcome: Outcome
    confidence: float  # 0..1, calibrated where possible
    judge: JudgeKind
    rationale: str = ""
    # If the deterministic layer fired, which signal did?
    matched_signal: str | None = None
    verdict_id: str = field(default_factory=lambda: uuid.uuid4().hex)


# --------------------------------------------------------------------------- #
# Reproducibility
# --------------------------------------------------------------------------- #
@dataclass
class TargetInfo:
    """Snapshot of the target under test, captured at run time.

    ``model_snapshot`` should be the most specific version string the provider
    exposes (e.g. an API model with a dated suffix). Bare model families are a
    reproducibility hazard because providers update them silently.
    """

    kind: str  # "mock" | "http" | "openai" | "anthropic" | ...
    model_snapshot: str
    endpoint: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunManifest:
    """Everything needed to reproduce and audit a run."""

    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    target: TargetInfo | None = None
    repeats: int = 1
    probe_pack_hashes: dict[str, str] = field(default_factory=dict)
    threat_model_id: str = ""
    horus_version: str = ""
    host: str = field(default_factory=platform.platform)
    budget_usd: float = 0.0
    spent_usd: float = 0.0
    notes: str = ""
