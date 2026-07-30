"""Target abstraction.

A ``Target`` is anything we can send a conversation to and get a response
from: a raw model API, a hosted chatbot behind HTTP, or an agent with tools.
Adding a new target means implementing one method. Everything upstream
(orchestrator, evaluator, reporting) is target-agnostic.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from ..models import TargetInfo


@dataclass
class TargetResponse:
    """Normalised response from any target."""

    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0
    tokens_prompt: int = 0
    tokens_completion: int = 0
    cost_usd: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class Target(abc.ABC):
    """Base class for all targets."""

    kind: str = "base"

    @abc.abstractmethod
    def send(self, messages: list[dict[str, str]]) -> TargetResponse:
        """Send a conversation and return a normalised response.

        ``messages`` is a list of ``{"role": ..., "content": ...}`` dicts.
        Implementations must never raise on a *remote* error — they catch it
        and return ``TargetResponse(error=...)`` so the orchestrator can record
        an ERROR outcome rather than crashing the whole run.
        """

    @abc.abstractmethod
    def info(self) -> TargetInfo:
        """Return a reproducibility snapshot of this target."""

    def close(self) -> None:  # pragma: no cover - optional cleanup hook
        pass
