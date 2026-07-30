"""Judge abstraction.

A judge takes a (Probe, Attempt) pair and returns a Verdict. The framework
ships three concrete judges — deterministic, LLM, and an ensemble that routes
between them — but the interface is deliberately tiny so a human-review judge
or a third-party classifier can drop in.
"""

from __future__ import annotations

import abc

from ..models import Attempt, Probe, Verdict


class Judge(abc.ABC):
    @abc.abstractmethod
    def judge(self, probe: Probe, attempt: Attempt) -> Verdict:
        ...
