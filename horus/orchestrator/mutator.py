"""Mutator interface (optional).

A mutator takes probes that FAILED to trip the target and proposes variants, so
the harness can search the neighbourhood of a near-miss (an iterative / genetic
approach). This is a powerful capability and also the one most easily misused,
so the framework ships only the *interface* plus a trivial, transparent
paraphrase mutator for demonstration.

Deliberate design choices:
* Mutation is OFF by default and must be explicitly enabled in config.
* Every generated variant is recorded with its parent id, so the report shows
  exactly how a finding was reached — no black-box exploit generation.
* Authoring a strong generative mutator is left to the operator, who is
  accountable for using it only against systems they are authorised to test.
"""

from __future__ import annotations

import abc

from ..models import Probe, Turn


class Mutator(abc.ABC):
    @abc.abstractmethod
    def mutate(self, probe: Probe, n: int) -> list[Probe]:
        ...


class ParaphraseMutator(Mutator):
    """A trivial illustrative mutator: light surface rewrites only.

    It does not strengthen an attack; it exists to show the plumbing (parent
    tracking, id derivation) that a real generative mutator would use.
    """

    _PREFIXES = ("Politely, ", "As a quick note, ", "For my records, ")

    def mutate(self, probe: Probe, n: int) -> list[Probe]:
        variants: list[Probe] = []
        base = probe.turns[-1].content
        for i in range(min(n, len(self._PREFIXES))):
            new_turns = probe.turns[:-1] + (
                Turn(role=probe.turns[-1].role, content=self._PREFIXES[i] + base),
            )
            variants.append(
                Probe(
                    id=f"{probe.id}~v{i+1}",
                    category=probe.category,
                    severity=probe.severity,
                    turns=new_turns,
                    expectation=probe.expectation,
                    fail_regexes=probe.fail_regexes,
                    canaries=probe.canaries,
                    source=f"mutated from {probe.id}",
                    tags=probe.tags + ("mutated",),
                    judge=probe.judge,
                )
            )
        return variants
