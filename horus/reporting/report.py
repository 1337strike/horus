"""Report aggregation.

Turns raw verdicts into the numbers a client's security team can act on:

* Attack Success Rate (ASR) per category, WITH a Wilson score confidence
  interval — because "3 of 5" and "300 of 500" are very different evidence even
  though both are 60%.
* The two axes kept separate: attack success (guardrail failures) and
  over-refusal (utility failures). One number for each; never averaged into a
  single misleading score.
* Coverage against the taxonomy, so gaps are explicit.
* The worst example transcript per category, for the appendix.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from ..models import Attempt, Category, Outcome, Verdict
from ..taxonomy import entry_for


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (95% by default)."""
    if n == 0:
        return (0.0, 0.0)
    phat = successes / n
    denom = 1 + z**2 / n
    centre = (phat + z**2 / (2 * n)) / denom
    margin = (z * math.sqrt((phat * (1 - phat) + z**2 / (4 * n)) / n)) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


@dataclass
class CategoryStat:
    category: Category
    total: int = 0
    fails: int = 0
    partials: int = 0
    errors: int = 0
    worst_example: dict | None = None

    @property
    def rate(self) -> float:
        graded = self.total - self.errors
        return (self.fails + 0.5 * self.partials) / graded if graded else 0.0

    @property
    def ci(self) -> tuple[float, float]:
        graded = self.total - self.errors
        return wilson_interval(self.fails, graded)


@dataclass
class Summary:
    run_id: str
    model_snapshot: str
    total_attempts: int = 0
    attack_categories: list[CategoryStat] = field(default_factory=list)
    refusal_stat: CategoryStat | None = None
    errors: int = 0
    spent_usd: float = 0.0
    started_at: str = ""
    finished_at: str = ""

    @property
    def overall_asr(self) -> float:
        tot = sum(c.total - c.errors for c in self.attack_categories)
        fails = sum(c.fails + 0.5 * c.partials for c in self.attack_categories)
        return fails / tot if tot else 0.0


def aggregate(manifest, attempts: list[Attempt], verdicts: list[Verdict]) -> Summary:
    by_attempt = {a.attempt_id: a for a in attempts}
    probe_category = {}  # probe_id -> Category, inferred from verdict grouping

    stats: dict[Category, CategoryStat] = defaultdict(lambda: CategoryStat(Category.JAILBREAK))
    # We need each probe's category; carry it on the attempt's request is not
    # ideal, so we look it up from verdict.probe_id via the caller-supplied map.
    # Here we reconstruct from the verdicts' probe ids using a category cache
    # populated by the caller through attach_categories(). To keep this function
    # self-contained, category is resolved from a module-level hook.
    cat_of = _CATEGORY_RESOLVER.get("fn", lambda pid: Category.JAILBREAK)

    for v in verdicts:
        cat = cat_of(v.probe_id)
        probe_category[v.probe_id] = cat
        if cat not in stats:
            stats[cat] = CategoryStat(cat)
        s = stats[cat]
        s.total += 1
        if v.outcome == Outcome.FAIL:
            s.fails += 1
            a = by_attempt.get(v.attempt_id)
            if a and (s.worst_example is None):
                s.worst_example = {
                    "probe_id": v.probe_id,
                    "request": a.request,
                    "response": a.response_text,
                    "rationale": v.rationale,
                    "confidence": v.confidence,
                }
        elif v.outcome == Outcome.PARTIAL:
            s.partials += 1
        elif v.outcome == Outcome.ERROR:
            s.errors += 1

    attack_stats = [s for c, s in stats.items() if c != Category.OVER_REFUSAL]
    refusal_stat = stats.get(Category.OVER_REFUSAL)

    t = manifest.target
    return Summary(
        run_id=manifest.run_id,
        model_snapshot=t.model_snapshot if t else "",
        total_attempts=len(attempts),
        attack_categories=sorted(attack_stats, key=lambda s: s.rate, reverse=True),
        refusal_stat=refusal_stat,
        errors=sum(s.errors for s in stats.values()),
        spent_usd=manifest.spent_usd,
        started_at=manifest.started_at,
        finished_at=manifest.finished_at or "",
    )


# The aggregator needs to know each probe's category. Rather than thread it
# through every signature, the CLI registers a resolver here before calling
# aggregate(). This keeps report.py importable and unit-testable in isolation.
_CATEGORY_RESOLVER: dict[str, object] = {}


def set_category_resolver(fn) -> None:
    _CATEGORY_RESOLVER["fn"] = fn


def taxonomy_row(category: Category) -> dict:
    e = entry_for(category)
    return {
        "category": category.value,
        "owasp": e.owasp_llm,
        "owasp_name": e.owasp_name,
        "atlas": ", ".join(e.atlas) or "—",
        "summary": e.summary,
    }
