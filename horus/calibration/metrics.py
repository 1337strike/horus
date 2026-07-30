"""Judge calibration metrics.

The central claim of this framework is that an *uncalibrated* LLM judge
produces confident-but-wrong numbers. This module measures how much you can
trust the judge by comparing its verdicts against a human-labelled gold set.

We report, per category and overall:
* Cohen's kappa       — agreement corrected for chance
* precision / recall  — on the FAIL class (a missed attack is the costly error)
* raw agreement

If kappa is low, the honest move is to say so in the report and lean harder on
deterministic checks and human review — not to ship a pretty number.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


@dataclass
class CalibrationReport:
    n: int
    agreement: float
    kappa: float
    precision_fail: float
    recall_fail: float
    f1_fail: float
    confusion: dict[str, int]

    def verdict_label(self) -> str:
        if self.n < 30:
            return "insufficient sample (need >= ~30 labelled items)"
        if self.kappa >= 0.8:
            return "strong agreement — judge is trustworthy"
        if self.kappa >= 0.6:
            return "substantial agreement — usable, watch borderline cases"
        if self.kappa >= 0.4:
            return "moderate agreement — human review recommended"
        return "weak agreement — do NOT trust automated verdicts alone"


def cohens_kappa(judge: list[str], human: list[str]) -> float:
    """Cohen's kappa for two raters over categorical labels."""
    if not judge:
        return 0.0
    n = len(judge)
    labels = set(judge) | set(human)
    observed = sum(1 for a, b in zip(judge, human) if a == b) / n

    jc = Counter(judge)
    hc = Counter(human)
    expected = sum((jc[l] / n) * (hc[l] / n) for l in labels)
    if expected >= 1.0:
        return 1.0
    return (observed - expected) / (1 - expected)


def _binary(labels: list[str], positive: str = "fail") -> list[int]:
    return [1 if l == positive else 0 for l in labels]


def calibrate(judge: list[str], human: list[str]) -> CalibrationReport:
    """Compute the full calibration report. Both lists are aligned outcomes."""
    if len(judge) != len(human):
        raise ValueError("judge and human label lists must be the same length")
    n = len(judge)
    agreement = sum(1 for a, b in zip(judge, human) if a == b) / n if n else 0.0
    kappa = cohens_kappa(judge, human)

    jb = _binary(judge)
    hb = _binary(human)
    tp = sum(1 for j, h in zip(jb, hb) if j == 1 and h == 1)
    fp = sum(1 for j, h in zip(jb, hb) if j == 1 and h == 0)
    fn = sum(1 for j, h in zip(jb, hb) if j == 0 and h == 1)
    tn = sum(1 for j, h in zip(jb, hb) if j == 0 and h == 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return CalibrationReport(
        n=n,
        agreement=agreement,
        kappa=kappa,
        precision_fail=precision,
        recall_fail=recall,
        f1_fail=f1,
        confusion={"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    )
