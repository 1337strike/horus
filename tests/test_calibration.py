"""Calibration and statistics tests.

These cover the maths the report leans on. If Wilson intervals or kappa are
wrong, the report is confidently misleading — the exact failure mode this
framework exists to prevent.
"""

from __future__ import annotations

import pytest

from horus.calibration import calibrate, cohens_kappa
from horus.reporting.report import wilson_interval


# --------------------------------------------------------------------------- #
# Cohen's kappa
# --------------------------------------------------------------------------- #
def test_perfect_agreement_is_kappa_one():
    labels = ["pass", "fail", "pass", "fail"]
    assert cohens_kappa(labels, labels) == pytest.approx(1.0)


def test_chance_agreement_is_near_zero():
    """Raters who agree only as often as chance must score ~0, not ~0.5.

    This is precisely why we report kappa instead of raw agreement: on a
    skewed set, a judge that always says "pass" can look 90% accurate.
    """
    judge = ["pass"] * 10
    human = ["pass"] * 9 + ["fail"]
    k = cohens_kappa(judge, human)
    assert k == pytest.approx(0.0, abs=1e-9)


def test_kappa_penalises_a_judge_that_always_passes():
    judge = ["pass"] * 20
    human = ["pass"] * 16 + ["fail"] * 4
    report = calibrate(judge, human)
    assert report.agreement == pytest.approx(0.8)  # looks good...
    assert report.kappa < 0.05                     # ...but is worthless
    assert report.recall_fail == 0.0               # missed every attack


def test_calibration_confusion_matrix():
    judge = ["fail", "fail", "pass", "pass"]
    human = ["fail", "pass", "fail", "pass"]
    r = calibrate(judge, human)
    assert r.confusion == {"tp": 1, "fp": 1, "fn": 1, "tn": 1}
    assert r.precision_fail == pytest.approx(0.5)
    assert r.recall_fail == pytest.approx(0.5)


def test_mismatched_lengths_rejected():
    with pytest.raises(ValueError):
        calibrate(["pass"], ["pass", "fail"])


def test_verdict_label_warns_on_small_sample():
    r = calibrate(["pass"] * 5, ["pass"] * 5)
    assert "insufficient sample" in r.verdict_label()


def test_verdict_label_flags_weak_judge():
    judge = ["pass"] * 30 + ["fail"] * 10
    human = ["pass"] * 20 + ["fail"] * 10 + ["pass"] * 10
    r = calibrate(judge, human)
    assert r.n >= 30
    assert "do NOT trust" in r.verdict_label() or "human review" in r.verdict_label()


# --------------------------------------------------------------------------- #
# Wilson interval
# --------------------------------------------------------------------------- #
def test_small_sample_yields_wide_interval():
    """3/5 and 300/500 are both 60% — the interval must distinguish them."""
    lo_s, hi_s = wilson_interval(3, 5)
    lo_l, hi_l = wilson_interval(300, 500)
    assert (hi_s - lo_s) > (hi_l - lo_l) * 3


def test_zero_successes_still_has_upper_bound():
    """0/8 does not mean 'proven safe' — the upper bound must be well above 0."""
    lo, hi = wilson_interval(0, 8)
    assert lo == pytest.approx(0.0, abs=1e-9)
    assert hi > 0.2


def test_interval_is_bounded_zero_to_one():
    for s, n in [(0, 1), (1, 1), (5, 10), (99, 100)]:
        lo, hi = wilson_interval(s, n)
        assert 0.0 <= lo <= hi <= 1.0


def test_empty_sample_is_safe():
    assert wilson_interval(0, 0) == (0.0, 0.0)
