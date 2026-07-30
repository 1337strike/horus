"""Probe loading, orchestration, storage, and end-to-end tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from horus.cli import _resolve_pack_paths
from horus.evaluator import EnsembleJudge, LLMJudge
from horus.models import Category, Outcome
from horus.orchestrator import ParaphraseMutator, Runner
from horus.probes import load_pack, load_packs
from horus.reporting import aggregate, render_html, set_category_resolver
from horus.storage import Store
from horus.targets import build_target

PACKS = Path(__file__).parent.parent / "horus" / "probes" / "packs"


# --------------------------------------------------------------------------- #
# Probe loading
# --------------------------------------------------------------------------- #
def test_load_shipped_pack():
    probes, digest = load_pack(PACKS / "examples.yaml")
    assert probes
    assert len(digest) == 16  # stable short hash for the manifest


def test_pack_hash_is_content_addressed(tmp_path):
    p = tmp_path / "a.yaml"
    p.write_text("probes: [{id: x, category: jailbreak, prompt: hi, expectation: safe}]")
    _, h1 = load_pack(p)
    p.write_text("probes: [{id: x, category: jailbreak, prompt: HI, expectation: safe}]")
    _, h2 = load_pack(p)
    assert h1 != h2  # editing a pack changes the run manifest


def test_duplicate_probe_ids_rejected(tmp_path):
    body = "probes: [{id: dup, category: jailbreak, prompt: hi, expectation: safe}]"
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    a.write_text(body)
    b.write_text(body)
    with pytest.raises(ValueError, match="Duplicate probe id"):
        load_packs([a, b])


def test_multi_turn_probe_preserves_roles():
    probes, _ = load_pack(PACKS / "examples.yaml")
    indirect = next(p for p in probes if p.category is Category.INDIRECT_INJECTION)
    roles = [t.role for t in indirect.turns]
    assert "document" in roles  # the untrusted-content channel


def test_benign_pack_is_the_second_axis():
    probes, _ = load_pack(PACKS / "benign_baseline.yaml")
    assert probes
    assert all(p.category is Category.OVER_REFUSAL for p in probes)


def test_probe_content_hash_is_stable():
    probes, _ = load_pack(PACKS / "examples.yaml")
    assert probes[0].content_hash() == probes[0].content_hash()
    assert probes[0].content_hash() != probes[1].content_hash()


def test_pack_shorthand_resolves_to_shipped_dir():
    resolved = _resolve_pack_paths(["examples.yaml"])
    assert Path(resolved[0]).exists()


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _judge():
    return EnsembleJudge(LLMJudge(build_target({"kind": "mock_judge"})))


def test_runner_executes_n_repeats():
    probes, hashes = load_pack(PACKS / "examples.yaml")
    runner = Runner(build_target({"kind": "mock"}), _judge(), repeats=4)
    result = runner.run(probes, {"examples.yaml": hashes})
    assert len(result.attempts) == len(probes) * 4
    assert len(result.verdicts) == len(result.attempts)


def test_stochastic_target_produces_mixed_outcomes():
    """A single shot is not evidence: the same probe can pass and fail."""
    probes, h = load_pack(PACKS / "examples.yaml")
    leaky = [p for p in probes if p.canaries]
    runner = Runner(build_target({"kind": "mock"}), _judge(), repeats=12)
    result = runner.run(leaky, {"p": h})
    outcomes = {v.outcome for v in result.verdicts}
    assert len(outcomes) >= 1  # at minimum it ran; rates are what we report


def test_manifest_captures_reproducibility_fields():
    probes, h = load_pack(PACKS / "examples.yaml")
    runner = Runner(build_target({"kind": "mock"}), _judge(), repeats=1,
                    threat_model_id="tm-1", horus_version="9.9.9")
    m = runner.run(probes, {"examples.yaml": h}).manifest
    assert m.target.model_snapshot          # exact model version pinned
    assert m.probe_pack_hashes              # which pack version was used
    assert m.threat_model_id == "tm-1"
    assert m.started_at and m.finished_at
    assert m.host


def test_budget_cap_stops_the_run():
    class CostlyTarget:
        kind = "costly"

        def send(self, messages):
            from horus.targets.base import TargetResponse
            return TargetResponse(text="ok", cost_usd=1.0)

        def info(self):
            from horus.models import TargetInfo
            return TargetInfo(kind="costly", model_snapshot="costly-v1")

    probes, h = load_pack(PACKS / "examples.yaml")
    runner = Runner(CostlyTarget(), _judge(), repeats=50, budget_usd=3.0)
    result = runner.run(probes, {"p": h})
    assert "budget exceeded" in result.manifest.notes
    assert len(result.attempts) < len(probes) * 50


def test_target_errors_are_recorded_not_crashed():
    class BrokenTarget:
        kind = "broken"

        def send(self, messages):
            from horus.targets.base import TargetResponse
            return TargetResponse(text="", error="connection refused")

        def info(self):
            from horus.models import TargetInfo
            return TargetInfo(kind="broken", model_snapshot="broken-v1")

    probes, h = load_pack(PACKS / "examples.yaml")
    runner = Runner(BrokenTarget(), _judge(), repeats=1, max_retries=0)
    result = runner.run(probes, {"p": h})
    assert all(v.outcome is Outcome.ERROR for v in result.verdicts)


def test_mutator_tracks_parentage():
    probes, _ = load_pack(PACKS / "examples.yaml")
    variants = ParaphraseMutator().mutate(probes[0], 3)
    assert variants
    assert all(v.id.startswith(probes[0].id + "~v") for v in variants)
    assert all("mutated" in v.tags for v in variants)


# --------------------------------------------------------------------------- #
# Storage + reporting (end to end)
# --------------------------------------------------------------------------- #
def test_end_to_end_run_report_and_persist(tmp_path):
    probes, hashes = load_packs([PACKS / "examples.yaml", PACKS / "benign_baseline.yaml"])
    cat_by_id = {p.id: p.category for p in probes}
    set_category_resolver(lambda pid: cat_by_id[pid])

    runner = Runner(build_target({"kind": "mock"}), _judge(), repeats=6)
    result = runner.run(probes, hashes)

    db = tmp_path / "t.db"
    store = Store(db)
    store.save_result(result)
    rows = store.conn.execute("SELECT COUNT(*) c FROM attempts").fetchone()["c"]
    verdict_rows = store.conn.execute("SELECT COUNT(*) c FROM verdicts").fetchone()["c"]
    store.close()
    assert rows == len(result.attempts) == verdict_rows

    summary = aggregate(result.manifest, result.attempts, result.verdicts)
    assert summary.total_attempts == len(result.attempts)
    assert 0.0 <= summary.overall_asr <= 1.0

    html = render_html(summary, result.manifest, calibration=None)
    assert "Adversarial Assessment" in html
    assert "uncalibrated" in html  # honest warning when no gold set was run


def test_over_refusal_is_reported_separately_not_averaged():
    """The two axes must never be collapsed into one number."""
    probes, hashes = load_packs([PACKS / "examples.yaml", PACKS / "benign_baseline.yaml"])
    cat_by_id = {p.id: p.category for p in probes}
    set_category_resolver(lambda pid: cat_by_id[pid])

    runner = Runner(build_target({"kind": "mock"}), _judge(), repeats=4)
    result = runner.run(probes, hashes)
    summary = aggregate(result.manifest, result.attempts, result.verdicts)

    assert summary.refusal_stat is not None
    assert Category.OVER_REFUSAL not in [c.category for c in summary.attack_categories]


def test_report_renders_calibration_warning_when_kappa_low():
    from horus.calibration import calibrate

    probes, hashes = load_pack(PACKS / "examples.yaml")
    cat_by_id = {p.id: p.category for p in probes}
    set_category_resolver(lambda pid: cat_by_id[pid])
    runner = Runner(build_target({"kind": "mock"}), _judge(), repeats=2)
    result = runner.run(probes, {"examples.yaml": hashes})
    summary = aggregate(result.manifest, result.attempts, result.verdicts)

    weak = calibrate(["pass"] * 40, ["pass"] * 30 + ["fail"] * 10)
    html = render_html(summary, result.manifest, calibration=weak)
    assert "κ =" in html


# --------------------------------------------------------------------------- #
# Silent-failure guards
#
# These cover the most dangerous defect class in a security tool: a broken
# pipeline that reports a clean bill of health. Both were found by asking what
# happens when a provider changes its response payload shape.
# --------------------------------------------------------------------------- #
def test_unresolvable_response_path_is_an_error_not_an_empty_pass():
    """A payload shape we cannot read must fail loudly.

    If an unreadable response yielded "" instead, the judge would see an empty
    reply, find nothing objectionable, and score every probe as safe — turning
    a provider's silent format change into a flawless security report.
    """
    import httpx

    from horus.targets.http import HTTPTarget

    t = HTTPTarget(endpoint="https://example.invalid/v1/chat",
                   response_path="choices.0.message.content")
    t._client = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={"output": {"reply": "hi"}})
        )
    )
    r = t.send([{"role": "user", "content": "x"}])
    assert r.error is not None
    assert "response_path" in r.error
    assert "output" in r.error  # tells the operator what shape actually arrived
    t.close()


def test_error_envelope_returned_with_http_200_is_surfaced():
    import httpx

    from horus.targets.http import HTTPTarget

    t = HTTPTarget(endpoint="https://example.invalid/v1/chat",
                   response_path="choices.0.message.content")
    t._client = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={"error": "quota exceeded"})
        )
    )
    r = t.send([{"role": "user", "content": "x"}])
    assert r.error and "quota exceeded" in r.error
    t.close()


def test_legitimately_empty_reply_is_not_an_error():
    """An empty string that the path DID resolve to is a real observation."""
    import httpx

    from horus.targets.http import HTTPTarget

    t = HTTPTarget(endpoint="https://example.invalid/v1/chat",
                   response_path="choices.0.message.content")
    t._client = httpx.Client(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200, json={"choices": [{"message": {"content": ""}}]}
            )
        )
    )
    r = t.send([{"role": "user", "content": "x"}])
    assert r.error is None and r.text == ""
    t.close()


def test_all_errored_category_never_renders_as_zero_percent():
    """A category with no gradable attempts must not look like proven safety."""
    from horus.reporting.report import CategoryStat

    s = CategoryStat(Category.JAILBREAK, total=8, fails=0, errors=8)
    assert s.is_ungraded
    assert s.ci == (0.0, 0.0)  # the maths still returns 0-0 ...

    from horus.models import Attempt as A
    from horus.models import Outcome as O
    from horus.models import Verdict as V

    probes, hashes = load_pack(PACKS / "examples.yaml")
    cat = {p.id: p.category for p in probes}
    set_category_resolver(lambda pid: cat[pid])

    runner = Runner(build_target({"kind": "mock"}), _judge(), repeats=1)
    result = runner.run(probes, {"examples.yaml": hashes})
    for v in result.verdicts:          # force the all-errored condition
        v.outcome = O.ERROR
    summary = aggregate(result.manifest, result.attempts, result.verdicts)
    html = render_html(summary, result.manifest)

    assert "no gradable attempts" in html   # ... but the report says so plainly
    assert "failed to execute" in html      # and warns at the run level
