"""Horus command-line interface.

Commands
--------
  horus run       --config CONFIG        run an assessment, write DB + HTML report
  horus calibrate --config CONFIG --gold GOLD.jsonl   measure judge vs human
  horus demo                              zero-config run against the mock target
  horus version

Everything is designed so `horus demo` works with no API keys and no network,
producing a full report — the fastest way to see the framework end to end.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .agentic import ToolPolicy
from .export import (
    collect_findings, exceeds, to_json, to_sarif, worst_finding_severity,
)
from .calibration import calibrate, load_goldset
from .config import RunConfig
from .evaluator import DeterministicJudge, EnsembleJudge, LLMJudge
from .models import Attempt, Category
from .probes import load_packs
from .reporting import aggregate, render_html, set_category_resolver
from .storage import Store
from .targets import build_target

_PKG = Path(__file__).parent


def _load_policy(cfg: RunConfig) -> ToolPolicy | None:
    """Load the tool policy if one is configured (required for agentic runs)."""
    if not cfg.tool_policy:
        return None
    path = Path(cfg.tool_policy)
    if not path.exists():
        alt = _PKG.parent / cfg.tool_policy
        path = alt if alt.exists() else path
    return ToolPolicy.load(path)


def _build_judge(cfg: RunConfig):
    if cfg.judge.kind == "deterministic":
        return DeterministicJudge()
    llm = None
    if cfg.judge.kind in ("llm", "ensemble"):
        judge_target = build_target(cfg.judge.judge_target)
        llm = LLMJudge(judge_target)
    if cfg.judge.kind == "llm":
        return llm
    return EnsembleJudge(
        llm,
        tool_policy=_load_policy(cfg),
        review_low=cfg.judge.review_low,
        review_high=cfg.judge.review_high,
    )


def _resolve_pack_paths(packs: list[str]) -> list[str]:
    resolved = []
    for p in packs:
        path = Path(p)
        if not path.exists():
            # allow shorthand names pointing at the shipped packs dir
            alt = _PKG / "probes" / "packs" / p
            path = alt if alt.exists() else path
        resolved.append(str(path))
    return resolved


def cmd_run(cfg: RunConfig, *, resume: str | None = None) -> int:
    from .orchestrator import Runner

    pack_paths = _resolve_pack_paths(cfg.packs)
    probes, hashes = load_packs(pack_paths)
    cat_by_id = {p.id: p.category for p in probes}
    set_category_resolver(lambda pid: cat_by_id.get(pid, Category.JAILBREAK))

    target = build_target(cfg.target)
    judge = _build_judge(cfg)
    info = target.info()

    if any(p.category is Category.TOOL_ABUSE for p in probes) and not cfg.tool_policy:
        print("[horus] WARNING: tool_abuse probes loaded but no tool_policy configured — "
              "action traces cannot be judged and will be scored on text alone.")
    if cfg.budget_usd and info.params.get("pricing_declared") is False:
        print(f"[horus] WARNING: budget_usd={cfg.budget_usd} is INERT — no pricing "
              "declared for this target, so spend is recorded as $0 and the cap "
              "can never trigger. Add a `pricing:` block to the target config.")

    store = Store(cfg.db_path)
    runner = Runner(
        target, judge,
        repeats=cfg.repeats, budget_usd=cfg.budget_usd,
        concurrency=cfg.concurrency,
        threat_model_id=cfg.threat_model_id, horus_version=__version__,
        store=store, run_id=resume,
    )

    mode = f", concurrency {cfg.concurrency}" if cfg.concurrency > 1 else ""
    print(f"[horus] running {len(probes)} probes x {cfg.repeats} repeats "
          f"against {info.model_snapshot}{mode} ...")
    result = runner.run(probes, hashes)
    if result.skipped:
        print(f"[horus] resumed run {result.manifest.run_id}: "
              f"{result.skipped} attempt(s) already complete, skipped")

    summary = aggregate(result.manifest, result.attempts, result.verdicts)
    html = render_html(summary, result.manifest, calibration=None)
    Path(cfg.out_html).write_text(html)

    findings = collect_findings(probes, result.attempts, result.verdicts)

    print(f"[horus] run id: {result.manifest.run_id}")
    print(f"[horus] overall attack success rate: {summary.overall_asr*100:.0f}%")
    if summary.refusal_stat:
        print(f"[horus] over-refusal rate:            {summary.refusal_stat.rate*100:.0f}%")
    if summary.errors:
        print(f"[horus] {summary.errors} attempt(s) errored and are excluded from all rates")
    if result.manifest.spent_usd:
        print(f"[horus] spend: ${result.manifest.spent_usd:.4f} of ${cfg.budget_usd}")
    review = getattr(judge, "review_flags", [])
    if review:
        print(f"[horus] {len(review)} verdict(s) flagged for human review")
    print(f"[horus] db:     {cfg.db_path}")
    print(f"[horus] report: {cfg.out_html}")
    store.close()

    if cfg.fail_on:
        if exceeds(findings, cfg.fail_on):
            worst = worst_finding_severity(findings)
            print(f"[horus] GATE FAILED: findings at severity {worst} "
                  f"(threshold {cfg.fail_on})")
            return 2
        print(f"[horus] gate passed: no findings at or above {cfg.fail_on}")
    return 0


def cmd_check(cfg: RunConfig) -> int:
    """Preflight. Prove the harness can actually read this target before a run.

    This exists because the expensive failure is not a crash, it is a long run
    that completes and reports a clean bill of health because every response was
    unreadable. One call answers that for a few cents instead of a few hundred.
    """
    pack_paths = _resolve_pack_paths(cfg.packs)
    ok = True

    print("── Preflight ─────────────────────────────────────")
    try:
        probes, hashes = load_packs(pack_paths)
        print(f"  packs         OK    {len(probes)} probes from {len(hashes)} pack(s)")
    except Exception as exc:
        print(f"  packs         FAIL  {exc}")
        return 1

    needs_policy = any(p.category is Category.TOOL_ABUSE for p in probes)
    policy = None
    try:
        policy = _load_policy(cfg)
    except Exception as exc:
        print(f"  tool policy   FAIL  {exc}")
        ok = False
    if needs_policy and policy is None:
        print("  tool policy   FAIL  tool_abuse probes present but no tool_policy set")
        ok = False
    elif policy is not None:
        print(f"  tool policy   OK    {len(policy.tools)} tool(s) declared")

    try:
        target = build_target(cfg.target)
    except Exception as exc:
        # A scope violation raises here, which is the point: an out-of-scope
        # infra target must fail preflight before any probe is sent.
        print(f"  target        FAIL  {exc}")
        return 1
    info = target.info()
    print(f"  target        ..    {info.kind} / {info.model_snapshot}")
    if "scope_ok" in info.params:
        print(f"  scope         OK    endpoint in scope "
              f"(resolved {info.params.get('scope_resolved')})")

    resp = target.send([{"role": "user", "content": "Reply with the single word: ready."}])
    if resp.error:
        print(f"  connectivity  FAIL  {resp.error}")
        return 1
    print(f"  connectivity  OK    {resp.latency_ms:.0f}ms")

    if resp.text.strip():
        print(f"  response_path OK    resolved, {len(resp.text)} chars")
    else:
        print("  response_path WARN  resolved but empty — verify this is expected")

    if needs_policy:
        if resp.tool_calls:
            print(f"  tool_calls    OK    {len(resp.tool_calls)} call(s) surfaced")
        else:
            print("  tool_calls    WARN  none surfaced on a trivial prompt. If this "
                  "target is an agent, confirm tool_calls_path matches its payload, "
                  "or trace judging will silently have nothing to judge.")

    declared = info.params.get("pricing_declared")
    if cfg.budget_usd and declared is False:
        print(f"  budget cap    WARN  INERT — no pricing declared, so budget_usd="
              f"{cfg.budget_usd} can never trigger. Add a `pricing:` block.")
        ok = False
    elif cfg.budget_usd and declared is True:
        print(f"  budget cap    OK    ${cfg.budget_usd}, pricing declared")
    elif cfg.budget_usd:
        print(f"  budget cap    n/a   this target reports no cost")

    if cfg.judge.kind in ("llm", "ensemble"):
        jt = build_target(cfg.judge.judge_target)
        jinfo = jt.info()
        jr = jt.send([{"role": "user", "content": "Reply with JSON: {\"ok\": true}"}])
        if jr.error:
            print(f"  judge         FAIL  {jr.error}")
            ok = False
        else:
            print(f"  judge         OK    {jinfo.model_snapshot}")
            if jinfo.model_snapshot == info.model_snapshot:
                print("  judge         WARN  same model as the target — shared blind "
                      "spots will be invisible to this assessment")
    target.close()
    print("──────────────────────────────────────────────────")
    print("  ready to run" if ok else "  fix the FAIL/WARN items above first")
    return 0 if ok else 1


def cmd_export(cfg: RunConfig, run_id: str, fmt: str, out: str) -> int:
    """Export a stored run as SARIF or JSON, with secrets redacted."""
    import json as _json
    import sqlite3

    from .models import Attempt as _A
    from .models import JudgeKind as _JK
    from .models import Outcome as _O
    from .models import RunManifest as _M
    from .models import TargetInfo as _T
    from .models import Verdict as _V

    probes, _ = load_packs(_resolve_pack_paths(cfg.packs))
    store = Store(cfg.db_path)
    row = store.load_manifest_row(run_id)
    if row is None:
        print(f"[horus] no run {run_id!r} in {cfg.db_path}")
        return 1

    manifest = _M(
        run_id=row["run_id"], started_at=row["started_at"],
        finished_at=row["finished_at"], repeats=row["repeats"],
        threat_model_id=row["threat_model_id"] or "",
        horus_version=row["horus_version"] or "",
        budget_usd=row["budget_usd"] or 0.0, spent_usd=row["spent_usd"] or 0.0,
        probe_pack_hashes=_json.loads(row["pack_hashes"] or "{}"),
        notes=row["notes"] or "",
        target=_T(kind=row["target_kind"], model_snapshot=row["model_snapshot"],
                  endpoint=row["endpoint"] or ""),
    )

    attempts, verdicts = [], []
    for r in store.conn.execute("SELECT * FROM attempts WHERE run_id=?", (run_id,)):
        a = _A(probe_id=r["probe_id"], run_id=run_id, repeat_index=r["repeat_index"],
               request=_json.loads(r["request"] or "[]"),
               response_text=r["response_text"] or "",
               tool_calls=_json.loads(r["tool_calls"] or "[]"),
               error=r["error"])
        a.attempt_id = r["attempt_id"]
        attempts.append(a)
    for r in store.conn.execute(
        "SELECT v.* FROM verdicts v JOIN attempts a ON a.attempt_id=v.attempt_id"
        " WHERE a.run_id=?", (run_id,)
    ):
        v = _V(attempt_id=r["attempt_id"], probe_id=r["probe_id"],
               outcome=_O(r["outcome"]), confidence=r["confidence"],
               judge=_JK(r["judge"]),
               rationale=r["rationale"] or "", matched_signal=r["matched_signal"])
        verdicts.append(v)

    findings = collect_findings(probes, attempts, verdicts)
    doc = (to_sarif(findings, manifest, tool_version=__version__) if fmt == "sarif"
           else to_json(findings, manifest))
    Path(out).write_text(_json.dumps(doc, indent=2))
    store.log(run_id, "export", detail=f"{fmt} -> {out}, {len(findings)} finding(s)")
    store.close()
    print(f"[horus] exported {len(findings)} finding(s) as {fmt} -> {out}")
    print("[horus] canary values are redacted in exports")
    return 0


def cmd_calibrate(cfg: RunConfig, gold_path: str) -> int:
    """Run the configured judge over a human-labelled gold set and score it."""
    items = load_goldset(gold_path)
    judge = _build_judge(cfg)

    from .models import JudgeKind, Outcome, Probe, Severity, Turn

    judge_labels, human_labels = [], []
    for it in items:
        probe = Probe(
            id=it.probe_id,
            category=Category(it.category) if it.category else Category.JAILBREAK,
            severity=Severity.MEDIUM,
            turns=(Turn("user", ""),),
            expectation=it.expectation or "The target should behave safely and in policy.",
            judge=JudgeKind.ENSEMBLE,
        )
        attempt = Attempt(
            probe_id=it.probe_id, run_id="calib", repeat_index=0,
            request=[], response_text=it.response_text,
        )
        v = judge.judge(probe, attempt)
        judge_labels.append(v.outcome.value)
        human_labels.append(it.human_outcome)

    report = calibrate(judge_labels, human_labels)
    print("── Judge calibration ─────────────────────────────")
    print(f"  items      : {report.n}")
    print(f"  agreement  : {report.agreement:.2f}")
    print(f"  Cohen's κ  : {report.kappa:.2f}  ({report.verdict_label()})")
    print(f"  precision  : {report.precision_fail:.2f} (FAIL class)")
    print(f"  recall     : {report.recall_fail:.2f} (FAIL class)")
    print(f"  confusion  : {report.confusion}")
    return 0


def cmd_demo() -> int:
    from .config import JudgeConfig

    cfg = RunConfig(
        target={"kind": "mock"},
        packs=["examples.yaml", "benign_baseline.yaml"],
        judge=JudgeConfig(kind="ensemble", judge_target={"kind": "mock_judge"}),
        repeats=8,
        db_path="horus_demo.db",
        out_html="horus_demo_report.html",
    )
    return cmd_run(cfg)


def cmd_demo_infra() -> int:
    from .config import JudgeConfig

    cfg = RunConfig(
        target={"kind": "mock_infra_agent"},
        packs=["infra.yaml"],
        judge=JudgeConfig(kind="ensemble", judge_target={"kind": "mock_judge"}),
        repeats=8,
        tool_policy=str(_PKG.parent / "config" / "infra_policy.example.yaml"),
        db_path="horus_infra_demo.db",
        out_html="horus_infra_demo_report.html",
    )
    return cmd_run(cfg)


def cmd_demo_agent() -> int:
    from .config import JudgeConfig

    cfg = RunConfig(
        target={"kind": "mock_agent"},
        packs=["agentic.yaml"],
        judge=JudgeConfig(kind="ensemble", judge_target={"kind": "mock_judge"}),
        repeats=8,
        tool_policy=str(_PKG.parent / "config" / "tool_policy.example.yaml"),
        db_path="horus_agent_demo.db",
        out_html="horus_agent_demo_report.html",
    )
    return cmd_run(cfg)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="horus", description="LLM red-team harness")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run an assessment from a config file")
    p_run.add_argument("--config", required=True)
    p_run.add_argument("--resume", metavar="RUN_ID",
                       help="continue a previous run, skipping completed attempts")
    p_run.add_argument("--concurrency", type=int,
                       help="override the config's concurrency")
    p_run.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                       help="exit 2 if any finding reaches this severity (CI gate)")

    p_chk = sub.add_parser("check", help="preflight a config without spending a full run")
    p_chk.add_argument("--config", required=True)

    p_exp = sub.add_parser("export", help="export a stored run as SARIF or JSON")
    p_exp.add_argument("--config", required=True)
    p_exp.add_argument("--run-id", required=True)
    p_exp.add_argument("--format", choices=["sarif", "json"], default="sarif")
    p_exp.add_argument("--out", required=True)

    p_cal = sub.add_parser("calibrate", help="score the judge against a gold set")
    p_cal.add_argument("--config", required=True)
    p_cal.add_argument("--gold", required=True)

    sub.add_parser("demo", help="zero-config run against the built-in mock target")
    sub.add_parser("demo-agent", help="zero-config agentic run (tool-abuse trace evaluation)")
    sub.add_parser("demo-infra", help="zero-config infra-agent run (RCE/SSRF/cred trace evaluation)")
    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)
    if args.cmd == "run":
        cfg = RunConfig.load(args.config)
        if args.concurrency:
            cfg.concurrency = args.concurrency
        if args.fail_on:
            cfg.fail_on = args.fail_on
        return cmd_run(cfg, resume=args.resume)
    if args.cmd == "check":
        return cmd_check(RunConfig.load(args.config))
    if args.cmd == "export":
        return cmd_export(RunConfig.load(args.config), args.run_id,
                          args.format, args.out)
    if args.cmd == "calibrate":
        return cmd_calibrate(RunConfig.load(args.config), args.gold)
    if args.cmd == "demo":
        return cmd_demo()
    if args.cmd == "demo-agent":
        return cmd_demo_agent()
    if args.cmd == "demo-infra":
        return cmd_demo_infra()
    if args.cmd == "version":
        print(f"horus {__version__}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
