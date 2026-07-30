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
from .calibration import calibrate, load_goldset
from .config import RunConfig
from .evaluator import DeterministicJudge, EnsembleJudge, LLMJudge
from .models import Attempt, Category
from .probes import load_packs
from .reporting import aggregate, render_html, set_category_resolver
from .storage import Store
from .targets import build_target

_PKG = Path(__file__).parent


def _build_judge(cfg: RunConfig):
    if cfg.judge.kind == "deterministic":
        return DeterministicJudge()
    llm = None
    if cfg.judge.kind in ("llm", "ensemble"):
        judge_target = build_target(cfg.judge.judge_target)
        llm = LLMJudge(judge_target)
    if cfg.judge.kind == "llm":
        return llm
    return EnsembleJudge(llm, review_low=cfg.judge.review_low, review_high=cfg.judge.review_high)


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


def cmd_run(cfg: RunConfig) -> int:
    from .orchestrator import Runner

    pack_paths = _resolve_pack_paths(cfg.packs)
    probes, hashes = load_packs(pack_paths)
    cat_by_id = {p.id: p.category for p in probes}
    set_category_resolver(lambda pid: cat_by_id.get(pid, Category.JAILBREAK))

    target = build_target(cfg.target)
    judge = _build_judge(cfg)
    runner = Runner(
        target, judge,
        repeats=cfg.repeats, budget_usd=cfg.budget_usd,
        threat_model_id=cfg.threat_model_id, horus_version=__version__,
    )

    print(f"[horus] running {len(probes)} probes x {cfg.repeats} repeats "
          f"against {target.info().model_snapshot} ...")
    result = runner.run(probes, hashes)

    store = Store(cfg.db_path)
    store.save_result(result)
    store.close()

    summary = aggregate(result.manifest, result.attempts, result.verdicts)
    html = render_html(summary, result.manifest, calibration=None)
    Path(cfg.out_html).write_text(html)

    print(f"[horus] overall attack success rate: {summary.overall_asr*100:.0f}%")
    if summary.refusal_stat:
        print(f"[horus] over-refusal rate:            {summary.refusal_stat.rate*100:.0f}%")
    review = getattr(judge, "review_flags", [])
    if review:
        print(f"[horus] {len(review)} verdict(s) flagged for human review")
    print(f"[horus] db:     {cfg.db_path}")
    print(f"[horus] report: {cfg.out_html}")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="horus", description="LLM red-team harness")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run an assessment from a config file")
    p_run.add_argument("--config", required=True)

    p_cal = sub.add_parser("calibrate", help="score the judge against a gold set")
    p_cal.add_argument("--config", required=True)
    p_cal.add_argument("--gold", required=True)

    sub.add_parser("demo", help="zero-config run against the built-in mock target")
    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)
    if args.cmd == "run":
        return cmd_run(RunConfig.load(args.config))
    if args.cmd == "calibrate":
        return cmd_calibrate(RunConfig.load(args.config), args.gold)
    if args.cmd == "demo":
        return cmd_demo()
    if args.cmd == "version":
        print(f"horus {__version__}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
