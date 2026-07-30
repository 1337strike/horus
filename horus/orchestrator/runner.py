"""Run orchestration.

Responsibilities:
* Execute each probe N times (red-teaming is stochastic — a single shot is not
  evidence). Report success *rates* with confidence intervals, not booleans.
* Enforce a hard USD budget cap so an iterative run can't melt the bill.
* Back off and retry on transient target errors, but never hang the whole run
  on one bad probe.
* Capture a full RunManifest for reproducibility.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..evaluator.base import Judge
from ..models import Attempt, Probe, RunManifest, TargetInfo, Verdict
from ..targets.base import Target


@dataclass
class RunResult:
    manifest: RunManifest
    attempts: list[Attempt] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)


class BudgetExceeded(RuntimeError):
    pass


class Runner:
    def __init__(
        self,
        target: Target,
        judge: Judge,
        *,
        repeats: int = 5,
        budget_usd: float = 5.0,
        max_retries: int = 2,
        base_backoff_s: float = 0.5,
        threat_model_id: str = "",
        horus_version: str = "0.1.0",
    ) -> None:
        self.target = target
        self.judge = judge
        self.repeats = repeats
        self.budget_usd = budget_usd
        self.max_retries = max_retries
        self.base_backoff_s = base_backoff_s
        self.threat_model_id = threat_model_id
        self.horus_version = horus_version

    def _send_with_retry(self, messages):
        last = None
        for attempt_no in range(self.max_retries + 1):
            resp = self.target.send(messages)
            if not resp.error:
                return resp
            last = resp
            if attempt_no < self.max_retries:
                time.sleep(self.base_backoff_s * (2**attempt_no))
        return last

    def run(self, probes: list[Probe], pack_hashes: dict[str, str]) -> RunResult:
        info: TargetInfo = self.target.info()
        manifest = RunManifest(
            target=info,
            repeats=self.repeats,
            probe_pack_hashes=pack_hashes,
            threat_model_id=self.threat_model_id,
            horus_version=self.horus_version,
            budget_usd=self.budget_usd,
        )
        result = RunResult(manifest=manifest)

        for probe in probes:
            messages = [{"role": t.role, "content": t.content} for t in probe.turns]
            for i in range(self.repeats):
                if manifest.spent_usd > self.budget_usd:
                    manifest.notes = "stopped early: budget exceeded"
                    manifest.finished_at = _now()
                    return result

                resp = self._send_with_retry(messages)
                attempt = Attempt(
                    probe_id=probe.id,
                    run_id=manifest.run_id,
                    repeat_index=i,
                    request=messages,
                    response_text=resp.text,
                    tool_calls=resp.tool_calls,
                    latency_ms=resp.latency_ms,
                    tokens_prompt=resp.tokens_prompt,
                    tokens_completion=resp.tokens_completion,
                    cost_usd=resp.cost_usd,
                    error=resp.error,
                )
                manifest.spent_usd += resp.cost_usd
                verdict = self.judge.judge(probe, attempt)
                result.attempts.append(attempt)
                result.verdicts.append(verdict)

        manifest.finished_at = _now()
        return result


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
