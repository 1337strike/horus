"""Run orchestration.

Responsibilities:

* Execute each probe N times. Red-teaming is stochastic; a single shot is not
  evidence, so the report gives rates with intervals rather than booleans.
* Run those attempts **concurrently** with a bounded worker pool. A real
  assessment is thousands of paid calls, and a strictly sequential runner turns
  that into an overnight job for no reason.
* **Checkpoint as it goes.** Every completed attempt is written immediately, so
  a run that dies at hour five can be resumed rather than repeated. Losing paid
  work to one transient failure is not an acceptable failure mode.
* Enforce a real USD budget cap, and say so loudly when the cap is inert
  because no pricing was declared.
* Back off on provider throttling, honouring ``Retry-After`` when the provider
  gives one rather than guessing.

Determinism note: attempts are executed concurrently but re-sorted into probe
order before anything downstream sees them, so a report from a parallel run is
identical to one from a sequential run. Concurrency is a scheduling detail and
must not leak into the findings.
"""

from __future__ import annotations

import getpass
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..evaluator.base import Judge
from ..models import Attempt, Probe, RunManifest, TargetInfo, Verdict
from ..targets.base import Target


@dataclass
class RunResult:
    manifest: RunManifest
    attempts: list[Attempt] = field(default_factory=list)
    verdicts: list[Verdict] = field(default_factory=list)
    skipped: int = 0  # slots already present from an earlier, resumed run


class BudgetExceeded(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _retry_after_seconds(error: str | None) -> float | None:
    if not error or "rate_limited" not in error:
        return None
    m = re.search(r"retry-after=(\d+(?:\.\d+)?)", error)
    return float(m.group(1)) if m else None


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - containers may lack a passwd entry
        return "unknown"


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
        concurrency: int = 1,
        threat_model_id: str = "",
        horus_version: str = "0.1.0",
        store=None,
        run_id: str | None = None,
        on_progress=None,
    ) -> None:
        self.target = target
        self.judge = judge
        self.repeats = repeats
        self.budget_usd = budget_usd
        self.max_retries = max_retries
        self.base_backoff_s = base_backoff_s
        self.concurrency = max(1, concurrency)
        self.threat_model_id = threat_model_id
        self.horus_version = horus_version
        self.store = store
        self.run_id = run_id
        self.on_progress = on_progress

        self._lock = threading.Lock()
        self._spent = 0.0
        self._stop = threading.Event()

    # ------------------------------------------------------------------ #
    def _send_with_retry(self, messages):
        last = None
        for attempt_no in range(self.max_retries + 1):
            resp = self.target.send(messages)
            if not resp.error:
                return resp
            last = resp
            if attempt_no >= self.max_retries:
                break
            # Honour the provider's own instruction when it gives one; only
            # fall back to exponential guessing when it does not.
            wait = _retry_after_seconds(resp.error)
            time.sleep(wait if wait is not None else self.base_backoff_s * (2**attempt_no))
        return last

    def _execute(self, probe: Probe, repeat_index: int, run_id: str):
        if self._stop.is_set():
            return None
        messages = [{"role": t.role, "content": t.content} for t in probe.turns]
        resp = self._send_with_retry(messages)

        attempt = Attempt(
            probe_id=probe.id,
            run_id=run_id,
            repeat_index=repeat_index,
            request=messages,
            response_text=resp.text,
            tool_calls=resp.tool_calls,
            latency_ms=resp.latency_ms,
            tokens_prompt=resp.tokens_prompt,
            tokens_completion=resp.tokens_completion,
            cost_usd=resp.cost_usd,
            error=resp.error,
        )
        verdict = self.judge.judge(probe, attempt)

        with self._lock:
            self._spent += resp.cost_usd
            if self.budget_usd and self._spent > self.budget_usd:
                self._stop.set()
            if self.store is not None:
                self.store.checkpoint(attempt, verdict)
            if self.on_progress:
                self.on_progress(attempt, verdict)
        return attempt, verdict

    # ------------------------------------------------------------------ #
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
        if self.run_id:
            manifest.run_id = self.run_id
        result = RunResult(manifest=manifest)

        # Resume: skip slots already recorded under this run id.
        done: set[tuple[str, int]] = set()
        if self.store is not None and self.run_id:
            done = self.store.completed_slots(self.run_id)

        slots = [(p, i) for p in probes for i in range(self.repeats)
                 if (p.id, i) not in done]
        result.skipped = len(probes) * self.repeats - len(slots)

        if self.store is not None:
            self.store.save_run(manifest)
            self.store.log(
                manifest.run_id, "run.start", actor=_actor(), host=manifest.host,
                target=info.model_snapshot,
                detail=f"{len(slots)} slots queued, {result.skipped} resumed",
            )

        if self.concurrency == 1:
            for probe, i in slots:
                if self._stop.is_set():
                    break
                out = self._execute(probe, i, manifest.run_id)
                if out:
                    result.attempts.append(out[0])
                    result.verdicts.append(out[1])
        else:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = [pool.submit(self._execute, p, i, manifest.run_id)
                           for p, i in slots]
                for fut in as_completed(futures):
                    out = fut.result()
                    if out:
                        result.attempts.append(out[0])
                        result.verdicts.append(out[1])

        # Restore deterministic order: concurrency must not change findings.
        order = {p.id: n for n, p in enumerate(probes)}
        result.attempts.sort(key=lambda a: (order.get(a.probe_id, 0), a.repeat_index))
        idx = {a.attempt_id: (order.get(a.probe_id, 0), a.repeat_index)
               for a in result.attempts}
        result.verdicts.sort(key=lambda v: idx.get(v.attempt_id, (0, 0)))

        manifest.spent_usd = self._spent
        if self._stop.is_set():
            manifest.notes = "stopped early: budget exceeded"
        manifest.finished_at = _now()

        if self.store is not None:
            self.store.save_run(manifest)
            self.store.log(
                manifest.run_id, "run.finish", actor=_actor(), host=manifest.host,
                target=info.model_snapshot,
                detail=f"{len(result.attempts)} attempts, ${self._spent:.4f} spent"
                       + (" (BUDGET STOP)" if self._stop.is_set() else ""),
            )
        return result
