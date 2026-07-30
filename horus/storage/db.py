"""SQLite persistence.

Stores every run, attempt, and verdict so results are auditable, reproducible,
and support regression testing (re-run one probe id and compare). We keep the
full request/response of each attempt — the transcript is the evidence.

Note on sensitivity: this database holds adversarial content and findings about
a client's system. Treat the file as a sensitive artifact — see RESPONSIBLE_USE.md.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict
from pathlib import Path

from ..models import Attempt, RunManifest, Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT, finished_at TEXT,
    target_kind TEXT, model_snapshot TEXT, endpoint TEXT,
    repeats INTEGER, threat_model_id TEXT, horus_version TEXT,
    budget_usd REAL, spent_usd REAL, host TEXT,
    pack_hashes TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    run_id TEXT, probe_id TEXT, repeat_index INTEGER,
    request TEXT, response_text TEXT, tool_calls TEXT,
    latency_ms REAL, tokens_prompt INTEGER, tokens_completion INTEGER,
    cost_usd REAL, error TEXT, created_at TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id TEXT PRIMARY KEY,
    attempt_id TEXT, probe_id TEXT,
    outcome TEXT, confidence REAL, judge TEXT,
    rationale TEXT, matched_signal TEXT,
    FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
);
CREATE INDEX IF NOT EXISTS idx_attempts_run ON attempts(run_id);
CREATE INDEX IF NOT EXISTS idx_verdicts_probe ON verdicts(probe_id);
-- Resume depends on knowing exactly which (probe, repeat) pairs already landed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_attempt_slot
    ON attempts(run_id, probe_id, repeat_index);

-- Who ran what, when, against which target. Findings about someone else's
-- system are sensitive enough that "which of us produced this report" is a
-- question that has to have an answer.
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, ts TEXT, actor TEXT, host TEXT,
    action TEXT, config_sha TEXT, target TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_run ON audit(run_id);
"""


class Store:
    def __init__(self, path: str | Path = "horus.db") -> None:
        self.path = str(path)
        # The runner writes from a worker pool, so the connection has to be
        # usable across threads. sqlite3 allows that only if we take
        # responsibility for serialising access ourselves, which the lock below
        # does for every write path. WAL lets a reader proceed during writes.
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self.conn.executescript(_SCHEMA)
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:  # pragma: no cover - e.g. :memory:
            pass

    def save_run(self, manifest: RunManifest) -> None:
        t = manifest.target
        with self._lock:
            self._save_run(manifest, t)

    def _save_run(self, manifest: RunManifest, t) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO runs VALUES
               (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                manifest.run_id, manifest.started_at, manifest.finished_at,
                t.kind if t else "", t.model_snapshot if t else "",
                t.endpoint if t else "", manifest.repeats,
                manifest.threat_model_id, manifest.horus_version,
                manifest.budget_usd, manifest.spent_usd, manifest.host,
                json.dumps(manifest.probe_pack_hashes), manifest.notes,
            ),
        )
        self.conn.commit()

    def save_attempt(self, a: Attempt) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                a.attempt_id, a.run_id, a.probe_id, a.repeat_index,
                json.dumps(a.request), a.response_text, json.dumps(a.tool_calls),
                a.latency_ms, a.tokens_prompt, a.tokens_completion,
                a.cost_usd, a.error, a.created_at,
            ),
        )

    def save_verdict(self, v: Verdict) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO verdicts VALUES (?,?,?,?,?,?,?,?)""",
            (
                v.verdict_id, v.attempt_id, v.probe_id, v.outcome.value,
                v.confidence, v.judge.value, v.rationale, v.matched_signal,
            ),
        )

    # ---------------------------------------------------------------- #
    # Checkpointing and resume
    # ---------------------------------------------------------------- #
    def completed_slots(self, run_id: str) -> set[tuple[str, int]]:  # noqa: D401
        """(probe_id, repeat_index) pairs already recorded for this run.

        A long assessment is thousands of paid calls. Losing six hours of them
        to one transient failure is not acceptable, so the runner writes as it
        goes and asks this on restart for what is left to do.
        """
        rows = self.conn.execute(
            "SELECT probe_id, repeat_index FROM attempts WHERE run_id = ?", (run_id,)
        ).fetchall()
        return {(r["probe_id"], r["repeat_index"]) for r in rows}

    def load_manifest_row(self, run_id: str):
        return self.conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    def checkpoint(self, attempt, verdict) -> None:
        """Persist one attempt and its verdict immediately."""
        with self._lock:
            self.save_attempt(attempt)
            self.save_verdict(verdict)
            self.conn.commit()

    def log(self, run_id: str, action: str, *, actor: str = "", host: str = "",
            config_sha: str = "", target: str = "", detail: str = "") -> None:
        from datetime import datetime, timezone

        with self._lock:
            self.conn.execute(
                "INSERT INTO audit (run_id, ts, actor, host, action, config_sha,"
                " target, detail) VALUES (?,?,?,?,?,?,?,?)",
                (run_id, datetime.now(timezone.utc).isoformat(), actor, host,
                 action, config_sha, target, detail),
            )
            self.conn.commit()

    def save_result(self, result) -> None:
        self.save_run(result.manifest)
        with self._lock:
            for a in result.attempts:
                self.save_attempt(a)
            for v in result.verdicts:
                self.save_verdict(v)
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()
