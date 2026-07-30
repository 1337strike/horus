"""Run configuration.

A run is fully described by one YAML file so it is version-controllable and
reproducible. See config/example.config.yaml for the annotated reference.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class JudgeConfig:
    kind: str = "ensemble"  # deterministic | llm | ensemble
    judge_target: dict[str, Any] = field(default_factory=lambda: {"kind": "mock"})
    review_low: float = 0.35
    review_high: float = 0.65


@dataclass
class RunConfig:
    target: dict[str, Any]
    packs: list[str]
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    repeats: int = 5
    budget_usd: float = 5.0
    threat_model_id: str = ""
    tool_policy: str = ""      # path to a tool policy YAML (agentic targets)
    db_path: str = "horus.db"
    out_html: str = "horus_report.html"

    @staticmethod
    def load(path: str | Path) -> "RunConfig":
        data = yaml.safe_load(Path(path).read_text())
        jc = data.get("judge", {}) or {}
        return RunConfig(
            target=data["target"],
            packs=data["packs"],
            judge=JudgeConfig(
                kind=jc.get("kind", "ensemble"),
                judge_target=jc.get("judge_target", {"kind": "mock"}),
                review_low=jc.get("review_low", 0.35),
                review_high=jc.get("review_high", 0.65),
            ),
            repeats=data.get("repeats", 5),
            budget_usd=data.get("budget_usd", 5.0),
            threat_model_id=data.get("threat_model_id", ""),
            tool_policy=data.get("tool_policy", ""),
            db_path=data.get("db_path", "horus.db"),
            out_html=data.get("out_html", "horus_report.html"),
        )
