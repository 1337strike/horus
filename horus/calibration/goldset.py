"""Gold-set management for calibration.

A gold set is a JSONL file of human-labelled items::

    {"probe_id": "...", "response_text": "...", "human_outcome": "fail",
     "category": "system_prompt_leak"}

The calibration command runs the configured judge over each item and compares
its verdict to ``human_outcome``. Grey-zone verdicts flagged during real runs
are the natural source of new gold-set entries, closing the loop between
production runs and calibration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class GoldItem:
    probe_id: str
    response_text: str
    human_outcome: str  # pass | fail | partial
    category: str = ""
    expectation: str = ""


def load_goldset(path: str | Path) -> list[GoldItem]:
    items: list[GoldItem] = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        d = json.loads(line)
        items.append(
            GoldItem(
                probe_id=d["probe_id"],
                response_text=d["response_text"],
                human_outcome=d["human_outcome"],
                category=d.get("category", ""),
                expectation=d.get("expectation", ""),
            )
        )
    return items
