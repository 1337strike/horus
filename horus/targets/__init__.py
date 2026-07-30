"""Target registry: build a Target from a config dict."""

from __future__ import annotations

from typing import Any

from .base import Target, TargetResponse
from .http import HTTPTarget, OpenAICompatTarget
from .mock import MockJudgeTarget, MockTarget

__all__ = ["Target", "TargetResponse", "build_target"]


def build_target(cfg: dict[str, Any]) -> Target:
    """Factory. ``cfg`` comes straight from the run config's ``target`` block.

    Example::

        target:
          kind: openai_compat
          base_url: https://api.openai.com/v1
          model: gpt-4o-mini-2024-07-18
          api_key_env: OPENAI_API_KEY
    """
    kind = cfg.get("kind", "mock")
    params = {k: v for k, v in cfg.items() if k != "kind"}

    if kind == "mock":
        return MockTarget(**params)
    if kind == "mock_judge":
        return MockJudgeTarget()
    if kind == "openai_compat":
        return OpenAICompatTarget(**params)
    if kind == "http":
        return HTTPTarget(**params)
    raise ValueError(f"Unknown target kind: {kind!r}")
