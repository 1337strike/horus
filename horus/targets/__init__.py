"""Target registry: build a Target from a config dict."""

from __future__ import annotations

from typing import Any

from .base import Target, TargetResponse
from .http import HTTPTarget, OpenAICompatTarget
from .mock import MockJudgeTarget, MockTarget
from .mock_agent import MockAgentTarget
from .mock_infra_agent import MockInfraAgentTarget
from .infra_agent import InfraAgentTarget, ScopeError
from .hexstrike import HexStrikeExecutor, AuthorisationError, ScopeRefusal

__all__ = ["Target", "TargetResponse", "build_target", "ScopeError",
           "AuthorisationError", "ScopeRefusal"]


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
    if kind == "mock_agent":
        return MockAgentTarget(**params)
    if kind == "mock_infra_agent":
        return MockInfraAgentTarget(**params)
    if kind == "infra_agent":
        return InfraAgentTarget(**params)
    if kind == "hexstrike":
        from ..agentic.scope import Scope
        sc = params.pop("scope", {})
        scope = Scope.load(sc) if isinstance(sc, str) else Scope(
            allow_hosts=tuple(sc.get("allow_hosts", [])),
            allow_cidrs=tuple(sc.get("allow_cidrs", [])),
            allow_private=bool(sc.get("allow_private", False)),
            deny_hosts=tuple(sc.get("deny_hosts", [])),
            deny_cidrs=tuple(sc.get("deny_cidrs", [])),
            deny_metadata=bool(sc.get("deny_metadata", True)),
        )
        return HexStrikeExecutor(scope=scope, **params)
    if kind == "openai_compat":
        return OpenAICompatTarget(**params)
    if kind == "http":
        return HTTPTarget(**params)
    raise ValueError(f"Unknown target kind: {kind!r}")
