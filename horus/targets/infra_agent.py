"""Scope-gated connector for a real infrastructure agent.

This is how you point Horus at an agent endpoint you already run in your lab.
It is a thin wrapper over the ordinary HTTP connector with one addition that is
not optional: a scope gate. Before the wrapper will send anything, the agent's
endpoint must resolve to a target inside the scope you declared. If it does not,
the run refuses to start — you cannot accidentally aim a run at something you
did not authorise.

The gate protects the *endpoint you are talking to*. It does not, and cannot,
stop the agent on the other end from reaching out to something out of scope on
its own — that is precisely the behaviour the network_pivot probes are designed
to detect and report. The scope gate keeps Horus itself inside the fence; the
probes measure whether the agent stays there too.
"""

from __future__ import annotations

from typing import Any

from ..agentic.scope import Scope
from ..models import TargetInfo
from .base import Target, TargetResponse
from .http import HTTPTarget


class ScopeError(RuntimeError):
    pass


class InfraAgentTarget(Target):
    kind = "infra_agent"

    def __init__(
        self,
        *,
        endpoint: str,
        scope: dict[str, Any] | str,
        model: str = "infra-agent",
        response_path: str = "choices.0.message.content",
        tool_calls_path: str = "choices.0.message.tool_calls",
        **kwargs: Any,
    ) -> None:
        self.scope = Scope.load(scope) if isinstance(scope, str) else Scope(
            allow_hosts=tuple(scope.get("allow_hosts", [])),
            allow_cidrs=tuple(scope.get("allow_cidrs", [])),
            allow_private=bool(scope.get("allow_private", False)),
            deny_hosts=tuple(scope.get("deny_hosts", [])),
            deny_cidrs=tuple(scope.get("deny_cidrs", [])),
            deny_metadata=bool(scope.get("deny_metadata", True)),
        )
        if not self.scope.is_configured:
            raise ScopeError(
                "infra_agent target requires a configured scope (allow_hosts / "
                "allow_cidrs / allow_private). Refusing to run without a fence."
            )

        result = self.scope.check(endpoint)
        if not result.allowed:
            raise ScopeError(
                f"endpoint {endpoint!r} is out of scope "
                f"(resolved {result.resolved}): {result.reason}. "
                f"Add it to the scope file if you are authorised to test it."
            )
        self._scope_result = result
        self._http = HTTPTarget(
            endpoint=endpoint, model=model,
            response_path=response_path, tool_calls_path=tool_calls_path,
            **kwargs,
        )

    def send(self, messages: list[dict[str, str]]) -> TargetResponse:
        return self._http.send(messages)

    def info(self) -> TargetInfo:
        base = self._http.info()
        base.params = {
            **base.params,
            "scope_ok": self._scope_result.allowed,
            "scope_resolved": self._scope_result.resolved,
        }
        base.kind = self.kind
        return base

    def close(self) -> None:
        self._http.close()
