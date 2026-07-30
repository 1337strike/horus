"""Executor connector for HexStrike AI.

This is the one place in Horus that drives real offensive tooling. It does not
run anything itself and it does not embody HexStrike's engine — HexStrike is a
separate service that already wraps 150+ tools behind a REST API, and this
module is a *client* to it. Horus stays what it is (the brain: what to run, what
is in scope, how to judge the result) and delegates execution to the thing built
for it.

Why a connector rather than a merge
-----------------------------------
HexStrike executes commands with ``shell=True`` and, crucially, does **not**
enforce scope: its ``scope`` field is descriptive metadata that nothing checks.
Copying that engine into Horus would hand an injection a shell and throw away
the property the rest of Horus is built to protect. Wrapping it as a client
lets Horus add the control HexStrike lacks and keep it on Horus's side of the
wire: **the scope gate is evaluated here, before every request leaves**. If the
target is not inside the scope you declared in writing, the call is refused and
nothing reaches HexStrike.

The connector is therefore two things at once: an executor (it makes real scans
happen in your lab) and a fence (it is the only thing standing between a
mistyped target and a scan of something you are not authorised to touch).

Safety posture
--------------
* Disabled unless explicitly constructed with ``i_have_authorisation=True`` and
  a configured scope. There is no zero-config path to running real tools.
* Scope is checked against the *resolved* address for every single call.
* An allowlist with no rules means nothing is in scope; the gate fails closed.
* Destructive tool categories are refused unless separately opted in.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..agentic.scope import Scope
from ..models import TargetInfo
from .base import Target, TargetResponse


class AuthorisationError(RuntimeError):
    """Raised when the connector is used without explicit authorisation/scope."""


class ScopeRefusal(RuntimeError):
    """Raised when a requested target falls outside the declared scope."""


# Tools that change state on the target rather than only observing it. These
# stay off unless the operator opts in per run, because "I meant to scan, not
# exploit" is a mistake that should require a deliberate second step.
_INTRUSIVE = frozenset({
    "sqlmap", "metasploit", "hydra", "john", "hashcat", "netexec", "wpscan",
})


@dataclass
class HexStrikeExecutor(Target):
    """A Horus target that executes probes as real HexStrike tool runs.

    Each probe's turns are read as a small instruction: the first line names a
    HexStrike tool, the rest are JSON parameters. The connector checks scope,
    calls HexStrike, and returns the tool output as the response text plus a
    synthetic tool-call so the trace judge and the report treat it like any
    other agentic action.
    """

    base_url: str
    scope: Scope
    i_have_authorisation: bool = False
    allow_intrusive: bool = False
    api_key_env: str = "HEXSTRIKE_TOKEN"
    timeout: float = 300.0
    kind: str = field(default="hexstrike", init=False)

    def __post_init__(self) -> None:
        if not self.i_have_authorisation:
            raise AuthorisationError(
                "HexStrikeExecutor runs real offensive tools. Construct it with "
                "i_have_authorisation=True only for systems you own or have "
                "written permission to test. See RESPONSIBLE_USE.md."
            )
        if not self.scope.is_configured:
            raise AuthorisationError(
                "refusing to start with an empty scope: an allowlist with no "
                "rules means nothing is authorised. Declare allow_cidrs / "
                "allow_hosts / allow_private for your lab."
            )
        headers = {}
        token = os.environ.get(self.api_key_env, "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(timeout=self.timeout, headers=headers)
        self._checked_health = False

    # ------------------------------------------------------------------ #
    def _parse_probe(self, messages: list[dict[str, str]]) -> tuple[str, dict[str, Any]]:
        """A probe turn is ``tool: nmap`` then JSON params on following lines."""
        import json

        text = "\n".join(m["content"] for m in messages if m.get("role") == "user")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        tool = ""
        params: dict[str, Any] = {}
        body_lines: list[str] = []
        for ln in lines:
            low = ln.strip().lower()
            if low.startswith("tool:"):
                tool = ln.split(":", 1)[1].strip()
            else:
                body_lines.append(ln)
        if body_lines:
            try:
                params = json.loads("\n".join(body_lines))
            except json.JSONDecodeError:
                params = {"target": body_lines[0].strip()}
        return tool, params

    def _target_of(self, params: dict[str, Any]) -> str:
        return str(params.get("target") or params.get("url") or params.get("host") or "")

    # ------------------------------------------------------------------ #
    def send(self, messages: list[dict[str, str]]) -> TargetResponse:
        tool, params = self._parse_probe(messages)
        if not tool:
            return TargetResponse(text="", error="probe did not name a HexStrike tool")

        if tool in _INTRUSIVE and not self.allow_intrusive:
            return TargetResponse(
                text="",
                error=f"tool {tool!r} is intrusive and allow_intrusive is off; "
                      "refused before any request was sent",
            )

        target = self._target_of(params)
        if not target:
            return TargetResponse(text="", error="probe params named no target")

        # THE FENCE. Evaluated here, on Horus's side, before anything leaves.
        verdict = self.scope.check(target)
        if not verdict.allowed:
            return TargetResponse(
                text="",
                error=f"scope refusal: {target!r} is out of scope "
                      f"(resolved {verdict.resolved}): {verdict.reason}",
                tool_calls=[{"name": f"hexstrike.{tool}", "arguments": params,
                             "blocked": "out_of_scope"}],
            )

        t0 = time.perf_counter()
        try:
            resp = self._client.post(f"{self.base_url.rstrip('/')}/api/tools/{tool}",
                                     json=params)
            latency = (time.perf_counter() - t0) * 1000
            if resp.status_code == 404:
                return TargetResponse(text="", latency_ms=latency,
                                      error=f"HexStrike has no tool endpoint {tool!r}")
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            return TargetResponse(text="", error=f"hexstrike_http_error: {exc}")
        except ValueError as exc:
            return TargetResponse(text="", error=f"hexstrike_decode_error: {exc}")

        stdout = data.get("stdout", "") or ""
        stderr = data.get("stderr", "") or ""
        combined = stdout if not stderr else f"{stdout}\n[stderr]\n{stderr}"

        # Present the execution as an action in the trace, so the evaluator,
        # the infra detectors, and the report all treat it uniformly.
        return TargetResponse(
            text=combined,
            tool_calls=[{
                "name": f"hexstrike.{tool}",
                "arguments": params,
                "resolved_target": verdict.resolved,
                "return_code": data.get("return_code"),
                "success": data.get("success"),
            }],
            latency_ms=latency,
            raw=data if isinstance(data, dict) else {},
        )

    def info(self) -> TargetInfo:
        return TargetInfo(
            kind=self.kind,
            model_snapshot=f"hexstrike@{self.base_url}",
            endpoint=self.base_url,
            params={
                "scope_configured": self.scope.is_configured,
                "allow_intrusive": self.allow_intrusive,
                "executes_real_tools": True,
            },
        )

    def health(self) -> tuple[bool, str]:
        """Ask HexStrike whether it is up and which tools it can see."""
        try:
            r = self._client.get(f"{self.base_url.rstrip('/')}/health")
            r.raise_for_status()
            d = r.json()
            return True, str(d.get("status", "ok"))
        except httpx.HTTPError as exc:
            return False, f"unreachable: {exc}"

    def close(self) -> None:
        self._client.close()
