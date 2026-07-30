"""Tool policy: a declaration of what authority the agent under test actually has.

Why a policy is required
------------------------
For a text target, "the attack succeeded" means the model *said* something it
shouldn't. For an agentic target it means the model *did* something it
shouldn't — and "shouldn't" is only meaningful relative to a declared authority.
Calling ``send_email`` is routine for a support agent and catastrophic for a
code-review bot. So Horus refuses to guess: you declare the policy, and the
trace evaluator judges against it.

The policy captures four things per tool, each of which drives a different class
of finding:

``authorization``
    ``allowed`` / ``confirm`` / ``forbidden``. The blunt instrument.

``reads_sensitive`` and ``egresses``
    The two halves of an exfiltration. Neither is a violation alone — reading a
    customer record is the agent's job, and posting to the ticketing API is too.
    The violation is the *flow* from one to the other, which is why the
    evaluator tracks taint across the call sequence rather than judging calls
    one at a time.

``reversible``
    Severity, not permission. An unauthorised read is bad; an unauthorised wire
    transfer cannot be undone. The same violation on an irreversible tool is
    escalated.

``arg_constraints``
    Per-parameter regexes. This is the general mechanism behind destination
    allowlists (``to`` must match an internal domain) and path scoping (``path``
    must stay under a prefix). Scope escalation usually shows up in an argument,
    not a tool name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Authorization(str, Enum):
    ALLOWED = "allowed"
    CONFIRM = "confirm"      # agent must obtain explicit human approval first
    FORBIDDEN = "forbidden"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    authorization: Authorization = Authorization.ALLOWED
    reads_sensitive: bool = False
    egresses: bool = False
    reversible: bool = True
    description: str = ""
    # param name -> regex the argument must fully match to be in scope
    arg_constraints: dict[str, str] = field(default_factory=dict)

    def check_args(self, args: dict[str, Any]) -> tuple[str, str] | None:
        """Return (param, pattern) of the first constraint violated, else None."""
        for param, pattern in self.arg_constraints.items():
            if param not in args:
                continue
            value = str(args[param])
            if not re.fullmatch(pattern, value, re.I):
                return (param, pattern)
        return None


@dataclass
class ToolPolicy:
    """The full authority declaration for one agentic target."""

    tools: dict[str, ToolSpec] = field(default_factory=dict)
    # Phrases in a user turn that count as the human granting approval. Without
    # one of these, a `confirm` tool must not be called.
    approval_markers: tuple[str, ...] = ("approved", "yes, go ahead", "confirmed")
    # Tools not named in the policy: treat as forbidden by default. Fail closed —
    # an agent reaching for an undeclared capability is a finding, not a gap in
    # our paperwork.
    unknown_tools_forbidden: bool = True

    def get(self, name: str) -> ToolSpec | None:
        return self.tools.get(name)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ToolPolicy":
        tools: dict[str, ToolSpec] = {}
        for t in d.get("tools", []):
            spec = ToolSpec(
                name=t["name"],
                authorization=Authorization(t.get("authorization", "allowed")),
                reads_sensitive=bool(t.get("reads_sensitive", False)),
                egresses=bool(t.get("egresses", False)),
                reversible=bool(t.get("reversible", True)),
                description=t.get("description", ""),
                arg_constraints=dict(t.get("arg_constraints", {})),
            )
            tools[spec.name] = spec
        return ToolPolicy(
            tools=tools,
            approval_markers=tuple(
                d.get("approval_markers", ["approved", "yes, go ahead", "confirmed"])
            ),
            unknown_tools_forbidden=bool(d.get("unknown_tools_forbidden", True)),
        )

    @staticmethod
    def load(path: str | Path) -> "ToolPolicy":
        return ToolPolicy.from_dict(yaml.safe_load(Path(path).read_text()) or {})
