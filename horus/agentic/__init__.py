"""Agentic target support: tool policies, scope, and action-trace evaluation."""

from .infra import InfraHit, scan_arguments, scan_text
from .policy import Authorization, ToolPolicy, ToolSpec
from .scope import Scope, ScopeResult
from .trace import (
    ToolCall, Violation, ViolationKind, analyse, primary_violation, worst_severity,
)

__all__ = [
    "Authorization", "ToolPolicy", "ToolSpec",
    "Scope", "ScopeResult",
    "InfraHit", "scan_text", "scan_arguments",
    "ToolCall", "Violation", "ViolationKind", "analyse", "primary_violation",
    "worst_severity",
]
