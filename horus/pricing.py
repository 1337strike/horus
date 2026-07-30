"""Cost accounting.

``budget_usd`` was previously documented as a hard cap that stops a run. It
could never fire, because nothing ever populated ``cost_usd`` — the counter sat
at zero forever while a run billed against a real provider. A documented control
that cannot trigger is worse than no control, because people rely on it.

Pricing is declared per target in the run config rather than hard-coded against
a table of model names. Provider prices change without notice, and a stale
built-in table would silently under-report spend — the same class of failure as
a stale response path. Declaring it in config means the number in the manifest
is the number you agreed to, and it is recorded with the run for audit.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Pricing:
    """USD per one million tokens, as billed by the provider."""

    input_per_1m: float = 0.0
    output_per_1m: float = 0.0
    # Some providers bill a flat fee per request on top of tokens.
    per_request: float = 0.0

    def cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (
            prompt_tokens / 1_000_000 * self.input_per_1m
            + completion_tokens / 1_000_000 * self.output_per_1m
            + self.per_request
        )

    @property
    def is_declared(self) -> bool:
        """False when no pricing was configured.

        The runner uses this to warn loudly: an undeclared price means the
        budget cap is inert, and the operator should know that before a long
        run rather than after the invoice.
        """
        return bool(self.input_per_1m or self.output_per_1m or self.per_request)

    @staticmethod
    def from_dict(d: dict | None) -> "Pricing":
        d = d or {}
        return Pricing(
            input_per_1m=float(d.get("input_per_1m", 0.0)),
            output_per_1m=float(d.get("output_per_1m", 0.0)),
            per_request=float(d.get("per_request", 0.0)),
        )
