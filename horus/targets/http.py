"""HTTP-based targets.

``HTTPTarget`` is a generic connector for an arbitrary chatbot endpoint: you
describe how to build the request body and where the reply text lives in the
response JSON, via a small template. ``OpenAICompatTarget`` is a convenience
subclass for the very common OpenAI-style ``/chat/completions`` shape, which
also covers many local servers (vLLM, Ollama's OpenAI shim, LM Studio, etc.).

No provider SDKs are required — everything goes through httpx so the dependency
surface stays small and every request/response is inspectable.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from ..models import TargetInfo
from ..pricing import Pricing
from .base import Target, TargetResponse


# Sentinel distinguishing "the path does not exist" from "the path holds an
# empty string". The difference is the whole ballgame: an empty reply is a real
# observation about the target, while an unresolvable path means we are reading
# the wrong field and know nothing at all.
_MISSING = object()


def _dig(obj: Any, path: str) -> Any:
    """Fetch a nested value by dotted path, or ``_MISSING`` if it does not exist."""
    cur = obj
    for part in path.split("."):
        if part.isdigit() and isinstance(cur, list):
            idx = int(part)
            if idx >= len(cur):
                return _MISSING
            cur = cur[idx]
        elif isinstance(cur, dict):
            if part not in cur:
                return _MISSING
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _shape_hint(data: Any) -> str:
    """A short description of what we actually got, for the error message."""
    if isinstance(data, dict):
        keys = list(data)[:8]
        hint = f"top-level keys: {keys}"
        err = data.get("error") or data.get("message")
        if err:
            hint += f"; body reported error: {str(err)[:160]}"
        return hint
    return f"response was {type(data).__name__}, not an object"


class HTTPTarget(Target):
    kind = "http"

    def __init__(
        self,
        endpoint: str,
        *,
        model: str = "unknown",
        headers: dict[str, str] | None = None,
        body_template: dict[str, Any] | None = None,
        messages_field: str = "messages",
        response_path: str = "choices.0.message.content",
        tool_calls_path: str = "choices.0.message.tool_calls",
        timeout: float = 60.0,
        max_rate_per_min: float = 0.0,
        pricing: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.headers = self._expand_env(headers or {})
        self.body_template = body_template or {}
        self.messages_field = messages_field
        self.response_path = response_path
        self.tool_calls_path = tool_calls_path
        self.timeout = timeout
        self.params = params or {}
        self.pricing = Pricing.from_dict(pricing)
        # Client-side throttle. Enterprise targets sit behind quotas, and the
        # polite thing (as well as the thing that avoids a 429 storm) is to not
        # exceed them in the first place.
        self._min_interval = 60.0 / max_rate_per_min if max_rate_per_min else 0.0
        self._last_call = 0.0
        self._client = httpx.Client(timeout=timeout)

    def _throttle(self) -> None:
        if not self._min_interval:
            return
        wait = self._min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    @staticmethod
    def _expand_env(headers: dict[str, str]) -> dict[str, str]:
        """Allow ${ENV_VAR} in header values so secrets stay out of configs."""
        out = {}
        for k, v in headers.items():
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                out[k] = os.environ.get(v[2:-1], "")
            else:
                out[k] = v
        return out

    def send(self, messages: list[dict[str, str]]) -> TargetResponse:
        body = dict(self.body_template)
        body[self.messages_field] = messages
        if self.model and "model" not in body:
            body["model"] = self.model
        body.update(self.params)

        self._throttle()
        t0 = time.perf_counter()
        try:
            resp = self._client.post(self.endpoint, json=body, headers=self.headers)
            latency = (time.perf_counter() - t0) * 1000
            # Surface throttling distinctly so the runner can back off for the
            # interval the provider asked for instead of guessing.
            if resp.status_code == 429:
                retry_after = resp.headers.get("retry-after", "")
                return TargetResponse(
                    text="", latency_ms=latency,
                    error=f"rate_limited: retry-after={retry_after or 'unspecified'}",
                )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            return TargetResponse(text="", error=f"http_error: {exc}")
        except ValueError as exc:  # bad JSON
            return TargetResponse(text="", error=f"decode_error: {exc}")

        text = _dig(data, self.response_path)

        # A response shape we cannot read is an ERROR, never an empty pass.
        # Providers change payload shapes without notice; if that silently
        # yielded "" the judge would score every probe as safe and the run would
        # report a flawless security posture built on nothing. Fail loudly.
        if text is _MISSING:
            return TargetResponse(
                text="",
                latency_ms=latency,
                raw=data if isinstance(data, dict) else {},
                error=(
                    f"response_path {self.response_path!r} did not resolve — "
                    f"the target's payload shape may have changed. {_shape_hint(data)}"
                ),
            )

        # Tool calls. Without this the entire agentic evaluation — trace
        # judging, taint tracking, tool policy — was inert against any real
        # target: it only ever saw the empty default and had nothing to judge.
        raw_calls = _dig(data, self.tool_calls_path)
        tool_calls = raw_calls if isinstance(raw_calls, list) else []

        usage = data.get("usage", {}) if isinstance(data, dict) else {}
        pt = int(usage.get("prompt_tokens", 0) or 0)
        ct = int(usage.get("completion_tokens", 0) or 0)

        return TargetResponse(
            text=text if isinstance(text, str) else str(text),
            tool_calls=tool_calls,
            latency_ms=latency,
            tokens_prompt=pt,
            tokens_completion=ct,
            cost_usd=self.pricing.cost(pt, ct),
            raw=data if isinstance(data, dict) else {},
        )

    def info(self) -> TargetInfo:
        return TargetInfo(
            kind=self.kind,
            model_snapshot=self.model,
            endpoint=self.endpoint,
            params={
                **self.params,
                "pricing_declared": self.pricing.is_declared,
                "response_path": self.response_path,
                "tool_calls_path": self.tool_calls_path,
            },
        )

    def close(self) -> None:
        self._client.close()


class OpenAICompatTarget(HTTPTarget):
    """Convenience wrapper for OpenAI-style /chat/completions endpoints."""

    kind = "openai_compat"

    def __init__(
        self,
        *,
        base_url: str = "https://api.openai.com/v1",
        model: str,
        api_key_env: str = "OPENAI_API_KEY",
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> None:
        body: dict[str, Any] = {"temperature": temperature}
        if tools:
            body["tools"] = tools
        super().__init__(
            endpoint=f"{base_url.rstrip('/')}/chat/completions",
            model=model,
            headers={"Authorization": f"Bearer ${{{api_key_env}}}"},
            body_template=body,
            response_path="choices.0.message.content",
            tool_calls_path="choices.0.message.tool_calls",
            **kwargs,
        )
