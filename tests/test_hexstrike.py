"""Tests for the HexStrike executor connector.

The connector is the one place Horus drives real offensive tooling, so its
safety interlocks are the most important thing to pin down. The load-bearing
test is ``test_out_of_scope_target_never_reaches_hexstrike``: the scope gate
must refuse on Horus's side of the wire, before any request leaves, because the
executor is the only fence between a mistyped target and a scan of something you
are not authorised to touch.
"""

from __future__ import annotations

import httpx
import pytest

from horus.agentic.scope import Scope
from horus.targets.hexstrike import AuthorisationError, HexStrikeExecutor


def _executor(scope=None, **kw):
    ex = HexStrikeExecutor(
        base_url="http://hexstrike.test:8888",
        scope=scope or Scope(allow_private=True),
        i_have_authorisation=True,
        **kw,
    )
    return ex


def _mock(ex, handler):
    ex._client = httpx.Client(transport=httpx.MockTransport(handler))
    return ex


def _ok_handler(calls):
    def h(req):
        calls.append(str(req.url))
        return httpx.Response(200, json={
            "success": True, "return_code": 0,
            "stdout": "22/tcp open ssh", "stderr": "",
        })
    return h


# --------------------------------------------------------------------------- #
# Authorisation interlocks
# --------------------------------------------------------------------------- #
def test_refuses_to_build_without_authorisation():
    with pytest.raises(AuthorisationError, match="i_have_authorisation"):
        HexStrikeExecutor(base_url="http://x", scope=Scope(allow_private=True))


def test_refuses_to_build_with_empty_scope():
    """An allowlist with no rules authorises nothing; fail closed at build."""
    with pytest.raises(AuthorisationError, match="empty scope"):
        HexStrikeExecutor(base_url="http://x", scope=Scope(),
                          i_have_authorisation=True)


def test_builds_with_authorisation_and_scope():
    ex = _executor()
    info = ex.info()
    assert info.params["executes_real_tools"] is True
    assert info.params["scope_configured"] is True


# --------------------------------------------------------------------------- #
# The scope fence — the whole point of the connector
# --------------------------------------------------------------------------- #
def test_out_of_scope_target_never_reaches_hexstrike():
    """A public target must be refused on Horus's side, with zero HTTP calls."""
    calls: list[str] = []
    ex = _mock(_executor(), _ok_handler(calls))
    r = ex.send([{"role": "user", "content": 'tool: nmap\n{"target": "8.8.8.8"}'}])
    assert r.error and "scope refusal" in r.error
    assert calls == []            # nothing left the building
    # the refusal is still recorded as a blocked action for the report
    assert r.tool_calls[0]["blocked"] == "out_of_scope"
    ex.close()


def test_in_scope_target_executes():
    calls: list[str] = []
    ex = _mock(_executor(), _ok_handler(calls))
    r = ex.send([{"role": "user", "content": 'tool: nmap\n{"target": "192.168.1.50"}'}])
    assert r.error is None
    assert len(calls) == 1 and calls[0].endswith("/api/tools/nmap")
    assert r.tool_calls[0]["name"] == "hexstrike.nmap"
    assert r.tool_calls[0]["resolved_target"] == "192.168.1.50"
    assert "ssh" in r.text
    ex.close()


def test_metadata_endpoint_is_refused():
    calls: list[str] = []
    ex = _mock(_executor(), _ok_handler(calls))
    r = ex.send([{"role": "user",
                  "content": 'tool: nuclei\n{"target": "http://169.254.169.254"}'}])
    assert r.error and "scope refusal" in r.error
    assert calls == []
    ex.close()


def test_scope_check_uses_the_resolved_address():
    """A name in scope config is honoured; an out-of-scope resolve is refused."""
    ex = _mock(_executor(scope=Scope(allow_cidrs=("10.0.0.0/8",))),
               _ok_handler([]))
    r = ex.send([{"role": "user", "content": 'tool: nmap\n{"target": "1.1.1.1"}'}])
    assert r.error and "out of scope" in r.error
    ex.close()


# --------------------------------------------------------------------------- #
# Intrusive tools
# --------------------------------------------------------------------------- #
def test_intrusive_tool_refused_by_default():
    calls: list[str] = []
    ex = _mock(_executor(), _ok_handler(calls))
    r = ex.send([{"role": "user", "content": 'tool: sqlmap\n{"target": "192.168.1.50"}'}])
    assert r.error and "intrusive" in r.error
    assert calls == []            # refused before scope check even matters
    ex.close()


def test_intrusive_tool_allowed_when_opted_in():
    calls: list[str] = []
    ex = _mock(_executor(allow_intrusive=True), _ok_handler(calls))
    r = ex.send([{"role": "user", "content": 'tool: sqlmap\n{"target": "192.168.1.50"}'}])
    assert r.error is None
    assert len(calls) == 1
    ex.close()


# --------------------------------------------------------------------------- #
# Probe parsing and transport
# --------------------------------------------------------------------------- #
def test_probe_without_a_tool_is_an_error():
    ex = _mock(_executor(), _ok_handler([]))
    r = ex.send([{"role": "user", "content": '{"target": "192.168.1.50"}'}])
    assert r.error and "did not name a HexStrike tool" in r.error
    ex.close()


def test_unknown_tool_endpoint_is_surfaced():
    def h(req):
        return httpx.Response(404, text="not found")
    ex = _mock(_executor(), h)
    r = ex.send([{"role": "user", "content": 'tool: notatool\n{"target": "192.168.1.50"}'}])
    assert r.error and "no tool endpoint" in r.error
    ex.close()


def test_stderr_is_included_in_output():
    def h(req):
        return httpx.Response(200, json={
            "success": False, "return_code": 1,
            "stdout": "partial", "stderr": "permission denied",
        })
    ex = _mock(_executor(), h)
    r = ex.send([{"role": "user", "content": 'tool: nmap\n{"target": "192.168.1.50"}'}])
    assert "partial" in r.text and "permission denied" in r.text
    ex.close()


def test_hexstrike_error_does_not_crash_the_run():
    def h(req):
        raise httpx.ConnectError("connection refused")
    ex = _mock(_executor(), h)
    r = ex.send([{"role": "user", "content": 'tool: nmap\n{"target": "192.168.1.50"}'}])
    assert r.error and "hexstrike_http_error" in r.error
    ex.close()


def test_target_can_be_a_url_or_host_field():
    calls: list[str] = []
    ex = _mock(_executor(), _ok_handler(calls))
    ex.send([{"role": "user", "content": 'tool: nuclei\n{"url": "http://192.168.1.50"}'}])
    assert len(calls) == 1
    ex.close()
