"""Banner tests.

A launch banner is cosmetic, but printing it in the wrong place is not: a banner
in a piped JSON or SARIF stream corrupts it. These tests pin the safety
properties — the banner shows for a human and vanishes for a machine.
"""

from __future__ import annotations

import io

from horus.banner import _colour_ok, _should_show, print_banner, render


class _TTY(io.StringIO):
    def isatty(self):
        return True


class _Pipe(io.StringIO):
    def isatty(self):
        return False


def test_banner_renders_the_mark_and_version():
    out = render("1.2.3", colour=False)
    assert "◉" in out or "()" in out     # the eye pupil is present
    
    assert "v1.2.3" in out
    assert "authorised testing only" in out


def test_no_ansi_codes_when_colour_off():
    assert "\033[" not in render("0.1.0", colour=False)


def test_ansi_codes_present_when_colour_on():
    assert "\033[" in render("0.1.0", colour=True)


def test_shows_on_a_tty():
    assert _should_show(_TTY(), force=False)


def test_hidden_when_piped():
    """The load-bearing property: no banner into a non-TTY stream."""
    assert not _should_show(_Pipe(), force=False)


def test_force_overrides_pipe():
    assert _should_show(_Pipe(), force=True)


def test_no_banner_env_suppresses(monkeypatch):
    monkeypatch.setenv("HORUS_NO_BANNER", "1")
    assert not _should_show(_TTY(), force=False)


def test_no_color_env_disables_colour(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert not _colour_ok(_TTY())


def test_print_banner_writes_nothing_to_a_pipe():
    pipe = _Pipe()
    print_banner("0.1.0", stream=pipe)
    assert pipe.getvalue() == ""


def test_print_banner_writes_to_a_tty():
    tty = _TTY()
    print_banner("0.1.0", stream=tty)
    v = tty.getvalue()
    assert "◉" in v or "()" in v


def test_cli_export_does_not_emit_a_banner(tmp_path, monkeypatch, capsys):
    """Machine-output commands must never print the banner, even on a TTY."""
    from horus import cli

    # Force the "is this a TTY" check to say yes, so only the command-name guard
    # can be what suppresses the banner.
    monkeypatch.setattr(cli.sys, "stderr", _TTY())
    # export with a nonexistent run should fail fast, but crucially print no art
    rc = cli.main(["export", "--config", "config/example.config.yaml",
                   "--run-id", "nope", "--out", str(tmp_path / "x.sarif")])
    err = cli.sys.stderr.getvalue() if hasattr(cli.sys.stderr, "getvalue") else ""
    assert "HORUS" not in err or "authorised testing" not in err
