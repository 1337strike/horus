"""Terminal launch banner.

A full-width launch banner in the style of offensive-tooling dashboards: a large
HORUS wordmark, the Eye of Horus as a mascot to its right, and a short capability
list beneath. Gold on a dark ground, mirroring docs/banner.svg.

Safety first, because a banner in the wrong stream breaks things — a banner in a
piped JSON or SARIF stream corrupts it. So it prints only on a real TTY, never
for machine-output commands, never when suppressed, and on a pipe it emits
nothing at all (no text, no escape codes). It writes to stderr so stdout stays
clean for data.

Two mascot styles are shipped. The block-character eye reads best on modern
terminals; an ASCII fallback is used when the terminal or locale cannot be
trusted with box-drawing glyphs, so the banner never turns into mojibake.
"""

from __future__ import annotations

import os
import sys

# 256-colour palette matched to docs/banner.svg: electrum gold on lapis.
_GOLD = "\033[38;5;179m"      # electrum
_GOLD_HI = "\033[38;5;222m"   # highlight
_GOLD_DK = "\033[38;5;136m"   # shadow strokes
_BLUE = "\033[38;5;73m"       # faience
_STEEL = "\033[38;5;66m"      # secondary text
_FAINT = "\033[38;5;240m"
_RED = "\033[38;5;131m"       # the one warning accent
_RESET = "\033[0m"
_BOLD = "\033[1m"

# HORUS in an ansi-shadow block face (embedded so pyfiglet is not a runtime dep).
_WORD = [
    "██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗",
    "██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔════╝",
    "███████║██║   ██║██████╔╝██║   ██║███████╗",
    "██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║",
    "██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║",
    "╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
]

# The Eye of Horus mascot — solid block silhouette, right of the wordmark.
_MASCOT = [
    "   ▄▄▄▄▄▄▄▄",
    " ▄█████████▄▄",
    "████▀    ▀▀███▄",
    "███  ▄▄▄▄▄  ▀██▌",
    "██  ██▀▀▀██▄  ██▌",
    "██ ██  ◉  ██  ▐██▄▄▄",
    "██  ██▄▄▄██▀  ████▀▀",
    "▐██▄ ▀▀▀▀▘  ▄██▀",
    " ▀████▄▄▄▄████▀",
    "   ▀▀████▀▀ ▀██▄",
    "      ▀        ▀██▄",
]

# ASCII-only fallback mascot for terminals we cannot trust with block glyphs.
_MASCOT_ASCII = [
    "    .-\"\"\"\"-.",
    "  .'  ____  '.",
    " /  .'    '.  \\",
    "|  |   ()   |  |",
    " \\  '.____.'  /",
    "  '-.,____,.-'",
    "     \\  \\'.",
    "      \\  '.'.",
    "       '.  '.'.",
    "         '.   '._",
    "           '-.__.>",
]

_TITLE = "Calibrated LLM Red-Team Harness"
_BY = "the eye that measures its own sight"
_FEATURES = [
    ("◆", "Judge calibration \u2014 Cohen's \u03ba, honest confidence intervals"),
    ("◆", "Agentic & infra testing \u2014 tool-abuse, RCE / SSRF, taint tracking"),
    ("◆", "Scope-fenced execution \u2014 drives real tools, never out of bounds"),
    ("●", "SARIF export, CI gate, resume, audit trail"),
]


def _should_show(stream, force: bool) -> bool:
    if force:
        return True
    if os.environ.get("HORUS_NO_BANNER"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _colour_ok(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _use_unicode() -> bool:
    """Box-drawing art needs a UTF-8 locale; fall back to ASCII otherwise."""
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in enc


def render(version: str, *, colour: bool, unicode: bool = True) -> str:
    if colour:
        g, hi, dk, blue, steel, faint, red, rst, bold = (
            _GOLD, _GOLD_HI, _GOLD_DK, _BLUE, _STEEL, _FAINT, _RED, _RESET, _BOLD
        )
    else:
        g = hi = dk = blue = steel = faint = red = rst = bold = ""

    word = _WORD if unicode else _fallback_word()
    mascot = _MASCOT if unicode else _MASCOT_ASCII
    word_w = max(len(l) for l in word)

    out: list[str] = [""]

    # Wordmark (left) beside mascot (right), top-aligned.
    pad_top = 0
    rows = max(len(word), len(mascot))
    word_off = (rows - len(word)) // 2
    for i in range(rows):
        wi = i - word_off
        w = word[wi] if 0 <= wi < len(word) else ""
        m = mascot[i] if i < len(mascot) else ""
        m_col = m.replace("◉", f"{hi}◉{g}") if colour else m
        out.append(f"  {g}{w:<{word_w}}{rst}    {g}{m_col}{rst}")

    out.append("")
    out.append(f"  {bold}{g}HORUS{rst}  {steel}{_TITLE}{rst}")
    out.append(f"  {faint}v{version}{rst}   {blue}{_BY}{rst}")
    out.append("")
    for mark, text in _FEATURES:
        mk = red if mark == "●" else g
        out.append(f"    {mk}{mark}{rst} {steel}{text}{rst}")
    out.append("")
    out.append(f"  {faint}authorised testing only \u2014 see RESPONSIBLE_USE.md{rst}")
    out.append("")
    return "\n".join(out)


def _fallback_word() -> list[str]:
    return [
        " _   _  ___  ____  _   _ ____",
        "| | | |/ _ \\|  _ \\| | | / ___|",
        "| |_| | | | | |_) | | | \\___ \\",
        "|  _  | |_| |  _ <| |_| |___) |",
        "|_| |_|\\___/|_| \\_\\\\___/|____/",
    ]


def print_banner(version: str, *, stream=None, force: bool = False) -> None:
    """Print the banner if it is safe to. No-op otherwise."""
    stream = stream or sys.stderr  # stderr keeps stdout clean for piped data
    if not _should_show(stream, force):
        return
    stream.write(render(version, colour=_colour_ok(stream), unicode=_use_unicode()))
    stream.flush()
