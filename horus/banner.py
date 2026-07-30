"""Terminal banner.

A launch banner makes the tool feel finished, but a banner printed in the wrong
place breaks things — a banner in a piped JSON or SARIF stream corrupts it. So
this prints one only when it is safe to: on a real TTY, not for machine-output
commands, not when suppressed. On a pipe it emits nothing at all.

The mark mirrors the repository banner: the wedjat (Eye of Horus) beside the
HORUS wordmark, in gold on a dark ground. Colour follows the same TTY rule; on a
pipe the art degrades to nothing, so no escape codes ever leak into a log.
"""

from __future__ import annotations

import os
import sys

# 256-colour palette chosen to match docs/banner.svg: electrum gold on lapis.
_GOLD = "\033[38;5;179m"       # electrum
_GOLD_HI = "\033[38;5;223m"    # highlight (the pupil / accents)
_BLUE = "\033[38;5;24m"        # faience blue (tagline)
_FAINT = "\033[38;5;238m"      # version line
_BG = "\033[48;5;233m"         # near-black lapis ground
_RESET = "\033[0m"

# The wedjat, matched to the SVG: brow arc, almond eye, pupil, malar stripe,
# spiral tail. Kept as a line list so no escape-prone raw strings are needed.
_EYE = [
    "   .-\"\"\"\"-.__",
    " .'         '--.",
    "'    _______     '.",
    "   .'       '.     \\",
    "  |    (O)    |     |",
    "   '.       .'     /",
    " '-.__'---'    _.-'",
    "      \\ \\'--''",
    "       \\ '.",
    "        '.  '._",
    "          '.   '-._",
    "            '-.___.>",
]
_WORD = [
    "",
    "",
    " _   _  ___  ____  _   _ ____",
    "| | | |/ _ \\|  _ \\| | | / ___|",
    "| |_| | | | | |_) | | | \\___ \\",
    "|  _  | |_| |  _ <| |_| |___) |",
    "|_| |_|\\___/|_| \\_\\\\___/|____/",
    "",
    "",
    "",
    "",
    "",
]
_TAGLINE = "the eye that measures its own sight"


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


def render(version: str, *, colour: bool) -> str:
    if colour:
        gold, hi, blue, faint, rst = _GOLD, _GOLD_HI, _BLUE, _FAINT, _RESET
    else:
        gold = hi = blue = faint = rst = ""

    eye_w = max(len(l) for l in _EYE)
    lines = []
    for i in range(max(len(_EYE), len(_WORD))):
        eye = _EYE[i] if i < len(_EYE) else ""
        word = _WORD[i] if i < len(_WORD) else ""
        # highlight the pupil line
        eye_col = f"{hi}{eye}{rst}" if "(O)" in eye else f"{gold}{eye}{rst}"
        lines.append(f"  {eye_col}{'' if not colour else ''}"
                     f"{' ' * (eye_w - len(eye) + 4)}{gold}{word}{rst}")
    body = "\n".join(lines)
    footer = (
        f"\n  {blue}{_TAGLINE}{rst}"
        f"{' ' * 8}{faint}v{version}  ·  authorised testing only{rst}"
    )
    return f"\n{body}{footer}\n"


def print_banner(version: str, *, stream=None, force: bool = False) -> None:
    """Print the banner if it is safe to. No-op otherwise."""
    stream = stream or sys.stderr  # stderr, so stdout stays clean for data
    if not _should_show(stream, force):
        return
    stream.write(render(version, colour=_colour_ok(stream)))
    stream.flush()
