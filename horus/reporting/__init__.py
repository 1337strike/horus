"""Report rendering."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import Category
from .report import Summary, aggregate, set_category_resolver, taxonomy_row

__all__ = ["aggregate", "set_category_resolver", "render_html", "Summary"]

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html(summary: Summary, manifest, calibration=None) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    tmpl = env.get_template("report.html.j2")
    tax = {c.value: taxonomy_row(c) for c in Category}
    return tmpl.render(summary=summary, manifest=manifest, calibration=calibration, tax=tax)
