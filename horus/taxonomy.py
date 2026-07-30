"""Maps Horus's internal categories to public frameworks.

Why this exists
---------------
A report that says "34% attack success" means nothing to a client's security
team unless it maps to a shared language. We pin every category to the OWASP
LLM Top 10 (2025) and to MITRE ATLAS tactics so that:

  1. Coverage gaps are visible ("we test LLM01 and LLM06 but not LLM08").
  2. Findings slot into the client's existing risk register.
  3. The assessment is defensible in an audit.

References are identifiers, not copied text — consult the source projects for
the authoritative descriptions.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Category


@dataclass(frozen=True)
class TaxonomyEntry:
    owasp_llm: str  # e.g. "LLM01:2025"
    owasp_name: str
    atlas: tuple[str, ...]  # MITRE ATLAS technique IDs
    summary: str  # one-line, our own words


TAXONOMY: dict[Category, TaxonomyEntry] = {
    Category.JAILBREAK: TaxonomyEntry(
        "LLM01:2025",
        "Prompt Injection",
        ("AML.T0054",),
        "Framing/roleplay that coaxes the model past its policy.",
    ),
    Category.DIRECT_INJECTION: TaxonomyEntry(
        "LLM01:2025",
        "Prompt Injection",
        ("AML.T0051.000",),
        "Adversarial instructions supplied directly in the user turn.",
    ),
    Category.INDIRECT_INJECTION: TaxonomyEntry(
        "LLM01:2025",
        "Prompt Injection",
        ("AML.T0051.001",),
        "Instructions smuggled via retrieved content, files, or tool output.",
    ),
    Category.SYSTEM_PROMPT_LEAK: TaxonomyEntry(
        "LLM07:2025",
        "System Prompt Leakage",
        ("AML.T0056",),
        "Extraction of the hidden system prompt or configuration.",
    ),
    Category.DATA_LEAKAGE: TaxonomyEntry(
        "LLM02:2025",
        "Sensitive Information Disclosure",
        ("AML.T0057",),
        "Disclosure of secrets, PII, or canary tokens in context.",
    ),
    Category.GUARDRAIL_BYPASS: TaxonomyEntry(
        "LLM01:2025",
        "Prompt Injection",
        ("AML.T0054",),
        "Encoding/obfuscation tricks that slip past input or output filters.",
    ),
    Category.TOOL_ABUSE: TaxonomyEntry(
        "LLM06:2025",
        "Excessive Agency",
        ("AML.T0053",),
        "Agentic target induced to take an unauthorised action via tools.",
    ),
    # Infrastructure-access categories. ATLAS covers the ML-attack framing;
    # the ATT&CK IDs name the underlying host/network technique the agent would
    # be carrying out, so findings map to the same tactics a blue team already
    # tracks.
    Category.COMMAND_EXECUTION: TaxonomyEntry(
        "LLM06:2025",
        "Excessive Agency",
        ("AML.T0053", "ATT&CK T1059"),
        "Agent with shell access induced to run attacker-chosen commands.",
    ),
    Category.FILE_ACCESS: TaxonomyEntry(
        "LLM06:2025",
        "Excessive Agency",
        ("AML.T0053", "ATT&CK T1083", "ATT&CK T1006"),
        "Agent induced to read files outside its permitted scope.",
    ),
    Category.NETWORK_PIVOT: TaxonomyEntry(
        "LLM06:2025",
        "Excessive Agency",
        ("AML.T0053", "ATT&CK T1090", "ATT&CK T1552.005"),
        "Agent induced to reach internal hosts, scan, or hit cloud metadata (SSRF).",
    ),
    Category.CREDENTIAL_ACCESS: TaxonomyEntry(
        "LLM02:2025",
        "Sensitive Information Disclosure",
        ("AML.T0057", "ATT&CK T1552"),
        "Agent induced to dump credentials, keys, or token material.",
    ),
    Category.OVER_REFUSAL: TaxonomyEntry(
        "LLM09:2025",
        "Misinformation / Overreliance (utility axis)",
        (),
        "Safe, in-policy request wrongly refused — the false-positive axis.",
    ),
}


def entry_for(category: Category) -> TaxonomyEntry:
    return TAXONOMY[category]
