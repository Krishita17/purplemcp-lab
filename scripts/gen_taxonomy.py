"""Regenerate docs/TAXONOMY.md from purplemcp/taxonomy.py (single source of truth).

    python scripts/gen_taxonomy.py
"""

from __future__ import annotations

from pathlib import Path

from purplemcp.taxonomy import (
    OWASP_LLM_TOP10,
    TAXONOMY,
    as_markdown_table,
    owasp_coverage,
)

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "TAXONOMY.md"


def main() -> int:
    cov = owasp_coverage()
    covered = sum(1 for ids in cov.values() if ids)
    lines = [
        "# PurpleMCP — threat taxonomy",
        "",
        f"All **{len(TAXONOMY)}** attack/defense modules mapped to the **OWASP Top 10 "
        "for LLM Applications (2025)**, **CWE**, and **MITRE ATLAS**. This file is "
        "generated from [`purplemcp/taxonomy.py`](../purplemcp/taxonomy.py) — run "
        "`python scripts/gen_taxonomy.py` to refresh, or `purplemcp taxonomy` to print it.",
        "",
        as_markdown_table(),
        "",
        f"## OWASP LLM Top 10 coverage — {covered}/10 categories",
        "",
    ]
    for code, name in OWASP_LLM_TOP10.items():
        ids = cov.get(code, [])
        mark = "✅" if ids else "⬜"
        suffix = f" — {', '.join(ids)}" if ids else " — _(not yet demonstrated)_"
        lines.append(f"- {mark} **{code}:2025 {name}** ({len(ids)}){suffix}")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)} ({len(TAXONOMY)} modules, {covered}/10 OWASP categories)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
