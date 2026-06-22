"""A one-shot, project-intrinsic security-posture report (Markdown).

Stitches the existing pieces — the threat taxonomy, the static scanner run over
the lab's own code, and the guardrail inventory — into a single reproducible
document. Deliberately machine-independent (no API keys, no local model state) so
the same report regenerates anywhere: ``purplemcp report``.
"""

from __future__ import annotations

from .config import REPO_ROOT
from .environment import stats
from .scanner import scan_path
from .taxonomy import (
    OWASP_LLM_TOP10,
    TAXONOMY,
    as_markdown_table,
    owasp_coverage,
)

_SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")


def _scan_counts(rel: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in scan_path(str(REPO_ROOT / rel)):
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _guardrail_modules() -> list[str]:
    d = REPO_ROOT / "purplemcp" / "guardrails"
    return sorted(p.stem for p in d.glob("*.py") if not p.stem.startswith("_"))


def _scan_row(label: str, counts: dict[str, int]) -> str:
    cells = " | ".join(str(counts.get(s, 0)) for s in _SEVERITIES)
    return f"| {label} | {cells} |"


def build_report() -> str:
    """Return the full report as a Markdown string."""
    s = stats()
    cov = owasp_coverage()
    covered = sum(1 for ids in cov.values() if ids)
    attacks = _scan_counts("attacks")
    twins = _scan_counts("defense/hardened_servers")

    lines: list[str] = [
        "# PurpleMCP — security posture report",
        "",
        "_Project-intrinsic and reproducible — regenerate with `purplemcp report`._",
        "",
        "## Summary",
        "",
        f"- **{s['attack_modules']}** attack/defense modules · "
        f"**{s['hardened_twins']}** hardened twins · "
        f"**{s['guardrails']}** guardrail modules",
        f"- **OWASP LLM Top-10 coverage:** {covered}/10 categories",
        "",
        "## Static scan of the lab's own code",
        "",
        "The bundled scanner (`purplemcp scan`) over the vulnerable modules and their "
        "hardened twins — the vulnerable code lights up, the twins are clean:",
        "",
        "| Target | HIGH | MEDIUM | LOW | INFO |",
        "| --- | --- | --- | --- | --- |",
        _scan_row("`attacks/` (intentionally vulnerable)", attacks),
        _scan_row("`defense/hardened_servers/`", twins),
        "",
        "## Threat taxonomy",
        "",
        as_markdown_table(),
        "",
        f"## OWASP LLM Top 10 coverage — {covered}/10",
        "",
    ]
    for code, name in OWASP_LLM_TOP10.items():
        ids = cov.get(code, [])
        mark = "✅" if ids else "⬜"
        suffix = f" — {', '.join(ids)}" if ids else ""
        lines.append(f"- {mark} **{code}:2025 {name}** ({len(ids)}){suffix}")
    lines += [
        "",
        "## Guardrail library",
        "",
        "Reusable hardening primitives in `purplemcp/guardrails/`:",
        "",
        ", ".join(f"`{g}`" for g in _guardrail_modules()),
        "",
    ]
    return "\n".join(lines) + "\n"
