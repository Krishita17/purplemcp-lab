"""Paper-ready rendering of a :class:`SusceptibilityReport`.

Produces the exact terminal blocks the capstone paper expects — the per-model
susceptibility table, the guardrail confusion matrix, the classification
metrics, and a short interpreted summary — plus a per-attack-per-model CSV for
loading into Excel / pandas. Every number is read straight from the report; this
module computes nothing about model behaviour, it only formats it.
"""

from __future__ import annotations

import csv
import datetime as _dt
from pathlib import Path
from typing import Optional

from rich.console import Console

from .runner import ModelSusceptibility, SusceptibilityReport

SEP = "═" * 56


# --------------------------------------------------------------------------- #
#  table helpers (fixed-width so header / separator / rows align)
# --------------------------------------------------------------------------- #
def _cell(v, w: int) -> str:
    return f"{str(v):^{w}}"


def _row(name: str, m, r, e, asr) -> str:
    return f" {name:<26}|{_cell(m, 7)}|{_cell(r, 8)}|{_cell(e, 7)}|{_cell(asr, 8)}"


_TABLE_SEP = " " + "─" * 26 + "┼" + "─" * 7 + "┼" + "─" * 8 + "┼" + "─" * 7 + "┼" + "─" * 8


def _pct(num: float, den: float) -> float:
    return (100.0 * num / den) if den else 0.0


def _susceptibility_block(report: SusceptibilityReport, m: ModelSusceptibility) -> list[str]:
    lines = [
        SEP,
        f" MODEL SUSCEPTIBILITY RESULTS — {m.label}",
        f" Temperature: {report.temperature} | Runs per probe: {report.runs_per_probe}",
        SEP,
        "",
        _row("Attack Type", "Manip", "Resist", "Error", "ASR"),
        _TABLE_SEP,
    ]
    tot_m = tot_r = tot_e = tot_n = 0
    for p in m.probes:
        asr = _pct(p.manipulated, p.total)
        lines.append(_row(p.title, p.manipulated, p.resisted, p.errors, f"{asr:.1f}%"))
        tot_m += p.manipulated
        tot_r += p.resisted
        tot_e += p.errors
        tot_n += p.total
    lines.append(_TABLE_SEP)
    lines.append(_row("TOTAL", tot_m, tot_r, tot_e, f"{_pct(tot_m, tot_n):.1f}%"))
    lines.append("")
    return lines


def _confusion_block(gm: Optional[dict]) -> list[str]:
    if not gm or "confusion" not in gm:
        return [
            SEP,
            " CONFUSION MATRIX (Guardrail as Classifier)",
            SEP,
            "",
            " (not available — run `purplemcp bench` to compute guardrail metrics)",
            "",
        ]
    c = gm["confusion"]
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    return [
        SEP,
        " CONFUSION MATRIX (Guardrail as Classifier)",
        " Positive = Attack should be BLOCKED by guardrail",
        " Negative = Attack should PASS (clean tool)",
        SEP,
        "",
        "                   Guardrail Said:",
        "                  BLOCKED    PASSED",
        f" Actually  ATTACK |  TP={tp:<3}|  FN={fn:<3}|",
        f" Malicious CLEAN  |  FP={fp:<3}|  TN={tn:<3}|",
        "",
        f" True Positives  (TP): {tp:<3}— attacks correctly blocked",
        f" False Negatives (FN): {fn:<3}— attacks missed by guardrail",
        f" False Positives (FP): {fp:<3}— clean tools wrongly blocked",
        f" True Negatives  (TN): {tn:<3}— clean tools correctly passed",
        "",
    ]


def _metrics_block(gm: Optional[dict]) -> list[str]:
    if not gm or "confusion" not in gm:
        return []
    c = gm["confusion"]
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    return [
        SEP,
        " CLASSIFICATION METRICS",
        SEP,
        "",
        f" Precision  = TP / (TP + FP) = {tp}/{tp + fp} = {precision:.3f}  ({precision * 100:.1f}%)",
        f" Recall     = TP / (TP + FN) = {tp}/{tp + fn} = {recall:.3f}  ({recall * 100:.1f}%)",
        f" F1 Score   = 2 * (P * R) / (P + R)  = {f1:.3f}  ({f1 * 100:.1f}%)",
        f" Accuracy   = (TP + TN) / Total       = {accuracy:.3f}  ({accuracy * 100:.1f}%)",
        "",
        " NOTE: These metrics measure guardrail effectiveness as a binary",
        " classifier (blocks attack vs passes clean), computed from real runs.",
        "",
    ]


def _summary_block(m: ModelSusceptibility, gm: Optional[dict]) -> list[str]:
    if not m.probes:
        return []
    ranked = sorted(m.probes, key=lambda p: _pct(p.manipulated, p.total))
    most_res = ranked[0]
    most_vuln = ranked[-1]
    vuln_pct = _pct(most_vuln.manipulated, most_vuln.total)
    res_pct = _pct(most_res.manipulated, most_res.total)
    lines = [
        SEP,
        " MODEL SUSCEPTIBILITY SUMMARY",
        SEP,
        "",
        f" Model:                    {m.label}",
        f" Most vulnerable attack:   {most_vuln.title} ({vuln_pct:.1f}% ASR)",
        f" Most resistant attack:    {most_res.title} ({res_pct:.1f}% ASR)",
        f" Overall model ASR:        {m.overall_pct}% ({m.total_manipulated}/{m.total_runs} runs)",
        "",
        " Interpretation:",
        f" - {m.model} is most susceptible to {most_vuln.title.lower()} ({vuln_pct:.1f}% ASR)",
        f" - {m.model} most strongly resists {most_res.title.lower()} ({res_pct:.1f}% ASR)",
    ]
    if gm and "recall_pct" in gm:
        lines.append(
            f" - Guardrails block {gm['recall_pct']}% of attacks on hardened servers"
        )
    lines.append("")
    return lines


def render_paper_report(report: SusceptibilityReport, console: Console) -> None:
    """Print the full paper-ready report (all models) to the terminal."""
    out: list[str] = []
    for m in report.models:
        out += _susceptibility_block(report, m)
    out += _confusion_block(report.guardrail_metrics)
    out += _metrics_block(report.guardrail_metrics)
    # One interpreted summary per model (primary model first).
    for m in report.models:
        out += _summary_block(m, report.guardrail_metrics)
    for s in report.skipped:
        out.append(f" (skipped {s['target']}: {s['reason']})")
    if report.skipped:
        out.append("")
    # markup/highlight off so the box-drawing + numbers render verbatim.
    console.print("\n".join(out), markup=False, highlight=False)


# --------------------------------------------------------------------------- #
#  CSV — one row per attack per model
# --------------------------------------------------------------------------- #
def write_metrics_csv(report: SusceptibilityReport, out_dir: Path, stem: Optional[str] = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
    path = out_dir / (f"{stem or 'metrics-' + ts}.csv")
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "model", "attack_class", "run1", "run2", "run3",
            "manipulated", "resisted", "errors", "asr", "owasp",
        ])
        for m in report.models:
            for p in m.probes:
                outs = [r.outcome for r in p.runs]
                outs += [""] * (3 - len(outs))
                w.writerow([
                    m.label, p.id, outs[0], outs[1], outs[2],
                    p.manipulated, p.resisted, p.errors, f"{p.asr:.3f}", p.owasp,
                ])
    return path
