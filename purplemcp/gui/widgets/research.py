"""Research page — threat taxonomy + the reproducible PurpleMCP-Bench."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...benchmark import run_guardrail_benchmark, write_reports
from ...config import REPO_ROOT
from ...taxonomy import OWASP_LLM_TOP10, TAXONOMY, as_rows, owasp_coverage
from ..async_bridge import AsyncLoop, run_job
from ..theme import MONO, PALETTE
from .common import BusyBar, Card, button, flash, make_scroll, muted, page_header

_TABLE_QSS = f"""
QTableWidget {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};
    border-radius: 10px; gridline-color: {PALETTE['border']}; }}
QTableWidget::item {{ padding: 5px 8px; color: {PALETTE['text']}; }}
QTableWidget::item:selected {{ background: {PALETTE['surface_hi']}; }}
QHeaderView::section {{ background: {PALETTE['surface_hi']}; color: {PALETTE['text_dim']};
    border: none; padding: 7px 8px; font-weight: 700; }}
QTableCornerButton::section {{ background: {PALETTE['surface_hi']}; border: none; }}
"""


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.NoSelection)
    t.setStyleSheet(_TABLE_QSS)
    t.setShowGrid(False)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def _cell(text: str, *, mono: bool = False, color: str | None = None, bold: bool = False) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    if color:
        item.setForeground(QColor(color))
    f = item.font()
    if mono:
        f.setFamily("Menlo")
    if bold:
        f.setBold(True)
    item.setFont(f)
    return item


class ResearchPage(QWidget):
    def __init__(self, loop: AsyncLoop, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._report = None
        self._job = None

        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)

        head = QHBoxLayout()
        head.addWidget(page_header(
            "Research", "Threat taxonomy mapped to OWASP LLM / CWE / MITRE ATLAS, and a reproducible benchmark"
        ))
        head.addStretch(1)
        self._run_btn = button("Run benchmark", "primary", "chart")
        self._run_btn.clicked.connect(self._run_bench)
        head.addWidget(self._run_btn, alignment=Qt.AlignTop)
        root.addLayout(head)
        self._busy = BusyBar()
        root.addWidget(self._busy)

        # taxonomy
        covered = sum(1 for v in owasp_coverage().values() if v)
        guardrails = len({e.meta.guardrail for e in TAXONOMY if e.meta.guardrail})
        tax_card = Card(
            "Threat taxonomy",
            f"{len(TAXONOMY)} modules · {covered}/{len(OWASP_LLM_TOP10)} OWASP-LLM categories · {guardrails} guardrails",
        )
        tax_table = _table(["#", "Attack", "Family", "OWASP-LLM (2025)", "CWE", "MITRE ATLAS", "Guardrail"])
        rows = as_rows()
        tax_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            fam = "MCP" if row["family"].startswith("MCP") else "AppSec"
            fam_color = PALETTE["purple_hi"] if fam == "MCP" else PALETTE["text_dim"]
            tax_table.setItem(r, 0, _cell(row["num"], mono=True))
            tax_table.setItem(r, 1, _cell(row["title"], bold=True))
            tax_table.setItem(r, 2, _cell(fam, color=fam_color))
            tax_table.setItem(r, 3, _cell(row["owasp_llm"]))
            tax_table.setItem(r, 4, _cell(row["cwe"], mono=True, color=PALETTE["cyan"]))
            tax_table.setItem(r, 5, _cell(row["atlas"], color=PALETTE["text_dim"]))
            tax_table.setItem(r, 6, _cell(row["guardrail"], mono=True, color=PALETTE["text_dim"]))
        tax_table.setMinimumHeight(360)
        tax_card.body.addWidget(tax_table)
        root.addWidget(tax_card)

        # benchmark
        self._bench_card = Card(
            "PurpleMCP-Bench — guardrail effectiveness",
            "Fires each attack at the vulnerable server and its hardened twin (deterministic, offline)",
        )
        self._effectiveness = QLabel("Run the benchmark to measure how many attacks the hardened twins block.")
        self._effectiveness.setObjectName("Muted")
        self._bench_card.body.addWidget(self._effectiveness)
        self._matrix = _table(["#", "Attack", "OWASP-LLM", "Vulnerable", "Hardened", "Fixed"])
        self._matrix.hide()
        self._bench_card.body.addWidget(self._matrix)
        export_row = QHBoxLayout()
        self._export_btn = button("Export JSON + Markdown", "ghost", "folder")
        self._export_btn.setEnabled(False)
        self._export_btn.clicked.connect(self._export)
        export_row.addWidget(self._export_btn)
        self._status = muted("", faint=True)
        export_row.addWidget(self._status)
        export_row.addStretch(1)
        self._bench_card.body.addLayout(export_row)
        root.addWidget(self._bench_card)
        root.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))

    # -- benchmark run ---------------------------------------------------- #
    def _run_bench(self) -> None:
        self._busy.start()
        self._run_btn.setEnabled(False)
        flash(self._status, "running benchmark…", PALETTE["text_dim"], ms=60000)
        self._job = run_job(
            self._loop,
            lambda job: run_guardrail_benchmark(
                on_case=lambda i, n, t: job.event.emit("case", (i, n, t))
            ),
            parent=self,
        )
        self._job.event.connect(self._on_progress)
        self._job.succeeded.connect(self._on_report)
        self._job.failed.connect(self._on_error)

    def _on_progress(self, kind: str, payload: object) -> None:
        if kind == "case":
            i, n, title = payload  # type: ignore[misc]
            flash(self._status, f"[{i}/{n}] {title}", PALETTE["text_dim"], ms=60000)

    def _on_error(self, msg: str) -> None:
        self._busy.stop()
        self._run_btn.setEnabled(True)
        flash(self._status, msg, PALETTE["red"], ms=6000)

    def _on_report(self, report) -> None:
        self._busy.stop()
        self._run_btn.setEnabled(True)
        self._report = report
        self._export_btn.setEnabled(True)
        pct = report.effectiveness_pct
        color = PALETTE["green"] if pct == 100 else (PALETTE["amber"] if pct >= 50 else PALETTE["red"])
        self._effectiveness.setText(
            f"Guardrail effectiveness: {report.n_correct}/{report.n_cases} ({pct}%) — "
            f"exploitable on the vulnerable server, blocked on the hardened twin."
        )
        self._effectiveness.setStyleSheet(f"color: {color}; font-weight: 700;")

        self._matrix.setRowCount(len(report.cases))
        for r, c in enumerate(report.cases):
            v_color = PALETTE["red"] if c.exploited_vulnerable else PALETTE["text_dim"]
            h_color = PALETTE["green"] if c.blocked_hardened else PALETTE["amber"]
            self._matrix.setItem(r, 0, _cell(c.num, mono=True))
            self._matrix.setItem(r, 1, _cell(c.title, bold=True))
            self._matrix.setItem(r, 2, _cell(c.owasp_llm.split(" ", 1)[0], mono=True))
            self._matrix.setItem(r, 3, _cell(c.vulnerable_verdict, color=v_color))
            self._matrix.setItem(r, 4, _cell(c.hardened_verdict, color=h_color))
            self._matrix.setItem(r, 5, _cell("✅" if c.correct else "⚠️"))
        self._matrix.show()
        flash(self._status, "done", PALETTE["green"])

    def _export(self) -> None:
        if self._report is None:
            return
        try:
            json_path, md_path = write_reports(self._report, REPO_ROOT / "results")
        except Exception as exc:  # noqa: BLE001
            flash(self._status, f"export failed: {exc}", PALETTE["red"], ms=5000)
            return
        flash(self._status, f"wrote results/{json_path.name} + {md_path.name}", PALETTE["green"], ms=5000)
