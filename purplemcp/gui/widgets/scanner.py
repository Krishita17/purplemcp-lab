"""Security Scanner — static AST analysis on files, dynamic checks on live servers."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...config import REPO_ROOT, load_registry
from ..async_bridge import AsyncLoop, run_job
from ..ops import scan_path, scan_server
from ..theme import MONO, PALETTE, SEVERITY_COLORS
from .common import (
    BusyBar,
    Card,
    button,
    clear_layout,
    flash,
    make_scroll,
    muted,
    page_header,
    severity_pill,
)

_SEV_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"]


class SeverityBar(QWidget):
    """A single rounded bar split into proportional severity segments."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._counts: dict[str, int] = {}
        self.setFixedHeight(12)
        self.setMinimumWidth(120)

    def set_counts(self, counts: dict[str, int]) -> None:
        self._counts = counts
        self.update()

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(PALETTE["surface_2"]))
        p.drawRoundedRect(QRectF(0, 0, w, h), h / 2, h / 2)
        total = sum(self._counts.values())
        if total == 0:
            return
        x = 0.0
        p.setClipping(True)
        from PySide6.QtGui import QPainterPath

        clip = QPainterPath()
        clip.addRoundedRect(QRectF(0, 0, w, h), h / 2, h / 2)
        p.setClipPath(clip)
        for sev in _SEV_ORDER:
            c = self._counts.get(sev, 0)
            if not c:
                continue
            seg = w * c / total
            p.setBrush(QColor(SEVERITY_COLORS[sev]))
            p.drawRect(QRectF(x, 0, seg + 0.5, h))
            x += seg
        p.end()


class FindingCard(QFrame):
    def __init__(self, finding, parent=None) -> None:
        super().__init__(parent)
        color = SEVERITY_COLORS.get(finding.severity, PALETTE["text_faint"])
        self.setObjectName("CardFlat")
        self.setStyleSheet(
            f"QFrame#CardFlat {{ background: {PALETTE['surface']};"
            f" border: 1px solid {PALETTE['border']}; border-left: 3px solid {color};"
            f" border-radius: 10px; }}"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 11, 14, 12)
        lay.setSpacing(5)
        top = QHBoxLayout()
        top.setSpacing(9)
        top.addWidget(severity_pill(finding.severity))
        rule = QLabel(finding.rule)
        rule.setStyleSheet(f"font-weight: 700; color: {PALETTE['text']};")
        top.addWidget(rule)
        top.addStretch(1)
        loc = QLabel(finding.location)
        loc.setStyleSheet(f"font-family: {MONO}; color: {PALETTE['text_faint']}; font-size: 11px;")
        loc.setTextInteractionFlags(Qt.TextSelectableByMouse)
        top.addWidget(loc)
        lay.addLayout(top)
        msg = QLabel(finding.message)
        msg.setWordWrap(True)
        msg.setObjectName("Muted")
        lay.addWidget(msg)


class ScannerPage(QWidget):
    def __init__(self, loop: AsyncLoop, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._job = None
        self._findings: list = []

        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)
        root.addWidget(
            page_header("Security Scanner", "Flag risky MCP servers before you ever run them")
        )

        # target card
        target = Card("Target")
        mode_row = QHBoxLayout()
        mode_row.setSpacing(8)
        self._mode_group = QButtonGroup(self)
        self._static_btn = _mode_button("Static · file or folder", True)
        self._dynamic_btn = _mode_button("Dynamic · live server", False)
        self._mode_group.addButton(self._static_btn, 0)
        self._mode_group.addButton(self._dynamic_btn, 1)
        self._static_btn.toggled.connect(self._update_mode)
        mode_row.addWidget(self._static_btn)
        mode_row.addWidget(self._dynamic_btn)
        mode_row.addStretch(1)
        target.body.addLayout(mode_row)

        # static input
        self._static_row = QWidget()
        sr = QHBoxLayout(self._static_row)
        sr.setContentsMargins(0, 0, 0, 0)
        sr.setSpacing(8)
        self._path = QLineEdit(str(REPO_ROOT / "attacks"))
        self._path.setPlaceholderText("path to a .py file or a directory")
        browse = button("Browse…", "ghost", "folder")
        browse.clicked.connect(self._browse)
        sr.addWidget(self._path, 1)
        sr.addWidget(browse)
        target.body.addWidget(self._static_row)

        chips = QHBoxLayout()
        chips.setSpacing(7)
        chips.addWidget(muted("Quick targets:", faint=True))
        for label, rel in (
            ("attacks/", "attacks"),
            ("servers/", "servers"),
            ("defense/", "defense"),
        ):
            chip = button(label, "ghost")
            chip.clicked.connect(lambda _=False, r=rel: self._path.setText(str(REPO_ROOT / r)))
            chips.addWidget(chip)
        chips.addStretch(1)
        target.body.addLayout(chips)

        # dynamic input
        self._dynamic_row = QWidget()
        dr = QHBoxLayout(self._dynamic_row)
        dr.setContentsMargins(0, 0, 0, 0)
        dr.setSpacing(8)
        dr.addWidget(QLabel("Server"))
        self._server_combo = QComboBox()
        for name, spec in load_registry().items():
            self._server_combo.addItem(name, userData=spec)
        dr.addWidget(self._server_combo)
        dr.addStretch(1)
        target.body.addWidget(self._dynamic_row)
        self._dynamic_row.hide()

        run_row = QHBoxLayout()
        self._scan_btn = button("Run scan", "primary", "search")
        self._scan_btn.clicked.connect(self._scan)
        run_row.addWidget(self._scan_btn)
        self._status = muted("", faint=True)
        run_row.addWidget(self._status)
        run_row.addStretch(1)
        self._export_btn = button("Export…", "ghost", "folder")
        self._export_btn.setEnabled(False)
        self._export_btn.setToolTip("Run a scan first")
        self._export_btn.clicked.connect(self._export)
        run_row.addWidget(self._export_btn)
        target.body.addLayout(run_row)
        root.addWidget(target)
        self._busy = BusyBar()
        root.addWidget(self._busy)

        # summary
        self._summary = Card("Results")
        self._summary_pills = QHBoxLayout()
        self._summary_pills.setSpacing(8)
        self._summary_pills.addStretch(1)
        self._summary.body.addLayout(self._summary_pills)
        self._bar = SeverityBar()
        self._summary.body.addWidget(self._bar)
        self._summary_note = muted("Run a scan to see findings.")
        self._summary.body.addWidget(self._summary_note)
        root.addWidget(self._summary)

        # findings
        self._findings_box = QVBoxLayout()
        self._findings_box.setSpacing(10)
        root.addLayout(self._findings_box)
        root.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))

    # -- mode ------------------------------------------------------------- #
    def _update_mode(self) -> None:
        static = self._static_btn.isChecked()
        self._static_row.setVisible(static)
        self._dynamic_row.setVisible(not static)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Pick an MCP server file", str(REPO_ROOT), "Python (*.py)"
        )
        if path:
            self._path.setText(path)

    # -- run -------------------------------------------------------------- #
    def _scan(self) -> None:
        self._busy.start()
        self._scan_btn.setEnabled(False)
        flash(self._status, "scanning…", PALETTE["text_dim"], ms=60000)
        if self._static_btn.isChecked():
            coro = scan_path(self._path.text().strip())
        else:
            coro = scan_server(self._server_combo.currentData())
        self._job = run_job(self._loop, coro, parent=self)
        self._job.succeeded.connect(self._on_findings)
        self._job.failed.connect(self._on_error)

    def _on_error(self, msg: str) -> None:
        self._busy.stop()
        self._scan_btn.setEnabled(True)
        flash(self._status, msg, PALETTE["red"], ms=6000)

    def _on_findings(self, findings: list) -> None:
        self._busy.stop()
        self._scan_btn.setEnabled(True)
        self._findings = findings
        self._export_btn.setEnabled(bool(findings))
        self._export_btn.setToolTip("" if findings else "Run a scan first")
        flash(self._status, f"✓ {len(findings)} finding(s)", PALETTE["green"])

        counts = {s: 0 for s in _SEV_ORDER}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        self._bar.set_counts(counts)

        # summary pills
        while self._summary_pills.count() > 1:
            item = self._summary_pills.takeAt(0)
            if item.widget():
                item.widget().setParent(None)
                item.widget().deleteLater()
        for sev in _SEV_ORDER:
            self._summary_pills.insertWidget(self._summary_pills.count() - 1, severity_pill(sev, counts[sev]))

        worst = next((s for s in _SEV_ORDER if counts[s]), None)
        if worst in ("HIGH", "MEDIUM"):
            self._summary_note.setText("⚠ Risky patterns found — review the findings below.")
            self._summary_note.setStyleSheet(f"color: {SEVERITY_COLORS[worst]};")
        elif findings:
            self._summary_note.setText("No high-risk patterns detected.")
            self._summary_note.setStyleSheet(f"color: {PALETTE['green']};")

        # finding cards
        _clear(self._findings_box)
        ordered = sorted(findings, key=lambda f: (_SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 9, f.location))
        for f in ordered:
            self._findings_box.addWidget(FindingCard(f))

    # -- export ----------------------------------------------------------- #
    def _export(self) -> None:
        if not self._findings:
            return
        path, selected = QFileDialog.getSaveFileName(
            self,
            "Export scan findings",
            str(REPO_ROOT / "purplemcp-scan.sarif"),
            "SARIF 2.1.0 (*.sarif);;JSON (*.json)",
        )
        if not path:
            return
        from pathlib import Path

        from ...scanner import to_json, to_sarif

        as_json = path.endswith(".json") or selected.startswith("JSON")
        text = to_json(self._findings) if as_json else to_sarif(self._findings)
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError as exc:
            flash(self._status, f"export failed: {exc}", PALETTE["red"], ms=5000)
            return
        flash(self._status, f"✓ exported {Path(path).name}", PALETTE["green"])


def _mode_button(text: str, checked: bool) -> QPushButton:
    btn = QPushButton(text)
    btn.setCheckable(True)
    btn.setChecked(checked)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setStyleSheet(
        f"QPushButton {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};"
        f" border-radius: 9px; padding: 8px 14px; color: {PALETTE['text_dim']}; font-weight: 600; }}"
        f"QPushButton:checked {{ background: {PALETTE['surface_hi']};"
        f" border-color: {PALETTE['violet']}; color: {PALETTE['text']}; }}"
    )
    return btn


def _clear(layout) -> None:
    clear_layout(layout)
