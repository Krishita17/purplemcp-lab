"""Attack Lab — browse all attack modules and run their real exploits."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .. import ops
from ..async_bridge import AsyncLoop, run_job
from ..catalog import CASES_BY_ID
from ..catalog_attacks import AttackMeta, grouped
from ..lab_commands import attack_commands
from ..state import LabState
from ..theme import MONO, PALETTE, rgba
from .common import (
    Badge,
    BusyBar,
    Card,
    button,
    clear_layout,
    filter_grouped_list,
    flash,
    make_scroll,
    muted,
    page_header,
    search_box,
    severity_pill,
    title_label,
)
from .terminal import TerminalCard

_LIST_QSS = f"""
QListWidget {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};
    border-radius: 12px; padding: 6px; }}
QListWidget::item {{ border-radius: 9px; margin: 2px 0; }}
QListWidget::item:selected {{ background: {PALETTE['surface_hi']}; }}
QListWidget::item:hover {{ background: {PALETTE['surface']}; }}
"""


class AttackLabPage(QWidget):
    def __init__(self, loop: AsyncLoop, lab: LabState, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._lab = lab
        self._meta: AttackMeta | None = None
        self._run_job = None

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 22)
        root.setSpacing(16)
        root.addWidget(
            page_header("Attack Lab", "Run the real exploits against intentionally-vulnerable servers")
        )
        root.addWidget(self._build_arm_banner())

        split = QSplitter(Qt.Horizontal)
        split.setHandleWidth(14)
        split.addWidget(self._build_list())
        split.addWidget(make_scroll(self._build_detail_host()))
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([330, 620])
        root.addWidget(split, 1)

        self._lab.changed.connect(self._sync_armed)
        self._select_first()

    # -- arm banner ------------------------------------------------------- #
    def _build_arm_banner(self) -> Card:
        card = Card()
        card.setStyleSheet(
            "QFrame#Card {"
            f"  border: 1px solid {rgba(PALETTE['red'], 0.34)}; border-radius: 14px;"
            "   background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"    stop:0 rgba(244,63,94,0.12), stop:1 rgba(244,63,94,0.03)); }}"
        )
        row = QHBoxLayout()
        row.setSpacing(12)
        warn = QLabel("⚠")
        warn.setStyleSheet(f"font-size: 22px; color: {PALETTE['red']};")
        row.addWidget(warn)
        tbox = QVBoxLayout()
        tbox.setSpacing(2)
        t = QLabel("Intentionally-vulnerable lab code")
        t.setStyleSheet(f"font-weight: 800; color: {PALETTE['text']};")
        tbox.addWidget(t)
        tbox.addWidget(muted(
            "Running an exploit launches deliberately insecure servers on localhost (exfil "
            "goes only to a fake local sink). Only do this on a machine you own. See ETHICS.md.",
            faint=True,
        ))
        row.addLayout(tbox, 1)
        self._arm = QCheckBox("Arm the lab")
        self._arm.setChecked(self._lab.armed)
        self._arm.setStyleSheet(
            f"QCheckBox {{ color: {PALETTE['red']}; font-weight: 700; }}"
            f"QCheckBox::indicator:checked {{ background: {PALETTE['red']}; border-color: {PALETTE['red']}; }}"
        )
        self._arm.toggled.connect(self._lab.set_armed)
        row.addWidget(self._arm, alignment=Qt.AlignVCenter)
        card.body.addLayout(row)
        return card

    def _sync_armed(self, armed: bool) -> None:
        if self._arm.isChecked() != armed:
            self._arm.setChecked(armed)
        if hasattr(self, "_run_btn") and self._meta is not None:
            self._run_btn.setEnabled(armed)
            self._run_btn.setToolTip("" if armed else "Arm the lab above to run")

    # -- list ------------------------------------------------------------- #
    def _build_list(self) -> QWidget:
        wrap = QWidget()
        lay = QVBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        lay.addWidget(title_label("Attacks"))
        lay.addWidget(search_box("Filter attacks…", lambda t: filter_grouped_list(self._list, t)))
        self._list = QListWidget()
        self._list.setStyleSheet(_LIST_QSS)
        self._list.itemSelectionChanged.connect(self._on_select)
        for family, items in grouped():
            header = QListWidgetItem(family.upper())
            header.setFlags(Qt.NoItemFlags)
            header.setForeground(QColor(PALETTE["text_faint"]))
            self._list.addItem(header)
            for meta in items:
                item = QListWidgetItem(self._list)
                item.setData(Qt.UserRole, meta)
                roww = _attack_row(meta)
                item.setSizeHint(roww.sizeHint())
                self._list.addItem(item)
                self._list.setItemWidget(item, roww)
        lay.addWidget(self._list)
        return wrap

    def _select_first(self) -> None:
        for i in range(self._list.count()):
            if self._list.item(i).data(Qt.UserRole) is not None:
                self._list.setCurrentRow(i)
                return

    # -- detail ----------------------------------------------------------- #
    def _build_detail_host(self) -> QWidget:
        self._detail_host = QWidget()
        self._detail = QVBoxLayout(self._detail_host)
        self._detail.setContentsMargins(0, 0, 0, 0)
        self._detail.setSpacing(14)
        self._detail.addWidget(muted("Select an attack to see its writeup and run the exploit."))
        self._detail.addStretch(1)
        return self._detail_host

    def _on_select(self) -> None:
        items = self._list.selectedItems()
        if not items:
            return
        meta = items[0].data(Qt.UserRole)
        if meta is None:
            return
        self._meta = meta
        self._build_detail(meta)

    def _build_detail(self, meta: AttackMeta) -> None:
        clear_layout(self._detail)

        head = QHBoxLayout()
        head.addWidget(Badge(f"#{meta.num}", PALETTE["violet"]))
        title = QLabel(meta.title)
        title.setStyleSheet(f"font-size: 19px; font-weight: 800; color: {PALETTE['text']};")
        head.addWidget(title)
        head.addWidget(severity_pill(meta.severity))
        head.addStretch(1)
        self._detail.addLayout(head)
        self._detail.addWidget(muted(meta.threat))

        run_row = QHBoxLayout()
        self._run_btn = button("Run exploit", "danger", "play", icon_color=PALETTE["red"])
        self._run_btn.setEnabled(self._lab.armed)
        if not self._lab.armed:
            self._run_btn.setToolTip("Arm the lab above to run")
        self._run_btn.clicked.connect(self._run)
        run_row.addWidget(self._run_btn)
        self._run_status = muted("", faint=True)
        run_row.addWidget(self._run_status)
        run_row.addStretch(1)
        self._detail.addLayout(run_row)
        self._busy = BusyBar()
        self._detail.addWidget(self._busy)

        console_card = Card(
            "1 · Live exploit output",
            "The real exploit runs against the intentionally-vulnerable server.",
        )
        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setPlaceholderText("Arm the lab, then Run exploit to see it work in real time.")
        self._console.setStyleSheet(
            f"QPlainTextEdit {{ font-family: {MONO}; font-size: 11.5px; color: {PALETTE['text']};"
            f" background: {PALETTE['bg']}; border: 1px solid {PALETTE['border']}; border-radius: 8px; }}"
        )
        self._console.setMinimumHeight(220)
        console_card.body.addWidget(self._console)
        self._detail.addWidget(console_card)

        # manual terminal: copy/run the exploit + scan commands yourself
        self._detail.addWidget(TerminalCard(
            self._loop,
            title="2 · Manual terminal",
            subtitle="Copy these into your own shell, or run them here and watch the output.",
            commands=attack_commands(meta),
            lab=self._lab,
        ))

        # nudge toward the blue-team side
        if meta.arena_case_id and meta.arena_case_id in CASES_BY_ID:
            defend = Card(flat=True)
            row = QHBoxLayout()
            from ..icons import icon

            ic = QLabel()
            ic.setPixmap(icon("lock", PALETTE["blue"], 15).pixmap(15, 15))
            row.addWidget(ic)
            row.addWidget(muted(
                "Now defend it → open the Defense Lab (⌘8) to watch this exact payload get blocked "
                "by its hardened twin.", faint=True,
            ), 1)
            defend.body.addLayout(row)
            self._detail.addWidget(defend)

        writeup = Card("Writeup")
        view = QTextEdit()
        view.setReadOnly(True)
        try:
            view.setMarkdown(meta.readme_path.read_text(encoding="utf-8"))
        except OSError:
            view.setPlainText("(writeup unavailable)")
        view.setStyleSheet(
            f"QTextEdit {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};"
            f" border-radius: 8px; }}"
        )
        view.setMinimumHeight(240)
        writeup.body.addWidget(view)
        self._detail.addWidget(writeup)
        self._detail.addStretch(1)

    # -- run -------------------------------------------------------------- #
    def _run(self) -> None:
        if self._meta is None or not self._lab.armed:
            return
        self._run_btn.setEnabled(False)
        self._busy.start()
        self._console.clear()
        flash(self._run_status, "running exploit…", PALETTE["text_dim"], ms=120000)
        self._run_job = run_job(self._loop, lambda j: ops.run_exploit(j, str(self._meta.exploit_path)), parent=self)
        self._run_job.event.connect(self._on_line)
        self._run_job.succeeded.connect(self._on_finished)
        self._run_job.failed.connect(self._on_failed)

    def _on_line(self, kind: str, payload) -> None:
        if kind == "line":
            self._console.appendPlainText(str(payload))

    def _on_finished(self, rc: int) -> None:
        self._busy.stop()
        self._run_btn.setEnabled(self._lab.armed)
        if rc == 0:
            flash(self._run_status, "✓ exploit finished", PALETTE["green"])
        else:
            flash(self._run_status, f"exited with code {rc}", PALETTE["amber"], ms=5000)

    def _on_failed(self, msg: str) -> None:
        self._busy.stop()
        self._run_btn.setEnabled(self._lab.armed)
        self._console.appendPlainText(f"\nERROR: {msg}")
        flash(self._run_status, "failed", PALETTE["red"], ms=4000)


def _attack_row(meta: AttackMeta) -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(9, 8, 9, 8)
    lay.setSpacing(10)
    num = QLabel(meta.num)
    num.setFixedSize(28, 28)
    num.setAlignment(Qt.AlignCenter)
    num.setStyleSheet(
        f"background: {PALETTE['surface_hi']}; color: {PALETTE['purple_hi']};"
        f" border-radius: 8px; font-weight: 800; font-family: {MONO};"
    )
    lay.addWidget(num)
    tbox = QVBoxLayout()
    tbox.setSpacing(1)
    t = QLabel(meta.title)
    t.setStyleSheet(f"font-weight: 700; color: {PALETTE['text']};")
    tbox.addWidget(t)
    threat = meta.threat if len(meta.threat) <= 48 else meta.threat[:47] + "…"
    d = QLabel(threat)
    d.setObjectName("Faint")
    tbox.addWidget(d)
    lay.addLayout(tbox, 1)
    return row
