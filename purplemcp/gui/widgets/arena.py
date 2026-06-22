"""Attack / Defend Arena — the signature red-vs-blue side-by-side demo.

Pick an attack, arm the lab, and fire the same payload at the vulnerable server
and its hardened twin. The vulnerable side leaks; the hardened side blocks. The
lab opt-in token is only injected after the user explicitly arms it here.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QTextOption
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ..async_bridge import AsyncLoop, run_job
from ..catalog import CASES, ArenaCase, judge
from ..ops import ArenaResult, arena_run
from ..theme import MONO, PALETTE, RED_TEAM, BLUE_TEAM, rgba
from .common import (
    Badge,
    BusyBar,
    Card,
    button,
    clear_layout,
    flash,
    muted,
    page_header,
    title_label,
)

_LIST_QSS = f"""
QListWidget {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};
    border-radius: 12px; padding: 6px; }}
QListWidget::item {{ border-radius: 9px; margin: 3px 0; }}
QListWidget::item:selected {{ background: {PALETTE['surface_hi']}; }}
QListWidget::item:hover {{ background: {PALETTE['surface']}; }}
"""


class ArenaPage(QWidget):
    lab_armed_changed = Signal(bool)

    def __init__(self, loop: AsyncLoop, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._case: ArenaCase | None = None
        self._job = None

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 24)
        root.setSpacing(16)
        root.addWidget(
            page_header(
                "Attack / Defend Arena",
                "Fire one payload at a vulnerable server and its hardened twin, side by side",
            )
        )

        root.addWidget(self._build_arm_banner())

        split = QSplitter(Qt.Horizontal)
        split.setHandleWidth(14)

        # left: case list
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(8)
        lv.addWidget(title_label("Attacks"))
        self._list = QListWidget()
        self._list.setStyleSheet(_LIST_QSS)
        self._list.itemSelectionChanged.connect(self._on_select)
        for case in CASES:
            item = QListWidgetItem(self._list)
            item.setData(Qt.UserRole, case)
            row = _case_row(case)
            item.setSizeHint(row.sizeHint())
            self._list.addItem(item)
            self._list.setItemWidget(item, row)
        lv.addWidget(self._list)
        split.addWidget(left)

        # right: stage
        self._stage_host = QWidget()
        self._stage = QVBoxLayout(self._stage_host)
        self._stage.setContentsMargins(0, 0, 0, 0)
        self._stage.setSpacing(14)
        self._stage.addWidget(muted("Select an attack to set up the arena."))
        self._stage.addStretch(1)
        from .common import make_scroll

        split.addWidget(make_scroll(self._stage_host))
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([300, 640])
        root.addWidget(split, 1)

        self._list.setCurrentRow(0)

    # -- arm banner ------------------------------------------------------- #
    def _build_arm_banner(self) -> QWidget:
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
        tbox.addWidget(
            muted(
                "Arming the lab lets the arena launch deliberately insecure servers on "
                "localhost (exfil goes only to a fake local sink). Only do this on a machine "
                "you own. See ETHICS.md.",
                faint=True,
            )
        )
        row.addLayout(tbox, 1)
        self._arm = QCheckBox("Arm the lab")
        self._arm.setStyleSheet(
            f"QCheckBox {{ color: {PALETTE['red']}; font-weight: 700; }}"
            f"QCheckBox::indicator:checked {{ background: {PALETTE['red']}; border-color: {PALETTE['red']}; }}"
        )
        self._arm.toggled.connect(self._on_arm)
        row.addWidget(self._arm, alignment=Qt.AlignVCenter)
        card.body.addLayout(row)
        return card

    def _on_arm(self, armed: bool) -> None:
        self.lab_armed_changed.emit(armed)
        if hasattr(self, "_run_btn"):
            self._run_btn.setEnabled(armed)
            self._run_btn.setToolTip("" if armed else "Arm the lab above to run")

    # -- selection -------------------------------------------------------- #
    def _on_select(self) -> None:
        items = self._list.selectedItems()
        if not items:
            return
        self._case = items[0].data(Qt.UserRole)
        self._build_stage(self._case)

    def _build_stage(self, case: ArenaCase) -> None:
        _clear(self._stage)

        head = QHBoxLayout()
        title = QLabel(f"{case.title}")
        title.setStyleSheet(f"font-size: 19px; font-weight: 800; color: {PALETTE['text']};")
        head.addWidget(Badge(f"#{case.num}", PALETTE["violet"]))
        head.addWidget(title)
        head.addStretch(1)
        self._stage.addLayout(head)
        self._stage.addWidget(muted(case.threat))

        guard = Card(flat=True)
        gr = QHBoxLayout()
        gl = QLabel()
        from ..icons import icon

        gl.setPixmap(icon("lock", PALETTE["blue"], 16).pixmap(16, 16))
        gr.addWidget(gl)
        gr.addWidget(muted(case.guardrail, faint=True), 1)
        guard.body.addLayout(gr)
        self._stage.addWidget(guard)

        run_row = QHBoxLayout()
        self._run_btn = button("Run the arena", "primary", "play")
        self._run_btn.setEnabled(self._arm.isChecked())
        if not self._arm.isChecked():
            self._run_btn.setToolTip("Arm the lab above to run")
        self._run_btn.clicked.connect(self._run)
        run_row.addWidget(self._run_btn)
        if case.needs_network:
            run_row.addWidget(Badge("needs network", PALETTE["amber"]))
        self._status = muted("", faint=True)
        run_row.addWidget(self._status)
        run_row.addStretch(1)
        self._stage.addLayout(run_row)
        self._busy = BusyBar()
        self._stage.addWidget(self._busy)

        # results columns (filled on run)
        self._columns = QHBoxLayout()
        self._columns.setSpacing(14)
        self._red_col = _TeamColumn("Vulnerable server", RED_TEAM, "skull")
        self._blue_col = _TeamColumn("Hardened twin", BLUE_TEAM, "lock")
        self._columns.addWidget(self._red_col, 1)
        self._columns.addWidget(self._blue_col, 1)
        self._stage.addLayout(self._columns)

        self._explain = Card("What happens")
        self._explain.body.addWidget(muted(case.explain))
        self._stage.addWidget(self._explain)
        self._stage.addStretch(1)

    # -- run -------------------------------------------------------------- #
    def _run(self) -> None:
        if self._case is None or not self._arm.isChecked():
            return
        self._run_btn.setEnabled(False)
        self._busy.start()
        self._red_col.reset()
        self._blue_col.reset()
        flash(self._status, "running both servers…", PALETTE["text_dim"], ms=60000)
        self._job = run_job(self._loop, arena_run(self._case), parent=self)
        self._job.succeeded.connect(self._on_done)
        self._job.failed.connect(self._on_error)

    def _on_done(self, result: ArenaResult) -> None:
        self._busy.stop()
        self._run_btn.setEnabled(self._arm.isChecked())
        case = self._case
        v = judge(result.vuln_attack, case, hardened=False)
        h = judge(result.hard_attack, case, hardened=True)
        self._red_col.fill(result.vuln_benign, result.vuln_attack, v, case)
        self._blue_col.fill(result.hard_benign, result.hard_attack, h, case)
        if h.kind == "good" and v.kind == "bad":
            flash(self._status, "✓ attack landed, then was blocked", PALETTE["green"])
        else:
            flash(self._status, "done — read the verdicts", PALETTE["text_dim"])

    def _on_error(self, msg: str) -> None:
        self._busy.stop()
        self._run_btn.setEnabled(self._arm.isChecked())
        flash(self._status, msg, PALETTE["red"], ms=6000)


# --------------------------------------------------------------------------- #
#  team column
# --------------------------------------------------------------------------- #
class _TeamColumn(Card):
    def __init__(self, title: str, color: str, icon_name: str, parent=None) -> None:
        super().__init__(parent=parent)
        self._color = color
        self.setStyleSheet(
            f"QFrame#Card {{ background: {PALETTE['surface']};"
            f" border: 1px solid {rgba(color, 0.27)}; border-radius: 14px; }}"
        )
        from ..icons import icon

        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon(icon_name, color, 17).pixmap(17, 17))
        head.addWidget(ic)
        t = QLabel(title)
        t.setStyleSheet(f"font-weight: 800; color: {color};")
        head.addWidget(t)
        head.addStretch(1)
        self._verdict = Badge("idle", PALETTE["text_faint"])
        head.addWidget(self._verdict)
        self.body.addLayout(head)

        self._body_box = QVBoxLayout()
        self._body_box.setSpacing(8)
        self.body.addLayout(self._body_box)
        self.reset()

    def reset(self) -> None:
        self._verdict.setText("idle")
        self._verdict.set_color(PALETTE["text_faint"])
        _clear(self._body_box)
        self._body_box.addWidget(muted("Run the arena to populate this side.", faint=True))

    def fill(self, benign, attack: str, verdict, case: ArenaCase) -> None:
        _clear(self._body_box)
        if benign is not None:
            self._body_box.addWidget(_labeled("Normal use", case.benign_args))
            self._body_box.addWidget(_output_box(benign))
        self._body_box.addWidget(_labeled("Attack", case.attack_args))
        self._body_box.addWidget(_output_box(attack))
        color = {"good": PALETTE["green"], "bad": PALETTE["red"]}.get(verdict.kind, PALETTE["amber"])
        self._verdict.setText(verdict.label)
        self._verdict.set_color(color)


def _labeled(label: str, args) -> QWidget:
    box = QWidget()
    lay = QVBoxLayout(box)
    lay.setContentsMargins(0, 2, 0, 0)
    lay.setSpacing(2)
    head = QLabel(label)
    head.setObjectName("Faint")
    head.setStyleSheet(f"color: {PALETTE['text_dim']}; font-weight: 700; font-size: 11px;")
    lay.addWidget(head)
    if args:
        import json

        a = QLabel(json.dumps(args, ensure_ascii=False))
        a.setWordWrap(True)
        a.setStyleSheet(f"font-family: {MONO}; color: {PALETTE['text_faint']}; font-size: 11px;")
        lay.addWidget(a)
    return box


def _output_box(text: str) -> QWidget:
    shown = (text or "").strip()
    if len(shown) > 1600:
        shown = shown[:1599] + "\n… (truncated)"
    # A read-only text view wraps long unbreakable strings (e.g. connection
    # strings) instead of forcing the whole column wider than its pane.
    view = QPlainTextEdit()
    view.setReadOnly(True)
    view.setPlainText(shown or "(no output)")
    view.setWordWrapMode(QTextOption.WrapAnywhere)
    view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    view.setFixedHeight(132)
    view.setStyleSheet(
        f"QPlainTextEdit {{ font-family: {MONO}; font-size: 11.5px; color: {PALETTE['text']};"
        f" background: {PALETTE['bg']}; border: 1px solid {PALETTE['border']};"
        f" border-radius: 8px; padding: 7px 9px; }}"
    )
    return view


def _case_row(case: ArenaCase) -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(9, 8, 9, 8)
    lay.setSpacing(10)
    num = QLabel(case.num)
    num.setFixedSize(30, 30)
    num.setAlignment(Qt.AlignCenter)
    num.setStyleSheet(
        f"background: {PALETTE['surface_hi']}; color: {PALETTE['purple_hi']};"
        f" border-radius: 8px; font-weight: 800; font-family: {MONO};"
    )
    lay.addWidget(num)
    tbox = QVBoxLayout()
    tbox.setSpacing(1)
    t = QLabel(case.title)
    t.setStyleSheet(f"font-weight: 700; color: {PALETTE['text']};")
    tbox.addWidget(t)
    threat = case.threat if len(case.threat) <= 52 else case.threat[:51] + "…"
    d = QLabel(threat)
    d.setObjectName("Faint")
    tbox.addWidget(d)
    lay.addLayout(tbox, 1)
    return row


def _clear(layout) -> None:
    clear_layout(layout)
