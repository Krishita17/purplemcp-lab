"""Dashboard — a playful, at-a-glance command center for the lab.

Sorbet edition: a time-aware greeting, lab stat tiles, a live **security-metrics**
panel (accuracy / precision / recall / ASR with a confusion matrix and bar charts),
and formatted coverage/mix tables. Everything is real — the metrics come from
actually running the guardrails as detectors, never from canned numbers.
"""

from __future__ import annotations

import datetime as _dt

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ... import environment
from ...config import REPO_ROOT, load_providers, load_registry
from ...taxonomy import OWASP_LLM_TOP10, TAXONOMY, owasp_coverage
from ..async_bridge import AsyncLoop, run_job
from ..icons import icon
from ..theme import PALETTE, rgba
from .common import (
    Badge,
    BusyBar,
    Card,
    add_shadow,
    button,
    clear_layout,
    flash,
    hline,
    make_scroll,
    muted,
    page_header,
)


def _count_attack_labs() -> int:
    attacks = REPO_ROOT / "attacks"
    if not attacks.exists():
        return 0
    return sum(1 for p in attacks.iterdir() if p.is_dir() and p.name[:2].isdigit())


def _count_hardened_twins() -> int:
    twins = REPO_ROOT / "defense" / "hardened_servers"
    if not twins.exists():
        return 0
    return sum(1 for p in twins.glob("safe_*.py"))


def _count_guardrails() -> int:
    gd = REPO_ROOT / "purplemcp" / "guardrails"
    if not gd.exists():
        return 0
    return sum(1 for p in gd.glob("*.py") if p.name != "__init__.py")


def _greeting() -> tuple[str, str]:
    """A time-aware greeting (text, emoji)."""
    h = _dt.datetime.now().hour
    if h < 12:
        return "Good morning", "🌅"
    if h < 17:
        return "Good afternoon", "🌤️"
    if h < 21:
        return "Good evening", "🌆"
    return "Working late", "🌙"


# --------------------------------------------------------------------------- #
#  small reusable widgets
# --------------------------------------------------------------------------- #
_TABLE_QSS = f"""
QTableWidget {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};
    border-radius: 10px; gridline-color: {PALETTE['border']}; }}
QTableWidget::item {{ padding: 5px 8px; color: {PALETTE['text']}; }}
QHeaderView::section {{ background: {PALETTE['surface_hi']}; color: {PALETTE['text_dim']};
    border: none; padding: 7px 8px; font-weight: 700; }}
QTableCornerButton::section {{ background: {PALETTE['surface_hi']}; border: none; }}
"""


def _tcell(text: str, *, mono: bool = False, color: str | None = None, bold: bool = False) -> QTableWidgetItem:
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


def _make_table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionMode(QAbstractItemView.NoSelection)
    t.setFocusPolicy(Qt.NoFocus)
    t.setShowGrid(False)
    t.setStyleSheet(_TABLE_QSS)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def _readiness_pill(check) -> QWidget:
    """A status pill for one environment.Check (live readiness data)."""
    color = PALETTE["green"] if check.ok else PALETTE["amber"]
    pill = QFrame()
    pill.setStyleSheet(
        f"background: {rgba(color, 0.12)}; border: 1px solid {rgba(color, 0.4)}; border-radius: 10px;"
    )
    lay = QVBoxLayout(pill)
    lay.setContentsMargins(12, 8, 12, 8)
    lay.setSpacing(1)
    top = QHBoxLayout()
    top.setSpacing(6)
    dot = QLabel("●")
    dot.setStyleSheet(f"color: {color}; font-size: 11px;")
    top.addWidget(dot)
    nm = QLabel(check.name)
    nm.setStyleSheet(f"color: {PALETTE['text']}; font-weight: 700; font-size: 12px;")
    top.addWidget(nm)
    top.addStretch(1)
    lay.addLayout(top)
    detail = check.detail if len(check.detail) <= 38 else check.detail[:37] + "…"
    lay.addWidget(muted(detail, faint=True))
    return pill


class HBarChart(QWidget):
    """A lightweight horizontal bar chart built from frames (renders offscreen)."""

    def __init__(self, label_w: int = 150, track_w: int = 220, parent=None) -> None:
        super().__init__(parent)
        self._label_w = label_w
        self._track_w = track_w
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 2, 0, 2)
        self._lay.setSpacing(8)

    def set_rows(self, rows: list[tuple[str, float, str]], max_value: float | None = None,
                 suffix: str = "") -> None:
        clear_layout(self._lay)
        mx = max_value or max([v for _, v, _ in rows] + [1])
        for label, value, color in rows:
            row = QHBoxLayout()
            row.setSpacing(10)
            lbl = QLabel(label)
            lbl.setFixedWidth(self._label_w)
            lbl.setStyleSheet(f"color: {PALETTE['text_dim']}; font-size: 12px;")
            row.addWidget(lbl)
            track = QFrame()
            track.setFixedSize(self._track_w, 14)
            track.setStyleSheet(f"background: {PALETTE['surface_hi']}; border-radius: 7px;")
            bar = QFrame(track)
            w = int(self._track_w * (value / mx)) if mx else 0
            bar.setGeometry(0, 0, max(w, 3), 14)
            bar.setStyleSheet(f"background: {color}; border-radius: 7px;")
            row.addWidget(track)
            val = QLabel(f"{value:g}{suffix}")
            val.setStyleSheet(f"color: {PALETTE['text']}; font-weight: 700; font-size: 12px;")
            row.addWidget(val)
            row.addStretch(1)
            self._lay.addLayout(row)


class Donut(QWidget):
    """A small painted donut/ring gauge showing a fraction (0..1) with a caption."""

    def __init__(self, fraction: float, caption: str, sub: str, color: str, parent=None) -> None:
        super().__init__(parent)
        self._frac = max(0.0, min(1.0, fraction))
        self._caption = caption
        self._sub = sub
        self._color = color
        self.setFixedSize(168, 168)

    def set_fraction(self, fraction: float, sub: str | None = None) -> None:
        self._frac = max(0.0, min(1.0, fraction))
        if sub is not None:
            self._sub = sub
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(20, 14, 128, 128)
        track = QPen(QColor(PALETTE["surface_hi"]))
        track.setWidth(15)
        track.setCapStyle(Qt.FlatCap)
        p.setPen(track)
        p.drawArc(rect, 0, 360 * 16)
        arc = QPen(QColor(self._color))
        arc.setWidth(15)
        arc.setCapStyle(Qt.RoundCap)
        p.setPen(arc)
        p.drawArc(rect, 90 * 16, -int(360 * 16 * self._frac))
        p.setPen(QColor(PALETTE["text"]))
        f = p.font()
        f.setPointSize(20)
        f.setBold(True)
        p.setFont(f)
        p.drawText(rect, Qt.AlignCenter, f"{round(self._frac * 100)}%")
        f.setPointSize(11)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(PALETTE["text"]))
        p.drawText(QRectF(0, 142, 168, 16), Qt.AlignCenter, self._caption)
        f.setPointSize(9)
        f.setBold(False)
        p.setFont(f)
        p.setPen(QColor(PALETTE["text_faint"]))
        p.drawText(QRectF(0, 156, 168, 12), Qt.AlignCenter, self._sub)
        p.end()


class ConfusionMatrix(QWidget):
    """A 2x2 confusion grid: TP / FN / FP / TN."""

    _SPEC = [
        ("tp", "TP", "attack blocked", "green", 0, 0),
        ("fn", "FN", "attack leaked", "red", 0, 1),
        ("fp", "FP", "benign blocked", "amber", 1, 0),
        ("tn", "TN", "benign allowed", "blue", 1, 1),
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        grid = QGridLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(9)
        self._cells: dict[str, QLabel] = {}
        for key, code, desc, color_key, r, c in self._SPEC:
            color = PALETTE[color_key]
            cell = QFrame()
            cell.setStyleSheet(
                f"background: {rgba(color, 0.12)}; border: 1px solid {rgba(color, 0.42)};"
                " border-radius: 10px;"
            )
            cl = QVBoxLayout(cell)
            cl.setContentsMargins(12, 9, 12, 9)
            cl.setSpacing(0)
            num = QLabel("—")
            num.setStyleSheet(f"font-size: 22px; font-weight: 800; color: {color};")
            top = QHBoxLayout()
            top.addWidget(num)
            top.addStretch(1)
            badge = QLabel(code)
            badge.setStyleSheet(f"color: {color}; font-weight: 800; font-size: 11px;")
            top.addWidget(badge)
            cl.addLayout(top)
            cl.addWidget(muted(desc, faint=True))
            self._cells[key] = num
            grid.addWidget(cell, r, c)

    def set_counts(self, tp: int, fp: int, tn: int, fn: int) -> None:
        self._cells["tp"].setText(str(tp))
        self._cells["fp"].setText(str(fp))
        self._cells["tn"].setText(str(tn))
        self._cells["fn"].setText(str(fn))


class MetricTile(Card):
    """A big-number metric tile (accuracy / precision / …)."""

    def __init__(self, label: str, hint: str, color: str, parent=None) -> None:
        super().__init__(parent=parent)
        self.body.setSpacing(2)
        self._value = QLabel("—")
        self._value.setStyleSheet(f"font-size: 30px; font-weight: 800; color: {color};")
        self.body.addWidget(self._value)
        name = QLabel(label)
        name.setStyleSheet(f"font-weight: 700; color: {PALETTE['text']};")
        self.body.addWidget(name)
        self.body.addWidget(muted(hint, faint=True))

    def set_value(self, value: str) -> None:
        self._value.setText(value)


class StatCard(Card):
    def __init__(self, value: str, label: str, icon_name: str, color: str, parent=None) -> None:
        super().__init__(parent=parent)
        self.body.setSpacing(8)
        top = QHBoxLayout()
        chip = QLabel()
        chip.setPixmap(icon(icon_name, color, 20).pixmap(20, 20))
        chip.setFixedSize(38, 38)
        chip.setAlignment(Qt.AlignCenter)
        chip.setStyleSheet(f"background: {rgba(color, 0.16)}; border-radius: 10px;")
        top.addWidget(chip)
        top.addStretch(1)
        self.body.addLayout(top)
        self._value = QLabel(value)
        self._value.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {PALETTE['text']};")
        self.body.addWidget(self._value)
        self.body.addWidget(muted(label, faint=True))

    def set_value(self, value: str) -> None:
        self._value.setText(value)


class HeroCard(Card):
    """A slim, playful greeting banner."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent=parent)
        self.setStyleSheet(
            "QFrame#Card {"
            "  border: 1px solid #e7c4d8;"
            "  border-radius: 16px;"
            "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1,"
            "    stop:0 rgba(205,180,240,0.45), stop:0.55 rgba(169,214,245,0.30),"
            "    stop:1 rgba(255,181,158,0.35));"
            "}"
        )
        add_shadow(self)
        greet, emoji = _greeting()
        row = QHBoxLayout()
        row.setSpacing(16)
        mark = QLabel(emoji)
        mark.setStyleSheet("font-size: 40px;")
        row.addWidget(mark, alignment=Qt.AlignVCenter)
        col = QVBoxLayout()
        col.setSpacing(5)
        tag = QLabel(f"{greet} — welcome to your purple-team lab")
        tag.setStyleSheet(f"font-size: 22px; font-weight: 800; color: {PALETTE['text']}; letter-spacing: -0.2px;")
        col.addWidget(tag)
        col.addWidget(muted(
            "Build it · Attack it · Defend it — connect models to MCP servers, break them, then harden them.",
        ))
        pillars = QHBoxLayout()
        pillars.setSpacing(10)
        for text, color in (
            ("🏗  Build & Connect", PALETTE["violet"]),
            ("🔴  Attack (lab)", PALETTE["red"]),
            ("🔵  Defend", PALETTE["blue"]),
        ):
            pillars.addWidget(Badge(text, color))
        pillars.addStretch(1)
        col.addLayout(pillars)
        row.addLayout(col, 1)
        self.body.addLayout(row)


QUICK_ACTIONS = [
    ("attacks", "Run an attack", "skull", "red"),
    ("defense", "Verify a defense", "lock", "blue"),
    ("scanner", "Scan a server", "search", "cyan"),
    ("chat", "Open chat", "chat", "violet"),
    ("research", "Full benchmark", "chart", "purple"),
]


class DashboardPage(QWidget):
    navigate = Signal(str)  # page key — wired to the main window's switcher

    def __init__(self, loop: AsyncLoop, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._metrics_job = None

        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(18)

        # greeting header
        header_row = QHBoxLayout()
        header_row.addWidget(page_header("Dashboard", "Your PurpleMCP-Lab — at a glance"), 1)
        self._refresh_btn = button("Refresh", "ghost", "refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self._refresh_btn, alignment=Qt.AlignTop)
        root.addLayout(header_row)

        root.addWidget(HeroCard())

        # 1) live readiness checks (real environment introspection)
        root.addWidget(self._build_readiness_card())

        # 2) stat tiles — defense-first ordering (re-sequenced)
        stats = QHBoxLayout()
        stats.setSpacing(14)
        self._guardrails_stat = StatCard(str(_count_guardrails()), "Guardrails", "tools", PALETTE["purple"])
        self._twins_stat = StatCard(str(_count_hardened_twins()), "Hardened twins", "lock", PALETTE["blue"])
        self._labs_stat = StatCard("0", "Attack labs", "skull", PALETTE["red"])
        self._servers_stat = StatCard("0", "MCP servers", "server", PALETTE["violet"])
        self._providers_stat = StatCard("0 / 0", "Providers ready", "cpu", PALETTE["green"])
        for card in (self._guardrails_stat, self._twins_stat, self._labs_stat,
                     self._servers_stat, self._providers_stat):
            stats.addWidget(card)
        root.addLayout(stats)

        # 3) at-a-glance donut gauges
        root.addWidget(self._build_charts_card())

        # 4) two-column: OWASP coverage chart | attack mix table
        mid = QHBoxLayout()
        mid.setSpacing(16)
        mid.addWidget(self._build_coverage_card(), 3)
        mid.addWidget(self._build_mix_card(), 2)
        root.addLayout(mid)

        # 5) security-metrics panel
        root.addWidget(self._build_metrics_card())

        # quick actions
        qa = Card("Quick actions", "Jump straight in")
        qrow = QHBoxLayout()
        qrow.setSpacing(12)
        for key, title, icon_name, color_key in QUICK_ACTIONS:
            qrow.addWidget(self._make_tile(key, title, icon_name, PALETTE[color_key]))
        qa.body.addLayout(qrow)
        root.addWidget(qa)

        # provider / server detail tables
        detail = QHBoxLayout()
        detail.setSpacing(16)
        prov_card = Card("LLM Providers", "Bring-your-own-key backends")
        self._providers_table = _make_table(["Provider", "Model", "Status"])
        prov_card.body.addWidget(self._providers_table)
        detail.addWidget(prov_card, 1)
        srv_card = Card("MCP Servers", "Registered & ready to drive")
        self._servers_table = _make_table(["Server", "Transport", "Description"])
        srv_card.body.addWidget(self._servers_table)
        detail.addWidget(srv_card, 1)
        root.addLayout(detail)
        root.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))
        self.refresh()

    # -- readiness -------------------------------------------------------- #
    def _build_readiness_card(self) -> Card:
        card = Card("Lab readiness", "Live environment checks — Python, providers, Ollama, servers, GUI, lab")
        self._readiness_grid = QGridLayout()
        self._readiness_grid.setHorizontalSpacing(10)
        self._readiness_grid.setVerticalSpacing(10)
        card.body.addLayout(self._readiness_grid)
        return card

    def _refresh_readiness(self) -> None:
        clear_layout(self._readiness_grid)
        try:
            checks = environment.gather()
        except Exception:  # noqa: BLE001 - never let a probe break the dashboard
            checks = []
        for i, chk in enumerate(checks):
            self._readiness_grid.addWidget(_readiness_pill(chk), i // 3, i % 3)

    # -- donut gauges ----------------------------------------------------- #
    def _build_charts_card(self) -> Card:
        card = Card("At a glance", "Coverage & composition of the lab")
        cov = owasp_coverage()
        covered = sum(1 for v in cov.values() if v)
        total = len(TAXONOMY) or 1
        high = sum(1 for e in TAXONOMY if e.severity == "HIGH")
        mcp = sum(1 for e in TAXONOMY if e.family.startswith("MCP"))
        row = QHBoxLayout()
        row.setSpacing(22)
        row.addStretch(1)
        row.addWidget(Donut(covered / len(OWASP_LLM_TOP10), "OWASP coverage",
                            f"{covered}/{len(OWASP_LLM_TOP10)} categories", PALETTE["purple"]))
        row.addWidget(Donut(high / total, "HIGH severity", f"{high}/{total} modules", PALETTE["red"]))
        row.addWidget(Donut(mcp / total, "MCP-specific", f"{mcp}/{total} modules", PALETTE["violet"]))
        row.addStretch(1)
        card.body.addLayout(row)
        return card

    # -- security metrics ------------------------------------------------- #
    def _build_metrics_card(self) -> Card:
        card = Card(
            "Security metrics — guardrails as detectors",
            "Accuracy · Precision · Recall · ASR, computed by running every guardrail for real",
        )
        run = button("Compute metrics", "primary", "chart")
        run.clicked.connect(self._run_metrics)
        self._metrics_btn = run
        card.add_header_widget(run)

        self._metrics_busy = BusyBar()
        card.body.addWidget(self._metrics_busy)
        self._metrics_status = muted(
            "Click “Compute metrics” to fire every attack + benign payload at the hardened twins "
            "(real MCP calls) and score the guardrails.", faint=True,
        )
        card.body.addWidget(self._metrics_status)

        tiles = QHBoxLayout()
        tiles.setSpacing(14)
        self._tile_acc = MetricTile("Accuracy", "correct / total", PALETTE["green"])
        self._tile_prec = MetricTile("Precision", "TP / (TP+FP)", PALETTE["blue"])
        self._tile_rec = MetricTile("Recall", "TP / (TP+FN)", PALETTE["violet"])
        self._tile_f1 = MetricTile("F1", "harmonic mean", PALETTE["purple"])
        self._tile_asr = MetricTile("ASR ↓", "attacks surviving", PALETTE["red"])
        for t in (self._tile_acc, self._tile_prec, self._tile_rec, self._tile_f1, self._tile_asr):
            tiles.addWidget(t)
        card.body.addLayout(tiles)

        grids = QHBoxLayout()
        grids.setSpacing(18)
        # confusion matrix
        cm_box = QVBoxLayout()
        cm_box.setSpacing(8)
        cm_box.addWidget(muted("Confusion matrix", faint=True))
        self._confusion = ConfusionMatrix()
        cm_box.addWidget(self._confusion)
        grids.addLayout(cm_box, 1)
        # ASR bar chart
        asr_box = QVBoxLayout()
        asr_box.setSpacing(8)
        asr_box.addWidget(muted("Attack Success Rate — before vs. after the guardrail", faint=True))
        self._asr_chart = HBarChart(label_w=150, track_w=240)
        self._asr_chart.set_rows(
            [("Vulnerable server", 0, PALETTE["red"]), ("Hardened twin", 0, PALETTE["green"])],
            max_value=100, suffix="%",
        )
        asr_box.addWidget(self._asr_chart)
        asr_box.addStretch(1)
        grids.addLayout(asr_box, 1)
        card.body.addLayout(grids)
        return card

    def _run_metrics(self) -> None:
        from ...benchmark import run_detection_metrics

        self._metrics_btn.setEnabled(False)
        self._metrics_busy.start()
        flash(self._metrics_status, "running real attack + benign payloads…", PALETTE["text_dim"], ms=120000)
        self._metrics_job = run_job(
            self._loop,
            lambda job: run_detection_metrics(
                on_case=lambda i, n, t: job.event.emit("case", (i, n, t))
            ),
            parent=self,
        )
        self._metrics_job.event.connect(self._on_metrics_progress)
        self._metrics_job.succeeded.connect(self._on_metrics)
        self._metrics_job.failed.connect(self._on_metrics_error)

    def _on_metrics_progress(self, kind: str, payload: object) -> None:
        if kind == "case":
            i, n, title = payload  # type: ignore[misc]
            flash(self._metrics_status, f"[{i}/{n}] {title}", PALETTE["text_dim"], ms=120000)

    def _on_metrics(self, m) -> None:
        self._metrics_busy.stop()
        self._metrics_btn.setEnabled(True)
        self._tile_acc.set_value(f"{m.accuracy:g}%")
        self._tile_prec.set_value(f"{m.precision:g}%")
        self._tile_rec.set_value(f"{m.recall:g}%")
        self._tile_f1.set_value(f"{m.f1:g}%")
        self._tile_asr.set_value(f"{m.asr_hardened:g}%")
        self._confusion.set_counts(m.tp, m.fp, m.tn, m.fn)
        self._asr_chart.set_rows(
            [("Vulnerable server", m.asr_vulnerable, PALETTE["red"]),
             ("Hardened twin", m.asr_hardened, PALETTE["green"])],
            max_value=100, suffix="%",
        )
        flash(
            self._metrics_status,
            f"✓ {m.n_attacks} attacks · ASR {m.asr_vulnerable:g}% → {m.asr_hardened:g}% after guardrails",
            PALETTE["green"], ms=8000,
        )

    def _on_metrics_error(self, msg: str) -> None:
        self._metrics_busy.stop()
        self._metrics_btn.setEnabled(True)
        flash(self._metrics_status, msg, PALETTE["red"], ms=6000)

    # -- coverage chart + table ------------------------------------------- #
    def _build_coverage_card(self) -> Card:
        cov = owasp_coverage()
        covered = sum(1 for v in cov.values() if v)
        card = Card(
            "OWASP LLM Top 10 (2025) coverage",
            f"{len(TAXONOMY)} modules · {covered}/{len(OWASP_LLM_TOP10)} categories demonstrated",
        )
        chart = HBarChart(label_w=210, track_w=180)
        rows = []
        for code, name in OWASP_LLM_TOP10.items():
            n = len(cov.get(code, []))
            color = PALETTE["purple"] if n else PALETTE["border_hi"]
            rows.append((f"{code} · {name}", n, color))
        chart.set_rows(rows, max_value=max([len(v) for v in cov.values()] + [1]))
        card.body.addWidget(chart)
        return card

    # -- attack mix table ------------------------------------------------- #
    def _build_mix_card(self) -> Card:
        card = Card("Attack mix", "By family and severity")
        table = _make_table(["Family", "Modules", "HIGH", "MEDIUM"])
        fams: dict[str, list[str]] = {}
        for e in TAXONOMY:
            fams.setdefault(e.family, []).append(e.severity)
        table.setRowCount(len(fams) + 1)
        r = 0
        tot_high = tot_med = tot = 0
        for fam, sevs in fams.items():
            high = sum(1 for s in sevs if s == "HIGH")
            med = sum(1 for s in sevs if s == "MEDIUM")
            tot_high += high
            tot_med += med
            tot += len(sevs)
            table.setItem(r, 0, _tcell(fam))
            table.setItem(r, 1, _tcell(str(len(sevs)), mono=True, bold=True))
            table.setItem(r, 2, _tcell(str(high), mono=True, color=PALETTE["red"]))
            table.setItem(r, 3, _tcell(str(med), mono=True, color=PALETTE["amber"]))
            r += 1
        table.setItem(r, 0, _tcell("Total", bold=True))
        table.setItem(r, 1, _tcell(str(tot), mono=True, bold=True, color=PALETTE["purple"]))
        table.setItem(r, 2, _tcell(str(tot_high), mono=True, color=PALETTE["red"]))
        table.setItem(r, 3, _tcell(str(tot_med), mono=True, color=PALETTE["amber"]))
        table.setMinimumHeight(150)
        card.body.addWidget(table)
        return card

    def _make_tile(self, key: str, title: str, icon_name: str, color: str) -> QPushButton:
        tile = QPushButton(f"  {title}")
        tile.setIcon(icon(icon_name, color, 18))
        tile.setCursor(Qt.PointingHandCursor)
        tile.setStyleSheet(
            f"QPushButton {{ background: {PALETTE['surface_2']}; color: {PALETTE['text']};"
            f" border: 1px solid {PALETTE['border']}; border-radius: 12px;"
            f" padding: 14px 12px; text-align: left; font-weight: 600; }}"
            f"QPushButton:hover {{ border-color: {color}; background: {PALETTE['surface_hi']}; }}"
        )
        tile.clicked.connect(lambda _=False, k=key: self.navigate.emit(k))
        return tile

    # -- data ------------------------------------------------------------- #
    def refresh(self) -> None:
        self._refresh_readiness()
        providers = load_providers()
        registry = load_registry()
        ready = sum(1 for c in providers.values() if c.ready)
        self._providers_stat.set_value(f"{ready} / {len(providers)}")
        self._servers_stat.set_value(str(len(registry)))
        self._labs_stat.set_value(str(_count_attack_labs()))

        self._providers_table.setRowCount(len(providers))
        for r, (name, cfg) in enumerate(providers.items()):
            self._providers_table.setItem(r, 0, _tcell(name, bold=True))
            self._providers_table.setItem(r, 1, _tcell(cfg.model, mono=True, color=PALETTE["text_dim"]))
            ok = cfg.ready
            self._providers_table.setItem(
                r, 2, _tcell("● ready" if ok else "○ no key",
                             color=PALETTE["green"] if ok else PALETTE["text_faint"]))

        self._servers_table.setRowCount(len(registry))
        for r, (name, spec) in enumerate(registry.items()):
            self._servers_table.setItem(r, 0, _tcell(name, bold=True))
            self._servers_table.setItem(r, 1, _tcell(spec.transport, color=PALETTE["indigo"]))
            self._servers_table.setItem(r, 2, _tcell(spec.description, color=PALETTE["text_dim"]))
