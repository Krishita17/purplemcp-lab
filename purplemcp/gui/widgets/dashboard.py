"""Dashboard — an at-a-glance overview of providers, servers, and the lab."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
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

from ...config import REPO_ROOT, load_providers, load_registry
from ...taxonomy import OWASP_LLM_TOP10, TAXONOMY, owasp_coverage
from ..icons import icon
from ..theme import PALETTE, rgba
from .common import (
    Badge,
    Card,
    add_shadow,
    button,
    clear_layout,
    hline,
    make_scroll,
    mono,
    muted,
    page_header,
)


def _count_attack_labs() -> int:
    attacks = REPO_ROOT / "attacks"
    if not attacks.exists():
        return 0
    return sum(
        1 for p in attacks.iterdir() if p.is_dir() and p.name[:2].isdigit()
    )


def _count_hardened_twins() -> int:
    twins = REPO_ROOT / "defense" / "hardened_servers"
    if not twins.exists():
        return 0
    return sum(1 for p in twins.glob("safe_*.py"))


def _count_guardrails() -> int:
    """Reusable guardrail modules under purplemcp/guardrails (excluding __init__)."""
    gd = REPO_ROOT / "purplemcp" / "guardrails"
    if not gd.exists():
        return 0
    return sum(1 for p in gd.glob("*.py") if p.name != "__init__.py")


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


class StatCard(Card):
    def __init__(self, value: str, label: str, icon_name: str, color: str, parent=None) -> None:
        super().__init__(parent=parent)
        self.body.setSpacing(8)
        top = QHBoxLayout()
        chip = QLabel()
        chip.setPixmap(icon(icon_name, color, 20).pixmap(20, 20))
        chip.setFixedSize(38, 38)
        chip.setAlignment(Qt.AlignCenter)
        chip.setStyleSheet(f"background: {rgba(color, 0.13)}; border-radius: 10px;")
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
    """The branded 'Build it. Attack it. Defend it.' banner."""

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

        from .sidebar import LogoMark

        row = QHBoxLayout()
        row.setSpacing(18)
        mark = LogoMark(64)
        row.addWidget(mark, alignment=Qt.AlignTop)

        col = QVBoxLayout()
        col.setSpacing(7)
        tag = QLabel("Build it.  Attack it.  Defend it.")
        tag.setStyleSheet(f"font-size: 24px; font-weight: 800; color: {PALETTE['text']}; letter-spacing: -0.2px;")
        col.addWidget(tag)
        col.addWidget(
            muted(
                "A purple-team lab for the Model Context Protocol — connect models to MCP "
                "servers, then break and harden them.",
            )
        )
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
    ("models", "Manage models", "cpu", "green"),
    ("research", "Run benchmark", "chart", "purple"),
]


class DashboardPage(QWidget):
    navigate = Signal(str)  # page key — wired to the main window's switcher

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(18)

        header_row = QHBoxLayout()
        header_row.addWidget(page_header("Dashboard", "Your PurpleMCP lab at a glance"), 1)
        self._refresh_btn = button("Refresh", "ghost", "refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self._refresh_btn, alignment=Qt.AlignTop)
        root.addLayout(header_row)

        root.addWidget(HeroCard())

        # stat cards
        self._stats = QGridLayout()
        self._stats.setSpacing(14)
        self._providers_stat = StatCard("0 / 0", "Providers ready", "cpu", PALETTE["green"])
        self._servers_stat = StatCard("0", "MCP servers", "server", PALETTE["violet"])
        self._labs_stat = StatCard("0", "Attack labs", "skull", PALETTE["red"])
        self._twins_stat = StatCard(str(_count_hardened_twins()), "Hardened twins", "lock", PALETTE["blue"])
        self._guardrails_stat = StatCard(str(_count_guardrails()), "Guardrails", "tools", PALETTE["purple"])
        for col, card in enumerate(
            (self._providers_stat, self._servers_stat, self._labs_stat,
             self._twins_stat, self._guardrails_stat)
        ):
            self._stats.addWidget(card, 0, col)
        root.addLayout(self._stats)

        # quick actions — clickable tiles that deep-link into the app
        qa = Card("Quick actions", "Jump straight in")
        qrow = QHBoxLayout()
        qrow.setSpacing(12)
        for key, title, icon_name, color_key in QUICK_ACTIONS:
            qrow.addWidget(self._make_tile(key, title, icon_name, PALETTE[color_key]))
        qa.body.addLayout(qrow)
        root.addWidget(qa)

        # OWASP-LLM coverage — a formatted table of how the lab maps to the standard
        root.addWidget(self._build_coverage_card())

        # detail cards row
        detail = QHBoxLayout()
        detail.setSpacing(16)
        self._providers_card = Card("LLM Providers", "Bring-your-own-key backends")
        self._providers_box = QVBoxLayout()
        self._providers_box.setSpacing(0)
        self._providers_card.body.addLayout(self._providers_box)
        detail.addWidget(self._providers_card, 1)

        self._servers_card = Card("MCP Servers", "Clean example servers, sandboxed")
        self._servers_box = QVBoxLayout()
        self._servers_box.setSpacing(0)
        self._servers_card.body.addLayout(self._servers_box)
        detail.addWidget(self._servers_card, 1)
        root.addLayout(detail)
        root.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))
        self.refresh()

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

    def _build_coverage_card(self) -> Card:
        card = Card("OWASP LLM Top 10 (2025) coverage", "How the lab's modules map to the standard")
        cov = owasp_coverage()
        covered = sum(1 for v in cov.values() if v)
        card.body.addWidget(muted(
            f"{len(TAXONOMY)} modules · {covered}/{len(OWASP_LLM_TOP10)} categories demonstrated",
            faint=True,
        ))
        table = QTableWidget(len(OWASP_LLM_TOP10), 4)
        table.setHorizontalHeaderLabels(["Code", "Category", "Modules", "Status"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.NoSelection)
        table.setShowGrid(False)
        table.setFocusPolicy(Qt.NoFocus)
        table.setStyleSheet(_TABLE_QSS)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        for r, (code, name) in enumerate(OWASP_LLM_TOP10.items()):
            n = len(cov.get(code, []))
            ok = n > 0
            table.setItem(r, 0, _tcell(code, mono=True, color=PALETTE["purple"]))
            table.setItem(r, 1, _tcell(name))
            table.setItem(r, 2, _tcell(str(n), mono=True, color=PALETTE["text_dim"]))
            table.setItem(r, 3, _tcell(
                "✓ covered" if ok else "—",
                color=PALETTE["green"] if ok else PALETTE["text_faint"],
            ))
        table.setMinimumHeight(330)
        card.body.addWidget(table)
        return card

    # -- data ------------------------------------------------------------- #
    def refresh(self) -> None:
        providers = load_providers()
        registry = load_registry()
        ready = sum(1 for c in providers.values() if c.ready)
        self._providers_stat.set_value(f"{ready} / {len(providers)}")
        self._servers_stat.set_value(str(len(registry)))
        self._labs_stat.set_value(str(_count_attack_labs()))

        _clear(self._providers_box)
        for i, (name, cfg) in enumerate(providers.items()):
            if i:
                self._providers_box.addWidget(hline())
            self._providers_box.addWidget(_provider_row(name, cfg))

        _clear(self._servers_box)
        for i, (name, spec) in enumerate(registry.items()):
            if i:
                self._servers_box.addWidget(hline())
            self._servers_box.addWidget(_server_row(name, spec))


def _clear(layout) -> None:
    clear_layout(layout)


def _provider_row(name: str, cfg) -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(0, 9, 0, 9)
    lay.setSpacing(10)
    nm = QLabel(name)
    nm.setStyleSheet("font-weight: 700;")
    nm.setFixedWidth(92)
    lay.addWidget(nm)
    lay.addWidget(mono(cfg.model, PALETTE["text_dim"]))
    lay.addStretch(1)
    if cfg.ready:
        lay.addWidget(Badge("ready", PALETTE["green"]))
    else:
        lay.addWidget(Badge("no key", PALETTE["text_faint"]))
    return row


def _server_row(name: str, spec) -> QWidget:
    row = QWidget()
    lay = QVBoxLayout(row)
    lay.setContentsMargins(0, 9, 0, 9)
    lay.setSpacing(2)
    top = QHBoxLayout()
    nm = QLabel(name)
    nm.setStyleSheet("font-weight: 700;")
    top.addWidget(nm)
    top.addStretch(1)
    top.addWidget(Badge(spec.transport, PALETTE["indigo"]))
    lay.addLayout(top)
    lay.addWidget(muted(spec.description, faint=True))
    return row
