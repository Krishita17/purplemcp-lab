"""The left navigation rail: brand mark, page switcher, and a status footer."""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QLinearGradient, QPainter
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ... import __version__
from ..icons import icon, pixmap
from ..theme import PALETTE

# Grouped navigation: (section label, [(page key, label, icon name), ...]).
NAV_GROUPS = [
    ("OVERVIEW", [
        ("dashboard", "Dashboard", "dashboard"),
        ("learn", "Learn", "book"),
    ]),
    ("CONNECT", [
        ("models", "AI Models", "cpu"),
        ("servers", "MCP Servers", "server"),
        ("explorer", "Tool Explorer", "tools"),
        ("chat", "Chat Playground", "chat"),
    ]),
    ("RED TEAM", [
        ("attacks", "Attack Lab", "skull"),
    ]),
    ("BLUE TEAM", [
        ("defense", "Defense Lab", "lock"),
        ("scanner", "Security Scanner", "scanner"),
    ]),
    ("RESEARCH", [
        ("research", "Research", "chart"),
    ]),
    ("SYSTEM", [
        ("settings", "Settings", "gear"),
    ]),
]

# Flattened (page key, label, icon) in display order — used by the app to build pages.
NAV_ITEMS = [item for _, items in NAV_GROUPS for item in items]


class LogoMark(QWidget):
    """A painted rounded-square brand mark: violet→purple gradient + shield glyph."""

    def __init__(self, size: int = 38, parent=None) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self._glyph = pixmap("scanner", "white", size - 16, width=2.2)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(0, 0, self.width(), self.height())
        grad = QLinearGradient(0, 0, self.width(), self.height())
        grad.setColorAt(0, QColor(PALETTE["violet"]))
        grad.setColorAt(1, QColor(PALETTE["purple"]))
        p.setBrush(QBrush(grad))
        p.setPen(Qt.NoPen)
        p.drawRoundedRect(rect, 11, 11)
        gx = (self.width() - self._glyph.width() / self._glyph.devicePixelRatio()) / 2
        gy = (self.height() - self._glyph.height() / self._glyph.devicePixelRatio()) / 2
        p.drawPixmap(int(gx), int(gy), self._glyph)
        p.end()


class NavButton(QPushButton):
    def __init__(self, label: str, icon_name: str, parent=None) -> None:
        super().__init__(label, parent)
        self.setObjectName("NavButton")
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self._icon_name = icon_name
        self._refresh_icon(False)
        self.setIconSize(QSize(20, 20))
        self.toggled.connect(self._refresh_icon)

    def _refresh_icon(self, checked: bool) -> None:
        color = PALETTE["purple_hi"] if checked else PALETTE["text_faint"]
        self.setIcon(icon(self._icon_name, color, 20))


class NavSidebar(QWidget):
    navigate = Signal(str)  # page key

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(232)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 22, 14, 16)
        layout.setSpacing(6)

        # brand
        brand = QHBoxLayout()
        brand.setSpacing(11)
        brand.addWidget(LogoMark())
        tbox = QVBoxLayout()
        tbox.setSpacing(0)
        t = QLabel("PurpleMCP-Lab")
        t.setObjectName("BrandTitle")
        s = QLabel("SORBET · PURPLE TEAM")
        s.setObjectName("BrandSub")
        tbox.addWidget(t)
        tbox.addWidget(s)
        brand.addLayout(tbox)
        brand.addStretch(1)
        layout.addLayout(brand)
        layout.addSpacing(18)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons: dict[str, NavButton] = {}
        for gi, (section, items) in enumerate(NAV_GROUPS):
            if gi:
                layout.addSpacing(12)
            header = QLabel(section)
            header.setObjectName("NavGroupLabel")
            layout.addWidget(header)
            layout.addSpacing(4)
            for key, label, icon_name in items:
                btn = NavButton(label, icon_name)
                btn.clicked.connect(lambda _=False, k=key: self.navigate.emit(k))
                self._group.addButton(btn)
                self._buttons[key] = btn
                layout.addWidget(btn)

        layout.addStretch(1)

        # footer status
        self._status_dot = QLabel("●")
        self._status_dot.setStyleSheet(f"color: {PALETTE['text_faint']}; font-size: 11px;")
        self._status_text = QLabel("Lab disarmed")
        self._status_text.setObjectName("Faint")
        foot = QHBoxLayout()
        foot.setSpacing(7)
        foot.addWidget(self._status_dot)
        foot.addWidget(self._status_text)
        foot.addStretch(1)
        layout.addLayout(foot)

        ver = QLabel(f"v{__version__} · sorbet")
        ver.setObjectName("Faint")
        ver.setStyleSheet(f"color: {PALETTE['text_faint']}; font-size: 10px;")
        layout.addWidget(ver)

    def select(self, key: str) -> None:
        if key in self._buttons:
            self._buttons[key].setChecked(True)

    def set_lab_status(self, armed: bool) -> None:
        if armed:
            self._status_dot.setStyleSheet(f"color: {PALETTE['red']}; font-size: 11px;")
            self._status_text.setText("Lab ARMED")
            self._status_text.setStyleSheet(f"color: {PALETTE['red']};")
        else:
            self._status_dot.setStyleSheet(f"color: {PALETTE['green']}; font-size: 11px;")
            self._status_text.setText("Lab disarmed")
            self._status_text.setStyleSheet(f"color: {PALETTE['text_faint']};")
