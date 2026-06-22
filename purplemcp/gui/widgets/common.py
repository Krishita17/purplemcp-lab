"""Small reusable building blocks shared across the GUI pages."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..icons import icon
from ..theme import PALETTE, SEVERITY_COLORS, rgba


# --------------------------------------------------------------------------- #
#  effects
# --------------------------------------------------------------------------- #
def add_shadow(widget: QWidget, blur: int = 34, dy: int = 10, alpha: int = 120) -> None:
    eff = QGraphicsDropShadowEffect(widget)
    eff.setBlurRadius(blur)
    eff.setOffset(0, dy)
    eff.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(eff)


# --------------------------------------------------------------------------- #
#  labels
# --------------------------------------------------------------------------- #
def title_label(text: str, object_name: str = "SectionTitle") -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName(object_name)
    return lbl


def muted(text: str, faint: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("Faint" if faint else "Muted")
    lbl.setWordWrap(True)
    return lbl


def mono(text: str = "", color: Optional[str] = None) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("Mono")
    lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
    if color:
        lbl.setStyleSheet(f"color: {color};")
    return lbl


# --------------------------------------------------------------------------- #
#  pills / badges
# --------------------------------------------------------------------------- #
class Badge(QLabel):
    """A small rounded pill label in a tinted colour."""

    def __init__(self, text: str, color: str = PALETTE["purple"], parent=None) -> None:
        super().__init__(text.upper(), parent)
        self.setObjectName("Badge")
        self.set_color(color)
        f = self.font()
        f.setPointSizeF(f.pointSizeF() - 1)
        f.setWeight(QFont.DemiBold)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 0.5)
        self.setFont(f)
        self.setAlignment(Qt.AlignCenter)

    def set_color(self, color: str) -> None:
        self._color = color
        self.setStyleSheet(
            f"QLabel#Badge {{ color: {color}; background: {rgba(color, 0.13)};"
            f" border: 1px solid {rgba(color, 0.34)}; border-radius: 8px;"
            f" padding: 3px 9px; }}"
        )


def severity_pill(severity: str, count: Optional[int] = None) -> Badge:
    color = SEVERITY_COLORS.get(severity.upper(), PALETTE["text_faint"])
    text = severity if count is None else f"{severity} {count}"
    return Badge(text, color)


# --------------------------------------------------------------------------- #
#  cards
# --------------------------------------------------------------------------- #
class Card(QFrame):
    """A rounded surface with an optional header (title + right-hand widget)."""

    def __init__(
        self,
        title: Optional[str] = None,
        subtitle: Optional[str] = None,
        flat: bool = False,
        shadow: bool = False,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("CardFlat" if flat else "Card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(12)
        self._outer = outer

        if title is not None:
            header = QHBoxLayout()
            header.setSpacing(8)
            tbox = QVBoxLayout()
            tbox.setSpacing(2)
            lbl = QLabel(title)
            lbl.setObjectName("CardTitle")
            tbox.addWidget(lbl)
            if subtitle:
                tbox.addWidget(muted(subtitle, faint=True))
            header.addLayout(tbox)
            header.addStretch(1)
            self._header = header
            outer.addLayout(header)

        if shadow:
            add_shadow(self)

    @property
    def body(self) -> QVBoxLayout:
        return self._outer

    def add(self, widget: QWidget) -> QWidget:
        self._outer.addWidget(widget)
        return widget

    def add_header_widget(self, widget: QWidget) -> None:
        self._header.addWidget(widget)


# --------------------------------------------------------------------------- #
#  buttons
# --------------------------------------------------------------------------- #
def button(
    text: str,
    variant: str = "default",
    icon_name: Optional[str] = None,
    icon_color: Optional[str] = None,
    parent=None,
) -> QPushButton:
    btn = QPushButton(text, parent)
    if variant != "default":
        btn.setProperty("variant", variant)
    if icon_name:
        col = icon_color or ("white" if variant == "primary" else PALETTE["text"])
        btn.setIcon(icon(icon_name, col, 18))
    btn.setCursor(Qt.PointingHandCursor)
    return btn


# --------------------------------------------------------------------------- #
#  busy indicator
# --------------------------------------------------------------------------- #
class BusyBar(QProgressBar):
    """A thin indeterminate progress bar used as an inline 'working…' cue."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setRange(0, 0)
        self.setTextVisible(False)
        self.setFixedHeight(3)
        self.setStyleSheet(
            f"QProgressBar {{ background: transparent; border: none; }}"
            f"QProgressBar::chunk {{ background: {PALETTE['purple']}; border-radius: 2px; }}"
        )
        self.hide()

    def start(self) -> None:
        self.show()

    def stop(self) -> None:
        self.hide()


# --------------------------------------------------------------------------- #
#  misc
# --------------------------------------------------------------------------- #
def page_header(title: str, subtitle: str = "") -> QWidget:
    """A page header: a brand accent bar beside a big title + optional subtitle."""
    box = QWidget()
    row = QHBoxLayout(box)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(13)

    accent = QFrame()
    accent.setFixedWidth(4)
    accent.setMinimumHeight(34)
    accent.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
    accent.setStyleSheet(
        "border: none; border-radius: 2px;"
        f" background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        f"   stop:0 {PALETTE['violet']}, stop:1 {PALETTE['purple']});"
    )
    row.addWidget(accent)

    col = QVBoxLayout()
    col.setContentsMargins(0, 0, 0, 0)
    col.setSpacing(3)
    t = QLabel(title)
    t.setObjectName("PageTitle")
    col.addWidget(t)
    if subtitle:
        s = QLabel(subtitle)
        s.setObjectName("PageSub")
        s.setWordWrap(True)
        col.addWidget(s)
    row.addLayout(col)
    row.addStretch(1)
    return box


def make_scroll(inner: QWidget) -> QScrollArea:
    """Wrap a widget in a transparent, vertically-scrolling area."""
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    area.setWidget(inner)
    return area


def search_box(placeholder: str, on_change):
    """A clearable search field wired to ``on_change(text)``."""
    from PySide6.QtWidgets import QLineEdit

    box = QLineEdit()
    box.setPlaceholderText(placeholder)
    box.setClearButtonEnabled(True)
    box.textChanged.connect(on_change)
    return box


def filter_grouped_list(list_widget, text: str) -> None:
    """Show/hide rows of a grouped ``QListWidget`` by a query.

    Module rows carry an object with ``num/title/family/threat/guardrail`` in
    ``Qt.UserRole``; header rows (``UserRole`` is ``None``) are hidden when their
    whole group is filtered out.
    """
    from PySide6.QtCore import Qt

    query = text.strip().lower()
    header = None
    header_has_match = False
    for i in range(list_widget.count()):
        item = list_widget.item(i)
        meta = item.data(Qt.UserRole)
        if meta is None:  # group header
            if header is not None:
                header.setHidden(not header_has_match)
            header = item
            header_has_match = False
            continue
        hay = " ".join(
            str(x)
            for x in (
                getattr(meta, "num", ""),
                getattr(meta, "title", ""),
                getattr(meta, "family", ""),
                getattr(meta, "threat", ""),
                getattr(meta, "guardrail", "") or "",
            )
        ).lower()
        match = (not query) or (query in hay)
        item.setHidden(not match)
        if match:
            header_has_match = True
    if header is not None:
        header.setHidden(not header_has_match)


def clear_layout(layout) -> None:
    """Remove and free every item in a layout, hiding widgets immediately.

    ``deleteLater`` alone leaves the old widget on screen until the next event
    cycle, which flickers when a panel is rebuilt; re-parenting to ``None`` first
    removes it from the display right away.
    """
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.setParent(None)
            w.deleteLater()
            continue
        child = item.layout()
        if child is not None:
            clear_layout(child)


def hline() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setStyleSheet(f"color: {PALETTE['border']}; background: {PALETTE['border']}; max-height: 1px;")
    return line


def hstretch() -> QWidget:
    w = QWidget()
    w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
    return w


def flash(label: QLabel, text: str, color: str, ms: int = 2200) -> None:
    """Briefly show a status message on a label, then clear it."""
    label.setText(text)
    label.setStyleSheet(f"color: {color};")
    QTimer.singleShot(ms, lambda: label.setText(""))
