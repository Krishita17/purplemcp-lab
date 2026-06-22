"""A ⌘K command palette — fuzzy-jump to any page or run a quick action."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..theme import PALETTE

Command = tuple[str, str, Callable[[], None]]  # (title, subtitle, callback)


def _fuzzy(query: str, text: str) -> bool:
    """Subsequence match: every query char appears in order in text."""
    query, text = query.lower(), text.lower()
    if not query:
        return True
    it = iter(text)
    return all(ch in it for ch in query)


class CommandPalette(QDialog):
    def __init__(self, commands: list[Command], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._commands = commands
        self.setWindowFlags(Qt.Popup | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedWidth(560)

        card = QWidget(self)
        card.setObjectName("PaletteCard")
        card.setStyleSheet(
            f"#PaletteCard {{ background: {PALETTE['surface']}; border: 1px solid {PALETTE['border_hi']};"
            f" border-radius: 14px; }}"
            f"QLineEdit {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};"
            f" border-radius: 9px; padding: 11px 13px; color: {PALETTE['text']}; font-size: 15px; }}"
            f"QLineEdit:focus {{ border-color: {PALETTE['violet']}; }}"
            f"QListWidget {{ background: transparent; border: none; }}"
            f"QListWidget::item {{ border-radius: 8px; padding: 2px; }}"
            f"QListWidget::item:selected {{ background: {PALETTE['surface_hi']}; }}"
        )
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(card)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(10)

        self._input = QLineEdit()
        self._input.setPlaceholderText("Jump to a page or run an action…")
        self._input.textChanged.connect(self._filter)
        self._input.installEventFilter(self)
        lay.addWidget(self._input)

        self._list = QListWidget()
        self._list.setUniformItemSizes(True)
        self._list.itemActivated.connect(lambda it: self._run(it))
        self._list.setMaximumHeight(360)
        lay.addWidget(self._list)

        self._filter("")

    # -- population/filtering -------------------------------------------- #
    def _filter(self, text: str) -> None:
        self._list.clear()
        for i, (title, subtitle, _cb) in enumerate(self._commands):
            if _fuzzy(text, f"{title} {subtitle}"):
                item = QListWidgetItem()
                item.setData(Qt.UserRole, i)
                self._list.addItem(item)
                self._list.setItemWidget(item, _row(title, subtitle))
                item.setSizeHint(self._list.itemWidget(item).sizeHint())
        if self._list.count():
            self._list.setCurrentRow(0)

    def _run(self, item: QListWidgetItem | None) -> None:
        if item is None:
            return
        idx = item.data(Qt.UserRole)
        self.accept()
        self._commands[idx][2]()

    # -- keyboard --------------------------------------------------------- #
    def eventFilter(self, obj, event) -> bool:
        if obj is self._input and event.type() == QEvent.KeyPress:
            key = event.key()
            if key in (Qt.Key_Down, Qt.Key_Up):
                row = self._list.currentRow()
                row += 1 if key == Qt.Key_Down else -1
                self._list.setCurrentRow(max(0, min(row, self._list.count() - 1)))
                return True
            if key in (Qt.Key_Return, Qt.Key_Enter):
                self._run(self._list.currentItem())
                return True
            if key == Qt.Key_Escape:
                self.reject()
                return True
        return super().eventFilter(obj, event)

    def show_centered(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            geo = parent.geometry()
            x = geo.x() + (geo.width() - self.width()) // 2
            y = geo.y() + max(80, geo.height() // 6)
            self.move(x, y)
        self.show()
        self._input.setFocus()


def _row(title: str, subtitle: str) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(11, 7, 11, 7)
    lay.setSpacing(1)
    t = QLabel(title)
    t.setStyleSheet(f"color: {PALETTE['text']}; font-weight: 600;")
    lay.addWidget(t)
    if subtitle:
        s = QLabel(subtitle)
        s.setStyleSheet(f"color: {PALETTE['text_faint']}; font-size: 11px;")
        lay.addWidget(s)
    return w
