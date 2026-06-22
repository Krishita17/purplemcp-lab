"""A keyboard-shortcuts help overlay (F1 / ⌘/)."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ..theme import MONO, PALETTE

# (keys, description) — ⌘ shown for macOS; maps to Ctrl elsewhere.
SHORTCUTS: list[tuple[str, str]] = [
    ("⌘K", "Open the command palette"),
    ("⌘1 – ⌘9", "Jump to the Nth page"),
    ("⌘,", "Open Settings"),
    ("F1  ·  ⌘/", "Show this shortcuts help"),
    ("Esc", "Close palette / dialog"),
]


class ShortcutsDialog(QDialog):
    def __init__(self, shortcuts: list[tuple[str, str]], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.Popup | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedWidth(420)

        card = QWidget(self)
        card.setObjectName("ShortcutsCard")
        card.setStyleSheet(
            f"#ShortcutsCard {{ background: {PALETTE['surface']};"
            f" border: 1px solid {PALETTE['border_hi']}; border-radius: 14px; }}"
        )
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(card)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(10)
        title = QLabel("Keyboard shortcuts")
        title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {PALETTE['text']};")
        lay.addWidget(title)
        for keys, desc in shortcuts:
            lay.addLayout(_row(keys, desc))

    def show_centered(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            geo = parent.geometry()
            self.move(
                geo.x() + (geo.width() - self.width()) // 2,
                geo.y() + max(80, geo.height() // 5),
            )
        self.show()


def _row(keys: str, desc: str) -> QHBoxLayout:
    row = QHBoxLayout()
    row.setSpacing(12)
    kbd = QLabel(keys)
    kbd.setAlignment(Qt.AlignCenter)
    kbd.setFixedWidth(110)
    kbd.setStyleSheet(
        f"font-family: {MONO}; color: {PALETTE['purple_hi']};"
        f" background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border_hi']};"
        f" border-radius: 7px; padding: 4px 8px;"
    )
    row.addWidget(kbd)
    label = QLabel(desc)
    label.setStyleSheet(f"color: {PALETTE['text_dim']};")
    row.addWidget(label, 1)
    return row
