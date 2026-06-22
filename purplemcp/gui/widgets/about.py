"""An About dialog: version, live lab stats, links, and the safety note."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ... import __version__
from ..theme import PALETTE
from .sidebar import LogoMark


class AboutDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(Qt.Popup | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedWidth(440)

        card = QWidget(self)
        card.setObjectName("AboutCard")
        card.setStyleSheet(
            f"#AboutCard {{ background: {PALETTE['surface']};"
            f" border: 1px solid {PALETTE['border_hi']}; border-radius: 16px; }}"
            f"QLabel {{ color: {PALETTE['text_dim']}; }}"
        )
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(card)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(22, 22, 22, 20)
        lay.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(13)
        head.addWidget(LogoMark(46))
        tbox = QVBoxLayout()
        tbox.setSpacing(1)
        title = QLabel("PurpleMCP-Lab")
        title.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {PALETTE['text']};")
        tbox.addWidget(title)
        ver = QLabel(f"v{__version__} · sorbet · purple-team console")
        ver.setStyleSheet(f"color: {PALETTE['text_faint']}; font-size: 12px;")
        tbox.addWidget(ver)
        head.addLayout(tbox)
        head.addStretch(1)
        lay.addLayout(head)

        tag = QLabel("Build it · Attack it · Defend it — a hands-on lab for the Model Context Protocol.")
        tag.setWordWrap(True)
        tag.setStyleSheet(f"color: {PALETTE['text']};")
        lay.addWidget(tag)

        try:
            from ...environment import stats

            s = stats()
            stat_text = (
                f"{s['attack_modules']} attack modules · {s['hardened_twins']} hardened "
                f"twins · {s['guardrails']} guardrails"
            )
        except Exception:  # noqa: BLE001
            stat_text = ""
        if stat_text:
            chip = QLabel(stat_text)
            chip.setStyleSheet(
                f"color: {PALETTE['purple_hi']}; background: {PALETTE['surface_2']};"
                f" border: 1px solid {PALETTE['border']}; border-radius: 8px; padding: 7px 10px;"
            )
            lay.addWidget(chip)

        repo = QLabel(
            '<a href="https://github.com/Krishita17/purplemcp-lab" '
            f'style="color:{PALETTE["purple_hi"]};">github.com/Krishita17/purplemcp-lab</a>'
        )
        repo.setOpenExternalLinks(True)
        lay.addWidget(repo)

        note = QLabel(
            "Intentionally-vulnerable lab code is opt-in and localhost-only. See ETHICS.md."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {PALETTE['text_faint']}; font-size: 11px;")
        lay.addWidget(note)

        footer = QLabel("MIT License · by Kailash Parshad")
        footer.setStyleSheet(f"color: {PALETTE['text_faint']}; font-size: 11px;")
        lay.addWidget(footer)

    def show_centered(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            geo = parent.geometry()
            self.move(
                geo.x() + (geo.width() - self.width()) // 2,
                geo.y() + max(80, geo.height() // 5),
            )
        self.show()
