"""A thin bottom status bar: lab state, live async activity, provider, version."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget

from ... import __version__
from ...config import default_provider_name
from ..async_bridge import ACTIVITY
from ..theme import PALETTE


class StatusBar(QWidget):
    def __init__(self, lab_state, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("StatusBar")
        self.setFixedHeight(28)
        self.setStyleSheet(
            f"#StatusBar {{ background: {PALETTE['sidebar']}; border-top: 1px solid {PALETTE['border']}; }}"
            f"QLabel {{ color: {PALETTE['text_faint']}; font-size: 11px; }}"
        )
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 14, 0)
        lay.setSpacing(10)

        self._lab = QLabel("● lab disarmed")
        lay.addWidget(self._lab)
        lay.addWidget(_sep())

        self._activity = QLabel("ready")
        lay.addWidget(self._activity)
        lay.addStretch(1)

        prov = QLabel(f"default model: {default_provider_name()}")
        lay.addWidget(prov)
        lay.addWidget(_sep())
        ver = QLabel(f"PurpleMCP-Lab v{__version__}")
        lay.addWidget(ver)

        if lab_state is not None:
            lab_state.changed.connect(self._on_lab)
            self._on_lab(getattr(lab_state, "armed", False))
        ACTIVITY.changed.connect(self._on_activity)

    def _on_lab(self, armed: bool) -> None:
        if armed:
            self._lab.setText("● lab ARMED")
            self._lab.setStyleSheet(f"color: {PALETTE['red']}; font-size: 11px;")
        else:
            self._lab.setText("● lab disarmed")
            self._lab.setStyleSheet(f"color: {PALETTE['green']}; font-size: 11px;")

    def _on_activity(self, count: int) -> None:
        if count > 0:
            self._activity.setText(f"working… ({count})")
            self._activity.setStyleSheet(f"color: {PALETTE['amber']}; font-size: 11px;")
        else:
            self._activity.setText("ready")
            self._activity.setStyleSheet(f"color: {PALETTE['text_faint']}; font-size: 11px;")


def _sep() -> QLabel:
    s = QLabel("·")
    s.setStyleSheet(f"color: {PALETTE['border_hi']}; font-size: 11px;")
    return s
