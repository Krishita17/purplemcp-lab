"""Small shared UI state objects.

``LabState`` is the single source of truth for whether the intentionally-vulnerable
lab is "armed". Both the Attack Lab and Defense Lab bind to it, so arming in one
place is reflected everywhere (and in the sidebar status), while preserving the
opt-in: nothing vulnerable launches until the user flips this on.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal


class LabState(QObject):
    changed = Signal(bool)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._armed = False

    @property
    def armed(self) -> bool:
        return self._armed

    def set_armed(self, value: bool) -> None:
        value = bool(value)
        if value != self._armed:
            self._armed = value
            self.changed.emit(value)
