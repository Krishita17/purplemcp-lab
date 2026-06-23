"""Application shell: the main window, navigation wiring, and the entry point."""

from __future__ import annotations

import sys

from PySide6.QtCore import QSettings
from PySide6.QtGui import QFontDatabase, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .async_bridge import AsyncLoop
from .state import LabState
from .theme import stylesheet
from .widgets.about import AboutDialog
from .widgets.attacks import AttackLabPage
from .widgets.chat import ChatPage
from .widgets.dashboard import DashboardPage
from .widgets.defense import DefenseLabPage
from .widgets.explorer import ToolExplorerPage
from .widgets.learn import LearnPage
from .widgets.models import ModelsPage
from .widgets.palette import CommandPalette
from .widgets.research import ResearchPage
from .widgets.scanner import ScannerPage
from .widgets.servers import ServersPage
from .widgets.settings import SettingsPage
from .widgets.shortcuts import SHORTCUTS, ShortcutsDialog
from .widgets.sidebar import NAV_ITEMS, NavSidebar
from .widgets.statusbar import StatusBar


class MainWindow(QMainWindow):
    def __init__(self, loop: AsyncLoop) -> None:
        super().__init__()
        self._loop = loop
        self._settings = QSettings("PurpleMCP", "PurpleMCP")
        self._current_key = "dashboard"
        self.setWindowTitle("PurpleMCP-Lab — Sorbet Console")
        self.resize(1200, 780)
        self.setMinimumSize(1000, 660)

        root = QWidget()
        root.setObjectName("Root")
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._sidebar = NavSidebar()
        self._sidebar.navigate.connect(self._go)
        layout.addWidget(self._sidebar)

        content = QWidget()
        content.setObjectName("ContentArea")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        self._stack = QStackedWidget()
        cl.addWidget(self._stack)
        self._content_layout = cl
        layout.addWidget(content, 1)
        self.setCentralWidget(root)

        # shared lab-arm state (Attack Lab + Defense Lab + sidebar status)
        self._lab = LabState(self)
        self._lab.changed.connect(self._sidebar.set_lab_status)

        # pages, in nav order
        self._dashboard = DashboardPage(loop)
        self._dashboard.navigate.connect(self._go_and_select)
        self._chat = ChatPage(loop)
        self._pages = {
            "dashboard": self._dashboard,
            "learn": LearnPage(),
            "models": ModelsPage(loop),
            "servers": ServersPage(loop),
            "explorer": ToolExplorerPage(loop),
            "chat": self._chat,
            "attacks": AttackLabPage(loop, self._lab),
            "defense": DefenseLabPage(loop, self._lab),
            "scanner": ScannerPage(loop),
            "research": ResearchPage(loop),
            "settings": SettingsPage(loop, self._lab),
        }
        self._keys = [key for key, _, _ in NAV_ITEMS]
        for key in self._keys:
            self._stack.addWidget(self._pages[key])

        # restore window size + last-open page from the previous session
        geometry = self._settings.value("geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        start = self._settings.value("page", "dashboard")
        if start not in self._pages:
            start = "dashboard"
        self._sidebar.select(start)
        self._go(start)

        # bottom status bar (lab state · async activity · provider · version)
        self._content_layout.addWidget(StatusBar(self._lab))

        # keyboard shortcuts: ⌘K command palette, ⌘1–9 page navigation
        self._palette: CommandPalette | None = None
        palette_sc = QShortcut(QKeySequence("Ctrl+K"), self)
        palette_sc.activated.connect(self._open_palette)
        for i, key in enumerate(self._keys[:9], start=1):
            sc = QShortcut(QKeySequence(f"Ctrl+{i}"), self)
            sc.activated.connect(lambda k=key: self._go_and_select(k))

        # ⌘, → Settings · F1 / ⌘/ → shortcuts help
        self._shortcuts_dialog: ShortcutsDialog | None = None
        settings_sc = QShortcut(QKeySequence("Ctrl+,"), self)
        settings_sc.activated.connect(lambda: self._go_and_select("settings"))
        for seq in ("F1", "Ctrl+/"):
            help_sc = QShortcut(QKeySequence(seq), self)
            help_sc.activated.connect(self._open_shortcuts)

    def _go(self, key: str) -> None:
        if key not in self._pages:
            return
        self._current_key = key
        self._stack.setCurrentWidget(self._pages[key])
        if key == "dashboard":
            self._dashboard.refresh()

    def _go_and_select(self, key: str) -> None:
        self._sidebar.select(key)
        self._go(key)

    def _open_palette(self) -> None:
        commands = [
            (f"Go to {label}", "Page", lambda k=key: self._go_and_select(k))
            for key, label, _icon in NAV_ITEMS
        ]
        commands.append((
            "Toggle lab arm", "Enable/disable the intentionally-vulnerable lab",
            lambda: self._lab.set_armed(not self._lab.armed),
        ))
        commands.append(("Refresh dashboard", "Reload providers & servers", self._dashboard.refresh))
        commands.append(("Keyboard shortcuts", "Show all key bindings", self._open_shortcuts))
        commands.append(("About PurpleMCP-Lab", "Version, links, and lab stats", self._open_about))
        self._palette = CommandPalette(commands, self)
        self._palette.show_centered()

    def _open_shortcuts(self) -> None:
        self._shortcuts_dialog = ShortcutsDialog(SHORTCUTS, self)
        self._shortcuts_dialog.show_centered()

    def _open_about(self) -> None:
        self._about_dialog = AboutDialog(self)
        self._about_dialog.show_centered()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._settings.setValue("geometry", self.saveGeometry())
        self._settings.setValue("page", self._current_key)
        self._chat.shutdown()
        self._loop.shutdown()
        super().closeEvent(event)


def run() -> int:
    QApplication.setApplicationName("PurpleMCP-Lab")
    QApplication.setApplicationDisplayName("PurpleMCP-Lab")
    app = QApplication.instance() or QApplication(sys.argv)

    font = QFontDatabase.systemFont(QFontDatabase.SystemFont.GeneralFont)
    font.setPointSize(13)
    app.setFont(font)
    app.setStyleSheet(stylesheet())

    loop = AsyncLoop()
    window = MainWindow(loop)
    window.show()
    window.raise_()
    window.activateWindow()
    return app.exec()
