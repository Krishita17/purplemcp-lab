"""A live, in-app terminal — run the lab's own commands and watch output stream.

This is the "manual mode" the labs hang off of: every exploit/defense exposes the
exact ``purplemcp …`` commands behind it, each one **copyable** (paste it into your
own shell) *and* **runnable in place**, with real subprocess output streaming into a
colourised console. It is deliberately scoped to the project's own commands (see
:data:`purplemcp.gui.ops.RUNNER_ALLOW`) so it stays a teaching tool, not a shell.
"""

from __future__ import annotations

import shlex
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from .. import ops
from ..async_bridge import AsyncLoop, run_job
from ..icons import icon
from ..state import LabState
from ..theme import MONO, PALETTE, rgba
from .common import Badge, BusyBar, Card, button, flash, muted


# --------------------------------------------------------------------------- #
#  console colouring
# --------------------------------------------------------------------------- #
class TerminalHighlighter(QSyntaxHighlighter):
    """Tint whole console lines by what they signal — prompt, win, loss, warning.

    Per-block (one line) colouring keeps the monospaced whitespace of real tool
    output intact, which an HTML console would mangle.
    """

    _BAD = ("error", "traceback", "refused", "exploited", "leaked", "exposed",
            "pwn", "danger_formula", "auth_bypass", "ssn-")
    _OK = ("blocked", "redacted", "✓", "✅", "[exit 0]", "scrubbed", "held",
           "pass", "safe", "ok —")
    _WARN = ("warn", "⚠", "needs network", "no guardrail")

    def __init__(self, document) -> None:
        super().__init__(document)
        self._fmt: dict[str, QTextCharFormat] = {}
        for key, col, bold in (
            ("cmd", PALETTE["purple_hi"], True),
            ("ok", PALETTE["green"], False),
            ("bad", PALETTE["red"], False),
            ("warn", PALETTE["amber"], False),
        ):
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(col))
            if bold:
                fmt.setFontWeight(QFont.Bold)
            self._fmt[key] = fmt

    def highlightBlock(self, text: str) -> None:  # noqa: N802 - Qt override
        n = len(text)
        if not n:
            return
        if text.startswith("$ "):
            self.setFormat(0, n, self._fmt["cmd"])
            return
        low = text.lower()
        if text.startswith("[exit ") and "[exit 0]" not in text:
            self.setFormat(0, n, self._fmt["warn"])
            return
        if any(k in low for k in self._OK):
            self.setFormat(0, n, self._fmt["ok"])
            return
        if any(k in low for k in self._BAD):
            self.setFormat(0, n, self._fmt["bad"])
            return
        if any(k in low for k in self._WARN):
            self.setFormat(0, n, self._fmt["warn"])


# --------------------------------------------------------------------------- #
#  one suggested command — copy it, or run it in place
# --------------------------------------------------------------------------- #
class _CommandRow(QWidget):
    def __init__(self, label: str, command: str, on_run, on_copy, parent=None) -> None:
        super().__init__(parent)
        self.command = command
        lay = QVBoxLayout(self)
        lay.setContentsMargins(11, 9, 11, 9)
        lay.setSpacing(6)
        self.setStyleSheet(
            f"QWidget {{ background: {PALETTE['bg']}; border: 1px solid {PALETTE['border']};"
            f" border-radius: 10px; }}"
        )

        top = QHBoxLayout()
        top.setSpacing(8)
        lab = QLabel(label)
        lab.setStyleSheet(f"color: {PALETTE['text_dim']}; font-weight: 700; font-size: 11.5px;")
        top.addWidget(lab)
        top.addStretch(1)
        copy = button("Copy", "ghost")
        copy.setFixedHeight(26)
        copy.clicked.connect(lambda: on_copy(command))
        run = button("Run", "blue", "play", icon_color=PALETTE["blue"])
        run.setFixedHeight(26)
        run.clicked.connect(lambda: on_run(command))
        top.addWidget(copy)
        top.addWidget(run)
        lay.addLayout(top)

        cmd = QLabel(command)
        cmd.setWordWrap(True)
        cmd.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cmd.setStyleSheet(f"font-family: {MONO}; color: {PALETTE['purple_hi']}; font-size: 12px;")
        lay.addWidget(cmd)


# --------------------------------------------------------------------------- #
#  the terminal card
# --------------------------------------------------------------------------- #
class TerminalCard(Card):
    """A copy-and-run console for a set of suggested project commands.

    ``commands`` is a list of ``(label, command_string)``. If ``lab`` is given,
    the lab opt-in token is injected into a command's environment only while the
    lab is armed (so ``purplemcp`` calls that touch vulnerable servers work).
    """

    def __init__(
        self,
        loop: AsyncLoop,
        *,
        title: str = "Manual terminal",
        subtitle: str = "Copy a command into your own shell, or run it right here.",
        commands: Optional[list[tuple[str, str]]] = None,
        lab: Optional[LabState] = None,
        placeholder: str = "purplemcp …  (or python attacks/…/exploit.py)",
        parent=None,
    ) -> None:
        super().__init__(title, subtitle, parent=parent)
        self._loop = loop
        self._lab = lab
        self._job = None

        self._commands = list(commands or [])

        # a small "real terminal" cue in the header: traffic lights + live pill
        self.add_header_widget(_traffic_lights())
        self.add_header_widget(Badge("live", PALETTE["green"]))

        # suggested commands
        if self._commands:
            for label, command in self._commands:
                self.body.addWidget(
                    _CommandRow(label, command, self._run, self._copy)
                )

        # console
        self._console = QPlainTextEdit()
        self._console.setReadOnly(True)
        self._console.setPlaceholderText(
            "Output appears here. Run a command above, or type one below."
        )
        self._console.setStyleSheet(
            f"QPlainTextEdit {{ font-family: {MONO}; font-size: 11.5px; color: {PALETTE['text']};"
            f" background: {PALETTE['bg']}; border: 1px solid {PALETTE['border_hi']};"
            f" border-radius: 10px; padding: 9px 11px; }}"
        )
        self._console.setMinimumHeight(190)
        self._highlighter = TerminalHighlighter(self._console.document())
        self.body.addWidget(self._console)

        self._busy = BusyBar()
        self.body.addWidget(self._busy)

        # free-form input
        in_row = QHBoxLayout()
        in_row.setSpacing(8)
        prompt = QLabel("›")
        prompt.setStyleSheet(f"color: {PALETTE['purple_hi']}; font-family: {MONO}; font-weight: 800;")
        in_row.addWidget(prompt)
        self._input = QLineEdit()
        self._input.setPlaceholderText(placeholder)
        self._input.returnPressed.connect(self._run_input)
        in_row.addWidget(self._input, 1)
        self._run_btn = button("Run", "primary", "play")
        self._run_btn.clicked.connect(self._run_input)
        in_row.addWidget(self._run_btn)
        if self._commands:
            self._copy_all_btn = button("Copy all", "ghost")
            self._copy_all_btn.setToolTip("Copy every command above to the clipboard")
            self._copy_all_btn.clicked.connect(self._copy_all)
            in_row.addWidget(self._copy_all_btn)
        self._clear_btn = button("Clear", "ghost")
        self._clear_btn.clicked.connect(self._console.clear)
        in_row.addWidget(self._clear_btn)
        self.body.addLayout(in_row)

        self._status = muted("", faint=True)
        self.body.addWidget(self._status)

    # -- actions ---------------------------------------------------------- #
    def _copy(self, command: str) -> None:
        QGuiApplication.clipboard().setText(command)
        flash(self._status, "copied to clipboard", PALETTE["green"])

    def _copy_all(self) -> None:
        text = "\n".join(command for _label, command in self._commands)
        QGuiApplication.clipboard().setText(text)
        flash(self._status, f"copied {len(self._commands)} commands", PALETTE["green"])

    def _run_input(self) -> None:
        text = self._input.text().strip()
        if text:
            self._run(text)

    def _run(self, command: str) -> None:
        if self._job is not None:
            flash(self._status, "a command is already running…", PALETTE["amber"])
            return
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            self._append(f"parse error: {exc}")
            return
        if argv and argv[0] not in ops.RUNNER_ALLOW:
            self._append(
                f"refused: '{argv[0]}' is not allowed — this terminal only runs "
                "purplemcp / python / ollama commands."
            )
            return
        self._input.setText(command)
        self._set_running(True)
        lab_on = bool(self._lab and self._lab.armed)
        self._job = run_job(
            self._loop, lambda j: ops.run_command(j, argv, lab=lab_on), parent=self
        )
        self._job.event.connect(self._on_event)
        self._job.succeeded.connect(self._on_done)
        self._job.failed.connect(self._on_failed)

    # -- streaming -------------------------------------------------------- #
    def _on_event(self, kind: str, payload) -> None:
        if kind == "line":
            self._append(str(payload))

    def _append(self, text: str) -> None:
        self._console.appendPlainText(text)
        bar = self._console.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _on_done(self, rc: int) -> None:
        self._set_running(False)
        self._job = None
        if rc == 0:
            flash(self._status, "✓ finished", PALETTE["green"])
        elif rc in (126, 127):
            flash(self._status, "command not run", PALETTE["amber"], ms=4000)
        else:
            flash(self._status, f"exited with code {rc}", PALETTE["amber"], ms=4000)

    def _on_failed(self, msg: str) -> None:
        self._set_running(False)
        self._job = None
        self._append(f"ERROR: {msg}")
        flash(self._status, "failed", PALETTE["red"], ms=5000)

    def _set_running(self, running: bool) -> None:
        self._run_btn.setEnabled(not running)
        self._input.setEnabled(not running)
        self._busy.start() if running else self._busy.stop()

    # -- helpers ---------------------------------------------------------- #
    def prefill(self, command: str) -> None:
        """Put a command in the input without running it (used on selection)."""
        self._input.setText(command)


def _dot(color: str) -> QLabel:
    d = QLabel()
    d.setFixedSize(11, 11)
    d.setStyleSheet(f"background: {color}; border-radius: 5px;")
    return d


def _traffic_lights() -> QWidget:
    """Three macOS-style window dots — a subtle 'this is a terminal' cue."""
    box = QWidget()
    lay = QHBoxLayout(box)
    lay.setContentsMargins(0, 0, 4, 0)
    lay.setSpacing(6)
    for color in (PALETTE["red"], PALETTE["amber"], PALETTE["green"]):
        lay.addWidget(_dot(color))
    return box
