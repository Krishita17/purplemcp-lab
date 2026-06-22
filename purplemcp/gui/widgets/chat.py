"""Chat Playground — talk to any provider and watch it drive MCP tools live."""

from __future__ import annotations

import json

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ...config import default_provider_name, load_providers, load_registry
from ..async_bridge import AsyncLoop, ChatSession
from ..icons import icon
from ..theme import MONO, PALETTE
from .common import Badge, BusyBar, button, flash, muted, page_header


# --------------------------------------------------------------------------- #
#  message widgets
# --------------------------------------------------------------------------- #
def _bubble_row(bubble: QWidget, align_right: bool) -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(0, 0, 0, 0)
    if align_right:
        lay.addStretch(1)
        lay.addWidget(bubble)
    else:
        lay.addWidget(bubble)
        lay.addStretch(1)
    return row


def _bubble(text: str, *, user: bool) -> QWidget:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
    lbl.setMaximumWidth(560)
    if user:
        lbl.setStyleSheet(
            f"QLabel {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,"
            f" stop:0 {PALETTE['violet']}, stop:1 {PALETTE['purple']});"
            f" color: white; padding: 11px 14px; border-radius: 14px; }}"
        )
    else:
        lbl.setStyleSheet(
            f"QLabel {{ background: {PALETTE['surface']}; color: {PALETTE['text']};"
            f" border: 1px solid {PALETTE['border']};"
            f" padding: 11px 14px; border-radius: 14px; }}"
        )
    return _bubble_row(lbl, align_right=user)


def _system_note(text: str, color: str = PALETTE["text_faint"]) -> QWidget:
    lbl = QLabel(text)
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setStyleSheet(f"color: {color}; font-size: 11px; padding: 2px;")
    return _bubble_row(lbl, align_right=False)


class ToolCallCard(QFrame):
    """An inline card for one tool call + its result, updated as it streams."""

    def __init__(self, name: str, arguments: dict, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("CardFlat")
        self.setMaximumWidth(620)
        self.setStyleSheet(
            f"QFrame#CardFlat {{ background: {PALETTE['surface_2']};"
            f" border: 1px solid {PALETTE['border_hi']}; border-radius: 12px; }}"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(13, 10, 13, 11)
        lay.setSpacing(6)

        head = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon("tools", PALETTE["purple_hi"], 15).pixmap(15, 15))
        head.addWidget(ic)
        nm = QLabel(name)
        nm.setStyleSheet(f"font-family: {MONO}; font-weight: 700; color: {PALETTE['purple_hi']};")
        head.addWidget(nm)
        head.addStretch(1)
        self._status = Badge("running", PALETTE["amber"])
        head.addWidget(self._status)
        lay.addLayout(head)

        args = json.dumps(arguments, ensure_ascii=False)
        if len(args) > 200:
            args = args[:199] + "…"
        argl = QLabel(args)
        argl.setWordWrap(True)
        argl.setStyleSheet(f"font-family: {MONO}; color: {PALETTE['text_dim']}; font-size: 12px;")
        lay.addWidget(argl)

        self._result = QLabel("…")
        self._result.setWordWrap(True)
        self._result.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._result.setStyleSheet(
            f"font-family: {MONO}; color: {PALETTE['text']}; font-size: 12px;"
            f" background: {PALETTE['bg']}; border-radius: 8px; padding: 8px 10px;"
        )
        lay.addWidget(self._result)

    def set_result(self, text: str) -> None:
        shown = text if len(text) <= 1200 else text[:1199] + "…"
        self._result.setText(shown or "(no output)")
        err = text.startswith("ERROR")
        self._status.setText("ERROR" if err else "DONE")
        self._status.set_color(PALETTE["red"] if err else PALETTE["green"])


# --------------------------------------------------------------------------- #
#  page
# --------------------------------------------------------------------------- #
class ChatPage(QWidget):
    def __init__(self, loop: AsyncLoop, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._session: ChatSession | None = None
        self._server_checks: dict[str, QWidget] = {}
        self._tool_cards: dict[str, ToolCallCard] = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 20)
        root.setSpacing(14)
        root.addWidget(
            page_header("Chat Playground", "Chat with any model and watch it call MCP tools live")
        )

        root.addLayout(self._build_controls())
        tip = muted(
            "Tip: tick the server you want (calculator, text_tools, live_data…) and use a "
            "tool-capable model like qwen2.5, then ask something that needs a tool — you'll see "
            "the calls stream as cards. Chat-only models (e.g. llama3.1) often won't call tools.",
            faint=True,
        )
        root.addWidget(tip)
        root.addWidget(self._build_suggestions())
        self._busy = BusyBar()
        root.addWidget(self._busy)

        # transcript
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet(
            f"QScrollArea {{ background: {PALETTE['bg']}; border: 1px solid {PALETTE['border']};"
            f" border-radius: 14px; }}"
        )
        canvas = QWidget()
        self._feed = QVBoxLayout(canvas)
        self._feed.setContentsMargins(18, 18, 18, 18)
        self._feed.setSpacing(10)
        self._empty = _system_note("Start a session to begin chatting.")
        self._feed.addWidget(self._empty)
        self._feed.addStretch(1)
        self._scroll.setWidget(canvas)
        root.addWidget(self._scroll, 1)

        # input
        in_row = QHBoxLayout()
        in_row.setSpacing(10)
        self._input = QLineEdit()
        self._input.setPlaceholderText("Start a session, then ask something…")
        self._input.setMinimumHeight(42)
        self._input.returnPressed.connect(self._send)
        self._input.setEnabled(False)
        self._clear_btn = button("Clear", "ghost", "refresh")
        self._clear_btn.setMinimumHeight(42)
        self._clear_btn.setToolTip("Clear the transcript on screen")
        self._clear_btn.clicked.connect(self._clear_chat)
        self._send_btn = button("Send", "primary", "send")
        self._send_btn.setMinimumHeight(42)
        self._send_btn.clicked.connect(self._send)
        self._send_btn.setEnabled(False)
        in_row.addWidget(self._input, 1)
        in_row.addWidget(self._clear_btn)
        in_row.addWidget(self._send_btn)
        root.addLayout(in_row)

    def _build_controls(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(10)
        self._provider = QComboBox()
        providers = load_providers()
        for name, cfg in providers.items():
            label = name if cfg.ready else f"{name} (no key)"
            self._provider.addItem(label, userData=name)
        default = default_provider_name()
        idx = self._provider.findData(default)
        if idx >= 0:
            self._provider.setCurrentIndex(idx)
        bar.addWidget(QLabel("Model"))
        bar.addWidget(self._provider)

        self._model = QLineEdit()
        self._model.setPlaceholderText("override model (optional)")
        self._model.setMaximumWidth(190)
        bar.addWidget(self._model)

        bar.addWidget(QLabel("·  Servers"))
        for name in load_registry():
            from PySide6.QtWidgets import QCheckBox

            cb = QCheckBox(name)
            # tick a safe tool server by default so a first chat actually has tools
            if name == "calculator":
                cb.setChecked(True)
            bar.addWidget(cb)
            self._server_checks[name] = cb

        bar.addWidget(QLabel("Steps"))
        self._steps = QSpinBox()
        self._steps.setRange(1, 20)
        self._steps.setValue(8)
        self._steps.setMaximumWidth(60)
        bar.addWidget(self._steps)

        bar.addStretch(1)
        self._status = muted("", faint=True)
        bar.addWidget(self._status)
        self._session_btn = button("Start session", "primary", "play")
        self._session_btn.clicked.connect(self._toggle_session)
        bar.addWidget(self._session_btn)
        return bar

    # -- example prompts -------------------------------------------------- #
    _EXAMPLES = [
        "What is 19% of 4,200 plus the square root of 144?",
        "SHA-256 hash the text 'purplemcp'.",
        "What's the current weather in Tokyo?",
    ]

    def _build_suggestions(self) -> QWidget:
        row = QWidget()
        lay = QHBoxLayout(row)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        lay.addWidget(muted("Try:", faint=True))
        for prompt in self._EXAMPLES:
            chip = button(prompt, "ghost")
            chip.setToolTip("Start a session (tick the matching server), then click to ask — watch the tools fire")
            chip.clicked.connect(lambda _=False, p=prompt: self._use_suggestion(p))
            lay.addWidget(chip)
        lay.addStretch(1)
        return row

    def _use_suggestion(self, text: str) -> None:
        self._input.setText(text)
        if self._session is not None and self._input.isEnabled():
            self._send()
        else:
            self._input.setFocus()
            flash(self._status, "start a session, then Send", PALETTE["amber"], ms=3000)

    # -- session ---------------------------------------------------------- #
    def _selected_specs(self):
        registry = load_registry()
        return [registry[n] for n, cb in self._server_checks.items() if cb.isChecked()]

    def _toggle_session(self) -> None:
        if self._session is not None:
            self._end_session()
            return
        name = self._provider.currentData()
        cfg = load_providers().get(name)
        if cfg is None:
            return
        if not cfg.ready:
            flash(self._status, f"{name} has no API key (see .env)", PALETTE["red"], ms=5000)
            return
        if self._model.text().strip():
            cfg = cfg.model_copy(update={"model": self._model.text().strip()})

        self._clear_feed()
        self._busy.start()
        self._session_btn.setEnabled(False)
        self._session = ChatSession(
            self._loop, cfg, self._selected_specs(), max_steps=self._steps.value(), parent=self
        )
        self._session.ready.connect(self._on_ready)
        self._session.answer.connect(self._on_answer)
        self._session.tool_call.connect(self._on_tool_call)
        self._session.tool_result.connect(self._on_tool_result)
        self._session.error.connect(self._on_error)
        self._session.busy.connect(self._on_busy)
        self._session.closed.connect(self._on_closed)

    def _end_session(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None
        self._input.setEnabled(False)
        self._send_btn.setEnabled(False)
        self._session_btn.setText("Start session")
        self._session_btn.setProperty("variant", "primary")
        _repolish(self._session_btn)

    def _on_ready(self, tool_info: list) -> None:
        self._busy.stop()
        self._session_btn.setEnabled(True)
        self._session_btn.setText("End session")
        self._session_btn.setProperty("variant", "danger")
        _repolish(self._session_btn)
        self._input.setEnabled(True)
        self._send_btn.setEnabled(True)
        self._input.setFocus()
        names = ", ".join(t.name for t in tool_info) or "no tools"
        self._add(_system_note(f"● session ready — {len(tool_info)} tool(s): {names}", PALETTE["green"]))
        flash(self._status, "connected", PALETTE["green"])

    def _on_answer(self, text: str) -> None:
        self._add(_bubble(text, user=False))

    def _on_tool_call(self, call) -> None:
        card = ToolCallCard(call.name, call.arguments)
        self._tool_cards[call.id] = card
        self._add(_bubble_row(card, align_right=False))

    def _on_tool_result(self, call, result: str) -> None:
        card = self._tool_cards.get(call.id)
        if card is not None:
            card.set_result(result)

    def _on_error(self, msg: str) -> None:
        self._add(_system_note(f"⚠ {msg}", PALETTE["red"]))
        self._busy.stop()

    def _on_busy(self, busy: bool) -> None:
        self._busy.start() if busy else self._busy.stop()
        self._input.setEnabled(not busy and self._session is not None)
        self._send_btn.setEnabled(not busy and self._session is not None)

    def _on_closed(self) -> None:
        self._busy.stop()
        self._add(_system_note("session closed"))
        self._end_session()

    # -- messaging -------------------------------------------------------- #
    def _send(self) -> None:
        text = self._input.text().strip()
        if not text or self._session is None:
            return
        self._input.clear()
        self._add(_bubble(text, user=True))
        self._session.send(text)

    # -- feed plumbing ---------------------------------------------------- #
    def _add(self, widget: QWidget) -> None:
        if self._empty is not None:
            self._empty.deleteLater()
            self._empty = None
        self._feed.insertWidget(self._feed.count() - 1, widget)
        QTimer.singleShot(0, self._scroll_to_bottom)

    def _scroll_to_bottom(self) -> None:
        bar = self._scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _clear_feed(self) -> None:
        self._tool_cards.clear()
        while self._feed.count() > 1:  # keep the trailing stretch
            item = self._feed.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        self._empty = None

    def _clear_chat(self) -> None:
        """Wipe the on-screen transcript (the model's session, if any, stays open)."""
        self._clear_feed()
        msg = "Transcript cleared." if self._session is not None else "Start a session to begin chatting."
        self._empty = _system_note(msg)
        self._feed.insertWidget(self._feed.count() - 1, self._empty)

    def shutdown(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None


def _repolish(widget: QWidget) -> None:
    widget.style().unpolish(widget)
    widget.style().polish(widget)
