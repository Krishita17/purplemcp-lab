"""Tool Explorer — browse a server's tools, inspect schemas, call them directly."""

from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ...config import load_registry
from ...host.client import ToolInfo
from ..async_bridge import AsyncLoop, run_job
from ..ops import call_tool, list_tools
from ..theme import MONO, PALETTE
from .common import (
    Badge,
    BusyBar,
    Card,
    button,
    clear_layout,
    flash,
    make_scroll,
    muted,
    page_header,
    title_label,
)

_LIST_QSS = f"""
QListWidget {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};
    border-radius: 12px; padding: 6px; }}
QListWidget::item {{ border-radius: 8px; padding: 2px; margin: 2px 0; }}
QListWidget::item:selected {{ background: {PALETTE['surface_hi']}; }}
QListWidget::item:hover {{ background: {PALETTE['surface']}; }}
"""


class ToolExplorerPage(QWidget):
    def __init__(self, loop: AsyncLoop, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._spec = None
        self._fields: list[tuple[str, str, QWidget]] = []
        self._job = None

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 24)
        root.setSpacing(16)
        root.addWidget(
            page_header("Tool Explorer", "Inspect and call MCP tools directly — no model required")
        )

        # controls
        controls = QHBoxLayout()
        controls.setSpacing(10)
        self._server_combo = QComboBox()
        self._server_combo.setMinimumWidth(220)
        for name, spec in load_registry().items():
            self._server_combo.addItem(f"{name}", userData=spec)
        self._connect_btn = button("Connect", "primary", "bolt")
        self._connect_btn.clicked.connect(self._connect)
        controls.addWidget(QLabel("Server"))
        controls.addWidget(self._server_combo)
        controls.addWidget(self._connect_btn)
        controls.addStretch(1)
        self._status = muted("", faint=True)
        controls.addWidget(self._status)
        root.addLayout(controls)
        self._busy = BusyBar()
        root.addWidget(self._busy)

        # split: tool list | detail
        split = QSplitter(Qt.Horizontal)
        split.setHandleWidth(14)

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(8)
        lv.addWidget(title_label("Tools"))
        self._tool_list = QListWidget()
        self._tool_list.setStyleSheet(_LIST_QSS)
        self._tool_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._tool_list.setWordWrap(True)
        self._tool_list.itemSelectionChanged.connect(self._on_select)
        lv.addWidget(self._tool_list)
        split.addWidget(left)

        self._detail_host = QWidget()
        self._detail = QVBoxLayout(self._detail_host)
        self._detail.setContentsMargins(0, 0, 0, 0)
        self._detail.setSpacing(14)
        self._placeholder = muted("Connect to a server, then pick a tool to inspect and run it.")
        self._detail.addWidget(self._placeholder)
        self._detail.addStretch(1)
        split.addWidget(make_scroll(self._detail_host))

        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([280, 620])
        root.addWidget(split, 1)

    # -- connect / list --------------------------------------------------- #
    def _connect(self) -> None:
        self._spec = self._server_combo.currentData()
        if self._spec is None:
            return
        self._busy.start()
        self._connect_btn.setEnabled(False)
        self._tool_list.clear()
        self._job = run_job(self._loop, list_tools(self._spec), parent=self)
        self._job.succeeded.connect(self._on_tools)
        self._job.failed.connect(self._on_error)

    def _on_tools(self, tools: list[ToolInfo]) -> None:
        self._busy.stop()
        self._connect_btn.setEnabled(True)
        for ti in tools:
            item = QListWidgetItem(self._tool_list)
            item.setData(Qt.UserRole, ti)
            row = _tool_row(ti)
            item.setSizeHint(row.sizeHint())
            self._tool_list.addItem(item)
            self._tool_list.setItemWidget(item, row)
        flash(self._status, f"✓ {len(tools)} tool(s) discovered", PALETTE["green"])
        if tools:
            self._tool_list.setCurrentRow(0)

    def _on_error(self, msg: str) -> None:
        self._busy.stop()
        self._connect_btn.setEnabled(True)
        flash(self._status, msg, PALETTE["red"], ms=5000)

    # -- detail ----------------------------------------------------------- #
    def _on_select(self) -> None:
        items = self._tool_list.selectedItems()
        if not items:
            return
        ti: ToolInfo = items[0].data(Qt.UserRole)
        self._build_detail(ti)

    def _build_detail(self, ti: ToolInfo) -> None:
        _clear_layout(self._detail)
        self._fields = []

        head = QHBoxLayout()
        name = QLabel(ti.name)
        name.setStyleSheet(f"font-size: 18px; font-weight: 800; color: {PALETTE['text']};")
        head.addWidget(name)
        head.addStretch(1)
        head.addWidget(Badge(ti.server, PALETTE["indigo"]))
        self._detail.addLayout(head)
        if ti.description:
            self._detail.addWidget(muted(ti.description))

        # parameter form
        props = (ti.schema or {}).get("properties", {}) or {}
        required = set((ti.schema or {}).get("required", []) or [])
        form_card = Card("Arguments" if props else "Arguments (none)")
        for pname, pinfo in props.items():
            ptype = pinfo.get("type", "string")
            req = pname in required
            lbl = QLabel(f"{pname}  ·  {ptype}" + ("  · required" if req else ""))
            lbl.setObjectName("Faint")
            form_card.body.addWidget(lbl)
            if pinfo.get("description"):
                form_card.body.addWidget(muted(pinfo["description"], faint=True))
            field = QLineEdit()
            field.setPlaceholderText(_placeholder_for(ptype))
            if "default" in pinfo:
                field.setText(str(pinfo["default"]))
            form_card.body.addWidget(field)
            self._fields.append((pname, ptype, field))
        run_row = QHBoxLayout()
        self._call_btn = button("Call tool", "primary", "play")
        self._call_btn.clicked.connect(self._call)
        run_row.addWidget(self._call_btn)
        self._call_status = muted("", faint=True)
        run_row.addWidget(self._call_status)
        run_row.addStretch(1)
        form_card.body.addLayout(run_row)
        self._detail.addWidget(form_card)

        # result
        self._result_card = Card("Result")
        self._result = QPlainTextEdit()
        self._result.setReadOnly(True)
        self._result.setPlaceholderText("Run the tool to see its output here.")
        self._result.setStyleSheet(
            f"QPlainTextEdit {{ font-family: {MONO}; background: {PALETTE['bg']};"
            f" border: 1px solid {PALETTE['border']}; }}"
        )
        self._result.setMinimumHeight(150)
        self._result_card.body.addWidget(self._result)
        self._detail.addWidget(self._result_card)

        # schema
        schema_card = Card("Input schema")
        schema_view = QPlainTextEdit()
        schema_view.setReadOnly(True)
        schema_view.setPlainText(json.dumps(ti.schema or {}, indent=2))
        schema_view.setStyleSheet(
            f"QPlainTextEdit {{ font-family: {MONO}; color: {PALETTE['text_dim']};"
            f" background: {PALETTE['bg']}; border: 1px solid {PALETTE['border']}; }}"
        )
        schema_view.setMaximumHeight(160)
        schema_card.body.addWidget(schema_view)
        self._detail.addWidget(schema_card)
        self._detail.addStretch(1)

    # -- call ------------------------------------------------------------- #
    def _collect_args(self) -> dict:
        args: dict = {}
        for name, ptype, field in self._fields:
            raw = field.text().strip()
            if raw == "":
                continue
            args[name] = _coerce(raw, ptype)
        return args

    def _call(self) -> None:
        if self._spec is None:
            return
        items = self._tool_list.selectedItems()
        if not items:
            return
        ti: ToolInfo = items[0].data(Qt.UserRole)
        try:
            args = self._collect_args()
        except (ValueError, json.JSONDecodeError) as exc:
            flash(self._call_status, f"bad argument: {exc}", PALETTE["red"], ms=4000)
            return
        self._call_btn.setEnabled(False)
        flash(self._call_status, "running…", PALETTE["text_dim"], ms=60000)
        self._job = run_job(self._loop, call_tool(self._spec, ti.name, args), parent=self)
        self._job.succeeded.connect(self._on_result)
        self._job.failed.connect(self._on_call_error)

    def _on_result(self, text: str) -> None:
        self._call_btn.setEnabled(True)
        self._result.setPlainText(text)
        flash(self._call_status, "✓ done", PALETTE["green"])

    def _on_call_error(self, msg: str) -> None:
        self._call_btn.setEnabled(True)
        self._result.setPlainText(f"ERROR\n\n{msg}")
        flash(self._call_status, "failed", PALETTE["red"], ms=4000)


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #
def _tool_row(ti: ToolInfo) -> QWidget:
    row = QWidget()
    lay = QVBoxLayout(row)
    lay.setContentsMargins(10, 7, 10, 7)
    lay.setSpacing(1)
    name = QLabel(ti.name)
    name.setStyleSheet(f"font-weight: 700; color: {PALETTE['text']}; font-family: {MONO};")
    lay.addWidget(name)
    desc = (ti.description or "").strip().split("\n")[0]
    if len(desc) > 60:
        desc = desc[:59] + "…"
    if desc:
        d = QLabel(desc)
        d.setObjectName("Faint")
        lay.addWidget(d)
    return row


def _placeholder_for(ptype: str) -> str:
    return {
        "integer": "e.g. 42",
        "number": "e.g. 3.14",
        "boolean": "true / false",
        "array": '["json", "array"]',
        "object": '{"json": "object"}',
    }.get(ptype, "text")


def _coerce(raw: str, ptype: str):
    if ptype == "integer":
        return int(raw)
    if ptype == "number":
        return float(raw)
    if ptype == "boolean":
        return raw.lower() in ("1", "true", "yes", "on")
    if ptype in ("array", "object"):
        return json.loads(raw)
    return raw


def _clear_layout(layout) -> None:
    clear_layout(layout)
