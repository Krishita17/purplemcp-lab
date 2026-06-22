"""MCP Servers page — view, add, install, and remove MCP servers."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ...config import (
    ServerSpec,
    default_registry,
    load_registry,
    load_user_registry,
    save_user_registry,
)
from ...installer import install_to_claude_desktop, render_mcp_json
from ..catalog_servers import CATALOG
from ..theme import MONO, PALETTE
from .common import (
    Badge,
    Card,
    button,
    clear_layout,
    flash,
    hline,
    make_scroll,
    muted,
    page_header,
)


class ServersPage(QWidget):
    def __init__(self, loop=None, parent=None) -> None:
        super().__init__(parent)
        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)
        root.addWidget(page_header("MCP Servers", "Add, install, and manage the servers your models can use"))

        # registry
        self._registry_card = Card("Registry", "Bundled examples + your own servers")
        refresh = button("Refresh", "ghost", "refresh")
        refresh.clicked.connect(self._refresh_registry)
        self._registry_card.add_header_widget(refresh)
        self._registry_box = QVBoxLayout()
        self._registry_box.setSpacing(0)
        self._registry_card.body.addLayout(self._registry_box)
        self._reg_status = muted("", faint=True)
        self._registry_card.body.addWidget(self._reg_status)
        root.addWidget(self._registry_card)

        root.addWidget(self._build_add_card())
        root.addWidget(self._build_catalog_card())
        root.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))
        self._refresh_registry()

    # -- registry list ---------------------------------------------------- #
    def _refresh_registry(self) -> None:
        clear_layout(self._registry_box)
        bundled = set(default_registry())
        registry = load_registry()
        for i, (name, spec) in enumerate(registry.items()):
            if i:
                self._registry_box.addWidget(hline())
            self._registry_box.addWidget(self._registry_row(name, spec, name in bundled))

    def _registry_row(self, name: str, spec: ServerSpec, bundled: bool) -> QWidget:
        row = QWidget()
        lay = QVBoxLayout(row)
        lay.setContentsMargins(0, 10, 0, 10)
        lay.setSpacing(4)
        top = QHBoxLayout()
        nm = QLabel(name)
        nm.setStyleSheet("font-weight: 700;")
        top.addWidget(nm)
        top.addWidget(Badge(spec.transport, PALETTE["indigo"]))
        top.addWidget(Badge("bundled" if bundled else "user", PALETTE["violet"] if bundled else PALETTE["green"]))
        top.addStretch(1)
        install = button("Install → Claude", "ghost")
        copy = button("Copy mcp.json", "ghost")
        install.clicked.connect(lambda _=False, s=spec: self._install(s))
        copy.clicked.connect(lambda _=False, s=spec: self._copy(s))
        top.addWidget(install)
        top.addWidget(copy)
        if not bundled:
            remove = button("Remove", "danger")
            remove.clicked.connect(lambda _=False, n=name: self._remove(n))
            top.addWidget(remove)
        lay.addLayout(top)
        if spec.description:
            lay.addWidget(muted(spec.description, faint=True))
        return row

    def _install(self, spec: ServerSpec) -> None:
        try:
            path = install_to_claude_desktop(spec)
        except Exception as exc:  # noqa: BLE001
            flash(self._reg_status, f"install failed: {exc}", PALETTE["red"], ms=6000)
            return
        flash(self._reg_status, f"✓ installed '{spec.name}' → {path} (restart Claude Desktop)", PALETTE["green"], ms=6000)

    def _copy(self, spec: ServerSpec) -> None:
        QApplication.clipboard().setText(render_mcp_json(spec))
        flash(self._reg_status, f"✓ copied {spec.name} mcp.json to clipboard", PALETTE["green"])

    def _remove(self, name: str) -> None:
        users = load_user_registry()
        users.pop(name, None)
        save_user_registry(users)
        self._refresh_registry()
        flash(self._reg_status, f"removed '{name}'", PALETTE["text_dim"])

    # -- add custom ------------------------------------------------------- #
    def _build_add_card(self) -> Card:
        card = Card("Add a custom server", "Register your own MCP server")
        self._f_name = QLineEdit()
        self._f_name.setPlaceholderText("name (e.g. my-tools)")
        self._f_desc = QLineEdit()
        self._f_desc.setPlaceholderText("description (optional)")
        self._f_transport = QComboBox()
        self._f_transport.addItems(["stdio", "streamable-http"])
        self._f_transport.currentTextChanged.connect(self._toggle_transport)
        trow = QHBoxLayout()
        trow.setSpacing(8)
        trow.addWidget(self._f_name, 1)
        trow.addWidget(self._f_transport)
        card.body.addLayout(trow)
        card.body.addWidget(self._f_desc)

        # stdio fields
        self._stdio = QWidget()
        sl = QVBoxLayout(self._stdio)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(8)
        self._f_command = QLineEdit()
        self._f_command.setPlaceholderText("command (e.g. npx or /usr/bin/python)")
        self._f_args = QLineEdit()
        self._f_args.setPlaceholderText("args, space-separated (e.g. -y @scope/server /path)")
        self._f_env = QLineEdit()
        self._f_env.setPlaceholderText("env, comma-separated KEY=VALUE (optional)")
        sl.addWidget(self._f_command)
        sl.addWidget(self._f_args)
        sl.addWidget(self._f_env)
        card.body.addWidget(self._stdio)

        # http field
        self._http = QWidget()
        hl = QVBoxLayout(self._http)
        hl.setContentsMargins(0, 0, 0, 0)
        self._f_url = QLineEdit()
        self._f_url.setPlaceholderText("url (e.g. http://localhost:8000/mcp)")
        hl.addWidget(self._f_url)
        card.body.addWidget(self._http)
        self._http.hide()

        add_row = QHBoxLayout()
        add_btn = button("Add server", "primary", "plus")
        add_btn.clicked.connect(self._add_custom)
        self._add_status = muted("", faint=True)
        add_row.addWidget(add_btn)
        add_row.addWidget(self._add_status)
        add_row.addStretch(1)
        card.body.addLayout(add_row)
        return card

    def _toggle_transport(self, transport: str) -> None:
        stdio = transport == "stdio"
        self._stdio.setVisible(stdio)
        self._http.setVisible(not stdio)

    def _add_custom(self) -> None:
        name = self._f_name.text().strip()
        if not name:
            flash(self._add_status, "name is required", PALETTE["amber"], ms=3000)
            return
        transport = self._f_transport.currentText()
        try:
            if transport == "stdio":
                command = self._f_command.text().strip()
                if not command:
                    flash(self._add_status, "command is required for stdio", PALETTE["amber"], ms=3000)
                    return
                env = {}
                for pair in self._f_env.text().split(","):
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        env[k.strip()] = v.strip()
                spec = ServerSpec(
                    name=name, description=self._f_desc.text().strip(), transport="stdio",
                    command=command, args=self._f_args.text().split(), env=env,
                )
            else:
                url = self._f_url.text().strip()
                if not url:
                    flash(self._add_status, "url is required for http", PALETTE["amber"], ms=3000)
                    return
                spec = ServerSpec(
                    name=name, description=self._f_desc.text().strip(),
                    transport="streamable-http", url=url,
                )
        except Exception as exc:  # noqa: BLE001
            flash(self._add_status, f"invalid: {exc}", PALETTE["red"], ms=5000)
            return
        users = load_user_registry()
        users[name] = spec
        save_user_registry(users)
        for f in (self._f_name, self._f_desc, self._f_command, self._f_args, self._f_env, self._f_url):
            f.clear()
        self._refresh_registry()
        flash(self._add_status, f"✓ added '{name}'", PALETTE["green"])

    # -- catalog ---------------------------------------------------------- #
    def _build_catalog_card(self) -> Card:
        card = Card("Catalog", "Popular published servers — need Node (npx) or uv (uvx) installed")
        existing = set(load_registry())
        for i, cs in enumerate(CATALOG):
            if i:
                card.body.addWidget(hline())
            card.body.addWidget(self._catalog_row(cs, cs.name in existing))
        return card

    def _catalog_row(self, cs, already: bool) -> QWidget:
        row = QWidget()
        lay = QVBoxLayout(row)
        lay.setContentsMargins(0, 10, 0, 10)
        lay.setSpacing(4)
        top = QHBoxLayout()
        nm = QLabel(cs.name)
        nm.setStyleSheet("font-weight: 700;")
        top.addWidget(nm)
        top.addWidget(Badge(cs.requires, PALETTE["amber"]))
        top.addStretch(1)
        add = button("Added ✓" if already else "Add", "ghost" if already else "primary")
        add.setEnabled(not already)
        status = muted("", faint=True)
        add.clicked.connect(lambda _=False, c=cs, b=add, s=status: self._add_catalog(c, b, s))
        top.addWidget(status)
        top.addWidget(add)
        lay.addLayout(top)
        lay.addWidget(muted(cs.description, faint=True))
        cmd = QLabel(f"{cs.command} {' '.join(cs.args)}")
        cmd.setStyleSheet(f"font-family: {MONO}; color: {PALETTE['text_faint']}; font-size: 11px;")
        cmd.setWordWrap(True)
        lay.addWidget(cmd)
        return row

    def _add_catalog(self, cs, btn, status) -> None:
        users = load_user_registry()
        users[cs.name] = cs.to_spec()
        save_user_registry(users)
        btn.setText("Added ✓")
        btn.setEnabled(False)
        self._refresh_registry()
        flash(status, "✓ added", PALETTE["green"])
