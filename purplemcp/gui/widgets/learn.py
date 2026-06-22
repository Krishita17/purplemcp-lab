"""Learn page — read the project's docs in-app (rendered Markdown)."""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ...config import REPO_ROOT
from ..theme import MONO, PALETTE
from .common import make_scroll, page_header  # noqa: F401 (page_header used)

DOCS = [
    ("★ MCP Security Handbook", REPO_ROOT / "docs" / "MCP-SECURITY-GUIDE.md"),
    ("Overview (README)", REPO_ROOT / "README.md"),
    ("01 · What is MCP", REPO_ROOT / "docs" / "01-what-is-mcp.md"),
    ("02 · Architecture", REPO_ROOT / "docs" / "02-architecture.md"),
    ("03 · Installing models", REPO_ROOT / "docs" / "03-installing-models.md"),
    ("04 · Attack catalog", REPO_ROOT / "docs" / "04-attack-catalog.md"),
    ("05 · Defense playbook", REPO_ROOT / "docs" / "05-defense-playbook.md"),
    ("06 · Desktop GUI", REPO_ROOT / "docs" / "06-gui.md"),
    ("07 · Research methodology", REPO_ROOT / "docs" / "07-research-methodology.md"),
    ("Threat taxonomy", REPO_ROOT / "docs" / "TAXONOMY.md"),
    ("Security report", REPO_ROOT / "docs" / "SECURITY-REPORT.md"),
    ("Ethics", REPO_ROOT / "ETHICS.md"),
    ("Contributing", REPO_ROOT / "CONTRIBUTING.md"),
    ("Security policy", REPO_ROOT / "SECURITY.md"),
    ("Changelog", REPO_ROOT / "CHANGELOG.md"),
]

_LIST_QSS = f"""
QListWidget {{ background: {PALETTE['surface_2']}; border: 1px solid {PALETTE['border']};
    border-radius: 12px; padding: 6px; }}
QListWidget::item {{ border-radius: 8px; padding: 9px 11px; color: {PALETTE['text_dim']}; }}
QListWidget::item:selected {{ background: {PALETTE['surface_hi']}; color: {PALETTE['text']}; }}
QListWidget::item:hover {{ background: {PALETTE['surface']}; }}
"""


class LearnPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 24)
        root.setSpacing(16)
        root.addWidget(page_header("Learn", "The PurpleMCP handbook — read every guide without leaving the app"))

        body = QHBoxLayout()
        body.setSpacing(16)

        self._list = QListWidget()
        self._list.setFixedWidth(240)
        self._list.setStyleSheet(_LIST_QSS)
        for title, path in DOCS:
            item = QListWidgetItem(title)
            item.setData(Qt.UserRole, str(path))
            self._list.addItem(item)
        self._list.currentItemChanged.connect(self._load)
        body.addWidget(self._list)

        self._view = QTextBrowser()
        self._view.setOpenExternalLinks(True)
        self._view.setSearchPaths([str(REPO_ROOT), str(REPO_ROOT / "docs")])
        self._view.document().setDefaultStyleSheet(
            f"body {{ color: {PALETTE['text']}; }}"
            f"h1, h2, h3 {{ color: {PALETTE['text']}; }}"
            f"a {{ color: {PALETTE['purple_hi']}; }}"
            f"code, pre {{ font-family: {MONO}; color: {PALETTE['cyan']}; }}"
        )
        self._view.setStyleSheet(
            f"QTextBrowser {{ background: {PALETTE['bg']}; color: {PALETTE['text']};"
            f" border: 1px solid {PALETTE['border']}; border-radius: 12px; padding: 14px; }}"
        )
        body.addWidget(self._view, 1)
        root.addLayout(body, 1)

        if self._list.count():
            self._list.setCurrentRow(0)

    def _load(self, current: QListWidgetItem | None, _prev=None) -> None:
        if current is None:
            return
        path = current.data(Qt.UserRole)
        try:
            from pathlib import Path

            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._view.setPlainText(f"Could not open {path}\n\n{exc}")
            return
        self._view.setSearchPaths([str(REPO_ROOT), str(REPO_ROOT / "docs")])
        self._view.setMarkdown(text)
        self._view.verticalScrollBar().setValue(0)
