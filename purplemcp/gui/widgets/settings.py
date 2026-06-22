"""Settings — environment readiness, defaults, the lab switch, and about."""

from __future__ import annotations

import asyncio

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ...config import default_provider_name, load_providers
from ..async_bridge import AsyncLoop, run_job
from ..envfile import set_env_key
from ..icons import icon
from ..theme import PALETTE
from .common import (
    Badge,
    Card,
    button,
    flash,
    make_scroll,
    muted,
    page_header,
)


async def _gather_async():
    from ...environment import gather, stats

    return await asyncio.to_thread(lambda: (gather(), stats()))


class SettingsPage(QWidget):
    def __init__(self, loop: AsyncLoop, lab_state, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._lab = lab_state
        self._job = None

        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)

        head = QHBoxLayout()
        head.addWidget(page_header("Settings", "Your environment, defaults, and the lab switch"))
        head.addStretch(1)
        self._refresh_btn = button("Re-check", "ghost", "refresh")
        self._refresh_btn.clicked.connect(self._refresh)
        head.addWidget(self._refresh_btn, alignment=Qt.AlignTop)
        root.addLayout(head)

        # environment
        self._env_card = Card("Environment", "Readiness of your local setup")
        self._env_box = QVBoxLayout()
        self._env_box.setSpacing(8)
        self._env_card.body.addLayout(self._env_box)
        self._env_box.addWidget(muted("Checking…", faint=True))
        root.addWidget(self._env_card)

        # defaults
        defaults = Card("Defaults", "Saved to your gitignored .env")
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addWidget(QLabel("Default model provider"))
        self._provider = QComboBox()
        for name in load_providers():
            self._provider.addItem(name, userData=name)
        idx = self._provider.findData(default_provider_name())
        if idx >= 0:
            self._provider.setCurrentIndex(idx)
        row.addWidget(self._provider)
        save = button("Save", "primary", "check")
        save.clicked.connect(self._save_default)
        row.addWidget(save)
        self._save_status = muted("", faint=True)
        row.addWidget(self._save_status)
        row.addStretch(1)
        defaults.body.addLayout(row)
        root.addWidget(defaults)

        # the lab
        lab = Card("The attack lab", "Intentionally-vulnerable code — off by default")
        self._lab_check = QCheckBox("Arm the lab (allow vulnerable servers to run)")
        self._lab_check.setChecked(bool(getattr(lab_state, "armed", False)))
        self._lab_check.toggled.connect(self._lab.set_armed)
        self._lab.changed.connect(self._sync_lab)
        lab.body.addWidget(self._lab_check)
        lab.body.addWidget(muted(
            "When armed, the Attack Lab and Defense Lab may launch intentionally-vulnerable "
            "servers on localhost. Everything stays on your machine; exfil demos hit a fake "
            "local sink. See ETHICS.md.", faint=True))
        root.addWidget(lab)

        # about
        about = Card("About")
        about.body.addWidget(_about_row("Version", "PurpleMCP v0.5 · purple-team"))
        repo = QLabel('<a href="https://github.com/at0m-b0mb/PurpleMCP" '
                      f'style="color:{PALETTE["purple_hi"]};">github.com/at0m-b0mb/PurpleMCP</a>')
        repo.setOpenExternalLinks(True)
        about.body.addWidget(_about_row("Repository", widget=repo))
        about.body.addWidget(_about_row("Docs", "Open the Learn page for the full handbook"))
        root.addWidget(about)
        root.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))

        self._refresh()

    # -- environment ------------------------------------------------------ #
    def _refresh(self) -> None:
        self._refresh_btn.setEnabled(False)
        self._job = run_job(self._loop, _gather_async(), parent=self)
        self._job.succeeded.connect(self._on_env)
        self._job.failed.connect(lambda msg: self._on_env(([], {}), error=msg))

    def _on_env(self, payload, error: str = "") -> None:
        self._refresh_btn.setEnabled(True)
        _clear(self._env_box)
        if error:
            self._env_box.addWidget(muted(error, faint=True))
            return
        checks, stats = payload
        for c in checks:
            self._env_box.addWidget(_check_row(c))
        if stats:
            self._env_box.addWidget(muted(
                f"Lab: {stats['attack_modules']} attack modules · "
                f"{stats['hardened_twins']} hardened twins · {stats['guardrails']} guardrails",
                faint=True))

    # -- defaults --------------------------------------------------------- #
    def _save_default(self) -> None:
        value = self._provider.currentData()
        try:
            set_env_key("PURPLEMCP_DEFAULT_PROVIDER", value)
        except Exception as exc:  # noqa: BLE001
            flash(self._save_status, f"failed: {exc}", PALETTE["red"], ms=4000)
            return
        flash(self._save_status, "✓ saved to .env", PALETTE["green"])

    # -- lab -------------------------------------------------------------- #
    def _sync_lab(self, armed: bool) -> None:
        if self._lab_check.isChecked() != armed:
            self._lab_check.blockSignals(True)
            self._lab_check.setChecked(armed)
            self._lab_check.blockSignals(False)


def _check_row(check) -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(9)
    mark = QLabel()
    color = PALETTE["green"] if check.ok else PALETTE["red"]
    mark.setPixmap(icon("check" if check.ok else "x", color, 16).pixmap(16, 16))
    lay.addWidget(mark)
    name = QLabel(check.name)
    name.setStyleSheet("font-weight: 600;")
    name.setFixedWidth(120)
    lay.addWidget(name)
    detail = QLabel(check.detail + (f"   → {check.hint}" if check.hint else ""))
    detail.setWordWrap(True)
    detail.setStyleSheet(f"color: {PALETTE['text_dim']};")
    lay.addWidget(detail, 1)
    return row


def _about_row(label: str, value: str = "", widget: QWidget | None = None) -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(0, 2, 0, 2)
    lay.setSpacing(10)
    key = QLabel(label)
    key.setObjectName("Faint")
    key.setFixedWidth(120)
    lay.addWidget(key)
    lay.addWidget(widget if widget is not None else QLabel(value))
    lay.addStretch(1)
    return row


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w is not None:
            w.deleteLater()
