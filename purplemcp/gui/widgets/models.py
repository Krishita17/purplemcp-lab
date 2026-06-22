"""AI Models page — install/run local Ollama models and configure cloud keys."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from ...config import default_provider_name, load_providers
from .. import ops
from ..async_bridge import AsyncLoop, run_job
from ..envfile import read_env, set_env_key
from ..theme import MONO, PALETTE
from .common import (
    Badge,
    BusyBar,
    Card,
    button,
    clear_layout,
    flash,
    hline,
    make_scroll,
    muted,
    page_header,
)

ENV_VARS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
}
# Non-LLM service integrations used by the bundled MCP servers (bring-your-own-key).
# (label, env var, where to get a free key) — saved to .env exactly like provider keys.
INTEGRATIONS = [
    ("VirusTotal", "VT_API_KEY", "virustotal.com — powers threat_intel URL/domain/hash lookups"),
    ("AbuseIPDB", "ABUSEIPDB_API_KEY", "abuseipdb.com — powers threat_intel IP reputation"),
    ("Tavily", "TAVILY_API_KEY", "tavily.com — powers the web_search server"),
]
# qwen2.5 first: it's the most reliable local model at *structured* tool-calling,
# which is what every PurpleMCP feature depends on.
SUGGESTED = ["qwen2.5", "llama3.1", "llama3.2", "mistral"]
TOOL_CAPABLE = ("llama3", "qwen", "mistral", "command-r", "firefunction", "hermes")


def _human(size: int) -> str:
    f = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.1f} {unit}" if unit != "B" else f"{int(f)} B"
        f /= 1024
    return f"{f:.1f} TB"


class ModelsPage(QWidget):
    def __init__(self, loop: AsyncLoop, parent=None) -> None:
        super().__init__(parent)
        self._loop = loop
        self._jobs: list = []

        inner = QWidget()
        root = QVBoxLayout(inner)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(16)
        root.addWidget(page_header("AI Models", "Install and run the models that drive the tools"))

        root.addWidget(self._build_ollama_card())
        root.addWidget(self._build_cloud_card())
        root.addWidget(self._build_integrations_card())
        root.addWidget(self._build_default_card())
        root.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(make_scroll(inner))
        self.refresh()

    # -- ollama ----------------------------------------------------------- #
    def _build_ollama_card(self) -> Card:
        card = Card("Local · Ollama", "Free, private models that run on your machine")
        refresh = button("Refresh", "ghost", "refresh")
        refresh.clicked.connect(self.refresh)
        card.add_header_widget(refresh)

        self._ollama_status = muted("Checking Ollama…", faint=True)
        card.body.addWidget(self._ollama_status)

        self._models_box = QVBoxLayout()
        self._models_box.setSpacing(0)
        card.body.addLayout(self._models_box)

        card.body.addWidget(hline())
        pull_label = QLabel("Pull a model")
        pull_label.setStyleSheet("font-weight: 700;")
        card.body.addWidget(pull_label)
        pull_row = QHBoxLayout()
        pull_row.setSpacing(8)
        self._pull_input = QLineEdit()
        self._pull_input.setPlaceholderText("model name, e.g. llama3.1")
        self._pull_btn = button("Pull", "primary", "plus")
        self._pull_btn.clicked.connect(self._pull)
        pull_row.addWidget(self._pull_input, 1)
        pull_row.addWidget(self._pull_btn)
        card.body.addLayout(pull_row)

        chips = QHBoxLayout()
        chips.setSpacing(6)
        chips.addWidget(muted("Popular:", faint=True))
        for name in SUGGESTED:
            chip = button(name, "ghost")
            chip.clicked.connect(lambda _=False, n=name: self._pull_input.setText(n))
            chips.addWidget(chip)
        chips.addStretch(1)
        card.body.addLayout(chips)

        self._pull_bar = QProgressBar()
        self._pull_bar.setTextVisible(True)
        self._pull_bar.setFixedHeight(16)
        self._pull_bar.hide()
        card.body.addWidget(self._pull_bar)
        self._pull_status = muted("", faint=True)
        card.body.addWidget(self._pull_status)
        return card

    def refresh(self) -> None:
        self._ollama_status.setText("Checking Ollama…")
        clear_layout(self._models_box)
        job = run_job(self._loop, ops.ollama_list(), parent=self)
        job.succeeded.connect(self._on_models)
        job.failed.connect(self._on_ollama_error)
        self._jobs.append(job)

    def _on_models(self, models: list) -> None:
        if not models:
            self._ollama_status.setText("Ollama is running, but no models are installed yet. Pull one below.")
            return
        self._ollama_status.setText(f"● Ollama running — {len(models)} model(s) installed")
        self._ollama_status.setStyleSheet(f"color: {PALETTE['green']};")
        for i, m in enumerate(models):
            if i:
                self._models_box.addWidget(hline())
            self._models_box.addWidget(self._model_row(m["name"], m["size"]))

    def _on_ollama_error(self, msg: str) -> None:
        self._ollama_status.setText("Ollama not reachable — start it with `ollama serve` (or install from ollama.com).")
        self._ollama_status.setStyleSheet(f"color: {PALETTE['amber']};")

    def _model_row(self, name: str, size: int) -> QWidget:
        row = QWidget()
        lay = QHBoxLayout(row)
        lay.setContentsMargins(0, 8, 0, 8)
        lay.setSpacing(8)
        nm = QLabel(name)
        nm.setStyleSheet(f"font-family: {MONO}; font-weight: 700;")
        lay.addWidget(nm)
        if any(tag in name.lower() for tag in TOOL_CAPABLE):
            lay.addWidget(Badge("tools", PALETTE["green"]))
        lay.addWidget(muted(_human(size), faint=True))
        lay.addStretch(1)
        status = muted("", faint=True)
        test = button("Test", "ghost")
        delete = button("Delete", "danger")
        test.clicked.connect(lambda _=False, n=name, s=status: self._test_model(n, s))
        delete.clicked.connect(lambda _=False, n=name: self._delete_model(n))
        lay.addWidget(status)
        lay.addWidget(test)
        lay.addWidget(delete)
        return row

    def _test_model(self, name: str, status: QLabel) -> None:
        flash(status, "testing…", PALETTE["text_dim"], ms=60000)
        job = run_job(self._loop, ops.ollama_test(name), parent=self)
        job.succeeded.connect(lambda r: flash(status, f"✓ {r}", PALETTE["green"]))
        job.failed.connect(lambda m: flash(status, "failed", PALETTE["red"], ms=4000))
        self._jobs.append(job)

    def _delete_model(self, name: str) -> None:
        job = run_job(self._loop, ops.ollama_delete(name), parent=self)
        job.succeeded.connect(lambda _: self.refresh())
        job.failed.connect(lambda m: flash(self._pull_status, m, PALETTE["red"], ms=4000))
        self._jobs.append(job)

    def _pull(self) -> None:
        model = self._pull_input.text().strip()
        if not model:
            return
        self._pull_btn.setEnabled(False)
        self._pull_bar.setRange(0, 0)
        self._pull_bar.show()
        flash(self._pull_status, f"pulling {model}…", PALETTE["text_dim"], ms=600000)
        job = run_job(self._loop, lambda j: ops.ollama_pull(j, model), parent=self)
        job.event.connect(self._on_pull_progress)
        job.succeeded.connect(lambda _: self._on_pull_done(model))
        job.failed.connect(self._on_pull_error)
        self._jobs.append(job)

    def _on_pull_progress(self, kind: str, payload) -> None:
        if kind != "progress":
            return
        total, completed = payload.get("total", 0), payload.get("completed", 0)
        if total:
            self._pull_bar.setRange(0, int(total))
            self._pull_bar.setValue(int(completed))
            self._pull_bar.setFormat(f"{payload.get('status','')}  %p%")
        else:
            self._pull_bar.setRange(0, 0)
            self._pull_bar.setFormat(payload.get("status", ""))

    def _on_pull_done(self, model: str) -> None:
        self._pull_btn.setEnabled(True)
        self._pull_bar.hide()
        flash(self._pull_status, f"✓ pulled {model}", PALETTE["green"])
        self._pull_input.clear()
        self.refresh()

    def _on_pull_error(self, msg: str) -> None:
        self._pull_btn.setEnabled(True)
        self._pull_bar.hide()
        flash(self._pull_status, msg, PALETTE["red"], ms=6000)

    # -- cloud ------------------------------------------------------------ #
    def _build_cloud_card(self) -> Card:
        card = Card("Cloud providers", "Bring your own key — saved to .env (gitignored)")
        self._cloud_box = QVBoxLayout()
        self._cloud_box.setSpacing(0)
        card.body.addLayout(self._cloud_box)
        return card

    def _refresh_cloud(self) -> None:
        clear_layout(self._cloud_box)
        providers = load_providers()
        env = read_env()
        first = True
        for name, cfg in providers.items():
            if name == "ollama":
                continue
            if not first:
                self._cloud_box.addWidget(hline())
            first = False
            self._cloud_box.addWidget(self._cloud_row(name, cfg, env))

    def _cloud_row(self, name: str, cfg, env: dict) -> QWidget:
        envvar = ENV_VARS.get(name, "")
        row = QWidget()
        lay = QVBoxLayout(row)
        lay.setContentsMargins(0, 10, 0, 10)
        lay.setSpacing(6)
        top = QHBoxLayout()
        nm = QLabel(name)
        nm.setStyleSheet("font-weight: 700;")
        top.addWidget(nm)
        top.addWidget(muted(cfg.model, faint=True))
        top.addStretch(1)
        top.addWidget(Badge("key set", PALETTE["green"]) if cfg.ready else Badge("no key", PALETTE["text_faint"]))
        lay.addLayout(top)

        entry = QHBoxLayout()
        entry.setSpacing(8)
        field = QLineEdit()
        field.setEchoMode(QLineEdit.Password)
        field.setPlaceholderText(f"paste {envvar}")
        save = button("Save to .env", "primary")
        test = button("Test", "ghost")
        status = muted("", faint=True)
        save.clicked.connect(lambda _=False, n=name, f=field, s=status: self._save_key(n, f, s))
        test.clicked.connect(lambda _=False, n=name, f=field, s=status: self._test_provider(n, f, s))
        entry.addWidget(field, 1)
        entry.addWidget(test)
        entry.addWidget(save)
        lay.addLayout(entry)
        lay.addWidget(status)
        return row

    def _save_key(self, name: str, field: QLineEdit, status: QLabel) -> None:
        key = field.text().strip()
        if not key:
            flash(status, "enter a key first", PALETTE["amber"], ms=3000)
            return
        try:
            set_env_key(ENV_VARS[name], key)
        except Exception as exc:  # noqa: BLE001
            flash(status, f"save failed: {exc}", PALETTE["red"], ms=5000)
            return
        field.clear()
        flash(status, "✓ saved to .env", PALETTE["green"])
        self._refresh_cloud()
        self._refresh_default()

    def _test_provider(self, name: str, field: QLineEdit, status: QLabel) -> None:
        providers = load_providers()
        cfg = providers[name]
        typed = field.text().strip()
        if typed:
            cfg = cfg.model_copy(update={"api_key": typed})
        if not cfg.api_key:
            flash(status, "enter or save a key first", PALETTE["amber"], ms=3000)
            return
        flash(status, "testing…", PALETTE["text_dim"], ms=60000)
        job = run_job(self._loop, ops.provider_test(cfg), parent=self)
        job.succeeded.connect(lambda r: flash(status, f"✓ {r}", PALETTE["green"]))
        job.failed.connect(lambda m: flash(status, m, PALETTE["red"], ms=6000))
        self._jobs.append(job)

    # -- service integrations (non-LLM API keys) -------------------------- #
    def _build_integrations_card(self) -> Card:
        card = Card("Service integrations", "Keys for the live-API MCP servers — saved to .env (gitignored)")
        self._integrations_box = QVBoxLayout()
        self._integrations_box.setSpacing(0)
        card.body.addLayout(self._integrations_box)
        return card

    def _refresh_integrations(self) -> None:
        clear_layout(self._integrations_box)
        env = read_env()
        for i, (label, envvar, hint) in enumerate(INTEGRATIONS):
            if i:
                self._integrations_box.addWidget(hline())
            self._integrations_box.addWidget(self._integration_row(label, envvar, hint, env))

    def _integration_row(self, label: str, envvar: str, hint: str, env: dict) -> QWidget:
        row = QWidget()
        lay = QVBoxLayout(row)
        lay.setContentsMargins(0, 10, 0, 10)
        lay.setSpacing(6)
        top = QHBoxLayout()
        nm = QLabel(label)
        nm.setStyleSheet("font-weight: 700;")
        top.addWidget(nm)
        top.addWidget(muted(hint, faint=True), 1)
        top.addStretch(1)
        is_set = bool(env.get(envvar, "").strip())
        top.addWidget(Badge("key set", PALETTE["green"]) if is_set else Badge("no key", PALETTE["text_faint"]))
        lay.addLayout(top)

        entry = QHBoxLayout()
        entry.setSpacing(8)
        field = QLineEdit()
        field.setEchoMode(QLineEdit.Password)
        field.setPlaceholderText(f"paste {envvar}")
        save = button("Save to .env", "primary")
        status = muted("", faint=True)
        save.clicked.connect(lambda _=False, v=envvar, f=field, s=status: self._save_integration(v, f, s))
        entry.addWidget(field, 1)
        entry.addWidget(save)
        lay.addLayout(entry)
        lay.addWidget(status)
        return row

    def _save_integration(self, envvar: str, field: QLineEdit, status: QLabel) -> None:
        key = field.text().strip()
        if not key:
            flash(status, "enter a key first", PALETTE["amber"], ms=3000)
            return
        try:
            set_env_key(envvar, key)
        except Exception as exc:  # noqa: BLE001
            flash(status, f"save failed: {exc}", PALETTE["red"], ms=5000)
            return
        field.clear()
        flash(status, "✓ saved to .env", PALETTE["green"])
        self._refresh_integrations()

    # -- default ---------------------------------------------------------- #
    def _build_default_card(self) -> Card:
        card = Card("Default provider", "Used by the Chat Playground and the CLI")
        row = QHBoxLayout()
        row.setSpacing(8)
        self._default_combo = QComboBox()
        self._set_default_btn = button("Set default", "ghost")
        self._set_default_btn.clicked.connect(self._set_default)
        self._default_status = muted("", faint=True)
        row.addWidget(self._default_combo)
        row.addWidget(self._set_default_btn)
        row.addWidget(self._default_status)
        row.addStretch(1)
        card.body.addLayout(row)
        return card

    def _refresh_default(self) -> None:
        self._default_combo.clear()
        for name in load_providers():
            self._default_combo.addItem(name)
        idx = self._default_combo.findText(default_provider_name())
        if idx >= 0:
            self._default_combo.setCurrentIndex(idx)

    def _set_default(self) -> None:
        name = self._default_combo.currentText()
        try:
            set_env_key("PURPLEMCP_DEFAULT_PROVIDER", name)
        except Exception as exc:  # noqa: BLE001
            flash(self._default_status, f"failed: {exc}", PALETTE["red"], ms=4000)
            return
        flash(self._default_status, f"✓ default is {name}", PALETTE["green"])

    # -- lifecycle -------------------------------------------------------- #
    def showEvent(self, event) -> None:  # noqa: N802 - refresh env-derived UI on show
        super().showEvent(event)
        self._refresh_cloud()
        self._refresh_integrations()
        self._refresh_default()
