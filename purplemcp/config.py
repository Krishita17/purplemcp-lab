"""Central configuration for PurpleMCP.

Two things live here:

1. **Provider settings** — bring-your-own-key config for every LLM backend,
   read from environment variables / ``.env``. Ollama needs no key.
2. **The MCP server registry** — the catalog of MCP servers the host can launch
   or connect to, with sane sandboxed defaults for the bundled examples.

Everything is read lazily so importing this module never fails, even with a
completely empty environment.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Literal, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError

# Repo-relative anchors. __file__ = purplemcp/config.py → repo root is two up.
REPO_ROOT = Path(__file__).resolve().parent.parent
SERVERS_DIR = REPO_ROOT / "servers"
SANDBOX_DIR = REPO_ROOT / "sandbox"

# Load .env from the repo root if it exists. Never raises when absent.
load_dotenv(REPO_ROOT / ".env")

Transport = Literal["stdio", "streamable-http"]


# --------------------------------------------------------------------------- #
#  Providers (bring-your-own-key)
# --------------------------------------------------------------------------- #
class ProviderConfig(BaseModel):
    """How to reach one LLM backend."""

    name: str
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    # Sampling temperature. ``None`` means "use the backend's own default".
    # The susceptibility probes set this to 0.7 so repeated runs can vary —
    # without it every run is deterministic and the experiment is meaningless.
    temperature: Optional[float] = None

    @property
    def ready(self) -> bool:
        """True when this provider can actually be used right now."""
        if self.name == "ollama":
            return True  # local; no key required
        return bool(self.api_key)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def load_providers() -> dict[str, ProviderConfig]:
    """Build the provider table from the current environment."""
    return {
        "ollama": ProviderConfig(
            name="ollama",
            # qwen2.5 does Ollama's *structured* tool-calling reliably; llama3.1
            # often just narrates a JSON blob instead of emitting a real tool call,
            # which makes a tool-driven app look broken. Default to the one that works.
            model=_env("OLLAMA_MODEL", "qwen2.5"),
            base_url=_env("OLLAMA_HOST", "http://localhost:11434"),
        ),
        "anthropic": ProviderConfig(
            name="anthropic",
            model=_env("ANTHROPIC_MODEL", "claude-opus-4-8"),
            api_key=_env("ANTHROPIC_API_KEY") or None,
        ),
        "openai": ProviderConfig(
            name="openai",
            model=_env("OPENAI_MODEL", "gpt-4o"),
            api_key=_env("OPENAI_API_KEY") or None,
        ),
        "gemini": ProviderConfig(
            name="gemini",
            model=_env("GEMINI_MODEL", "gemini-2.0-flash"),
            # Canonical var is GOOGLE_API_KEY (a real key starts with "AIzaSy").
            # GEMINI_API_KEY is accepted as a legacy fallback.
            api_key=_env("GOOGLE_API_KEY") or _env("GEMINI_API_KEY") or None,
        ),
        "openrouter": ProviderConfig(
            name="openrouter",
            model=_env("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet"),
            api_key=_env("OPENROUTER_API_KEY") or None,
            base_url="https://openrouter.ai/api/v1",
        ),
    }


def default_provider_name() -> str:
    return _env("PURPLEMCP_DEFAULT_PROVIDER", "ollama")


# --------------------------------------------------------------------------- #
#  MCP server registry
# --------------------------------------------------------------------------- #
class ServerSpec(BaseModel):
    """How to launch (stdio) or reach (http) one MCP server."""

    name: str
    description: str = ""
    transport: Transport = "stdio"
    # stdio transport
    command: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: Optional[str] = None
    # streamable-http transport
    url: Optional[str] = None

    def resolved_command(self) -> str:
        """The executable to spawn for stdio servers (defaults to this Python)."""
        return self.command or sys.executable


def _py_server(
    name: str, rel_path: str, description: str, env: dict[str, str] | None = None
) -> ServerSpec:
    """Helper: a stdio server run as ``python servers/<rel_path>``."""
    return ServerSpec(
        name=name,
        description=description,
        transport="stdio",
        command=sys.executable,
        args=[str(SERVERS_DIR / rel_path)],
        env=env or {},
    )


def default_registry() -> dict[str, ServerSpec]:
    """The bundled clean example servers, with safe defaults."""
    return {
        "calculator": _py_server(
            "calculator",
            "calculator/server.py",
            "Safe arithmetic & math helpers (no eval).",
        ),
        "filesystem": _py_server(
            "filesystem",
            "filesystem/server.py",
            "Sandboxed file read/write confined to a single root.",
            env={"PURPLEMCP_FS_ROOT": str(SANDBOX_DIR)},
        ),
        "web_fetch": _py_server(
            "web_fetch",
            "web_fetch/server.py",
            "SSRF-safe HTTP GET for public URLs only.",
        ),
        "notes": _py_server(
            "notes",
            "notes/server.py",
            "SQLite-backed personal notes (parameterized queries).",
            env={"PURPLEMCP_NOTES_DB": str(SANDBOX_DIR / "notes.sqlite")},
        ),
        "text_tools": _py_server(
            "text_tools",
            "text_tools/server.py",
            "Hashing, encoding & text helpers (stdlib, no network).",
        ),
        "live_data": _py_server(
            "live_data",
            "live_data/server.py",
            "Real weather (Open-Meteo) & crypto prices (CoinGecko) — no key needed.",
        ),
        "web_search": _py_server(
            "web_search",
            "web_search/server.py",
            "Live web search via the Tavily API (needs TAVILY_API_KEY).",
        ),
        "threat_intel": _py_server(
            "threat_intel",
            "threat_intel/server.py",
            "URL/domain/hash reputation (VirusTotal) + IP abuse (AbuseIPDB).",
        ),
        "dns_tools": _py_server(
            "dns_tools",
            "dns_tools/server.py",
            "Real DNS resolution, reverse DNS & IP geo/ASN info — no key needed.",
        ),
    }


def user_registry_path() -> Path:
    """Where user-added servers are persisted (gitignored, repo-local)."""
    return REPO_ROOT / "servers.local.json"


def load_user_registry() -> dict[str, ServerSpec]:
    """User-added servers from ``servers.local.json`` (empty if absent/invalid)."""
    path = user_registry_path()
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    out: dict[str, ServerSpec] = {}
    for name, entry in (raw or {}).items():
        try:
            out[name] = ServerSpec(name=name, **{k: v for k, v in entry.items() if k != "name"})
        except ValidationError:
            continue  # skip malformed entries rather than breaking the whole app
    return out


def save_user_registry(specs: dict[str, ServerSpec]) -> Path:
    """Persist the user server registry; returns the file path."""
    path = user_registry_path()
    data = {name: spec.model_dump(exclude_none=True) for name, spec in specs.items()}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def load_registry() -> dict[str, ServerSpec]:
    """The active server registry: bundled defaults merged with user-added servers.

    User entries (``servers.local.json``) win on name collisions, so you can
    override a bundled server if you need to.
    """
    return {**default_registry(), **load_user_registry()}


def ensure_sandbox() -> Path:
    """Create (if needed) and return the sandbox directory the example servers
    are confined to. Keeping demo I/O here means nothing escapes the repo."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    return SANDBOX_DIR
