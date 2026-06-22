"""Environment & readiness checks — powers ``purplemcp doctor`` and the GUI Settings page.

Pure, dependency-light introspection of the local setup: Python version, which LLM
providers are usable, whether Ollama is reachable, whether the desktop GUI is
installed, and the lab's arm state — plus a quick count of the lab's contents.
Everything degrades gracefully so a half-configured machine still gets a report.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass

from .config import REPO_ROOT, load_providers, load_registry

LAB_ENV_VAR = "PURPLEMCP_LAB_ENABLED"
LAB_TOKEN = "i-understand-this-is-a-lab"


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    hint: str = ""


def lab_armed() -> bool:
    return os.environ.get(LAB_ENV_VAR) == LAB_TOKEN


def ollama_status() -> tuple[bool, str]:
    """(reachable, human detail) for the local Ollama daemon."""
    try:
        import ollama

        result = ollama.list()
        models = [m.get("model") or m.get("name") for m in result.get("models", [])]
        models = [m for m in models if m]
        shown = ", ".join(models[:4]) + ("…" if len(models) > 4 else "")
        return True, f"running · {len(models)} model(s){': ' + shown if shown else ''}"
    except Exception as exc:  # noqa: BLE001 - any failure means 'not reachable'
        return False, f"not reachable ({type(exc).__name__})"


def _count(path, predicate) -> int:
    if not path.exists():
        return 0
    return sum(1 for p in path.iterdir() if predicate(p))


def stats() -> dict[str, int]:
    """Counts of the lab's contents (modules, twins, guardrails)."""
    attacks = REPO_ROOT / "attacks"
    twins = REPO_ROOT / "defense" / "hardened_servers"
    guards = REPO_ROOT / "purplemcp" / "guardrails"
    return {
        "attack_modules": _count(attacks, lambda p: p.is_dir() and p.name[:2].isdigit()),
        "hardened_twins": _count(twins, lambda p: p.suffix == ".py" and not p.name.startswith("_")),
        "guardrails": _count(guards, lambda p: p.suffix == ".py" and not p.name.startswith("_")),
    }


def gather() -> list[Check]:
    """Run all readiness checks and return them in display order."""
    checks: list[Check] = []

    v = sys.version_info
    checks.append(Check(
        "Python", v >= (3, 11),
        f"{platform.python_version()} on {platform.system()} {platform.machine()}",
        "" if v >= (3, 11) else "PurpleMCP needs Python 3.11+",
    ))

    providers = load_providers()
    ready = [n for n, c in providers.items() if c.ready]
    checks.append(Check(
        "LLM providers", bool(ready),
        f"{len(ready)}/{len(providers)} ready" + (f": {', '.join(ready)}" if ready else ""),
        "" if ready else "Add an API key to .env, or start Ollama for a local model",
    ))

    ok, detail = ollama_status()
    checks.append(Check("Ollama (local)", ok, detail,
                        "" if ok else "Install & run Ollama from https://ollama.com (optional)"))

    registry = load_registry()
    checks.append(Check("MCP servers", bool(registry), f"{len(registry)} registered", ""))

    try:
        import PySide6

        gui_ok, gui_detail = True, f"PySide6 {PySide6.__version__}"
    except Exception:  # noqa: BLE001
        gui_ok, gui_detail = False, "not installed"
    checks.append(Check("Desktop GUI", gui_ok, gui_detail,
                        "" if gui_ok else "pip install 'purplemcp[gui]'"))

    armed = lab_armed()
    checks.append(Check(
        "Attack lab", True,
        "ARMED — intentionally-vulnerable code may run" if armed else "disarmed (safe default)",
        "",
    ))

    return checks


def all_ok(checks: list[Check] | None = None) -> bool:
    """True if every non-optional readiness check passed (Ollama is optional)."""
    checks = checks or gather()
    optional = {"Ollama (local)"}
    return all(c.ok for c in checks if c.name not in optional)
