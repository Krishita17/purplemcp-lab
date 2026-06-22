"""Minimal, careful ``.env`` reader/writer for the AI Models page.

Writing secrets to disk deserves care: we preserve unrelated lines and comments,
update a key in place if present (else append), create the file with ``600``
permissions, and never log values. The repo's ``.env`` stays gitignored.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


def _env_path() -> Path:
    from ..config import REPO_ROOT

    return REPO_ROOT / ".env"


def read_env() -> dict[str, str]:
    """Parse the repo ``.env`` into a dict (empty if absent)."""
    path = _env_path()
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        out[key.strip()] = value.strip().strip("'\"")
    return out


def set_env_key(key: str, value: str) -> Path:
    """Set ``key=value`` in the repo ``.env`` (update in place or append).

    Also updates ``os.environ`` for the current process so the change takes effect
    immediately. Returns the .env path.
    """
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
        raise ValueError(f"invalid env key: {key!r}")
    path = _env_path()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    new_line = f"{key}={value}"
    replaced = False
    for i, line in enumerate(lines):
        if re.match(rf"\s*{re.escape(key)}\s*=", line) and not line.lstrip().startswith("#"):
            lines[i] = new_line
            replaced = True
            break
    if not replaced:
        lines.append(new_line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    os.environ[key] = value
    return path
