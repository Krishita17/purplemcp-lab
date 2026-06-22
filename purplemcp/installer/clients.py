"""Write MCP server entries into host application configs.

Right now this targets Claude Desktop (the most common local MCP host) and can
also render a generic JSON snippet you can paste into any host's config.

We always back up an existing config to ``*.bak`` before modifying it.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from ..config import ServerSpec


def claude_desktop_config_path() -> Path:
    """Best-effort path to Claude Desktop's config for the current OS."""
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library/Application Support/Claude/claude_desktop_config.json"
    if sys.platform.startswith("win"):
        import os

        base = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        return base / "Claude/claude_desktop_config.json"
    # Linux / other
    return home / ".config/Claude/claude_desktop_config.json"


def _entry(spec: ServerSpec) -> dict:
    entry: dict = {"command": spec.resolved_command(), "args": list(spec.args)}
    if spec.env:
        entry["env"] = dict(spec.env)
    return entry


def render_mcp_json(spec: ServerSpec) -> str:
    """A copy-pasteable ``mcpServers`` snippet for any MCP host."""
    return json.dumps({"mcpServers": {spec.name: _entry(spec)}}, indent=2)


def install_to_claude_desktop(spec: ServerSpec) -> Path:
    """Merge ``spec`` into Claude Desktop's config and return the config path."""
    path = claude_desktop_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    data: dict = {}
    if path.exists() and path.stat().st_size > 0:
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            data = {}

    data.setdefault("mcpServers", {})[spec.name] = _entry(spec)
    path.write_text(json.dumps(data, indent=2))
    return path
