"""Filesystem MCP server — sandboxed file access (clean reference).

Every path the model supplies is forced through
``purplemcp.guardrails.safe_resolve``, which confines it to one root directory.
Compare with attacks/04_path_traversal to see what happens without that.

Root directory comes from ``PURPLEMCP_FS_ROOT`` (defaults to ./sandbox).
Run directly:  PURPLEMCP_FS_ROOT=./sandbox python servers/filesystem/server.py
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import safe_resolve

ROOT = Path(os.environ.get("PURPLEMCP_FS_ROOT", "./sandbox")).resolve()
ROOT.mkdir(parents=True, exist_ok=True)

mcp = FastMCP(
    "filesystem",
    instructions=f"Sandboxed file read/write. All paths are confined to {ROOT}.",
    log_level="WARNING",
)


@mcp.tool()
def list_dir(path: str = ".") -> str:
    """List entries under a directory (relative to the sandbox root)."""
    target = safe_resolve(ROOT, path, must_exist=True)
    if not target.is_dir():
        raise ValueError(f"{path!r} is not a directory")
    lines = [("d " if p.is_dir() else "f ") + p.name for p in sorted(target.iterdir())]
    return "\n".join(lines) or "(empty)"


@mcp.tool()
def read_file(path: str) -> str:
    """Read a UTF-8 text file from inside the sandbox (capped at 100k chars)."""
    target = safe_resolve(ROOT, path, must_exist=True)
    if not target.is_file():
        raise ValueError(f"{path!r} is not a file")
    return target.read_text(encoding="utf-8", errors="replace")[:100_000]


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Create or overwrite a text file inside the sandbox."""
    target = safe_resolve(ROOT, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} bytes to {path}"


if __name__ == "__main__":
    mcp.run()
