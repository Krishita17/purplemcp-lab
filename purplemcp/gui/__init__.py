"""PurpleMCP desktop GUI (PySide6).

A native, dark "purple-team" console over the same core the CLI uses: connect
models to MCP servers, explore and call tools, chat with live tool-call tracing,
scan servers for vulnerabilities, and run the red-vs-blue attack/defend arena.

Launch it with::

    purplemcp gui
    # or
    python -m purplemcp.gui

PySide6 is an optional dependency. Install it with::

    pip install "purplemcp[gui]"
"""

from __future__ import annotations


def run() -> int:
    """Launch the desktop application. Returns the process exit code."""
    from .app import run as _run

    return _run()


__all__ = ["run"]
