"""Installers that wire PurpleMCP's servers into real MCP hosts."""

from .clients import (
    claude_desktop_config_path,
    install_to_claude_desktop,
    render_mcp_json,
)

__all__ = [
    "claude_desktop_config_path",
    "install_to_claude_desktop",
    "render_mcp_json",
]
