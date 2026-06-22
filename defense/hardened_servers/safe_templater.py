"""Hardened twin of attacks/11 (template / format-string injection).

Same `render_welcome` tool, but rendering goes through `guardrails.safe_format`,
which uses `string.Template` (`$name` placeholders). That grammar can only
substitute named values — it cannot reach object attributes, indexes, or globals
— so a `{...}` format-string payload is returned as inert text.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import safe_format

mcp = FastMCP("greeter-hardened", instructions="Render a greeting (safely).", log_level="WARNING")


@mcp.tool()
def render_welcome(template: str, username: str) -> str:
    """Render a welcome message. Use $user and $app_name in the template."""
    return safe_format(template, user=username, app_name="PurpleNotes", app_version="1.0")


if __name__ == "__main__":
    mcp.run()
