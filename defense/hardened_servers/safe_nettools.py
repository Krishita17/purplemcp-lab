"""Hardened twin of attacks/03 (command injection).

Same `ping` tool, no shell. `guardrails.safe_run` passes an argv list and
allowlists the executable, so injected metacharacters are inert data.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import CommandNotAllowed, safe_run

mcp = FastMCP("net-tools-hardened", instructions="Network diagnostics.", log_level="WARNING")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host once and return the output."""
    try:
        # host is ONE argv element; ';', '$(...)', '|' are literal text.
        return safe_run(["ping", "-c", "1", host], allow={"ping"}, timeout=8)
    except CommandNotAllowed as exc:
        return f"refused: {exc}"


if __name__ == "__main__":
    mcp.run()
