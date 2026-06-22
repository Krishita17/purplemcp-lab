"""Hardened twin of attacks/17 (output / log injection).

Same `record_event` tool, but the untrusted message is passed through
`guardrails.sanitize_output` first: ANSI/terminal control characters are stripped
and newlines are escaped, so the text can't forge a separate log line or smuggle
control sequences. (Use `frame_untrusted` when the consumer is the model.)
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import sanitize_output

mcp = FastMCP("event-logger-hardened", instructions="Record events (safely).", log_level="WARNING")


@mcp.tool()
def record_event(message: str) -> str:
    """Record an event and return a confirmation line (message sanitized)."""
    return f"[INFO] event recorded: {sanitize_output(message)}"


if __name__ == "__main__":
    mcp.run()
