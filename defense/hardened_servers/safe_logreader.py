"""Hardened twin of attacks/22 (unbounded output / context flooding).

Same `dump_logs` tool, but the result passes through `guardrails.cap_text`, which
truncates to a fixed byte budget with a clear marker. A caller can still ask for
five million lines — they just get a bounded, labelled response instead of a flood.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import cap_text

mcp = FastMCP("log-reader-hardened", instructions="Read application logs (bounded).", log_level="WARNING")

_EOF = "EOF-LOG-MARKER-7731"


def _render(lines: int) -> str:
    body = "\n".join(f"log line {i}: request handled (200 OK)" for i in range(lines))
    return f"{body}\n{_EOF}"


@mcp.tool()
def dump_logs(lines: int = 10) -> str:
    """Return the most recent N log lines, capped to a safe size."""
    return cap_text(_render(lines), max_bytes=2 * 1024)


if __name__ == "__main__":
    mcp.run()
