"""17 - Output / log injection. VULNERABLE. Lab only.

An 'event logger' tool that echoes the caller's message verbatim into its result.
That result flows into two trusting readers — your logs and the model's context —
so the message can forge a new log line, inject terminal/ANSI control sequences,
or impersonate a 'system' instruction (a cousin of indirect prompt injection).
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("17 output-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("event-logger", instructions="Record events.", log_level="WARNING")


@mcp.tool()
def record_event(message: str) -> str:
    """Record an event and return a confirmation line."""
    # VULNERABLE: untrusted text is echoed verbatim. A newline forges a new line;
    # control chars survive; "system"-looking text reaches the model as instructions.
    return f"[INFO] event recorded: {message}"


if __name__ == "__main__":
    mcp.run()
