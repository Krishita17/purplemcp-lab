"""22 - Unbounded output / context flooding. VULNERABLE. Lab only.

A 'read logs' tool returns however many lines the caller asks for, with no cap. A
model coaxed into `dump_logs(lines=5_000_000)` floods the host's context window,
burns the token budget, and can wedge the session — denial-of-service by output.
This is OWASP-LLM LLM10: Unbounded Consumption.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("22 unbounded-output vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("log-reader", instructions="Read application logs.", log_level="WARNING")

# A sentinel that only survives if the WHOLE response is returned uncapped.
_EOF = "EOF-LOG-MARKER-7731"


def _render(lines: int) -> str:
    body = "\n".join(f"log line {i}: request handled (200 OK)" for i in range(lines))
    return f"{body}\n{_EOF}"


@mcp.tool()
def dump_logs(lines: int = 10) -> str:
    """Return the most recent N log lines."""
    # VULNERABLE: no ceiling — the caller dictates the response size.
    return _render(lines)


if __name__ == "__main__":
    mcp.run()
