"""28 - CRLF / HTTP header injection. VULNERABLE. Lab only.

A tool builds a ``Set-Cookie`` response header from caller input. Because the value
is placed into the header verbatim, a CR/LF in the value ends the header and starts a
new one the attacker controls (HTTP response splitting, CWE-113).
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("28 header-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("http-headers", instructions="Build HTTP response headers.", log_level="WARNING")


@mcp.tool()
def set_cookie(name: str, value: str) -> str:
    """Build a Set-Cookie response header for the given name/value."""
    # VULNERABLE: the value is placed into the header verbatim, so a CR/LF splits the
    # response and injects an attacker-controlled header.
    return f"Set-Cookie: {name}={value}"


if __name__ == "__main__":
    mcp.run()
