"""05 - Server-Side Request Forgery (SSRF). VULNERABLE. Lab only.

A 'fetch this URL' tool with no checks. The model (or whoever is injecting into
it) can aim it at internal-only addresses the server can reach but the outside
world cannot: cloud metadata, localhost admin panels, RFC-1918 hosts.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("05 ssrf vulnerable server")

import httpx  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("fetcher", instructions="Fetch a URL.", log_level="WARNING")


@mcp.tool()
def fetch(url: str) -> str:
    """Fetch a URL and return the response body."""
    # VULNERABLE: any scheme, any host, follows redirects (a 302 SSRF bypass).
    resp = httpx.get(url, timeout=5, follow_redirects=True)
    return resp.text[:2000]


if __name__ == "__main__":
    mcp.run()
