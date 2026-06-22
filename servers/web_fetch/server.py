"""Web-fetch MCP server — SSRF-safe HTTP GET (clean reference).

Uses ``purplemcp.guardrails.safe_get``, which rejects non-public hosts (cloud
metadata, localhost, RFC-1918), refuses non-http(s) schemes, and won't follow
redirects. Compare with attacks/05_ssrf to see the unprotected version.

Run directly:  python servers/web_fetch/server.py
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import safe_get

mcp = FastMCP(
    "web_fetch",
    instructions="Fetch text from public http(s) URLs only. SSRF-protected.",
    log_level="WARNING",
)


@mcp.tool()
def fetch_url(url: str, max_chars: int = 5000) -> str:
    """Fetch a public http(s) URL and return its text body.

    Internal/loopback/link-local addresses are rejected. Redirects are not
    followed. The response is size-capped.
    """
    body = safe_get(url, timeout=5.0, max_bytes=1_000_000)
    return body[:max_chars]


if __name__ == "__main__":
    mcp.run()
