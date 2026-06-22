"""Hardened twin of attacks/05 (SSRF).

Same `fetch` tool, but `guardrails.safe_get` allows only http(s), rejects
private/loopback/link-local hosts, and never follows redirects.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import SSRFError, safe_get

mcp = FastMCP("fetcher-hardened", instructions="Fetch public URLs only.", log_level="WARNING")


@mcp.tool()
def fetch(url: str, max_chars: int = 2000) -> str:
    """Fetch a public http(s) URL and return its body."""
    try:
        return safe_get(url, timeout=5)[:max_chars]
    except SSRFError as exc:
        return f"refused: {exc}"


if __name__ == "__main__":
    mcp.run()
