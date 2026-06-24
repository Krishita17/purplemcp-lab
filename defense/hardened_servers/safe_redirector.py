"""Hardened twin of attacks/27 (open redirect).

Same `build_redirect` tool, but the target is checked by
`guardrails.redirects.safe_redirect`, which requires an http(s) scheme and an
allowlisted host. Off-site targets are refused; on-site links pass through.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails.redirects import OpenRedirectError, safe_redirect

mcp = FastMCP("link-builder-hardened", instructions="Build redirect links (allowlisted).", log_level="WARNING")

_ALLOWED = {"app.example.com"}


@mcp.tool()
def build_redirect(target: str) -> str:
    """Build a redirect only if the target host is allowlisted."""
    try:
        url = safe_redirect(target, _ALLOWED)
    except OpenRedirectError as exc:
        return str(exc)
    return f"302 Location: {url}"


if __name__ == "__main__":
    mcp.run()
