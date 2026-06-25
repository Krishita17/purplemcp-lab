"""Hardened twin of attacks/28 (CRLF / HTTP header injection).

Same `set_cookie` tool, but the value is checked by
`guardrails.headers.safe_header_value`, which refuses any CR/LF or control character.
A newline-laden value is rejected, so it can never split the response into extra
headers.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails.headers import HeaderInjectionError, safe_header_value

mcp = FastMCP("http-headers-hardened", instructions="Build response headers (CRLF-safe).", log_level="WARNING")


@mcp.tool()
def set_cookie(name: str, value: str) -> str:
    """Build a Set-Cookie header only if the value is a safe single line."""
    try:
        safe = safe_header_value(value)
    except HeaderInjectionError as exc:
        return str(exc)
    return f"Set-Cookie: {name}={safe}"


if __name__ == "__main__":
    mcp.run()
