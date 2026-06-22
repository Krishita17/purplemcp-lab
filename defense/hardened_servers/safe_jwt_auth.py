"""Hardened twin of attacks/24 (insecure JWT verification).

Same `whoami` tool, but it runs the token through `guardrails.jwtsafe.verify_jwt`,
which requires HS256, rejects `alg:none`, and verifies the HMAC signature before any
claim is trusted. A forged/unsigned admin token is refused outright.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails.jwtsafe import JWTError, verify_jwt

mcp = FastMCP("account-api-hardened", instructions="Account info from a verified JWT.", log_level="WARNING")

_ADMIN_SECRET = "JWT-ADMIN-SECRET-9921"
SECRET = "server-side-signing-secret"


@mcp.tool()
def whoami(token: str) -> str:
    """Return account info, but only after verifying the JWT signature (HS256)."""
    try:
        claims = verify_jwt(token, SECRET)
    except JWTError as exc:
        return f"refused: {exc}"
    user = claims.get("user", "anonymous")
    if claims.get("role") == "admin":
        return f"user={user} role=admin secret={_ADMIN_SECRET}"
    return f"user={user} role={claims.get('role', 'guest')}"


if __name__ == "__main__":
    mcp.run()
