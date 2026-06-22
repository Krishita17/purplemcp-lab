"""Hardened twin of attacks/16 (weak randomness).

Same `issue_reset_token` tool, but the token comes from `guardrails.new_token`,
which uses the OS CSPRNG (`secrets.token_urlsafe`, 256 bits). There's no recipe to
reproduce and no clock dependence to replay, so it can't be forged.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import new_token

mcp = FastMCP("auth-helper-hardened", instructions="Issue password-reset tokens.", log_level="WARNING")


@mcp.tool()
def issue_reset_token(user: str) -> str:
    """Issue a cryptographically-random password-reset token for a user."""
    return f"reset token for {user}: {new_token()}"


if __name__ == "__main__":
    mcp.run()
