"""Hardened twin of attacks/20 (mass assignment).

Same `update_profile` tool, but it passes the update through
`guardrails.assert_assignable` with an explicit allowlist of editable fields.
Privileged, server-owned fields (role, is_admin) can't be set by the caller.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import AuthorizationError, assert_assignable

EDITABLE = {"display_name", "email", "bio"}

USER = {
    "username": "mallory",
    "display_name": "Mallory",
    "email": "mallory@corp.test",
    "role": "user",
    "is_admin": False,
}

mcp = FastMCP("profile-service-hardened", instructions="Update your profile (safely).", log_level="WARNING")


def _summary() -> str:
    return ", ".join(f"{k}={USER[k]}" for k in ("username", "display_name", "role", "is_admin"))


@mcp.tool()
def update_profile(updates: dict) -> str:
    """Update the current user's profile (only display_name / email / bio)."""
    try:
        assert_assignable(updates, EDITABLE)
    except AuthorizationError as exc:
        return f"refused: {exc}"
    USER.update(updates)
    return "profile now: " + _summary()


if __name__ == "__main__":
    mcp.run()
