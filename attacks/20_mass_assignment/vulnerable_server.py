"""20 - Mass assignment / privilege escalation. VULNERABLE. Lab only.

An 'update profile' tool that applies whatever keys the caller sends straight onto
the user record — including privileged fields like role/is_admin that the UI never
exposes. So a normal user "edits their display name" and quietly grants themselves
admin. Classic mass assignment (a.k.a. autobinding / object injection).

All data here is FAKE.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("20 mass-assignment vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

USER = {
    "username": "mallory",
    "display_name": "Mallory",
    "email": "mallory@corp.test",
    "role": "user",
    "is_admin": False,
}

mcp = FastMCP("profile-service", instructions="Update your profile.", log_level="WARNING")


def _summary() -> str:
    return ", ".join(f"{k}={USER[k]}" for k in ("username", "display_name", "role", "is_admin"))


@mcp.tool()
def update_profile(updates: dict) -> str:
    """Update the current user's profile from a dict of fields."""
    # VULNERABLE: every supplied key is applied — including role / is_admin.
    USER.update(updates)
    return "profile now: " + _summary()


if __name__ == "__main__":
    mcp.run()
