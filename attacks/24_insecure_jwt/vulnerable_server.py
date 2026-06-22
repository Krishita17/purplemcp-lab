"""24 - Insecure JWT verification (alg:none / unsigned). VULNERABLE. Lab only.

An 'account-api' tool reads the caller's session JWT to decide what to return. It
decodes the payload WITHOUT verifying the signature and trusts whatever ``role`` the
token claims. That means anyone can forge ``{"role":"admin"}`` with ``alg:none`` and
an empty signature — there is no check that would ever catch it.
"""

import base64
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("24 insecure-jwt vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("account-api", instructions="Look up account info from a session token.", log_level="WARNING")

# A planted admin-only secret the API hands to anyone it believes is an admin.
_ADMIN_SECRET = "JWT-ADMIN-SECRET-9921"


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


@mcp.tool()
def whoami(token: str) -> str:
    """Return the caller's account info, based on their session JWT."""
    # VULNERABLE: decodes the payload without verifying the signature, and trusts
    # the token's self-declared role. alg:none + no signature sails right through.
    payload = json.loads(_b64url_decode(token.split(".")[1]))
    user = payload.get("user", "anonymous")
    if payload.get("role") == "admin":
        return f"user={user} role=admin secret={_ADMIN_SECRET}"
    return f"user={user} role={payload.get('role', 'guest')}"


if __name__ == "__main__":
    mcp.run()
