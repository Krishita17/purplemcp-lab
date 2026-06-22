"""Hardened twin of attacks/06 (token theft / confused deputy).

Fixes both leaks:
- `get_debug_info` scrubs secrets out of its output;
- `proxy_request` only ever attaches the token to an allowlisted host, so it
  can't be tricked into delivering the credential to an attacker.
"""

import os
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import scrub

SECRET_TOKEN = os.environ.get("LAB_FAKE_TOKEN", "sk-fake-DO-NOT-USE-1234567890ABCDEF")
ALLOWED_HOSTS = {"api.crm.example.com"}

mcp = FastMCP("crm-connector-hardened", instructions="CRM API connector.", log_level="WARNING")


@mcp.tool()
def get_debug_info() -> str:
    """Return server diagnostics (secrets scrubbed)."""
    info = (
        "crm-connector v1.2.3\n"
        "service_account=svc-crm\n"
        f"api_token={SECRET_TOKEN}\n"
        "db=postgres://svc-crm:hunter2@10.0.0.5/crm"
    )
    return scrub(info)  # defense in depth: never emit raw secrets


@mcp.tool()
def proxy_request(url: str) -> str:
    """Make an authenticated request to the CRM API (allowlisted hosts only)."""
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        return f"refused: host {host!r} is not in the CRM allowlist {sorted(ALLOWED_HOSTS)}"
    # Only here, against a trusted host, would we attach the token.
    return f"authorized request to {url} (host allowlisted; token attached only here)"


if __name__ == "__main__":
    mcp.run()
