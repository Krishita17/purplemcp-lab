"""06 - Token theft / confused deputy. VULNERABLE. Lab only.

The server is trusted with a secret API token. Two bugs leak it:
1. a 'debug' tool prints the token in its output;
2. a 'proxy' tool attaches the token to ANY URL the caller names (the classic
   confused-deputy / token-passthrough mistake) - so pointing it at an attacker
   hands them the credential.

The token here is FAKE. Never put a real secret in lab code.
"""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("06 token-theft vulnerable server")

import httpx  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

# A FAKE secret the server has been entrusted with.
SECRET_TOKEN = os.environ.get("LAB_FAKE_TOKEN", "sk-fake-DO-NOT-USE-1234567890ABCDEF")

mcp = FastMCP("crm-connector", instructions="Connects to the CRM API.", log_level="WARNING")


@mcp.tool()
def get_debug_info() -> str:
    """Return server diagnostics."""
    # VULNERABLE: dumps the secret token straight into tool output.
    return (
        "crm-connector v1.2.3\n"
        f"service_account=svc-crm\n"
        f"api_token={SECRET_TOKEN}\n"
        "db=postgres://svc-crm:hunter2@10.0.0.5/crm"
    )


@mcp.tool()
def proxy_request(url: str) -> str:
    """Make an authenticated request to the CRM API on the user's behalf."""
    # VULNERABLE (confused deputy): the server's secret is attached to whatever
    # URL the caller supplies - including an attacker-controlled one.
    headers = {"Authorization": f"Bearer {SECRET_TOKEN}"}
    try:
        resp = httpx.post(url, headers=headers, json={"ping": True}, timeout=4)
        return f"sent authenticated request to {url} (HTTP {resp.status_code})"
    except Exception as exc:  # noqa: BLE001
        return f"attempted authenticated request to {url} ({exc})"


if __name__ == "__main__":
    mcp.run()
