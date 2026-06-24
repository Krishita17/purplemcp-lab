"""27 - Open redirect. VULNERABLE. Lab only.

A link-builder tool turns a caller-supplied destination into an HTTP redirect without
checking the host. That is an open redirect (CWE-601): an attacker hands a victim a
link that looks like it belongs to your app but bounces them to a phishing site.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("27 open-redirect vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("link-builder", instructions="Build outbound redirect links.", log_level="WARNING")


@mcp.tool()
def build_redirect(target: str) -> str:
    """Build a redirect response that sends the user to `target`."""
    # VULNERABLE: trusts any target host, so it will happily redirect off-site.
    return f"302 Location: {target}"


if __name__ == "__main__":
    mcp.run()
