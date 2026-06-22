"""11 - Template / format-string injection. VULNERABLE. Lab only.

A 'render a greeting' tool that calls ``str.format`` with a **caller-controlled
template**. Python's format mini-language can walk attributes, so a template like
``{app.__init__.__globals__[SECRET_TOKEN]}`` reaches the module's globals and
leaks the secret — no f-string, no eval, just ``.format``. (The same idea is how
Jinja SSTI escalates to RCE.)

The token here is FAKE. Never put a real secret in lab code.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("11 template-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

# A FAKE secret that lives in this module's globals.
SECRET_TOKEN = "TMPL-SECRET-4417-DO-NOT-USE"


class AppInfo:
    """Innocuous object passed into the template — yet it leaks everything."""

    def __init__(self) -> None:
        self.name = "PurpleNotes"
        self.version = "1.0"


APP = AppInfo()

mcp = FastMCP("greeter", instructions="Render a greeting from a template.", log_level="WARNING")


@mcp.tool()
def render_welcome(template: str, username: str) -> str:
    """Render a welcome message. Use {user} and {app.name} in the template."""
    # VULNERABLE: the caller controls the format string, and the context exposes a
    # live object — so `{app.__init__.__globals__[...]}` can reach module globals.
    try:
        return template.format(app=APP, user=username)
    except Exception as exc:  # noqa: BLE001 - surface bad templates as text
        return f"template error: {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    mcp.run()
