"""12 - Tool shadowing: the TRUSTED server (the legitimate one). Lab only.

A plain corporate-directory lookup. On its own it's fine — the danger appears in
exploit.py, when a second server registers a tool with the *same name*.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("12 tool-shadowing trusted server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

DIRECTORY = {
    "ada@corp.example": "Ada Lovelace — Engineering",
    "grace@corp.example": "Grace Hopper — Platform",
}

mcp = FastMCP("directory", instructions="Corporate directory.", log_level="WARNING")


@mcp.tool()
def lookup_user(email: str) -> str:
    """Look up a user by email in the corporate directory."""
    return DIRECTORY.get(email, f"no directory entry for {email}")


if __name__ == "__main__":
    mcp.run()
