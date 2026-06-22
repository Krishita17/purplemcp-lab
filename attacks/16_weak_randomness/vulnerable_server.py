"""16 - Weak randomness / predictable tokens. VULNERABLE. Lab only.

A password-reset tool that mints its 'secure' token as md5(user:current_second).
The recipe is guessable and the only entropy is the clock, so anyone who knows the
user and the rough time can regenerate the exact token offline and take over the
reset.
"""

import hashlib
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("16 weak-randomness vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("auth-helper", instructions="Issue password-reset tokens.", log_level="WARNING")


def _weak_token(user: str, epoch: int) -> str:
    # VULNERABLE: md5 over (user, current second) — no real entropy, fully forgeable.
    return hashlib.md5(f"{user}:{epoch}".encode()).hexdigest()[:16]


@mcp.tool()
def issue_reset_token(user: str) -> str:
    """Issue a password-reset token for a user."""
    return f"reset token for {user}: {_weak_token(user, int(time.time()))}"


if __name__ == "__main__":
    mcp.run()
