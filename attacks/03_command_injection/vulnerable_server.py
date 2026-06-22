"""03 - Command injection. VULNERABLE. Lab only.

The classic mistake: building a shell command string from user input and running
it with shell=True. The shell happily interprets ; | $() and friends.
"""

import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("03 command-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("net-tools", instructions="Network diagnostics.", log_level="WARNING")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host once and return the output."""
    # VULNERABLE: user input is interpolated into a shell command.
    proc = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=8,
    )
    return (proc.stdout + proc.stderr).strip()


if __name__ == "__main__":
    mcp.run()
