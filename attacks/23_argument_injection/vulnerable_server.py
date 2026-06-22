"""23 - Argument / flag injection. VULNERABLE. Lab only.

This server never uses a shell (so it isn't *command* injection). It runs a fixed
program with `shell=False`. The bug is subtler: it **splits** the caller's string
into multiple argv elements, so a value like `--debug` is read by the program as an
*option*, not as data. Same binary, unintended behaviour — CWE-88 argument injection.
"""

import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("23 argument-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("directory", instructions="Look up user records.", log_level="WARNING")

# A tiny "user lookup" helper. A hidden --debug flag dumps an internal secret —
# exactly the kind of operator-only switch an attacker reaches via arg injection.
_HELPER = (
    "import argparse\n"
    "p = argparse.ArgumentParser(prog='userinfo')\n"
    "p.add_argument('name')\n"
    "p.add_argument('--debug', action='store_true')\n"
    "a = p.parse_args()\n"
    "if a.debug:\n"
    "    print('internal_api_key=ARGINJ-SECRET-5521')\n"
    "print('user record:', a.name)\n"
)


@mcp.tool()
def lookup(user: str) -> str:
    """Look up a user record by name."""
    # VULNERABLE: splitting the caller's value lets part of it become an option.
    argv = [sys.executable, "-c", _HELPER, *user.split()]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    return (proc.stdout + proc.stderr).strip()


if __name__ == "__main__":
    mcp.run()
