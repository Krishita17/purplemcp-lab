"""Hardened twin of attacks/23 (argument / flag injection).

Same `lookup` tool, same helper program — but the argv is built with
`guardrails.safe_argv`, which passes the caller's value through *whole* (never
split) and inserts a `--` end-of-options separator. A value like `alice --debug`
is now a single positional operand, so the program can't read `--debug` as a flag.
"""

import subprocess
import sys

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import safe_argv

mcp = FastMCP("directory-hardened", instructions="Look up user records (safely).", log_level="WARNING")

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
    """Look up a user record by name, with user input confined to operands."""
    argv = safe_argv([sys.executable, "-c", _HELPER], [user])
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    return (proc.stdout + proc.stderr).strip()


if __name__ == "__main__":
    mcp.run()
