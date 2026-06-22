"""18 - Eval / expression injection. VULNERABLE. Lab only.

A 'calculator' tool that evaluates the expression with eval(). eval() is not a
math engine — it runs arbitrary Python, so a caller can read globals, import os,
and spawn a shell. This is one of the most common footguns in LLM "calculator"
and "formula" tools.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("18 eval-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("calculator", instructions="Evaluate math expressions.", log_level="WARNING")


@mcp.tool()
def calculate(expr: str) -> str:
    """Evaluate a math expression and return the result."""
    # VULNERABLE: eval runs arbitrary Python, not just arithmetic.
    return str(eval(expr))  # noqa: S307 - the whole point of the lab


if __name__ == "__main__":
    mcp.run()
