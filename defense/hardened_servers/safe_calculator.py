"""Hardened twin of attacks/18 (eval injection).

Same `calculate` tool, but it evaluates with `guardrails.safe_eval`, which parses
the expression with ast and permits only numbers and arithmetic operators — no
names, calls, attributes or imports — so "math" can never become code.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import UnsafeExpression, safe_eval

mcp = FastMCP("calculator-hardened", instructions="Evaluate math (safely).", log_level="WARNING")


@mcp.tool()
def calculate(expr: str) -> str:
    """Evaluate an arithmetic expression (numbers and + - * / // % ** only)."""
    try:
        return str(safe_eval(expr))
    except UnsafeExpression as exc:
        return f"refused: {exc}"


if __name__ == "__main__":
    mcp.run()
