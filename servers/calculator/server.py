"""Calculator MCP server — a clean, safe reference server.

Teaching points:
- Tools are plain typed functions; FastMCP derives the JSON schema from the
  type hints and the docstring becomes the tool description.
- There is **no `eval`**. A "calculator" that evals strings is the classic way
  to turn a helpful tool into remote code execution. We expose explicit
  operations instead. (See attacks/03_command_injection for why eval is unsafe.)

Run directly:  python servers/calculator/server.py
"""

from __future__ import annotations

import math

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "calculator",
    instructions="Safe arithmetic and math helpers. No expression evaluation.",
    log_level="WARNING",
)


@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers and return the sum."""
    return a + b


@mcp.tool()
def subtract(a: float, b: float) -> float:
    """Subtract b from a."""
    return a - b


@mcp.tool()
def multiply(a: float, b: float) -> float:
    """Multiply two numbers."""
    return a * b


@mcp.tool()
def divide(a: float, b: float) -> float:
    """Divide a by b. Errors if b is zero."""
    if b == 0:
        raise ValueError("division by zero")
    return a / b


@mcp.tool()
def power(base: float, exponent: float) -> float:
    """Raise base to the given exponent."""
    return math.pow(base, exponent)


@mcp.tool()
def sqrt(x: float) -> float:
    """Square root of a non-negative number."""
    if x < 0:
        raise ValueError("cannot take sqrt of a negative number")
    return math.sqrt(x)


@mcp.tool()
def percent_of(percent: float, value: float) -> float:
    """Return `percent` percent of `value` (e.g. percent_of(19, 4200) -> 798)."""
    return percent / 100.0 * value


@mcp.tool()
def factorial(n: int) -> int:
    """Factorial of a non-negative integer n (n!). Capped at n <= 1000."""
    if n < 0:
        raise ValueError("factorial is undefined for negative numbers")
    if n > 1000:
        raise ValueError("n too large (max 1000) — keeps output bounded")
    return math.factorial(n)


@mcp.tool()
def logarithm(value: float, base: float = 10.0) -> float:
    """Logarithm of a positive value in the given base (default base 10)."""
    if value <= 0:
        raise ValueError("logarithm is defined for positive numbers only")
    if base <= 0 or base == 1:
        raise ValueError("base must be positive and not equal to 1")
    return math.log(value, base)


@mcp.tool()
def mean(numbers: list[float]) -> float:
    """Arithmetic mean (average) of a non-empty list of numbers."""
    if not numbers:
        raise ValueError("cannot take the mean of an empty list")
    return sum(numbers) / len(numbers)


if __name__ == "__main__":
    mcp.run()
