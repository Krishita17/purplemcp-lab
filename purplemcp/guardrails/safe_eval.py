"""Safe arithmetic evaluation — the fix for **eval / expression injection**.

A "calculator" tool that does ``eval(user_expr)`` is not doing math — it is
running arbitrary Python. ``__import__('os').system('…')`` reads files, spawns
shells, exfiltrates secrets. (``ast.literal_eval`` is safer but still allows huge
literals and isn't meant for operators.)

The fix is to parse the expression with :mod:`ast` and walk the tree, allowing
**only** numeric literals and arithmetic operators — no names, calls, attributes,
subscripts, or comprehensions. There is simply no node that can reach code.
"""

from __future__ import annotations

import ast
import operator
from typing import Union

Number = Union[int, float]


class UnsafeExpression(ValueError):
    """Raised when an expression contains anything beyond plain arithmetic."""


_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval(node: ast.AST) -> Number:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(
        node.value, bool
    ):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        left, right = _eval(node.left), _eval(node.right)
        # Guard against resource-exhaustion via huge exponents (10**10**9).
        if isinstance(node.op, ast.Pow) and (abs(right) > 1000 or abs(left) > 10**8):
            raise UnsafeExpression("exponent operands too large")
        return _BIN_OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_eval(node.operand))
    # Deliberately does NOT echo the source, so a rejected payload can't smuggle
    # its proof string back through the error message.
    raise UnsafeExpression(f"disallowed expression element: {type(node).__name__}")


def safe_eval(expr: str) -> Number:
    """Evaluate a plain arithmetic expression (``+ - * / // % **`` on numbers).

    Raises :class:`UnsafeExpression` for anything else — names, calls, attribute
    access, subscripts, strings — i.e. everything an attacker would need.
    """
    if not isinstance(expr, str):
        raise UnsafeExpression("expression must be a string")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise UnsafeExpression(f"not a valid expression: {exc.msg}") from exc
    return _eval(tree.body)
