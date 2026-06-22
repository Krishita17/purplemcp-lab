"""Safe SQL building — the fix for **SQL injection**.

The real fix is **parameterized queries**: pass values as ``?``/``%s`` bind
parameters so they can never change the query's structure. Never build SQL by
string-formatting user input (``f"... WHERE x = '{value}'"``).

Bind parameters can't be used for *identifiers* (table/column/order-by names),
though — those are part of the SQL text. When an identifier must be dynamic,
:func:`safe_identifier` confines it to an explicit allowlist. :func:`like_escape`
neutralizes the ``%`` / ``_`` wildcards in user input used inside a ``LIKE``.
"""

from __future__ import annotations

import re

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SQLIdentifierError(ValueError):
    """Raised when a dynamic SQL identifier is not allowlisted/valid."""


def safe_identifier(name: str, allowed: set[str]) -> str:
    """Return ``name`` only if it is a plain identifier in ``allowed``.

    Use for the parts of a query that *can't* be bound — e.g. a column to sort by:

        col = safe_identifier(user_col, allowed={"id", "title", "created"})
        cur.execute(f"SELECT * FROM notes ORDER BY {col}")  # col is now trusted
    """
    if name in allowed and _IDENT_RE.match(name):
        return name
    raise SQLIdentifierError(
        f"identifier {name!r} is not in the allowlist {sorted(allowed)}"
    )


def like_escape(value: str, escape: str = "\\") -> str:
    """Escape ``%`` and ``_`` so user text is matched literally inside a LIKE.

    Pair with ``... LIKE ? ESCAPE '\\'`` and bind ``f"%{like_escape(value)}%"``.
    """
    return (
        value.replace(escape, escape + escape)
        .replace("%", escape + "%")
        .replace("_", escape + "_")
    )
