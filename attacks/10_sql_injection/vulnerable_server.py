"""10 - SQL injection. VULNERABLE. Lab only.

A notes search tool that builds its query by f-string interpolation. Because the
user's text becomes part of the SQL *structure* (not just a value), a crafted
query escapes the intended ``LIKE`` and reads rows it was never meant to — here,
an admin-only note holding a recovery code.

The token here is FAKE. Never put a real secret in lab code.
"""

import os
import pathlib
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("10 sql-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

DB_PATH = pathlib.Path(
    os.environ.get(
        "PURPLEMCP_SQLI_DB",
        str(pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "10_sqli_vuln.sqlite"),
    )
)

# A FAKE secret only the "admin" note holds — a normal search must never reveal it.
SEED = [
    ("Groceries", "milk, eggs, bread, coffee"),
    ("Standup notes", "discuss roadmap and the sprint backlog"),
    ("ADMIN ONLY - account recovery", "RECOVERY-CODE-7F3A2B91 (do not share)"),
]


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DROP TABLE IF EXISTS notes")
        conn.execute(
            "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " title TEXT NOT NULL, body TEXT NOT NULL)"
        )
        conn.executemany("INSERT INTO notes (title, body) VALUES (?, ?)", SEED)


_init_db()
mcp = FastMCP("notes-search", instructions="Search your notes.", log_level="WARNING")


@mcp.tool()
def search_notes(query: str) -> str:
    """Search note bodies for text."""
    # VULNERABLE: the query text is interpolated straight into the SQL string, so
    # it can break out of the LIKE and change what the statement returns.
    sql = f"SELECT id, title, body FROM notes WHERE body LIKE '%{query}%'"
    with sqlite3.connect(DB_PATH) as conn:
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.Error as exc:
            return f"SQL error: {exc}\n(statement was: {sql})"
    if not rows:
        return "(no matches)"
    return "\n".join(f"#{r[0]}  {r[1]}: {r[2]}" for r in rows)


if __name__ == "__main__":
    mcp.run()
