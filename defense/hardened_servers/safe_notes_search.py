"""Hardened twin of attacks/10 (SQL injection).

Same `search_notes` tool and same seed data, but the query is a **bound
parameter** (`LIKE ?`), so the user's text is always a value and can never change
the statement's structure. `guardrails.like_escape` additionally neutralizes the
`%`/`_` wildcards so a search is matched literally.
"""

import os
import pathlib
import sqlite3

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import like_escape

DB_PATH = pathlib.Path(
    os.environ.get(
        "PURPLEMCP_SQLI_SAFE_DB",
        str(pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "10_sqli_safe.sqlite"),
    )
)

# Identical data to the vulnerable twin, so you compare on the same rows.
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
mcp = FastMCP("notes-search-hardened", instructions="Search your notes (safely).", log_level="WARNING")


@mcp.tool()
def search_notes(query: str) -> str:
    """Search note bodies for text (parameterized — injection-proof)."""
    like = f"%{like_escape(query)}%"
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, title, body FROM notes WHERE body LIKE ? ESCAPE '\\'", (like,)
        ).fetchall()
    if not rows:
        return "(no matches)"
    return "\n".join(f"#{r[0]}  {r[1]}: {r[2]}" for r in rows)


if __name__ == "__main__":
    mcp.run()
