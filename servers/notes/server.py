"""Notes MCP server — SQLite-backed personal notes (clean reference).

Teaching point: every query is **parameterized** (``?`` placeholders), so user
input can never alter SQL structure. A "search" tool that does
``f"... WHERE body LIKE '%{query}%'"`` is the classic SQL-injection footgun;
we never build SQL from strings.

DB path comes from ``PURPLEMCP_NOTES_DB`` (defaults to ./sandbox/notes.sqlite).
Run directly:  python servers/notes/server.py
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from mcp.server.fastmcp import FastMCP

DB_PATH = Path(os.environ.get("PURPLEMCP_NOTES_DB", "./sandbox/notes.sqlite"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

mcp = FastMCP(
    "notes",
    instructions="Store and search personal notes. Parameterized queries only.",
    log_level="WARNING",
)


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notes ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " title TEXT NOT NULL,"
        " body TEXT NOT NULL,"
        " created TEXT DEFAULT CURRENT_TIMESTAMP)"
    )
    return conn


@mcp.tool()
def add_note(title: str, body: str) -> str:
    """Add a note and return its id."""
    with _conn() as conn:
        cur = conn.execute(
            "INSERT INTO notes (title, body) VALUES (?, ?)", (title, body)
        )
        return f"added note #{cur.lastrowid}"


@mcp.tool()
def list_notes() -> str:
    """List all notes (id, title, created time)."""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, title, created FROM notes ORDER BY id"
        ).fetchall()
    if not rows:
        return "(no notes yet)"
    return "\n".join(f"#{r[0]}  {r[1]}  ({r[2]})" for r in rows)


@mcp.tool()
def get_note(note_id: int) -> str:
    """Fetch one note's full contents by id."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT id, title, body, created FROM notes WHERE id = ?", (note_id,)
        ).fetchone()
    if not row:
        raise ValueError(f"no note #{note_id}")
    return f"#{row[0]}  {row[1]}  ({row[3]})\n\n{row[2]}"


@mcp.tool()
def search_notes(query: str) -> str:
    """Search titles and bodies (parameterized LIKE — safe against injection)."""
    like = f"%{query}%"
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, title FROM notes WHERE title LIKE ? OR body LIKE ? ORDER BY id",
            (like, like),
        ).fetchall()
    if not rows:
        return "(no matches)"
    return "\n".join(f"#{r[0]}  {r[1]}" for r in rows)


@mcp.tool()
def delete_note(note_id: int) -> str:
    """Delete a note by id."""
    with _conn() as conn:
        cur = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    return f"deleted {cur.rowcount} note(s)"


if __name__ == "__main__":
    mcp.run()
