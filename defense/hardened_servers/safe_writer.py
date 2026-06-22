"""Hardened twin of attacks/15 (unrestricted file write).

Same `save_note` tool, but every write path goes through `guardrails.safe_resolve`
(the same primitive that fixes read-side path traversal, attack 04) with
`must_exist=False`. `..` and absolute paths are rejected, so writes are confined
to the notes root.
"""

import pathlib

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import PathTraversalError, safe_resolve

ROOT = pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "15_notes"
ROOT.mkdir(parents=True, exist_ok=True)

mcp = FastMCP("note-writer-hardened", instructions=f"Save notes under {ROOT}.", log_level="WARNING")


@mcp.tool()
def save_note(path: str, content: str) -> str:
    """Save a note at the given (relative) path, confined to the notes folder."""
    try:
        target = safe_resolve(ROOT, path)  # must_exist=False: the file is new
    except PathTraversalError as exc:
        return f"refused: {exc}"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} bytes to {target}"


if __name__ == "__main__":
    mcp.run()
