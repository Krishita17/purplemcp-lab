"""Hardened twin of attacks/04 (path traversal).

Same `read_doc` tool, but every path goes through `guardrails.safe_resolve`,
which confines it to the docs root (rejecting `..`, absolute paths, and symlinks
that escape).
"""

import pathlib

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import PathTraversalError, safe_resolve

# Same root the vulnerable twin uses, so you can compare on identical data.
ROOT = pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "04_docs"
ROOT.mkdir(parents=True, exist_ok=True)
(ROOT / "welcome.txt").write_text("Welcome to the company docs.\n", encoding="utf-8")

mcp = FastMCP("doc-reader-hardened", instructions=f"Reads docs from {ROOT}.", log_level="WARNING")


@mcp.tool()
def read_doc(path: str) -> str:
    """Read a document by (relative) path, confined to the docs root."""
    try:
        target = safe_resolve(ROOT, path, must_exist=True)
    except (PathTraversalError, FileNotFoundError) as exc:
        return f"refused: {exc}"
    return target.read_text(encoding="utf-8", errors="replace")[:5000]


if __name__ == "__main__":
    mcp.run()
