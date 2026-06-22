"""15 - Unrestricted file write. VULNERABLE. Lab only.

A 'save a note' tool that joins the user's path onto the notes root with no
confinement. A `..` (or an absolute path) escapes the root, so the tool can write
anywhere the process can — overwriting config/startup files for persistence, or
dropping a script somewhere it'll be executed. This is path traversal's more
dangerous write-side twin.

The exploit only ever writes inside the repo's sandbox, never your real files.
"""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("15 unrestricted-file-write vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "15_notes"
ROOT.mkdir(parents=True, exist_ok=True)

mcp = FastMCP("note-writer", instructions=f"Save notes under {ROOT}.", log_level="WARNING")


@mcp.tool()
def save_note(path: str, content: str) -> str:
    """Save a note at the given (relative) path under the notes folder."""
    # VULNERABLE: os.path.join trusts `path`; '..' walks out, an absolute path
    # ignores ROOT entirely. No confinement at all.
    full = pathlib.Path(os.path.join(str(ROOT), path))
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} bytes to {full.resolve()}"


if __name__ == "__main__":
    mcp.run()
