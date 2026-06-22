"""04 - Path traversal. VULNERABLE. Lab only.

A document reader that trusts the path it's given. ``os.path.join`` with a
relative path containing ``..`` walks out of the docs root; with an absolute
path it ignores the root entirely.
"""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("04 path-traversal vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

# The "intended" docs root, created with one sample file.
ROOT = pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "04_docs"
ROOT.mkdir(parents=True, exist_ok=True)
(ROOT / "welcome.txt").write_text("Welcome to the company docs.\n", encoding="utf-8")

mcp = FastMCP("doc-reader", instructions=f"Reads docs from {ROOT}.", log_level="WARNING")


@mcp.tool()
def read_doc(path: str) -> str:
    """Read a document by (relative) path."""
    # VULNERABLE: no confinement. `..` escapes; an absolute path ignores ROOT.
    full = os.path.join(str(ROOT), path)
    with open(full, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()[:5000]


if __name__ == "__main__":
    mcp.run()
