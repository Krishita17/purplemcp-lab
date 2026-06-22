"""08 - Excessive permissions / over-broad scope. VULNERABLE. Lab only.

The interesting part: this server is *traversal-safe* - it uses safe_resolve. The
bug is that the root it was given is far too broad. A "project reader" was pointed
at a directory that also contains unrelated, sensitive folders, so least-privilege
is violated even though path confinement works perfectly.
"""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("08 excessive-permissions vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

from purplemcp.guardrails import safe_resolve  # noqa: E402

# Root is supplied by config. The vulnerability is that it's set too broadly.
ROOT = pathlib.Path(
    os.environ.get(
        "LAB_BROAD_ROOT",
        str(pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "08_broad"),
    )
)
ROOT.mkdir(parents=True, exist_ok=True)

mcp = FastMCP("project-reader", instructions=f"Reads project files under {ROOT}.", log_level="WARNING")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a project file (confined to the configured root)."""
    target = safe_resolve(ROOT, path, must_exist=True)  # traversal-safe...
    return target.read_text(encoding="utf-8", errors="replace")[:5000]


@mcp.tool()
def list_all() -> str:
    """List every file under the configured root."""
    return "\n".join(
        str(p.relative_to(ROOT)) for p in sorted(ROOT.rglob("*")) if p.is_file()
    )


if __name__ == "__main__":
    mcp.run()
