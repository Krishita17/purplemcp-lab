"""Hardened twin of attacks/13 (insecure deserialization).

Same `load_session` tool and same base64 envelope, but the payload is decoded as
**JSON** via `guardrails.safe_loads` — which refuses pickle streams outright and
validates the top-level shape. JSON can carry data but never call code, so there
is no `__reduce__` to abuse.
"""

import base64
import binascii

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import UnsafeDeserialization, safe_loads

mcp = FastMCP("session-store-hardened", instructions="Save/restore session state.", log_level="WARNING")


@mcp.tool()
def load_session(blob: str) -> str:
    """Restore session state from a base64-encoded JSON blob."""
    try:
        raw = base64.b64decode(blob)
    except (binascii.Error, ValueError) as exc:
        return f"refused: bad base64: {exc}"
    try:
        data = safe_loads(raw, require=dict)
    except UnsafeDeserialization as exc:
        return f"refused: {exc}"
    return f"session restored: {data!r}"


if __name__ == "__main__":
    mcp.run()
