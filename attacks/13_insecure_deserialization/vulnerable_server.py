"""13 - Insecure deserialization. VULNERABLE. Lab only.

A 'restore session' tool that ``pickle.loads`` a caller-supplied blob. Pickle is
not a data format — it's a tiny VM that *runs code* during loading (via
``__reduce__``). So any attacker who can supply the blob gets code execution.

The exploit's proof payload is harmless (it just computes a string).
"""

import base64
import binascii
import pathlib
import pickle
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("13 insecure-deserialization vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("session-store", instructions="Save/restore session state.", log_level="WARNING")


@mcp.tool()
def load_session(blob: str) -> str:
    """Restore session state from a base64-encoded blob."""
    try:
        raw = base64.b64decode(blob)
    except (binascii.Error, ValueError) as exc:
        return f"bad base64: {exc}"
    # VULNERABLE: pickle.loads executes the object's __reduce__ during loading.
    data = pickle.loads(raw)
    return f"session restored: {data!r}"


if __name__ == "__main__":
    mcp.run()
