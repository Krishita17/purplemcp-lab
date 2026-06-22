"""Hardened twin of attacks/19 (zip slip).

Same `unpack` tool, but every archive member is resolved against the extraction
root with `guardrails.safe_resolve` before anything is written. A member that
escapes (``..``, absolute path, symlink) is refused instead of extracted.
"""

import base64
import binascii
import io
import pathlib
import zipfile

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import PathTraversalError, safe_resolve

OUT = pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "19_unpack"
OUT.mkdir(parents=True, exist_ok=True)

mcp = FastMCP("archive-unpacker-hardened", instructions=f"Unpack archives into {OUT}.", log_level="WARNING")


@mcp.tool()
def unpack(zip_b64: str) -> str:
    """Unpack a base64-encoded zip, confining every member to the unpack folder."""
    try:
        raw = base64.b64decode(zip_b64)
    except (binascii.Error, ValueError) as exc:
        return f"bad base64: {exc}"
    written: list[str] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for member in zf.namelist():
            try:
                target = safe_resolve(OUT, member, must_exist=False)
            except PathTraversalError as exc:
                return f"refused: archive entry {member!r} escapes the unpack dir ({exc})"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(member))
            written.append(str(target))
    return "unpacked:\n" + "\n".join(written)


if __name__ == "__main__":
    mcp.run()
