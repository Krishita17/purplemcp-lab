"""19 - Zip slip / archive extraction traversal. VULNERABLE. Lab only.

An 'unpack' tool that extracts a caller-supplied zip, trusting the archive's
member names. A member named '../escape.txt' (or an absolute path) is written
OUTSIDE the extraction directory — the archive equivalent of path traversal, used
to overwrite config/startup files for persistence.

The exploit only ever writes inside the repo's sandbox.
"""

import base64
import binascii
import io
import pathlib
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("19 zip-slip vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parents[2] / "sandbox" / "lab" / "19_unpack"
OUT.mkdir(parents=True, exist_ok=True)

mcp = FastMCP("archive-unpacker", instructions=f"Unpack archives into {OUT}.", log_level="WARNING")


@mcp.tool()
def unpack(zip_b64: str) -> str:
    """Unpack a base64-encoded zip archive into the unpack folder."""
    try:
        raw = base64.b64decode(zip_b64)
    except (binascii.Error, ValueError) as exc:
        return f"bad base64: {exc}"
    written: list[str] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for member in zf.namelist():
            # VULNERABLE: the member name is trusted; '..' walks out of OUT.
            target = pathlib.Path(OUT) / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(member))
            written.append(str(target.resolve()))
    return "unpacked:\n" + "\n".join(written)


if __name__ == "__main__":
    mcp.run()
