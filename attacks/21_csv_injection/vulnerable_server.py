"""21 - CSV / formula injection. VULNERABLE. Lab only.

An 'export to CSV' tool that writes caller-supplied values straight into cells. A
value starting with = + - @ is a *formula* to Excel / Google Sheets, so opening
the export can run =HYPERLINK(...) to exfiltrate other cells, or the legacy
=cmd|'/c …'!A1 to launch a process. The data file becomes code.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("21 csv-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("csv-exporter", instructions="Export rows to CSV.", log_level="WARNING")


@mcp.tool()
def export_row(name: str, note: str = "") -> str:
    """Export a contact as a CSV document (header + one row)."""
    # VULNERABLE: values are written verbatim; a leading = makes the cell a formula.
    return f"name,note\n{name},{note}"


if __name__ == "__main__":
    mcp.run()
