"""Hardened twin of attacks/21 (CSV / formula injection).

Same `export_row` tool, but every cell goes through `guardrails.escape_formula`,
which prefixes a single quote to any value a spreadsheet would treat as a formula
(leading = + - @). The export is data again, not code.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import escape_formula

mcp = FastMCP("csv-exporter-hardened", instructions="Export rows to CSV (safely).", log_level="WARNING")


@mcp.tool()
def export_row(name: str, note: str = "") -> str:
    """Export a contact as a CSV document, neutralizing formula-shaped cells."""
    return f"name,note\n{escape_formula(name)},{escape_formula(note)}"


if __name__ == "__main__":
    mcp.run()
