"""Hardened twin of attacks/25 (XXE).

Same `parse_profile` tool, but it parses with `guardrails.safexml.safe_parse_xml`,
which refuses any document carrying a DOCTYPE/ENTITY declaration before parsing and
then uses the stdlib parser (which does not expand external entities). The XXE
payload is rejected; ordinary profiles parse normally.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails.safexml import XMLSecurityError, safe_parse_xml

mcp = FastMCP("profile-parser-hardened", instructions="Parse profile XML (XXE-safe).", log_level="WARNING")


@mcp.tool()
def parse_profile(xml_text: str) -> str:
    """Parse a <profile> document, refusing any DTD/entity declarations."""
    try:
        root = safe_parse_xml(xml_text)
    except XMLSecurityError as exc:
        return str(exc)
    return "".join(root.itertext()).strip()


if __name__ == "__main__":
    mcp.run()
