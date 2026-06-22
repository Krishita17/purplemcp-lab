"""25 - XML External Entity (XXE). VULNERABLE. Lab only.

A 'profile-parser' tool parses user-supplied XML with a SAX parser that has external
general entities ENABLED. That lets a document define
``<!ENTITY xxe SYSTEM "file:///etc/hosts">`` and expand ``&xxe;`` into the contents
of a local file — classic XXE (it can also reach internal URLs, i.e. SSRF).
"""

import io
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("25 xxe vulnerable server")

import xml.sax  # noqa: E402
from xml.sax.handler import feature_external_ges  # noqa: E402

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("profile-parser", instructions="Parse user profile XML.", log_level="WARNING")


class _Collector(xml.sax.ContentHandler):
    def __init__(self) -> None:
        self.text: list[str] = []

    def characters(self, content: str) -> None:  # noqa: D401
        self.text.append(content)


@mcp.tool()
def parse_profile(xml_text: str) -> str:
    """Parse a <profile> XML document and return its text content."""
    # VULNERABLE: external general entities are enabled, so a SYSTEM entity will be
    # resolved — reading local files or internal URLs. This is the insecure SAX setup.
    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, True)
    handler = _Collector()
    parser.setContentHandler(handler)
    parser.parse(io.BytesIO(xml_text.encode("utf-8")))
    return "".join(handler.text).strip()


if __name__ == "__main__":
    mcp.run()
