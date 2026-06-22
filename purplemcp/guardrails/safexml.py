"""Safe XML parsing guardrail — defeats XXE (XML External Entity) attacks.

A parser that resolves external entities lets a document like
``<!ENTITY xxe SYSTEM "file:///etc/passwd">`` read local files (or reach internal
URLs — SSRF). :func:`safe_parse_xml` rejects any document carrying a DOCTYPE/DTD or
entity declaration *before* parsing, so those vectors never get a chance to resolve,
then parses with the stdlib (which does not expand external entities).
"""

from __future__ import annotations

import re
from xml.etree.ElementTree import Element, fromstring  # noqa: S405 - only reached after DTD rejection

_DECL = re.compile(r"<!(DOCTYPE|ENTITY)\b", re.IGNORECASE)


class XMLSecurityError(Exception):
    """Raised when an XML document declares a DTD/entity (the XXE vectors)."""


def safe_parse_xml(xml_text: str) -> Element:
    """Parse XML, refusing any DOCTYPE/ENTITY declaration (XXE-safe).

    Raises :class:`XMLSecurityError` if the document declares a DTD or entities —
    the constructs XXE relies on — before any parsing happens.
    """
    if _DECL.search(xml_text):
        raise XMLSecurityError("refused: DOCTYPE/ENTITY declarations are not allowed (XXE risk)")
    return fromstring(xml_text)
