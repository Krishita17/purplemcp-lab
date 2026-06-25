"""HTTP header-value guardrail — defeats CRLF / response-splitting injection.

A tool that builds a header (``Set-Cookie``, ``Location``, …) from caller input is a
header injection (CWE-113) if the value can carry a CR or LF: the newline ends the
current header and starts a new one the attacker controls. :func:`safe_header_value`
refuses any CR/LF or other C0 control character before the value reaches a header.
"""

from __future__ import annotations


class HeaderInjectionError(Exception):
    """Raised when a header value contains CR/LF or control characters."""


def safe_header_value(value: str) -> str:
    """Return ``value`` if it is a safe single-line header value; else raise.

    Refuses every C0 control character (including CR ``\\r``, LF ``\\n`` and NUL) —
    the characters used to split a response into extra attacker-controlled headers.
    """
    if any(ord(c) < 0x20 for c in value):
        raise HeaderInjectionError("refused: CR/LF or control characters are not allowed in a header value")
    return value
