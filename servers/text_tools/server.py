"""Text-tools MCP server — a clean, safe reference server (no key, no network).

A grab-bag of deterministic text/encoding helpers built on the Python standard
library. Every operation is real (hashlib, base64, urllib) — there is nothing
mocked here. It exists so the Tool Explorer and Chat Playground have a second,
non-math server to drive alongside the calculator.

Run directly:  python servers/text_tools/server.py
"""

from __future__ import annotations

import base64 as _b64
import hashlib
import unicodedata
import urllib.parse

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "text_tools",
    instructions="Hashing, encoding and text helpers. Pure stdlib, no network.",
    log_level="WARNING",
)


@mcp.tool()
def sha256(text: str) -> str:
    """Return the SHA-256 hex digest of the given text (UTF-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@mcp.tool()
def sha1(text: str) -> str:
    """Return the SHA-1 hex digest of the given text (UTF-8)."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


@mcp.tool()
def base64_encode(text: str) -> str:
    """Base64-encode UTF-8 text and return the ASCII result."""
    return _b64.b64encode(text.encode("utf-8")).decode("ascii")


@mcp.tool()
def base64_decode(data: str) -> str:
    """Decode a base64 string back to UTF-8 text. Errors on invalid input."""
    return _b64.b64decode(data.encode("ascii"), validate=True).decode("utf-8")


@mcp.tool()
def url_encode(text: str) -> str:
    """Percent-encode text for safe use in a URL query component."""
    return urllib.parse.quote(text, safe="")


@mcp.tool()
def word_count(text: str) -> dict:
    """Count characters, words and lines in the given text."""
    return {
        "characters": len(text),
        "words": len(text.split()),
        "lines": len(text.splitlines()) or (1 if text else 0),
    }


@mcp.tool()
def slugify(text: str) -> str:
    """Turn arbitrary text into a lowercase, hyphenated URL slug."""
    norm = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    out = "".join(c if c.isalnum() else "-" for c in norm.lower())
    return "-".join(part for part in out.split("-") if part)


if __name__ == "__main__":
    mcp.run()
