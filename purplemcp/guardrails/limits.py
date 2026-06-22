"""Output-size limiting — the fix for **unbounded output / context flooding**.

An MCP tool that returns however much its caller asks for is a denial-of-service
(and cost) vector: a model coaxed into ``dump_logs(lines=10_000_000)`` floods the
host's context window, blows the token budget, and can wedge the session. This is
OWASP-LLM **LLM10: Unbounded Consumption**.

The fix is boring and effective: every tool result passes through a hard byte cap
before it leaves the server, truncating with a clear marker so nothing silently
disappears.
"""

from __future__ import annotations

#: A sane default ceiling for a single tool result (8 KiB).
DEFAULT_MAX_BYTES = 8 * 1024


def cap_text(text: str, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    """Truncate ``text`` to a UTF-8 byte budget, marking it when cut.

    Byte-based (not character-based) so the cap is a real memory/transport bound
    regardless of multibyte content. The marker reports the original size so the
    caller knows truncation happened and by how much.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= max_bytes:
        return text
    clipped = encoded[:max_bytes].decode("utf-8", "ignore")
    return f"{clipped}\n…[truncated: {len(encoded)} bytes capped to {max_bytes}]"


def within_limit(text: str, max_bytes: int = DEFAULT_MAX_BYTES) -> bool:
    """True if ``text`` fits the byte budget without truncation."""
    return len(text.encode("utf-8", "replace")) <= max_bytes
