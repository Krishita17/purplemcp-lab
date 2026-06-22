"""Safe deserialization — the fix for **insecure deserialization (e.g. pickle)**.

``pickle.loads`` (and ``yaml.load``, ``cloudpickle``, etc.) will *execute code*
embedded in the data via ``__reduce__``. If a tool deserializes anything an
attacker can influence, that's remote code execution. The rule is simple:

1. **Never unpickle untrusted data.** Use a data-only format — JSON — that can
   represent values but never call code.
2. **Validate the shape** after parsing, so a surprising structure is rejected
   before the rest of the tool trusts it.

``safe_loads`` is JSON-only by construction, so there is no ``__reduce__`` to
abuse. ``looks_like_pickle`` is a cheap heuristic the scanner/defense use to flag
a blob that is clearly a pickle stream rather than JSON.
"""

from __future__ import annotations

import json
from typing import Any


class UnsafeDeserialization(ValueError):
    """Raised when data can't be safely (JSON-)deserialized or fails validation."""


# Pickle streams start with the PROTO opcode (0x80) + a version byte, or are
# made of printable opcodes ending in '.'. This is a heuristic, not a parser.
_PICKLE_PROTO = b"\x80"


def looks_like_pickle(blob: bytes) -> bool:
    """True if ``blob`` looks like a pickle stream (so it must never be loaded)."""
    if not blob:
        return False
    if blob[:1] == _PICKLE_PROTO:  # protocol 2+ marker
        return True
    # protocol 0/1 are ASCII; a trailing STOP opcode '.' after opcodes is typical
    return blob[:1] in (b"(", b"c", b"]", b"}") and blob.rstrip()[-1:] == b"."


def safe_loads(text: str | bytes, *, require: type | None = None) -> Any:
    """Deserialize ``text`` as JSON only (never pickle), optionally type-checked.

    ``require`` is an optional expected top-level type (e.g. ``dict``); the value
    is rejected if it doesn't match. Raises :class:`UnsafeDeserialization` on any
    problem so callers never act on malformed or unexpected input.
    """
    if isinstance(text, bytes):
        if looks_like_pickle(text):
            raise UnsafeDeserialization("refusing to load a pickle stream — JSON only")
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UnsafeDeserialization(f"not valid UTF-8 JSON: {exc}") from exc
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise UnsafeDeserialization(f"not valid JSON: {exc}") from exc
    if require is not None and not isinstance(value, require):
        raise UnsafeDeserialization(
            f"expected a JSON {require.__name__}, got {type(value).__name__}"
        )
    return value
