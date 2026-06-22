"""Secure tokens — the fix for **weak randomness / predictable secrets**.

Reset tokens, API keys and session ids must be unguessable. Values derived from
``random`` (a Mersenne-Twister PRNG, not cryptographic) or from the clock are
predictable: an attacker who knows the recipe can regenerate them. Use the OS
CSPRNG via :mod:`secrets`, give tokens enough entropy, and compare them in
constant time so a check can't be brute-forced character-by-character via timing.
"""

from __future__ import annotations

import secrets

MIN_BYTES = 16  # 128 bits — the floor for an unguessable token


def new_token(nbytes: int = 32) -> str:
    """A URL-safe, cryptographically-random token (256 bits by default)."""
    if nbytes < MIN_BYTES:
        raise ValueError(f"use at least {MIN_BYTES} bytes ({MIN_BYTES * 8} bits) of entropy")
    return secrets.token_urlsafe(nbytes)


def new_hex_token(nbytes: int = 32) -> str:
    """A hex token from the CSPRNG (when a hex shape is required)."""
    if nbytes < MIN_BYTES:
        raise ValueError(f"use at least {MIN_BYTES} bytes ({MIN_BYTES * 8} bits) of entropy")
    return secrets.token_hex(nbytes)


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two tokens without leaking length/content through timing."""
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
