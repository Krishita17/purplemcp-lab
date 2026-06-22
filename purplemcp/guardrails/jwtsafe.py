"""JWT verification guardrail — defeats ``alg:none`` and unsigned-token forgery.

The classic JWT footgun is trusting the token's own header to choose the algorithm
(so an attacker sets ``alg:none`` and drops the signature) or decoding the payload
without checking the signature at all. :func:`verify_jwt` ignores the header's alg,
*requires* HS256, and verifies the HMAC signature in constant time before returning
any claims — so a forged token never gets trusted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json


class JWTError(Exception):
    """Raised when a token is malformed, unsigned, or fails verification."""


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sign_jwt(claims: dict, secret: str) -> str:
    """Mint a correctly-signed HS256 JWT for ``claims`` (helper for tests/demos)."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url_encode(sig)}"


def verify_jwt(token: str, secret: str) -> dict:
    """Verify an HS256 JWT and return its claims, or raise :class:`JWTError`.

    Refuses any ``alg`` other than HS256 (including ``none``), refuses a missing or
    blank signature, and compares the HMAC in constant time. The token header is
    **never** trusted to select the algorithm — that is the whole vulnerability this
    neutralizes.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError("malformed token (expected header.payload.signature)")
    h_seg, p_seg, sig_seg = parts
    try:
        header = json.loads(_b64url_decode(h_seg))
    except Exception as exc:  # noqa: BLE001
        raise JWTError(f"bad header: {exc}") from exc
    if header.get("alg") != "HS256":
        raise JWTError(f"unsupported alg {header.get('alg')!r} (only HS256 is accepted)")
    if not sig_seg:
        raise JWTError("missing signature")
    expected = hmac.new(secret.encode(), f"{h_seg}.{p_seg}".encode("ascii"), hashlib.sha256).digest()
    try:
        provided = _b64url_decode(sig_seg)
    except Exception as exc:  # noqa: BLE001
        raise JWTError(f"bad signature encoding: {exc}") from exc
    if not hmac.compare_digest(provided, expected):
        raise JWTError("signature verification failed")
    try:
        return json.loads(_b64url_decode(p_seg))
    except Exception as exc:  # noqa: BLE001
        raise JWTError(f"bad payload: {exc}") from exc
