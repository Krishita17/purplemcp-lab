"""Open-redirect guardrail — confine redirects to an allowlist of hosts.

A redirect/link tool that trusts a caller-supplied destination is an open redirect
(CWE-601): an attacker sends a victim to ``https://evil.example/phish`` under your
domain's trust, or smuggles in a non-web scheme. :func:`safe_redirect` parses the
target and refuses any host that is not on the allowlist (and any non-http(s) scheme).
"""

from __future__ import annotations

from urllib.parse import urlparse


class OpenRedirectError(Exception):
    """Raised when a redirect target is off-allowlist or uses a bad scheme."""


def safe_redirect(url: str, allowed_hosts: set[str]) -> str:
    """Return ``url`` if its host is allowlisted and scheme is http(s); else raise.

    Comparison is case-insensitive on the host. Schemes other than http/https (e.g.
    ``javascript:``, ``data:``) are refused outright.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise OpenRedirectError(f"refused: scheme {parsed.scheme or '(none)'!r} is not allowed")
    host = (parsed.hostname or "").lower()
    if host not in {h.lower() for h in allowed_hosts}:
        raise OpenRedirectError(f"refused: host {host or '(none)'!r} is not on the redirect allowlist")
    return url
