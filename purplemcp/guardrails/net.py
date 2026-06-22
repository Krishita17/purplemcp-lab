"""SSRF-safe HTTP — the fix for **Server-Side Request Forgery**.

A "fetch this URL" tool is a gift to an attacker: they point it at
``http://169.254.169.254/`` (cloud metadata / credentials), ``http://localhost``
(internal admin panels), or other RFC-1918 hosts your server can reach but the
attacker can't. ``safe_get`` blocks that by:

- allowing only ``http`` / ``https`` (no ``file://``, ``gopher://`` …);
- resolving the hostname and rejecting it if *any* resolved IP is private,
  loopback, link-local, multicast, reserved or unspecified;
- refusing to follow redirects (a ``302`` is a classic SSRF bypass);
- capping response size and time;
- optionally enforcing a host allowlist.

Note (educational): there is a small TOCTOU window between our DNS check and the
client's own connection. The robust production fix is to pin the validated IP
and send the original ``Host`` header; we keep the readable version here and call
the limitation out explicitly.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx


class SSRFError(ValueError):
    """Raised when a URL is not allowed by the SSRF policy."""


def _is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_all(host: str) -> list[str]:
    """Every IP a hostname resolves to (so a split-horizon trick can't sneak by)."""
    infos = socket.getaddrinfo(host, None)
    return sorted({info[4][0] for info in infos})


def assert_url_allowed(url: str, *, allow_hosts: set[str] | None = None) -> None:
    """Raise :class:`SSRFError` unless ``url`` is safe to fetch. (No request made.)"""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError(f"scheme {parsed.scheme!r} not allowed (use http/https)")
    host = parsed.hostname
    if not host:
        raise SSRFError("URL has no host")
    if allow_hosts is not None and host not in allow_hosts:
        raise SSRFError(f"host {host!r} is not in the allowlist")
    for ip in _resolve_all(host):
        if not _is_public_ip(ip):
            raise SSRFError(f"host {host!r} resolves to non-public address {ip}")


def safe_get(
    url: str,
    *,
    allow_hosts: set[str] | None = None,
    timeout: float = 5.0,
    max_bytes: int = 1_000_000,
) -> str:
    """Fetch ``url`` with SSRF protections and return decoded text (size-capped)."""
    assert_url_allowed(url, allow_hosts=allow_hosts)
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        resp = client.get(url)
        data = resp.content[:max_bytes]
        return data.decode(resp.encoding or "utf-8", errors="replace")
