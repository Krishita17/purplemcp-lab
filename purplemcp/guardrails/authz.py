"""Authorization — the fix for **broken access control / IDOR**.

MCP tools usually execute with the *server's* ambient authority, and the model
can put anything into a tool argument. So two rules:

1. **Identity comes from the session/context, never a tool parameter.** If the
   caller can name themselves in an argument, they can impersonate anyone.
2. **Every access is checked against that identity.** Owning the resource (or
   holding an explicit scope like ``admin``) is required — not merely knowing its
   id. "I can reference it" must never imply "I may read it".
"""

from __future__ import annotations

from typing import Iterable


class AuthorizationError(PermissionError):
    """Raised when the caller isn't allowed to access a resource."""


def assert_owner(principal: str, owner: str, *, scopes: Iterable[str] = ()) -> None:
    """Allow access iff the caller owns the resource (or holds an ``admin`` scope).

    ``principal`` must come from the trusted session context, not a tool argument.
    """
    if principal and (principal == owner or "admin" in set(scopes)):
        return
    raise AuthorizationError(
        f"{principal or '<anonymous>'!r} may not access a resource owned by {owner!r}"
    )


def can_access(principal: str, owner: str, scopes: Iterable[str] = ()) -> bool:
    """Boolean form of :func:`assert_owner` (no exception)."""
    try:
        assert_owner(principal, owner, scopes=scopes)
        return True
    except AuthorizationError:
        return False


def require_scope(have: Iterable[str], need: str) -> None:
    """Raise unless ``need`` is among the caller's granted scopes."""
    if need not in set(have):
        raise AuthorizationError(f"missing required scope {need!r}")


def assert_assignable(updates: Iterable[str], allowed: Iterable[str]) -> None:
    """The fix for **mass assignment** — reject writes to non-allowlisted fields.

    A tool that does ``record.update(payload)`` lets the caller set *any* field,
    including privileged ones (``role``, ``is_admin``) the UI never exposes. Pass
    an explicit allowlist of editable fields; anything else is refused.
    """
    extra = sorted(set(updates) - set(allowed))
    if extra:
        raise AuthorizationError(f"fields not editable: {extra}")
