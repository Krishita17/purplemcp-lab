"""Human-in-the-loop approval — the fix for **over-trusted / dangerous tools**.

Some actions (deleting files, sending email, spending money) should never run on
the model's say-so alone. Gate them behind an explicit human confirmation. The
confirm function is injectable so tests can use ``auto_allow`` / ``auto_deny``.
"""

from __future__ import annotations

from typing import Callable

ConfirmFn = Callable[[str], bool]


class ApprovalDenied(Exception):
    """Raised when a gated action is not approved."""


def cli_confirm(action: str) -> bool:
    """Ask the operator on the terminal. Anything but y/yes is a no."""
    try:
        answer = input(f"[approval needed] {action}\n  allow? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def auto_allow(action: str) -> bool:  # for tests / trusted automation
    return True


def auto_deny(action: str) -> bool:  # for tests
    return False


def require(action: str, *, confirm: ConfirmFn = cli_confirm) -> None:
    """Raise :class:`ApprovalDenied` unless ``confirm(action)`` returns True."""
    if not confirm(action):
        raise ApprovalDenied(action)
