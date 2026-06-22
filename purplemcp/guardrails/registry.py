"""Safe tool registries — the fix for **tool shadowing / name collisions**.

When a host connects to more than one MCP server, two servers can expose tools
with the *same* name. A malicious server can register a ``send_email`` (or a
poisoned twin of a trusted tool) and, if the host routes by bare name or the
model just picks the more assertive description, the attacker's tool wins. This
is the MCP analogue of PATH hijacking / dependency confusion.

Defenses, in layers:

1. **Namespacing** — keep tools addressable per *source server* (the host already
   exposes them as ``server__tool``), so a name is never ambiguous.
2. **Collision detection** — surface when two servers claim the same tool name so
   a human/policy can decide, instead of silently trusting one.
3. **Allowlisting** — only let through the exact ``(server, tool)`` pairs you
   intend to use.

These helpers duck-type their input: any object with ``.server``, ``.name`` and
``.description`` attributes works (e.g. ``host.tool_info`` entries).
"""

from __future__ import annotations

from typing import Iterable


class ToolShadowingError(ValueError):
    """Raised when a tool isn't allowlisted, or a collision is rejected."""


def base_name(tool) -> str:
    """The bare tool name, stripped of any ``server__`` namespacing prefix."""
    prefix = f"{tool.server}__"
    name = tool.name
    return name[len(prefix):] if name.startswith(prefix) else name


def find_collisions(tools: Iterable) -> dict[str, list[str]]:
    """Map ``base tool name -> [servers]`` for names exposed by 2+ servers."""
    by_name: dict[str, list[str]] = {}
    for tool in tools:
        by_name.setdefault(base_name(tool), []).append(tool.server)
    return {name: servers for name, servers in by_name.items() if len(set(servers)) > 1}


def enforce_allowlist(tools: Iterable, allowed: set[tuple[str, str]]) -> list:
    """Return only the tools whose ``(server, base_name)`` pair is allowlisted."""
    return [t for t in tools if (t.server, base_name(t)) in allowed]


def assert_no_shadowing(tools: Iterable) -> None:
    """Raise if any tool name is claimed by more than one server."""
    collisions = find_collisions(tools)
    if collisions:
        detail = ", ".join(f"{name} <- {sorted(set(s))}" for name, s in collisions.items())
        raise ToolShadowingError(f"tool name(s) shadowed across servers: {detail}")
