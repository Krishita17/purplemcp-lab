"""Path confinement — the fix for **path traversal**.

A file tool should only ever touch files under one root directory. The bug is
almost always the same: the server does ``open(os.path.join(root, user_path))``
and trusts ``user_path``. An attacker passes ``../../../../etc/passwd`` (or an
absolute path, or a symlink) and walks straight out of the sandbox.

``safe_resolve`` closes all three holes:
- ``..`` components: we ``resolve()`` (normalize) and then confirm the result is
  still inside the root;
- absolute paths: rejected outright (joining an absolute path silently discards
  the root);
- symlinks: ``resolve()`` follows them, so a link pointing outside the root
  resolves outside and is rejected.
"""

from __future__ import annotations

from pathlib import Path


class PathTraversalError(ValueError):
    """Raised when a requested path would escape the sandbox root."""


def safe_resolve(root: str | Path, user_path: str, *, must_exist: bool = False) -> Path:
    """Resolve ``user_path`` *within* ``root`` or raise :class:`PathTraversalError`.

    Returns an absolute, normalized path guaranteed to be inside ``root``.
    """
    root_resolved = Path(root).resolve()
    requested = Path(user_path)

    if requested.is_absolute():
        raise PathTraversalError("absolute paths are not allowed")

    candidate = (root_resolved / requested).resolve()

    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise PathTraversalError(f"path escapes sandbox root: {user_path!r}")

    if must_exist and not candidate.exists():
        raise FileNotFoundError(user_path)

    return candidate
