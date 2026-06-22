"""Tiny helpers shared by the exploit scripts (keeps each exploit short)."""

from __future__ import annotations

import pathlib
import socket
import sys

from purplemcp.config import ServerSpec


def free_port() -> int:
    """Find an unused localhost TCP port (for spinning up lab services)."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def sibling(file_dunder: str, name: str) -> str:
    """Absolute path to a file next to the given ``__file__``."""
    return str(pathlib.Path(file_dunder).resolve().parent / name)


def vulnerable_spec(server_path: str, name: str = "vulnerable", env: dict | None = None) -> ServerSpec:
    """A ServerSpec that launches a vulnerable server with this same Python."""
    return ServerSpec(
        name=name,
        transport="stdio",
        command=sys.executable,
        args=[str(server_path)],
        env=env or {},
    )


def rule(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)
