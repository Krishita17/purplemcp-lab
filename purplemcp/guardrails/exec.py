"""Safe subprocess execution — the fix for **command injection**.

The vulnerable pattern is ``subprocess.run(f"ping {host}", shell=True)``: the
shell happily interprets ``host = "8.8.8.8; rm -rf ~"``. Two rules kill the
entire bug class:

1. **Never use a shell.** Pass an argv *list*; the OS executes the program
   directly with no shell parsing, so metacharacters (``;`` ``|`` ``$()`` `` ` ``)
   are inert data.
2. **Allowlist the executable.** Even without a shell, you don't want the model
   running arbitrary binaries — only the ones the tool is supposed to use.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class CommandNotAllowed(ValueError):
    """Raised when a command is rejected by the execution policy."""


def run(
    argv: list[str],
    *,
    allow: set[str],
    timeout: float = 10.0,
    cwd: str | None = None,
) -> str:
    """Run ``argv`` (a list, never a string) with no shell and an allowlist.

    ``allow`` is the set of permitted executable *basenames* (e.g. {"ping"}).
    """
    if not isinstance(argv, list) or not argv:
        raise CommandNotAllowed("argv must be a non-empty list (never a shell string)")

    basename = Path(argv[0]).name
    if basename not in allow:
        raise CommandNotAllowed(f"executable {basename!r} is not allowed")

    resolved = shutil.which(argv[0]) or argv[0]
    proc = subprocess.run(
        [resolved, *argv[1:]],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        shell=False,  # the whole point
    )
    output = proc.stdout
    if proc.returncode != 0:
        output += f"\n[exit {proc.returncode}] {proc.stderr.strip()}"
    return output.strip()
