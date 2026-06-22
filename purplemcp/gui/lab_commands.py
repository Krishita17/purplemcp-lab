"""The exact, copyable commands behind each Attack-Lab and Defense-Lab module.

These are what the in-app terminal runs *and* what you can paste into your own
shell — they are identical, so "watch it work here" and "do it yourself" are the
same commands. Kept in one place so the labs stay about layout.
"""

from __future__ import annotations

from pathlib import Path

from ..config import REPO_ROOT
from .catalog import ArenaCase
from .catalog_attacks import AttackMeta

ATTACKS_DIR = REPO_ROOT / "attacks"


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _vuln_server(meta: AttackMeta) -> Path | None:
    """The module's primary insecure server file (names vary slightly)."""
    folder = ATTACKS_DIR / meta.folder
    for name in ("vulnerable_server.py", "malicious_server.py", "trusted_server.py"):
        candidate = folder / name
        if candidate.exists():
            return candidate
    return None


def attack_commands(meta: AttackMeta) -> list[tuple[str, str]]:
    """Copy-and-run commands for the Attack Lab: run the exploit, scan the server."""
    cmds: list[tuple[str, str]] = [
        ("Run the real exploit", f"python {_rel(meta.exploit_path)}"),
    ]
    vuln = _vuln_server(meta)
    if vuln is not None:
        cmds.append(("Scan the vulnerable server for the flaw", f"purplemcp scan {_rel(vuln)}"))
    return cmds


def defense_commands(meta: AttackMeta, case: ArenaCase | None) -> list[tuple[str, str]]:
    """Copy-and-run commands for the Defense Lab: scan, replay live, benchmark."""
    cmds: list[tuple[str, str]] = []
    vuln = _vuln_server(meta)
    if vuln is not None:
        cmds.append(("Scan the vulnerable server (static analysis)", f"purplemcp scan {_rel(vuln)}"))
    if case is not None:
        cmds.append(
            ("Replay the attack live — exploited vs. blocked",
             f"python defense/compare.py {case.tool}")
        )
    cmds.append(("Benchmark every guardrail (15 cases)", "purplemcp bench"))
    return cmds
