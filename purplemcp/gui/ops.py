"""Backend coroutines the GUI pages run through the async bridge.

These are thin wrappers over the same core the CLI uses (``MCPHost``, the
scanner). Keeping them here means the page widgets stay about layout, not about
how MCP sessions are opened and torn down.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from ..config import REPO_ROOT, ProviderConfig, ServerSpec
from ..host import MCPHost
from ..host.client import ToolInfo
from .catalog import LAB_ENV_VAR, LAB_TOKEN, ArenaCase

if TYPE_CHECKING:  # ``Job`` is used only in annotations; importing async_bridge pulls
    from .async_bridge import Job  # in PySide6, so keep it out of the runtime import path.


# --------------------------------------------------------------------------- #
#  tool explorer
# --------------------------------------------------------------------------- #
async def list_tools(spec: ServerSpec) -> list[ToolInfo]:
    async with MCPHost([spec]) as host:
        return list(host.tool_info)


async def call_tool(spec: ServerSpec, tool: str, args: dict) -> str:
    async with MCPHost([spec]) as host:
        return await host.call_tool(tool, args)


# --------------------------------------------------------------------------- #
#  scanner
# --------------------------------------------------------------------------- #
async def scan_path(target: str):
    from ..scanner import scan_path as _scan  # lazy: pulls in ast-only path

    return await asyncio.to_thread(_scan, target)


async def scan_server(spec: ServerSpec):
    from ..scanner import scan_server as _scan

    return await _scan(spec)


# --------------------------------------------------------------------------- #
#  arena
# --------------------------------------------------------------------------- #
@dataclass
class ArenaResult:
    case_id: str
    vuln_benign: Optional[str] = None
    vuln_attack: str = ""
    hard_benign: Optional[str] = None
    hard_attack: str = ""


def _lab_spec(path, name: str) -> ServerSpec:
    """A spec that launches a lab server with the opt-in token set in its env."""
    return ServerSpec(
        name=name,
        transport="stdio",
        command=sys.executable,
        args=[str(path)],
        env={LAB_ENV_VAR: LAB_TOKEN},
    )


async def _try(host: MCPHost, tool: str, args: dict) -> str:
    try:
        return await host.call_tool(tool, args)
    except Exception as exc:  # noqa: BLE001 - shown verbatim in the arena
        return f"ERROR: {type(exc).__name__}: {exc}"


async def _pair(spec: ServerSpec, tool: str, benign, attack) -> tuple[Optional[str], str]:
    async with MCPHost([spec]) as host:
        b = await _try(host, tool, benign) if benign is not None else None
        a = await _try(host, tool, attack)
    return b, a


async def arena_run(case: ArenaCase) -> ArenaResult:
    """Fire the benign + attack payloads at the vulnerable and hardened twins."""
    result = ArenaResult(case_id=case.id)
    result.vuln_benign, result.vuln_attack = await _pair(
        _lab_spec(case.vuln_path, "vulnerable"), case.tool, case.benign_args, case.attack_args
    )
    result.hard_benign, result.hard_attack = await _pair(
        _lab_spec(case.hardened_path, "hardened"), case.tool, case.benign_args, case.attack_args
    )
    return result


# --------------------------------------------------------------------------- #
#  attack lab — run a real exploit script, streaming its output
# --------------------------------------------------------------------------- #
async def run_exploit(job: Job, exploit_path: str) -> int:
    """Run ``exploit_path`` as a subprocess (lab token injected), streaming stdout.

    The opt-in token is set ONLY here, so a vulnerable server can't start unless
    the caller (the armed Attack Lab) actually invokes this.
    """
    env = {**os.environ, LAB_ENV_VAR: LAB_TOKEN}
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-u", str(exploit_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
        cwd=str(REPO_ROOT),
    )
    assert proc.stdout is not None
    async for raw in proc.stdout:
        job.event.emit("line", raw.decode("utf-8", "replace").rstrip("\n"))
    return await proc.wait()


# --------------------------------------------------------------------------- #
#  manual command runner — the in-app "live terminal"
# --------------------------------------------------------------------------- #
#: Only the project's own commands may be launched from the in-app terminal.
#: This keeps the manual runner a *teaching* tool, not an arbitrary shell.
RUNNER_ALLOW = {"purplemcp", "python", "python3", "ollama"}


def resolve_argv(argv: list[str]) -> list[str]:
    """Map a friendly command (``purplemcp …`` / ``python …``) to a concrete argv.

    The labs show copyable ``purplemcp …`` commands that also work verbatim in the
    user's own terminal; in-app we route them through the very interpreter the GUI
    is running under, so a missing PATH entry or the wrong venv can't make a
    command that "should work" fail mysteriously.
    """
    if not argv:
        return argv
    head, *rest = argv
    if head == "purplemcp":
        return [sys.executable, "-m", "purplemcp.cli", *rest]
    if head in ("python", "python3"):
        return [sys.executable, *rest]
    return argv


async def run_command(job: Job, argv: list[str], *, lab: bool = False) -> int:
    """Run an allowlisted project command as a subprocess, streaming its output.

    Emits ``('line', str)`` events for the prompt echo, every output line, and a
    final exit marker. ``lab=True`` injects the lab opt-in token — the caller is
    responsible for only passing it once the user has armed the lab.
    """
    head = argv[0] if argv else ""
    if head not in RUNNER_ALLOW:
        job.event.emit(
            "line",
            f"refused: '{head}' is not allowed here — this terminal only runs "
            "purplemcp / python / ollama commands.",
        )
        return 126

    env = {**os.environ}
    if lab:
        env[LAB_ENV_VAR] = LAB_TOKEN
    resolved = resolve_argv(argv)
    job.event.emit("line", "$ " + " ".join(argv))
    try:
        proc = await asyncio.create_subprocess_exec(
            *resolved,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
            cwd=str(REPO_ROOT),
        )
    except FileNotFoundError as exc:
        job.event.emit("line", f"ERROR: {exc}")
        return 127
    assert proc.stdout is not None
    async for raw in proc.stdout:
        job.event.emit("line", raw.decode("utf-8", "replace").rstrip("\n"))
    rc = await proc.wait()
    job.event.emit("line", f"[exit {rc}]")
    return rc


# --------------------------------------------------------------------------- #
#  AI models — ollama management + provider key tests
# --------------------------------------------------------------------------- #
def _model_field(entry, *names):
    for n in names:
        val = getattr(entry, n, None)
        if val is None and isinstance(entry, dict):
            val = entry.get(n)
        if val is not None:
            return val
    return None


async def ollama_list() -> list[dict]:
    """Installed Ollama models as ``[{name, size}]`` (works across lib versions)."""
    import ollama

    res = await asyncio.to_thread(ollama.list)
    models = _model_field(res, "models") or (res.get("models") if isinstance(res, dict) else []) or []
    out = []
    for m in models:
        name = _model_field(m, "model", "name")
        size = _model_field(m, "size") or 0
        if name:
            out.append({"name": name, "size": int(size or 0)})
    return out


async def ollama_test(model: str) -> str:
    import ollama

    res = await asyncio.to_thread(
        lambda: ollama.chat(
            model=model,
            messages=[{"role": "user", "content": "Reply with exactly one word: pong"}],
        )
    )
    msg = _model_field(res, "message")
    content = _model_field(msg, "content") if msg is not None else None
    return (content or "").strip() or "(empty response)"


async def ollama_delete(model: str) -> str:
    import ollama

    await asyncio.to_thread(ollama.delete, model)
    return f"deleted {model}"


async def ollama_pull(job: Job, model: str) -> str:
    """Pull a model, emitting ('progress', {status, completed, total}) events."""
    import ollama

    def _pull() -> None:
        for chunk in ollama.pull(model, stream=True):
            job.event.emit(
                "progress",
                {
                    "status": _model_field(chunk, "status") or "",
                    "completed": _model_field(chunk, "completed") or 0,
                    "total": _model_field(chunk, "total") or 0,
                },
            )

    await asyncio.to_thread(_pull)
    return f"pulled {model}"


async def provider_test(cfg: ProviderConfig) -> str:
    """Make one minimal live completion to verify a provider/key works."""
    from ..providers import build_provider
    from ..providers.base import Message

    provider = build_provider(cfg)
    reply = await asyncio.to_thread(
        provider.complete,
        [Message(role="user", content="Reply with exactly one word: pong")],
        [],
    )
    return (reply.content or "").strip() or "(empty response)"
