"""Tests for the in-app manual terminal: command scoping + the lab command catalog.

The subprocess/argv logic is pure Python (no Qt) and always runs; the widget-level
refusal check is skipped unless PySide6 is installed.
"""

from __future__ import annotations

import asyncio
import os
import sys
from types import SimpleNamespace

import pytest

from purplemcp.gui import ops
from purplemcp.gui.catalog import CASES_BY_ID
from purplemcp.gui.catalog_attacks import ATTACKS, ATTACKS_BY_ID
from purplemcp.gui.lab_commands import attack_commands, defense_commands


def _fake_job():
    lines: list[tuple[str, object]] = []
    job = SimpleNamespace(
        event=SimpleNamespace(emit=lambda kind, payload: lines.append((kind, payload)))
    )
    return job, lines


def test_resolve_argv_maps_friendly_commands():
    assert ops.resolve_argv(["purplemcp", "scan", "x"]) == [
        sys.executable, "-m", "purplemcp.cli", "scan", "x",
    ]
    assert ops.resolve_argv(["python", "a.py"]) == [sys.executable, "a.py"]
    assert ops.resolve_argv(["python3", "a.py"]) == [sys.executable, "a.py"]
    assert ops.resolve_argv(["ollama", "list"]) == ["ollama", "list"]  # passthrough


def test_run_command_refuses_disallowed():
    job, lines = _fake_job()
    rc = asyncio.run(ops.run_command(job, ["rm", "-rf", "/"]))
    assert rc == 126
    assert any("refused" in str(p).lower() for _, p in lines)
    # a refused command must never spawn a subprocess (no prompt echo)
    assert not any(str(p).startswith("$ ") for _, p in lines)


def test_run_command_streams_allowed_output():
    job, lines = _fake_job()
    rc = asyncio.run(ops.run_command(job, ["python", "-c", "print('hello-term')"]))
    assert rc == 0
    text = "\n".join(str(p) for _, p in lines)
    assert "hello-term" in text
    assert "[exit 0]" in text


def test_lab_commands_reference_real_files_and_commands():
    meta = ATTACKS_BY_ID["command-injection"]
    case = CASES_BY_ID["command-injection"]

    acmds = attack_commands(meta)
    assert any(c.startswith("python ") and c.endswith("exploit.py") for _, c in acmds)
    assert any(c.startswith("purplemcp scan ") for _, c in acmds)

    dcmds = defense_commands(meta, case)
    assert any("compare.py" in c for _, c in dcmds)
    assert any(c == "purplemcp bench" for _, c in dcmds)


def test_every_attack_module_yields_runnable_commands():
    from purplemcp.config import REPO_ROOT

    for meta in ATTACKS:
        cmds = attack_commands(meta)
        assert cmds, f"no commands for {meta.id}"
        # the exploit path each command points at must exist on disk
        for _label, command in cmds:
            if command.startswith("python "):
                rel = command.split(" ", 1)[1]
                assert (REPO_ROOT / rel).exists(), f"missing file for: {command}"


def test_terminal_widget_refuses_in_ui():
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from purplemcp.gui.async_bridge import AsyncLoop
    from purplemcp.gui.widgets.terminal import TerminalCard

    app = QApplication.instance() or QApplication([])
    assert app is not None
    loop = AsyncLoop()
    try:
        term = TerminalCard(loop, commands=[("providers", "purplemcp providers")])
        term._run("rm -rf /")  # disallowed -> refused synchronously, no job started
        assert "refused" in term._console.toPlainText().lower()
        assert term._job is None
    finally:
        loop.shutdown()
