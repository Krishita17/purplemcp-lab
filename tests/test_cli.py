"""Smoke tests for the CLI entry point."""

from typer.testing import CliRunner

from purplemcp import __version__
from purplemcp.cli import app

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_version_string_is_sane():
    parts = __version__.split(".")
    assert len(parts) == 3 and all(p.isdigit() for p in parts)


def test_taxonomy_command_runs():
    assert runner.invoke(app, ["taxonomy"]).exit_code == 0


def test_doctor_command_runs():
    assert runner.invoke(app, ["doctor"]).exit_code == 0


def test_report_writes_markdown(tmp_path):
    out = tmp_path / "report.md"
    result = runner.invoke(app, ["report", "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "security posture" in out.read_text(encoding="utf-8").lower()
