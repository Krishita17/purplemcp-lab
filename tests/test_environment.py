"""Environment/readiness checks behave sanely regardless of host configuration."""

from purplemcp import environment as env


def test_gather_includes_core_checks():
    checks = env.gather()
    names = {c.name for c in checks}
    assert {"Python", "LLM providers", "Ollama (local)", "MCP servers"} <= names


def test_python_check_passes_on_supported_runtime():
    py = next(c for c in env.gather() if c.name == "Python")
    assert py.ok  # the test suite itself runs on 3.11+


def test_stats_reflect_lab_contents():
    s = env.stats()
    assert s["attack_modules"] >= 21
    assert s["hardened_twins"] >= 16
    assert s["guardrails"] >= 13


def test_lab_armed_tracks_env(monkeypatch):
    monkeypatch.delenv(env.LAB_ENV_VAR, raising=False)
    assert env.lab_armed() is False
    monkeypatch.setenv(env.LAB_ENV_VAR, env.LAB_TOKEN)
    assert env.lab_armed() is True


def test_all_ok_ignores_optional_ollama():
    # A passing set with Ollama down should still be "ok" (Ollama is optional).
    checks = [
        env.Check("Python", True, ""),
        env.Check("LLM providers", True, ""),
        env.Check("Ollama (local)", False, "not reachable"),
        env.Check("MCP servers", True, ""),
        env.Check("Desktop GUI", True, ""),
    ]
    assert env.all_ok(checks) is True
