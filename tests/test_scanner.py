"""The static scanner must flag the obvious footguns and stay quiet on clean code."""

from purplemcp.scanner import scan_path


def _rules(path):
    return {finding.rule for finding in scan_path(str(path))}


def test_flags_shell_true(tmp_path):
    f = tmp_path / "s.py"
    f.write_text("import subprocess\nsubprocess.run(f'ping {h}', shell=True)\n")
    assert "command-injection" in _rules(f)


def test_flags_eval(tmp_path):
    f = tmp_path / "s.py"
    f.write_text("def run(x):\n    return eval(x)\n")
    assert "code-exec" in _rules(f)


def test_flags_hardcoded_secret(tmp_path):
    f = tmp_path / "s.py"
    f.write_text('TOKEN = "AKIAIOSFODNN7EXAMPLE"\n')
    assert "hardcoded-secret" in _rules(f)


def test_clean_file_has_no_high_findings(tmp_path):
    f = tmp_path / "s.py"
    f.write_text("def add(a, b):\n    return a + b\n")
    highs = [x for x in scan_path(str(f)) if x.severity == "HIGH"]
    assert highs == []


def test_flags_sql_injection_fstring(tmp_path):
    f = tmp_path / "s.py"
    f.write_text(
        "def q(conn, name):\n"
        "    sql = f\"SELECT * FROM t WHERE n = '{name}'\"\n"
        "    return conn.execute(sql)\n"
    )
    assert "sql-injection" in _rules(f)


def test_parameterized_sql_is_clean(tmp_path):
    f = tmp_path / "s.py"
    f.write_text(
        "def q(conn, name):\n"
        "    return conn.execute('SELECT * FROM t WHERE n = ?', (name,))\n"
    )
    assert "sql-injection" not in _rules(f)


def test_flags_pickle_loads(tmp_path):
    f = tmp_path / "s.py"
    f.write_text("import pickle\ndef load(b):\n    return pickle.loads(b)\n")
    assert "deserialization" in _rules(f)
