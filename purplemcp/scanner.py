"""MCP security scanner.

Two modes:

- **static** (``scan_path``): parse Python source with ``ast`` and flag the risky
  patterns the attack lab demonstrates — ``shell=True``, ``eval``/``exec``,
  unguarded network calls, ``open()`` on a variable path, unsafe deserialization,
  hardcoded secrets, and suspicious string literals.
- **dynamic** (``scan_server``): connect to a live MCP server, read every tool's
  description, and flag prompt-injection patterns or hidden Unicode — the things
  static analysis misses when a description is built at runtime.

This is intentionally simple and explainable, not a replacement for a real SAST
tool. The point is to *see* the risks before you trust a server.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path

from .config import ServerSpec
from .guardrails import find_injection, find_secrets, has_hidden_unicode
from .host import MCPHost

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    severity: str
    rule: str
    location: str
    message: str


# --------------------------------------------------------------------------- #
#  static analysis
# --------------------------------------------------------------------------- #
def _dotted(node: ast.expr) -> str:
    """Best-effort dotted name of a call target (e.g. ``subprocess.run``)."""
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        cur: ast.expr = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _is_built_string(node: ast.expr) -> bool:
    """True if ``node`` is a string assembled at runtime (f-string / + / .format)."""
    return (
        isinstance(node, ast.JoinedStr)  # f-string
        or (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add))  # "a" + x
        or (isinstance(node, ast.Call) and _dotted(node.func).split(".")[-1] == "format")
    )


class _StaticVisitor(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: list[Finding] = []
        # names bound to a runtime-built string, so `sql = f"…"; execute(sql)` is caught
        self.built_strings: set[str] = set()

    def _add(self, severity: str, rule: str, node: ast.AST, message: str) -> None:
        line = getattr(node, "lineno", "?")
        self.findings.append(Finding(severity, rule, f"{self.filename}:{line}", message))

    def visit_Assign(self, node: ast.Assign) -> None:
        if _is_built_string(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.built_strings.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        tail = name.split(".")[-1]
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        # command injection: shell=True on any subprocess-style call
        shell = kwargs.get("shell")
        if isinstance(shell, ast.Constant) and shell.value is True:
            self._add("HIGH", "command-injection", node,
                      "subprocess call with shell=True — use an argv list + allowlist "
                      "(guardrails.exec.run)")

        # arbitrary code / command execution
        if name in {"eval", "exec"}:
            self._add("HIGH", "code-exec", node, f"use of {name}() on dynamic input")
        if name in {"os.system", "os.popen"}:
            self._add("HIGH", "code-exec", node, f"use of {name}()")

        # unsafe deserialization
        if name in {"pickle.loads", "pickle.load", "cloudpickle.loads"}:
            self._add("HIGH", "deserialization", node, f"{name} can execute code")
        if name in {"yaml.load"} and "Loader" not in kwargs:
            self._add("HIGH", "deserialization", node, "yaml.load without SafeLoader")

        # SSRF: network fetch, especially following redirects
        if tail in {"get", "post", "put", "request", "urlopen"} and (
            name.startswith(("httpx", "requests", "urllib", "aiohttp"))
            or name in {"urlopen", "request.urlopen"}
        ):
            redirect = kwargs.get("follow_redirects")
            follows = isinstance(redirect, ast.Constant) and redirect.value is True
            self._add(
                "MEDIUM" if not follows else "HIGH",
                "ssrf",
                node,
                "outbound HTTP without SSRF allowlist"
                + (" and follows redirects" if follows else "")
                + " — use guardrails.net.safe_get",
            )

        # path traversal: open() on a non-constant path
        if name == "open" and node.args:
            first = node.args[0]
            if not isinstance(first, ast.Constant):
                self._add("LOW", "path-traversal", node,
                          "open() on a computed path — confine with "
                          "guardrails.paths.safe_resolve")

        # sql injection: execute() on a string built at runtime
        if tail in {"execute", "executemany", "executescript"} and node.args:
            first = node.args[0]
            risky = _is_built_string(first) or (
                isinstance(first, ast.Name) and first.id in self.built_strings
            )
            if risky:
                self._add("HIGH", "sql-injection", node,
                          "SQL built from a non-constant string — use parameterized "
                          "queries (? placeholders), see guardrails.sqlsafe")

        # zip slip: extractall() trusts archive member paths
        if tail == "extractall":
            self._add("MEDIUM", "zip-slip", node,
                      "archive extractall() can write outside the target dir — validate "
                      "each member with guardrails.paths.safe_resolve")

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            value = node.value
            secrets = find_secrets(value)
            if secrets:
                self._add("HIGH", "hardcoded-secret", node,
                          f"string literal looks like a secret: {secrets}")
            if len(value) > 40 and (find_injection(value) or has_hidden_unicode(value)):
                self._add("MEDIUM", "suspicious-string", node,
                          "string literal reads like an injected instruction / hides "
                          "invisible characters")
        self.generic_visit(node)


def _scan_file(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [Finding("INFO", "io-error", str(path), str(exc))]
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [Finding("INFO", "parse-error", f"{path}:{exc.lineno}", str(exc.msg))]
    visitor = _StaticVisitor(str(path))
    visitor.visit(tree)
    return visitor.findings


def scan_path(target: str) -> list[Finding]:
    """Static-scan a Python file, or every ``*.py`` under a directory."""
    root = Path(target)
    if not root.exists():
        return [Finding("INFO", "not-found", target, "path does not exist")]
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*.py") if ".venv" not in p.parts
    )
    findings: list[Finding] = []
    for file in files:
        findings.extend(_scan_file(file))
    return findings


# --------------------------------------------------------------------------- #
#  dynamic analysis (live server)
# --------------------------------------------------------------------------- #
async def scan_server(spec: ServerSpec) -> list[Finding]:
    """Connect to a server and inspect its advertised tool definitions."""
    findings: list[Finding] = []
    async with MCPHost([spec]) as host:
        for tool in host.tool_info:
            loc = f"{spec.name}:{tool.name}"
            injections = find_injection(tool.description)
            if injections:
                findings.append(Finding("HIGH", "poisoned-description", loc,
                                        f"tool description matches injection patterns: {injections}"))
            if has_hidden_unicode(tool.description):
                findings.append(Finding("HIGH", "hidden-unicode", loc,
                                        "tool description contains invisible Unicode"))
            secrets = find_secrets(tool.description)
            if secrets:
                findings.append(Finding("MEDIUM", "secret-in-description", loc,
                                        f"description leaks a secret-like value: {secrets}"))
        if not findings:
            findings.append(Finding("INFO", "clean", spec.name,
                                    f"{len(host.tool_info)} tool(s) inspected, nothing suspicious"))
    return findings


# --------------------------------------------------------------------------- #
#  reporting
# --------------------------------------------------------------------------- #
def print_report(findings: list[Finding], console) -> None:
    from rich.table import Table

    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.location))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    table = Table(title="MCP security scan")
    table.add_column("severity")
    table.add_column("rule", style="bold")
    table.add_column("location")
    table.add_column("detail")
    colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
    for f in findings:
        color = colors.get(f.severity, "white")
        table.add_row(f"[{color}]{f.severity}[/{color}]", f.rule, f.location, f.message)
    console.print(table)

    summary = "  ".join(f"{sev}={counts.get(sev, 0)}" for sev in ("HIGH", "MEDIUM", "LOW", "INFO"))
    console.print(f"[bold]summary:[/bold] {summary}")


# --------------------------------------------------------------------------- #
#  machine-readable output (JSON + SARIF for CI / code scanning)
# --------------------------------------------------------------------------- #
def to_json(findings: list[Finding]) -> str:
    """Findings as a plain JSON array."""
    return json.dumps(
        [
            {"severity": f.severity, "rule": f.rule, "location": f.location, "message": f.message}
            for f in findings
        ],
        indent=2,
    )


# SARIF severity levels: error/warning/note.
_SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def to_sarif(findings: list[Finding]) -> str:
    """Findings as SARIF 2.1.0 — drop-in for GitHub code scanning / other SAST UIs."""
    try:
        from importlib.metadata import version as _v

        tool_version = _v("purplemcp")
    except Exception:  # noqa: BLE001
        tool_version = "0.0.0"

    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rules.setdefault(
            f.rule,
            {"id": f.rule, "name": f.rule, "shortDescription": {"text": f.rule}},
        )
        path, _, line = f.location.partition(":")
        phys: dict = {"artifactLocation": {"uri": path}}
        if line.isdigit():
            phys["region"] = {"startLine": int(line)}
        results.append(
            {
                "ruleId": f.rule,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [{"physicalLocation": phys}],
                "properties": {"severity": f.severity},
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "purplemcp-scanner",
                        "informationUri": "https://github.com/at0m-b0mb/PurpleMCP",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
