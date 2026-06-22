"""Metadata for every attack module — drives the Attack Lab and Defense Lab.

This is the single registry of the 23 modules: where each exploit/readme lives,
which guardrail file fixes it, and which Defense-Lab arena case (if any) gives the
side-by-side proof. The runnable code stays in ``attacks/`` and
``purplemcp/guardrails/`` — this only points at it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..config import REPO_ROOT

ATTACKS_DIR = REPO_ROOT / "attacks"
GUARDRAILS_DIR = REPO_ROOT / "purplemcp" / "guardrails"

FAMILY_MCP = "MCP-specific"
FAMILY_CLASSIC = "Classic appsec, now model-reachable"


@dataclass(frozen=True)
class AttackMeta:
    num: str
    id: str
    title: str
    family: str
    severity: str            # HIGH | MEDIUM
    threat: str
    folder: str
    guardrail: str | None    # guardrail module filename, or None
    arena_case_id: str | None = None

    @property
    def exploit_path(self) -> Path:
        return ATTACKS_DIR / self.folder / "exploit.py"

    @property
    def readme_path(self) -> Path:
        return ATTACKS_DIR / self.folder / "README.md"

    @property
    def guardrail_source(self) -> Path | None:
        return (GUARDRAILS_DIR / self.guardrail) if self.guardrail else None


ATTACKS: list[AttackMeta] = [
    AttackMeta("01", "tool-poisoning", "Tool Poisoning", FAMILY_MCP, "HIGH",
               "Hidden instructions in a tool description hijack the model.",
               "01_tool_poisoning", "descriptions.py"),
    AttackMeta("02", "indirect-injection", "Indirect Prompt Injection", FAMILY_MCP, "HIGH",
               "Malicious text in returned data steers the model.",
               "02_indirect_prompt_injection", "descriptions.py"),
    AttackMeta("07", "rug-pull", "Rug Pull", FAMILY_MCP, "HIGH",
               "A tool changes its definition after you approved it.",
               "07_rug_pull", "descriptions.py"),
    AttackMeta("12", "tool-shadowing", "Tool Shadowing", FAMILY_MCP, "HIGH",
               "A 2nd server registers the same tool name and intercepts calls.",
               "12_tool_shadowing", "registry.py"),
    AttackMeta("17", "output-injection", "Output / Log Injection", FAMILY_MCP, "HIGH",
               "A tool's output forges log lines / injects control chars into context.",
               "17_output_injection", "framing.py", "output-injection"),
    AttackMeta("03", "command-injection", "Command Injection", FAMILY_CLASSIC, "HIGH",
               "A tool that shells out runs attacker commands.",
               "03_command_injection", "exec.py", "command-injection"),
    AttackMeta("04", "path-traversal", "Path Traversal", FAMILY_CLASSIC, "HIGH",
               "A file tool reads outside its root (/etc/hosts).",
               "04_path_traversal", "paths.py", "path-traversal"),
    AttackMeta("05", "ssrf", "Server-Side Request Forgery", FAMILY_CLASSIC, "HIGH",
               "A fetch tool hits internal/metadata addresses.",
               "05_ssrf", "net.py", "ssrf"),
    AttackMeta("06", "token-theft", "Token Theft / Confused Deputy", FAMILY_CLASSIC, "HIGH",
               "A tool leaks or passes through the credentials it holds.",
               "06_token_theft", "secrets.py", "token-theft"),
    AttackMeta("08", "excessive-permissions", "Excessive Permissions", FAMILY_CLASSIC, "MEDIUM",
               "Over-broad scope magnifies every other bug.",
               "08_excessive_permissions", "approval.py"),
    AttackMeta("09", "data-exfiltration", "Data Exfiltration", FAMILY_CLASSIC, "HIGH",
               "A tool ships data to an attacker endpoint.",
               "09_data_exfiltration", "secrets.py", "data-exfiltration"),
    AttackMeta("10", "sql-injection", "SQL Injection", FAMILY_CLASSIC, "HIGH",
               "Query built from model input dumps hidden rows.",
               "10_sql_injection", "sqlsafe.py", "sql-injection"),
    AttackMeta("11", "template-injection", "Template / Format-String Injection", FAMILY_CLASSIC, "HIGH",
               "str.format on a caller's template reaches secrets/globals.",
               "11_template_injection", "templating.py", "template-injection"),
    AttackMeta("13", "insecure-deserialization", "Insecure Deserialization", FAMILY_CLASSIC, "HIGH",
               "pickle.loads of an attacker blob → code execution.",
               "13_insecure_deserialization", "serialization.py", "insecure-deserialization"),
    AttackMeta("14", "broken-access-control", "Broken Access Control (IDOR)", FAMILY_CLASSIC, "HIGH",
               "A tool returns any record by id, ignoring the caller.",
               "14_broken_access_control", "authz.py", "broken-access-control"),
    AttackMeta("15", "unrestricted-file-write", "Unrestricted File Write", FAMILY_CLASSIC, "HIGH",
               "A save tool escapes its root and overwrites startup files.",
               "15_unrestricted_file_write", "paths.py", "unrestricted-file-write"),
    AttackMeta("16", "weak-randomness", "Weak Randomness / Predictable Tokens", FAMILY_CLASSIC, "HIGH",
               "'Secure' tokens minted from time/PRNG are forgeable.",
               "16_weak_randomness", "tokens.py"),
    AttackMeta("18", "eval-injection", "Eval / Expression Injection", FAMILY_CLASSIC, "HIGH",
               "A 'calculator' tool uses eval() — arbitrary code execution.",
               "18_eval_injection", "safe_eval.py", "eval-injection"),
    AttackMeta("19", "zip-slip", "Zip Slip / Archive Traversal", FAMILY_CLASSIC, "HIGH",
               "An archive member named '../x' writes outside the extract dir.",
               "19_zip_slip", "paths.py", "zip-slip"),
    AttackMeta("20", "mass-assignment", "Mass Assignment / Priv-Esc", FAMILY_CLASSIC, "HIGH",
               "An update tool binds any field the caller sends — including role.",
               "20_mass_assignment", "authz.py", "mass-assignment"),
    AttackMeta("21", "csv-injection", "CSV / Formula Injection", FAMILY_CLASSIC, "MEDIUM",
               "An exported cell starting with '=' runs as a spreadsheet formula.",
               "21_csv_injection", "csvsafe.py", "csv-injection"),
    AttackMeta("22", "unbounded-output", "Unbounded Output / Context Flooding", FAMILY_CLASSIC, "MEDIUM",
               "A tool returns unbounded output, flooding the model's context.",
               "22_unbounded_output", "limits.py", "unbounded-output"),
    AttackMeta("23", "argument-injection", "Argument / Flag Injection", FAMILY_CLASSIC, "HIGH",
               "A caller's value becomes a command-line option, not data.",
               "23_argument_injection", "argv.py", "argument-injection"),
    AttackMeta("24", "jwt-none", "Insecure JWT Verification", FAMILY_CLASSIC, "HIGH",
               "A tool trusts an unsigned / alg:none JWT and grants admin.",
               "24_insecure_jwt", "jwtsafe.py", "jwt-none"),
    AttackMeta("25", "xxe", "XML External Entity (XXE)", FAMILY_CLASSIC, "HIGH",
               "An XML parser resolves external entities, reading local files.",
               "25_xxe", "safexml.py", "xxe"),
]

ATTACKS_BY_ID = {a.id: a for a in ATTACKS}


def grouped() -> list[tuple[str, list[AttackMeta]]]:
    """Attacks grouped by family, MCP-specific first, in numeric order within."""
    families = [FAMILY_MCP, FAMILY_CLASSIC]
    out = []
    for fam in families:
        items = sorted((a for a in ATTACKS if a.family == fam), key=lambda a: a.num)
        out.append((fam, items))
    return out
