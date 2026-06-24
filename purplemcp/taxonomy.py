"""Threat taxonomy — mapping PurpleMCP's modules to standard frameworks.

For the lab to be a *research* artifact (not just a demo), every module is mapped
to the community threat frameworks so findings are comparable and citable:

* **OWASP Top 10 for LLM Applications (2025)** — the LLM-app risk categories.
* **CWE** — the precise software-weakness id (e.g. CWE-89 SQL injection).
* **MITRE ATLAS** — adversarial-ML technique ids, where one applies cleanly.

The module list itself is the single source of truth in
``purplemcp.gui.catalog_attacks`` (import-safe, no GUI deps); this module enriches
each entry with framework references and exposes coverage helpers used by the
benchmark, the docs, and the GUI Research page.
"""

from __future__ import annotations

from dataclasses import dataclass

from .gui.catalog_attacks import ATTACKS as _ATTACKS
from .gui.catalog_attacks import AttackMeta

# OWASP Top 10 for LLM Applications, 2025.
OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


@dataclass(frozen=True)
class FrameworkRefs:
    owasp_llm: str          # e.g. "LLM05" (key into OWASP_LLM_TOP10)
    cwe: str                # e.g. "CWE-89"
    cwe_name: str
    atlas: str | None = None  # MITRE ATLAS technique id + name, when one applies


# id (matches catalog_attacks) -> framework references.
_REFS: dict[str, FrameworkRefs] = {
    "tool-poisoning": FrameworkRefs(
        "LLM01", "CWE-1427", "Improper Neutralization of Input Used for LLM Prompting",
        "AML.T0051 LLM Prompt Injection"),
    "indirect-injection": FrameworkRefs(
        "LLM01", "CWE-1427", "Improper Neutralization of Input Used for LLM Prompting",
        "AML.T0051 LLM Prompt Injection (Indirect)"),
    "rug-pull": FrameworkRefs(
        "LLM03", "CWE-494", "Download of Code Without Integrity Check",
        "AML.T0053 LLM Plugin Compromise"),
    "tool-shadowing": FrameworkRefs(
        "LLM03", "CWE-706", "Use of Incorrectly-Resolved Name or Reference",
        "AML.T0053 LLM Plugin Compromise"),
    "output-injection": FrameworkRefs(
        "LLM05", "CWE-117", "Improper Output Neutralization for Logs"),
    "command-injection": FrameworkRefs(
        "LLM05", "CWE-78", "OS Command Injection"),
    "path-traversal": FrameworkRefs(
        "LLM05", "CWE-22", "Improper Limitation of a Pathname to a Restricted Directory"),
    "ssrf": FrameworkRefs(
        "LLM06", "CWE-918", "Server-Side Request Forgery (SSRF)"),
    "token-theft": FrameworkRefs(
        "LLM02", "CWE-522", "Insufficiently Protected Credentials (confused deputy, CWE-441)",
        "AML.T0057 LLM Data Leakage"),
    "excessive-permissions": FrameworkRefs(
        "LLM06", "CWE-250", "Execution with Unnecessary Privileges"),
    "data-exfiltration": FrameworkRefs(
        "LLM02", "CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor",
        "AML.T0057 LLM Data Leakage"),
    "sql-injection": FrameworkRefs(
        "LLM05", "CWE-89", "SQL Injection"),
    "template-injection": FrameworkRefs(
        "LLM05", "CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine"),
    "insecure-deserialization": FrameworkRefs(
        "LLM05", "CWE-502", "Deserialization of Untrusted Data"),
    "broken-access-control": FrameworkRefs(
        "LLM06", "CWE-639", "Authorization Bypass Through User-Controlled Key (IDOR)"),
    "unrestricted-file-write": FrameworkRefs(
        "LLM05", "CWE-73", "External Control of File Name or Path"),
    "weak-randomness": FrameworkRefs(
        "LLM06", "CWE-330", "Use of Insufficiently Random Values"),
    "eval-injection": FrameworkRefs(
        "LLM05", "CWE-95", "Improper Neutralization of Directives in Dynamically Evaluated Code"),
    "zip-slip": FrameworkRefs(
        "LLM05", "CWE-22", "Path Traversal during archive extraction"),
    "mass-assignment": FrameworkRefs(
        "LLM06", "CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
    "csv-injection": FrameworkRefs(
        "LLM05", "CWE-1236", "Improper Neutralization of Formula Elements in a CSV File"),
    "unbounded-output": FrameworkRefs(
        "LLM10", "CWE-400", "Uncontrolled Resource Consumption"),
    "argument-injection": FrameworkRefs(
        "LLM05", "CWE-88", "Improper Neutralization of Argument Delimiters in a Command"),
    "jwt-none": FrameworkRefs(
        "LLM06", "CWE-347", "Improper Verification of Cryptographic Signature (JWT alg:none)"),
    "xxe": FrameworkRefs(
        "LLM05", "CWE-611", "Improper Restriction of XML External Entity Reference"),
    "regex-injection": FrameworkRefs(
        "LLM05", "CWE-625", "Permissive Regular Expression (caller-controlled regex)"),
    "open-redirect": FrameworkRefs(
        "LLM05", "CWE-601", "URL Redirection to Untrusted Site (Open Redirect)"),
}


@dataclass(frozen=True)
class ThreatEntry:
    meta: AttackMeta
    refs: FrameworkRefs

    @property
    def num(self) -> str:
        return self.meta.num

    @property
    def id(self) -> str:
        return self.meta.id

    @property
    def title(self) -> str:
        return self.meta.title

    @property
    def family(self) -> str:
        return self.meta.family

    @property
    def severity(self) -> str:
        return self.meta.severity

    @property
    def owasp_label(self) -> str:
        code = self.refs.owasp_llm
        return f"{code}:2025 {OWASP_LLM_TOP10.get(code, '?')}"


TAXONOMY: list[ThreatEntry] = [ThreatEntry(m, _REFS[m.id]) for m in _ATTACKS if m.id in _REFS]
BY_ID: dict[str, ThreatEntry] = {e.id: e for e in TAXONOMY}


def owasp_coverage() -> dict[str, list[str]]:
    """OWASP-LLM category code -> module ids demonstrated for it."""
    out: dict[str, list[str]] = {code: [] for code in OWASP_LLM_TOP10}
    for entry in TAXONOMY:
        out[entry.refs.owasp_llm].append(entry.id)
    return out


def as_rows() -> list[dict[str, str]]:
    """Flat, serialization-friendly rows (used by docs + the GUI table)."""
    return [
        {
            "num": e.num,
            "id": e.id,
            "title": e.title,
            "family": e.family,
            "severity": e.severity,
            "owasp_llm": e.owasp_label,
            "cwe": e.refs.cwe,
            "cwe_name": e.refs.cwe_name,
            "atlas": e.refs.atlas or "—",
            "guardrail": e.meta.guardrail or "—",
        }
        for e in TAXONOMY
    ]


def as_markdown_table() -> str:
    """The taxonomy as a GitHub-Markdown table (used by docs/TAXONOMY.md)."""
    lines = [
        "| # | Threat | Family | Sev | OWASP LLM (2025) | CWE | MITRE ATLAS | Guardrail |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in as_rows():
        lines.append(
            f"| {r['num']} | {r['title']} | {r['family']} | {r['severity']} | "
            f"{r['owasp_llm']} | {r['cwe']} | {r['atlas']} | `{r['guardrail']}` |"
        )
    return "\n".join(lines)
