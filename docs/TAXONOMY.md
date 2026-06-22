# PurpleMCP — threat taxonomy

All **25** attack/defense modules mapped to the **OWASP Top 10 for LLM Applications (2025)**, **CWE**, and **MITRE ATLAS**. This file is generated from [`purplemcp/taxonomy.py`](../purplemcp/taxonomy.py) — run `python scripts/gen_taxonomy.py` to refresh, or `purplemcp taxonomy` to print it.

| # | Threat | Family | Sev | OWASP LLM (2025) | CWE | MITRE ATLAS | Guardrail |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 01 | Tool Poisoning | MCP-specific | HIGH | LLM01:2025 Prompt Injection | CWE-1427 | AML.T0051 LLM Prompt Injection | `descriptions.py` |
| 02 | Indirect Prompt Injection | MCP-specific | HIGH | LLM01:2025 Prompt Injection | CWE-1427 | AML.T0051 LLM Prompt Injection (Indirect) | `descriptions.py` |
| 07 | Rug Pull | MCP-specific | HIGH | LLM03:2025 Supply Chain | CWE-494 | AML.T0053 LLM Plugin Compromise | `descriptions.py` |
| 12 | Tool Shadowing | MCP-specific | HIGH | LLM03:2025 Supply Chain | CWE-706 | AML.T0053 LLM Plugin Compromise | `registry.py` |
| 17 | Output / Log Injection | MCP-specific | HIGH | LLM05:2025 Improper Output Handling | CWE-117 | — | `framing.py` |
| 03 | Command Injection | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-78 | — | `exec.py` |
| 04 | Path Traversal | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-22 | — | `paths.py` |
| 05 | Server-Side Request Forgery | Classic appsec, now model-reachable | HIGH | LLM06:2025 Excessive Agency | CWE-918 | — | `net.py` |
| 06 | Token Theft / Confused Deputy | Classic appsec, now model-reachable | HIGH | LLM02:2025 Sensitive Information Disclosure | CWE-522 | AML.T0057 LLM Data Leakage | `secrets.py` |
| 08 | Excessive Permissions | Classic appsec, now model-reachable | MEDIUM | LLM06:2025 Excessive Agency | CWE-250 | — | `approval.py` |
| 09 | Data Exfiltration | Classic appsec, now model-reachable | HIGH | LLM02:2025 Sensitive Information Disclosure | CWE-200 | AML.T0057 LLM Data Leakage | `secrets.py` |
| 10 | SQL Injection | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-89 | — | `sqlsafe.py` |
| 11 | Template / Format-String Injection | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-1336 | — | `templating.py` |
| 13 | Insecure Deserialization | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-502 | — | `serialization.py` |
| 14 | Broken Access Control (IDOR) | Classic appsec, now model-reachable | HIGH | LLM06:2025 Excessive Agency | CWE-639 | — | `authz.py` |
| 15 | Unrestricted File Write | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-73 | — | `paths.py` |
| 16 | Weak Randomness / Predictable Tokens | Classic appsec, now model-reachable | HIGH | LLM06:2025 Excessive Agency | CWE-330 | — | `tokens.py` |
| 18 | Eval / Expression Injection | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-95 | — | `safe_eval.py` |
| 19 | Zip Slip / Archive Traversal | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-22 | — | `paths.py` |
| 20 | Mass Assignment / Priv-Esc | Classic appsec, now model-reachable | HIGH | LLM06:2025 Excessive Agency | CWE-915 | — | `authz.py` |
| 21 | CSV / Formula Injection | Classic appsec, now model-reachable | MEDIUM | LLM05:2025 Improper Output Handling | CWE-1236 | — | `csvsafe.py` |
| 22 | Unbounded Output / Context Flooding | Classic appsec, now model-reachable | MEDIUM | LLM10:2025 Unbounded Consumption | CWE-400 | — | `limits.py` |
| 23 | Argument / Flag Injection | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-88 | — | `argv.py` |
| 24 | Insecure JWT Verification | Classic appsec, now model-reachable | HIGH | LLM06:2025 Excessive Agency | CWE-347 | — | `jwtsafe.py` |
| 25 | XML External Entity (XXE) | Classic appsec, now model-reachable | HIGH | LLM05:2025 Improper Output Handling | CWE-611 | — | `safexml.py` |

## OWASP LLM Top 10 coverage — 6/10 categories

- ✅ **LLM01:2025 Prompt Injection** (2) — tool-poisoning, indirect-injection
- ✅ **LLM02:2025 Sensitive Information Disclosure** (2) — token-theft, data-exfiltration
- ✅ **LLM03:2025 Supply Chain** (2) — rug-pull, tool-shadowing
- ⬜ **LLM04:2025 Data and Model Poisoning** (0) — _(not yet demonstrated)_
- ✅ **LLM05:2025 Improper Output Handling** (12) — output-injection, command-injection, path-traversal, sql-injection, template-injection, insecure-deserialization, unrestricted-file-write, eval-injection, zip-slip, csv-injection, argument-injection, xxe
- ✅ **LLM06:2025 Excessive Agency** (6) — ssrf, excessive-permissions, broken-access-control, weak-randomness, mass-assignment, jwt-none
- ⬜ **LLM07:2025 System Prompt Leakage** (0) — _(not yet demonstrated)_
- ⬜ **LLM08:2025 Vector and Embedding Weaknesses** (0) — _(not yet demonstrated)_
- ⬜ **LLM09:2025 Misinformation** (0) — _(not yet demonstrated)_
- ✅ **LLM10:2025 Unbounded Consumption** (1) — unbounded-output
