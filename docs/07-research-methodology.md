# Research methodology

PurpleMCP is built to be a *reproducible research artifact* for studying the
security of the Model Context Protocol (MCP), not only a teaching demo. This
document describes the threat model, the experimental design, the metrics, and
how to reproduce every number.

## 1. Threat model

MCP gives an LLM **agency**: a host connects a model to *servers* that expose
*tools*, *resources*, and *prompts*, and the model decides which to invoke. That
creates three trust boundaries an attacker can target:

1. **Model ← server metadata.** Tool *descriptions* are fed to the model as
   trusted context (tool poisoning, rug pull, tool shadowing).
2. **Model ← tool results.** Returned data is attacker-influenced but read by the
   model as if trustworthy (indirect prompt injection, output/log injection).
3. **System ← tool actions.** The model's arguments flow into real sinks —
   shells, file systems, databases, HTTP, deserializers (the classic appsec
   bug classes, now reachable by a model).

PurpleMCP instantiates each boundary as a **vulnerable server + exploit** and a
**hardened twin** that imports a reusable guardrail.

## 2. Threat taxonomy

Every module is mapped to the community frameworks so results are comparable and
citable. The mapping is defined in [`purplemcp/taxonomy.py`](../purplemcp/taxonomy.py)
(the single source of truth) and reproduced here:

<!-- generated from purplemcp.taxonomy.as_rows() -->
| # | Attack | Family | OWASP-LLM (2025) | CWE | MITRE ATLAS | Guardrail |
| --- | --- | --- | --- | --- | --- | --- |
| 01 | Tool Poisoning | MCP | LLM01:2025 Prompt Injection | CWE-1427 | AML.T0051 LLM Prompt Injection | `descriptions.py` |
| 02 | Indirect Prompt Injection | MCP | LLM01:2025 Prompt Injection | CWE-1427 | AML.T0051 LLM Prompt Injection (Indirect) | `descriptions.py` |
| 07 | Rug Pull | MCP | LLM03:2025 Supply Chain | CWE-494 | AML.T0053 LLM Plugin Compromise | `descriptions.py` |
| 12 | Tool Shadowing | MCP | LLM03:2025 Supply Chain | CWE-706 | AML.T0053 LLM Plugin Compromise | `registry.py` |
| 17 | Output / Log Injection | MCP | LLM05:2025 Improper Output Handling | CWE-117 | — | `framing.py` |
| 03 | Command Injection | AppSec | LLM05:2025 Improper Output Handling | CWE-78 | — | `exec.py` |
| 04 | Path Traversal | AppSec | LLM05:2025 Improper Output Handling | CWE-22 | — | `paths.py` |
| 05 | Server-Side Request Forgery | AppSec | LLM06:2025 Excessive Agency | CWE-918 | — | `net.py` |
| 06 | Token Theft / Confused Deputy | AppSec | LLM02:2025 Sensitive Information Disclosure | CWE-522 | AML.T0057 LLM Data Leakage | `secrets.py` |
| 08 | Excessive Permissions | AppSec | LLM06:2025 Excessive Agency | CWE-250 | — | `approval.py` |
| 09 | Data Exfiltration | AppSec | LLM02:2025 Sensitive Information Disclosure | CWE-200 | AML.T0057 LLM Data Leakage | `secrets.py` |
| 10 | SQL Injection | AppSec | LLM05:2025 Improper Output Handling | CWE-89 | — | `sqlsafe.py` |
| 11 | Template / Format-String Injection | AppSec | LLM05:2025 Improper Output Handling | CWE-1336 | — | `templating.py` |
| 13 | Insecure Deserialization | AppSec | LLM05:2025 Improper Output Handling | CWE-502 | — | `serialization.py` |
| 14 | Broken Access Control (IDOR) | AppSec | LLM06:2025 Excessive Agency | CWE-639 | — | `authz.py` |
| 15 | Unrestricted File Write | AppSec | LLM05:2025 Improper Output Handling | CWE-73 | — | `paths.py` |
| 16 | Weak Randomness / Predictable Tokens | AppSec | LLM06:2025 Excessive Agency | CWE-330 | — | `tokens.py` |
| 18 | Eval / Expression Injection | AppSec | LLM05:2025 Improper Output Handling | CWE-95 | — | `safe_eval.py` |
| 19 | Zip Slip / Archive Traversal | AppSec | LLM05:2025 Improper Output Handling | CWE-22 | — | `paths.py` |
| 20 | Mass Assignment / Priv-Esc | AppSec | LLM06:2025 Excessive Agency | CWE-915 | — | `authz.py` |
| 21 | CSV / Formula Injection | AppSec | LLM05:2025 Improper Output Handling | CWE-1236 | — | `csvsafe.py` |
| 22 | Unbounded Output / Context Flooding | AppSec | LLM10:2025 Unbounded Consumption | CWE-400 | — | `limits.py` |
| 23 | Argument / Flag Injection | AppSec | LLM05:2025 Improper Output Handling | CWE-88 | — | `argv.py` |

**OWASP-LLM coverage:** the 23 modules exercise 6 of the 10 categories — LLM01,
LLM02, LLM03, LLM05, LLM06, LLM10. LLM04 (data/model poisoning), LLM07 (system-prompt
leakage), LLM08 (vector/embedding) and LLM09 (misinformation) are **out of scope**
today and noted under *Limitations*.

## 3. Experiment design

PurpleMCP-Bench ([`purplemcp/benchmark.py`](../purplemcp/benchmark.py),
`purplemcp bench`) runs two measurements:

### M1 — Guardrail effectiveness (deterministic)
For each red/blue case, the **same attack payload** is sent to the vulnerable
server and to its hardened twin over the real MCP protocol (no LLM). A transparent
verdict function (refusal-phrase + attack-success "proof" signatures, see
`gui.catalog.judge`) labels each result. A case is **fixed** iff the attack is
*exploitable/exposed* on the vulnerable server **and** *blocked* on the twin.

- Metric: `effectiveness = fixed_cases / total_cases`.
- Deterministic and offline → identical across runs and machines.

### M2 — Model susceptibility (optional, `--provider`)
For the model-in-the-loop attacks (tool poisoning, indirect injection), a real
agent is driven against the vulnerable server with a fixed benign prompt; a
detector records whether the model **complied** with the injected instruction
(e.g. called `export_telemetry` / `run_maintenance`). Outcomes vary by model and
run — that variance is the experimental signal, not noise to be removed.

## 4. Reproducibility

```bash
pip install -e ".[dev]"

# M1 — deterministic; writes results/*.json + *.md
purplemcp bench

# M2 — add a provider (local Ollama needs no key)
purplemcp bench --provider ollama --model llama3.1

# Static analysis as SARIF (the same report CI uploads to code scanning)
purplemcp scan attacks --format sarif -o purplemcp.sarif

pytest -q          # the guardrail tests prove every defense blocks its attack
```

A reference run is committed at [`results/guardrail-benchmark.md`](../results/guardrail-benchmark.md).
Every vulnerable component refuses to start without the explicit lab token, so
nothing dangerous runs by accident (see [ETHICS.md](../ETHICS.md)).

## 5. Metrics, precisely

- **Exploited (vulnerable):** the attack-success proof appears, or no guardrail
  phrase is present (`EXPLOITED` / `EXPOSED`).
- **Blocked (hardened):** the proof is absent and/or a refusal phrase is present.
- **Guardrail effectiveness:** % of cases that are both exploitable and blocked.
- **Model manipulated:** the injected tool/action was invoked (M2).

## 6. Limitations & threats to validity

- The verdict heuristic is intentionally simple and string-based; it is auditable
  but could mislabel a pathological tool output. Excerpts are stored so every
  verdict is checkable.
- M2 covers only two attacks and small/instruct models behave inconsistently; it
  is a *probe*, not a leaderboard.
- Five OWASP-LLM categories are unmodeled (see §2).
- Network-dependent cases (SSRF, exfiltration) are judged on *refusal vs attempt*
  offline; the contrast holds without egress but the full leak needs a network.

## 7. Ethics

All offensive code is intentionally vulnerable, localhost-only, gated behind
`PURPLEMCP_LAB_ENABLED`, and exfiltrates only to a fake local sink. Use only on
systems you own. See [ETHICS.md](../ETHICS.md).

## 8. Related work & references

- OWASP Top 10 for LLM Applications (2025) — <https://genai.owasp.org/>
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems) — <https://atlas.mitre.org/>
- MITRE CWE — <https://cwe.mitre.org/>
- Model Context Protocol specification — <https://modelcontextprotocol.io/>
- "Zip Slip" (Snyk, 2018); spreadsheet/CSV formula injection (OWASP).
