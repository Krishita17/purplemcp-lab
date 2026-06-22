# 04 — Attack catalog

The runnable modules live in [`../attacks`](../attacks) (each has a vulnerable
server, an exploit, and a writeup). This page is the conceptual map.

> Lab only. `export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"`. See
> [../ETHICS.md](../ETHICS.md).

## Two families of MCP risk

**A) MCP-specific** — the protocol creates these because tool *metadata* and tool
*output* flow into the model as trusted text:

| # | Attack | One-liner |
| --- | --- | --- |
| [01](../attacks/01_tool_poisoning/) | Tool poisoning | hidden instructions in a tool description |
| [02](../attacks/02_indirect_prompt_injection/) | Indirect injection | instructions hidden in tool *output* / fetched data |
| [07](../attacks/07_rug_pull/) | Rug pull | a tool's definition mutates after you trusted it |
| [12](../attacks/12_tool_shadowing/) | Tool shadowing | two servers expose one tool name; the malicious twin wins |

**B) Classic appsec, now reachable by the model** — old bugs, new caller. The
model (or whoever injects into it) can now trigger them:

| # | Attack | One-liner |
| --- | --- | --- |
| [03](../attacks/03_command_injection/) | Command injection | `shell=True` on model input |
| [04](../attacks/04_path_traversal/) | Path traversal | unchecked file path escapes the root |
| [05](../attacks/05_ssrf/) | SSRF | unchecked URL hits internal/metadata hosts |
| [06](../attacks/06_token_theft/) | Token theft / confused deputy | server leaks or passes through its credentials |
| [08](../attacks/08_excessive_permissions/) | Excessive permissions | over-broad scope magnifies every other bug |
| [09](../attacks/09_data_exfiltration/) | Data exfiltration | a tool ships data to an attacker endpoint |
| [10](../attacks/10_sql_injection/) | SQL injection | query built by string-formatting model input |
| [11](../attacks/11_template_injection/) | Template injection | `str.format`/SSTI on a caller-controlled template |
| [13](../attacks/13_insecure_deserialization/) | Insecure deserialization | `pickle.loads` of an attacker blob = RCE |
| [14](../attacks/14_broken_access_control/) | Broken access control (IDOR) | returns any record by id, no ownership check |
| [15](../attacks/15_unrestricted_file_write/) | Unrestricted file write | write path escapes the root (persistence) |
| [16](../attacks/16_weak_randomness/) | Weak randomness | predictable tokens from time/PRNG |
| [17](../attacks/17_output_injection/) | Output / log injection | echoed tool output forges lines / control chars |

## The killer combination

The scary chains mix the families: an **indirect injection** (02) in a web page
tells the agent to use an **over-permissioned** (08) file tool to read secrets,
then an unconstrained **exfiltration** (09) tool to send them out — no human ever
issued a malicious instruction. Defense therefore has to be layered, not a single
filter.

Next: [05 — defense playbook](05-defense-playbook.md).
