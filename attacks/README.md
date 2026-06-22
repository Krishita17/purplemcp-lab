# 🔴 The Attack Lab

> [!CAUTION]
> Everything in this directory is **intentionally vulnerable** and exists only
> to teach. It runs on `localhost`, refuses to start without an opt-in flag, and
> sends "stolen" data only to a **fake local sink**. Read [../ETHICS.md](../ETHICS.md).
> Only ever run this against systems you own.

## Enable the lab

```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
```

Without that, every vulnerable server and exploit exits immediately.

## How a module is laid out

Each `NN_*/` folder is one attack and contains the same three files:

| File | What it is |
| --- | --- |
| `vulnerable_server.py` | An MCP server with the flaw built in |
| `exploit.py` | A runnable script that performs the attack and prints what it got |
| `README.md` | The writeup: mechanism, impact, and the link to its defense |

Run an exploit like:

```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/03_command_injection/exploit.py
```

The exploits are **deterministic** — they demonstrate the flaw by driving the
real MCP protocol, no API key or LLM required. Where an attack only fully lands
when an LLM "falls for it" (tool poisoning, indirect injection), the exploit
shows the exact malicious text the model would ingest and uses the guardrails to
flag it, so you see the mechanism without needing a model.

## The catalog

| # | Attack | Where the flaw lives | Defense |
| --- | --- | --- | --- |
| [01](01_tool_poisoning/) | Tool poisoning / line jumping | tool **description** | [`guardrails.descriptions`](../purplemcp/guardrails/descriptions.py) |
| [02](02_indirect_prompt_injection/) | Indirect prompt injection | tool **return data** | description scanning + output framing |
| [03](03_command_injection/) | Command injection | `shell=True` | [`guardrails.exec`](../purplemcp/guardrails/exec.py) |
| [04](04_path_traversal/) | Path traversal | unchecked file path | [`guardrails.paths`](../purplemcp/guardrails/paths.py) |
| [05](05_ssrf/) | SSRF | unchecked URL fetch | [`guardrails.net`](../purplemcp/guardrails/net.py) |
| [06](06_token_theft/) | Token theft / confused deputy | credential handling | [`guardrails.secrets`](../purplemcp/guardrails/secrets.py) + allowlist |
| [07](07_rug_pull/) | Rug pull (definition mutation) | tool changing after trust | [`ToolPinner`](../purplemcp/guardrails/descriptions.py) |
| [08](08_excessive_permissions/) | Excessive permissions | over-broad scope | least privilege + scoping |
| [09](09_data_exfiltration/) | Data exfiltration | tool sends data out | allowlist + [`approval`](../purplemcp/guardrails/approval.py) + [`scrub`](../purplemcp/guardrails/secrets.py) |
| [10](10_sql_injection/) | SQL injection | query built from strings | parameterized queries + [`guardrails.sqlsafe`](../purplemcp/guardrails/sqlsafe.py) |
| [11](11_template_injection/) | Template / format-string injection | `.format` on caller input | [`guardrails.templating`](../purplemcp/guardrails/templating.py) |
| [12](12_tool_shadowing/) | Tool shadowing / name collision | two servers, one tool name | [`guardrails.registry`](../purplemcp/guardrails/registry.py) |
| [13](13_insecure_deserialization/) | Insecure deserialization | `pickle.loads` of input | [`guardrails.serialization`](../purplemcp/guardrails/serialization.py) |
| [14](14_broken_access_control/) | Broken access control (IDOR) | missing ownership check | [`guardrails.authz`](../purplemcp/guardrails/authz.py) |
| [15](15_unrestricted_file_write/) | Unrestricted file write | unchecked write path | [`guardrails.paths`](../purplemcp/guardrails/paths.py) |
| [16](16_weak_randomness/) | Weak randomness / tokens | `md5(user:time)` | [`guardrails.tokens`](../purplemcp/guardrails/tokens.py) |
| [17](17_output_injection/) | Output / log injection | echoed untrusted text | [`guardrails.framing`](../purplemcp/guardrails/framing.py) |
| [18](18_eval_injection/) | Eval / expression injection | `eval()` on input | [`guardrails.safe_eval`](../purplemcp/guardrails/safe_eval.py) |
| [19](19_zip_slip/) | Zip slip / archive traversal | trusted archive member names | [`guardrails.paths`](../purplemcp/guardrails/paths.py) |
| [20](20_mass_assignment/) | Mass assignment / priv-esc | `record.update(payload)` | [`guardrails.authz`](../purplemcp/guardrails/authz.py) |
| [21](21_csv_injection/) | CSV / formula injection | leading `=` in a cell | [`guardrails.csvsafe`](../purplemcp/guardrails/csvsafe.py) |

## The point: red → blue

Each attack here has a hardened twin in [`../defense/`](../defense/). The
intended workflow is to run the exploit, watch it succeed, then run the same
exploit against the hardened version and watch it fail. That pairing is the
whole reason this lab exists.
