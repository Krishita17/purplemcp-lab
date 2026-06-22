# 🔵 Defense

This is the blue-team half of the lab. Every attack in [`../attacks`](../attacks)
has its fix here. The philosophy is **defense in depth**: no single control is
trusted to be perfect, so we layer input validation, least privilege, and
monitoring.

## The reusable guardrails library

The actual hardening code lives in the installable package so *your* servers can
import it too: [`../purplemcp/guardrails/`](../purplemcp/guardrails/).

| Primitive | Stops | Attack |
| --- | --- | --- |
| `safe_resolve` | path traversal | [04](../attacks/04_path_traversal/) |
| `safe_get` / `assert_url_allowed` | SSRF | [05](../attacks/05_ssrf/) |
| `safe_run` | command injection | [03](../attacks/03_command_injection/) |
| `sanitize_description` / `find_injection` / `has_hidden_unicode` | tool poisoning, indirect injection | [01](../attacks/01_tool_poisoning/), [02](../attacks/02_indirect_prompt_injection/) |
| `tool_fingerprint` / `ToolPinner` | rug pulls | [07](../attacks/07_rug_pull/) |
| `scrub` / `find_secrets` | credential leakage | [06](../attacks/06_token_theft/), [09](../attacks/09_data_exfiltration/) |
| `require` (approval) | unsafe autonomous actions | [02](../attacks/02_indirect_prompt_injection/), [09](../attacks/09_data_exfiltration/) |
| `RateLimiter` | abuse / runaway loops | cross-cutting |

## Hardened server twins

Full, runnable servers showing the fix in the same shape as the vulnerable one,
in [`hardened_servers/`](hardened_servers/):

| Attack | Hardened twin | Fix |
| --- | --- | --- |
| 03 command injection | `safe_nettools.py` | `safe_run` (no shell, allowlist) |
| 04 path traversal | `safe_docreader.py` | `safe_resolve` (confine to root) |
| 05 SSRF | `safe_fetcher.py` | `safe_get` (block private IPs, no redirects) |
| 06 token theft | `safe_crm.py` | `scrub` output + destination allowlist |
| 09 exfiltration | `safe_backup.py` | allowlist + scrub + approval gate |

## See it: red vs blue, side by side

```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python defense/compare.py
```
Runs the same malicious input against each vulnerable server and its hardened
twin. Red leaks; blue refuses.

## Scan before you trust

```bash
purplemcp scan attacks/                 # static analysis of source
purplemcp scan --server calculator      # dynamic inspection of a live server
```
See [`scanner/README.md`](scanner/README.md).

## The principles (in priority order)

1. **Treat all model/tool input and output as untrusted** — descriptions, tool
   results, file contents, web pages. Scan and frame accordingly.
2. **Validate at the boundary** — confine paths, allowlist hosts/executables,
   parameterize queries. Never build a shell/SQL string from input.
3. **Least privilege** — the narrowest root, scope, and token each server needs.
   Separate servers for separate trust levels.
4. **Human in the loop** for high-impact actions (delete, send, pay, deploy).
5. **No secrets in tool surfaces** — not in descriptions, not in output. Scrub as
   defense in depth; don't pass tokens through to caller-named destinations.
6. **Pin and re-verify** tool definitions; "approved once" is not "safe forever".
7. **Constrain egress** — allowlist outbound destinations and log them.
8. **Rate-limit and monitor** — cap blast radius, alert on anomalies.

Checklist: [`checklist.md`](checklist.md) · Catalog: [`../attacks`](../attacks)
