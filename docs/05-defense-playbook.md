# 05 — Defense playbook

The hardening code lives in [`../purplemcp/guardrails`](../purplemcp/guardrails)
and the hardened servers in [`../defense`](../defense). This page is the strategy.

## Map: attack → guardrail

| Attack | Primitive | Idea |
| --- | --- | --- |
| Tool poisoning (01) | `sanitize_description`, `find_injection`, `has_hidden_unicode` | scrub + flag metadata before the model sees it |
| Indirect injection (02) | `find_injection` on **output** + `require` (approval) | treat tool output as untrusted; gate actions |
| Command injection (03) | `safe_run` | argv list, no shell, executable allowlist |
| Path traversal (04) | `safe_resolve` | confine to a root; reject `..`/absolute/symlink-escape |
| SSRF (05) | `safe_get` / `assert_url_allowed` | block private IPs, no redirects, host allowlist |
| Token theft (06) | `scrub`, destination allowlist | never emit/passthrough secrets |
| Rug pull (07) | `tool_fingerprint`, `ToolPinner` | pin definitions; re-verify; re-approve on change |
| Excessive perms (08) | least privilege | narrowest root/scope/token; separate servers |
| Exfiltration (09) | allowlist + `require` + `scrub` | constrain egress; approve; redact |

## Defense in depth, in layers

1. **Input boundary** — validate/confine/allowlist everything from the model.
2. **Tool design** — no shell, no eval, parameterized queries, native libs over
   shelling out.
3. **Privilege** — least scope; one trust level per server; don't leak the env.
4. **Trust verification** — scan + pin tool definitions; re-check on connect.
5. **Human control** — approval gates on high-impact tools; step caps; kill
   switch.
6. **Output & egress** — scrub secrets; allowlist and log outbound destinations.
7. **Monitoring** — audit every call; alert on new egress hosts / volume spikes.

## Prove it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python defense/compare.py            # vulnerable vs hardened, side by side
purplemcp scan attacks/              # static findings
pytest -q                            # the guardrails block the attacks
```

Checklist for PRs: [../defense/checklist.md](../defense/checklist.md).
