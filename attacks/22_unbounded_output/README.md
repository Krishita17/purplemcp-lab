# 22 — Unbounded Output / Context Flooding

**Family:** Classic appsec, now model-reachable · **Severity:** MEDIUM
**OWASP-LLM:** LLM10 Unbounded Consumption · **CWE-400** Uncontrolled Resource Consumption

## The flaw

`dump_logs(lines)` returns exactly as many lines as the caller asks for, with no
ceiling:

```python
@mcp.tool()
def dump_logs(lines: int = 10) -> str:
    return _render(lines)        # VULNERABLE: caller dictates the response size
```

A tool result becomes part of the model's context. So a single
`dump_logs(lines=5_000_000)` — easily triggered by a prompt-injected instruction in
some other tool's output — forces the host to receive, buffer, and re-feed
**megabytes** of attacker-chosen text. The token budget is burned, the context
window is flooded, latency spikes, and the session can wedge. It's a denial-of-service
(and a cost attack) delivered entirely through a legitimate tool.

## Run it

```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/22_unbounded_output/exploit.py
```

One `dump_logs(lines=50_000)` call returns ~2 MB from a tool the model expected to
return a handful of lines.

## Impact

- **Availability** — floods the context window; can stall or crash the session.
- **Cost** — every flooded token is billed on metered models.
- **Amplification** — pairs with indirect prompt injection: untrusted data tells the
  model to request the flood.

## The defense

Cap every tool result at the boundary with
[`guardrails.cap_text`](../../purplemcp/guardrails/limits.py): truncate to a fixed
**byte** budget and append a clear marker so nothing vanishes silently. The hardened
twin is [`defense/hardened_servers/safe_logreader.py`](../../defense/hardened_servers/safe_logreader.py).

```python
from purplemcp.guardrails import cap_text

@mcp.tool()
def dump_logs(lines: int = 10) -> str:
    return cap_text(_render(lines), max_bytes=2 * 1024)
```

The Defense Lab's **Verify** replays `dump_logs(lines=50_000)` at both servers: the
vulnerable one returns the full flood (ending in the `EOF-LOG-MARKER` sentinel); the
hardened one returns a bounded, truncated response with the sentinel gone.
