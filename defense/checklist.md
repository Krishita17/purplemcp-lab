# MCP Security Checklist

A practical, copy-into-your-PR checklist. Grouped by what you're doing.

## ✍️ Building an MCP server

- [ ] **No shell.** No `shell=True`, `os.system`, `os.popen`, `eval`, `exec`.
      Use an argv list + executable allowlist (`guardrails.safe_run`).
- [ ] **Confine file paths** to a single root with `guardrails.safe_resolve`
      (rejects `..`, absolute paths, escaping symlinks).
- [ ] **SSRF-proof every outbound request** with `guardrails.safe_get`: http(s)
      only, no private/loopback/link-local IPs, no redirect-following, size cap.
- [ ] **Parameterize all queries** (SQL `?` placeholders, etc.). Never format
      input into a query string.
- [ ] **No secrets in tool descriptions or output.** Scrub output
      (`guardrails.scrub`) as defense in depth.
- [ ] **Descriptions are documentation, not instructions** — and contain no
      invisible Unicode (`has_hidden_unicode` should be False).
- [ ] **Least privilege**: scope the root / DB grant / token to the minimum.
- [ ] **Gate dangerous tools** (delete, send, pay, deploy) behind
      `guardrails.approval.require`.
- [ ] **Rate-limit** expensive or sensitive tools (`guardrails.RateLimiter`).
- [ ] **Validate every argument** (types, ranges, enums) — don't trust the model.
- [ ] Run `purplemcp scan path/to/server.py` and fix HIGH/MEDIUM findings.

## 🔌 Connecting / installing a third-party server

- [ ] **Read the actual tool definitions**, including hidden characters
      (`purplemcp scan --server …`). Don't trust the marketing name.
- [ ] **Pin definitions** (`tool_fingerprint`) and alert on changes (rug pull).
- [ ] **Vet the source/publisher**; pin a version or commit hash.
- [ ] **Pass only the env vars the server needs** — not your whole environment.
- [ ] **Isolate** untrusted servers (container, separate user, no network if
      possible).
- [ ] Assume any data a tool returns may carry injected instructions.

## 🛟 Operating (runtime)

- [ ] **Human approval** for high-impact actions stays on.
- [ ] **Egress allowlist + logging** for every outbound destination.
- [ ] **Audit log** every tool call (tool, args, result size, outcome).
- [ ] **Monitor** for anomalies: new egress hosts, sudden tool-call volume,
      secret-shaped strings in output.
- [ ] **Short-lived, scoped tokens**; rotate; never pass them through to
      caller-controlled destinations.
- [ ] **Keep humans able to interrupt** the agent loop (step caps, kill switch).

## 🧠 Model / host configuration

- [ ] Scan tool **descriptions and output** for injection — not just one of them.
- [ ] Frame tool results to the model as untrusted data.
- [ ] Cap agent steps (`Agent(max_steps=…)`) to bound runaway loops.
- [ ] Prefer the fewest tools necessary in any one session.
