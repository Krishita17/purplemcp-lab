# 06 — Token theft / confused deputy

## The flaw
MCP servers often hold credentials (an API token, an OAuth access token, a DB
password). Two common ways they leak:

1. **Direct leak** — a "debug"/"status"/"config" tool returns the secret in its
   output, where the model (and its logs, and attack 02's injected instructions)
   can grab it.
2. **Confused deputy / token passthrough** — a tool attaches the server's secret
   to a request whose *destination is controlled by the caller*. Point it at an
   attacker's URL and the server faithfully delivers its own credential.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/06_token_theft/exploit.py
```
You'll see the token printed by `get_debug_info`, and the **fake attacker sink
capture the `Authorization: Bearer …` header** sent by `proxy_request`.
(The token is a fake placeholder.)

## Impact
Whoever steals the token inherits the server's access — to the CRM, the cloud
account, the database. Tokens are the keys to the kingdom.

## Defense → [`guardrails.secrets`](../../purplemcp/guardrails/secrets.py)
- **Never** return secrets from tools; `scrub` output as defense in depth.
- **Allowlist destinations** for authenticated requests; never send credentials
  to a caller-supplied host.
- **Least-privilege, short-lived tokens** so a leak is small and expires.
- Don't pass the user's token through to downstream services (the MCP spec calls
  this out explicitly as token passthrough — don't do it).
