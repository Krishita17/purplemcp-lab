# 09 — Data exfiltration

## The flaw
Any tool that can send data outward — "backup", "share", "webhook", "post to
Slack", even a URL in an image markdown — is an exfiltration channel if it isn't
constrained. Here, `backup_note(content, endpoint)` will POST to *any* endpoint,
with no approval and no scrubbing. Chain it with prompt injection (02) and a
malicious document tells the agent to "back up" your secrets to the attacker.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/09_data_exfiltration/exploit.py
```
The fake attacker sink captures the "private customer record" the tool sent.

## Impact
Quiet, ongoing data theft that looks like normal tool use. Often the *final
stage* of an attack that began with injection or poisoning.

## Defense
- **Allowlist destinations** — outbound tools may only talk to known-good hosts.
- **Human approval** for outbound sends ([`guardrails.approval`](../../purplemcp/guardrails/approval.py)),
  so a hijacked agent can't ship data silently.
- **Scrub** content before it leaves ([`guardrails.scrub`](../../purplemcp/guardrails/secrets.py)).
- **Egress monitoring**: log every outbound destination and alert on new ones.
