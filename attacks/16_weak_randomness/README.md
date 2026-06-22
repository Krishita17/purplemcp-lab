# 16 — Weak randomness / predictable tokens

## The flaw
```python
token = hashlib.md5(f"{user}:{int(time.time())}".encode()).hexdigest()[:16]
```
The token looks random but its only entropy is the current second, and the recipe
is guessable. An attacker who knows the username and the approximate time can
regenerate the exact token offline — no secret required. The same bug appears with
`random` (a non-cryptographic PRNG), incremental ids, or `uuid1` (time/MAC based).

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/16_weak_randomness/exploit.py
```
The exploit brute-forces a ±3 second window and **reproduces the server's token**
— proof it's forgeable.

## Impact
Account takeover: forge password-reset tokens, session ids, or API keys. Predict
"unguessable" values and skip authentication entirely.

## Defense → [`guardrails.tokens`](../../purplemcp/guardrails/tokens.py)
- **Use a CSPRNG.** `guardrails.new_token()` wraps `secrets.token_urlsafe(32)`
  (256 bits) — no recipe, no clock dependence.
- **Compare in constant time** (`guardrails.constant_time_compare`) so a check
  can't be brute-forced via timing. Never use `random`, `time`, or `uuid1` for
  anything security-sensitive. Hardened twin:
  [`safe_token_issuer.py`](../../defense/hardened_servers/safe_token_issuer.py).
