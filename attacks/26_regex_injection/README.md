# 26 — Regex injection

## The flaw
```python
def search_logs(pattern: str) -> str:
    hits = [line for line in _LOGS if re.search(pattern, line)]   # caller's regex
```
The caller supplies the *pattern*, which is compiled as a regular expression. That's
a query language over your data: `.*` matches everything, alternation reaches other
records, and nested quantifiers (`(a+)+$`) can hang the process (ReDoS).

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/26_regex_injection/exploit.py
```
The pattern `.*` matches every log line, leaking the hidden admin recovery code
`REGEX-SECRET-3310`.

## Impact
Information disclosure (read records you were never meant to match) and, with a
crafted catastrophic pattern, denial of service.

## Defense → [`guardrails.saferegex`](../../purplemcp/guardrails/saferegex.py)
`literal_search` runs `re.escape` over the caller's text, so `.*` matches the two
literal characters `.` and `*` — which appear in no line — and the secret stays
hidden. Hardened twin:
[`safe_log_search.py`](../../defense/hardened_servers/safe_log_search.py).
