# 19 — Zip slip / archive extraction traversal

## The flaw
```python
for member in zf.namelist():
    (OUT / member).write_bytes(zf.read(member))   # member can be '../../x'
```
Archive formats let an entry be named anything — including `../../../etc/cron.d/x`
or an absolute path. `zipfile.extractall()` and naive joins honour those names and
write **outside** the extraction directory. Same bug class as path traversal, but
the malicious path is hidden inside an archive.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/19_zip_slip/exploit.py
```
The archive contains a member `../19_ZIPSLIP_PROOF.txt`; the vulnerable tool
writes it one level **above** its unpack folder (harmlessly, inside the sandbox).

## Impact
Arbitrary file write → overwrite startup files / SSH keys / cron for persistence
and privilege escalation.

## Defense → [`guardrails.paths.safe_resolve`](../../purplemcp/guardrails/paths.py)
Resolve **every** member against the extraction root before writing and reject any
that escape (also covers absolute paths and symlinks). Never trust
`extractall()`. Hardened twin:
[`safe_unpacker.py`](../../defense/hardened_servers/safe_unpacker.py).
