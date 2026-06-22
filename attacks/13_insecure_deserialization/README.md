# 13 — Insecure deserialization

## The flaw
```python
data = pickle.loads(base64.b64decode(blob))   # blob comes from the caller
```
`pickle` isn't a data format — it's a tiny VM that **executes code while loading**
via an object's `__reduce__`. A crafted blob can make unpickling call `eval`,
`os.system`, or anything else. The same holds for `yaml.load` (without
`SafeLoader`), `cloudpickle`, `jsonpickle`, and Python's `marshal`.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/13_insecure_deserialization/exploit.py
```
The blob contains no `PWN42` literal — yet the result is `…'PWN42'`, because the
expression `'PWN' + str(6*7)` was **evaluated on the server** during unpickling.

## Impact
Remote code execution as the server's user — the same blast radius as command
injection (attack 03), reached through a tool that looks like it just "loads
state".

## Defense → [`guardrails.serialization`](../../purplemcp/guardrails/serialization.py)
- **Never deserialize untrusted data with pickle/yaml/marshal.** Use **JSON**,
  which represents values but can't call code.
- `guardrails.safe_loads` is JSON-only by construction, refuses pickle streams
  (`looks_like_pickle`), and can enforce the expected top-level type.
- **Validate the shape** after parsing before trusting it. Hardened twin:
  [`safe_state_loader.py`](../../defense/hardened_servers/safe_state_loader.py).
