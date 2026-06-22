# 15 — Unrestricted file write

## The flaw
```python
full = os.path.join(ROOT, path)   # path from the model
Path(full).write_text(content)
```
The write-side twin of path traversal (attack 04). `path = "../../.zshrc"` (or an
absolute path) walks out of the notes root, so the tool can **overwrite** files —
shell startup scripts, cron/agent configs, SSH `authorized_keys` — turning a
"save a note" tool into a persistence and code-execution primitive.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/15_unrestricted_file_write/exploit.py
```
The exploit writes to `../15_ESCAPED_PROOF.txt` — landing **outside** the notes
root (but safely inside the repo sandbox) to prove the escape without touching any
real file.

## Impact
Arbitrary file write → persistence (modify `~/.zshrc`, drop a launch agent),
config tampering, or RCE if you can write to a location that later gets executed.

## Defense → [`guardrails.paths`](../../purplemcp/guardrails/paths.py)
- **Confine writes** with the same `safe_resolve(root, path, must_exist=False)`
  used for reads — `..`, absolute paths, and escaping symlinks are rejected.
- Additionally allowlist extensions/subdirs the tool may write, and never write to
  locations that are later executed. Hardened twin:
  [`safe_writer.py`](../../defense/hardened_servers/safe_writer.py).
