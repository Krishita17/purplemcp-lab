# 04 — Path traversal

## The flaw
```python
full = os.path.join(ROOT, path)   # path comes from the model
open(full)
```
`os.path.join(ROOT, "../../../etc/passwd")` walks out of `ROOT`. Worse,
`os.path.join(ROOT, "/etc/passwd")` returns `/etc/passwd` — an absolute path
silently discards the root. Symlinks inside the root can also point outward.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/04_path_traversal/exploit.py
```
You'll see the reader return `/etc/hosts`, a file far outside its docs folder.
(We target `/etc/hosts` because it's harmless; `~/.ssh/id_rsa` would work too.)

## Impact
Read any file the server process can — config, credentials, source, other users'
data. If the tool also writes, traversal becomes arbitrary file *write*.

## Defense → [`guardrails.paths`](../../purplemcp/guardrails/paths.py)
`safe_resolve(root, user_path)` rejects absolute paths, normalizes `..`, follows
symlinks, and confirms the final path is still inside the root — raising
`PathTraversalError` otherwise. This is exactly what the clean
[`servers/filesystem`](../../servers/filesystem/server.py) uses.
