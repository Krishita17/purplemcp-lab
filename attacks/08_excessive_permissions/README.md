# 08 — Excessive permissions / over-broad scope

## The flaw
This one is subtle: the server is **traversal-safe** (it uses `safe_resolve`).
The bug is the *grant*. A "project reader" was rooted at a directory that also
contains an unrelated `finance/` folder. Confinement works perfectly — and the
tool still reads salaries, because the scope it was given was too wide.

The same mistake shows up everywhere in MCP:
- a filesystem server rooted at `$HOME` instead of one project,
- a database tool with read/write on every table instead of one,
- an OAuth token with `repo` scope when it only needed `read:issues`,
- a server that inherits the whole environment (every API key you have).

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/08_excessive_permissions/exploit.py
```
The reader returns `finance/salaries.csv` (fake data) — outside its job, inside
its scope.

## Impact
Every other bug gets bigger. A prompt injection (02) or a small logic flaw turns
into total compromise because the blast radius was never contained.

## Defense
- **Least privilege**: give each server the narrowest root / scope / token set it
  needs. Here, root it at `project/`, not the parent.
- **Don't leak the environment**: pass only the env vars a server needs, not all
  of `os.environ` (PurpleMCP's host merges env for convenience — a hardened
  deployment would allowlist).
- **Separate servers for separate trust levels** instead of one do-everything
  server.
