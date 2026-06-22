# The MCP security scanner

`purplemcp scan` flags risky MCP servers — before you run or trust them. The code
is [`../../purplemcp/scanner.py`](../../purplemcp/scanner.py).

## Two modes

### Static (scan source)
```bash
purplemcp scan attacks/                                   # a whole tree
purplemcp scan attacks/03_command_injection/vulnerable_server.py   # one file
```
Parses Python with `ast` and flags:

| rule | severity | what |
| --- | --- | --- |
| `command-injection` | HIGH | `subprocess(..., shell=True)` |
| `code-exec` | HIGH | `eval` / `exec` / `os.system` / `os.popen` |
| `deserialization` | HIGH | `pickle.loads`, `yaml.load` without SafeLoader |
| `ssrf` | MED/HIGH | `httpx`/`requests`/`urllib` fetches (HIGH if redirects followed) |
| `path-traversal` | LOW | `open()` on a computed (non-constant) path |
| `hardcoded-secret` | HIGH | string literal that matches a secret shape |
| `suspicious-string` | MED | long literal that reads like an instruction / hides Unicode |

### Dynamic (inspect a live server)
```bash
purplemcp scan --server calculator
```
Connects, lists tools, and flags `poisoned-description`, `hidden-unicode`, and
`secret-in-description`. This catches what static analysis can't — e.g. a
description assembled at runtime (see attack 01).

## Use both
They're complementary: static reads code paths that may never run; dynamic reads
the *actual* tool metadata a model would receive. Run static in CI on your own
servers, run dynamic against any third-party server before connecting it.

## Limitations
This is an explainable teaching scanner, not a full SAST product. It uses
heuristics (it can miss obfuscated code and can false-positive on safe network
calls). Treat findings as "look here", not "proven exploit". Pair it with the
[checklist](../checklist.md).
