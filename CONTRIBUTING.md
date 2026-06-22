# Contributing to PurpleMCP

Thanks for helping make PurpleMCP a better place to learn MCP security! This guide
covers the dev setup and — most usefully — the exact recipe for adding a new
attack/defense module so it shows up everywhere (CLI, GUI, benchmark, taxonomy).

> [!IMPORTANT]
> PurpleMCP ships **intentionally vulnerable code** on purpose (everything under
> [`attacks/`](attacks/)). Read [ETHICS.md](ETHICS.md) and [SECURITY.md](SECURITY.md)
> first. All lab code must keep the safety guarantees below.

## Dev setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[gui,dev]"     # editable, with the desktop GUI + pytest
python -m pytest -q             # the suite must stay green
```

## Safety rules (non-negotiable for lab code)

Every intentionally-vulnerable server and exploit MUST:

1. **Gate on the opt-in flag** — call `require_lab()` from
   [`attacks/_lab/safety.py`](attacks/_lab/safety.py) at import, so it refuses to run
   unless `PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"`.
2. **Stay local** — bind only to `127.0.0.1`; "exfiltrate" only to the fake local
   sink ([`attacks/_lab/attacker_sink.py`](attacks/_lab/attacker_sink.py)).
3. **Use fake data** — never real secrets, never a real external host.
4. **Prove harmlessly** — the exploit demonstrates the flaw with a deterministic,
   harmless marker (e.g. `echo PWNED-$((6*7))`), never a destructive payload.

## Anatomy of a module

To add attack `NN` (next number), create these and register them:

| File | Purpose |
| --- | --- |
| `attacks/NN_name/vulnerable_server.py` | A FastMCP server with the flaw (lab-gated). |
| `attacks/NN_name/exploit.py` | A deterministic exploit driving the MCP protocol. |
| `attacks/NN_name/README.md` | The writeup: flaw, run, impact, defense. |
| `defense/hardened_servers/safe_*.py` | The hardened twin importing a guardrail. |
| `purplemcp/guardrails/*.py` | The reusable fix (export it in `guardrails/__init__.py`). |

Then wire it in:

- **GUI / labs:** add an `AttackMeta` to [`purplemcp/gui/catalog_attacks.py`](purplemcp/gui/catalog_attacks.py).
  If the attack is deterministic and offline, also add an `ArenaCase` to
  [`purplemcp/gui/catalog.py`](purplemcp/gui/catalog.py) so the Defense Lab can show
  the red→blue verify.
- **Taxonomy:** map it to OWASP-LLM / CWE / ATLAS in
  [`purplemcp/taxonomy.py`](purplemcp/taxonomy.py) (`_REFS`).
- **Tests:** prove the guardrail blocks the attack in `tests/`.
- **Docs:** `python scripts/gen_taxonomy.py` to refresh `docs/TAXONOMY.md`, and
  add a row to the README attack table.

The CLI, Attack Lab, Defense Lab, `purplemcp taxonomy`, `purplemcp report`, and the
benchmark all read those registries — register once and it appears everywhere.

## Guardrails

Reusable fixes live in [`purplemcp/guardrails/`](purplemcp/guardrails/) — small,
documented, dependency-light primitives. Each should explain the exact attack it
neutralizes and have a test. Export new names in `guardrails/__init__.py`.

## Style & tests

- Python 3.11+, type hints and short docstrings; match the surrounding style.
- Keep the test suite green (`python -m pytest -q`); add tests for new behavior.
- Regenerate docs artifacts when relevant: `scripts/gen_taxonomy.py`,
  `scripts/gen_screenshots.py`.

## Commits & PRs

- Clear, imperative commit subjects; explain the *why* in the body.
- Keep diffs focused; one logical change per PR.
- Make sure `pytest` and `purplemcp scan attacks` behave as expected before pushing.
