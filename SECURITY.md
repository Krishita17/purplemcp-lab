# Security Policy

## ⚠️ Intentional vulnerabilities (by design)

PurpleMCP is a security **teaching lab**. Everything under [`attacks/`](attacks/)
and the vulnerable demo servers are **intentionally insecure** — that's the whole
point. Please **do not** file vulnerability reports for code in `attacks/`, or for
the deliberately-weak behavior the exploits demonstrate.

That code is contained by design: it refuses to run without the opt-in flag
(`PURPLEMCP_LAB_ENABLED`), binds only to `127.0.0.1`, and "exfiltrates" only to a
fake local sink. See [ETHICS.md](ETHICS.md).

## What *is* in scope

Report real security issues in the **framework** — i.e. anything that could harm a
user of PurpleMCP itself:

- the host / agent loop (`purplemcp/host/`, `purplemcp/providers/`),
- the guardrails library (`purplemcp/guardrails/`) failing to block what it claims,
- the scanner, benchmark, installer, or CLI,
- the desktop GUI (`purplemcp/gui/`),
- the lab safety controls being bypassable (e.g. vulnerable code running *without*
  the opt-in flag) — this one we care about a lot.

## Reporting

Please report privately via GitHub:

1. Go to the repo's **Security** tab → **Report a vulnerability** (private advisory).
2. Include steps to reproduce, affected version/commit, and impact.

For non-sensitive bugs, a regular GitHub issue is fine. We aim to acknowledge
reports within a few days.

## Supported versions

This is an educational project; fixes land on the latest `main`. Please test
against the current `main` before reporting.
