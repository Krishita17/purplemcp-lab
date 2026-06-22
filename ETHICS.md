# Responsible Use & Ethics

PurpleMCP contains **intentionally vulnerable software** under [`attacks/`](attacks/).
It exists for one reason: to help people learn how Model Context Protocol (MCP)
systems break, so they can build ones that don't.

Read this before you run anything in the attack lab.

## The rules

1. **Your lab, your machines, your consent.** Only ever run the attack material
   against systems you own or have **explicit, written permission** to test.
   Practicing on someone else's server, account, or model is likely a crime in
   your jurisdiction (e.g. CFAA in the US, the Computer Misuse Act in the UK,
   and equivalents elsewhere). "It was for learning" is not a legal defense.

2. **Keep it isolated.** The vulnerable servers bind to `localhost` only and
   refuse to start unless you opt in (see below). Don't expose them to a
   network, a VM you share, or the internet. Treat them like live malware
   samples, because functionally they behave like the target of one.

3. **The vulnerable code is a teaching prop, not a starting point.** Every file
   under `attacks/` is deliberately insecure. Never copy it into a real project.
   For code you can actually build on, use [`servers/`](servers/) (clean
   examples) and [`purplemcp/guardrails/`](purplemcp/guardrails/) (the hardening
   library) and [`defense/`](defense/) (hardened equivalents).

4. **No real targets, no real secrets.** The "exfiltration" demos send data to a
   **local, fake** attacker sink that you run yourself. Don't point them at a
   real endpoint. Don't load real API keys, customer data, or credentials into
   the lab.

## The safety switch

The vulnerable servers check an environment variable and exit immediately if it
isn't set:

```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
```

This is intentional friction. If you ever see a vulnerable server refusing to
start, that guard is doing its job.

## Why an attack section at all?

You cannot defend a threat you don't understand. Every attack in this repo is
paired with a concrete defense in [`defense/`](defense/), and the whole point is
the *pair*: see the break, then see the fix. That is the purple-team mindset —
red and blue learning from each other.

If you use this material, use it to make software safer.
