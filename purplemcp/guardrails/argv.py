"""Argument / flag injection safety — the fix for **argument injection** (CWE-88).

Running a fixed binary with ``shell=False`` stops *command* injection, but not
*argument* injection: if caller-controlled text is split into multiple argv
elements (or passed as a list), a value like ``--output=/etc/cron.d/x`` or tar's
``--checkpoint-action=exec=…`` is read by the program as an **option**, not data.
The process is the one you intended — but doing something you didn't.

Two rules close this:

1. **Never split** a single user value into multiple argv elements — pass it whole.
2. Place a literal ``--`` after the trusted prefix, so every following element is
   treated as a positional operand, never an option.
"""

from __future__ import annotations

from collections.abc import Iterable


def safe_argv(base: list[str], user_values: Iterable[str]) -> list[str]:
    """Build an argv where user values can't be reinterpreted as option flags.

    ``base`` is the trusted command prefix (e.g. ``["grep", "-n", pattern_flag]``);
    ``user_values`` are the caller-supplied operands, each passed through whole.
    A ``--`` end-of-options separator is inserted between them. NUL bytes (which
    argv cannot carry) are rejected.
    """
    values = list(user_values)
    for value in values:
        if "\x00" in value:
            raise ValueError("argument contains a NUL byte")
    return [*base, "--", *values]
