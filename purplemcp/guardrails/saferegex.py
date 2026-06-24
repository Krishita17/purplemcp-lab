"""Safe regex-search guardrail — defeats caller-controlled regex injection.

A search tool that compiles a *caller-supplied* pattern hands the caller full regex
power over the data: ``.*``, alternation and lookarounds can broaden a query to match
hidden records (information disclosure), and nested quantifiers can hang the process
(ReDoS). :func:`literal_search` treats the caller's text as a **literal substring**
(via ``re.escape``), so metacharacters are inert.
"""

from __future__ import annotations

import re


def literal_search(needle: str, haystack: str, *, ignore_case: bool = True) -> bool:
    """True if ``needle`` occurs in ``haystack`` as a literal substring (regex-safe).

    The needle is escaped, so ``.*`` matches the two characters ``.`` and ``*`` — not
    "anything". That removes both the information-disclosure and the ReDoS footguns.
    """
    flags = re.IGNORECASE if ignore_case else 0
    return re.search(re.escape(needle), haystack, flags) is not None
