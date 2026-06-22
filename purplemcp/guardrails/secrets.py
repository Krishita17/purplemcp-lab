"""Secret scrubbing — the fix for **credential / data leakage in tool output**.

If a tool can return file contents or command output, it can return secrets. A
defensive server scrubs known secret shapes before handing text back to the
model (which may then echo it, log it, or send it onward). This is defense in
depth, not a substitute for not reading secret files in the first place.
"""

from __future__ import annotations

import re

# Order matters: specific/long shapes first, broad assignment pattern last, so a
# value gets the most precise label before the catch-all can claim it.
PATTERNS: dict[str, str] = {
    "private_key_block": (
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    ),
    "aws_access_key_id": r"AKIA[0-9A-Z]{16}",
    "anthropic_key": r"sk-ant-[A-Za-z0-9_\-]{16,}",
    # sk-style keys, allowing hyphens/underscores in the body (e.g. sk-fake-...).
    "sk_style_key": r"sk-[A-Za-z0-9_\-]{16,}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{20,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "bearer_token": r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}",
    # user:password@host inside a connection string / URL.
    "conn_string_password": r"(?i)[a-z][a-z0-9+.\-]*://[^:/@\s]+:[^@/\s]{3,}@",
    # key/secret/token assignments, allowing a prefix or suffix on the keyword
    # so api_token / access_token / my_password etc. are caught too.
    "secret_assignment": (
        r"(?i)\b\w*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|auth)"
        r"\w*\s*[:=]\s*['\"]?[A-Za-z0-9._\-/+]{6,}"
    ),
}

_COMPILED = {name: re.compile(pat) for name, pat in PATTERNS.items()}


def find_secrets(text: str) -> list[str]:
    """Names of secret patterns found in ``text`` (empty == nothing obvious)."""
    return [name for name, rx in _COMPILED.items() if rx.search(text or "")]


def scrub(text: str) -> str:
    """Replace anything that looks like a secret with a ``[REDACTED:...]`` tag."""
    redacted = text or ""
    for name, rx in _COMPILED.items():
        redacted = rx.sub(f"[REDACTED:{name}]", redacted)
    return redacted
