"""Output framing — the fix for **output / log injection**.

A tool's result flows into two trusting readers: your **logs** and the **model's
context**. If a tool echoes attacker-controlled text verbatim, that text can:

- forge new log lines (an embedded ``\\n[SECURITY] access granted``),
- inject terminal/ANSI control sequences (``\\x1b[2J`` clears a screen, etc.),
- impersonate ``system`` instructions to the model (a cousin of indirect
  prompt injection, attack 02).

So strip control characters, neutralize newlines in untrusted spans so they can't
forge a line, and frame untrusted output clearly as *data*.
"""

from __future__ import annotations

import re

# Full ANSI CSI escape sequences (colour, cursor moves, screen clears, …).
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# Remaining C0 controls except tab(\x09)/newline(\x0a), plus DEL and the C1 range.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def strip_control(text: str) -> str:
    """Remove ANSI escape sequences and terminal control characters.

    Tab and newline are preserved; everything else that could move a cursor,
    recolour, or clear a terminal is removed.
    """
    return _CONTROL_RE.sub("", _ANSI_RE.sub("", text or ""))


def sanitize_output(text: str, *, keep_newlines: bool = False) -> str:
    """Strip control chars; by default also escape newlines so untrusted text
    can't forge a separate log line."""
    cleaned = strip_control(text)
    if not keep_newlines:
        cleaned = cleaned.replace("\n", "\\n")
    return cleaned


def frame_untrusted(text: str, label: str = "untrusted") -> str:
    """Wrap untrusted text so a downstream reader/model treats it as data."""
    return f"<{label}>{sanitize_output(text)}</{label}>"
