"""Safe templating — the fix for **template / format-string injection**.

Python's ``str.format`` and f-strings are deceptively dangerous when the
*template itself* is attacker-controlled: ``"{x.__class__}".format(x=obj)`` walks
object attributes, and from there ``__init__.__globals__`` reaches module globals
(secrets, ``os``, …). The same idea is how Jinja SSTI escalates to RCE.

The fix is to use a template engine that can only substitute named values and
**cannot access attributes, indexes, or call anything** — that's exactly
``string.Template`` with ``$name`` placeholders.

    safe_format("Hello $name, your role is $role", name="Ada", role="admin")
"""

from __future__ import annotations

from string import Template


class TemplateInjectionError(ValueError):
    """Raised when a template is rejected by the safe formatter."""


def safe_format(template: str, /, **values: object) -> str:
    """Render ``$name`` placeholders in ``template`` from ``values`` only.

    Unlike ``str.format``, this can never reach object attributes or globals: the
    grammar is just ``$name`` / ``${name}`` substitution. Unknown placeholders are
    left intact (via ``safe_substitute``) rather than crashing the tool.
    """
    if not isinstance(template, str):
        raise TemplateInjectionError("template must be a string")
    # Stringify values so a placeholder can never smuggle a live object through.
    safe_values = {k: str(v) for k, v in values.items()}
    return Template(template).safe_substitute(safe_values)
