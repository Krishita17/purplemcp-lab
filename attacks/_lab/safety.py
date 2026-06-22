"""The attack-lab safety guard.

Every intentionally-vulnerable server and every exploit calls ``require_lab()``
first. If the opt-in environment variable isn't set to the exact token, the
component refuses to run. This is deliberate friction so you never start
vulnerable code by accident.

    export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
"""

from __future__ import annotations

import os
import sys

LAB_TOKEN = "i-understand-this-is-a-lab"
ENV_VAR = "PURPLEMCP_LAB_ENABLED"


def lab_enabled() -> bool:
    return os.environ.get(ENV_VAR) == LAB_TOKEN


def require_lab(component: str = "this component") -> None:
    """Exit unless the operator has explicitly opted into the lab."""
    if lab_enabled():
        return
    sys.stderr.write(
        "\n"
        "  ┌──────────────────────────────────────────────────────────────┐\n"
        "  │  REFUSED: intentionally-vulnerable lab code                    │\n"
        "  └──────────────────────────────────────────────────────────────┘\n"
        f"  {component} is deliberately insecure and is disabled by default.\n\n"
        "  To run it in your isolated lab, opt in:\n\n"
        f'      export {ENV_VAR}="{LAB_TOKEN}"\n\n'
        "  Only do this on a machine you own and control. See ETHICS.md.\n\n"
    )
    raise SystemExit(2)
