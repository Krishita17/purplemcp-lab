"""Lab opt-in guard for the susceptibility-probe MCP servers.

These servers carry *subtle* adversarial tool descriptions / outputs used to
measure whether a model can be manipulated. Like the rest of the lab they refuse
to start unless the operator has explicitly opted in with the same token the
benchmark harness injects (``PURPLEMCP_LAB_ENABLED``). This keeps the probe
servers self-contained — they do not depend on the ``attacks/`` package layout.
"""

from __future__ import annotations

import os
import sys

LAB_TOKEN = "i-understand-this-is-a-lab"
ENV_VAR = "PURPLEMCP_LAB_ENABLED"


def require_lab(component: str = "this probe server") -> None:
    """Exit unless the operator has opted into the lab."""
    if os.environ.get(ENV_VAR) == LAB_TOKEN:
        return
    sys.stderr.write(
        f"REFUSED: {component} is a susceptibility-probe lab server and is "
        f'disabled by default. Opt in with {ENV_VAR}="{LAB_TOKEN}".\n'
    )
    raise SystemExit(2)
