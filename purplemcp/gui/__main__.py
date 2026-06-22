"""Run the GUI with ``python -m purplemcp.gui``."""

from __future__ import annotations

import sys

from .app import run

if __name__ == "__main__":
    sys.exit(run())
