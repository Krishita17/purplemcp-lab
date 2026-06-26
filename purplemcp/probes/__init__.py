"""Model-susceptibility probes.

A probe drives a *real* agent (real LLM, real MCP tool calls) against a subtle
adversarial MCP server and decides — purely by inspecting the tool calls the
model made and the text it produced — whether the model was manipulated. Each
probe runs several times at temperature 0.7 so the Attack Success Rate (ASR)
reflects genuine variation, not a single deterministic outcome.

See :mod:`purplemcp.probes.runner` for the harness and :func:`run_susceptibility`.
"""

from .paper import render_paper_report, write_metrics_csv
from .runner import (
    PROBES,
    ProbeTarget,
    SusceptibilityReport,
    render_cross_model_table,
    resolve_targets,
    run_susceptibility,
    write_susceptibility_reports,
)

__all__ = [
    "PROBES",
    "ProbeTarget",
    "SusceptibilityReport",
    "render_cross_model_table",
    "render_paper_report",
    "resolve_targets",
    "run_susceptibility",
    "write_metrics_csv",
    "write_susceptibility_reports",
]
