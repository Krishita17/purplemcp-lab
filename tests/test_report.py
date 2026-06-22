"""The security-posture report stays complete and reflects the scanner."""

from purplemcp.report import build_report


def test_report_has_all_sections():
    md = build_report()
    for section in (
        "# PurpleMCP — security posture report",
        "## Summary",
        "## Static scan",
        "## Threat taxonomy",
        "OWASP LLM Top 10 coverage",
        "## Guardrail library",
    ):
        assert section in md


def test_report_includes_taxonomy_and_guardrails():
    md = build_report()
    assert "CWE-89" in md and "CWE-502" in md  # SQLi + deserialization mapped
    assert "`safe_eval`" in md and "`authz`" in md  # guardrail inventory


def test_report_flags_vulnerable_code():
    md = build_report()
    # the attacks/ scan row exists and the scanner found something there
    assert "intentionally vulnerable" in md
