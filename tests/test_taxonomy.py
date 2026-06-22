"""The threat taxonomy stays complete and consistent with the module registry."""

from purplemcp import taxonomy as tx
from purplemcp.gui.catalog_attacks import ATTACKS


def test_every_module_is_mapped():
    assert len(tx.TAXONOMY) == len(ATTACKS)
    assert {a.id for a in ATTACKS} == set(tx.BY_ID)


def test_markdown_table_has_a_row_per_module():
    md = tx.as_markdown_table()
    body = md.splitlines()[2:]  # drop header + separator
    assert len(body) == len(tx.TAXONOMY)
    assert "OWASP LLM" in md and "CWE-89" in md  # SQL injection mapped


def test_owasp_coverage_spans_multiple_categories():
    cov = tx.owasp_coverage()
    assert sum(1 for ids in cov.values() if ids) >= 5


def test_rows_expose_expected_keys():
    row = tx.as_rows()[0]
    assert {"num", "title", "owasp_llm", "cwe", "atlas", "guardrail"} <= set(row)
