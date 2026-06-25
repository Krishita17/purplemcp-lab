"""Tests for the research layer: taxonomy, machine-readable scanner output, bench."""

from __future__ import annotations

import asyncio
import json

from purplemcp import scanner
from purplemcp import taxonomy as tax
from purplemcp.benchmark import BenchmarkReport, CaseResult, run_guardrail_benchmark
from purplemcp.gui.catalog import CASES_BY_ID
from purplemcp.gui.catalog_attacks import ATTACKS


class TestTaxonomy:
    def test_covers_every_module(self):
        assert len(tax.TAXONOMY) == len(ATTACKS) == 28
        for meta in ATTACKS:
            assert meta.id in tax.BY_ID

    def test_owasp_codes_are_valid(self):
        for entry in tax.TAXONOMY:
            assert entry.refs.owasp_llm in tax.OWASP_LLM_TOP10
            assert entry.refs.cwe.startswith("CWE-")

    def test_rows_are_serializable(self):
        rows = tax.as_rows()
        assert len(rows) == 28
        assert all({"num", "title", "owasp_llm", "cwe", "guardrail"} <= r.keys() for r in rows)


class TestScannerExport:
    def _findings(self):
        return scanner.scan_path("attacks/03_command_injection/vulnerable_server.py")

    def test_json_export_is_valid(self):
        data = json.loads(scanner.to_json(self._findings()))
        assert isinstance(data, list) and data
        assert {"severity", "rule", "location", "message"} <= data[0].keys()

    def test_sarif_export_is_valid_210(self):
        doc = json.loads(scanner.to_sarif(self._findings()))
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "purplemcp-scanner"
        assert run["results"], "expected at least one SARIF result"
        assert run["results"][0]["level"] in {"error", "warning", "note"}


class TestBenchmark:
    def test_report_serialization_round_trips(self):
        report = BenchmarkReport(
            generated_at="2026-01-01T00:00:00+00:00", tool_version="0.0.0",
            python="3.12", platform="test",
            cases=[CaseResult("03", "x", "X", "LLM05", "CWE-78", "g",
                              True, True, "EXPLOITED", "BLOCKED", "v", "h")],
        )
        assert report.effectiveness_pct == 100.0
        doc = json.loads(report.to_json())
        assert doc["metrics"]["guardrail_effectiveness_pct"] == 100.0
        assert "PurpleMCP-Bench" in report.to_markdown()

    def test_guardrail_benchmark_fixes_offline_cases(self):
        # A fast subset of deterministic, offline cases (no network timeouts).
        subset = [CASES_BY_ID[i] for i in ("command-injection", "eval-injection", "csv-injection")]
        report = asyncio.run(run_guardrail_benchmark(cases=subset))
        assert report.n_cases == 3
        assert report.n_correct == 3, [c.id for c in report.cases if not c.correct]

    def test_new_modules_22_23_blocked_by_hardened_twins(self):
        subset = [CASES_BY_ID[i] for i in ("unbounded-output", "argument-injection")]
        report = asyncio.run(run_guardrail_benchmark(cases=subset))
        assert report.n_cases == 2
        assert report.n_correct == 2, [c.id for c in report.cases if not c.correct]


class TestDetectionMetrics:
    def test_metrics_on_offline_subset(self):
        from purplemcp.benchmark import run_detection_metrics

        subset = [CASES_BY_ID[i] for i in ("command-injection", "eval-injection", "jwt-none", "xxe")]
        m = asyncio.run(run_detection_metrics(cases=subset))
        # every attack lands on the vulnerable server and is blocked on the twin
        assert m.n_attacks == 4
        assert m.tp == 4 and m.fn == 0
        assert m.fp == 0
        assert m.asr_vulnerable == 100.0
        assert m.asr_hardened == 0.0
        assert m.accuracy == 100.0 and m.precision == 100.0 and m.recall == 100.0

    def test_metrics_dict_shape(self):
        from purplemcp.benchmark import DetectionMetrics, MetricRow

        m = DetectionMetrics(rows=[MetricRow("18", "Eval", True, True, True)])
        d = m.to_dict()
        assert d["confusion"] == {"tp": 1, "fp": 0, "tn": 1, "fn": 0}
        assert d["asr_vulnerable_pct"] == 100.0 and d["asr_hardened_pct"] == 0.0

    def test_metrics_markdown_and_report(self, tmp_path):
        from purplemcp.benchmark import DetectionMetrics, MetricRow, write_metrics_report

        m = DetectionMetrics(rows=[
            MetricRow("18", "Eval", True, True, True),
            MetricRow("25", "XXE", True, True, None),
        ])
        md = m.to_markdown()
        assert "detection metrics" in md and "TP 2" in md and "Eval" in md
        json_path, md_path = write_metrics_report(m, tmp_path)
        assert json_path.exists() and md_path.exists()
        import json as _json
        doc = _json.loads(json_path.read_text())
        assert doc["confusion"]["tp"] == 2 and doc["n_attacks"] == 2
        assert len(doc["cases"]) == 2

    def test_by_family_groups_rows(self):
        from purplemcp.benchmark import DetectionMetrics, MetricRow

        m = DetectionMetrics(rows=[
            MetricRow("03", "Cmd", True, True, True, family="Classic appsec, now model-reachable"),
            MetricRow("17", "Log", True, True, True, family="MCP-specific"),
            MetricRow("18", "Eval", True, False, True, family="Classic appsec, now model-reachable"),
        ])
        fams = dict((name, (n, blocked, recall)) for name, n, blocked, recall in m.by_family())
        assert fams["MCP-specific"] == (1, 1, 100.0)
        assert fams["Classic appsec, now model-reachable"] == (2, 1, 50.0)
