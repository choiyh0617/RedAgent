from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.models import FindingCandidate, ReconResult, ScanRecord, ScanStatus, Severity, ToolExecution
from app.reports.generator import (
    ReportBuilder,
    filter_findings,
    group_findings,
    normalize_final_severity,
    resolve_final_status,
    write_scan_reports,
)
from app.reports.models import REPORT_SCHEMA_VERSION


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.reports_dir = Path(self.temp_dir.name) / "reports"
        self.started_at = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)
        self.completed_at = self.started_at + timedelta(seconds=2)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _candidate(self, **overrides) -> FindingCandidate:
        payload = {
            "id": "R-001",
            "title": "Missing Content-Security-Policy",
            "category": "Security Misconfiguration",
            "severity": Severity.MEDIUM,
            "endpoint": "http://127.0.0.1:3000/",
            "method": "GET",
            "evidence": ["Content-Security-Policy header missing"],
            "source_tool": "nuclei",
            "confidence": 0.82,
            "raw_reference": "missing-csp-template",
            "rag_context": {
                "results": [
                    {"source": "CWE", "title": "CWE-16", "content": "c", "metadata": {}},
                ]
            },
            "analysis": {
                "status": "needs_validation",
                "reasoning_summary": "Header evidence aligns with deterministic checks.",
                "impact": "Missing CSP weakens browser-side hardening.",
                "evidence_assessment": "Direct scanner evidence is available.",
                "cwe_id": "CWE-16",
                "owasp_category": "A05:2021 Security Misconfiguration",
                "final_confidence": 0.7997,
            },
            "validation": {
                "status": "verified",
                "validator": "check_security_header",
                "reason": "header_missing_confirmed",
                "confidence_after": 0.9,
                "evidence": [
                    {
                        "type": "http_observation",
                        "request": {"method": "GET", "path": "/", "headers": {"Authorization": "Bearer secret.token"}},
                        "response": {"status_code": 200, "content_type": "text/html", "body_length": 4210},
                        "observation": "Content-Security-Policy missing on GET /",
                    }
                ],
            },
            "final_status": "verified",
        }
        payload.update(overrides)
        return FindingCandidate(**payload)

    def _scan(self, candidates: list[FindingCandidate] | None = None, **overrides) -> ScanRecord:
        payload = {
            "scan_id": "scan-report-001",
            "target": "http://127.0.0.1:3000",
            "status": ScanStatus.COMPLETED,
            "created_at": self.started_at,
            "updated_at": self.completed_at,
            "scope": ["127.0.0.1", "localhost"],
            "recon": ReconResult(target="http://127.0.0.1:3000", finding_candidates=[]),
            "finding_candidates": candidates or [self._candidate()],
            "findings": [],
            "blocked_actions": ["scope redirect blocked"],
            "tools_used": [
                ToolExecution(tool="web_probe", success=True, duration_ms=10),
                ToolExecution(tool="analysis_agent", success=True, duration_ms=20),
            ],
            "validation_metrics": {
                "validation_attempted_count": 1,
                "validation_verified_count": 1,
                "validation_false_positive_count": 0,
                "validation_unverified_count": 0,
                "validation_skipped_count": 0,
                "validation_request_count": 1,
                "validation_duration": 35,
            },
        }
        payload.update(overrides)
        return ScanRecord(**payload)

    def test_final_status_resolution_and_verified_priority(self) -> None:
        candidate = self._candidate()
        status = resolve_final_status(candidate, {"status": "likely"}, {"status": "verified"})
        self.assertEqual(status, "verified")

    def test_false_positive_preservation(self) -> None:
        candidate = self._candidate(validation={"status": "false_positive"})
        status = resolve_final_status(candidate, candidate.analysis or {}, candidate.validation or {})
        self.assertEqual(status, "false_positive")

    def test_severity_normalization(self) -> None:
        self.assertEqual(normalize_final_severity(Severity.HIGH, "verified").value, "high")
        self.assertEqual(normalize_final_severity("INFO", "informational").value, "info")

    def test_report_summary_counts_and_false_positive_exclusion(self) -> None:
        verified = self._candidate()
        false_positive = self._candidate(
            id="R-002",
            title="Admin Panel",
            severity=Severity.HIGH,
            validation={"status": "false_positive", "reason": "endpoint_not_accessible"},
            final_status="false_positive",
        )
        scan = self._scan(candidates=[verified, false_positive], validation_metrics={
            "validation_attempted_count": 2,
            "validation_verified_count": 1,
            "validation_false_positive_count": 1,
            "validation_unverified_count": 0,
            "validation_skipped_count": 0,
            "validation_request_count": 2,
            "validation_duration": 70,
        })
        report = ReportBuilder().build(scan)
        self.assertEqual(report.executive_summary.total_findings, 2)
        self.assertEqual(report.executive_summary.confirmed_findings, 1)
        self.assertEqual(report.finding_summary.false_positive_count, 1)
        self.assertEqual(report.validation_summary.validation_false_positive_count, 1)

    def test_scan_metrics_aggregation(self) -> None:
        report = ReportBuilder().build(self._scan())
        self.assertEqual(report.metrics.scan_duration_ms, 2000)
        self.assertEqual(report.metrics.tool_call_count, 2)
        self.assertEqual(report.metrics.candidate_count, 1)
        self.assertEqual(report.metrics.final_finding_count, 1)

    def test_json_report_schema_and_version(self) -> None:
        json_path, html_path, report = write_scan_reports(self._scan(), self.reports_dir)
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], REPORT_SCHEMA_VERSION)
        self.assertEqual(payload["scan_metadata"]["schema_version"], REPORT_SCHEMA_VERSION)
        self.assertTrue(html_path.exists())
        self.assertEqual(report.schema_version, REPORT_SCHEMA_VERSION)

    def test_html_report_generation_and_escaping(self) -> None:
        malicious = self._candidate(
            title="<script>alert(1)</script>",
            validation={
                "status": "verified",
                "validator": "check_security_header",
                "reason": "header_missing_confirmed",
                "confidence_after": 0.9,
                "evidence": [{"type": "http_observation", "observation": "<img src=x onerror=alert(1)>"}],
            },
        )
        _, html_path, _ = write_scan_reports(self._scan(candidates=[malicious]), self.reports_dir)
        content = html_path.read_text(encoding="utf-8")
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)
        self.assertNotIn("<img src=x onerror=alert(1)>", content)

    def test_evidence_redaction_and_no_secrets_in_persisted_report(self) -> None:
        json_path, html_path, _ = write_scan_reports(self._scan(), self.reports_dir)
        json_content = json_path.read_text(encoding="utf-8")
        html_content = html_path.read_text(encoding="utf-8")
        self.assertIn("[REDACTED]", json_content)
        self.assertNotIn("secret.token", json_content)
        self.assertNotIn("secret.token", html_content)

    def test_report_filtering_and_grouping(self) -> None:
        findings = [
            self._candidate().model_dump(mode="json"),
            self._candidate(id="R-002", severity=Severity.HIGH, final_status="false_positive", validation={"status": "false_positive"}).model_dump(mode="json"),
        ]
        filtered = filter_findings(findings, severity="high")
        grouped = group_findings(filtered, "status")
        self.assertEqual(len(filtered), 1)
        self.assertIn("false_positive", grouped)

    def test_report_generation_when_one_finding_is_malformed(self) -> None:
        scan = self._scan()
        broken_scan = scan.model_copy(update={"finding_candidates": [self._candidate(), object()]})
        findings = ReportBuilder().build_final_findings(broken_scan)
        self.assertEqual(len(findings), 1)

    def test_report_generation_without_llm(self) -> None:
        scan = self._scan(candidates=[self._candidate(analysis=None, validation=None, final_status="candidate")], validation_metrics=None)
        report = ReportBuilder().build(scan)
        self.assertEqual(report.findings[0].final_status, "informational")

