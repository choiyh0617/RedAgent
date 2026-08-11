from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import main
from app.core.models import FindingCandidate, ReconResult, ScanRecord, ScanStatus
from app.reports.generator import write_scan_reports
from app.validation.models import ValidationMetrics


class ApiReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.reports_dir = Path(self.temp_dir.name) / "reports"
        self.scan = ScanRecord(
            scan_id="scan-api-001",
            target="http://127.0.0.1:3000",
            status=ScanStatus.COMPLETED,
            scope=["127.0.0.1"],
            recon=ReconResult(target="http://127.0.0.1:3000", finding_candidates=[]),
            finding_candidates=[
                FindingCandidate(
                    id="API-001",
                    title="Admin Panel",
                    category="Access Control",
                    severity="HIGH",
                    endpoint="http://127.0.0.1:3000/admin",
                    method="GET",
                    evidence=["Admin endpoint visible"],
                    source_tool="nuclei",
                    confidence=0.8,
                    analysis={"status": "needs_validation", "final_confidence": 0.8},
                    validation={"status": "unverified", "reason": "endpoint_access_inconclusive"},
                    final_status="unverified",
                )
            ],
            findings=[],
            validation_metrics=ValidationMetrics(validation_attempted_count=1, validation_unverified_count=1).model_dump(mode="json"),
        )
        self.scan = self.scan.model_copy(update={"findings": []})
        write_scan_reports(self.scan, self.reports_dir)
        self.patch = patch.object(main.settings, "reports_dir", self.reports_dir)
        self.patch.start()

    def tearDown(self) -> None:
        self.patch.stop()
        self.temp_dir.cleanup()

    def test_findings_filters(self) -> None:
        payload = main.get_findings("scan-api-001", severity="high", status="unverified")
        self.assertEqual(len(payload["findings"]), 1)

    def test_findings_grouping(self) -> None:
        payload = main.get_findings("scan-api-001", group_by="status")
        self.assertIn("unverified", payload["grouped_findings"])

    def test_report_endpoint_and_schema_version(self) -> None:
        payload = main.get_scan("scan-api-001")
        self.assertEqual(payload["schema_version"], "v1")
        report_payload = main.get_report("scan-api-001")
        self.assertTrue(report_payload["report_json"].endswith(".json"))

    def test_metrics_endpoint(self) -> None:
        payload = main.get_metrics("scan-api-001")
        self.assertIn("metrics", payload)

    def test_html_report_endpoint(self) -> None:
        response = main.get_html_report("scan-api-001")
        self.assertIn("text/html", response.media_type)
