from __future__ import annotations

import unittest
from unittest.mock import patch

from app.core.config import Settings
from app.core.models import (
    CrawlResult,
    EndpointProbeResult,
    FindingCandidate,
    HTTPHeader,
    NetworkScanResult,
    NucleiScanResult,
    PortInfo,
    RobotsTxtResult,
    SecurityHeader,
    WebProbeResult,
)
from app.core.scope import ScopeGuard
from app.llm.models import FindingAnalysis, RecommendedValidation
from app.orchestrator.supervisor import ScanSupervisor
from app.validation.models import ValidationResult


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings()
        self.scope_guard = ScopeGuard(self.settings)
        self.supervisor = ScanSupervisor(self.settings, self.scope_guard)

    def _analysis_stub(self):
        return {
            "finding_id": "NUCLEI-001",
            "title": "Public Swagger API - Detect",
            "category": "Information Disclosure",
            "severity": "MEDIUM",
            "confidence": 0.66,
            "impact": "API documentation may disclose attack surface.",
            "reasoning_summary": "Scanner evidence indicates an exposed API definition.",
            "evidence_assessment": "Evidence is direct but should be validated.",
            "status": "needs_validation",
            "recommended_validation": {"type": "compare_http_response", "reason": "Confirm exposure consistently."},
            "model_used": "small-model",
            "routing_reason": "simple finding with strong deterministic signals",
            "escalated": False,
            "prompt_version": "v1",
            "model_confidence": 0.7,
            "final_confidence": 0.66,
            "analysis_error": None,
        }

    def _analysis_result(self, analysis_input) -> FindingAnalysis:
        payload = self._analysis_stub()
        payload.update(
            {
                "finding_id": analysis_input.finding_id,
                "title": analysis_input.title,
                "category": analysis_input.category,
                "severity": analysis_input.severity,
                "cwe_id": analysis_input.exact_cwe_id,
            }
        )
        recommended_type = "check_security_header"
        if analysis_input.endpoint.endswith("/administration"):
            recommended_type = "check_endpoint_accessibility"
        payload["recommended_validation"] = RecommendedValidation(
            type=recommended_type,
            reason="workflow test stub",
        )
        return FindingAnalysis.model_validate(payload)

    def _validation_result(self, candidate, analysis, *, remaining_scan_requests: int) -> ValidationResult:
        validator = None
        if analysis and analysis.recommended_validation:
            validator = analysis.recommended_validation.type
        return ValidationResult(
            finding_id=candidate.id,
            status="validation_skipped",
            validator=validator,
            confidence_before=float(getattr(analysis, "final_confidence", candidate.confidence) or 0.0),
            confidence_after=float(getattr(analysis, "final_confidence", candidate.confidence) or 0.0),
            reason="workflow_test_stub",
            engine_version="v1",
        )

    def test_partial_recon_when_network_scan_fails(self) -> None:
        probe = WebProbeResult(
            target="http://127.0.0.1:3000",
            in_scope=True,
            final_url="http://127.0.0.1:3000",
            status_code=200,
            reason_phrase="OK",
            ip="127.0.0.1",
            port=3000,
            scheme="http",
            title="OWASP Juice Shop",
            server="Node.js",
            content_type="text/html",
            headers=[HTTPHeader(name="X-Powered-By", value="Express")],
            security_headers=[SecurityHeader(name="X-Frame-Options", present=True, value="DENY")],
            meta_tags={},
            script_urls=["/main.angular.js"],
            body_preview="<html ng-version='15.0.0'></html>",
            body_length=40,
        )
        robots = RobotsTxtResult(
            target="http://127.0.0.1:3000",
            url="http://127.0.0.1:3000/robots.txt",
            status_code=200,
            exists=True,
            disallow=["/ftp"],
        )
        endpoints = [
            EndpointProbeResult(
                path="/",
                url="http://127.0.0.1:3000/",
                method="HEAD",
                status_code=200,
                content_type="text/html",
                exists=True,
            )
        ]
        crawl = CrawlResult(
            target="http://127.0.0.1:3000",
            pages=[],
            discovered_urls=[],
            total_requests=0,
            max_depth_reached=0,
            success=True,
        )
        failed_network = NetworkScanResult(
            target="http://127.0.0.1:3000",
            resolved_ip="127.0.0.1",
            mode="quick",
            ports=[],
            scan_duration_ms=1,
            success=False,
            error="nmap is not installed",
        )
        nuclei = NucleiScanResult(
            target="http://127.0.0.1:3000",
            command=["nuclei"],
            candidates=[],
            success=False,
            scan_duration_ms=1,
            error="nuclei is not installed",
        )

        with (
            patch("app.orchestrator.workflow.web_probe", return_value=probe),
            patch("app.orchestrator.workflow.network_scan", return_value=failed_network),
            patch("app.orchestrator.workflow.inspect_robots_txt", return_value=robots),
            patch("app.orchestrator.workflow.discover_common_endpoints", return_value=endpoints),
            patch("app.orchestrator.workflow.crawl_web", return_value=crawl),
            patch("app.orchestrator.workflow.run_nuclei", return_value=nuclei),
            patch("app.orchestrator.workflow.AnalysisAgent.analyze", side_effect=self._analysis_result),
            patch("app.orchestrator.workflow.ValidationAgent.validate_finding", side_effect=self._validation_result),
        ):
            scan = self.supervisor.run_scan("http://127.0.0.1:3000")

        self.assertEqual(scan.status, "completed")
        self.assertEqual(scan.recon.target_ip, "127.0.0.1")
        technology_names = {technology.name for technology in scan.recon.technologies}
        self.assertEqual(technology_names, {"Angular", "Express", "Node.js", "OWASP Juice Shop"})
        network_execution = next(item for item in scan.tools_used if item.tool == "network_scan")
        self.assertFalse(network_execution.success)
        self.assertEqual(network_execution.error, "nmap is not installed")
        nuclei_execution = next(item for item in scan.tools_used if item.tool == "nuclei")
        self.assertFalse(nuclei_execution.success)
        self.assertEqual(nuclei_execution.error, "nuclei is not installed")

    def test_partial_recon_when_network_scan_returns_ports(self) -> None:
        probe = WebProbeResult(
            target="http://127.0.0.1:3000",
            in_scope=True,
            final_url="http://127.0.0.1:3000",
            status_code=200,
            reason_phrase="OK",
            ip="127.0.0.1",
            port=3000,
            scheme="http",
            title="OWASP Juice Shop",
            server="Node.js",
            content_type="text/html",
            headers=[HTTPHeader(name="X-Powered-By", value="Express")],
            security_headers=[SecurityHeader(name="X-Frame-Options", present=True, value="DENY")],
            meta_tags={},
            script_urls=[],
            body_preview="<html></html>",
            body_length=13,
        )
        network = NetworkScanResult(
            target="http://127.0.0.1:3000",
            resolved_ip="127.0.0.1",
            mode="quick",
            ports=[PortInfo(port=3000, protocol="tcp", state="open", service="http")],
            scan_duration_ms=1,
            success=True,
        )
        crawl = CrawlResult(
            target="http://127.0.0.1:3000",
            pages=[],
            discovered_urls=[],
            total_requests=0,
            max_depth_reached=0,
            success=True,
        )
        nuclei = NucleiScanResult(
            target="http://127.0.0.1:3000",
            command=["nuclei"],
            candidates=[],
            success=True,
            scan_duration_ms=1,
        )

        with (
            patch("app.orchestrator.workflow.web_probe", return_value=probe),
            patch("app.orchestrator.workflow.network_scan", return_value=network),
            patch("app.orchestrator.workflow.inspect_robots_txt", return_value=None),
            patch("app.orchestrator.workflow.discover_common_endpoints", return_value=[]),
            patch("app.orchestrator.workflow.crawl_web", return_value=crawl),
            patch("app.orchestrator.workflow.run_nuclei", return_value=nuclei),
            patch("app.orchestrator.workflow.AnalysisAgent.analyze", side_effect=self._analysis_result),
            patch("app.orchestrator.workflow.ValidationAgent.validate_finding", side_effect=self._validation_result),
        ):
            scan = self.supervisor.run_scan("http://127.0.0.1:3000")

        self.assertEqual(scan.recon.open_ports[0].port, 3000)
        self.assertEqual(scan.recon.open_ports[0].service, "http")

    def test_http_probe_corrects_weak_service_fingerprint(self) -> None:
        probe = WebProbeResult(
            target="http://127.0.0.1:3000",
            in_scope=True,
            final_url="http://127.0.0.1:3000",
            status_code=200,
            reason_phrase="OK",
            ip="127.0.0.1",
            port=3000,
            scheme="http",
            title="OWASP Juice Shop",
            server=None,
            content_type="text/html",
            headers=[],
            security_headers=[],
            meta_tags={},
            script_urls=["main.js", "polyfills.js"],
            body_preview="<html><body><app-root></app-root><title>OWASP Juice Shop</title></body></html>",
            body_length=42,
        )
        network = NetworkScanResult(
            target="http://127.0.0.1:3000",
            resolved_ip="127.0.0.1",
            mode="quick",
            ports=[PortInfo(port=3000, protocol="tcp", state="open", service="ppp")],
            scan_duration_ms=1,
            success=True,
        )
        crawl = CrawlResult(
            target="http://127.0.0.1:3000",
            pages=[],
            discovered_urls=[],
            total_requests=0,
            max_depth_reached=0,
            success=True,
        )
        nuclei = NucleiScanResult(
            target="http://127.0.0.1:3000",
            command=["nuclei"],
            candidates=[],
            success=True,
            scan_duration_ms=1,
        )

        with (
            patch("app.orchestrator.workflow.web_probe", return_value=probe),
            patch("app.orchestrator.workflow.network_scan", return_value=network),
            patch("app.orchestrator.workflow.inspect_robots_txt", return_value=None),
            patch("app.orchestrator.workflow.discover_common_endpoints", return_value=[]),
            patch("app.orchestrator.workflow.crawl_web", return_value=crawl),
            patch("app.orchestrator.workflow.run_nuclei", return_value=nuclei),
            patch("app.orchestrator.workflow.AnalysisAgent.analyze", side_effect=self._analysis_result),
            patch("app.orchestrator.workflow.ValidationAgent.validate_finding", side_effect=self._validation_result),
        ):
            scan = self.supervisor.run_scan("http://127.0.0.1:3000")

        self.assertEqual(scan.recon.open_ports[0].service, "http")
        self.assertEqual(scan.recon.open_ports[0].product, "Node.js")

    def test_analysis_failure_does_not_crash_scan(self) -> None:
        probe = WebProbeResult(
            target="http://127.0.0.1:3000",
            in_scope=True,
            final_url="http://127.0.0.1:3000",
            status_code=200,
            reason_phrase="OK",
            ip="127.0.0.1",
            port=3000,
            scheme="http",
            title="OWASP Juice Shop",
            server="Node.js",
            content_type="text/html",
            headers=[],
            security_headers=[],
            meta_tags={},
            script_urls=[],
            body_preview="<html></html>",
            body_length=13,
        )
        nuclei = NucleiScanResult(
            target="http://127.0.0.1:3000",
            command=["nuclei"],
            candidates=[
                FindingCandidate(
                    id="NUCLEI-001",
                    title="Public Swagger API - Detect",
                    category="Information Disclosure",
                    severity="MEDIUM",
                    endpoint="/api-docs",
                    method="GET",
                    evidence=["matched-at=http://127.0.0.1:3000/api-docs"],
                    source_tool="nuclei",
                    confidence=0.8,
                )
            ],
            success=True,
            scan_duration_ms=1,
        )
        crawl = CrawlResult(
            target="http://127.0.0.1:3000",
            pages=[],
            discovered_urls=[],
            total_requests=0,
            max_depth_reached=0,
            success=True,
        )
        with (
            patch("app.orchestrator.workflow.web_probe", return_value=probe),
            patch("app.orchestrator.workflow.network_scan", return_value=None),
            patch("app.orchestrator.workflow.inspect_robots_txt", return_value=None),
            patch("app.orchestrator.workflow.discover_common_endpoints", return_value=[]),
            patch("app.orchestrator.workflow.crawl_web", return_value=crawl),
            patch("app.orchestrator.workflow.run_nuclei", return_value=nuclei),
            patch("app.orchestrator.workflow.AnalysisAgent.analyze", side_effect=RuntimeError("ollama unavailable")),
        ):
            scan = self.supervisor.run_scan("http://127.0.0.1:3000")

        self.assertEqual(scan.status, "completed")
        self.assertEqual(scan.finding_candidates[0].analysis["status"], "insufficient_evidence")

    def test_deterministic_recon_generates_csp_and_admin_candidates(self) -> None:
        probe = WebProbeResult(
            target="http://127.0.0.1:3000",
            in_scope=True,
            final_url="http://127.0.0.1:3000/",
            status_code=200,
            reason_phrase="OK",
            ip="127.0.0.1",
            port=3000,
            scheme="http",
            title="OWASP Juice Shop",
            server="Node.js",
            content_type="text/html",
            headers=[],
            security_headers=[
                SecurityHeader(name="Content-Security-Policy", present=False, value=None),
                SecurityHeader(name="X-Frame-Options", present=True, value="DENY"),
            ],
            meta_tags={},
            script_urls=[],
            body_preview="<html></html>",
            body_length=13,
        )
        endpoints = [
            EndpointProbeResult(
                path="/administration",
                url="http://127.0.0.1:3000/administration",
                method="GET",
                status_code=200,
                content_type="text/html",
                exists=True,
            )
        ]
        crawl = CrawlResult(
            target="http://127.0.0.1:3000",
            pages=[],
            discovered_urls=[],
            total_requests=0,
            max_depth_reached=0,
            success=True,
        )
        nuclei = NucleiScanResult(
            target="http://127.0.0.1:3000",
            command=["nuclei"],
            candidates=[],
            success=True,
            scan_duration_ms=1,
        )

        with (
            patch("app.orchestrator.workflow.web_probe", return_value=probe),
            patch("app.orchestrator.workflow.network_scan", return_value=None),
            patch("app.orchestrator.workflow.inspect_robots_txt", return_value=None),
            patch("app.orchestrator.workflow.discover_common_endpoints", return_value=endpoints),
            patch("app.orchestrator.workflow.crawl_web", return_value=crawl),
            patch("app.orchestrator.workflow.run_nuclei", return_value=nuclei),
            patch("app.orchestrator.workflow.AnalysisAgent.analyze", side_effect=self._analysis_result),
            patch("app.orchestrator.workflow.ValidationAgent.validate_finding", side_effect=self._validation_result),
        ):
            scan = self.supervisor.run_scan("http://127.0.0.1:3000")

        titles = {candidate.title for candidate in scan.finding_candidates}
        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Exposed Admin Endpoint", titles)
