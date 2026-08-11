from __future__ import annotations

import socket
import tempfile
import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from app.core.config import Settings
from app.core.models import FindingCandidate, Severity
from app.core.scope import ScopeGuard, ScopeViolationError
from app.llm.models import FindingAnalysis, RecommendedValidation
from app.orchestrator.workflow import _final_status
from app.validation.models import ValidationActionType, ValidationResult
from app.validation.router import (
    ALLOWED_VALIDATION_METHODS,
    ValidationContext,
    ValidationRouter,
    ValidationService,
    build_controlled_alternate_url,
    build_validation_cache_key,
    update_confidence,
)
from app.validation.sanitizer import EvidenceSanitizer


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict[str, str], body: bytes, reason: str = "OK", url: str = "http://127.0.0.1:3000") -> None:
        self._status_code = status_code
        self.headers = Message()
        for name, value in headers.items():
            self.headers[name] = value
        self._body = body
        self.reason = reason
        self._url = url

    def getcode(self) -> int:
        return self._status_code

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def geturl(self) -> str:
        return self._url


class _SequentialOpener:
    def __init__(self, responses) -> None:
        self.responses = list(responses)

    def open(self, request, timeout: float):
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _AuthAwareOpener:
    def open(self, request, timeout: float):
        auth = request.headers.get("Authorization")
        if auth:
            return _FakeResponse(200, {"Content-Type": "text/html"}, b"<html><title>Admin</title></html>")
        return _FakeResponse(403, {"Content-Type": "text/html"}, b"<html><title>Denied</title></html>")


class ValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.settings = Settings(
            sqlite_path=Path(self.temp_dir.name) / "pentestflow.db",
            validation_auth_header=None,
            max_validation_requests_per_finding=3,
            max_validation_requests_per_scan=20,
            validation_timeout_seconds=1.0,
        )
        self.scope_guard = ScopeGuard(self.settings)
        self.service = ValidationService(self.settings, self.scope_guard)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _candidate(self, **overrides) -> FindingCandidate:
        payload = {
            "id": "VAL-001",
            "title": "Missing Content-Security-Policy",
            "category": "Security Misconfiguration",
            "severity": Severity.MEDIUM,
            "endpoint": "http://127.0.0.1:3000/",
            "method": "GET",
            "evidence": ["Content-Security-Policy header missing"],
            "source_tool": "nuclei",
            "confidence": 0.82,
        }
        payload.update(overrides)
        return FindingCandidate(**payload)

    def _analysis(self, validation_type: str, **overrides) -> FindingAnalysis:
        payload = {
            "finding_id": "VAL-001",
            "title": "Missing Content-Security-Policy",
            "category": "Security Misconfiguration",
            "severity": Severity.MEDIUM,
            "confidence": 0.8,
            "cwe_id": "CWE-16",
            "owasp_category": "A05:2021 Security Misconfiguration",
            "impact": "impact",
            "reasoning_summary": "reason",
            "evidence_assessment": "evidence",
            "status": "needs_validation",
            "recommended_validation": {"type": validation_type, "reason": "deterministic validation"},
            "model_used": "small-model",
            "routing_reason": "simple",
            "escalated": False,
            "prompt_version": "v1",
            "model_confidence": 0.74,
            "final_confidence": 0.7997,
            "analysis_error": None,
        }
        payload.update(overrides)
        return FindingAnalysis.model_validate(payload)

    def test_supported_validation_enum_and_registry(self) -> None:
        router = ValidationRouter()
        supported = set(router.supported_types())
        self.assertEqual(
            supported,
            {
                ValidationActionType.COMPARE_HTTP_RESPONSE.value,
                ValidationActionType.CHECK_SECURITY_HEADER.value,
                ValidationActionType.CHECK_STATUS_BEHAVIOR.value,
                ValidationActionType.CHECK_REDIRECT_BEHAVIOR.value,
                ValidationActionType.CHECK_ENDPOINT_ACCESSIBILITY.value,
                ValidationActionType.CHECK_AUTH_BEHAVIOR.value,
                ValidationActionType.CHECK_METHOD_BEHAVIOR.value,
                ValidationActionType.CHECK_CONTENT_DIFFERENCE.value,
            },
        )

    def test_unknown_validator_is_skipped(self) -> None:
        result = self.service.validate_candidate(
            self._candidate(),
            self._analysis("shell_command"),
            remaining_scan_requests=10,
        )
        self.assertEqual(result.status, "validation_skipped")
        self.assertEqual(result.reason, "unsupported_validator")

    def test_scope_guard_runs_before_validation_request(self) -> None:
        analysis = self._analysis("check_security_header")
        with (
            patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([_FakeResponse(200, {}, b"ok")])),
            patch("app.tools.http_utils.GuardrailService.enforce_scope") as enforce_scope,
        ):
            result = self.service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        self.assertEqual(result.status, "verified")
        self.assertTrue(enforce_scope.called)

    def test_off_scope_redirect_is_blocked(self) -> None:
        headers = Message()
        headers["Location"] = "http://example.com/offsite"
        error = HTTPError(
            url="http://127.0.0.1:3000/admin",
            code=302,
            msg="Found",
            hdrs=headers,
            fp=BytesIO(b""),
        )
        analysis = self._analysis("check_endpoint_accessibility")
        with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([error])):
            result = self.service.validate_candidate(
                self._candidate(title="Exposed Admin Panel", evidence=["admin panel publicly reachable"]),
                analysis,
                remaining_scan_requests=10,
            )
        self.assertEqual(result.status, "unverified")
        self.assertTrue(result.evidence[0].response.blocked_redirect)

    def test_security_header_validator_verified_case(self) -> None:
        analysis = self._analysis("check_security_header")
        with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([_FakeResponse(200, {"Content-Type": "text/html"}, b"<html>ok</html>")])):
            result = self.service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.validator, "check_security_header")
        self.assertIn("missing", result.evidence[0].observation.lower())

    def test_security_header_validator_false_positive_case(self) -> None:
        analysis = self._analysis("check_security_header")
        response = _FakeResponse(200, {"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'"}, b"<html>ok</html>")
        with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([response])):
            result = self.service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        self.assertEqual(result.status, "false_positive")

    def test_response_comparison_validator(self) -> None:
        analysis = self._analysis("compare_http_response")
        responses = [
            _FakeResponse(200, {"Content-Type": "text/html"}, b"<html><title>A</title></html>"),
            _FakeResponse(200, {"Content-Type": "text/html"}, b"<html><title>B</title></html>"),
        ]
        with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener(responses)):
            result = self.service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        self.assertEqual(result.status, "verified")
        self.assertEqual(result.requests_made, 2)

    def test_endpoint_accessibility_validator(self) -> None:
        analysis = self._analysis("check_endpoint_accessibility")
        with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([_FakeResponse(200, {"Content-Type": "text/html"}, b"<html><title>Admin</title></html>")])):
            result = self.service.validate_candidate(
                self._candidate(title="Exposed Admin Panel", evidence=["admin panel publicly reachable"]),
                analysis,
                remaining_scan_requests=10,
            )
        self.assertEqual(result.status, "verified")

    def test_auth_behavior_skipped_without_auth_context(self) -> None:
        analysis = self._analysis("check_auth_behavior")
        result = self.service.validate_candidate(
            self._candidate(title="Broken Access Control", category="Broken Access Control"),
            analysis,
            remaining_scan_requests=10,
        )
        self.assertEqual(result.status, "validation_skipped")
        self.assertEqual(result.reason, "missing_auth_context")

    def test_forbidden_http_methods(self) -> None:
        context = ValidationContext(
            settings=self.settings,
            scope_guard=self.scope_guard,
            sanitizer=EvidenceSanitizer(),
            finding_title="title",
            finding_evidence=[],
            base_url="http://127.0.0.1:3000/",
            per_finding_limit=3,
            scan_remaining_requests=3,
        )
        with self.assertRaisesRegex(ValueError, "forbidden_method"):
            context.request("http://127.0.0.1:3000/", method="DELETE")
        self.assertEqual(ALLOWED_VALIDATION_METHODS, {"GET", "HEAD", "OPTIONS"})

    def test_max_request_budget(self) -> None:
        self.settings.max_validation_requests_per_finding = 1
        service = ValidationService(self.settings, self.scope_guard)
        analysis = self._analysis("compare_http_response")
        with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([_FakeResponse(200, {}, b"a")])):
            result = service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        self.assertEqual(result.status, "validation_skipped")
        self.assertEqual(result.reason, "request_budget_exceeded")

    def test_timeout_behavior(self) -> None:
        analysis = self._analysis("check_security_header")
        with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([URLError(socket.timeout("timed out"))])):
            result = self.service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        self.assertEqual(result.status, "unverified")
        self.assertEqual(result.reason, "request_timeout")

    def test_evidence_redaction(self) -> None:
        self.settings.validation_auth_header = "Bearer secret.jwt.token"
        service = ValidationService(self.settings, self.scope_guard)
        analysis = self._analysis("check_auth_behavior")
        with patch("app.tools.http_utils.build_opener", return_value=_AuthAwareOpener()):
            result = service.validate_candidate(
                self._candidate(title="Broken Access Control", category="Broken Access Control"),
                analysis,
                remaining_scan_requests=10,
            )
        self.assertEqual(result.evidence[1].request.headers["Authorization"], "[REDACTED]")
        self.assertNotIn("secret.jwt.token", str(result.model_dump(mode="json")))

    def test_confidence_increase_on_verified(self) -> None:
        self.assertEqual(update_confidence(self.settings, 0.7997, "verified"), 0.9)

    def test_confidence_decrease_on_false_positive(self) -> None:
        self.assertEqual(update_confidence(self.settings, 0.7997, "false_positive"), 0.2)

    def test_only_validator_can_mark_verified(self) -> None:
        candidate = self._candidate()
        analysis = self._analysis("check_security_header", status="likely")
        skipped = ValidationResult(
            finding_id=candidate.id,
            status="validation_skipped",
            validator="check_security_header",
            confidence_before=0.8,
            confidence_after=0.8,
            reason="validation_disabled",
        )
        verified = skipped.model_copy(update={"status": "verified"})
        self.assertNotEqual(_final_status(candidate, analysis, skipped), "verified")
        self.assertEqual(_final_status(candidate, analysis, verified), "verified")

    def test_partial_validation_failure(self) -> None:
        analysis = self._analysis("check_security_header")
        with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([RuntimeError("boom")])):
            result = self.service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        self.assertEqual(result.status, "unverified")
        self.assertEqual(result.reason, "unexpected_response")

    def test_validation_cache_version_key(self) -> None:
        first = build_validation_cache_key(
            finding_id="F-1",
            validator_type="check_security_header",
            endpoint="http://127.0.0.1:3000/",
            method="GET",
            reason="a",
            engine_version="v1",
        )
        second = build_validation_cache_key(
            finding_id="F-1",
            validator_type="check_security_header",
            endpoint="http://127.0.0.1:3000/",
            method="GET",
            reason="a",
            engine_version="v2",
        )
        self.assertNotEqual(first, second)

    def test_validation_cache_reuses_success(self) -> None:
        analysis = self._analysis("check_security_header")
        opener = _SequentialOpener([_FakeResponse(200, {}, b"ok")])
        with patch("app.tools.http_utils.build_opener", return_value=opener):
            first = self.service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        with patch("app.tools.http_utils.build_opener", side_effect=AssertionError("cache should avoid new requests")):
            second = self.service.validate_candidate(self._candidate(), analysis, remaining_scan_requests=10)
        self.assertEqual(first.status, "verified")
        self.assertTrue(second.cached)

    def test_no_shell_execution_and_no_arbitrary_payload_execution(self) -> None:
        supported = set(ValidationRouter().supported_types())
        self.assertNotIn("shell_command", supported)
        self.assertNotIn("arbitrary_http_request", supported)
        self.assertNotIn("sqlmap", supported)
        alternate = build_controlled_alternate_url("http://127.0.0.1:3000/search?q=apple")
        self.assertEqual(alternate, "http://127.0.0.1:3000/search?q=apple&pentestflow_probe=1")

    def test_scope_violation_returns_structured_result(self) -> None:
        candidate = self._candidate(endpoint="http://127.0.0.1:3000/")
        analysis = self._analysis("compare_http_response")
        with patch("app.validation.router.build_controlled_alternate_url", return_value="http://example.com/offsite"):
            with patch("app.tools.http_utils.build_opener", return_value=_SequentialOpener([_FakeResponse(200, {}, b"a")])):
                result = self.service.validate_candidate(candidate, analysis, remaining_scan_requests=10)
        self.assertEqual(result.status, "validation_skipped")
        self.assertEqual(result.reason, "scope_violation")

