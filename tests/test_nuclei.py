from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from app.core.config import Settings
from app.core.scope import ScopeGuard, ScopeViolationError
from app.tools.nuclei import _build_nuclei_command, parse_nuclei_jsonl, run_nuclei


NUCLEI_JSONL = """
{"template-id":"missing-security-headers","matcher-name":"csp-missing","matched-at":"http://127.0.0.1:3000/login","request":"GET /login HTTP/1.1","info":{"name":"Missing Security Headers","severity":"medium","tags":["misconfig","headers"]},"extracted-results":["missing Content-Security-Policy"]}
{"template-id":"exposed-api-docs","matcher-name":"openapi","matched-at":"http://127.0.0.1:3000/openapi.json","request":"GET /openapi.json HTTP/1.1","info":{"name":"Exposed API Documentation","severity":"low","tags":["exposure","api"]}}
""".strip()

NUCLEI_FILTERED_JSONL = """
{"template-id":"x-recruiting-header","matched-at":"http://127.0.0.1:3000","request":"GET / HTTP/1.1","info":{"name":"X-Recruiting Header","severity":"info","tags":["miscellaneous","generic"]},"extracted-results":["/#/jobs"]}
{"template-id":"owasp-juice-shop-detect","matched-at":"http://127.0.0.1:3000","request":"GET / HTTP/1.1","info":{"name":"OWASP Juice Shop","severity":"info","tags":["tech","owasp","discovery"]}}
{"template-id":"swagger-api","matched-at":"http://127.0.0.1:3000/api-docs/swagger.json","request":"GET /api-docs/swagger.json HTTP/1.1","info":{"name":"Public Swagger API - Detect","severity":"info","tags":["exposure","api","swagger","discovery"]}}
""".strip()


class NucleiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings()
        self.scope_guard = ScopeGuard(self.settings)

    def test_nuclei_command_uses_safe_flags(self) -> None:
        command = _build_nuclei_command("http://127.0.0.1:3000", self.settings)
        self.assertEqual(command[:4], ["nuclei", "-u", "http://127.0.0.1:3000", "-type"])
        self.assertIn("-jsonl", command)
        self.assertIn("-duc", command)
        self.assertIn("-t", command)
        self.assertIn("nuclei-templates/http/exposures/apis/swagger-api.yaml", command)
        self.assertIn("nuclei-templates/http/technologies/owasp-juice-shop-detected.yaml", command)
        self.assertNotIn("-headless", command)

    def test_scope_validation_runs_before_nuclei(self) -> None:
        with self.assertRaises(ScopeViolationError):
            run_nuclei("http://example.com", self.scope_guard, self.settings)

    def test_nuclei_missing_returns_structured_error(self) -> None:
        with patch("app.tools.nuclei.subprocess.run", side_effect=FileNotFoundError):
            result = run_nuclei("http://127.0.0.1:3000", self.scope_guard, self.settings)
        self.assertFalse(result.success)
        self.assertEqual(result.error, "nuclei is not installed")

    def test_nuclei_timeout_returns_structured_error(self) -> None:
        with patch(
            "app.tools.nuclei.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["nuclei"], timeout=30),
        ):
            result = run_nuclei("http://127.0.0.1:3000", self.scope_guard, self.settings)
        self.assertFalse(result.success)
        self.assertIn("timed out", result.error or "")

    def test_nuclei_json_is_parsed_into_candidates(self) -> None:
        candidates = parse_nuclei_jsonl(NUCLEI_JSONL)
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].severity.value, "MEDIUM")
        self.assertEqual(candidates[0].category, "Security Misconfiguration")
        self.assertEqual(candidates[1].category, "Information Disclosure")
        self.assertEqual(candidates[1].endpoint, "/openapi.json")

    def test_run_nuclei_invokes_subprocess_without_shell(self) -> None:
        completed = subprocess.CompletedProcess(args=["nuclei"], returncode=0, stdout=NUCLEI_JSONL, stderr="")
        with patch("app.tools.nuclei.subprocess.run", return_value=completed) as mocked_run:
            result = run_nuclei("http://127.0.0.1:3000", self.scope_guard, self.settings)
        self.assertTrue(result.success)
        self.assertEqual(len(result.candidates), 2)
        _, kwargs = mocked_run.call_args
        self.assertFalse(kwargs.get("shell", False))

    def test_nuclei_filters_non_finding_templates(self) -> None:
        candidates = parse_nuclei_jsonl(NUCLEI_FILTERED_JSONL)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].raw_reference, "swagger-api")
        self.assertEqual(candidates[0].endpoint, "/api-docs/swagger.json")
