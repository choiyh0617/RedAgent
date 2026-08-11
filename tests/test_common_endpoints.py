from __future__ import annotations

import unittest
from unittest.mock import patch

from app.core.config import Settings
from app.core.scope import ScopeGuard
from app.tools.common_endpoints import discover_common_endpoints
from app.tools.http_utils import HTTPFetchResult


class CommonEndpointsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings(max_endpoint_probes=2)
        self.scope_guard = ScopeGuard(self.settings)

    def test_endpoint_probe_uses_head_and_falls_back_to_get(self) -> None:
        responses = [
            HTTPFetchResult(
                requested_url="http://127.0.0.1:3000/",
                final_url="http://127.0.0.1:3000/",
                status_code=405,
                reason_phrase="Method Not Allowed",
                headers=[("Content-Type", "text/html")],
                body=b"",
                body_length=0,
                redirect_location=None,
                blocked_redirect=False,
                redirect_chain=[],
                response_time_ms=1,
            ),
            HTTPFetchResult(
                requested_url="http://127.0.0.1:3000/",
                final_url="http://127.0.0.1:3000/",
                status_code=200,
                reason_phrase="OK",
                headers=[("Content-Type", "text/html")],
                body=b"ok",
                body_length=2,
                redirect_location=None,
                blocked_redirect=False,
                redirect_chain=[],
                response_time_ms=1,
            ),
            HTTPFetchResult(
                requested_url="http://127.0.0.1:3000/robots.txt",
                final_url="http://127.0.0.1:3000/robots.txt",
                status_code=200,
                reason_phrase="OK",
                headers=[("Content-Type", "text/plain")],
                body=b"",
                body_length=0,
                redirect_location=None,
                blocked_redirect=False,
                redirect_chain=[],
                response_time_ms=1,
            ),
        ]
        with patch("app.tools.common_endpoints.perform_request", side_effect=responses) as mocked_request:
            results = discover_common_endpoints("http://127.0.0.1:3000", self.scope_guard, self.settings)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].method, "GET")
        self.assertTrue(results[0].exists)
        self.assertEqual(results[1].path, "/robots.txt")
        self.assertEqual(mocked_request.call_count, 3)
