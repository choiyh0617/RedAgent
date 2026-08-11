from __future__ import annotations

import unittest
from unittest.mock import patch

from app.core.config import Settings
from app.core.scope import ScopeGuard
from app.tools.http_utils import HTTPFetchResult
from app.tools.robots_txt import _parse_robots_txt, inspect_robots_txt


class RobotsTxtTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings()
        self.scope_guard = ScopeGuard(self.settings)

    def test_parse_robots_txt(self) -> None:
        allow, disallow, sitemaps = _parse_robots_txt(
            "User-agent: *\nDisallow: /admin\nAllow: /api\nSitemap: http://127.0.0.1:3000/sitemap.xml\n"
        )
        self.assertEqual(allow, ["/api"])
        self.assertEqual(disallow, ["/admin"])
        self.assertEqual(sitemaps, ["http://127.0.0.1:3000/sitemap.xml"])

    def test_inspect_robots_txt_returns_structured_result(self) -> None:
        response = HTTPFetchResult(
            requested_url="http://127.0.0.1:3000/robots.txt",
            final_url="http://127.0.0.1:3000/robots.txt",
            status_code=200,
            reason_phrase="OK",
            headers=[("Content-Type", "text/plain")],
            body=b"Disallow: /private\nAllow: /public\n",
            body_length=33,
            redirect_location=None,
            blocked_redirect=False,
            redirect_chain=[],
            response_time_ms=5,
        )
        with patch("app.tools.robots_txt.perform_request", return_value=response):
            result = inspect_robots_txt("http://127.0.0.1:3000", self.scope_guard, self.settings)

        self.assertTrue(result.exists)
        self.assertEqual(result.disallow, ["/private"])
        self.assertEqual(result.allow, ["/public"])
