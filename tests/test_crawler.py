from __future__ import annotations

import unittest
from unittest.mock import patch

from app.core.config import Settings
from app.core.scope import ScopeGuard, ScopeViolationError
from app.tools.crawler import crawl_web, normalize_crawl_candidates
from app.tools.http_utils import HTTPFetchResult


def _response(url: str, body: str, status_code: int = 200, content_type: str = "text/html") -> HTTPFetchResult:
    return HTTPFetchResult(
        requested_url=url,
        final_url=url,
        status_code=status_code,
        reason_phrase="OK",
        headers=[("Content-Type", content_type)],
        body=body.encode("utf-8"),
        body_length=len(body.encode("utf-8")),
        redirect_location=None,
        blocked_redirect=False,
        redirect_chain=[],
        response_time_ms=1,
    )


class CrawlerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings(max_crawl_depth=1, max_crawl_pages=2)
        self.scope_guard = ScopeGuard(self.settings)

    def test_scope_blocking_happens_before_crawl(self) -> None:
        with self.assertRaises(ScopeViolationError):
            crawl_web("http://example.com", self.scope_guard, self.settings)

    def test_deduplication_and_same_origin_restrictions(self) -> None:
        responses = {
            "http://127.0.0.1:3000/": _response(
                "http://127.0.0.1:3000/",
                """
                <html><body>
                  <a href="/admin">admin</a>
                  <a href="/admin">admin again</a>
                  <a href="http://example.com/out">external</a>
                </body></html>
                """,
            ),
            "http://127.0.0.1:3000/admin": _response("http://127.0.0.1:3000/admin", "<html></html>"),
        }

        with patch("app.tools.crawler.perform_request", side_effect=lambda url, **_: responses[url]) as mocked:
            result = crawl_web("http://127.0.0.1:3000", self.scope_guard, self.settings)

        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(result.discovered_urls, ["http://127.0.0.1:3000/admin"])
        self.assertTrue(all("example.com" not in page.url for page in result.pages))

    def test_max_depth_and_max_pages_are_enforced(self) -> None:
        responses = {
            "http://127.0.0.1:3000/": _response(
                "http://127.0.0.1:3000/",
                """
                <html><body>
                  <a href="/one">one</a>
                  <a href="/two">two</a>
                </body></html>
                """,
            ),
            "http://127.0.0.1:3000/one": _response(
                "http://127.0.0.1:3000/one",
                "<html><body><a href='/three'>three</a></body></html>",
            ),
        }

        with patch("app.tools.crawler.perform_request", side_effect=lambda url, **_: responses[url]):
            result = crawl_web("http://127.0.0.1:3000", self.scope_guard, self.settings)

        self.assertEqual(len(result.pages), 2)
        self.assertEqual(result.max_depth_reached, 1)
        self.assertNotIn("http://127.0.0.1:3000/three", result.discovered_urls)

    def test_crawl_candidate_normalization(self) -> None:
        responses = {
            "http://127.0.0.1:3000/": _response(
                "http://127.0.0.1:3000/",
                "<html><body><a href='/admin'>admin</a><a href='/swagger'>swagger</a></body></html>",
            ),
            "http://127.0.0.1:3000/admin": _response("http://127.0.0.1:3000/admin", "<html></html>"),
        }

        with patch("app.tools.crawler.perform_request", side_effect=lambda url, **_: responses[url]):
            result = crawl_web("http://127.0.0.1:3000", self.scope_guard, self.settings)
        candidates = normalize_crawl_candidates(result)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].title, "Administrative Endpoint Discovered")

    def test_discovers_api_path_from_script_bundle(self) -> None:
        settings = Settings(max_crawl_depth=1, max_crawl_pages=4)
        responses = {
            "http://127.0.0.1:3000/": _response(
                "http://127.0.0.1:3000/",
                "<html><head><script src='/main.js'></script></head><body><app-root></app-root></body></html>",
            ),
            "http://127.0.0.1:3000/main.js": _response(
                "http://127.0.0.1:3000/main.js",
                'const swagger="/api-docs/swagger.json"; const login="/login";',
                content_type="application/javascript",
            ),
            "http://127.0.0.1:3000/api-docs/swagger.json": _response(
                "http://127.0.0.1:3000/api-docs/swagger.json",
                '{"openapi":"3.0.0"}',
                content_type="application/json",
            ),
            "http://127.0.0.1:3000/login": _response(
                "http://127.0.0.1:3000/login",
                "<html>login</html>",
            ),
        }

        with patch("app.tools.crawler.perform_request", side_effect=lambda url, **_: responses[url]):
            result = crawl_web("http://127.0.0.1:3000", ScopeGuard(settings), settings)

        self.assertIn("http://127.0.0.1:3000/api-docs/swagger.json", result.discovered_urls)
        page_urls = {page.url for page in result.pages}
        self.assertIn("http://127.0.0.1:3000/api-docs/swagger.json", page_urls)
