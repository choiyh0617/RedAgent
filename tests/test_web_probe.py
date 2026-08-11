from __future__ import annotations

import unittest
from email.message import Message
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError

from app.core.config import Settings
from app.core.scope import ScopeGuard
from app.tools.web_probe import web_probe


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict[str, str], body: bytes, reason: str = "OK") -> None:
        self._status_code = status_code
        self.headers = Message()
        for name, value in headers.items():
            self.headers[name] = value
        self._body = body
        self.reason = reason

    def getcode(self) -> int:
        return self._status_code

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def geturl(self) -> str:
        return "http://127.0.0.1:3000"


class _FakeOpener:
    def __init__(self, response: _FakeResponse | HTTPError) -> None:
        self.response = response

    def open(self, request, timeout: float):
        if isinstance(self.response, HTTPError):
            raise self.response
        return self.response


class WebProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings()
        self.scope_guard = ScopeGuard(self.settings)

    def test_probe_returns_structured_response(self) -> None:
        body = (
            b"<html><head><title>Juice Shop Lab</title>"
            b"<meta name='generator' content='Lab CMS'>"
            b"<script src='/static/angular.js'></script></head><body>ok</body></html>"
        )
        response = _FakeResponse(
            status_code=200,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Server": "lab-server",
                "X-Frame-Options": "DENY",
            },
            body=body,
        )

        with patch("app.tools.http_utils.build_opener", return_value=_FakeOpener(response)):
            result = web_probe(
                target="http://127.0.0.1:3000",
                scope_guard=self.scope_guard,
                settings=self.settings,
            )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.title, "Juice Shop Lab")
        self.assertFalse(result.blocked_redirect)
        self.assertEqual(result.port, 3000)
        self.assertEqual(result.server, "lab-server")
        self.assertEqual(result.final_url, "http://127.0.0.1:3000")
        self.assertEqual(result.body_length, len(body))
        self.assertIn("/static/angular.js", result.script_urls)
        self.assertEqual(result.meta_tags["generator"], "Lab CMS")
        security_headers = {header.name: header for header in result.security_headers}
        self.assertTrue(security_headers["X-Frame-Options"].present)
        self.assertFalse(security_headers["Content-Security-Policy"].present)

    def test_probe_marks_external_redirect_as_blocked(self) -> None:
        headers = Message()
        headers["Location"] = "http://example.com/offsite"
        error = HTTPError(
            url="http://127.0.0.1:3000/redirect",
            code=302,
            msg="Found",
            hdrs=headers,
            fp=BytesIO(b""),
        )

        with patch("app.tools.http_utils.build_opener", return_value=_FakeOpener(error)):
            result = web_probe(
                target="http://127.0.0.1:3000/redirect",
                scope_guard=self.scope_guard,
                settings=self.settings,
            )

        self.assertEqual(result.status_code, 302)
        self.assertTrue(result.blocked_redirect)
        self.assertEqual(result.redirect_location, "http://example.com/offsite")
        self.assertEqual(len(result.redirect_chain), 1)
        self.assertTrue(result.redirect_chain[0].blocked)
