from __future__ import annotations

import unittest

from app.core.models import HTTPHeader, SecurityHeader, WebProbeResult
from app.tools.technology_detect import detect_technologies


class TechnologyDetectTests(unittest.TestCase):
    def test_detects_technologies_from_headers_and_scripts(self) -> None:
        probe = WebProbeResult(
            target="http://127.0.0.1:3000",
            in_scope=True,
            final_url="http://127.0.0.1:3000",
            status_code=200,
            reason_phrase="OK",
            ip="127.0.0.1",
            port=3000,
            scheme="http",
            title="Lab",
            server="Node.js",
            content_type="text/html",
            headers=[HTTPHeader(name="X-Powered-By", value="Express")],
            security_headers=[SecurityHeader(name="X-Frame-Options", present=True, value="DENY")],
            meta_tags={"generator": "WordPress"},
            script_urls=["/static/angular.js"],
            body_preview="<html ng-version='15.0.0'></html>",
            body_length=50,
        )

        results = detect_technologies(probe)
        names = {result.name for result in results}

        self.assertIn("Angular", names)
        self.assertIn("Node.js", names)
        self.assertIn("Express", names)
        self.assertIn("WordPress", names)

    def test_detects_juice_shop_fingerprint(self) -> None:
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
            script_urls=["polyfills.js", "scripts.js", "main.js"],
            body_preview="<html><body><app-root></app-root></body></html>",
            body_length=80,
        )

        results = detect_technologies(probe)
        names = {result.name for result in results}

        self.assertIn("OWASP Juice Shop", names)
        self.assertIn("Angular", names)
        self.assertIn("Node.js", names)
