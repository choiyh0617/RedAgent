from __future__ import annotations

import time
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app.core.config import Settings
from app.core.scope import ScopeGuard, ScopeViolationError
from app.security.guardrails import GuardedAction, GuardrailService


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class BodyInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._inside_title = False
        self.title_parts: list[str] = []
        self.meta_tags: dict[str, str] = {}
        self.script_urls: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag_name = tag.lower()
        attributes = {key.lower(): value for key, value in attrs}
        if tag_name == "title":
            self._inside_title = True
            return
        if tag_name == "meta":
            name = (
                attributes.get("name")
                or attributes.get("property")
                or attributes.get("http-equiv")
                or ""
            ).strip()
            content = (attributes.get("content") or "").strip()
            if name and content:
                self.meta_tags[name.lower()] = content
            return
        if tag_name == "script":
            src = (attributes.get("src") or "").strip()
            if src:
                self.script_urls.append(src)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            stripped = data.strip()
            if stripped:
                self.title_parts.append(stripped)


@dataclass(slots=True)
class HTTPFetchResult:
    requested_url: str
    final_url: str
    status_code: int
    reason_phrase: str
    headers: list[tuple[str, str]]
    body: bytes
    body_length: int
    redirect_location: str | None
    blocked_redirect: bool
    redirect_chain: list[tuple[str, str, int, bool]]
    response_time_ms: int


def perform_request(
    url: str,
    *,
    tool_name: str,
    scope_guard: ScopeGuard,
    settings: Settings,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout_seconds: float | None = None,
    read_limit: int = 16384,
) -> HTTPFetchResult:
    GuardrailService(scope_guard).enforce_scope(GuardedAction(tool_name=tool_name, target=url))
    opener = build_opener(_NoRedirectHandler())
    request_headers = {"User-Agent": settings.user_agent}
    if headers:
        request_headers.update(headers)
    request = Request(url, headers=request_headers, method=method)

    start = time.perf_counter()
    try:
        with opener.open(request, timeout=timeout_seconds or settings.web_request_timeout_seconds) as response:
            body = response.read(read_limit)
            final_url = response.geturl() if hasattr(response, "geturl") else url
            result = HTTPFetchResult(
                requested_url=url,
                final_url=final_url,
                status_code=response.getcode(),
                reason_phrase=str(getattr(response, "reason", "OK")),
                headers=list(response.headers.items()),
                body=body,
                body_length=len(body),
                redirect_location=None,
                blocked_redirect=False,
                redirect_chain=[],
                response_time_ms=int((time.perf_counter() - start) * 1000),
            )
            return result
    except HTTPError as exc:
        body = exc.read(read_limit) if exc.fp else b""
        redirect_location = exc.headers.get("Location")
        redirect_chain: list[tuple[str, str, int, bool]] = []
        blocked_redirect = False
        if redirect_location:
            absolute_redirect = urljoin(url, redirect_location)
            try:
                scope_guard.validate_redirect(url, absolute_redirect)
            except ScopeViolationError:
                blocked_redirect = True
            redirect_chain.append((url, absolute_redirect, exc.code, blocked_redirect))
        return HTTPFetchResult(
            requested_url=url,
            final_url=exc.geturl(),
            status_code=exc.code,
            reason_phrase=str(getattr(exc, "reason", "HTTPError")),
            headers=list(exc.headers.items()),
            body=body,
            body_length=len(body),
            redirect_location=redirect_location,
            blocked_redirect=blocked_redirect,
            redirect_chain=redirect_chain,
            response_time_ms=int((time.perf_counter() - start) * 1000),
        )
    except URLError as exc:
        raise RuntimeError(f"request failed: {exc.reason}") from exc


def inspect_html(body: bytes) -> tuple[str | None, dict[str, str], list[str], str | None]:
    preview = body.decode("utf-8", errors="ignore")
    parser = BodyInspector()
    try:
        parser.feed(preview)
    except Exception:
        return None, {}, [], preview[:2048] or None
    title = " ".join(parser.title_parts) or None
    return title, parser.meta_tags, parser.script_urls, preview[:2048] or None
