from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
import re
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from app.core.config import Settings
from app.core.models import CrawlForm, CrawlPageResult, CrawlResult, FindingCandidate, Severity
from app.core.scope import ScopeGuard, ScopeViolationError
from app.tools.http_utils import inspect_html, perform_request


SCRIPT_DISCOVERY_LIMIT = 2
SCRIPT_PATH_PATTERN = re.compile(
    r"""["']((?:/?(?:api-docs|api|rest|login|admin|basket|health|status|swagger|openapi(?:\.json)?)(?:/[^"'?#]*)?))["']""",
    re.IGNORECASE,
)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[CrawlForm] = []
        self._current_form: CrawlForm | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = {key.lower(): value for key, value in attrs}
        tag_name = tag.lower()
        if tag_name == "a":
            href = (attributes.get("href") or "").strip()
            if href:
                self.links.append(href)
        elif tag_name == "form":
            action = (attributes.get("action") or "").strip()
            method = (attributes.get("method") or "GET").upper()
            self._current_form = CrawlForm(action=action or "", method=method, fields=[])
            self.forms.append(self._current_form)
        elif tag_name == "input" and self._current_form is not None:
            name = (attributes.get("name") or "").strip()
            if name and name not in self._current_form.fields:
                self._current_form.fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


def crawl_web(target: str, scope_guard: ScopeGuard, settings: Settings) -> CrawlResult:
    target_info = scope_guard.parse_target(target)
    root_url = _canonicalize_url(str(target_info.normalized))
    expected_origin = (target_info.scheme, target_info.hostname, target_info.port)
    queue = deque([(root_url, 0)])
    visited: set[str] = set()
    pages: list[CrawlPageResult] = []
    discovered_urls: list[str] = []
    total_requests = 0
    max_depth_reached = 0

    while queue and len(pages) < settings.max_crawl_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        max_depth_reached = max(max_depth_reached, depth)

        try:
            response = perform_request(
                url,
                tool_name="crawler",
                scope_guard=scope_guard,
                settings=settings,
                method="GET",
                read_limit=32768,
            )
        except RuntimeError:
            total_requests += 1
            continue

        total_requests += 1
        content_type = _find_header(response.headers, "Content-Type")
        title, _, script_urls, _ = inspect_html(response.body)
        links, forms = _parse_page(response.body)
        normalized_links = _normalize_links(
            links=links,
            base_url=url,
            scope_guard=scope_guard,
            expected_origin=expected_origin,
        )
        script_links, script_request_count = _discover_links_from_scripts(
            base_url=url,
            script_urls=script_urls,
            scope_guard=scope_guard,
            settings=settings,
            expected_origin=expected_origin,
            budget=max(0, settings.max_crawl_pages - len(visited) - len(queue)),
        )
        total_requests += script_request_count
        normalized_links = _combine_links(normalized_links, script_links)
        parameters = sorted({name for link in normalized_links for name, _ in parse_qsl(urlparse(link).query)})
        api_endpoints = [link for link in normalized_links if _looks_like_api(link)]

        page = CrawlPageResult(
            url=url,
            depth=depth,
            status_code=response.status_code,
            title=title,
            content_type=content_type,
            links=normalized_links,
            forms=forms,
            parameters=parameters,
            script_urls=script_urls,
            api_endpoints=api_endpoints,
        )
        pages.append(page)

        for link in normalized_links:
            if depth >= settings.max_crawl_depth:
                continue
            if link in visited or any(queued == link for queued, _ in queue):
                continue
            if len(visited) + len(queue) >= settings.max_crawl_pages:
                continue
            if link not in discovered_urls:
                discovered_urls.append(link)
            queue.append((link, depth + 1))

    return CrawlResult(
        target=target_info.normalized,
        pages=pages,
        discovered_urls=discovered_urls,
        total_requests=total_requests,
        max_depth_reached=max_depth_reached,
        success=True,
    )


def normalize_crawl_candidates(crawl: CrawlResult) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    seen: set[tuple[str, str]] = set()

    for page in crawl.pages:
        parsed = urlparse(page.url)
        path = parsed.path or "/"
        if path in {"/admin", "/swagger", "/openapi.json", "/api-docs/swagger.json"}:
            title = {
                "/admin": "Administrative Endpoint Discovered",
                "/swagger": "API Documentation Endpoint Discovered",
                "/openapi.json": "OpenAPI Specification Exposed",
                "/api-docs/swagger.json": "Swagger Specification Exposed",
            }[path]
            category = "Information Disclosure" if "swagger" in path or "openapi" in path else "Attack Surface"
            key = (title, page.url)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                FindingCandidate(
                    id=f"CRAWL-{len(candidates) + 1:03d}",
                    title=title,
                    category=category,
                    severity=Severity.INFO,
                    endpoint=page.url,
                    method="GET",
                    evidence=[f"crawler discovered endpoint {path}", f"status={page.status_code}"],
                    source_tool="crawler",
                    confidence=0.55 if "swagger" in path or "openapi" in path else 0.35,
                    raw_reference=page.url,
                )
            )

    return candidates


def _parse_page(body: bytes) -> tuple[list[str], list[CrawlForm]]:
    parser = _PageParser()
    parser.feed(body.decode("utf-8", errors="ignore"))
    return parser.links, parser.forms


def _normalize_links(
    *,
    links: list[str],
    base_url: str,
    scope_guard: ScopeGuard,
    expected_origin: tuple[str, str, int],
) -> list[str]:
    normalized: list[str] = []
    for link in links:
        absolute = _canonicalize_url(urljoin(base_url, link))
        parsed = urlparse(absolute)
        if (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)) != expected_origin:
            continue
        try:
            scope_guard.validate(absolute)
        except ScopeViolationError:
            continue
        if absolute not in normalized:
            normalized.append(absolute)
    return normalized


def _discover_links_from_scripts(
    *,
    base_url: str,
    script_urls: list[str],
    scope_guard: ScopeGuard,
    settings: Settings,
    expected_origin: tuple[str, str, int],
    budget: int,
) -> tuple[list[str], int]:
    if budget <= 0:
        return [], 0

    discovered: list[str] = []
    request_count = 0
    for script_url in _prioritize_script_urls(script_urls)[:SCRIPT_DISCOVERY_LIMIT]:
        absolute_script_url = _canonicalize_url(urljoin(base_url, script_url))
        parsed_script = urlparse(absolute_script_url)
        if (parsed_script.scheme, parsed_script.hostname, parsed_script.port or (443 if parsed_script.scheme == "https" else 80)) != expected_origin:
            continue
        try:
            response = perform_request(
                absolute_script_url,
                tool_name="crawler",
                scope_guard=scope_guard,
                settings=settings,
                method="GET",
                read_limit=32768,
            )
        except RuntimeError:
            request_count += 1
            continue
        request_count += 1
        script_body = response.body.decode("utf-8", errors="ignore")
        extracted = [match.group(1) for match in SCRIPT_PATH_PATTERN.finditer(script_body)]
        normalized = _normalize_links(
            links=extracted,
            base_url=base_url,
            scope_guard=scope_guard,
            expected_origin=expected_origin,
        )
        discovered = _combine_links(discovered, normalized[:budget])
        if len(discovered) >= budget:
            break
    return discovered, request_count


def _prioritize_script_urls(script_urls: list[str]) -> list[str]:
    def sort_key(script_url: str) -> tuple[int, str]:
        name = script_url.rsplit("/", 1)[-1].lower()
        if "main" in name or "app" in name:
            return (0, name)
        if "script" in name:
            return (1, name)
        if "polyfill" in name:
            return (2, name)
        return (3, name)

    return sorted(dict.fromkeys(script_urls), key=sort_key)


def _combine_links(existing: list[str], incoming: list[str]) -> list[str]:
    combined = list(existing)
    for link in incoming:
        if link not in combined:
            combined.append(link)
    return combined


def _canonicalize_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    fragmentless = parsed._replace(fragment="", path=path)
    return urlunparse(fragmentless)


def _find_header(headers: list[tuple[str, str]], header_name: str) -> str | None:
    target = header_name.lower()
    for name, value in headers:
        if name.lower() == target:
            return value
    return None


def _looks_like_api(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.startswith("/api") or path.startswith("/rest")
