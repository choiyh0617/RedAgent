from __future__ import annotations

from urllib.parse import urljoin

from app.core.config import Settings
from app.core.models import EndpointProbeResult
from app.core.scope import ScopeGuard
from app.tools.http_utils import perform_request


COMMON_ENDPOINT_PATHS = [
    "/",
    "/robots.txt",
    "/login",
    "/admin",
    "/administration",
    "/api",
    "/rest",
    "/health",
    "/swagger",
    "/openapi.json",
]


def discover_common_endpoints(target: str, scope_guard: ScopeGuard, settings: Settings) -> list[EndpointProbeResult]:
    target_info = scope_guard.parse_target(target)
    results: list[EndpointProbeResult] = []

    for path in COMMON_ENDPOINT_PATHS[: settings.max_endpoint_probes]:
        endpoint_url = urljoin(str(target_info.normalized), path)
        response = perform_request(
            endpoint_url,
            tool_name="common_endpoints",
            scope_guard=scope_guard,
            settings=settings,
            method="HEAD",
            read_limit=1024,
        )
        method = "HEAD"
        if response.status_code in {405, 501}:
            response = perform_request(
                endpoint_url,
                tool_name="common_endpoints",
                scope_guard=scope_guard,
                settings=settings,
                method="GET",
                read_limit=2048,
            )
            method = "GET"

        results.append(
            EndpointProbeResult(
                path=path,
                url=endpoint_url,
                method=method,
                status_code=response.status_code,
                content_type=_find_header(response.headers, "Content-Type"),
                redirect_location=response.redirect_location,
                blocked_redirect=response.blocked_redirect,
                exists=_endpoint_exists(response.status_code),
            )
        )

    return results


def _find_header(headers: list[tuple[str, str]], header_name: str) -> str | None:
    target_name = header_name.lower()
    for name, value in headers:
        if name.lower() == target_name:
            return value
    return None


def _endpoint_exists(status_code: int) -> bool:
    return status_code < 400 or status_code in {401, 403, 405}
