from __future__ import annotations

import socket

from app.core.config import Settings
from app.core.models import HTTPHeader, RedirectHop, SecurityHeader, WebProbeResult
from app.core.scope import ScopeGuard
from app.tools.http_utils import inspect_html, perform_request


SECURITY_HEADER_NAMES = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


def web_probe(target: str, scope_guard: ScopeGuard, settings: Settings) -> WebProbeResult:
    target_info = scope_guard.parse_target(target)
    response = perform_request(
        target,
        tool_name="web_probe",
        scope_guard=scope_guard,
        settings=settings,
        method="GET",
        read_limit=16384,
    )
    title, meta_tags, script_urls, body_preview = inspect_html(response.body)
    header_items = [HTTPHeader(name=name, value=value) for name, value in response.headers]
    headers_lookup = {header.name.lower(): header.value for header in header_items}
    security_headers = [
        SecurityHeader(
            name=header_name,
            present=header_name.lower() in headers_lookup,
            value=headers_lookup.get(header_name.lower()),
        )
        for header_name in SECURITY_HEADER_NAMES
    ]
    redirect_chain = [
        RedirectHop(from_url=from_url, to_url=to_url, status_code=status_code, blocked=blocked)
        for from_url, to_url, status_code, blocked in response.redirect_chain
    ]

    return WebProbeResult(
        target=target_info.normalized,
        in_scope=True,
        final_url=response.final_url,
        status_code=response.status_code,
        reason_phrase=response.reason_phrase,
        ip=target_info.ip or _best_effort_ip(target_info.hostname),
        port=target_info.port,
        scheme=target_info.scheme,
        title=title,
        server=headers_lookup.get("server"),
        content_type=headers_lookup.get("content-type"),
        headers=header_items,
        security_headers=security_headers,
        meta_tags=meta_tags,
        script_urls=script_urls,
        body_preview=body_preview,
        body_length=response.body_length,
        redirect_chain=redirect_chain,
        redirect_location=response.redirect_location,
        blocked_redirect=response.blocked_redirect,
        response_time_ms=response.response_time_ms,
    )


def _best_effort_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None
