from __future__ import annotations

from urllib.parse import urljoin

from app.core.config import Settings
from app.core.models import RobotsTxtResult
from app.core.scope import ScopeGuard
from app.tools.http_utils import perform_request


def inspect_robots_txt(target: str, scope_guard: ScopeGuard, settings: Settings) -> RobotsTxtResult:
    target_info = scope_guard.parse_target(target)
    robots_url = urljoin(str(target_info.normalized), "/robots.txt")
    response = perform_request(
        robots_url,
        tool_name="robots_txt",
        scope_guard=scope_guard,
        settings=settings,
        method="GET",
        read_limit=16384,
    )
    allow, disallow, sitemaps = _parse_robots_txt(response.body.decode("utf-8", errors="ignore"))
    return RobotsTxtResult(
        target=target_info.normalized,
        url=robots_url,
        status_code=response.status_code,
        exists=response.status_code == 200,
        allow=allow,
        disallow=disallow,
        sitemaps=sitemaps,
        redirect_location=response.redirect_location,
        blocked_redirect=response.blocked_redirect,
    )


def _parse_robots_txt(content: str) -> tuple[list[str], list[str], list[str]]:
    allow: list[str] = []
    disallow: list[str] = []
    sitemaps: list[str] = []
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        directive = key.strip().lower()
        parsed_value = value.strip()
        if directive == "allow" and parsed_value:
            allow.append(parsed_value)
        elif directive == "disallow" and parsed_value:
            disallow.append(parsed_value)
        elif directive == "sitemap" and parsed_value:
            sitemaps.append(parsed_value)
    return allow, disallow, sitemaps
