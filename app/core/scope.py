from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from .config import Settings
from .models import ScopeDecision, TargetInfo


class ScopeViolationError(ValueError):
    """Raised when a target falls outside the configured lab scope."""


@dataclass(slots=True)
class ResolvedTarget:
    hostname: str
    port: int
    scheme: str
    ip: str | None


class ScopeGuard:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.allowed_hosts = {host.lower() for host in settings.allowed_hosts}
        self.allowed_networks = settings.parsed_allowed_networks()

    def validate(self, target: str) -> ScopeDecision:
        target_info = self.parse_target(target)
        if self._is_allowed(target_info.hostname, target_info.ip):
            return ScopeDecision(
                target=target,
                normalized_target=str(target_info.normalized),
                allowed=True,
                reason="target is within authorized scope",
            )
        raise ScopeViolationError(f"Target outside allowed scope: {target_info.hostname}")

    def parse_target(self, target: str) -> TargetInfo:
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeViolationError(f"Unsupported URL scheme: {parsed.scheme or 'missing'}")
        if not parsed.hostname:
            raise ScopeViolationError("Target URL must include a hostname")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        resolved_ip = self._resolve(parsed.hostname)
        return TargetInfo(
            original=target,
            normalized=target,
            scheme=parsed.scheme,
            hostname=parsed.hostname,
            port=port,
            ip=resolved_ip,
        )

    def validate_redirect(self, current_target: str, redirect_url: str) -> None:
        redirect_info = self.parse_target(redirect_url)
        if not self._is_allowed(redirect_info.hostname, redirect_info.ip):
            raise ScopeViolationError(
                f"Redirect target outside authorized scope: {redirect_info.hostname}"
            )

    def _resolve(self, hostname: str) -> str | None:
        try:
            return socket.gethostbyname(hostname)
        except OSError:
            return None

    def _is_allowed(self, hostname: str, ip: str | None) -> bool:
        normalized_host = hostname.lower()
        if normalized_host in self.allowed_hosts:
            return True

        candidate_ip = ip or self._resolve(hostname)
        if not candidate_ip:
            return False

        try:
            ip_obj = ipaddress.ip_address(candidate_ip)
        except ValueError:
            return False

        if candidate_ip in self.allowed_hosts:
            return True
        return any(ip_obj in network for network in self.allowed_networks)
