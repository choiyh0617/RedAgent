from __future__ import annotations

from app.core.scope import ScopeGuard
from app.eval.metrics import RuntimeMetricsCollector
from app.validation.router import ValidationService


class ValidationAgent:
    def __init__(self, settings, scope_guard: ScopeGuard, metrics_collector: RuntimeMetricsCollector | None = None) -> None:
        self.service = ValidationService(settings, scope_guard, metrics_collector=metrics_collector)

    def validate_finding(self, candidate, analysis, *, remaining_scan_requests: int):
        return self.service.validate_candidate(
            candidate,
            analysis,
            remaining_scan_requests=remaining_scan_requests,
        )
