from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.config import Settings
from app.core.models import ScanRecord, ScanStatus
from app.core.scope import ScopeGuard
from app.orchestrator.workflow import run_initial_recon
from app.reports.generator import ReportBuilder


class ScanSupervisor:
    def __init__(self, settings: Settings, scope_guard: ScopeGuard) -> None:
        self.settings = settings
        self.scope_guard = scope_guard

    def run_scan(self, target: str) -> ScanRecord:
        started_at = datetime.now(timezone.utc)
        recon = run_initial_recon(target=target, scope_guard=self.scope_guard, settings=self.settings)
        completed_at = datetime.now(timezone.utc)
        scan = ScanRecord(
            scan_id=str(uuid.uuid4()),
            target=recon.target,
            status=ScanStatus.COMPLETED,
            created_at=started_at,
            updated_at=completed_at,
            scope=[*self.settings.allowed_hosts, *self.settings.allowed_networks],
            recon=recon,
            finding_candidates=recon.finding_candidates,
            tools_used=recon.tool_executions,
            validation_metrics=recon.validation_metrics,
            runtime_metrics=recon.runtime_metrics,
        )
        report = ReportBuilder().build_final_findings(scan)
        return scan.model_copy(update={"findings": [item.model_dump(mode="json") for item in report]})
