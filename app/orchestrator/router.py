from __future__ import annotations

from app.core.models import ReconResult


def select_next_steps(recon: ReconResult) -> list[str]:
    steps: list[str] = []
    if recon.http_services:
        steps.append("web_discovery")
        steps.append("scanner_phase")
    return steps
