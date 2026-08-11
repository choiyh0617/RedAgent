from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any
from urllib.parse import urlparse
from pathlib import Path

from app.core.config import Settings
from app.core.models import FindingCandidate, NucleiScanResult, Severity
from app.core.scope import ScopeGuard
from app.security.guardrails import GuardedAction, GuardrailService


SAFE_NUCLEI_TEMPLATE_PATHS = [
    "nuclei-templates/http/exposures/apis/swagger-api.yaml",
    "nuclei-templates/http/miscellaneous/x-recruiting-header.yaml",
    "nuclei-templates/http/misconfiguration/weak-csp-detect.yaml",
    "nuclei-templates/http/technologies/owasp-juice-shop-detected.yaml",
]
NON_FINDING_TEMPLATE_IDS = {
    "x-recruiting-header",
    "owasp-juice-shop-detect",
}


def run_nuclei(target: str, scope_guard: ScopeGuard, settings: Settings) -> NucleiScanResult:
    GuardrailService(scope_guard).enforce_scope(GuardedAction(tool_name="nuclei", target=target))
    target_info = scope_guard.parse_target(target)

    if not settings.nuclei_enabled:
        return NucleiScanResult(
            target=target_info.normalized,
            success=False,
            error="nuclei disabled by configuration",
        )

    command = _build_nuclei_command(target, settings)
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.nuclei_timeout_seconds,
            check=False,
            env=_build_nuclei_env(),
        )
    except FileNotFoundError:
        return NucleiScanResult(
            target=target_info.normalized,
            command=command,
            success=False,
            scan_duration_ms=int((time.perf_counter() - start) * 1000),
            error="nuclei is not installed",
        )
    except subprocess.TimeoutExpired:
        return NucleiScanResult(
            target=target_info.normalized,
            command=command,
            success=False,
            scan_duration_ms=int((time.perf_counter() - start) * 1000),
            error=f"nuclei timed out after {settings.nuclei_timeout_seconds} seconds",
        )

    candidates = parse_nuclei_jsonl(completed.stdout)
    duration_ms = int((time.perf_counter() - start) * 1000)
    success = completed.returncode == 0
    error = None if success else _sanitize_error(completed.stderr) or "nuclei scan failed"
    return NucleiScanResult(
        target=target_info.normalized,
        command=command,
        candidates=candidates,
        success=success,
        scan_duration_ms=duration_ms,
        error=error,
        raw_summary=f"{len(candidates)} candidate(s)",
    )


def parse_nuclei_jsonl(output: str) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    for index, raw_line in enumerate(output.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        data = json.loads(line)
        candidate = _normalize_nuclei_match(data, index)
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _build_nuclei_command(target: str, settings: Settings) -> list[str]:
    command = [
        "nuclei",
        "-u",
        target,
        "-type",
        "http",
        "-jsonl",
        "-silent",
        "-duc",
        "-severity",
        "info,low,medium,high",
        "-rl",
        "2",
        "-timeout",
        str(int(settings.nuclei_timeout_seconds)),
    ]
    for template_path in SAFE_NUCLEI_TEMPLATE_PATHS:
        command.extend(["-t", template_path])
    return command


def _normalize_nuclei_match(payload: dict[str, Any], index: int) -> FindingCandidate | None:
    info = payload.get("info", {})
    template_id = str(payload.get("template-id") or "")
    tags = {str(tag).lower() for tag in info.get("tags", [])}
    if template_id in NON_FINDING_TEMPLATE_IDS or ("tech" in tags and "misconfig" not in tags and "exposure" not in tags):
        return None

    severity = _normalize_severity(info.get("severity"))
    matched_at = payload.get("matched-at") or payload.get("host") or ""
    parsed = urlparse(matched_at)
    endpoint = parsed.path or "/"
    method = _extract_method(payload.get("request"))
    evidence = []
    matcher_name = payload.get("matcher-name")
    if matcher_name:
        evidence.append(f"matcher={matcher_name}")
    extracted_results = payload.get("extracted-results") or []
    evidence.extend(str(value) for value in extracted_results[:3])
    if matched_at:
        evidence.append(f"matched-at={matched_at}")

    title = info.get("name") or template_id or f"nuclei-match-{index}"
    category = _categorize_nuclei_match(info)
    confidence = 0.85 if severity in {Severity.HIGH, Severity.MEDIUM} else 0.7 if severity == Severity.LOW else 0.6
    return FindingCandidate(
        id=f"NUCLEI-{index:03d}",
        title=title,
        category=category,
        severity=severity,
        endpoint=parsed.path or endpoint,
        method=method,
        evidence=evidence or [f"matched-at={matched_at or 'unknown'}"],
        source_tool="nuclei",
        confidence=confidence,
        raw_reference=template_id or None,
    )


def _normalize_severity(value: str | None) -> Severity:
    normalized = (value or "info").strip().upper()
    return Severity[normalized] if normalized in Severity.__members__ else Severity.INFO


def _extract_method(request_blob: str | None) -> str:
    if not request_blob:
        return "GET"
    first_line = request_blob.splitlines()[0].strip()
    return first_line.split(" ", 1)[0] if first_line else "GET"


def _categorize_nuclei_match(info: dict[str, Any]) -> str:
    tags = [str(tag).lower() for tag in info.get("tags", [])]
    if "misconfig" in tags:
        return "Security Misconfiguration"
    if "exposure" in tags:
        return "Information Disclosure"
    if "swagger" in tags or "api" in tags:
        return "Information Disclosure"
    if "panel" in tags or "admin" in tags:
        return "Broken Access Control"
    return "Security Observation"


def _sanitize_error(value: str | None) -> str | None:
    if not value:
        return None
    return " ".join(value.strip().split())[:300] or None


def _build_nuclei_env() -> dict[str, str]:
    env = os.environ.copy()
    workspace_root = Path.cwd()
    env["HOME"] = str(workspace_root)
    env["XDG_CONFIG_HOME"] = str(workspace_root)
    env["XDG_CACHE_HOME"] = str(workspace_root / "Library" / "Caches")
    return env
