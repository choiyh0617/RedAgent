from __future__ import annotations

import html
import json
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.models import ScanRecord, Severity
from app.reports.models import (
    REPORT_SCHEMA_VERSION,
    ExecutiveSummary,
    FinalFinding,
    FinalSeverity,
    FindingEvidenceRecord,
    FindingReference,
    FindingSummary,
    GuardrailSummary,
    PentestReport,
    ReconSummary,
    ReportMetrics,
    ScanMetadata,
    ToolSummary,
    ValidationSummary,
)
from app.validation.sanitizer import EvidenceSanitizer


SEVERITY_ORDER = {
    FinalSeverity.CRITICAL.value: 0,
    FinalSeverity.HIGH.value: 1,
    FinalSeverity.MEDIUM.value: 2,
    FinalSeverity.LOW.value: 3,
    FinalSeverity.INFO.value: 4,
}
STATUS_ORDER = {
    "verified": 0,
    "likely": 1,
    "unverified": 2,
    "validation_skipped": 3,
    "false_positive": 4,
    "informational": 5,
}


class ReportBuilder:
    def __init__(self) -> None:
        self.sanitizer = EvidenceSanitizer()

    def build(self, scan: ScanRecord, *, app_name: str = "PentestFlow") -> PentestReport:
        generated_at = datetime.now(timezone.utc)
        findings = self.build_final_findings(scan)
        severity_counts = _count_values(item.severity.value for item in findings)
        status_counts = _count_values(item.final_status for item in findings)
        validation_summary = ValidationSummary.model_validate(scan.validation_metrics or {})
        guardrail_summary = self._guardrail_summary(scan, findings)
        metrics = ReportMetrics(
            scan_duration_ms=_scan_duration_ms(scan),
            tool_call_count=len(scan.tools_used),
            llm_call_count=None,
            rag_retrieval_count=sum(1 for candidate in scan.finding_candidates if candidate.rag_context),
            candidate_count=len(scan.finding_candidates),
            final_finding_count=len(findings),
            severity_counts=severity_counts,
            status_counts=status_counts,
            blocked_action_count=guardrail_summary.blocked_action_count,
            scope_violation_count=guardrail_summary.scope_violation_count,
            validation_attempted_count=validation_summary.validation_attempted_count,
            validation_verified_count=validation_summary.validation_verified_count,
            validation_false_positive_count=validation_summary.validation_false_positive_count,
            validation_unverified_count=validation_summary.validation_unverified_count,
            validation_skipped_count=validation_summary.validation_skipped_count,
            validation_request_count=validation_summary.validation_request_count,
            validation_duration=validation_summary.validation_duration,
        )
        executive_summary = ExecutiveSummary(
            target=scan.target,
            scan_id=scan.scan_id,
            scan_duration_ms=metrics.scan_duration_ms,
            total_findings=len(findings),
            confirmed_findings=status_counts.get("verified", 0) + status_counts.get("likely", 0),
            severity_counts=severity_counts,
            status_counts=status_counts,
            verified_findings=status_counts.get("verified", 0),
            unverified_findings=status_counts.get("unverified", 0),
            false_positive_findings=status_counts.get("false_positive", 0),
            validation_skipped_findings=status_counts.get("validation_skipped", 0),
        )
        return PentestReport(
            executive_summary=executive_summary,
            scope=scan.scope,
            scan_metadata=ScanMetadata(
                app_name=app_name,
                schema_version=REPORT_SCHEMA_VERSION,
                scan_id=scan.scan_id,
                status=str(scan.status),
                created_at=scan.created_at,
                updated_at=scan.updated_at,
                scan_duration_ms=metrics.scan_duration_ms,
                report_generated_at=generated_at,
            ),
            recon_summary=self._recon_summary(scan),
            finding_summary=FindingSummary(
                total_candidates=len(scan.finding_candidates),
                final_finding_count=len(findings),
                confirmed_finding_count=executive_summary.confirmed_findings,
                false_positive_count=status_counts.get("false_positive", 0),
                unverified_count=status_counts.get("unverified", 0),
                validation_skipped_count=status_counts.get("validation_skipped", 0),
                severity_counts=severity_counts,
                status_counts=status_counts,
            ),
            findings=findings,
            validation_summary=validation_summary,
            tool_execution_summary=[
                ToolSummary(tool=item.tool, success=item.success, duration_ms=item.duration_ms, error=item.error)
                for item in scan.tools_used
            ],
            guardrail_summary=guardrail_summary,
            limitations=_limitations(),
            metrics=metrics,
        )

    def build_final_findings(self, scan: ScanRecord) -> list[FinalFinding]:
        findings: list[FinalFinding] = []
        for candidate in scan.finding_candidates:
            try:
                findings.append(self._build_final_finding(scan, candidate))
            except Exception:
                continue
        return sorted(
            findings,
            key=lambda item: (
                SEVERITY_ORDER[item.severity.value],
                STATUS_ORDER[item.final_status],
                item.title.lower(),
                item.endpoint,
            ),
        )

    def _build_final_finding(self, scan: ScanRecord, candidate) -> FinalFinding:
        analysis = candidate.analysis or {}
        validation = candidate.validation or {}
        final_status = resolve_final_status(candidate, analysis, validation)
        severity = normalize_final_severity(candidate.severity, final_status)
        confidence = _resolve_confidence(candidate, analysis, validation)
        description = _sanitize_for_report(
            analysis.get("reasoning_summary")
            or candidate.title
        )
        impact = _sanitize_for_report(
            analysis.get("impact")
            or "Potential security impact requires review within the authorized scope."
        )
        recommendation = _recommendation(candidate, analysis, validation, final_status)
        evidence = self._evidence_records(candidate, validation)
        references = self._references(candidate, analysis, validation)
        return FinalFinding(
            id=candidate.id,
            title=_sanitize_for_report(candidate.title, 200),
            severity=severity,
            confidence=confidence,
            final_status=final_status,
            target=scan.target,
            endpoint=_sanitize_for_report(candidate.endpoint, 240),
            method=_sanitize_for_report(candidate.method, 16),
            category=_sanitize_for_report(candidate.category, 160),
            cwe_id=_sanitize_optional(analysis.get("cwe_id")),
            owasp_category=_sanitize_optional(analysis.get("owasp_category"), 160),
            description=description,
            impact=impact,
            recommendation=recommendation,
            evidence=evidence,
            validation_status=_sanitize_optional(validation.get("status"), 64),
            validation_reason=_sanitize_optional(validation.get("reason"), 160),
            source_tools=sorted({candidate.source_tool}),
            references=references,
            created_at=scan.updated_at,
        )

    def _evidence_records(self, candidate, validation: dict[str, Any]) -> list[FindingEvidenceRecord]:
        records: list[FindingEvidenceRecord] = []
        for item in candidate.evidence[:5]:
            records.append(
                FindingEvidenceRecord(
                    type="scanner_evidence",
                    observation=_sanitize_for_report(item, 320),
                )
            )
        for item in (validation.get("evidence") or [])[:3]:
            request = item.get("request")
            response = item.get("response")
            if request is not None:
                request = {
                    "method": _sanitize_for_report(str(request.get("method") or ""), 16),
                    "path": _sanitize_for_report(str(request.get("path") or ""), 200),
                    "query": {
                        _sanitize_for_report(str(key), 80): _sanitize_for_report(str(value), 120)
                        for key, value in (request.get("query") or {}).items()
                    },
                    "headers": self.sanitizer.sanitize_headers(
                        {str(key): str(value) for key, value in (request.get("headers") or {}).items()}
                    ),
                }
            if response is not None:
                response = {
                    "status_code": response.get("status_code"),
                    "content_type": _sanitize_optional(response.get("content_type"), 120),
                    "body_length": int(response.get("body_length") or 0),
                    "body_hash": _sanitize_optional(response.get("body_hash"), 96),
                    "title": _sanitize_optional(response.get("title"), 160),
                    "selected_headers": self.sanitizer.sanitize_headers(
                        {str(key): str(value) for key, value in (response.get("selected_headers") or {}).items()}
                    ),
                    "redirect_location": _sanitize_optional(response.get("redirect_location"), 200),
                    "blocked_redirect": bool(response.get("blocked_redirect")),
                }
            records.append(
                FindingEvidenceRecord(
                    type=_sanitize_for_report(str(item.get("type") or "http_observation"), 64),
                    request=request,
                    response=response,
                    observation=_sanitize_for_report(str(item.get("observation") or ""), 320),
                )
            )
        return records

    def _references(self, candidate, analysis: dict[str, Any], validation: dict[str, Any]) -> list[FindingReference]:
        references = [
            FindingReference(kind="source_tool", label="Scanner", value=_sanitize_for_report(candidate.source_tool, 80)),
        ]
        if candidate.raw_reference:
            references.append(
                FindingReference(kind="scanner_reference", label="Template/Reference", value=_sanitize_for_report(candidate.raw_reference, 160))
            )
        if analysis.get("cwe_id"):
            references.append(
                FindingReference(kind="cwe", label="CWE", value=_sanitize_for_report(str(analysis["cwe_id"]), 80))
            )
        for item in (candidate.rag_context or {}).get("results", [])[:3]:
            references.append(
                FindingReference(
                    kind="rag",
                    label=_sanitize_for_report(str(item.get("source") or "RAG"), 80),
                    value=_sanitize_for_report(str(item.get("title") or "knowledge"), 160),
                )
            )
        if validation.get("validator"):
            references.append(
                FindingReference(
                    kind="validation",
                    label="Validation",
                    value=_sanitize_for_report(str(validation["validator"]), 120),
                )
            )
        return references

    def _recon_summary(self, scan: ScanRecord) -> ReconSummary:
        probe = scan.recon.http_services[0] if scan.recon and scan.recon.http_services else None
        return ReconSummary(
            target_ip=scan.recon.target_ip if scan.recon else None,
            http_status=probe.status_code if probe else None,
            http_title=_sanitize_optional(probe.title if probe else None, 160),
            open_ports=_open_ports(scan),
            technologies=[_sanitize_for_report(item.name, 80) for item in (scan.recon.technologies if scan.recon else [])],
            endpoint_count=len(scan.recon.common_endpoints) if scan.recon else 0,
            candidate_count=len(scan.finding_candidates),
        )

    def _guardrail_summary(self, scan: ScanRecord, findings: list[FinalFinding]) -> GuardrailSummary:
        scope_violations = len(
            [item for item in findings if item.validation_reason == "scope_violation"]
        ) + len([item for item in scan.blocked_actions if "scope" in item.lower()])
        return GuardrailSummary(
            blocked_action_count=len(scan.blocked_actions),
            scope_violation_count=scope_violations,
            blocked_actions=[_sanitize_for_report(item, 240) for item in scan.blocked_actions],
        )


class HtmlReportRenderer:
    def render(self, report: PentestReport) -> str:
        rows = "\n".join(_html_finding_row(item) for item in report.findings)
        details = "\n".join(_html_finding_detail(item) for item in report.findings)
        tools = "\n".join(
            f"<tr><td>{_e(tool.tool)}</td><td>{'yes' if tool.success else 'no'}</td><td>{tool.duration_ms}</td><td>{_e(tool.error or '')}</td></tr>"
            for tool in report.tool_execution_summary
        )
        limitations = "".join(f"<li>{_e(item)}</li>" for item in report.limitations)
        blocked_actions = "".join(f"<li>{_e(item)}</li>" for item in report.guardrail_summary.blocked_actions) or "<li>none</li>"
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="report-schema-version" content="{_e(report.schema_version)}">
  <title>PentestFlow Report { _e(report.scan_metadata.scan_id) }</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #17202a; background: #f8fafc; }}
    h1, h2, h3 {{ color: #0f172a; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; margin-bottom: 1.5rem; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.6rem; text-align: left; vertical-align: top; }}
    th {{ background: #e2e8f0; }}
    .card {{ background: #fff; border: 1px solid #d1d5db; padding: 1rem; margin-bottom: 1rem; }}
    code {{ background: #eff6ff; padding: 0.1rem 0.3rem; }}
    ul {{ margin-top: 0.25rem; }}
  </style>
</head>
<body>
  <h1>PentestFlow Report</h1>
  <div class="card">
    <h2>Executive Summary</h2>
    <p><strong>Target:</strong> {_e(str(report.executive_summary.target))}</p>
    <p><strong>Scan ID:</strong> {_e(report.executive_summary.scan_id)}</p>
    <p><strong>Scan Duration:</strong> {report.executive_summary.scan_duration_ms} ms</p>
    <p><strong>Total Findings:</strong> {report.executive_summary.total_findings}</p>
    <p><strong>Verified:</strong> {report.executive_summary.verified_findings} | <strong>Unverified:</strong> {report.executive_summary.unverified_findings} | <strong>False Positives:</strong> {report.executive_summary.false_positive_findings} | <strong>Validation Skipped:</strong> {report.executive_summary.validation_skipped_findings}</p>
  </div>
  <div class="card">
    <h2>Scope</h2>
    <p>{_e(", ".join(report.scope) or "none")}</p>
  </div>
  <div class="card">
    <h2>Scan Metadata</h2>
    <p><strong>Status:</strong> {_e(report.scan_metadata.status)}</p>
    <p><strong>Schema Version:</strong> {_e(report.scan_metadata.schema_version)}</p>
    <p><strong>Generated:</strong> {_e(report.scan_metadata.report_generated_at.isoformat())}</p>
  </div>
  <div class="card">
    <h2>Recon Summary</h2>
    <p><strong>IP:</strong> {_e(report.recon_summary.target_ip or "unknown")}</p>
    <p><strong>HTTP:</strong> {_e(str(report.recon_summary.http_status) if report.recon_summary.http_status is not None else "unavailable")} {_e(report.recon_summary.http_title or "")}</p>
    <p><strong>Open Ports:</strong> {_e(", ".join(report.recon_summary.open_ports) or "none")}</p>
    <p><strong>Technologies:</strong> {_e(", ".join(report.recon_summary.technologies) or "none")}</p>
  </div>
  <div class="card">
    <h2>Finding Summary</h2>
    <table>
      <thead><tr><th>Severity</th><th>Status</th><th>Title</th><th>Endpoint</th><th>Confidence</th><th>CWE</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Detailed Findings</h2>
    {details or "<p>none</p>"}
  </div>
  <div class="card">
    <h2>Validation Summary</h2>
    <p>Attempted: {report.validation_summary.validation_attempted_count} | Verified: {report.validation_summary.validation_verified_count} | False Positive: {report.validation_summary.validation_false_positive_count} | Unverified: {report.validation_summary.validation_unverified_count} | Skipped: {report.validation_summary.validation_skipped_count} | Requests: {report.validation_summary.validation_request_count}</p>
  </div>
  <div class="card">
    <h2>Tool Execution Summary</h2>
    <table>
      <thead><tr><th>Tool</th><th>Success</th><th>Duration ms</th><th>Error</th></tr></thead>
      <tbody>{tools}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Guardrail / Blocked Action Summary</h2>
    <p><strong>Blocked Actions:</strong> {report.guardrail_summary.blocked_action_count}</p>
    <p><strong>Scope Violations:</strong> {report.guardrail_summary.scope_violation_count}</p>
    <ul>{blocked_actions}</ul>
  </div>
  <div class="card">
    <h2>Limitations</h2>
    <ul>{limitations}</ul>
  </div>
</body>
</html>"""


class JsonReportRenderer:
    def render(self, report: PentestReport) -> str:
        return json.dumps(report.model_dump(mode="json"), indent=2)


def write_scan_reports(scan: ScanRecord, reports_dir: Path, *, app_name: str = "PentestFlow") -> tuple[Path, Path, PentestReport]:
    builder = ReportBuilder()
    report = builder.build(scan, app_name=app_name)
    json_path = reports_dir / f"scan-{scan.scan_id}.json"
    html_path = reports_dir / f"scan-{scan.scan_id}.html"
    _atomic_write_text(json_path, JsonReportRenderer().render(report))
    _atomic_write_text(html_path, HtmlReportRenderer().render(report))
    return json_path, html_path, report


def filter_findings(
    findings: list[dict[str, Any]] | list[FinalFinding],
    *,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    source_tool: str | None = None,
) -> list[dict[str, Any]]:
    items = [item.model_dump(mode="json") if isinstance(item, FinalFinding) else dict(item) for item in findings]
    filtered: list[dict[str, Any]] = []
    for item in items:
        if severity and str(item.get("severity", "")).lower() != severity.lower():
            continue
        if status and str(item.get("final_status", item.get("status", ""))).lower() != status.lower():
            continue
        if category and str(item.get("category", "")).lower() != category.lower():
            continue
        if source_tool and source_tool.lower() not in {str(value).lower() for value in item.get("source_tools", [])}:
            continue
        filtered.append(item)
    return filtered


def group_findings(findings: list[dict[str, Any]], group_by: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in findings:
        key_name = "final_status" if group_by == "status" else group_by
        key = str(item.get(key_name, "unknown"))
        grouped[key].append(item)
    return dict(grouped)


def resolve_final_status(candidate, analysis: dict[str, Any], validation: dict[str, Any]) -> str:
    validation_status = str(validation.get("status") or "").lower()
    if validation_status == "verified":
        return "verified"
    if validation_status == "false_positive":
        return "false_positive"
    if validation_status == "unverified":
        return "unverified"
    if validation_status == "validation_skipped":
        return "validation_skipped"
    analysis_status = str(analysis.get("status") or "").lower()
    if analysis_status == "likely":
        return "likely"
    if analysis_status == "likely_false_positive":
        return "informational"
    return "informational"


def normalize_final_severity(severity: Severity | str, final_status: str) -> FinalSeverity:
    if final_status == "informational":
        return FinalSeverity.INFO
    value = severity.value if isinstance(severity, Severity) else str(severity)
    normalized = value.strip().lower()
    if normalized == "critical":
        return FinalSeverity.CRITICAL
    if normalized == "high":
        return FinalSeverity.HIGH
    if normalized == "medium":
        return FinalSeverity.MEDIUM
    if normalized == "low":
        return FinalSeverity.LOW
    return FinalSeverity.INFO


def _open_ports(scan: ScanRecord) -> list[str]:
    if not scan.recon:
        return []
    return [f"{port.port}/{port.protocol} {port.service or 'unknown'}" for port in scan.recon.open_ports]


def _recommendation(candidate, analysis: dict[str, Any], validation: dict[str, Any], final_status: str) -> str:
    if final_status == "false_positive":
        return "No remediation required for this observation. Retain the evidence for audit traceability."
    if final_status == "validation_skipped":
        return "Review manually within the authorized scope because safe deterministic validation did not complete."
    if validation.get("validator") == "check_security_header":
        return "Add the missing security header consistently on the affected endpoint and verify with a follow-up safe request."
    if analysis.get("evidence_assessment"):
        return _sanitize_for_report(str(analysis["evidence_assessment"]), 260)
    return f"Review and remediate the {candidate.category.lower()} condition on the affected endpoint."


def _resolve_confidence(candidate, analysis: dict[str, Any], validation: dict[str, Any]) -> float:
    if validation.get("confidence_after") is not None:
        return max(0.0, min(1.0, float(validation["confidence_after"])))
    if analysis.get("final_confidence") is not None:
        return max(0.0, min(1.0, float(analysis["final_confidence"])))
    return max(0.0, min(1.0, float(candidate.confidence)))


def _scan_duration_ms(scan: ScanRecord) -> int:
    return max(0, int((scan.updated_at - scan.created_at).total_seconds() * 1000))


def _count_values(values) -> dict[str, int]:
    counts = Counter(values)
    ordered_keys = [*SEVERITY_ORDER.keys(), *STATUS_ORDER.keys()]
    return {key: counts.get(key, 0) for key in ordered_keys}


def _limitations() -> list[str]:
    return [
        "authorized scope only",
        "safe non-destructive validation only",
        "no brute force",
        "no destructive exploitation",
        "no persistence or post-exploitation",
        "some findings may remain unverified",
        "results reflect target state at scan time",
    ]


def _sanitize_for_report(value: str, max_length: int = 320) -> str:
    return EvidenceSanitizer().sanitize_text(value, max_length=max_length)


def _sanitize_optional(value: Any, max_length: int = 320) -> str | None:
    if value is None or value == "":
        return None
    return _sanitize_for_report(str(value), max_length)


def _html_finding_row(item: FinalFinding) -> str:
    return (
        "<tr>"
        f"<td>{_e(item.severity.value)}</td>"
        f"<td>{_e(item.final_status)}</td>"
        f"<td>{_e(item.title)}</td>"
        f"<td>{_e(item.endpoint)}</td>"
        f"<td>{item.confidence:.2f}</td>"
        f"<td>{_e(item.cwe_id or '')}</td>"
        "</tr>"
    )


def _html_finding_detail(item: FinalFinding) -> str:
    evidence = "".join(_html_evidence_row(entry) for entry in item.evidence) or "<li>none</li>"
    references = "".join(f"<li>{_e(ref.label)}: {_e(ref.value)}</li>" for ref in item.references) or "<li>none</li>"
    return f"""
    <section class="card">
      <h3>{_e(item.title)}</h3>
      <p><strong>Severity:</strong> {_e(item.severity.value)} | <strong>Final Status:</strong> {_e(item.final_status)} | <strong>Confidence:</strong> {item.confidence:.2f}</p>
      <p><strong>Endpoint:</strong> <code>{_e(item.method)} {_e(item.endpoint)}</code></p>
      <p><strong>Category:</strong> {_e(item.category)} | <strong>CWE:</strong> {_e(item.cwe_id or 'n/a')} | <strong>OWASP:</strong> {_e(item.owasp_category or 'n/a')}</p>
      <p><strong>Description:</strong> {_e(item.description)}</p>
      <p><strong>Impact:</strong> {_e(item.impact)}</p>
      <p><strong>Recommendation:</strong> {_e(item.recommendation)}</p>
      <p><strong>Validation:</strong> {_e(item.validation_status or 'none')} {_e(item.validation_reason or '')}</p>
      <p><strong>Source Tools:</strong> {_e(', '.join(item.source_tools) or 'none')}</p>
      <p><strong>Evidence:</strong></p>
      <ul>{evidence}</ul>
      <p><strong>References:</strong></p>
      <ul>{references}</ul>
    </section>
    """


def _html_evidence_row(entry: FindingEvidenceRecord) -> str:
    parts = [f"<li><strong>{_e(entry.type)}</strong>: {_e(entry.observation)}"]
    if entry.request:
        parts.append(f"<div>Request: {_e(str(entry.request.get('method', '')))} {_e(str(entry.request.get('path', '')))}</div>")
    if entry.response:
        parts.append(
            f"<div>Response: HTTP {_e(str(entry.response.get('status_code', '')))} | Content-Type: {_e(str(entry.response.get('content_type') or ''))} | Body Length: {_e(str(entry.response.get('body_length') or '0'))}</div>"
        )
    parts.append("</li>")
    return "".join(parts)


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _atomic_write_text(output_path: Path, content: str) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output_path.parent, delete=False) as temp_file:
        temp_file.write(content)
        temp_path = Path(temp_file.name)
    temp_path.replace(output_path)
    return output_path
