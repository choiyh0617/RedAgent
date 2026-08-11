from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.models import ScanRequest
from app.core.scope import ScopeGuard, ScopeViolationError
from app.eval.benchmark import EvaluationBenchmarkRunner
from app.eval.models import EvaluationResult, RegressionThresholds
from app.eval.regression import RegressionComparator
from app.orchestrator.supervisor import ScanSupervisor
from app.rag.knowledge_base import KnowledgeBase
from app.reports.generator import filter_findings, group_findings, write_scan_reports


settings = get_settings()
configure_logging(settings.log_level)
scope_guard = ScopeGuard(settings)
supervisor = ScanSupervisor(settings=settings, scope_guard=scope_guard)
api = FastAPI(title="PentestFlow", version="0.1.0")


@api.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@api.post("/scans")
def create_scan(request: ScanRequest) -> dict:
    try:
        scan = supervisor.run_scan(str(request.target))
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    json_path, html_path, _ = write_scan_reports(scan, settings.reports_dir, app_name=settings.app_name)
    return {"scan_id": scan.scan_id, "status": scan.status, "report_json": str(json_path), "report_html": str(html_path)}


@api.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    report_path = _report_path(scan_id, suffix="json")
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="scan not found")
    return json.loads(report_path.read_text(encoding="utf-8"))


@api.get("/scans/{scan_id}/findings")
def get_findings(
    scan_id: str,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    source_tool: str | None = None,
    group_by: str | None = None,
) -> dict:
    scan = get_scan(scan_id)
    findings = filter_findings(
        scan.get("findings", []),
        severity=severity,
        status=status,
        category=category,
        source_tool=source_tool,
    )
    if group_by:
        if group_by not in {"severity", "final_status", "status", "category"}:
            raise HTTPException(status_code=400, detail="unsupported group_by")
        return {"scan_id": scan_id, "grouped_findings": group_findings(findings, group_by)}
    return {
        "scan_id": scan_id,
        "findings": findings,
    }


@api.get("/scans/{scan_id}/report")
def get_report(scan_id: str) -> dict:
    report_path = _report_path(scan_id, suffix="json")
    html_path = _report_path(scan_id, suffix="html")
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="report not found")
    return {"scan_id": scan_id, "report_json": str(report_path), "report_html": str(html_path)}


@api.get("/scans/{scan_id}/metrics")
def get_metrics(scan_id: str) -> dict:
    scan = get_scan(scan_id)
    return {"scan_id": scan_id, "metrics": scan.get("metrics", {}), "validation_summary": scan.get("validation_summary", {})}


@api.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
def get_html_report(scan_id: str) -> HTMLResponse:
    report_path = _report_path(scan_id, suffix="html")
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="html report not found")
    return HTMLResponse(report_path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    args = argv or sys.argv[1:]
    if not args:
        print(_usage())
        return 1
    if args[0] == "scan":
        return _handle_scan_command(args[1:])
    if args[0] == "knowledge":
        return _handle_knowledge_command(args[1:])
    if args[0] == "eval":
        return _handle_eval_command(args[1:])
    print(_usage())
    return 1


def _handle_scan_command(args: list[str]) -> int:
    if len(args) != 1:
        print("Usage: python -m app.main scan <target>")
        return 1

    target = args[0]
    try:
        scan = supervisor.run_scan(target)
    except ScopeViolationError as exc:
        print(f"[Scope] blocked: {exc}")
        return 2

    json_path, html_path, report = write_scan_reports(scan, settings.reports_dir, app_name=settings.app_name)
    print("PentestFlow")
    print()
    print("Target:")
    print(report.executive_summary.target)
    print()
    print("Scan completed")
    print()
    print("Findings:")
    for severity in ["critical", "high", "medium", "low", "info"]:
        print(f"{severity.capitalize():<9} {report.finding_summary.severity_counts.get(severity, 0)}")
    print()
    print("Status:")
    print(f"{'Verified':<20} {report.finding_summary.status_counts.get('verified', 0)}")
    print(f"{'Likely':<20} {report.finding_summary.status_counts.get('likely', 0)}")
    print(f"{'Unverified':<20} {report.finding_summary.status_counts.get('unverified', 0)}")
    print(f"{'False Positive':<20} {report.finding_summary.status_counts.get('false_positive', 0)}")
    print(f"{'Validation Skipped':<20} {report.finding_summary.status_counts.get('validation_skipped', 0)}")
    print()
    print("Top Findings:")
    for line in _format_top_findings(report):
        print(line)
    print()
    print("Reports:")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")
    return 0


def _handle_knowledge_command(args: list[str]) -> int:
    if not args or args[0] not in {"rebuild", "status", "search"}:
        print("Usage: python -m app.main knowledge <rebuild|status|search> [query]")
        return 1

    knowledge_base = KnowledgeBase(settings)
    command = args[0]
    if command == "rebuild":
        status = knowledge_base.rebuild()
        print("Knowledge Base")
        print()
        print(f"Documents: {status.document_count}")
        print(f"Chunks: {status.chunk_count}")
        print(f"Embedding Provider: {status.embedding_provider}")
        print(f"Vector Store: {status.vector_store}")
        print(f"Version: {status.knowledge_base_version}")
        return 0
    if command == "status":
        status = knowledge_base.status()
        print("Knowledge Base")
        print()
        print(f"Documents: {status.document_count}")
        print(f"Chunks: {status.chunk_count}")
        print(f"Embedding Provider: {status.embedding_provider}")
        print(f"Vector Store: {status.vector_store}")
        print(f"Version: {status.knowledge_base_version}")
        return 0

    query = " ".join(args[1:]).strip()
    if not query:
        print('Usage: python -m app.main knowledge search "SQL injection"')
        return 1
    context = knowledge_base.search(query=query, top_k=settings.rag_top_k)
    print("Knowledge Base")
    print()
    print("Search:")
    print(f'"{query}"')
    print()
    for index, result in enumerate(context.results, start=1):
        print(f"{index}. {result.title}")
    return 0


def _usage() -> str:
    return (
        "Usage:\n"
        "  python -m app.main scan <target>\n"
        "  python -m app.main knowledge rebuild\n"
        "  python -m app.main knowledge status\n"
        '  python -m app.main knowledge search "SQL injection"\n'
        "  python -m app.main eval run --benchmark <name> [--profile baseline|optimized]\n"
        "  python -m app.main eval compare <baseline.json> <current.json>\n"
        "  python -m app.main eval summary <result.json>"
    )


def _report_path(scan_id: str, suffix: str) -> Path:
    return settings.reports_dir / f"scan-{scan_id}.{suffix}"


def _tool_marker(scan, tool_name: str) -> str:
    for execution in scan.tools_used:
        if execution.tool == tool_name:
            return "✓" if execution.success else "x"
    return "-"


def _format_ports(scan) -> list[str]:
    if not scan.recon or not scan.recon.open_ports:
        return ["none"]
    return [f"{port.port}/{port.protocol} {port.service or 'unknown'}" for port in scan.recon.open_ports]


def _format_http_summary(scan) -> str:
    if not scan.recon or not scan.recon.http_services:
        return "unavailable"
    probe = scan.recon.http_services[0]
    return f"{probe.status_code} {probe.reason_phrase}"


def _format_title(scan) -> str:
    if not scan.recon or not scan.recon.http_services:
        return "unknown"
    return scan.recon.http_services[0].title or "unknown"


def _format_technologies(scan) -> list[str]:
    if not scan.recon or not scan.recon.technologies:
        return ["none"]
    return [technology.name for technology in scan.recon.technologies]


def _format_endpoints(scan) -> list[str]:
    if not scan.recon or not scan.recon.common_endpoints:
        return ["none"]
    return [endpoint.path for endpoint in scan.recon.common_endpoints if endpoint.exists] or ["none"]


def _format_analyses(scan) -> list[str]:
    if not scan.finding_candidates:
        return ["Analysis: none"]
    lines = ["Analysis:"]
    for candidate in scan.finding_candidates:
        analysis = candidate.analysis or {}
        if not analysis:
            continue
        severity = analysis.get("severity", candidate.severity)
        confidence = float(analysis.get("final_confidence", analysis.get("confidence", 0.0)))
        status = analysis.get("status", "insufficient_evidence")
        model = analysis.get("model_used", "none")
        validation = candidate.validation or {}
        if validation:
            lines.append(f"[{severity}][{confidence:.2f}] {candidate.title} status={status} model={model}")
            lines.append(
                f"  validation={validation.get('validator', 'none')} result={validation.get('status', 'validation_skipped')} "
                f"confidence={float(validation.get('confidence_after', confidence)):.2f}"
            )
            observation = ""
            evidence = validation.get("evidence") or []
            if evidence:
                observation = evidence[0].get("observation", "")
            if observation:
                lines.append(f"  evidence={observation}")
            continue
        lines.append(f"[{severity}][{confidence:.2f}] {candidate.title} status={status} model={model}")
    return lines if len(lines) > 1 else ["Analysis: none"]


def _format_top_findings(report) -> list[str]:
    if not report.findings:
        return ["none"]
    lines: list[str] = []
    for item in report.findings[:5]:
        lines.append(f"[{item.severity.value.upper()}][{item.final_status.upper()}][{item.confidence:.2f}]")
        lines.append(item.title)
        lines.append(item.endpoint)
        lines.append("")
    return lines[:-1] if lines and lines[-1] == "" else lines


def _handle_eval_command(args: list[str]) -> int:
    if not args:
        print("Usage: python -m app.main eval <run|compare|summary> ...")
        return 1
    command = args[0]
    if command == "run":
        return _handle_eval_run(args[1:])
    if command == "compare":
        return _handle_eval_compare(args[1:])
    if command == "summary":
        return _handle_eval_summary(args[1:])
    print("Usage: python -m app.main eval <run|compare|summary> ...")
    return 1


def _handle_eval_run(args: list[str]) -> int:
    benchmark = None
    profile = "optimized"
    index = 0
    while index < len(args):
        if args[index] == "--benchmark" and index + 1 < len(args):
            benchmark = args[index + 1]
            index += 2
            continue
        if args[index] == "--profile" and index + 1 < len(args):
            profile = args[index + 1]
            index += 2
            continue
        print("Usage: python -m app.main eval run --benchmark <name> [--profile baseline|optimized]")
        return 1
    if not benchmark:
        print("Usage: python -m app.main eval run --benchmark <name> [--profile baseline|optimized]")
        return 1

    runner = EvaluationBenchmarkRunner(settings, scan_runner=lambda configured_settings, target: ScanSupervisor(configured_settings, ScopeGuard(configured_settings)).run_scan(target))
    try:
        result, output_path = runner.run(benchmark=benchmark, profile=profile)
    except Exception as exc:
        print(f"Evaluation failed: {exc}")
        return 1
    _print_eval_result(result)
    print()
    print(f"Saved: {output_path}")
    return 0


def _handle_eval_compare(args: list[str]) -> int:
    if len(args) != 2:
        print("Usage: python -m app.main eval compare <baseline.json> <current.json>")
        return 1
    comparator = RegressionComparator()
    result = comparator.compare_files(
        Path(args[0]),
        Path(args[1]),
        RegressionThresholds(
            max_precision_drop=settings.max_precision_drop,
            max_recall_drop=settings.max_recall_drop,
            max_runtime_increase_percent=settings.max_runtime_increase_percent,
            max_llm_call_increase_percent=settings.max_llm_call_increase_percent,
        ),
    )
    print("PentestFlow Evaluation Comparison")
    print()
    print(f"Regression: {'PASS' if result.passed else 'FAIL'}")
    for check in result.checks:
        print(f"{check.name}: {'PASS' if check.passed else 'FAIL'} ({check.reason})")
    return 0 if result.passed else 2


def _handle_eval_summary(args: list[str]) -> int:
    if len(args) != 1:
        print("Usage: python -m app.main eval summary <result.json>")
        return 1
    payload = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    result = EvaluationResult.model_validate(payload)
    _print_eval_result(result)
    return 0


def _print_eval_result(result: EvaluationResult) -> None:
    print("PentestFlow Evaluation")
    print()
    print("Benchmark:")
    print(result.benchmark)
    print()
    print("Accuracy:")
    print(f"Precision  {result.accuracy.precision:.2f}")
    print(f"Recall     {result.accuracy.recall:.2f}")
    print(f"F1         {result.accuracy.f1:.2f}")
    print()
    print("Findings:")
    print(f"TP {result.accuracy.tp}")
    print(f"FP {result.accuracy.fp}")
    print(f"FN {result.accuracy.fn}")
    print()
    print("Performance:")
    print(f"Duration   {result.performance.duration_seconds:.1f}s")
    print(f"LLM Calls  {result.performance.llm_calls}")
    print(f"Tool Calls {result.performance.tool_calls}")
    print()
    print("Cache:")
    print(f"Hit Rate   {result.cache.hit_rate:.0%}")


if __name__ == "__main__":
    raise SystemExit(main())
