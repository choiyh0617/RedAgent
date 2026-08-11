from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from app.core.models import (
    CrawlResult,
    EndpointProbeResult,
    FindingCandidate,
    NetworkScanResult,
    NucleiScanResult,
    ReconResult,
    RobotsTxtResult,
    Severity,
    ToolExecution,
    WebProbeResult,
)
from app.eval.metrics import RuntimeMetricsCollector
from app.llm.models import FindingAnalysis
from app.core.scope import ScopeGuard
from app.agents.analysis_agent import AnalysisAgent, build_analysis_input
from app.agents.validation_agent import ValidationAgent
from app.llm.ollama import OllamaProvider
from app.rag.knowledge_base import KnowledgeBase
from app.rag.retriever import SecurityRetriever
from app.tools.common_endpoints import discover_common_endpoints
from app.tools.crawler import crawl_web, normalize_crawl_candidates
from app.tools.network_scan import network_scan
from app.tools.nuclei import run_nuclei
from app.tools.robots_txt import inspect_robots_txt
from app.tools.technology_detect import detect_technologies
from app.tools.web_probe import web_probe
from app.validation.models import ValidationMetrics


T = TypeVar("T")


def run_initial_recon(target: str, scope_guard: ScopeGuard, settings) -> ReconResult:
    target_info = scope_guard.parse_target(target)
    tool_executions: list[ToolExecution] = []
    notes: list[str] = []
    metrics_collector = RuntimeMetricsCollector()
    scope_started = datetime.now(timezone.utc)
    scope_guard.validate(target)
    scope_ended = datetime.now(timezone.utc)
    metrics_collector.record_phase("scope", duration_ms=int((scope_ended - scope_started).total_seconds() * 1000), tool_calls=0)

    recon_started_at = datetime.now(timezone.utc)
    probe = _run_tool(
        tool_executions,
        "web_probe",
        {"target": target},
        lambda: web_probe(target=target, scope_guard=scope_guard, settings=settings),
    )
    network = _run_tool(
        tool_executions,
        "network_scan",
        {"target": target, "mode": "quick"},
        lambda: network_scan(target=target, scope_guard=scope_guard, settings=settings, mode="quick"),
    )
    robots = _run_tool(
        tool_executions,
        "robots_txt",
        {"target": target},
        lambda: inspect_robots_txt(target=target, scope_guard=scope_guard, settings=settings),
    )
    endpoints = _run_tool(
        tool_executions,
        "common_endpoints",
        {"target": target},
        lambda: discover_common_endpoints(target=target, scope_guard=scope_guard, settings=settings),
    )
    crawl = None
    nuclei = None
    finding_candidates: list[FindingCandidate] = []
    if probe:
        crawl = _run_tool(
            tool_executions,
            "crawler",
            {"target": target, "max_depth": settings.max_crawl_depth, "max_pages": settings.max_crawl_pages},
            lambda: crawl_web(target=target, scope_guard=scope_guard, settings=settings),
        )
        nuclei = _run_tool(
            tool_executions,
            "nuclei",
            {"target": target},
            lambda: run_nuclei(target=target, scope_guard=scope_guard, settings=settings),
        )
        if crawl:
            finding_candidates.extend(normalize_crawl_candidates(crawl))
        if nuclei:
            finding_candidates.extend(nuclei.candidates)
    finding_candidates.extend(_synthesize_recon_candidates(probe=probe, endpoints=endpoints or []))

    technology_started_at = datetime.now(timezone.utc)
    technologies = detect_technologies(probe) if probe else []
    technology_ended_at = datetime.now(timezone.utc)
    tool_executions.append(
        ToolExecution(
            tool="technology_detect",
            arguments={"source": "web_probe"},
            started_at=technology_started_at,
            ended_at=technology_ended_at,
            duration_ms=int((technology_ended_at - technology_started_at).total_seconds() * 1000),
            success=probe is not None,
            error=None if probe is not None else "web probe unavailable",
        )
    )

    if probe:
        notes.append("Initial HTTP probe completed")
    else:
        notes.append("Web probe failed")
    if network and not network.success:
        notes.append(f"Network scan unavailable: {network.error}")
    if robots and not robots.exists:
        notes.append("robots.txt not found")
    if crawl and not crawl.success:
        notes.append(f"Crawler unavailable: {crawl.error}")
    if nuclei and not nuclei.success:
        notes.append(f"Nuclei unavailable: {nuclei.error}")

    merged_ports = _merge_http_port_details(
        ports=network.ports if network else [],
        probe=probe,
        technologies=technologies,
    )
    finding_candidates = _dedupe_candidates(finding_candidates)
    rag_started_at = datetime.now(timezone.utc)
    finding_candidates = _attach_rag_contexts(
        candidates=finding_candidates,
        settings=settings,
        metrics_collector=metrics_collector,
    )
    rag_ended_at = datetime.now(timezone.utc)
    metrics_collector.record_phase(
        "rag",
        duration_ms=int((rag_ended_at - rag_started_at).total_seconds() * 1000),
        tool_calls=0,
    )
    finding_candidates, analysis_execution = _attach_analyses(
        candidates=finding_candidates,
        settings=settings,
        metrics_collector=metrics_collector,
    )
    if analysis_execution is not None:
        tool_executions.append(analysis_execution)
        metrics_collector.record_phase(
            "analysis",
            duration_ms=analysis_execution.duration_ms,
            success=analysis_execution.success,
            failures=0 if analysis_execution.success else 1,
            tool_calls=1,
            llm_calls=len(metrics_collector.llm_calls),
        )
    finding_candidates, validation_execution, validation_metrics = _attach_validations(
        candidates=finding_candidates,
        settings=settings,
        scope_guard=scope_guard,
        metrics_collector=metrics_collector,
    )
    if validation_execution is not None:
        tool_executions.append(validation_execution)
        metrics_collector.record_phase(
            "validation",
            duration_ms=validation_execution.duration_ms,
            success=validation_execution.success,
            failures=0 if validation_execution.success else 1,
            tool_calls=1,
        )
    recon_ended_at = datetime.now(timezone.utc)
    metrics_collector.record_phase(
        "recon",
        duration_ms=int((recon_ended_at - recon_started_at).total_seconds() * 1000),
        tool_calls=len(tool_executions),
    )

    return ReconResult(
        target=target_info.normalized,
        target_ip=(probe.ip if probe else None) or (network.resolved_ip if network else None) or target_info.ip,
        http_services=[probe] if probe else [],
        network_scan=network,
        open_ports=merged_ports,
        technologies=technologies,
        robots_txt=robots,
        common_endpoints=endpoints or [],
        crawl=crawl,
        nuclei=nuclei,
        finding_candidates=finding_candidates,
        tool_executions=tool_executions,
        notes=notes + [f"validation_engine_version={settings.validation_engine_version}"],
        validation_metrics=validation_metrics.model_dump(mode="json"),
        runtime_metrics=metrics_collector.snapshot(),
    )


def _run_tool(
    executions: list[ToolExecution],
    tool_name: str,
    arguments: dict[str, Any],
    func: Callable[[], T],
) -> T | None:
    started_at = datetime.now(timezone.utc)
    try:
        result = func()
    except Exception as exc:
        ended_at = datetime.now(timezone.utc)
        executions.append(
            ToolExecution(
                tool=tool_name,
                arguments=arguments,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=int((ended_at - started_at).total_seconds() * 1000),
                success=False,
                error=_sanitize_error(str(exc)),
            )
        )
        return None

    ended_at = datetime.now(timezone.utc)
    executions.append(
        ToolExecution(
            tool=tool_name,
            arguments=arguments,
            started_at=started_at,
            ended_at=ended_at,
            duration_ms=int((ended_at - started_at).total_seconds() * 1000),
            success=_result_success(result),
            error=_sanitize_error(_extract_error(result)),
        )
    )
    return result


def _result_success(result: Any) -> bool:
    if isinstance(result, NetworkScanResult):
        return result.success
    if isinstance(result, NucleiScanResult):
        return result.success
    if isinstance(result, CrawlResult):
        return result.success
    if isinstance(result, RobotsTxtResult):
        return result.status_code is not None
    if isinstance(result, WebProbeResult):
        return True
    if isinstance(result, list):
        return True
    return True


def _extract_error(result: Any) -> str | None:
    if isinstance(result, NetworkScanResult):
        return result.error
    if isinstance(result, NucleiScanResult):
        return result.error
    if isinstance(result, CrawlResult):
        return result.error
    return None


def _sanitize_error(value: str | None) -> str | None:
    if not value:
        return None
    return " ".join(value.split())[:300] or None


def _merge_http_port_details(
    *,
    ports,
    probe: WebProbeResult | None,
    technologies,
):
    if not probe:
        return ports
    merged = []
    product = "Node.js" if any(technology.name == "Node.js" for technology in technologies) else None
    for port in ports:
        if port.port == probe.port:
            merged.append(
                port.model_copy(
                    update={
                        "service": probe.scheme,
                        "product": port.product or product,
                    }
                )
            )
        else:
            merged.append(port)
    return merged


def _dedupe_candidates(candidates: list[FindingCandidate]) -> list[FindingCandidate]:
    deduped: list[FindingCandidate] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        key = (candidate.title, candidate.endpoint, candidate.source_tool)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _synthesize_recon_candidates(*, probe: WebProbeResult | None, endpoints: list[EndpointProbeResult]) -> list[FindingCandidate]:
    synthesized: list[FindingCandidate] = []
    if probe is not None:
        synthesized.extend(_security_header_candidates(probe))
    synthesized.extend(_endpoint_access_candidates(endpoints))
    return synthesized


def _security_header_candidates(probe: WebProbeResult) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    if probe.status_code >= 400:
        return candidates
    missing_headers = {item.name: item for item in probe.security_headers if not item.present}
    csp = missing_headers.get("Content-Security-Policy")
    if csp is not None:
        candidates.append(
            FindingCandidate(
                id="DET-001",
                title="Missing Content-Security-Policy",
                category="Security Misconfiguration",
                severity=Severity.MEDIUM,
                endpoint=probe.final_url,
                method="GET",
                evidence=[
                    "header=Content-Security-Policy missing",
                    f"status={probe.status_code}",
                    f"final-url={probe.final_url}",
                ],
                source_tool="deterministic_recon",
                confidence=0.9,
                raw_reference="deterministic-security-header",
            )
        )
    return candidates


def _endpoint_access_candidates(endpoints: list[EndpointProbeResult]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    for endpoint in endpoints:
        normalized_path = (endpoint.path or "").rstrip("/") or "/"
        if normalized_path != "/administration":
            continue
        if not endpoint.exists or endpoint.status_code is None:
            continue
        if endpoint.status_code >= 500:
            continue
        candidates.append(
            FindingCandidate(
                id="DET-002",
                title="Exposed Admin Endpoint",
                category="Access Control",
                severity=Severity.HIGH,
                endpoint=endpoint.url,
                method="GET",
                evidence=[
                    f"path={endpoint.path}",
                    f"status={endpoint.status_code}",
                    f"content-type={endpoint.content_type or 'unknown'}",
                ],
                source_tool="deterministic_recon",
                confidence=0.85,
                raw_reference="deterministic-admin-endpoint",
            )
        )
        break
    return candidates


def _attach_rag_contexts(*, candidates: list[FindingCandidate], settings, metrics_collector: RuntimeMetricsCollector | None = None) -> list[FindingCandidate]:
    if not settings.rag_enabled or not candidates:
        return candidates
    retriever = SecurityRetriever(KnowledgeBase(settings, metrics_collector=metrics_collector), top_k=settings.rag_top_k)
    enriched: list[FindingCandidate] = []
    for candidate in candidates:
        try:
            rag_context = retriever.retrieve_for_finding(candidate)
        except Exception:
            rag_context = None
        if rag_context is None:
            enriched.append(candidate)
            continue
        enriched.append(candidate.model_copy(update={"rag_context": rag_context.model_dump(mode="json")}))
    return enriched


def _attach_analyses(*, candidates: list[FindingCandidate], settings, metrics_collector: RuntimeMetricsCollector | None = None):
    if not candidates:
        return candidates, None
    started_at = datetime.now(timezone.utc)
    agent = AnalysisAgent(settings, provider=_build_llm_provider(settings), metrics_collector=metrics_collector)
    enriched: list[FindingCandidate] = []
    success_count = 0
    for candidate in candidates:
        try:
            analysis_input = build_analysis_input(candidate, settings)
            if not analysis_input.knowledge and candidate.source_tool == "crawler":
                enriched.append(candidate)
                continue
            analysis = agent.analyze(analysis_input)
        except Exception as exc:
            enriched.append(candidate.model_copy(update={"analysis": {"status": "insufficient_evidence", "analysis_error": _sanitize_error(str(exc))}}))
            continue
        if analysis.analysis_error is None:
            success_count += 1
        enriched.append(candidate.model_copy(update={"analysis": analysis.model_dump(mode="json")}))
    ended_at = datetime.now(timezone.utc)
    execution = ToolExecution(
        tool="analysis_agent",
        arguments={"candidate_count": len(candidates)},
        started_at=started_at,
        ended_at=ended_at,
        duration_ms=int((ended_at - started_at).total_seconds() * 1000),
        success=success_count > 0,
        error=None if success_count > 0 else "analysis unavailable",
    )
    return enriched, execution


def _attach_validations(*, candidates: list[FindingCandidate], settings, scope_guard: ScopeGuard, metrics_collector: RuntimeMetricsCollector | None = None):
    if not candidates:
        return candidates, None, ValidationMetrics()
    started_at = datetime.now(timezone.utc)
    agent = ValidationAgent(settings, scope_guard, metrics_collector=metrics_collector)
    enriched: list[FindingCandidate] = []
    metrics = ValidationMetrics()
    scan_requests_used = 0
    for candidate in candidates:
        analysis_payload = candidate.analysis or {}
        analysis = None
        if analysis_payload:
            try:
                analysis = FindingAnalysis.model_validate(analysis_payload)
            except Exception:
                analysis = None
        remaining_scan_requests = max(settings.max_validation_requests_per_scan - scan_requests_used, 0)
        result = agent.validate_finding(candidate, analysis, remaining_scan_requests=remaining_scan_requests)
        metrics.record(result)
        scan_requests_used += result.requests_made
        enriched.append(
            candidate.model_copy(
                update={
                    "validation": result.model_dump(mode="json"),
                    "final_status": _final_status(candidate, analysis, result),
                }
            )
        )
    ended_at = datetime.now(timezone.utc)
    execution = ToolExecution(
        tool="validation_engine",
        arguments={
            "candidate_count": len(candidates),
            "engine_version": settings.validation_engine_version,
        },
        started_at=started_at,
        ended_at=ended_at,
        duration_ms=int((ended_at - started_at).total_seconds() * 1000),
        success=metrics.validation_attempted_count > 0,
        error=None,
    )
    return enriched, execution, metrics


def _final_status(candidate: FindingCandidate, analysis: FindingAnalysis | None, validation_result) -> str:
    if validation_result.status == "verified":
        return "verified"
    if validation_result.status == "false_positive":
        return "false_positive"
    if validation_result.status == "unverified":
        return "unverified"
    if analysis and analysis.status == "likely":
        return "likely"
    return "candidate"


def _build_llm_provider(settings):
    if not settings.llm_enabled:
        return None
    if settings.llm_provider == "ollama":
        return OllamaProvider(base_url=settings.ollama_base_url)
    return None
