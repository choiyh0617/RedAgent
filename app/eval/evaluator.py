from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.eval.cost import build_cost_metrics
from app.eval.metrics import build_cache_metrics, build_llm_metrics, build_phase_metrics, build_severity_metrics, build_tool_metrics, compute_accuracy, safe_divide
from app.eval.models import (
    AccuracyMetrics,
    BenchmarkFixture,
    EvaluationMetadata,
    EvaluationResult,
    FalseNegativeAttribution,
    FalsePositiveAttribution,
    FindingMatchResult,
    GroundTruthFinding,
    PerformanceMetrics,
    PipelineAttribution,
    SeverityMetricEntry,
    StatusMetrics,
    VersionMetadata,
)
from app.reports.models import REPORT_SCHEMA_VERSION


class BenchmarkEvaluator:
    def evaluate(
        self,
        *,
        benchmark: BenchmarkFixture,
        profile: str,
        scan,
        config_snapshot: dict[str, Any],
        git_commit: str | None = None,
    ) -> EvaluationResult:
        findings = [dict(item) for item in scan.findings]
        matches = match_findings(findings, benchmark.supported_ground_truth)
        tp = sum(1 for item in matches if item.disposition == "tp")
        fp = sum(1 for item in matches if item.disposition == "fp")
        fn = sum(1 for item in matches if item.disposition == "fn")
        accuracy = compute_accuracy(tp, fp, fn)
        runtime_metrics = scan.runtime_metrics or {}
        llm_metrics = build_llm_metrics(runtime_metrics)
        cache_metrics = build_cache_metrics(runtime_metrics)
        phase_metrics = build_phase_metrics(runtime_metrics)
        tool_metrics = build_tool_metrics(scan.tools_used)
        findings_by_id = {item["id"]: item for item in findings}
        ground_truth_by_id = {item.id: item for item in benchmark.supported_ground_truth}
        severity_metrics = build_severity_metrics(matches, findings_by_id, ground_truth_by_id)
        status_metrics = self._status_metrics(matches, findings)
        metadata = EvaluationMetadata(
            eval_id=f"{benchmark.benchmark_id}-{profile}-{scan.scan_id}",
            benchmark=benchmark.benchmark_id,
            profile=profile,
            timestamp=datetime.now(timezone.utc),
            target=str(scan.target),
            git_commit=git_commit,
            config_snapshot=config_snapshot,
            versions=VersionMetadata(
                analysis_prompt_version=config_snapshot.get("analysis_prompt_version"),
                validation_engine_version=config_snapshot.get("validation_engine_version"),
                report_schema_version=REPORT_SCHEMA_VERSION,
                knowledge_base_version=_knowledge_base_version(scan),
                model_names=sorted({item.model_name for item in llm_metrics if item.model_name}),
            ),
        )
        return EvaluationResult(
            benchmark=benchmark.benchmark_id,
            profile=profile,
            metadata=metadata,
            accuracy=accuracy,
            status_metrics=status_metrics,
            severity_metrics=severity_metrics,
            performance=PerformanceMetrics(
                duration_seconds=max(0.0, (scan.updated_at - scan.created_at).total_seconds()),
                tool_calls=len(scan.tools_used),
                llm_calls=sum(item.call_count for item in llm_metrics),
            ),
            cache=cache_metrics,
            cost=build_cost_metrics(llm_metrics),
            phase_metrics=phase_metrics,
            tool_metrics=tool_metrics,
            llm_metrics=llm_metrics,
            matches=matches,
            false_positive_analysis=self._false_positive_analysis(matches, findings_by_id),
            false_negative_analysis=self._false_negative_analysis(matches, findings, benchmark.supported_ground_truth),
            pipeline_attribution=self._pipeline_attribution(benchmark.supported_ground_truth, findings),
        )

    def _status_metrics(self, matches: list[FindingMatchResult], findings: list[dict[str, Any]]) -> StatusMetrics:
        finding_by_id = {item["id"]: item for item in findings}
        verified_tp = 0
        likely_tp = 0
        for match in matches:
            if match.disposition != "tp" or not match.finding_id:
                continue
            status = str(finding_by_id[match.finding_id].get("final_status") or "").lower()
            if status == "verified":
                verified_tp += 1
            if status == "likely":
                likely_tp += 1
        verified_findings = [item for item in findings if item.get("final_status") == "verified"]
        assisted_findings = [item for item in findings if item.get("final_status") in {"verified", "likely"}]
        return StatusMetrics(
            strict_precision=safe_divide(verified_tp, len(verified_findings)),
            assisted_precision=safe_divide(verified_tp + likely_tp, len(assisted_findings)),
            verified_true_positive=verified_tp,
            likely_true_positive=likely_tp,
            unverified_candidates=sum(1 for item in findings if item.get("final_status") == "unverified"),
            false_positive_findings=sum(1 for item in findings if item.get("final_status") == "false_positive"),
            validation_skipped_findings=sum(1 for item in findings if item.get("final_status") == "validation_skipped"),
            verified_finding_ratio=safe_divide(len(verified_findings), len(findings)),
            unverified_finding_ratio=safe_divide(sum(1 for item in findings if item.get("final_status") == "unverified"), len(findings)),
            validation_success_rate=safe_divide(
                sum(1 for item in findings if item.get("validation_status") == "verified"),
                sum(1 for item in findings if item.get("validation_status") is not None),
            ),
        )

    def _false_positive_analysis(self, matches: list[FindingMatchResult], findings_by_id: dict[str, dict[str, Any]]) -> list[FalsePositiveAttribution]:
        results: list[FalsePositiveAttribution] = []
        for match in matches:
            if match.disposition != "fp" or not match.finding_id:
                continue
            finding = findings_by_id[match.finding_id]
            results.append(
                FalsePositiveAttribution(
                    finding_id=match.finding_id,
                    title=finding["title"],
                    category=finding["category"],
                    source_tool=(finding.get("source_tools") or ["unknown"])[0],
                    analysis_confidence=float(finding.get("confidence") or 0.0),
                    validation_status=finding.get("validation_status"),
                    reason=match.reason,
                )
            )
        return results

    def _false_negative_analysis(
        self,
        matches: list[FindingMatchResult],
        findings: list[dict[str, Any]],
        ground_truth: list[GroundTruthFinding],
    ) -> list[FalseNegativeAttribution]:
        findings_lower = [
            {
                "title": str(item.get("title", "")).lower(),
                "category": str(item.get("category", "")).lower(),
                "endpoint": str(item.get("endpoint", "")).lower(),
                "cwe_id": str(item.get("cwe_id", "")).lower(),
                "validation_status": item.get("validation_status"),
                "final_status": item.get("final_status"),
                "references": item.get("references", []),
            }
            for item in findings
        ]
        results: list[FalseNegativeAttribution] = []
        for match in matches:
            if match.disposition != "fn" or not match.ground_truth_id:
                continue
            truth = next(item for item in ground_truth if item.id == match.ground_truth_id)
            candidate = _candidate_for_truth(findings_lower, truth)
            results.append(
                FalseNegativeAttribution(
                    ground_truth_id=truth.id,
                    expected_category=truth.category,
                    endpoint=truth.endpoint,
                    scanner_candidate=bool(candidate),
                    rag_relevant=_rag_relevant(candidate),
                    analysis_status=candidate.get("final_status") if candidate else None,
                    validation_status=candidate.get("validation_status") if candidate else None,
                    reason=match.reason,
                )
            )
        return results

    def _pipeline_attribution(self, ground_truth: list[GroundTruthFinding], findings: list[dict[str, Any]]) -> list[PipelineAttribution]:
        lowered = [
            {
                "title": str(item.get("title", "")).lower(),
                "category": str(item.get("category", "")).lower(),
                "endpoint": str(item.get("endpoint", "")).lower(),
                "cwe_id": str(item.get("cwe_id", "")).lower(),
                "final_status": item.get("final_status"),
                "validation_status": item.get("validation_status"),
                "references": item.get("references", []),
            }
            for item in findings
        ]
        output: list[PipelineAttribution] = []
        for truth in ground_truth:
            candidate = _candidate_for_truth(lowered, truth)
            output.append(
                PipelineAttribution(
                    ground_truth_id=truth.id,
                    scanner_candidate=bool(candidate),
                    rag_relevant=_rag_relevant(candidate),
                    analysis=candidate.get("final_status") if candidate else None,
                    validation=candidate.get("validation_status") if candidate else None,
                    final="tp" if candidate else "fn",
                )
            )
        return output


def match_findings(findings: list[dict[str, Any]], ground_truth: list[GroundTruthFinding]) -> list[FindingMatchResult]:
    matches: list[FindingMatchResult] = []
    unmatched_finding_ids = {item["id"] for item in findings}
    matched_truth_ids: set[str] = set()
    for truth in ground_truth:
        best = None
        best_score = 0.0
        for finding in findings:
            if finding["id"] not in unmatched_finding_ids:
                continue
            score, reason = match_score(finding, truth)
            if score > best_score:
                best = (finding, reason)
                best_score = score
        if best and best_score >= 0.7:
            finding, reason = best
            unmatched_finding_ids.remove(finding["id"])
            matched_truth_ids.add(truth.id)
            matches.append(
                FindingMatchResult(
                    finding_id=finding["id"],
                    ground_truth_id=truth.id,
                    disposition="tp",
                    score=best_score,
                    reason=reason,
                    finding_title=finding["title"],
                    category=finding["category"],
                    endpoint=finding.get("endpoint"),
                    final_status=finding.get("final_status"),
                    validation_status=finding.get("validation_status"),
                    source_tool=(finding.get("source_tools") or ["unknown"])[0],
                )
            )
        else:
            matches.append(
                FindingMatchResult(
                    ground_truth_id=truth.id,
                    disposition="fn",
                    reason="no_supported_finding_match",
                    category=truth.category,
                    endpoint=truth.endpoint,
                )
            )
    for finding in findings:
        if finding["id"] not in unmatched_finding_ids:
            continue
        matches.append(
            FindingMatchResult(
                finding_id=finding["id"],
                disposition="fp",
                reason="no_ground_truth_match",
                finding_title=finding["title"],
                category=finding["category"],
                endpoint=finding.get("endpoint"),
                final_status=finding.get("final_status"),
                validation_status=finding.get("validation_status"),
                source_tool=(finding.get("source_tools") or ["unknown"])[0],
            )
        )
    return matches


def match_score(finding: dict[str, Any], truth: GroundTruthFinding) -> tuple[float, str]:
    score = 0.0
    reasons: list[str] = []
    if truth.cwe_id and str(finding.get("cwe_id") or "").upper() == truth.cwe_id.upper():
        score += 0.5
        reasons.append("exact_cwe")
    finding_category = _normalize_text(finding.get("category"))
    truth_category = _normalize_text(truth.category)
    if finding_category == truth_category:
        score += 0.25
        reasons.append("category")
    finding_endpoint = _normalize_endpoint(finding.get("endpoint"))
    truth_endpoint = _normalize_endpoint(truth.endpoint)
    if truth_endpoint and finding_endpoint.endswith(truth_endpoint):
        score += 0.2
        reasons.append("endpoint")
    if truth.method and str(finding.get("method") or "").upper() == truth.method.upper():
        score += 0.05
        reasons.append("method")
    aliases = [truth.title, *truth.aliases]
    normalized_title = _normalize_text(finding.get("title"))
    if any(alias and _normalize_text(alias) in normalized_title for alias in aliases):
        score += 0.2
        reasons.append("title_alias")
    return min(score, 1.0), "+".join(reasons) or "no_match"


def _normalize_text(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    return " ".join(text.replace("-", " ").split())


def _normalize_endpoint(value: Any) -> str:
    if not value:
        return ""
    text = str(value).strip().lower()
    if "://" in text:
        text = "/" + text.split("/", 3)[-1] if text.count("/") >= 3 else "/"
    return text.rstrip("/") or "/"


def _knowledge_base_version(scan) -> str | None:
    for candidate in scan.finding_candidates:
        rag = candidate.rag_context or {}
        if rag.get("knowledge_base_version"):
            return str(rag["knowledge_base_version"])
    return None


def _candidate_for_truth(findings: list[dict[str, Any]], truth: GroundTruthFinding) -> dict[str, Any] | None:
    truth_endpoint = _normalize_endpoint(truth.endpoint)
    truth_category = _normalize_text(truth.category)
    for item in findings:
        if truth.cwe_id and item.get("cwe_id") == truth.cwe_id.lower():
            return item
        if truth_endpoint and item.get("endpoint", "").endswith(truth_endpoint) and item.get("category") == truth_category:
            return item
        aliases = [truth.title, *truth.aliases]
        if any(_normalize_text(alias) in item.get("title", "") for alias in aliases):
            return item
    return None


def _rag_relevant(candidate: dict[str, Any] | None) -> bool:
    if not candidate:
        return False
    references = candidate.get("references") or []
    return any(str(item.get("kind") or "") == "rag" for item in references)
