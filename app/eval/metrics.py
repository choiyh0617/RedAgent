from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.eval.models import AccuracyMetrics, CacheMetrics, LLMMetricEntry, PhaseMetric, SeverityMetricEntry, ToolMetricEntry


@dataclass
class RuntimeMetricsCollector:
    cache_hits: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    cache_misses: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    llm_calls: list[dict[str, Any]] = field(default_factory=list)
    phase_metrics: dict[str, dict[str, Any]] = field(default_factory=lambda: defaultdict(dict))

    def record_cache(self, cache_name: str, hit: bool) -> None:
        if hit:
            self.cache_hits[cache_name] += 1
        else:
            self.cache_misses[cache_name] += 1

    def record_llm_call(
        self,
        *,
        model_name: str,
        route: str,
        escalated: bool,
        latency_ms: int,
        input_chars: int,
        output_chars: int,
        parse_failed: bool = False,
        retry: bool = False,
    ) -> None:
        self.llm_calls.append(
            {
                "model_name": model_name,
                "route": route,
                "escalated": escalated,
                "latency_ms": latency_ms,
                "input_chars": input_chars,
                "output_chars": output_chars,
                "parse_failed": parse_failed,
                "retry": retry,
            }
        )

    def record_phase(
        self,
        phase: str,
        *,
        duration_ms: int,
        success: bool = True,
        failures: int = 0,
        retry_count: int = 0,
        tool_calls: int = 0,
        llm_calls: int = 0,
    ) -> None:
        self.phase_metrics[phase] = {
            "phase": phase,
            "duration_ms": duration_ms,
            "success": success,
            "failures": failures,
            "retry_count": retry_count,
            "tool_calls": tool_calls,
            "llm_calls": llm_calls,
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "cache_hits": dict(self.cache_hits),
            "cache_misses": dict(self.cache_misses),
            "llm_calls": list(self.llm_calls),
            "phase_metrics": list(self.phase_metrics.values()),
        }


def compute_accuracy(tp: int, fp: int, fn: int) -> AccuracyMetrics:
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2 * precision * recall, precision + recall) if precision + recall else 0.0
    return AccuracyMetrics(tp=tp, fp=fp, fn=fn, precision=precision, recall=recall, f1=f1)


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def build_cache_metrics(runtime_metrics: dict[str, Any]) -> CacheMetrics:
    hits = runtime_metrics.get("cache_hits", {})
    misses = runtime_metrics.get("cache_misses", {})
    total_hits = sum(hits.values())
    total_misses = sum(misses.values())
    return CacheMetrics(
        rag_cache_hits=hits.get("rag", 0),
        rag_cache_misses=misses.get("rag", 0),
        analysis_cache_hits=hits.get("analysis", 0),
        analysis_cache_misses=misses.get("analysis", 0),
        validation_cache_hits=hits.get("validation", 0),
        validation_cache_misses=misses.get("validation", 0),
        avoided_rag_retrievals=hits.get("rag", 0),
        avoided_llm_calls=hits.get("analysis", 0),
        hit_rate=safe_divide(total_hits, total_hits + total_misses),
    )


def build_llm_metrics(runtime_metrics: dict[str, Any]) -> list[LLMMetricEntry]:
    aggregated: dict[tuple[str, str], LLMMetricEntry] = {}
    for call in runtime_metrics.get("llm_calls", []):
        key = (call["model_name"], call["route"])
        entry = aggregated.setdefault(
            key,
            LLMMetricEntry(model_name=call["model_name"], route=call["route"]),
        )
        entry.call_count += 1
        entry.latency_ms += int(call["latency_ms"])
        entry.input_chars += int(call["input_chars"])
        entry.output_chars += int(call["output_chars"])
        entry.parse_failures += 1 if call.get("parse_failed") else 0
        entry.retry_count += 1 if call.get("retry") else 0
        entry.escalation_count += 1 if call.get("escalated") else 0
    return list(aggregated.values())


def build_phase_metrics(runtime_metrics: dict[str, Any]) -> list[PhaseMetric]:
    return [PhaseMetric.model_validate(item) for item in runtime_metrics.get("phase_metrics", [])]


def build_tool_metrics(tool_executions: list[Any]) -> list[ToolMetricEntry]:
    aggregated: dict[str, ToolMetricEntry] = {}
    for tool in tool_executions:
        entry = aggregated.setdefault(tool.tool, ToolMetricEntry(tool=tool.tool))
        entry.call_count += 1
        entry.duration_ms += int(tool.duration_ms)
        if tool.success:
            entry.success_count += 1
        else:
            entry.failure_count += 1
        if tool.error and "timeout" in tool.error.lower():
            entry.timeout_count += 1
    return list(aggregated.values())


def build_severity_metrics(matches: list[Any], findings_by_id: dict[str, Any], ground_truth_by_id: dict[str, Any]) -> dict[str, SeverityMetricEntry]:
    severities = ["critical", "high", "medium", "low", "info"]
    result = {severity: SeverityMetricEntry(severity=severity) for severity in severities}
    for match in matches:
        if match.disposition == "tp":
            severity = str((ground_truth_by_id.get(match.ground_truth_id) or {}).severity).lower()
            result[severity].tp += 1
        elif match.disposition == "fp":
            finding = findings_by_id.get(match.finding_id)
            severity = str(getattr(finding, "severity", "info")).lower()
            result[severity].fp += 1
        elif match.disposition == "fn":
            severity = str((ground_truth_by_id.get(match.ground_truth_id) or {}).severity).lower()
            result[severity].fn += 1
    for severity, entry in result.items():
        accuracy = compute_accuracy(entry.tp, entry.fp, entry.fn)
        entry.precision = accuracy.precision
        entry.recall = accuracy.recall
        entry.f1 = accuracy.f1
    return result
