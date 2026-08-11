from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


GroundTruthExpectedStatus = Literal["present", "out_of_scope"]
MatchDisposition = Literal["tp", "fp", "fn"]


class GroundTruthFinding(BaseModel):
    id: str
    title: str
    category: str
    severity: str
    endpoint: str | None = None
    method: str | None = None
    cwe_id: str | None = None
    expected_status: GroundTruthExpectedStatus = "present"
    aliases: list[str] = Field(default_factory=list)
    notes: str | None = None


class BenchmarkFixture(BaseModel):
    benchmark_id: str
    description: str
    target: str
    supported_ground_truth: list[GroundTruthFinding] = Field(default_factory=list)
    out_of_scope_ground_truth: list[GroundTruthFinding] = Field(default_factory=list)


class FindingMatchResult(BaseModel):
    finding_id: str | None = None
    ground_truth_id: str | None = None
    disposition: MatchDisposition
    score: float = 0.0
    reason: str
    finding_title: str | None = None
    category: str | None = None
    endpoint: str | None = None
    final_status: str | None = None
    validation_status: str | None = None
    source_tool: str | None = None


class AccuracyMetrics(BaseModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


class StatusMetrics(BaseModel):
    strict_precision: float = 0.0
    assisted_precision: float = 0.0
    verified_true_positive: int = 0
    likely_true_positive: int = 0
    unverified_candidates: int = 0
    false_positive_findings: int = 0
    validation_skipped_findings: int = 0
    verified_finding_ratio: float = 0.0
    unverified_finding_ratio: float = 0.0
    validation_success_rate: float = 0.0


class SeverityMetricEntry(BaseModel):
    severity: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


class ToolMetricEntry(BaseModel):
    tool: str
    call_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    duration_ms: int = 0
    timeout_count: int = 0


class LLMMetricEntry(BaseModel):
    model_name: str
    route: str
    call_count: int = 0
    escalation_count: int = 0
    latency_ms: int = 0
    input_chars: int = 0
    output_chars: int = 0
    parse_failures: int = 0
    retry_count: int = 0


class CacheMetrics(BaseModel):
    rag_cache_hits: int = 0
    rag_cache_misses: int = 0
    analysis_cache_hits: int = 0
    analysis_cache_misses: int = 0
    validation_cache_hits: int = 0
    validation_cache_misses: int = 0
    avoided_rag_retrievals: int = 0
    avoided_llm_calls: int = 0
    hit_rate: float = 0.0


class PhaseMetric(BaseModel):
    phase: str
    duration_ms: int = 0
    success: bool = True
    failures: int = 0
    retry_count: int = 0
    tool_calls: int = 0
    llm_calls: int = 0


class CostMetrics(BaseModel):
    external_api_cost_usd: float = 0.0
    llm_call_count: int = 0
    input_chars: int = 0
    output_chars: int = 0
    models: list[str] = Field(default_factory=list)


class FalsePositiveAttribution(BaseModel):
    finding_id: str
    title: str
    category: str
    source_tool: str
    analysis_confidence: float = 0.0
    validation_status: str | None = None
    reason: str


class FalseNegativeAttribution(BaseModel):
    ground_truth_id: str
    expected_category: str
    endpoint: str | None = None
    scanner_candidate: bool = False
    rag_relevant: bool = False
    analysis_status: str | None = None
    validation_status: str | None = None
    reason: str


class PipelineAttribution(BaseModel):
    ground_truth_id: str
    scanner_candidate: bool = False
    rag_relevant: bool = False
    analysis: str | None = None
    validation: str | None = None
    final: str


class VersionMetadata(BaseModel):
    analysis_prompt_version: str | None = None
    validation_engine_version: str | None = None
    report_schema_version: str | None = None
    knowledge_base_version: str | None = None
    model_names: list[str] = Field(default_factory=list)


class EvaluationMetadata(BaseModel):
    eval_id: str
    benchmark: str
    profile: str
    timestamp: datetime
    target: str
    git_commit: str | None = None
    pentestflow_version: str = "0.1"
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    versions: VersionMetadata


class PerformanceMetrics(BaseModel):
    duration_seconds: float = 0.0
    tool_calls: int = 0
    llm_calls: int = 0


class EvaluationResult(BaseModel):
    benchmark: str
    profile: str
    metadata: EvaluationMetadata
    accuracy: AccuracyMetrics
    status_metrics: StatusMetrics
    severity_metrics: dict[str, SeverityMetricEntry] = Field(default_factory=dict)
    performance: PerformanceMetrics
    cache: CacheMetrics
    cost: CostMetrics
    phase_metrics: list[PhaseMetric] = Field(default_factory=list)
    tool_metrics: list[ToolMetricEntry] = Field(default_factory=list)
    llm_metrics: list[LLMMetricEntry] = Field(default_factory=list)
    matches: list[FindingMatchResult] = Field(default_factory=list)
    false_positive_analysis: list[FalsePositiveAttribution] = Field(default_factory=list)
    false_negative_analysis: list[FalseNegativeAttribution] = Field(default_factory=list)
    pipeline_attribution: list[PipelineAttribution] = Field(default_factory=list)


class RegressionThresholds(BaseModel):
    max_precision_drop: float = 0.03
    max_recall_drop: float = 0.05
    max_runtime_increase_percent: float = 20.0
    max_llm_call_increase_percent: float = 20.0


class RegressionCheck(BaseModel):
    name: str
    passed: bool
    reason: str


class RegressionResult(BaseModel):
    passed: bool
    baseline_path: str
    current_path: str
    checks: list[RegressionCheck] = Field(default_factory=list)
