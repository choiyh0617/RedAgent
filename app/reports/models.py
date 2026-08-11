from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


REPORT_SCHEMA_VERSION = "v1"
FinalFindingStatus = Literal[
    "verified",
    "likely",
    "unverified",
    "false_positive",
    "validation_skipped",
    "informational",
]


class FinalSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingReference(BaseModel):
    kind: str
    label: str
    value: str


class FindingEvidenceRecord(BaseModel):
    type: str
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    observation: str


class FinalFinding(BaseModel):
    id: str
    title: str
    severity: FinalSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    final_status: FinalFindingStatus
    target: HttpUrl
    endpoint: str
    method: str
    category: str
    cwe_id: str | None = None
    owasp_category: str | None = None
    description: str
    impact: str
    recommendation: str
    evidence: list[FindingEvidenceRecord] = Field(default_factory=list)
    validation_status: str | None = None
    validation_reason: str | None = None
    source_tools: list[str] = Field(default_factory=list)
    references: list[FindingReference] = Field(default_factory=list)
    created_at: datetime


class ExecutiveSummary(BaseModel):
    target: HttpUrl
    scan_id: str
    scan_duration_ms: int
    total_findings: int
    confirmed_findings: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    status_counts: dict[str, int] = Field(default_factory=dict)
    verified_findings: int = 0
    unverified_findings: int = 0
    false_positive_findings: int = 0
    validation_skipped_findings: int = 0


class ScanMetadata(BaseModel):
    app_name: str
    schema_version: str = REPORT_SCHEMA_VERSION
    scan_id: str
    status: str
    created_at: datetime
    updated_at: datetime
    scan_duration_ms: int
    report_generated_at: datetime


class ReconSummary(BaseModel):
    target_ip: str | None = None
    http_status: int | None = None
    http_title: str | None = None
    open_ports: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    endpoint_count: int = 0
    candidate_count: int = 0


class FindingSummary(BaseModel):
    total_candidates: int
    final_finding_count: int
    confirmed_finding_count: int
    false_positive_count: int
    unverified_count: int
    validation_skipped_count: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    status_counts: dict[str, int] = Field(default_factory=dict)


class ValidationSummary(BaseModel):
    validation_attempted_count: int = 0
    validation_verified_count: int = 0
    validation_false_positive_count: int = 0
    validation_unverified_count: int = 0
    validation_skipped_count: int = 0
    validation_request_count: int = 0
    validation_duration: int = 0


class ToolSummary(BaseModel):
    tool: str
    success: bool
    duration_ms: int
    error: str | None = None


class GuardrailSummary(BaseModel):
    blocked_action_count: int = 0
    scope_violation_count: int = 0
    blocked_actions: list[str] = Field(default_factory=list)


class ReportMetrics(BaseModel):
    scan_duration_ms: int
    tool_call_count: int
    llm_call_count: int | None = None
    rag_retrieval_count: int
    candidate_count: int
    final_finding_count: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    status_counts: dict[str, int] = Field(default_factory=dict)
    blocked_action_count: int = 0
    scope_violation_count: int = 0
    validation_attempted_count: int = 0
    validation_verified_count: int = 0
    validation_false_positive_count: int = 0
    validation_unverified_count: int = 0
    validation_skipped_count: int = 0
    validation_request_count: int = 0
    validation_duration: int = 0


class PentestReport(BaseModel):
    schema_version: str = REPORT_SCHEMA_VERSION
    executive_summary: ExecutiveSummary
    scope: list[str] = Field(default_factory=list)
    scan_metadata: ScanMetadata
    recon_summary: ReconSummary
    finding_summary: FindingSummary
    findings: list[FinalFinding] = Field(default_factory=list)
    validation_summary: ValidationSummary
    tool_execution_summary: list[ToolSummary] = Field(default_factory=list)
    guardrail_summary: GuardrailSummary
    limitations: list[str] = Field(default_factory=list)
    metrics: ReportMetrics
