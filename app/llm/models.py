from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.core.models import Severity


AnalysisStatus = Literal["likely", "needs_validation", "insufficient_evidence", "likely_false_positive"]


class AnalysisKnowledgeChunk(BaseModel):
    source: str
    title: str
    content: str
    trusted_as_instruction: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalysisInput(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: Severity
    endpoint: str
    method: str
    source_tool: str
    scanner_confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    evidence_count: int = 0
    exact_cwe_id: str | None = None
    rag_context_version: str | None = None
    knowledge: list[AnalysisKnowledgeChunk] = Field(default_factory=list)
    injection_warnings: list[str] = Field(default_factory=list)
    prompt_version: str


class InjectionScreenResult(BaseModel):
    is_suspicious: bool
    reason: str | None = None
    matched_rules: list[str] = Field(default_factory=list)


class RecommendedValidation(BaseModel):
    type: str
    reason: str


class ModelRouteDecision(BaseModel):
    selected_model: str | None = None
    routing_reason: str
    escalated: bool = False
    duration_ms: int = 0


class FindingAnalysis(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    cwe_id: str | None = None
    owasp_category: str | None = None
    impact: str
    reasoning_summary: str
    evidence_assessment: str
    status: AnalysisStatus
    recommended_validation: RecommendedValidation | None = None
    model_used: str | None = None
    routing_reason: str | None = None
    escalated: bool = False
    prompt_version: str = ""
    model_confidence: float = Field(ge=0.0, le=1.0)
    final_confidence: float = Field(ge=0.0, le=1.0)
    analysis_error: str | None = None


class AnalysisFailure(BaseModel):
    finding_id: str
    error: str
    retry_attempted: bool = False
    model_used: str | None = None
    prompt_version: str
