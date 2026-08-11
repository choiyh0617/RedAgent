from __future__ import annotations

import time

from app.llm.models import AnalysisInput, FindingAnalysis, ModelRouteDecision


class ModelRouter:
    def __init__(self, settings) -> None:
        self.settings = settings

    def route(self, analysis_input: AnalysisInput) -> ModelRouteDecision:
        started = time.perf_counter()
        if not self.settings.model_cascading_enabled:
            return ModelRouteDecision(
                selected_model=self.settings.ollama_large_model or self.settings.ollama_small_model or None,
                routing_reason="model cascading disabled; using primary reasoning model",
                escalated=False,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        simple_finding = _is_simple_finding(analysis_input)
        has_exact_cwe = analysis_input.exact_cwe_id is not None
        strong_scanner_signal = analysis_input.scanner_confidence >= 0.8
        good_evidence = analysis_input.evidence_count >= 2

        if simple_finding and (has_exact_cwe or strong_scanner_signal or good_evidence):
            return ModelRouteDecision(
                selected_model=self.settings.ollama_small_model or self.settings.ollama_large_model or None,
                routing_reason="simple finding with strong deterministic signals",
                escalated=False,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        return ModelRouteDecision(
            selected_model=self.settings.ollama_large_model or self.settings.ollama_small_model or None,
            routing_reason="ambiguous or weak evidence requires larger reasoning path",
            escalated=True,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


class ConfidenceEvaluator:
    def __init__(self, settings) -> None:
        self.settings = settings

    def calculate(self, analysis_input: AnalysisInput, finding_analysis: FindingAnalysis) -> float:
        evidence_score = min(1.0, analysis_input.evidence_count / 3.0)
        rag_score = 1.0 if analysis_input.exact_cwe_id else 0.7 if analysis_input.knowledge else 0.2
        value = (
            analysis_input.scanner_confidence * self.settings.analysis_weight_scanner
            + finding_analysis.model_confidence * self.settings.analysis_weight_model
            + rag_score * self.settings.analysis_weight_rag
            + evidence_score * self.settings.analysis_weight_evidence
        )
        return max(0.0, min(1.0, value))

    def apply_gate(self, finding_analysis: FindingAnalysis, final_confidence: float) -> FindingAnalysis:
        if finding_analysis.status == "likely_false_positive":
            gated_status = "likely_false_positive"
        elif final_confidence >= self.settings.analysis_confidence_high:
            gated_status = "likely"
        elif final_confidence >= self.settings.analysis_confidence_low:
            gated_status = "needs_validation"
        else:
            gated_status = "insufficient_evidence"
        return finding_analysis.model_copy(update={"confidence": final_confidence, "final_confidence": final_confidence, "status": gated_status})


def _is_simple_finding(analysis_input: AnalysisInput) -> bool:
    title = analysis_input.title.lower()
    category = analysis_input.category.lower()
    simple_markers = ("missing ", "content-security-policy", "security header", "x-frame-options", "swagger", "openapi")
    if any(marker in title for marker in simple_markers):
        return True
    return "security misconfiguration" in category or "information disclosure" in category
