from __future__ import annotations

from app.eval.models import CostMetrics


def build_cost_metrics(llm_metrics: list) -> CostMetrics:
    models = sorted({entry.model_name for entry in llm_metrics if entry.model_name})
    return CostMetrics(
        external_api_cost_usd=0.0,
        llm_call_count=sum(entry.call_count for entry in llm_metrics),
        input_chars=sum(entry.input_chars for entry in llm_metrics),
        output_chars=sum(entry.output_chars for entry in llm_metrics),
        models=models,
    )
