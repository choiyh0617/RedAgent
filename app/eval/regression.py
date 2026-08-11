from __future__ import annotations

import json
from pathlib import Path

from app.eval.models import EvaluationResult, RegressionCheck, RegressionResult, RegressionThresholds


class RegressionComparator:
    def compare(self, baseline: EvaluationResult, current: EvaluationResult, thresholds: RegressionThresholds) -> RegressionResult:
        baseline = _normalize_result(baseline)
        current = _normalize_result(current)
        checks: list[RegressionCheck] = []
        precision_drop = baseline.accuracy.precision - current.accuracy.precision
        checks.append(
            RegressionCheck(
                name="precision",
                passed=precision_drop <= thresholds.max_precision_drop,
                reason=f"precision_drop={precision_drop:.3f}",
            )
        )
        recall_drop = baseline.accuracy.recall - current.accuracy.recall
        checks.append(
            RegressionCheck(
                name="recall",
                passed=recall_drop <= thresholds.max_recall_drop,
                reason=f"recall_drop={recall_drop:.3f}",
            )
        )
        runtime_percent = _increase_percent(baseline.performance.duration_seconds, current.performance.duration_seconds)
        checks.append(
            RegressionCheck(
                name="runtime",
                passed=runtime_percent <= thresholds.max_runtime_increase_percent,
                reason=f"runtime_increase_percent={runtime_percent:.2f}",
            )
        )
        llm_percent = _increase_percent(baseline.performance.llm_calls, current.performance.llm_calls)
        checks.append(
            RegressionCheck(
                name="llm_calls",
                passed=llm_percent <= thresholds.max_llm_call_increase_percent,
                reason=f"llm_call_increase_percent={llm_percent:.2f}",
            )
        )
        return RegressionResult(
            passed=all(check.passed for check in checks),
            baseline_path="",
            current_path="",
            checks=checks,
        )

    def compare_files(self, baseline_path: Path, current_path: Path, thresholds: RegressionThresholds) -> RegressionResult:
        baseline = EvaluationResult.model_validate(json.loads(baseline_path.read_text(encoding="utf-8")))
        current = EvaluationResult.model_validate(json.loads(current_path.read_text(encoding="utf-8")))
        result = self.compare(baseline, current, thresholds)
        return result.model_copy(update={"baseline_path": str(baseline_path), "current_path": str(current_path)})


def _increase_percent(baseline: float, current: float) -> float:
    if baseline <= 0:
        return 0.0 if current <= 0 else 100.0
    return ((current - baseline) / baseline) * 100.0


def _normalize_result(result: EvaluationResult) -> EvaluationResult:
    if isinstance(result, EvaluationResult):
        return EvaluationResult.model_validate(result.model_dump(mode="json"))
    return EvaluationResult.model_validate(result)
