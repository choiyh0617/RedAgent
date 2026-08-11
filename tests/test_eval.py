from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.config import Settings
from app.core.models import FindingCandidate, ReconResult, ScanRecord, ScanStatus, ToolExecution
from app.eval.benchmark import EvaluationBenchmarkRunner, build_profile_settings, sanitize_config
from app.eval.evaluator import BenchmarkEvaluator, match_findings, match_score
from app.eval.ground_truth import GroundTruthRepository
from app.eval.metrics import build_cache_metrics, compute_accuracy, safe_divide
from app.eval.models import BenchmarkFixture, EvaluationResult, GroundTruthFinding, RegressionThresholds
from app.eval.regression import RegressionComparator


class EvalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.eval_dir = Path(self.temp_dir.name) / "eval"
        (self.eval_dir / "ground_truth").mkdir(parents=True)
        fixture = {
            "benchmark_id": "juice-shop-safe-v1",
            "description": "fixture",
            "target": "http://127.0.0.1:3000",
            "supported_ground_truth": [
                {
                    "id": "GT-001",
                    "title": "Missing Content-Security-Policy",
                    "category": "security misconfiguration",
                    "severity": "medium",
                    "endpoint": "/",
                    "method": "GET",
                    "cwe_id": "CWE-16",
                    "expected_status": "present",
                    "aliases": ["Missing Security Headers"],
                },
                {
                    "id": "GT-002",
                    "title": "Exposed Admin Endpoint",
                    "category": "access control",
                    "severity": "high",
                    "endpoint": "/admin",
                    "method": "GET",
                    "expected_status": "present",
                    "aliases": ["Admin Panel Exposure"],
                },
            ],
            "out_of_scope_ground_truth": [
                {
                    "id": "OOS-001",
                    "title": "SQL Injection Challenge",
                    "category": "injection",
                    "severity": "high",
                    "expected_status": "out_of_scope",
                    "aliases": ["Injection challenge"],
                }
            ],
        }
        (self.eval_dir / "ground_truth" / "juice-shop-safe-v1.json").write_text(json.dumps(fixture), encoding="utf-8")
        self.settings = Settings(eval_dir=self.eval_dir, reports_dir=Path(self.temp_dir.name) / "reports")
        self.started = datetime(2026, 8, 11, 10, 0, tzinfo=timezone.utc)
        self.ended = self.started + timedelta(seconds=4)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _scan(self) -> ScanRecord:
        candidate = FindingCandidate(
            id="F-001",
            title="Missing Content-Security-Policy",
            category="security misconfiguration",
            severity="MEDIUM",
            endpoint="http://127.0.0.1:3000/",
            method="GET",
            evidence=["missing header"],
            source_tool="nuclei",
            confidence=0.82,
            rag_context={"knowledge_base_version": "kb-v1", "results": [{"source": "CWE", "title": "CWE-16"}]},
            final_status="verified",
        )
        finding = {
            "id": "F-001",
            "title": "Missing Content-Security-Policy",
            "severity": "medium",
            "confidence": 0.9,
            "final_status": "verified",
            "endpoint": "http://127.0.0.1:3000/",
            "method": "GET",
            "category": "security misconfiguration",
            "cwe_id": "CWE-16",
            "validation_status": "verified",
            "source_tools": ["nuclei"],
            "references": [{"kind": "rag", "label": "CWE", "value": "CWE-16"}],
        }
        return ScanRecord(
            scan_id="scan-eval-001",
            target="http://127.0.0.1:3000",
            status=ScanStatus.COMPLETED,
            created_at=self.started,
            updated_at=self.ended,
            scope=["127.0.0.1"],
            recon=ReconResult(target="http://127.0.0.1:3000", finding_candidates=[]),
            finding_candidates=[candidate],
            findings=[finding],
            tools_used=[
                ToolExecution(tool="web_probe", success=True, duration_ms=100),
                ToolExecution(tool="analysis_agent", success=True, duration_ms=200),
            ],
            validation_metrics={
                "validation_attempted_count": 1,
                "validation_verified_count": 1,
                "validation_false_positive_count": 0,
                "validation_unverified_count": 0,
                "validation_skipped_count": 0,
                "validation_request_count": 1,
                "validation_duration": 40,
            },
            runtime_metrics={
                "cache_hits": {"rag": 1, "analysis": 2},
                "cache_misses": {"validation": 1},
                "llm_calls": [
                    {
                        "model_name": "small-model",
                        "route": "small",
                        "escalated": False,
                        "latency_ms": 150,
                        "input_chars": 1000,
                        "output_chars": 300,
                        "parse_failed": False,
                        "retry": False,
                    }
                ],
                "phase_metrics": [
                    {"phase": "analysis", "duration_ms": 200, "success": True, "failures": 0, "retry_count": 0, "tool_calls": 1, "llm_calls": 1}
                ],
            },
        )

    def test_ground_truth_loading(self) -> None:
        fixture = GroundTruthRepository(self.eval_dir).load("juice-shop-safe-v1")
        self.assertEqual(fixture.benchmark_id, "juice-shop-safe-v1")
        self.assertEqual(len(fixture.supported_ground_truth), 2)

    def test_malformed_ground_truth(self) -> None:
        broken = self.eval_dir / "ground_truth" / "broken.json"
        broken.write_text('{"benchmark_id": "broken"}', encoding="utf-8")
        with self.assertRaises(Exception):
            GroundTruthRepository(self.eval_dir).load("broken")

    def test_exact_cwe_matching(self) -> None:
        truth = GroundTruthFinding(id="GT", title="x", category="security misconfiguration", severity="medium", cwe_id="CWE-16")
        score, reason = match_score({"title": "x", "category": "security misconfiguration", "cwe_id": "CWE-16"}, truth)
        self.assertGreaterEqual(score, 0.7)
        self.assertIn("exact_cwe", reason)

    def test_title_alias_matching(self) -> None:
        truth = GroundTruthFinding(id="GT", title="Exposed Admin Endpoint", category="access control", severity="high", aliases=["Admin Panel Exposure"])
        score, reason = match_score({"title": "Admin Panel Exposure", "category": "access control"}, truth)
        self.assertGreater(score, 0.4)
        self.assertIn("title_alias", reason)

    def test_endpoint_matching(self) -> None:
        truth = GroundTruthFinding(id="GT", title="x", category="access control", severity="high", endpoint="/admin")
        score, reason = match_score({"title": "x", "category": "access control", "endpoint": "http://127.0.0.1:3000/admin"}, truth)
        self.assertIn("endpoint", reason)

    def test_tp_fp_fn_computation(self) -> None:
        fixture = GroundTruthRepository(self.eval_dir).load("juice-shop-safe-v1")
        findings = self._scan().findings + [{
            "id": "F-002",
            "title": "Swagger API",
            "severity": "low",
            "confidence": 0.7,
            "final_status": "unverified",
            "endpoint": "http://127.0.0.1:3000/api-docs",
            "method": "GET",
            "category": "information disclosure",
            "source_tools": ["nuclei"],
            "references": [],
        }]
        matches = match_findings(findings, fixture.supported_ground_truth)
        counts = {key: sum(1 for item in matches if item.disposition == key) for key in ("tp", "fp", "fn")}
        self.assertEqual(counts["tp"], 1)
        self.assertEqual(counts["fp"], 1)
        self.assertEqual(counts["fn"], 1)

    def test_precision_recall_f1_and_divide_by_zero(self) -> None:
        metrics = compute_accuracy(5, 1, 2)
        self.assertAlmostEqual(metrics.precision, 5 / 6, places=3)
        self.assertAlmostEqual(metrics.recall, 5 / 7, places=3)
        self.assertGreater(metrics.f1, 0)
        self.assertEqual(safe_divide(1, 0), 0.0)

    def test_strict_vs_assisted_metrics_and_severity_metrics(self) -> None:
        evaluator = BenchmarkEvaluator()
        fixture = GroundTruthRepository(self.eval_dir).load("juice-shop-safe-v1")
        scan = self._scan()
        scan.findings.append({
            "id": "F-003",
            "title": "Exposed Admin Endpoint",
            "severity": "high",
            "confidence": 0.74,
            "final_status": "likely",
            "endpoint": "http://127.0.0.1:3000/admin",
            "method": "GET",
            "category": "access control",
            "validation_status": "validation_skipped",
            "source_tools": ["crawler"],
            "references": [],
        })
        result = evaluator.evaluate(
            benchmark=fixture,
            profile="optimized",
            scan=scan,
            config_snapshot=sanitize_config(self.settings),
            git_commit=None,
        )
        self.assertGreaterEqual(result.status_metrics.assisted_precision, result.status_metrics.strict_precision)
        self.assertIn("medium", result.severity_metrics)

    def test_cache_hit_rate(self) -> None:
        cache = build_cache_metrics({"cache_hits": {"rag": 2}, "cache_misses": {"rag": 1}})
        self.assertAlmostEqual(cache.hit_rate, 2 / 3, places=3)

    def test_regression_pass_and_failures(self) -> None:
        base = EvaluationResult.model_validate({
            "benchmark": "b",
            "profile": "baseline",
            "metadata": {"eval_id": "1", "benchmark": "b", "profile": "baseline", "timestamp": self.started, "target": "t", "versions": {}},
            "accuracy": {"tp": 5, "fp": 1, "fn": 1, "precision": 0.83, "recall": 0.83, "f1": 0.83},
            "status_metrics": {},
            "severity_metrics": {},
            "performance": {"duration_seconds": 10.0, "tool_calls": 5, "llm_calls": 5},
            "cache": {},
            "cost": {},
            "phase_metrics": [],
            "tool_metrics": [],
            "llm_metrics": [],
            "matches": [],
            "false_positive_analysis": [],
            "false_negative_analysis": [],
            "pipeline_attribution": []
        })
        current = base.model_copy(update={"accuracy": {"tp": 5, "fp": 2, "fn": 2, "precision": 0.71, "recall": 0.71, "f1": 0.71}})
        comparator = RegressionComparator()
        thresholds = RegressionThresholds(max_precision_drop=0.2, max_recall_drop=0.2, max_runtime_increase_percent=20, max_llm_call_increase_percent=20)
        self.assertTrue(comparator.compare(base, base, thresholds).passed)
        self.assertFalse(comparator.compare(base, current, RegressionThresholds(max_precision_drop=0.03, max_recall_drop=0.05, max_runtime_increase_percent=20, max_llm_call_increase_percent=20)).passed)

    def test_runtime_and_llm_regression(self) -> None:
        base = EvaluationResult.model_validate({
            "benchmark": "b",
            "profile": "baseline",
            "metadata": {"eval_id": "1", "benchmark": "b", "profile": "baseline", "timestamp": self.started, "target": "t", "versions": {}},
            "accuracy": {"tp": 1, "fp": 0, "fn": 0, "precision": 1, "recall": 1, "f1": 1},
            "status_metrics": {},
            "severity_metrics": {},
            "performance": {"duration_seconds": 10.0, "tool_calls": 5, "llm_calls": 5},
            "cache": {},
            "cost": {},
            "phase_metrics": [],
            "tool_metrics": [],
            "llm_metrics": [],
            "matches": [],
            "false_positive_analysis": [],
            "false_negative_analysis": [],
            "pipeline_attribution": []
        })
        current = base.model_copy(update={"performance": {"duration_seconds": 15.0, "tool_calls": 5, "llm_calls": 7}})
        result = RegressionComparator().compare(base, current, RegressionThresholds(max_precision_drop=0.03, max_recall_drop=0.05, max_runtime_increase_percent=20, max_llm_call_increase_percent=20))
        self.assertFalse(result.passed)
        failed = {check.name for check in result.checks if not check.passed}
        self.assertIn("runtime", failed)
        self.assertIn("llm_calls", failed)

    def test_version_metadata_and_config_sanitization(self) -> None:
        fixture = GroundTruthRepository(self.eval_dir).load("juice-shop-safe-v1")
        settings = self.settings.model_copy(update={"validation_auth_header": "Bearer secret", "analysis_prompt_version": "v2"})
        result = BenchmarkEvaluator().evaluate(
            benchmark=fixture,
            profile="optimized",
            scan=self._scan(),
            config_snapshot=sanitize_config(settings),
        )
        self.assertEqual(result.metadata.versions.analysis_prompt_version, "v2")
        self.assertNotIn("validation_auth_header", result.metadata.config_snapshot)

    def test_false_positive_and_false_negative_attribution_and_pipeline(self) -> None:
        fixture = GroundTruthRepository(self.eval_dir).load("juice-shop-safe-v1")
        scan = self._scan()
        scan.findings = scan.findings + [{
            "id": "F-002",
            "title": "Swagger API",
            "severity": "low",
            "confidence": 0.6,
            "final_status": "false_positive",
            "endpoint": "http://127.0.0.1:3000/api-docs",
            "method": "GET",
            "category": "information disclosure",
            "validation_status": "false_positive",
            "source_tools": ["nuclei"],
            "references": [],
        }]
        result = BenchmarkEvaluator().evaluate(
            benchmark=fixture,
            profile="optimized",
            scan=scan,
            config_snapshot=sanitize_config(self.settings),
        )
        self.assertGreaterEqual(len(result.false_positive_analysis), 1)
        self.assertGreaterEqual(len(result.false_negative_analysis), 1)
        self.assertEqual(len(result.pipeline_attribution), len(fixture.supported_ground_truth))

    def test_profile_behavior_and_safety_not_disabled(self) -> None:
        baseline = build_profile_settings(self.settings, "baseline")
        optimized = build_profile_settings(self.settings, "optimized")
        self.assertFalse(baseline.rag_cache_enabled)
        self.assertFalse(baseline.model_cascading_enabled)
        self.assertTrue(optimized.validation_enabled)
        self.assertEqual(baseline.allowed_hosts, self.settings.allowed_hosts)

    def test_benchmark_runner_saves_result(self) -> None:
        runner = EvaluationBenchmarkRunner(self.settings, scan_runner=lambda cfg, target: self._scan())
        result, path = runner.run(benchmark="juice-shop-safe-v1", profile="optimized")
        self.assertTrue(path.exists())
        self.assertEqual(result.benchmark, "juice-shop-safe-v1")
