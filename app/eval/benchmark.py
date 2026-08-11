from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import Settings
from app.eval.evaluator import BenchmarkEvaluator
from app.eval.ground_truth import GroundTruthRepository
from app.eval.models import EvaluationResult


@dataclass
class EvaluationProfile:
    name: str
    settings: Settings


class EvaluationBenchmarkRunner:
    def __init__(self, settings: Settings, scan_runner) -> None:
        self.settings = settings
        self.scan_runner = scan_runner
        self.repository = GroundTruthRepository(settings.eval_dir)
        self.evaluator = BenchmarkEvaluator()

    def run(self, *, benchmark: str, profile: str = "optimized") -> tuple[EvaluationResult, Path]:
        fixture = self.repository.load(benchmark)
        profile_settings = build_profile_settings(self.settings, profile)
        scan = self.scan_runner(profile_settings, fixture.target)
        result = self.evaluator.evaluate(
            benchmark=fixture,
            profile=profile,
            scan=scan,
            config_snapshot=sanitize_config(profile_settings),
            git_commit=current_git_commit(),
        )
        output_path = profile_settings.eval_dir / "results" / f"{benchmark}-{profile}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result.model_dump(mode="json"), indent=2), encoding="utf-8")
        return result, output_path


def build_profile_settings(settings: Settings, profile: str) -> Settings:
    if profile == "baseline":
        return settings.model_copy(
            update={
                "rag_cache_enabled": False,
                "analysis_cache_enabled": False,
                "validation_cache_enabled": False,
                "model_cascading_enabled": False,
            }
        )
    if profile == "optimized":
        return settings.model_copy(
            update={
                "rag_cache_enabled": True,
                "analysis_cache_enabled": True,
                "validation_cache_enabled": True,
                "model_cascading_enabled": True,
            }
        )
    raise ValueError(f"unsupported profile: {profile}")


def sanitize_config(settings: Settings) -> dict[str, object]:
    payload = settings.model_dump(mode="json")
    payload.pop("validation_auth_header", None)
    return payload


def current_git_commit() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return None
    return completed.stdout.strip() or None
