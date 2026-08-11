from __future__ import annotations

import json
from pathlib import Path

from app.eval.models import BenchmarkFixture


class GroundTruthRepository:
    def __init__(self, eval_dir: Path) -> None:
        self.eval_dir = eval_dir

    def load(self, benchmark: str) -> BenchmarkFixture:
        fixture_path = self.eval_dir / "ground_truth" / f"{benchmark}.json"
        if not fixture_path.exists():
            raise FileNotFoundError(f"benchmark fixture not found: {fixture_path}")
        payload = json.loads(fixture_path.read_text(encoding="utf-8"))
        return BenchmarkFixture.model_validate(payload)
