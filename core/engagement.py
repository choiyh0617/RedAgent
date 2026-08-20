"""
인게이지먼트 식별자 관리. state/<engagement_id>/ 밑에 findings.jsonl,
credentials.jsonl이 저장된다 (core/state_store.py).
"""

import re
from datetime import datetime, timezone
from pathlib import Path

STATE_ROOT = Path(__file__).resolve().parent.parent / "state"


def new_engagement_id(label: str | None = None) -> str:
    """예: 20260808-143000-kioptrix2. label이 없으면 타임스탬프만."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if not label:
        return ts
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", label).strip("-").lower()
    return f"{ts}-{slug}"


def engagement_dir(engagement_id: str) -> Path:
    d = STATE_ROOT / engagement_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_engagements() -> list[str]:
    if not STATE_ROOT.exists():
        return []
    return sorted(p.name for p in STATE_ROOT.iterdir() if p.is_dir())
