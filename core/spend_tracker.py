"""
종량제 API 누적 지출 추정 + 상한. DESIGN.md 17절.

주의(중요한 한계): Anthropic API에는 "남은 잔액"을 조회하는 공식 방법이 없다.
그래서 이건 우리가 토큰 수 x 공개 가격표로 계산한 **추정치** 기준의 소프트
가드레일이다. 진짜 하드 스톱은 Anthropic Console의 지출 한도(계정 레벨,
DESIGN.md 14절)이고, 이건 그걸 보완하는 2차 방어선이다 — 둘 다 설정할 것.

호출 흐름: 매 종량제 API 호출 전에 "이미 상한을 넘었는지" 확인하고(넘었으면
그 호출 자체를 막음), 호출 후 실제 토큰 사용량으로 비용을 기록한다. 즉 상한을
넘기는 순간의 그 마지막 한 번은 막을 수 없지만(호출 전엔 정확한 비용을 모름),
그 다음 호출부터는 확실히 막힌다.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

SPEND_STATE_PATH = Path(__file__).resolve().parent.parent / "state" / "_api_spend.json"

DEFAULT_CAP_USD = 5.0  # 사용자가 .env의 MAX_API_SPEND_USD로 실제 충전 금액에 맞게 조정할 것

# 2026-08 기준 공개 가격(백만 토큰당 USD). 가격이 바뀌면 여기를 갱신해야 정확해진다.
PRICING_PER_MILLION_TOKENS = {
    "claude-sonnet-5": {"input": 3.0, "output": 15.0},
    "claude-opus-5": {"input": 15.0, "output": 75.0},
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},
}


class SpendCapExceededError(RuntimeError):
    pass


def get_cap_usd() -> float:
    return float(os.environ.get("MAX_API_SPEND_USD", DEFAULT_CAP_USD))


def _read_state() -> dict:
    if not SPEND_STATE_PATH.exists():
        return {"total_usd": 0.0, "calls": []}
    try:
        return json.loads(SPEND_STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"total_usd": 0.0, "calls": []}


def _write_state(state: dict) -> None:
    SPEND_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SPEND_STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def current_total_usd() -> float:
    return _read_state().get("total_usd", 0.0)


def reset() -> None:
    """구독 사용량 한도가 리셋되어 다시 구독 경로를 쓸 수 있게 될 때 호출.

    MAX_API_SPEND_USD는 '전체 기간 누적 총합'이 아니라 '구독이 막혀서 종량제로
    돌던 한 구간(limited window)당 예산'으로 쓰기로 함(사용자 확인) - 구독이
    다시 풀리면 다음 구간을 위해 0으로 되돌린다.
    """
    _write_state({"total_usd": 0.0, "calls": []})


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    rates = PRICING_PER_MILLION_TOKENS.get(model)
    if not rates:
        return 0.0  # 모르는 모델은 추정 불가 -> 누적에도 안 잡힘 (아래 record_and_check 경고 참고)
    return (input_tokens * rates["input"] + output_tokens * rates["output"]) / 1_000_000


def ensure_within_cap() -> None:
    """호출 시작 전에 부른다. 이미 상한을 넘었으면 이번 호출 자체를 막는다."""
    cap = get_cap_usd()
    total = current_total_usd()
    if total >= cap:
        raise SpendCapExceededError(
            f"누적 API 지출 추정치 ${total:.4f}가 상한 ${cap:.2f}에 도달/초과함 - "
            "추가 종량제 호출을 막습니다. .env의 MAX_API_SPEND_USD를 조정하거나 "
            "state/_api_spend.json을 확인하세요."
        )


def record(model: str, input_tokens: int, output_tokens: int) -> tuple[float, float]:
    """이번 호출 비용을 기록. (이번 호출 비용, 누적 비용)을 반환."""
    cost = estimate_cost(model, input_tokens, output_tokens)
    state = _read_state()
    state["total_usd"] = state.get("total_usd", 0.0) + cost
    state.setdefault("calls", []).append({
        "ts": datetime.now(timezone.utc).isoformat(), "model": model,
        "input_tokens": input_tokens, "output_tokens": output_tokens, "cost_usd": round(cost, 6),
    })
    _write_state(state)
    if model not in PRICING_PER_MILLION_TOKENS:
        print(f"[spend_tracker] 경고: '{model}' 가격 정보 없음 - 이번 호출 비용은 누적에 반영 안 됨")
    return cost, state["total_usd"]
