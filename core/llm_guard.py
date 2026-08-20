"""
LLM 호출 공통 안전장치. DESIGN.md 14절(API 사용 제한 논의) 참고.

Anthropic Console의 지출 한도(계정 레벨)가 최후 방어선이고, 이건 그 안쪽 레이어:
1. 동시 호출 수 제한 - ThreadPoolExecutor(max_workers=N)를 호출부에서 직접 씀
   (core/llm_client.py의 call()이 동기 함수라 세마포어 대신 이 방식이 더 단순함)
2. 입력 텍스트 크기 상한 (프롬프트 폭발 방지) - 실제로 searchsploit 결과가
   560만 토큰까지 부푼 사고가 있었음 (vuln_analysis.py에서 발견)
3. 실행당 호출 횟수 상한 (circuit breaker) - 버그로 무한 루프가 생겨도 여기서 끊김
"""

from core.state_store import append_finding

MAX_PROMPT_CHARS = 8000  # 대략 2000토큰 상당의 방어적 상한. 넘으면 자름


def truncate(text: str, max_chars: int = MAX_PROMPT_CHARS) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... (생략됨, 원래 {len(text)}자)"


def check_call_budget(engagement_id: str, stage: str, requested: int, max_calls: int) -> None:
    """실행당 LLM 호출 총량 상한. 초과 시 findings에 기록 후 예외."""
    if requested > max_calls:
        append_finding(
            engagement_id, stage=stage, event="llm_call_budget_exceeded",
            requested=requested, max_calls=max_calls,
        )
        raise RuntimeError(
            f"{stage}: LLM 호출 {requested}건이 상한({max_calls})을 초과해서 중단함 "
            "(circuit breaker, DESIGN.md 14절)"
        )
