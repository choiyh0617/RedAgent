"""
Ollama 기반 LLM 호출 경로가 실제로 동작하는지 확인.
민감한 키는 없지만, 설정값 자체는 출력하지 않고 성공/실패와 응답만 보고한다.
"""

from core.llm_client import call


def check() -> tuple[bool, str]:
    try:
        result = call("say ok", max_tokens=8)
        return bool(result), result
    except Exception as exc:  # noqa: BLE001 - 진단용으로 모든 실패를 잡아서 보고
        return False, str(exc)


if __name__ == "__main__":
    ok, detail = check()
    if ok:
        print(f"LLM 호출 경로: 정상 동작 (응답: {detail!r})")
        print("현재 경로는 Ollama HTTP API입니다.")
    else:
        print(f"LLM 호출 경로: 실패 - {detail}")
