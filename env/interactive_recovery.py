"""
권한/세션 문제를 사람과 핑퐁하며 복구하는 공통 유틸리티.

실패를 무조건 최종 실패로 닫지 않고, 사용자가 직접 확인한 결과나 대체 명령을
받아 한 번 더 진행할 수 있게 한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_INTERACTIVE_ERROR_RE = re.compile(
    r"permission denied|operation not permitted|access denied|must be root|sudo:|"
    r"error starting guest session|guest session force-closed|verr_duplicate|"
    r"current status is: terminated|machine is not running|kali 세션 락",
    re.IGNORECASE,
)


@dataclass
class RecoveryDecision:
    retry_command: str | None = None
    confirmed_output: str | None = None
    skip: bool = False


def looks_interactive_worthy(*texts: str) -> bool:
    return any(_INTERACTIVE_ERROR_RE.search(text or "") for text in texts)


def ask_user_for_recovery(command: str, stdout: str = "", stderr: str = "") -> RecoveryDecision:
    print("\n[interactive-recovery] 권한/세션 문제 감지")
    print(f"명령: {command}")
    if stderr.strip():
        print(f"stderr: {stderr.strip()[:800]}")
    elif stdout.strip():
        print(f"stdout: {stdout.strip()[:800]}")
    print(
        "입력 규칙:\n"
        "  - 그냥 Enter: 현재 실패 유지\n"
        "  - RESULT:<텍스트>: 사람이 직접 확인한 결과를 성공 출력으로 사용\n"
        "  - CMD:<명령>: 이 명령으로 한 번 더 재시도\n"
        "  - SKIP: 실패로 보지 않고 건너뜀"
    )
    try:
        answer = input("선택: ").strip()
    except (KeyboardInterrupt, EOFError):
        return RecoveryDecision()

    if not answer:
        return RecoveryDecision()
    if answer.upper() == "SKIP":
        return RecoveryDecision(skip=True)
    if answer.startswith("RESULT:"):
        return RecoveryDecision(confirmed_output=answer[len("RESULT:"):].strip())
    if answer.startswith("CMD:"):
        retry_command = answer[len("CMD:"):].strip()
        return RecoveryDecision(retry_command=retry_command or None)
    return RecoveryDecision(confirmed_output=answer)
