"""
.env 파일 로드 + stdout/stderr 인코딩 고정. 이 모듈을 import하기만 하면 적용된다.

1. .env: 이미 셸에 환경변수로 설정돼 있으면 그대로 우선 적용됨(override=False가
   기본값). 호스트 셸이 언제 시작됐는지와 무관하게 매번 파일을 다시 읽으므로,
   "환경변수를 설정했는데 이미 떠 있던 셸엔 안 보인다"는 문제(DESIGN.md 13절)를
   피할 수 있다.
2. stdout/stderr: Windows에서 파이썬이 로케일 기본 인코딩(cp1252)을 쓰면 한글
   출력(print)이 UnicodeEncodeError로 죽는다 -> UTF-8로 고정.
"""

import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - 선택 의존성
    def load_dotenv(*_args, **_kwargs):
        return False

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(ENV_PATH)

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")
