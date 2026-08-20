"""
파이프라인 진행상황을 사람이 읽기 좋은 형식으로 콘솔에 찍는다. DESIGN.md 30절.

로컬에서 `run_pipeline.py`를 돌리면 nmap 전체 포트 스캔, msfconsole -x 체이닝
같은 단계는 수 분씩 걸린다(job_runner.py가 이미 폴링 중간 로그를 findings에
남기지만, 콘솔에는 최종 결과만 반환되기 전까지 아무것도 안 보임) - 그래서
"지금 몇 번째 단계를 하고 있는지"를 매 단계 전환마다, 그리고 단계 안의 중요한
중간 지점마다 일관된 형식으로 출력해서, 화면이 오래 멈춰있는 것처럼 보이지
않게 한다.

`stage()`를 부른 시점부터 다음 `stage()`/`done()` 호출까지가 "그 단계가
진행 중"이라는 뜻 - 별도의 상태 추적 없이 호출 순서 자체가 진행 표시다.
"""

import time

_start_time: float = 0.0
_total_stages: int = 0
_current_stage: int = 0

BAR_WIDTH = 20


def start_pipeline(total_stages: int) -> None:
    """파이프라인 시작 시 한 번 호출. 전체 단계 수를 알아야 [n/총] 형식으로
    찍을 수 있어서 - 단계 수를 모르면 total_stages=0으로 두면 [n/총] 없이
    번호만 찍는다."""
    global _start_time, _total_stages, _current_stage
    _start_time = time.time()
    _total_stages = total_stages
    _current_stage = 0


def format_elapsed(seconds: float) -> str:
    """초를 h/m/s로 사람이 읽기 좋게 바꾼다(사용자 요청: "경과시간은 h m s로
    표시하자 읽기힘들어") - 파이프라인이 수십 분씩 걸리면 "(경과 2140s)"보다
    "(경과 35m 40s)"가 훨씬 빨리 읽힌다. job_runner.py의 하트비트 메시지도
    이 함수를 공유해서 같은 형식으로 찍는다."""
    total = int(seconds)
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _bar(current: int, total: int, width: int = BAR_WIDTH) -> str:
    """텍스트 진행률 바. curses/rich 같은 외부 의존성 없이 plain print()로도
    전체 파이프라인이 몇 단계 중 몇 단계인지 한눈에 보이게(사용자 요청) -
    별도 라이브러리를 새로 끌어오지 않는 게 이 프로젝트의 기존 방향과 맞다."""
    if total <= 0:
        return ""
    filled = round(width * min(current, total) / total)
    return f"[{'■' * filled}{'░' * (width - filled)}] {current}/{total}"


def stage(name: str) -> None:
    """새 단계 시작을 알린다."""
    global _current_stage
    _current_stage += 1
    bar = _bar(_current_stage, _total_stages) if _total_stages else f"[{_current_stage}]"
    print(f"\n▶ {bar} {name}  (경과 {format_elapsed(_elapsed())})", flush=True)


def info(message: str) -> None:
    """현재 단계 안에서의 중간 진행 상황(예: 발견한 포트 개수, 후보 개수)."""
    print(f"    {message}", flush=True)


def checklist_start(items: list[str]) -> None:
    """현재 단계 안에서 병렬/순차로 처리할 항목 목록을 먼저 보여준다(예:
    취약점 후보 N개). 이후 각 항목이 끝날 때마다 checklist_item()으로 체크
    표시를 이어붙인다 - 사용자가 "정찰 후 잠재적 취약점 분석 종류를 보여주면서
    하나씩 완료됐다고 표시"를 원해서(요청 원문) 추가한 기능."""
    info(f"분석 대상 {len(items)}개:")
    for item in items:
        print(f"      - {item}", flush=True)


def checklist_item(index: int, total: int, label: str) -> None:
    """checklist_start()로 보여준 항목 하나가 끝났을 때 체크 표시로 찍는다."""
    print(f"      ✓ [{index}/{total}] {label}", flush=True)


def done(message: str = "완료") -> None:
    """현재 단계가 끝났음을 알린다(선택 사항 - 다음 stage() 호출로도 이전
    단계가 끝났다는 게 암시되지만, 명시적으로 남기고 싶을 때 사용)."""
    print(f"  ✓ {message}  (누적 {format_elapsed(_elapsed())})", flush=True)


def warn(message: str) -> None:
    """건너뛰거나 실패했지만 파이프라인 자체는 계속 진행하는 경우."""
    print(f"  ⚠ {message}", flush=True)


def _elapsed() -> float:
    return time.time() - _start_time if _start_time else 0.0
