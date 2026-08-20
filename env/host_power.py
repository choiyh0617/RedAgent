"""
호스트(Windows) 종료/절전/최대절전 전에 떠 있는 VM들을 안전하게 처리. DESIGN.md 20-3절.

배경: 오늘 세션이 길게 이어지면서 호스트가 절전/최대절전에 들어갔다가 돌아온
시점 즈음 kali VM이 하트비트 응답불능("aborted")이 된 걸 겪었다(11절). 호스트가
절전 상태로 들어가면 그 안에서 돌고 있던 VM 프로세스도 같이 멈추는데, 이게
길어지면 VirtualBox가 게스트를 "죽었다"고 오판하거나, 최악의 경우 VM 디스크가
비정상 종료된 것과 같은 상태로 남을 수 있다.

이 모듈은 사용자가 "호스트 끌게/재울게"라고 말해주면 호출하는 용도다 - Windows
자체의 절전/종료 이벤트를 자동으로 감지하는 건 아니다(OS 레벨 훅이 필요해서
범위 밖으로 뒀다, 필요하면 나중에 Task Scheduler의 "on power event" 트리거로
확장 가능).

VM을 완전히 끄는 대신(shutdown_vm) **일시정지(savestate)**를 쓴다:
  - 게스트 OS의 종료/재부팅 시퀀스를 아예 안 타서, 오래된 CTF 이미지들의 느리고
    불안정한 재부팅(오늘 하루 종일 겪음)을 호스트 절전할 때마다 다시 안 겪어도 됨
  - 진행 중이던 상태(예: 셸 세션)가 그대로 보존됨 - 다음에 켜면 그 지점부터 재개
"""

import json
import time
from pathlib import Path

from core import config  # noqa: F401 - import 시점에 stdout/stderr를 UTF-8로 고정
from env.guest_control import KALI_VM, force_clear_stale_lock, is_guest_ready, lock_status
from env.health_check import check_incomplete_jobs, run_diagnosis
from env.provision_target import VBOXMANAGE, _list_names, _run, is_running

HOLD_MARKER_PATH = Path(__file__).resolve().parent.parent / "state" / "_host_hold.json"


def suspend_vm(name: str) -> bool:
    """RAM+CPU 상태를 디스크에 저장하고 끈다(hibernate와 같은 개념). 이미 꺼져
    있으면 그냥 성공 처리."""
    if not is_running(name):
        print(f"[suspend] '{name}' 이미 꺼져있음")
        return True
    print(f"[suspend] {name}")
    try:
        _run("controlvm", name, "savestate")
        return True
    except RuntimeError as exc:
        print(f"[suspend 실패] {name}: {exc}")
        return False


def prepare_all_for_host_sleep() -> bool:
    """호스트를 종료/절전/최대절전으로 보내기 전에 호출. 떠 있는 VM을 전부
    안전하게 일시정지한다. 전부 성공하면 True."""
    running = sorted(_list_names("runningvms"))
    if not running:
        print("[prepare] 실행 중인 VM 없음 - 바로 종료/절전해도 안전합니다.")
        return True

    print(f"[prepare] {len(running)}개 VM 일시정지 시작: {running}")
    results = {name: suspend_vm(name) for name in running}

    still_running = sorted(_list_names("runningvms"))
    if still_running:
        print(f"[prepare] 경고: 아직 실행 중인 VM이 있음: {still_running} - 수동으로 확인하세요.")
        return False

    print("[prepare] 전부 안전하게 일시정지됨. 이제 호스트를 종료/절전해도 안전합니다.")
    return all(results.values())


def hold() -> bool:
    """호스트를 끄기 직전에 부른다. 단순히 VM을 재우는 것(prepare_all_for_host_sleep)에
    더해서, (1) 지금 뭔가 Kali와 통신 중인 건 아닌지 확인하고 (2) 그 시점의
    미완료 job 목록을 남겨서, 다음에 켰을 때 뭘 이어서 할지 판단할 수 있게 한다.
    DESIGN.md 20-6절 참고.

    guestcontrol 락이 걸려 있는데 stale이 아니면(=지금 실제로 뭔가 진행 중)
    그 상태로 VM을 재우는 건 위험하므로 진행하지 않고 False를 반환한다 -
    잠깐 기다렸다가 다시 호출하면 된다."""
    status = lock_status()
    if status.get("locked"):
        if status.get("stale"):
            force_clear_stale_lock()
            print("[hold] 방치된 세션 락 정리함")
        else:
            print(
                f"[hold] Kali와 통신 중인 작업이 있음(락 age={status.get('age_seconds')}s) - "
                "지금 재우면 위험하니 잠시 후 다시 시도하세요."
            )
            return False

    incomplete_jobs = check_incomplete_jobs()
    running_vms = sorted(_list_names("runningvms"))

    if not prepare_all_for_host_sleep():
        print("[hold] 일부 VM 일시정지 실패 - 수동 확인 필요, 홀드 마커는 남기지 않음")
        return False

    marker = {
        "held_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "vms": running_vms,
        "incomplete_jobs": incomplete_jobs,
    }
    HOLD_MARKER_PATH.parent.mkdir(parents=True, exist_ok=True)
    HOLD_MARKER_PATH.write_text(json.dumps(marker, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[hold] 완료 - {len(running_vms)}개 VM 일시정지, 미완료 job {len(incomplete_jobs)}개 기록함")
    print("[hold] 이제 호스트를 안전하게 종료/절전해도 됩니다. 다시 켠 뒤에는 env.host_power.resume()을 부르세요.")
    return True


def resume() -> None:
    """호스트를 다시 켠 뒤 부른다. hold()가 남긴 마커를 읽어서 VM들을 복원하고,
    health_check로 상태를 재검증한 뒤, 홀드 시점에 미완료였던 job을 사람이 볼 수
    있게 보여준다. 자동으로 job을 이어서 실행하진 않는다 - 얼마나 오래 홀드돼
    있었는지에 따라 이어서 하는 게 안 맞을 수도 있어서(job 성격에 따라 사람 판단)."""
    if not HOLD_MARKER_PATH.exists():
        print("[resume] 홀드 기록 없음 - 그냥 새로 시작하면 됩니다.")
        return

    marker = json.loads(HOLD_MARKER_PATH.read_text(encoding="utf-8"))
    print(f"[resume] {marker['held_at']}에 홀드된 기록 발견: VM {marker['vms']}")

    for name in marker["vms"]:
        print(f"[resume] {name} 복원 시도 (savestate였다면 자동으로 그 지점부터 재개)")
        try:
            _run("startvm", name, "--type", "headless")
        except RuntimeError as exc:
            # savestate 복원이 드물게 실패할 수 있음(예: VirtualBox 버전 변경) -
            # 이 경우 일반 콜드 부팅으로 폴백. startvm이 이미 실패했으니 그냥
            # 재시도해서 콜드부팅 경로를 태운다(VirtualBox가 손상된 savestate를
            # 감지하면 다음 startvm은 콜드부팅으로 처리함).
            print(f"[resume] {name} savestate 복원 실패, 콜드부팅으로 재시도: {exc}")
            try:
                _run("startvm", name, "--type", "headless")
            except RuntimeError as exc2:
                print(f"[resume] {name} 콜드부팅도 실패 - 수동 확인 필요: {exc2}")

    if KALI_VM in marker["vms"]:
        print("[resume] kali 게스트 애디션 응답 대기 중...")
        if not is_guest_ready(retries=24, delay=5):
            print("[resume] kali가 2분 넘게 응답 없음 - health_check.recover_locked_session() 등으로 수동 확인 필요")

    other_vms = [v for v in marker["vms"] if v != KALI_VM]
    report = run_diagnosis(vm_names=other_vms, auto_fix=True)
    if report.problems:
        print("[resume] 재검증 중 발견된 문제:")
        for p in report.problems:
            print(" -", p)
    else:
        print("[resume] 재검증 완료 - 문제 없음")

    if marker["incomplete_jobs"]:
        print(f"[resume] 홀드 당시 미완료였던 job {len(marker['incomplete_jobs'])}개 (이어서 할지는 판단 필요):")
        for job in marker["incomplete_jobs"]:
            print(f"  - {job['engagement_id']}/{job['job_id']}: {job.get('command')}")

    HOLD_MARKER_PATH.unlink()
    print("[resume] 홀드 마커 정리 완료")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "resume":
        resume()
    else:
        hold()
