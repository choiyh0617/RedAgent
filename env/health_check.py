"""
전반적인 환경 상태 진단/트러블슈팅 도구. DESIGN.md 20절.

이번 세션에서 실제로 반복해서 겪은 불안정성 패턴들을 한 번에 점검한다:
  - Kali VM이 응답불능으로 죽어서 "aborted" 상태가 됨 (하트비트 flatline 후
    로그가 그냥 끊김 - 리소스 부족으로 추정, 메모리 1.9GB로 빠듯함)
  - guestcontrol 세션이 orphan으로 남아서 이후 호출이 원인불명 에러를 냄
  - VirtualBox 가상 네트워크가 순간적으로 패킷을 손실해서 "0 hosts up"/전부
    filtered로 잘못 나옴
  - 미완료 job(job_started는 있는데 종료 이벤트가 없음)이 남아있을 수 있음

job_runner.py의 watchdog은 "지금 이 명령 하나"를 감시하는 거고, 이건 "지금
환경 전체가 어떤 상태인지"를 한 번에 훑어보는 별도 진단 도구다. 뭔가 이상할 때
`python -m env.health_check <target_ip...>`로 바로 원인을 좁힐 수 있게 하는 게
목적. auto_fix=True(기본값)면 발견한 문제 중 안전하게 자동으로 고칠 수 있는 것
(VM 재기동, orphan 세션 정리)은 바로 고친다.
"""

import re
import subprocess
import time
from dataclasses import dataclass, field

from core import config  # noqa: F401 - import 시점에 stdout/stderr를 UTF-8로 고정
from core.engagement import list_engagements
from core.state_store import read_findings
from env.guest_control import (
    KALI_VM,
    VBOXMANAGE,
    close_all_sessions,
    force_clear_stale_lock,
    is_guest_ready,
    kali_lock,
    lock_status,
    run_in_kali,
)

LOW_MEMORY_THRESHOLD_MB = 300
HIGH_DISK_USAGE_PCT = 80
JOB_FILE_CLEANUP_AGE_MIN = 60  # 이보다 오래된 job 파일만 정리 - 진행 중인 job은 mtime이 최신이라 안 건드려짐


@dataclass
class HealthReport:
    vm_states: dict[str, str] = field(default_factory=dict)
    guest_responsive: bool | None = None
    orphaned_sessions: int = 0
    kali_available_mb: float | None = None
    kali_load: str | None = None
    kali_disk_used_pct: float | None = None
    target_reachability: dict[str, bool] = field(default_factory=dict)
    incomplete_jobs: list[dict] = field(default_factory=list)
    kali_lock: dict = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


VBM_TIMEOUT = 15


class VBoxTimeoutError(RuntimeError):
    pass


def _vbm(*args: str, timeout: int = VBM_TIMEOUT) -> str:
    """VBoxManage 호출에 타임아웃을 건다. 세션이 stuck 상태면 showvminfo 같은
    명령이 응답 없이 무한정 멈출 수 있는 걸 실제로 겪었음(호스트에서 강제
    종료한 프로세스가 VirtualBox 세션 락을 stuck 상태로 남김) - 그냥 기다리는
    대신 타임아웃을 걸어서 "멈춰버림" 자체를 하나의 진단 신호로 쓴다."""
    try:
        proc = subprocess.run(
            [VBOXMANAGE, *args], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        return proc.stdout
    except subprocess.TimeoutExpired:
        raise VBoxTimeoutError(f"VBoxManage {' '.join(args)} timed out after {timeout}s (세션 락 stuck 의심)")


def check_vm_states(vm_names: list[str]) -> dict[str, str]:
    states = {}
    for name in vm_names:
        try:
            out = _vbm("showvminfo", name, "--machinereadable")
        except VBoxTimeoutError:
            states[name] = "locked/unresponsive"
            continue
        m = re.search(r'VMState="([^"]+)"', out)
        states[name] = m.group(1) if m else "unknown/not-registered"
    return states


def recover_locked_session(name: str) -> bool:
    """showvminfo가 멈출 정도로 세션이 stuck된 VM을 복구한다.

    1단계(가벼움, 정상 종료 우선): ACPI 전원 버튼으로 정상 종료 시도(짧은
    타임아웃) -> 안 꺼지면 강제 종료 -> startvm 재시도. 강제 종료(poweroff)를
    반복하면 게스트 파일시스템이 손상될 수 있다는 걸 실제로 겪어서(오래된 CTF
    이미지가 로그인은 되는데 서비스가 하나도 안 뜨는 상태가 됨), 세션이 stuck된
    상황에서도 일단 정상 종료를 먼저 시도한다 - 다만 이 상황 자체가 이미
    VirtualBox API가 응답 안 하는 상태라 ACPI 신호도 안 먹힐 수 있어서 대기
    시간은 짧게 둔다.

    그래도 안 되면: VBoxSVC(호스트의 모든 VM 세션을 관리하는 백그라운드 서비스)
    자체를 재시작해야 하는데, 이건 이 VM만이 아니라 **호스트에 떠 있는 다른 모든
    VM의 세션 추적에도 영향을 준다** (실제로 겪음: kali 하나 고치려다 Kioptrix2도
    세션이 끊기면서 프로세스는 떠 있는데 VBoxManage가 모르는 상태(zombie)가 됨,
    결국 둘 다 강제 종료 후 재기동해야 했음). 그래서 이 함수는 여기까지만
    자동으로 하고, 그걸로 안 풀리면 자동으로 escalate하지 않고 사람이 판단하도록
    안내만 한다."""
    print(f"[health_check] '{name}' 세션이 멈춘 것으로 보임 -> 정상 종료(ACPI) 시도")
    try:
        subprocess.run(
            [VBOXMANAGE, "controlvm", name, "acpipowerbutton"], timeout=10,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        time.sleep(15)  # 정상 종료는 즉시 안 꺼지므로 잠깐 기다려봄
    except subprocess.TimeoutExpired:
        pass

    still_stuck = True
    try:
        check_vm_states([name])
        still_stuck = False
    except VBoxTimeoutError:
        pass

    if still_stuck:
        print(f"[health_check] 정상 종료 응답 없음 -> 강제 종료(마지막 수단)")
        try:
            subprocess.run(
                [VBOXMANAGE, "controlvm", name, "poweroff"], timeout=20,
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
        except subprocess.TimeoutExpired:
            pass

    try:
        _vbm("startvm", name, "--type", "headless", timeout=15)
        return True
    except VBoxTimeoutError:
        pass

    print(
        f"[health_check] poweroff으로도 안 풀림 -> VBoxSVC 재시작이 필요할 수 있음. "
        "이건 호스트의 다른 모든 VM 세션에도 영향을 주니 자동으로 안 함 - 수동으로: "
        "1) VBoxSVC.exe 프로세스 종료, 2) 좀비로 남은 VBoxHeadless.exe들 확인 후 종료, "
        "3) 영향받은 VM들 전부 재기동 (DESIGN.md 20-1절 참고)"
    )
    return False


def _restart_kali() -> bool:
    """kali를 정상종료 우선으로 재기동한다. 이미 꺼져 있으면 shutdown_vm이
    바로 스킵하므로, "꺼져 있어서 그냥 켜야 하는 경우"와 "떠 있는데 게스트가
    응답 없어서 재기동해야 하는 경우" 둘 다 같은 경로로 처리한다."""
    from env.provision_target import shutdown_vm  # 지연 import - 순환 참조 방지

    print("[health_check] kali 정상종료 후 재기동...")
    shutdown_vm(KALI_VM, graceful_timeout=30)
    try:
        _vbm("startvm", KALI_VM, "--type", "headless")
    except VBoxTimeoutError:
        print("[health_check] kali startvm 응답 없음")
        return False
    return is_guest_ready(retries=24, delay=5)


def ensure_kali_running(auto_restart: bool = True) -> bool:
    """Kali가 running이 아니면(aborted/poweroff/세션 stuck 등) 감지, auto_restart면
    재기동까지 (stuck 세션은 poweroff까지만 자동, 그 이상은 recover_locked_session
    참고).

    VM 상태가 "running"이어도 게스트(Guest Additions)가 응답 없을 수 있다는 걸
    실제로 겪었음(showvminfo는 정상 응답하는데 guestcontrol이 계속 타임아웃) -
    상태만 보고 넘어가지 않고 실제 연결성까지 확인한다."""
    state = check_vm_states([KALI_VM])[KALI_VM]

    if state == "running":
        if check_guest_responsive():
            return True
        print("[health_check] kali는 running 상태지만 게스트가 응답 없음 -> 재연결 시도")
        if not auto_restart:
            return False
        return _restart_kali()

    print(f"[health_check] kali VM 상태: {state} (running 아님)")
    if not auto_restart:
        return False

    if state == "locked/unresponsive":
        if not recover_locked_session(KALI_VM):
            return False
        return is_guest_ready(retries=24, delay=5)

    return _restart_kali()


def check_guest_responsive() -> bool:
    return run_in_kali("true", timeout=15).ok


def check_orphaned_sessions() -> int:
    with kali_lock():
        out = _vbm("guestcontrol", KALI_VM, "list", "sessions")
    if "No active guest sessions" in out:
        return 0
    return len(re.findall(r"Session #\d+", out))


def check_kali_lock() -> dict:
    """guest_control.py의 크로스프로세스 락이 지금 걸려 있는지, 걸려 있다면
    얼마나 오래됐는지 확인한다. age_seconds가 크면(수십 초 이상) 어딘가에서
    guestcontrol 호출이 멈춰 있다는 신호 - 세션 락 사고의 조기 경보."""
    return lock_status()


def check_kali_disk() -> tuple[float | None, float | None]:
    """/tmp(tmpfs) 사용률을 확인한다. job_runner.py의 JOB_DIR(/tmp/pentest-agent-jobs)이
    여기 산다 - tmpfs는 RAM 기반이라 보통 1GB 미만으로 작은데, job마다 쌓이는
    .out/.pid 파일이 계속 누적되면 언젠가 꽉 찬다.

    실제로 겪은 사고: 폐기된 pwncat-cs 조사에서 남은 리스너 출력 파일 2개(각
    ~490MB)가 tmpfs 985M를 거의 다 채워서, 그 이후의 모든 job이 pidfile조차
    못 쓰고 "died_unexpectedly"로 조용히 죽었다 - job_runner.py에 콘솔
    하트비트를 추가하고 검증하다가 발견함(job 상태만 보면 절대 못 잡는
    원인이라, VM 상태/메모리와 나란히 디스크도 정기적으로 봐야 함 -
    DESIGN.md 43절)."""
    result = run_in_kali("df -m /tmp | tail -1", timeout=15)
    if not result.ok:
        return None, None
    parts = result.stdout.split()
    # df -m 출력: Filesystem Size Used Avail Use% Mounted
    if len(parts) < 5:
        return None, None
    try:
        used_pct = float(parts[4].rstrip("%"))
        avail_mb = float(parts[3])
    except ValueError:
        return None, None
    return used_pct, avail_mb


def cleanup_old_job_files(older_than_min: int = JOB_FILE_CLEANUP_AGE_MIN) -> None:
    """JOB_DIR에서 오래된 .out/.pid 파일을 지운다. 진행 중인 job은 계속 파일에
    쓰는 중이라 mtime이 최신이라서 안 지워짐. job의 실제 결과물(linpeas 출력,
    발견한 flag 등)은 이미 호스트 쪽 state/<engagement_id>/에 별도로 저장돼
    있으므로, 게스트 쪽 스크래치 파일을 지워도 findings는 유실되지 않는다."""
    from env.job_runner import JOB_DIR  # 지연 import - job_runner가 이 모듈을 임포트하므로 순환 참조 방지

    run_in_kali(f"find {JOB_DIR} -type f -mmin +{older_than_min} -delete", timeout=30)


def check_kali_resources() -> tuple[float | None, str | None]:
    result = run_in_kali("free -m | awk '/Mem:/{print $7}'; uptime", timeout=15)
    if not result.ok:
        return None, None
    lines = result.stdout.strip().splitlines()
    available_mb = float(lines[0]) if lines and lines[0].strip().isdigit() else None
    load = lines[1].strip() if len(lines) > 1 else None
    return available_mb, load


def check_target_reachability(targets: list[str], retries: int = 3, delay: int = 5) -> dict[str, bool]:
    """VirtualBox 호스트온리 네트워크가 순간적으로 패킷을 손실해서 ping이 한
    번 실패하는 걸 실제로 겪었다(scanning.py의 "0 hosts up" 거짓음성과 같은
    원인). 한 번 실패했다고 바로 "연결 끊김"으로 단정하지 않고 몇 번 재시도한
    뒤에도 계속 실패해야 진짜 문제로 본다."""
    results: dict[str, bool] = {}
    for t in targets:
        ok = False
        for attempt in range(1, retries + 1):
            ok = run_in_kali(f"ping -c1 -W2 {t}", timeout=15).ok
            if ok:
                break
            if attempt < retries:
                time.sleep(delay)
        results[t] = ok
    return results


def check_incomplete_jobs() -> list[dict]:
    """모든 인게이지먼트를 훑어서 job_started는 있는데 종료 이벤트가 없는 job을 찾는다.
    job_runner.resume_job()으로 이어서 감시할 수 있는 후보 목록."""
    terminal_events = {"job_finished", "job_hard_timeout", "job_died_unexpectedly"}
    incomplete = []
    for eid in list_engagements():
        jobs: dict[str, dict] = {}
        for f in read_findings(eid):
            job_id = f.get("job_id")
            if not job_id or f["stage"] != "job_runner":
                continue
            if f["event"] == "job_started":
                jobs[job_id] = {"engagement_id": eid, "job_id": job_id, "command": f.get("command"), "terminal": False}
            elif f["event"] in terminal_events and job_id in jobs:
                jobs[job_id]["terminal"] = True
        incomplete.extend(j for j in jobs.values() if not j["terminal"])
    return incomplete


def run_diagnosis(
    vm_names: list[str] | None = None, targets: list[str] | None = None, auto_fix: bool = True,
) -> HealthReport:
    """전체 진단을 한 번에 실행하고 문제 목록을 report.problems에 남긴다."""
    report = HealthReport()
    vm_names = [KALI_VM, *(vm_names or [])]

    report.kali_lock = check_kali_lock()
    if report.kali_lock.get("locked"):
        age = report.kali_lock.get("age_seconds")
        if report.kali_lock.get("stale"):
            report.problems.append(f"Kali 세션 락이 {age}s째 방치됨 (죽은 프로세스로 추정)")
            if auto_fix and force_clear_stale_lock():
                print(f"[health_check] 방치된 세션 락 정리함 (age={age}s)")
        elif age is not None and age > 30:
            # 30s 미만은 정상적인 guestcontrol 호출 진행 중일 뿐이라 문제로 안 침
            report.problems.append(f"Kali 세션 락이 {age}s째 사용 중 (다른 작업이 오래 진행 중일 수 있음)")

    report.vm_states = check_vm_states(vm_names)
    for name, state in report.vm_states.items():
        if state != "running":
            report.problems.append(f"VM '{name}'이 running 상태가 아님 ({state})")

    if report.vm_states.get(KALI_VM) != "running":
        if not auto_fix:
            return report  # kali가 안 켜져 있으면 나머지 체크는 의미 없음
        fixed = ensure_kali_running(auto_restart=True)
        if not fixed:
            report.problems.append("kali 재기동 실패 - 수동 확인 필요")
            return report
        report.vm_states[KALI_VM] = "running"

    report.guest_responsive = check_guest_responsive()
    if not report.guest_responsive:
        report.problems.append("kali guestcontrol이 응답하지 않음 (Guest Additions 문제일 수 있음)")
        if not auto_fix:
            return report
        print("[health_check] 게스트 연결성 끊김 감지 -> 서비스 확인 및 재연결 시도")
        if _restart_kali():
            report.guest_responsive = True
            report.vm_states[KALI_VM] = "running"
            print("[health_check] 재기동으로 게스트 연결성 복구됨")
        else:
            report.problems.append("kali 재기동으로도 게스트 연결성 복구 실패 - 수동 확인 필요")
            return report  # 이후 체크도 guestcontrol을 쓰므로 여기서 중단

    report.orphaned_sessions = check_orphaned_sessions()
    if report.orphaned_sessions > 0:
        report.problems.append(f"orphan guestcontrol 세션 {report.orphaned_sessions}개 발견")
        if auto_fix:
            close_all_sessions()
            print(f"[health_check] {report.orphaned_sessions}개 세션 정리함")

    report.kali_available_mb, report.kali_load = check_kali_resources()
    if report.kali_available_mb is not None and report.kali_available_mb < LOW_MEMORY_THRESHOLD_MB:
        report.problems.append(
            f"kali 가용 메모리 부족 ({report.kali_available_mb:.0f}MB < {LOW_MEMORY_THRESHOLD_MB}MB) - VM 크래시 위험"
        )

    disk_used_pct, disk_avail_mb = check_kali_disk()
    report.kali_disk_used_pct = disk_used_pct
    if disk_used_pct is not None and disk_used_pct >= HIGH_DISK_USAGE_PCT:
        report.problems.append(
            f"kali /tmp 사용률 {disk_used_pct:.0f}% (여유 {disk_avail_mb:.0f}MB) - job이 파일을 못 써서 조용히 죽을 위험"
        )
        if auto_fix:
            print(f"[health_check] /tmp 사용률 {disk_used_pct:.0f}% -> 오래된 job 파일 정리 시도")
            cleanup_old_job_files()
            disk_used_pct, disk_avail_mb = check_kali_disk()
            report.kali_disk_used_pct = disk_used_pct
            print(f"[health_check] 정리 후 /tmp 사용률 {disk_used_pct:.0f}% (여유 {disk_avail_mb:.0f}MB)")

    if targets:
        report.target_reachability = check_target_reachability(targets)
        for t, ok in report.target_reachability.items():
            if not ok:
                report.problems.append(f"대상 {t}에 ping 실패 (일시적일 수 있음, 재시도 권장)")

    report.incomplete_jobs = check_incomplete_jobs()
    for job in report.incomplete_jobs:
        report.problems.append(
            f"미완료 job 발견: {job['engagement_id']}/{job['job_id']} - resume_job()으로 이어서 확인 필요"
        )

    return report


def _print_report(report: HealthReport) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n=== 진단 결과 ({ts}) ===")
    print("VM 상태:", report.vm_states)
    print("guestcontrol 응답:", report.guest_responsive)
    print("orphan 세션:", report.orphaned_sessions)
    print("세션 락 상태:", report.kali_lock)
    print(f"kali 가용 메모리: {report.kali_available_mb}MB, load: {report.kali_load}")
    print(f"kali /tmp 사용률: {report.kali_disk_used_pct}%")
    if report.target_reachability:
        print("대상 도달성:", report.target_reachability)
    if report.incomplete_jobs:
        print("미완료 job:", len(report.incomplete_jobs), "개")

    if report.problems:
        print("문제 발견:")
        for p in report.problems:
            print(" -", p)
    else:
        print("문제 없음")


def watch(
    vm_names: list[str] | None = None,
    targets: list[str] | None = None,
    interval_seconds: int = 60,
    auto_fix: bool = True,
) -> None:
    """세션 락/VM 상태를 주기적으로 계속 확인한다. 반복 실행 중인 작업(예: 백그라운드
    파이프라인)과는 별도 프로세스로 띄워서 감시하는 용도 - Ctrl+C로 중단.

    주의: 이 자체도 guestcontrol을 호출하므로(run_in_kali 등) 같은 크로스프로세스
    락을 타고 순서대로 실행된다. 너무 짧은 interval은 다른 작업의 락 대기 시간을
    늘리기만 하므로 기본값은 60s로 여유 있게 잡았다."""
    print(f"[health_check] watch 모드 시작 (interval={interval_seconds}s, Ctrl+C로 중단)")
    try:
        while True:
            report = run_diagnosis(vm_names=vm_names, targets=targets, auto_fix=auto_fix)
            _print_report(report)
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\n[health_check] watch 모드 종료")


if __name__ == "__main__":
    import sys

    args = sys.argv[1:]
    if args and args[0] == "--watch":
        interval = int(args[1]) if len(args) > 1 and args[1].isdigit() else 60
        remaining_targets = [a for a in args[1:] if not a.isdigit()]
        watch(targets=remaining_targets, interval_seconds=interval)
    else:
        _print_report(run_diagnosis(targets=args))
