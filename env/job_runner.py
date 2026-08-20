"""
장시간 걸리는 게스트 명령을 감시(watchdog)하며 실행. DESIGN.md 참고.

기존 run_in_kali()는 명령 하나가 끝날 때까지 블로킹하고, 타임아웃되면 그냥
죽인다 — "왜 느린지"는 전혀 모르고, "느리지만 정상 진행 중"과 "멈춰버림"을
구분 못 한다. 또 파이썬 프로세스/VM 연결이 끊겼다가 돌아오면 이전 작업이
어떻게 됐는지 알 방법이 없다.

해결 방식:
  1. guestcontrol start로 명령을 게스트에서 논블로킹 실행 (출력은 게스트 파일로
     리다이렉트, PID는 pidfile에 기록)
  2. 별도의 가벼운 폴링으로 "살아있나/끝났나/진행되고 있나"만 주기적으로 확인
  3. 진행률 신호(예: nmap --stats-every의 "X% done")가 있으면 그걸로 정체를 판단,
     없으면 그냥 살아있는지만 봄
  4. 정체된 것 같으면 대상 ping 등으로 원인을 진단 후 개입(kill) 여부 결정
  5. 모든 상태 전이를 findings.jsonl에 기록 -> 재시작/재연결 후 resume_job()으로
     이전 작업을 이어서 감시 가능 (별도 저장소 없이 findings.jsonl 재활용)
"""

import re
import shlex
import subprocess
import time
from dataclasses import dataclass

from core import progress
from core.state_store import append_finding, read_findings
from env.guest_control import KALI_PASS, KALI_USER, KALI_VM, VBOXMANAGE, close_all_sessions, kali_lock, run_in_kali
from env.interactive_recovery import ask_user_for_recovery, looks_interactive_worthy
from env.health_check import ensure_kali_running

JOB_DIR = "/tmp/pentest-agent-jobs"


@dataclass
class JobHandle:
    job_id: str
    command: str
    pid_path: str
    out_path: str
    started_at: float


@dataclass
class JobResult:
    finished: bool
    exit_code: int | None
    output: str
    killed: bool = False
    reason: str = ""


def start_job(engagement_id: str, job_id: str, command: str) -> JobHandle:
    """명령을 게스트에서 논블로킹으로 시작하고 findings.jsonl에 시작 이벤트를 남긴다.

    사전에 kali VM이 running 상태인지 확인한다 - 실제로 VM이 "aborted"(하트비트
    응답불능으로 죽음) 상태에서 이 함수를 불렀더니 "Machine is not running" 같은
    원인 불명확한 VBoxManage 에러로 바로 죽는 걸 겪었다. env/health_check.py로
    감지 + 필요시 자동 재기동한다."""
    if not ensure_kali_running(auto_restart=True):
        raise RuntimeError("kali VM이 응답하지 않고 재기동도 실패함 - env.health_check로 직접 확인 필요")

    pid_path = f"{JOB_DIR}/{job_id}.pid"
    out_path = f"{JOB_DIR}/{job_id}.out"

    setup = run_in_kali(f"mkdir -p {JOB_DIR}", timeout=20)
    if not setup.ok:
        raise RuntimeError(f"failed to prepare job dir: {setup.stderr}")

    # $$ 는 이 bash 프로세스 자신의 PID -> pidfile에 기록해두고 나중에 kill -0으로 생사 확인,
    # 죽일 때는 이 PID의 자식들(pkill -P)까지 같이 정리한다.
    #
    # stdbuf -oL -eL: 표준 출력이 터미널이 아니라 파일로 리다이렉트되면 대부분의
    # 프로그램이 라인 버퍼링 대신 블록 버퍼링(보통 4~8KB)으로 바뀐다 - nmap의
    # `--stats-every 10s` 진행률 줄이 실제로는 몇 분씩 스캔이 진행 중인데도 파일에
    # 안 써지고 있어서, wait_for_job()의 progress_regex 정체 감지가 처음부터 진짜
    # 진행 신호를 못 보고 있었다(실측: run_pipeline.py 첫 end-to-end 실전 검증 중
    # 발견 - job이 4분 넘게 도는데 원본 .out 파일엔 nmap 시작 배너 한 줄만 있었음,
    # DESIGN.md 43절). stdbuf로 강제 라인 버퍼링하면 이 문제가 해결된다.
    #
    # 회귀 버그(같은 43절 수정에서 바로 다음 실전 검증 중 발견, 45-1절): `stdbuf`는
    # 자기 뒤에 오는 첫 토큰을 "실행 파일"로만 취급한다 - `command`가
    # `cd /tmp/... && python3 x.py`처럼 셸 내장 명령(cd)이나 `&&`/`;` 같은 셸
    # 문법을 쓰면 `stdbuf -oL -eL cd ...`가 "cd"라는 실행파일을 PATH에서 찾다가
    # "No such file or directory"로 즉시 실패한다(cd는 내장 명령이라 실행파일이
    # 없음) - exploitation.py의 PoC 실행이 전부 이 에러로 조용히 실패했었다.
    # 고침: stdbuf로 nmap을 직접 감싸지 말고, `bash -c`를 감싼다 - `command`는
    # bash가 정상적으로 해석하고(cd/&&/파이프 다 그대로 동작), stdbuf가 설정하는
    # LD_PRELOAD는 환경변수라 bash가 실행하는 자식 프로세스(nmap 등)에도 그대로
    # 상속되므로 라인 버퍼링 효과는 동일하게 유지된다.
    wrapped = (
        f"echo $$ > {pid_path}; "
        f"(stdbuf -oL -eL /bin/bash -c {shlex.quote(command)}) > {out_path} 2>&1; "
        f"echo __JOB_EXIT__:$? >> {out_path}"
    )
    args = [
        VBOXMANAGE, "guestcontrol", KALI_VM, "start",
        "--username", KALI_USER, "--password", KALI_PASS,
        "--exe", "/bin/bash", "--", "-c", wrapped,
    ]
    with kali_lock():
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        if looks_interactive_worthy(proc.stdout, proc.stderr):
            decision = ask_user_for_recovery(command, proc.stdout, proc.stderr)
            if decision.skip:
                run_in_kali(
                    f"mkdir -p {JOB_DIR} && cat > {out_path} << 'EOF'\n[interactive-skip]\n__JOB_EXIT__:0\nEOF",
                    timeout=20,
                    _allow_interactive_recovery=False,
                )
                append_finding(
                    engagement_id, stage="job_runner", event="job_skipped_interactively",
                    job_id=job_id, command=command,
                )
                return JobHandle(job_id=job_id, command=command, pid_path=pid_path, out_path=out_path, started_at=time.time())
            if decision.retry_command:
                return start_job(engagement_id, job_id, decision.retry_command)
            if decision.confirmed_output is not None:
                run_in_kali(
                    f"mkdir -p {JOB_DIR} && cat > {out_path} << 'EOF'\n{decision.confirmed_output}\n__JOB_EXIT__:0\nEOF",
                    timeout=20,
                    _allow_interactive_recovery=False,
                )
                return JobHandle(job_id=job_id, command=command, pid_path=pid_path, out_path=out_path, started_at=time.time())
        raise RuntimeError(f"failed to start job: {proc.stderr}")

    handle = JobHandle(job_id=job_id, command=command, pid_path=pid_path, out_path=out_path, started_at=time.time())
    append_finding(
        engagement_id, stage="job_runner", event="job_started",
        job_id=job_id, command=command, pid_path=pid_path, out_path=out_path, started_at=handle.started_at,
    )
    return handle


def _poll_raw(handle: JobHandle) -> tuple[bool, str] | None:
    """(guest_reachable, alive, output) 조회. 연결 자체가 안 되면 None."""
    check = run_in_kali(
        f"test -f {handle.pid_path} && PID=$(cat {handle.pid_path}) && "
        f"(kill -0 $PID 2>/dev/null && echo ALIVE || echo DEAD) || echo DEAD; "
        f"echo __SEP__; cat {handle.out_path} 2>/dev/null",
        timeout=20,
    )
    if check.exit_code == -1:  # run_in_kali 자체가 타임아웃 -> 연결 문제
        return None
    marker, _, output = check.stdout.partition("__SEP__")
    return ("ALIVE" in marker, output)


def _diagnose(handle: JobHandle) -> dict:
    """정체된 것 같을 때 원인 후보를 모은다."""
    m = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", handle.command)
    target = m.group(0) if m else None
    ping_ok = False
    if target:
        ping = run_in_kali(f"ping -c1 -W2 {target}", timeout=15)
        ping_ok = ping.ok
    return {"target": target, "target_reachable": ping_ok}


def kill_job(handle: JobHandle) -> None:
    run_in_kali(f"PID=$(cat {handle.pid_path} 2>/dev/null); pkill -9 -P $PID 2>/dev/null; kill -9 $PID 2>/dev/null", timeout=20)


def wait_for_job(
    engagement_id: str,
    handle: JobHandle,
    progress_regex: str | None = None,
    poll_interval: int = 15,
    unreachable_poll_interval: int = 30,
    stall_polls_before_diagnose: int = 4,
    hard_timeout: int = 3600,
) -> JobResult:
    """`_wait_for_job_inner()`를 감싸서, job이 어떻게 끝나든(성공/실패/타임아웃)
    항상 마지막에 guestcontrol 세션을 정리한다.

    실전에서 잡은 버그(Kioptrix1 반복 검증 중 발견, DESIGN.md 56절): `start_job()`
    이 쓰는 `guestcontrol ... start`(비동기)는 `run_in_kali()`가 쓰는
    `guestcontrol ... run`(동기, 정상 종료 시 세션 자동 정리)과 달리 **한 번도
    명시적으로 세션을 안 닫았다** - job 하나 실행할 때마다 세션이 하나씩
    orphan으로 남아 누적됐다(실측: 하루 세션 동안 9개까지 쌓여서 VirtualBox
    동시 세션 제한에 걸리고, 그 이후 모든 guestcontrol 호출이 원인 불명의
    "Error starting guest session"/VERR_DUPLICATE로 실패함). job마다 끝나는
    시점에 정리하면 애초에 쌓일 일이 없다 - 파이프라인 시작 시점에 한 번
    치우는 51/56절 수정은 이미 쌓인 걸 청소하는 대증 요법이었을 뿐, 이게
    쌓이는 것 자체를 막는 근본 수정이다."""
    try:
        return _wait_for_job_inner(
            engagement_id, handle, progress_regex, poll_interval,
            unreachable_poll_interval, stall_polls_before_diagnose, hard_timeout,
        )
    finally:
        close_all_sessions()


def _wait_for_job_inner(
    engagement_id: str,
    handle: JobHandle,
    progress_regex: str | None,
    poll_interval: int,
    unreachable_poll_interval: int,
    stall_polls_before_diagnose: int,
    hard_timeout: int,
) -> JobResult:
    """폴링하며 진행 상황을 findings에 기록하고, 멈춘 것 같으면 진단 후 필요시 kill한다.

    폴링마다 콘솔에도 짧은 하트비트를 찍는다(core.progress) - nmap/msfconsole -x/
    sqlmap처럼 몇 분씩 걸리는 job이 전부 이 함수 하나를 거쳐가는데, 예전엔
    findings.jsonl에만 기록되고 콘솔은 그동안 완전히 조용해서 CLI로 직접 돌리는
    사용자 입장에선 "멈춘 건지 도는 중인지" 알 방법이 없었다(사용자 지적) -
    Claude Code 세션에서 곁에서 설명해주는 것과 실제 터미널 화면이 달랐던 지점.
    호출자마다 따로 손댈 필요 없이 이 한 곳만 고치면 전부 해결됨."""
    last_progress = None
    stall_count = 0

    while True:
        elapsed = time.time() - handle.started_at
        polled = _poll_raw(handle)

        if polled is None:
            append_finding(engagement_id, stage="job_runner", event="guest_unreachable",
                            job_id=handle.job_id, elapsed=round(elapsed))
            progress.warn(f"{handle.job_id}: Kali 응답 없음 - 재시도 중 (경과 {progress.format_elapsed(elapsed)})")
            time.sleep(unreachable_poll_interval)
            continue

        alive, output = polled

        if "__JOB_EXIT__:" in output:
            m = re.search(r"__JOB_EXIT__:(\d+)", output)
            exit_code = int(m.group(1)) if m else None
            append_finding(engagement_id, stage="job_runner", event="job_finished",
                            job_id=handle.job_id, elapsed=round(elapsed), exit_code=exit_code)
            return JobResult(finished=True, exit_code=exit_code, output=output.split("__JOB_EXIT__:")[0])

        if not alive:
            # pidfile은 있는데 프로세스가 없고, 종료 마커도 없음 -> 예기치 않게 죽음
            append_finding(engagement_id, stage="job_runner", event="job_died_unexpectedly",
                            job_id=handle.job_id, elapsed=round(elapsed), tail=output[-500:])
            return JobResult(finished=False, exit_code=None, output=output, reason="died_unexpectedly")

        if elapsed > hard_timeout:
            append_finding(engagement_id, stage="job_runner", event="job_hard_timeout",
                            job_id=handle.job_id, elapsed=round(elapsed))
            kill_job(handle)
            return JobResult(finished=False, exit_code=None, output=output, killed=True, reason="hard_timeout")

        if progress_regex:
            matches = re.findall(progress_regex, output)
            current_progress = matches[-1] if matches else None
            if current_progress == last_progress:
                stall_count += 1
            else:
                stall_count = 0
                last_progress = current_progress
                append_finding(engagement_id, stage="job_runner", event="job_progress",
                                job_id=handle.job_id, elapsed=round(elapsed), progress=current_progress)
                progress.info(f"{handle.job_id}: {current_progress}% 진행 (경과 {progress.format_elapsed(elapsed)})")

            if stall_count >= stall_polls_before_diagnose:
                diag = _diagnose(handle)
                append_finding(engagement_id, stage="job_runner", event="job_stalled",
                                job_id=handle.job_id, elapsed=round(elapsed), progress=current_progress, **diag)
                progress.warn(f"{handle.job_id}: 진행률 정체 감지, 원인 진단 중 (경과 {progress.format_elapsed(elapsed)})")
                if not diag["target_reachable"]:
                    kill_job(handle)
                    return JobResult(finished=False, exit_code=None, output=output,
                                      killed=True, reason="target_unreachable")
                stall_count = 0  # 진단 남겼으니 반복 알림은 하지 않고 계속 지켜봄
        else:
            # 진행률 신호가 없는 job(msfconsole -x, sqlmap 등)도 "살아있음"만이라도
            # 매 폴링마다 찍어줘야 침묵 구간이 안 생긴다.
            progress.info(f"{handle.job_id}: 실행 중... (경과 {progress.format_elapsed(elapsed)})")

        time.sleep(poll_interval)


def resume_job(engagement_id: str, job_id: str) -> JobHandle | None:
    """스크립트 재시작/재연결 후, 아직 끝나지 않은 job을 findings.jsonl에서 찾아 이어서 감시."""
    events = [f for f in read_findings(engagement_id) if f.get("job_id") == job_id]
    if not events:
        return None
    started = next((e for e in events if e["event"] == "job_started"), None)
    if not started:
        return None
    terminal = {"job_finished", "job_hard_timeout", "target_unreachable", "job_died_unexpectedly"}
    if any(e["event"] in terminal for e in events):
        return None  # 이미 끝난 job
    return JobHandle(
        job_id=job_id, command=started["command"], pid_path=started["pid_path"],
        out_path=started["out_path"], started_at=started["started_at"],
    )
