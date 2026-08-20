"""
VBoxManage guestcontrol 래퍼.

호스트에서 Kali 게스트 내부로 네트워크 없이(하이퍼바이저 채널로) 명령을 실행한다.
Guest Additions가 설치되어 있어야 하며, Kali 공식 VirtualBox 이미지는 기본 포함.

주의: `run --exe <path> -- <args...>` 에서 <args...> 의 첫 값은 argv[0]으로 쓰이므로
프로그램 이름을 다시 넣으면 인자가 중복된다.
  올바른 예: --exe /bin/bash -- -c "echo hi"
  잘못된 예: --exe /bin/bash -- bash -c "echo hi"   (bash가 두 번 들어가 깨짐)
"""

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from core.host_platform import get_vboxmanage_path, is_mac_host
from core.host_platform import get_vboxmanage_path
from env.kali_ssh import run_noninteractive_command
from env.interactive_recovery import ask_user_for_recovery, looks_interactive_worthy

VBOXMANAGE = get_vboxmanage_path()

KALI_VM = "kali"
KALI_USER = "kali"
KALI_PASS = "kali"

# 여러 파이썬 프로세스(백그라운드로 동시에 띄운 것들)가 동시에 Kali를 두드려서
# guestcontrol 세션이 쌓이다 못해 VirtualBox 자체가 "세션 락" 상태로 멈추는
# 문제를 반복해서 겪었다(DESIGN.md 20-1절). 그래서 프로세스 경계를 넘는 파일
# 기반 락으로 **한 번에 하나의 guestcontrol 호출만** 나가도록 강제한다.
# 트레이드오프: scanning.py의 서비스별 서브모듈 병렬 실행(5개 동시)도 이 락 때문에
# 사실상 순차 실행이 된다 - 속도보다 안정성을 우선한다는 사용자 방침에 따른 결정.
_LOCK_PATH = Path(__file__).resolve().parent.parent / "state" / "_kali_session.lock"
_LOCK_STALE_SECONDS = 180  # 이보다 오래된 락은 죽은 프로세스가 남긴 것으로 보고 정리
_LOCK_WAIT_TIMEOUT = 90    # 락을 못 얻고 이 시간 넘게 기다리면 포기


class KaliLockTimeout(RuntimeError):
    pass


class _KaliSessionLock:
    """`with _KaliSessionLock():` 로 감싼 구간만 Kali와 통신한다."""

    def __enter__(self):
        _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + _LOCK_WAIT_TIMEOUT
        while True:
            try:
                fd = os.open(_LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, f"{os.getpid()},{time.time()}".encode())
                os.close(fd)
                return self
            except FileExistsError:
                if self._is_stale():
                    self._break()
                    continue
                if time.time() > deadline:
                    raise KaliLockTimeout(
                        f"Kali 세션 락을 {_LOCK_WAIT_TIMEOUT}s 넘게 못 얻음 - 다른 프로세스가 계속 점유 중이거나 stuck"
                    )
                time.sleep(0.5)

    def __exit__(self, *_exc):
        self._break()

    @staticmethod
    def _is_stale() -> bool:
        try:
            _, ts = _LOCK_PATH.read_text().split(",")
            return time.time() - float(ts) > _LOCK_STALE_SECONDS
        except (OSError, ValueError):
            return True  # 못 읽으면 죽은 락으로 취급

    @staticmethod
    def _break() -> None:
        try:
            _LOCK_PATH.unlink()
        except FileNotFoundError:
            pass


def kali_lock() -> _KaliSessionLock:
    """다른 모듈(health_check.py 등)이 VBoxManage로 Kali에 직접 guestcontrol
    명령을 날릴 때도 같은 락을 쓰도록 공개하는 진입점."""
    return _KaliSessionLock()


def lock_status() -> dict:
    """지금 락이 걸려 있는지, 걸려 있다면 누가(PID) 얼마나 오래 들고 있는지
    조회한다 - 세션 락 상태를 계속 확인하고 싶을 때 사용 (health_check.py의
    watch 모드에서 사용)."""
    if not _LOCK_PATH.exists():
        return {"locked": False}
    try:
        pid_str, ts_str = _LOCK_PATH.read_text().split(",")
        age = time.time() - float(ts_str)
        return {
            "locked": True,
            "pid": int(pid_str),
            "age_seconds": round(age, 1),
            "stale": age > _LOCK_STALE_SECONDS,
        }
    except (OSError, ValueError):
        return {"locked": True, "pid": None, "age_seconds": None, "stale": True}


def force_clear_stale_lock() -> bool:
    """락이 실제로 stale(오래 방치됨)일 때만 지워준다. health_check.py의
    watch 모드가 주기적으로 호출해서, 죽은 프로세스가 남긴 락을 다음 사용자가
    올 때까지 기다리지 않고 미리 치워둔다. 살아있는 정상 락은 건드리지 않는다."""
    status = lock_status()
    if status.get("locked") and status.get("stale"):
        _KaliSessionLock._break()
        return True
    return False


@dataclass
class GuestResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def run_in_kali(command: str, timeout: int = 120, _allow_interactive_recovery: bool = True) -> GuestResult:
    """Kali 안에서 bash -c 로 명령 한 줄을 실행하고 결과를 회수한다.

    타임아웃되면 subprocess.run이 호스트 쪽 VBoxManage.exe만 죽이고, 게스트 쪽
    프로세스/세션은 살아남는다 (하이퍼바이저 채널 특성상 호스트 프로세스를 죽여도
    게스트에 SIGTERM이 전파되지 않음 — 실제로 겪은 문제: nmap/whatweb를 강제
    종료했더니 세션이 "started" 상태로 남아서 이후 guestcontrol 호출이 원인 불명의
    에러를 내기 시작함). 그래서 타임아웃 시 세션을 명시적으로 정리한다.

    `_KaliSessionLock`으로 감싸서 다른 프로세스가 동시에 guestcontrol을 못 쏘게
    막는다 - 이게 반복된 세션 락 사고의 실제 원인이었다.
    """
    with _KaliSessionLock():
        if is_mac_host():
            return _run_in_kali_via_ssh(command, timeout, _allow_interactive_recovery=_allow_interactive_recovery)
        return _run_in_kali_locked(command, timeout, _allow_interactive_recovery=_allow_interactive_recovery)


def _run_in_kali_via_ssh(command: str, timeout: int, *, _allow_interactive_recovery: bool) -> GuestResult:
    try:
        exit_code, stdout, stderr = run_noninteractive_command(command, timeout=timeout)
        result = GuestResult(exit_code=exit_code, stdout=stdout, stderr=stderr)
        if (
            _allow_interactive_recovery
            and result.exit_code != 0
            and looks_interactive_worthy(result.stdout, result.stderr)
        ):
            decision = ask_user_for_recovery(command, result.stdout, result.stderr)
            if decision.confirmed_output is not None:
                return GuestResult(exit_code=0, stdout=decision.confirmed_output, stderr="[interactive-confirmed]")
            if decision.skip:
                return GuestResult(exit_code=0, stdout="[interactive-skip]", stderr="")
            if decision.retry_command:
                return _run_in_kali_via_ssh(decision.retry_command, timeout, _allow_interactive_recovery=False)
        return result
    except Exception as exc:  # noqa: BLE001 - SSH fallback 경로는 호출부에 stderr로 보고
        result = GuestResult(exit_code=-1, stdout="", stderr=str(exc))
        if _allow_interactive_recovery and looks_interactive_worthy(result.stderr):
            decision = ask_user_for_recovery(command, result.stdout, result.stderr)
            if decision.confirmed_output is not None:
                return GuestResult(exit_code=0, stdout=decision.confirmed_output, stderr="[interactive-confirmed]")
            if decision.skip:
                return GuestResult(exit_code=0, stdout="[interactive-skip]", stderr="")
            if decision.retry_command:
                return _run_in_kali_via_ssh(decision.retry_command, timeout, _allow_interactive_recovery=False)
        return result


def _run_in_kali_locked(command: str, timeout: int, *, _allow_interactive_recovery: bool) -> GuestResult:
    args = [
        VBOXMANAGE, "guestcontrol", KALI_VM, "run",
        "--username", KALI_USER, "--password", KALI_PASS,
        "--exe", "/bin/bash", "--",
        "-c", command,
    ]
    try:
        # encoding/errors를 명시하지 않으면 파이썬이 로케일 기본 인코딩(예: Windows
        # PowerShell에서 cp1252)을 쓰는데, VBoxManage 출력은 UTF-8이라 디코딩이
        # 깨질 수 있다 (Git Bash에서 실행할 땐 안 드러나다가 PowerShell에서 직접
        # 실행하니 UnicodeDecodeError로 재현됨) -> 명시적으로 UTF-8 고정.
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        result = GuestResult(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
        if (
            _allow_interactive_recovery
            and result.exit_code != 0
            and looks_interactive_worthy(result.stdout, result.stderr)
        ):
            decision = ask_user_for_recovery(command, result.stdout, result.stderr)
            if decision.confirmed_output is not None:
                return GuestResult(exit_code=0, stdout=decision.confirmed_output, stderr="[interactive-confirmed]")
            if decision.skip:
                return GuestResult(exit_code=0, stdout="[interactive-skip]", stderr="")
            if decision.retry_command:
                return _run_in_kali_locked(decision.retry_command, timeout, _allow_interactive_recovery=False)
        return result
    except subprocess.TimeoutExpired:
        _close_all_sessions_locked()
        result = GuestResult(exit_code=-1, stdout="", stderr=f"timed out after {timeout}s (guest session force-closed)")
        if _allow_interactive_recovery and looks_interactive_worthy(result.stderr):
            decision = ask_user_for_recovery(command, result.stdout, result.stderr)
            if decision.confirmed_output is not None:
                return GuestResult(exit_code=0, stdout=decision.confirmed_output, stderr="[interactive-confirmed]")
            if decision.skip:
                return GuestResult(exit_code=0, stdout="[interactive-skip]", stderr="")
            if decision.retry_command:
                return _run_in_kali_locked(decision.retry_command, timeout, _allow_interactive_recovery=False)
        return result


def close_all_sessions() -> None:
    """orphan된 guestcontrol 세션을 전부 정리. 타임아웃/강제종료 후 호출."""
    with _KaliSessionLock():
        _close_all_sessions_locked()


def _close_all_sessions_locked() -> None:
    if is_mac_host():
        return
    subprocess.run(
        [VBOXMANAGE, "guestcontrol", KALI_VM, "closesession", "--all"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def is_guest_ready(retries: int = 24, delay: int = 5) -> bool:
    """게스트 애디션이 명령을 받을 준비가 됐는지 폴링. VM 부팅 직후 호출."""
    import time
    for _ in range(retries):
        result = run_in_kali("true", timeout=15, _allow_interactive_recovery=False)
        if result.ok:
            return True
        time.sleep(delay)
    return False


if __name__ == "__main__":
    r = run_in_kali("whoami && ip -4 addr show eth1 | grep inet")
    print(f"exit={r.exit_code}")
    print(r.stdout)
    if r.stderr:
        print("stderr:", r.stderr)
