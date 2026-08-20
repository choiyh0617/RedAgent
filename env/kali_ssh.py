"""
Kali에 실제 pty를 붙여서 대화형 도구를 파이썬으로 직접 구동한다. DESIGN.md 26절.

`guest_control.py`(VBoxManage guestcontrol)는 pty가 없는 비대화형 실행 채널이라,
pwncat-cs 같은 대화형 도구를 돌리면 "Input is not a terminal" 경고와 함께
제대로 동작하지 않는 걸 실측으로 확인했다(DESIGN.md 26절 - 리버스쉘 연결은
받는데 곧바로 끊김). `paramiko`의 `invoke_shell()`은 SSH 채널에 **진짜 pty**를
요청해서 붙여주므로, 이 문제를 원천적으로 피할 수 있다 - 사람이 SSH로 접속해서
직접 타이핑하는 것과 동일한 환경을 코드로 재현하는 것.

이건 `guest_control.py`를 대체하는 게 아니라 보완한다 - 빠르고 상태 없는
(stateless) 명령 하나는 SSH 핸드셰이크 비용이 없는 `run_in_kali()`가 여전히
더 간단하고 빠르다. 이 모듈은 **대화형 프로그램을 여러 번의 주고받음에 걸쳐
구동해야 할 때만** 쓴다(pwncat-cs, 대화형 msfconsole, ftp/telnet 클라이언트 등).

Kali에 SSH가 켜져 있어야 한다(DESIGN.md 26절에서 활성화함 - `systemctl
enable --now ssh` + 호스트 키 재생성).
"""

import re
import time

import paramiko

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정

KALI_HOST = "192.168.56.101"
KALI_USER = "kali"
KALI_PASS = "kali"

_ANSI_RE = re.compile(r"\x1b(\[[0-9;?]*[a-zA-Z]|\][^\x07]*\x07|[<-~])")
PLAIN_PROMPT = "###PWNAGENT_PROMPT###"


def run_noninteractive_command(
    command: str,
    *,
    host: str = KALI_HOST,
    username: str = KALI_USER,
    password: str = KALI_PASS,
    timeout: float = 120,
) -> tuple[int, str, str]:
    """SSH exec_command 기반 단발성 명령 실행.

    Mac/ARM 환경처럼 guestcontrol을 기대하기 어려운 경우의 대체 경로로 쓴다.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, timeout=timeout)
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return (
            exit_code,
            stdout.read().decode("utf-8", errors="replace"),
            stderr.read().decode("utf-8", errors="replace"),
        )
    finally:
        client.close()


class InteractiveSSHSession:
    """SSH + 진짜 pty로 연 대화형 셸. `send()`/`expect()`로 사람이 터미널에서
    타이핑/읽는 것과 같은 방식으로 프로그램을 구동한다.

    `with InteractiveSSHSession() as sh:` 형태로 쓰는 걸 권장(연결 정리 보장)."""

    def __init__(
        self, host: str = KALI_HOST, username: str = KALI_USER, password: str = KALI_PASS,
        term: str = "xterm", timeout: float = 15,
    ):
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(host, username=username, password=password, timeout=timeout)
        self._channel = self._client.invoke_shell(term=term, width=220, height=50)
        self._buffer = ""
        self._drain(wait=1.0)  # 로그인 배너/최초 프롬프트(zsh 기본 프롬프트, ANSI 색상 포함)가 뜰 시간

        # Kali 기본 zsh 프롬프트는 다단 박스에 ANSI 색상이 섞여 있어 expect()로
        # 매칭하기 번거롭다 - 단순한 평문 프롬프트로 바꿔서 이후 expect() 패턴을
        # 간단하게 만든다.
        self._channel.send(f"export PS1='{PLAIN_PROMPT}'\n")
        self.expect(re.escape(PLAIN_PROMPT), timeout=timeout)

    def _drain(self, wait: float = 0.3) -> str:
        """지금까지 도착한 출력을 전부 읽어서 내부 버퍼에 쌓고, 이번에 읽은
        조각을 반환한다. ANSI 이스케이프 시퀀스(색상, 커서 이동, 터미널 타이틀
        설정 등)는 제거해서 사람이 읽는 텍스트만 남긴다."""
        time.sleep(wait)
        chunk = ""
        while self._channel.recv_ready():
            chunk += self._channel.recv(65536).decode("utf-8", errors="replace")
        chunk = _ANSI_RE.sub("", chunk)
        self._buffer += chunk
        return chunk

    def send(self, line: str) -> None:
        """한 줄을 입력하고 엔터를 누른 것처럼 보낸다."""
        self._channel.send(line + "\n")

    def expect(self, pattern: str, timeout: float = 30, poll_interval: float = 0.5) -> str:
        """`pattern`(정규식)이 나타날 때까지 기다리며 출력을 모은다. 나타나면
        마지막으로 비운 이후 쌓인 전체 출력을 반환하고 내부 버퍼를 비운다.
        시간 안에 안 나타나면 `TimeoutError`(지금까지 받은 출력 일부를 메시지에
        포함해서 디버깅에 도움되게 함)."""
        deadline = time.time() + timeout
        regex = re.compile(pattern)
        while time.time() < deadline:
            self._drain(wait=poll_interval)
            if regex.search(self._buffer):
                out, self._buffer = self._buffer, ""
                return out
        raise TimeoutError(f"{timeout}s 안에 패턴을 못 찾음: {pattern!r} (마지막 500자: {self._buffer[-500:]!r})")

    def read_available(self) -> str:
        """지금까지 도착한 출력을 패턴 대기 없이 그냥 다 읽어서 반환한다."""
        self._drain()
        out, self._buffer = self._buffer, ""
        return out

    def close(self) -> None:
        try:
            self._channel.close()
        finally:
            self._client.close()

    def __enter__(self) -> "InteractiveSSHSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


if __name__ == "__main__":
    with InteractiveSSHSession() as sh:
        sh.send("whoami && hostname")
        print(sh.expect(re.escape(PLAIN_PROMPT), timeout=10))
