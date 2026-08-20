"""
사람이 MCP 클라이언트(Claude Desktop 등)로 직접 붙어서 VM을 대화형으로
트러블슈팅하는 부가 인터페이스. DESIGN.md 40/42절.

40절에서 "메인 파이프라인을 MCP로 감싸는 것"은 기각했다 - 순서가 코드에
고정된 결정론적 체인이라 MCP가 필요한 "매번 판단" 상황이 아니어서다. 이
파일은 그 반례다: 여기는 **사람**이 MCP 클라이언트 채팅창에서 임의 순서로
증상을 관찰하고 조치를 시도하는, 애초에 순서가 코드에 정해져 있지 않은
상황이라 MCP가 실제로 맞는 자리다.

env/setup_doctor.py(LLM이 스스로 도구를 골라 도는 에이전틱 루프)와 같은
도구 세트/안전 범위를 재사용한다 - 저기서는 이 코드베이스가 Claude API를
직접 호출해서 루프를 돌리고, 여기서는 그 대신 외부 MCP 클라이언트(사람이
붙어 있는 Claude Desktop 등)가 루프를 돈다는 차이뿐이다. 안전 범위는
동일하게 유지한다: 진단(스크린샷/명령실행/상태조회)은 자유롭게, 변경
행위는 VM 전원 조작(reset/startvm/poweroff)까지만 - 디스크 재구성/파일
삭제 같은 되돌리기 어려운 작업은 도구로 안 준다.

모든 도구 호출을 findings.jsonl에 남긴다(stage="mcp_interactive") - 이 서버
프로세스 하나당 인게이지먼트 ID 하나를 발급해서, 세션 동안 뭘 시도했는지
나중에 감사(audit)할 수 있게 한다.

실행: `python -m mcp_servers.vm_troubleshoot_server` (stdio transport).
Claude Desktop 설정(claude_desktop_config.json)의 mcpServers에 등록해서
연결한다 - README 참고.
"""

import tempfile
import time
from pathlib import Path
from typing import Literal

from core import config  # noqa: F401 - .env 로드 + stdout UTF-8 고정
from core.engagement import new_engagement_id
from core.state_store import append_finding
from env.guest_control import run_in_kali as _run_in_kali
from env.health_check import check_target_reachability, check_vm_states
from env.provision_target import _run, list_target_vms
from mcp.server.mcpserver import Image, MCPServer

ENGAGEMENT_ID = new_engagement_id("interactive-troubleshoot")

INSTRUCTIONS = (
    "승인된 개인 침투테스트 랩(사용자가 소유/통제하는 격리된 VirtualBox 환경)의 "
    "VM 트러블슈팅 도구다. 증상을 관찰하고(스크린샷이 특히 유용 - 텍스트 로그로 "
    "안 보이는 부팅 화면/에러를 직접 볼 수 있다) -> 원인 가설을 세우고 -> 안전한 "
    "범위 안에서 조치하고 -> 다시 관찰해서 확인하는 순서로 진행해라.\n\n"
    "할 수 없는 것: 디스크 파티션 재구성, 설정 파일 수정, 파일 삭제 - 이런 "
    "수준의 조치가 필요하면 시도하지 말고 사람에게 알려라. run_in_kali는 진단용 "
    "읽기 전용/조회성 명령(nmap, VBoxManage 상태 조회 등)에만 써라 - 대상을 "
    "변경하는 명령은 쓰지 마라."
)

mcp = MCPServer("pentest-vm-troubleshoot", instructions=INSTRUCTIONS)


def _log(tool: str, target: str | None = None, **kwargs) -> None:
    append_finding(ENGAGEMENT_ID, stage="mcp_interactive", event="tool_call", target=target, tool=tool, **kwargs)


@mcp.tool()
def list_vms() -> list[str]:
    """등록된 VM 목록을 반환한다(Kali 포함) - 다른 도구를 어떤 vm_name으로 호출할지 확인할 때 먼저 쓸 것."""
    _log("list_vms")
    return list_target_vms(exclude=set())


@mcp.tool()
def take_screenshot(vm_name: str) -> Image:
    """VM의 현재 화면을 캡처한다. 부팅 실패/에러 메시지처럼 텍스트 로그로 안 보이는 문제를 진단할 때 가장 먼저 써볼 것."""
    _log("take_screenshot", target=vm_name)
    # screenshotpng는 VBoxManage가 실행되는 호스트(Windows)에 저장한다 - Kali 안의
    # 경로가 아님 (setup_doctor.py에서 겪은 것과 같은 함정, 여기도 동일하게 방어).
    path = str(Path(tempfile.gettempdir()) / f"mcp_troubleshoot_{vm_name}_{int(time.time())}.png")
    _run("controlvm", vm_name, "screenshotpng", path)
    return Image(path=path)


@mcp.tool()
def check_vm_state(vm_name: str) -> dict:
    """VM이 지금 running/poweroff/aborted 등 어떤 상태인지 조회한다."""
    _log("check_vm_state", target=vm_name)
    return check_vm_states([vm_name])


@mcp.tool()
def vm_power_action(vm_name: str, action: Literal["reset", "poweroff", "startvm"]) -> str:
    """VM에 전원 조작을 한다. reset=강제 재시작, poweroff=강제 종료, startvm=headless 기동."""
    _log("vm_power_action", target=vm_name, action=action)
    try:
        if action == "startvm":
            _run("startvm", vm_name, "--type", "headless")
        else:
            _run("controlvm", vm_name, action)
        return f"{action} on {vm_name}: ok"
    except RuntimeError as exc:
        return f"{action} on {vm_name} failed: {exc}"


@mcp.tool()
def check_reachability(ip: str) -> dict:
    """Kali에서 이 IP로 ping이 가는지 확인한다(대상이 네트워크에 올라왔는지 확인용)."""
    _log("check_reachability", target=ip)
    return check_target_reachability([ip], retries=1)


@mcp.tool()
def run_in_kali(command: str, timeout: int = 30) -> str:
    """Kali 안에서 진단 명령(nmap, VBoxManage 상태 조회 등)을 실행한다. 읽기 전용/조회성 명령만 - 대상을 변경하는 명령은 쓰지 말 것. timeout 최대 90초."""
    _log("run_in_kali", command=command)
    result = _run_in_kali(command, timeout=min(timeout, 90))
    return f"exit={result.exit_code}\nstdout={result.stdout}\nstderr={result.stderr}"


if __name__ == "__main__":
    mcp.run()
