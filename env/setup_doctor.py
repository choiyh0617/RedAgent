"""
환경 설정 트러블슈터 (VM 설치/부팅/연결성 진단). DESIGN.md 33절.

**왜 필요한가**: 이 세션에서 임포트/설치한 VM마다 전부 다른 종류의 문제를 겪었다
- Kioptrix1 NIC 드라이버 비호환, Kioptrix2 DHCP IP 재발견, msfconsole bootsnap
크래시, pwncat-cs Python 3.13 호환성, Windows Server 무인설치 부팅 실패. 근본
원인이 매번 완전히 달라서, 미리 정해둔 if-else 체크리스트(`health_check.py`)로는
못 잡는 클래스의 문제다. 이건 사람(또는 이 세션 내내 LLM)이 "증상 관찰 -> 가설
-> 시도 -> 재관찰"을 반복하며 풀어온 문제라, 그 루프 자체를 자동화한다.

**왜 이게 코드베이스의 다른 LLM 호출과 다른가**: 나머지 모듈(vuln_analysis.py,
exploitation.py 등)은 전부 "구조화된 입력 -> 판정 1회 반환"이라 단발성 프롬프트로
충분했다(DESIGN.md 1절). 이건 "명령 실행 -> 결과 관찰 -> 다음 행동 결정"을 여러
턴 반복해야 하는 진짜 에이전틱 툴콜 루프다 - DESIGN.md 1절이 명시한 "전환
포인트"("실패하면 모델이 알아서 다른 접근을 시도하는 방식이 필요해지면 Agent
SDK로 전환")에 정확히 해당한다. 다만 전체 파이프라인을 에이전틱하게 바꾸는 대신,
이 모듈 하나에만 국한해서 범위를 좁혔다.

**안전 범위**: 진단 도구(스크린샷/명령 실행/상태 조회)는 자유롭게 쓰게 하지만,
실제 변경 행위는 VM 전원 조작(reset/startvm/poweroff - 이미 이 세션 내내 사람이
반복해온 안전한 복구 동작)까지만 허용한다. 디스크 재구성, autounattend.xml 수정,
파일 삭제처럼 되돌리기 어려운 행위는 도구로 안 준다 - 그런 수준의 수정이
필요하다는 진단이 나오면 `report_diagnosis`로 사람에게 넘긴다.

모든 도구 호출과 최종 진단을 findings.jsonl에 남겨서(stage="setup_doctor")
나중에 뭘 시도했는지 감사(audit)할 수 있게 한다.
"""

import base64
import json
import tempfile
import time
import os
from pathlib import Path

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core.llm_client import call_with_tools
from core.state_store import append_finding
from env.guest_control import run_in_kali
from env.health_check import check_target_reachability, check_vm_states
from env.provision_target import VBOXMANAGE, _run

MODEL = os.getenv("PENTEST_AGENT_OLLAMA_TOOL_MODEL", os.getenv("PENTEST_AGENT_OLLAMA_MODEL", "llama3.2:latest"))
MAX_ITERATIONS = 10

SYSTEM_PROMPT = """너는 승인된 개인 침투테스트 랩(사용자가 소유/통제하는 격리된
VirtualBox 환경, CTF/OSCP 연습 + AD 랩 구축용)의 환경 설정 트러블슈터다. VM
설치/부팅/네트워크 연결성 문제를 진단하고, 안전한 범위(VM 전원 조작) 안에서
고쳐본다.

접근 방식: 증상을 관찰하고(스크린샷/로그/상태조회) -> 원인 가설을 세우고 ->
안전한 조치를 시도하고 -> 다시 관찰해서 확인해라. 스크린샷은 특히 중요하다 -
텍스트 로그로는 안 보이는 부팅 화면/에러 메시지를 직접 볼 수 있다.

네가 할 수 없는 것: 디스크 파티션 재구성, 설정 파일(autounattend.xml 등) 수정,
파일 삭제 - 이런 수준의 조치가 필요하다고 판단되면 시도하지 말고
report_diagnosis로 원인과 필요한 조치를 정리해서 사람에게 넘겨라.

충분히 진단했거나(문제를 못 고쳐도 원인을 알아냈으면 충분) 도구를 다 써봤으면
report_diagnosis를 불러서 마무리해라."""

TOOLS = [
    {
        "name": "take_screenshot",
        "description": "VM의 현재 화면을 캡처해서 본다. 부팅 실패/에러 메시지처럼 텍스트 로그로 안 보이는 문제를 진단할 때 가장 먼저 써볼 것.",
        "input_schema": {
            "type": "object",
            "properties": {"vm_name": {"type": "string"}},
            "required": ["vm_name"],
        },
    },
    {
        "name": "check_vm_state",
        "description": "VM이 지금 running/poweroff/aborted 등 어떤 상태인지 조회한다.",
        "input_schema": {
            "type": "object",
            "properties": {"vm_name": {"type": "string"}},
            "required": ["vm_name"],
        },
    },
    {
        "name": "vm_power_action",
        "description": "VM에 전원 조작을 한다. reset(강제 재시작)/poweroff(강제 종료)/startvm(기동) 중 하나.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vm_name": {"type": "string"},
                "action": {"type": "string", "enum": ["reset", "poweroff", "startvm"]},
            },
            "required": ["vm_name", "action"],
        },
    },
    {
        "name": "check_reachability",
        "description": "Kali에서 이 IP로 ping이 가는지 확인한다(대상이 네트워크에 올라왔는지 확인용).",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "run_in_kali",
        "description": "Kali 안에서 읽기 전용 진단 명령(nmap, VBoxManage 상태 조회 등)을 실행한다. 대상을 변경하는 명령은 쓰지 말 것.",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "wait",
        "description": "N초 기다린다(부팅/설치가 더 진행될 시간을 줄 때).",
        "input_schema": {
            "type": "object",
            "properties": {"seconds": {"type": "integer"}},
            "required": ["seconds"],
        },
    },
    {
        "name": "report_diagnosis",
        "description": "진단을 마무리한다. 문제를 고쳤든 못 고쳤든, 원인과 결과를 정리해서 이 도구로 보고해라.",
        "input_schema": {
            "type": "object",
            "properties": {
                "root_cause": {"type": "string", "description": "원인으로 판단되는 것"},
                "fixed": {"type": "boolean", "description": "이 루프 안에서 실제로 고쳤는지"},
                "summary": {"type": "string", "description": "시도한 것과 결과 요약"},
                "next_steps": {"type": "string", "description": "못 고쳤다면 사람이 다음에 뭘 해야 하는지"},
            },
            "required": ["root_cause", "fixed", "summary"],
        },
    },
]


def _execute_tool(engagement_id: str, name: str, tool_input: dict) -> list[dict]:
    """도구 하나를 실행하고 tool_result의 content(list)를 만들어 반환한다.
    스크린샷은 image 블록으로 넣어야 모델이 실제로 볼 수 있다."""
    append_finding(engagement_id, stage="setup_doctor", event="tool_call", target=None, tool=name, input=tool_input)

    if name == "take_screenshot":
        # screenshotpng는 VBoxManage가 실행되는 호스트(Windows)에 저장한다 -
        # Kali 안의 경로가 아님. Unix 스타일 /tmp 경로를 썼다가 VERR_PATH_NOT_FOUND로
        # 실패한 적이 있음(실측) -> 호스트 임시 디렉터리 사용.
        path = str(Path(tempfile.gettempdir()) / f"setup_doctor_{tool_input['vm_name']}_{int(time.time())}.png")
        _run("controlvm", tool_input["vm_name"], "screenshotpng", path)
        with open(path, "rb") as f:
            img_b64 = base64.b64encode(f.read()).decode()
        return [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": img_b64}}]

    if name == "check_vm_state":
        states = check_vm_states([tool_input["vm_name"]])
        return [{"type": "text", "text": json.dumps(states, ensure_ascii=False)}]

    if name == "vm_power_action":
        action = tool_input["action"]
        vm = tool_input["vm_name"]
        try:
            if action == "startvm":
                _run("startvm", vm, "--type", "headless")
            else:
                _run("controlvm", vm, action)
            return [{"type": "text", "text": f"{action} on {vm}: ok"}]
        except RuntimeError as exc:
            return [{"type": "text", "text": f"{action} on {vm} failed: {exc}"}]

    if name == "check_reachability":
        result = check_target_reachability([tool_input["ip"]], retries=1)
        return [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]

    if name == "run_in_kali":
        result = run_in_kali(tool_input["command"], timeout=30)
        return [{"type": "text", "text": f"exit={result.exit_code}\nstdout={result.stdout}\nstderr={result.stderr}"}]

    if name == "wait":
        time.sleep(min(tool_input.get("seconds", 10), 120))
        return [{"type": "text", "text": "waited"}]

    return [{"type": "text", "text": f"알 수 없는 도구: {name}"}]


def diagnose(engagement_id: str, vm_name: str, symptom: str) -> dict:
    """`symptom`(사람이 관찰한 증상 설명)을 시작점으로 진단 루프를 돈다.
    최종 진단(dict: root_cause/fixed/summary/next_steps)을 반환한다."""
    messages = [{
        "role": "user",
        "content": f"VM '{vm_name}'에서 다음 문제가 생겼다: {symptom}\n진단하고, 안전한 범위에서 고쳐봐라.",
    }]

    for _ in range(MAX_ITERATIONS):
        response = call_with_tools(messages, tools=TOOLS, model=MODEL)
        messages.append({"role": "assistant", "content": response.content})

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            break  # 도구 호출 없이 끝남 - 텍스트만 왔다는 뜻, 진단 없이 종료

        tool_results = []
        finished_report: dict | None = None
        for block in tool_uses:
            if block.name == "report_diagnosis":
                finished_report = block.input
                tool_results.append({
                    "type": "tool_result", "tool_use_id": block.id,
                    "content": [{"type": "text", "text": "보고 접수함"}],
                })
                continue
            content = _execute_tool(engagement_id, block.name, block.input)
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": content})

        messages.append({"role": "user", "content": tool_results})

        if finished_report is not None:
            append_finding(
                engagement_id, stage="setup_doctor", event="diagnosis_complete", target=vm_name,
                **finished_report,
            )
            return finished_report

    fallback = {
        "root_cause": "미확정 (반복 한도 도달)",
        "fixed": False,
        "summary": f"{MAX_ITERATIONS}회 반복 안에 report_diagnosis를 못 받음",
        "next_steps": "findings.jsonl의 setup_doctor 단계 로그를 사람이 직접 확인할 것",
    }
    append_finding(engagement_id, stage="setup_doctor", event="diagnosis_incomplete", target=vm_name, **fallback)
    return fallback


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("usage: python -m env.setup_doctor <engagement_id> <vm_name> [증상 설명]")
        sys.exit(1)

    eid, vm = sys.argv[1], sys.argv[2]
    sym = " ".join(sys.argv[3:]) or "부팅/연결성 문제로 추정 - 직접 진단해봐라"

    result = diagnose(eid, vm, sym)
    print(json.dumps(result, ensure_ascii=False, indent=2))
