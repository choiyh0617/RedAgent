"""
AD 측면 이동/열거 오케스트레이션 에이전트. DESIGN.md 52절.

**왜 필요한가**: `ad_enum.py`/`lateral_movement.py`는 각각 결정론적인 개별
함수(도메인 열거, kerberoast 대상 찾기, 크레덴셜 검증, 원격 명령 실행, 시크릿
덤프)일 뿐, 그것들을 어떤 순서로 조합할지는 정해진 적이 없었다(둘 다 이 세션
안에서 개별적으로만 실전 검증됨). AD 측면 이동은 본질적으로 그래프 탐색
문제다 - "이 크레덴셜로 저 호스트가 열리네, 그럼 거기서 덤프한 시크릿으로
또 다른 호스트를 시도해보자" 식으로, 다음에 뭘 시도할지가 그 순간까지
발견한 것에 따라 매번 달라진다. `env/setup_doctor.py`가 "환경 문제는 매번
원인이 달라서 고정 스크립트로 못 잡는다"는 이유로 에이전틱해진 것과 정확히
같은 논리로(DESIGN.md 1절의 "전환 포인트"), 여기도 고정된 순서로는 커버가
안 되는 영역이다.

**안전 범위**: `lateral_movement.py`가 이미 문서화한 계정 잠금(lockout) 주의
사항을 시스템 프롬프트에도 명시한다 - 같은 크레덴셜을 같은 호스트에 반복
시도하지 않고, 대상마다 순차적으로(병렬 아님) 시도하게 한다. `execute_command`
는 정찰/열거 목적 명령(whoami, net user 등)에 쓰도록 안내하고 파괴적인
명령은 피하라고 명시한다 - 다만 이건 프롬프트 수준의 안내일 뿐 강제는 아니다
(lateral_movement.py 자체가 이미 임의 명령 실행을 허용하는 구조라, 이
에이전트가 새로운 위험을 추가한다기보다는 기존 신뢰 모델 위에서 "언제 어떤
순서로 부를지"만 자동화하는 것).

**아직 검증 못 한 부분**: 현재 AD 랩에는 도메인 컨트롤러(AD-DC01) 하나뿐이라
(멤버 워크스테이션 없음) "측면 이동"의 실제 이동 구간(다른 호스트로 건너가기)은
검증할 대상이 없다 - enumerate/kerberoast/자격증명 검증까지는 실제로
확인 가능하지만, dump_secrets 이후 새 크레덴셜로 다른 호스트를 여는 흐름은
멤버 호스트가 추가되기 전까지는 코드 리뷰 수준 검증에 머문다.
"""

import os
from dataclasses import asdict

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core import progress
from core.llm_client import call_with_tools
from core.state_store import append_finding, read_credentials
from modules.ad_enum import (
    DomainCredential,
    collect_bloodhound_data,
    enumerate_domain,
    find_asrep_roastable_users,
    find_kerberoast_targets,
)
from modules.lateral_movement import dump_local_secrets, execute_command, try_credential_on_target

MODEL = os.getenv("PENTEST_AGENT_OLLAMA_TOOL_MODEL", os.getenv("PENTEST_AGENT_OLLAMA_MODEL", "llama3.2:latest"))
MAX_ITERATIONS = 15  # 그래프 탐색이라 exploit_doctor.py(3)보다 훨씬 넉넉하게, setup_doctor.py(10)보다도 조금 더

SYSTEM_PROMPT_TEMPLATE = """너는 승인된 개인 침투테스트 랩(사용자가 소유/통제
하고 서면으로 스스로 승인한, 격리된 VirtualBox 환경 - CTF/OSCP/AD 연습용,
인터넷에 노출 안 됨)의 Active Directory 열거/측면 이동 담당이다.

도메인: {domain} (DC: {dc_ip})
시작 크레덴셜: {username} (이미 검증된 유효한 자격증명)
알려진 호스트: {scope_hosts}

접근 방식: 도메인을 열거해서(enumerate_domain, collect_bloodhound) 구조를
파악하고 -> kerberoast/AS-REP roasting 대상이 있으면 확인하고(크래킹은 이
도구 범위 밖 - 해시만 확보하는 걸로 충분) -> 알려진 호스트마다 지금 가진
크레덴셜이 통하는지 확인하고(try_credential) -> 관리자 권한이 확보된
호스트에서는 시크릿을 덤프해서(dump_secrets) 새 크레덴셜을 얻고 -> 새
크레덴셜로 다른 호스트를 다시 시도하는 식으로 확장해가라.

주의사항(계정 잠금 방지, lateral_movement.py 8-3절 정책과 동일):
- 같은 크레덴셜을 같은 호스트에 반복 시도하지 마라(한 번 실패하면 다른
  크레덴셜이나 다른 호스트로 넘어가라).
- 호스트는 항상 순차적으로 하나씩 시도해라(병렬 아님).
- execute_command는 정찰 목적 명령(whoami, net user /domain, ipconfig 등)에만
  써라 - 파일 삭제/서비스 중지 같은 파괴적인 명령은 쓰지 마라.

list_known_credentials로 지금까지 발견된 크레덴셜 전체를 언제든 다시 확인할
수 있다. 더 확장할 게 없거나(모든 알려진 호스트/크레덴셜 조합을 소진함)
충분히 진행했다고 판단되면 finish로 마무리해라."""

TOOLS = [
    {
        "name": "enumerate_domain",
        "description": "netexec SMB로 공유폴더/도메인 사용자 목록을 훑는다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "username": {"type": "string"}, "password": {"type": "string"}, "ntlm_hash": {"type": "string"},
            },
        },
    },
    {
        "name": "collect_bloodhound",
        "description": "bloodhound-python으로 도메인 구조(사용자/그룹/ACL/세션) 데이터를 수집한다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "username": {"type": "string"}, "password": {"type": "string"}, "ntlm_hash": {"type": "string"},
            },
            "required": ["username"],
        },
    },
    {
        "name": "find_kerberoast_targets",
        "description": "SPN이 설정된 계정(kerberoasting 대상)의 크래킹 가능한 TGS 해시를 요청한다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "username": {"type": "string"}, "password": {"type": "string"}, "ntlm_hash": {"type": "string"},
            },
            "required": ["username"],
        },
    },
    {
        "name": "find_asrep_roastable",
        "description": "Kerberos 사전인증이 꺼진 계정(AS-REP roasting 대상)을 찾는다. 크레덴셜 불필요.",
        "input_schema": {
            "type": "object",
            "properties": {"usernames": {"type": "array", "items": {"type": "string"}}},
            "required": ["usernames"],
        },
    },
    {
        "name": "try_credential",
        "description": "이 크레덴셜이 특정 호스트 SMB에서 통하는지 확인한다. 로컬 관리자 권한이면 결과에 admin으로 표시됨.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"}, "username": {"type": "string"},
                "password": {"type": "string"}, "ntlm_hash": {"type": "string"},
            },
            "required": ["target", "username"],
        },
    },
    {
        "name": "execute_command",
        "description": "이 크레덴셜로 대상 호스트에 원격 명령을 실행한다(로컬 관리자 권한 필요). 정찰 명령만 - 파괴적인 명령 쓰지 마라.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"}, "username": {"type": "string"},
                "password": {"type": "string"}, "ntlm_hash": {"type": "string"},
                "command_to_run": {"type": "string"},
            },
            "required": ["target", "username", "command_to_run"],
        },
    },
    {
        "name": "dump_secrets",
        "description": "로컬 관리자 권한이 확보된 호스트에서 SAM/LSASS를 덤프한다. 새 크레덴셜은 자동으로 기록되고 결과로도 반환된다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"}, "username": {"type": "string"},
                "password": {"type": "string"}, "ntlm_hash": {"type": "string"},
            },
            "required": ["target", "username"],
        },
    },
    {
        "name": "list_known_credentials",
        "description": "지금까지 발견/기록된 크레덴셜 전체 목록을 조회한다.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "finish",
        "description": "탐색을 마무리한다. 확보한 것(호스트/자격증명/공격 경로)을 요약해서 보고해라.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "compromised_hosts": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary"],
        },
    },
]


def _cred_from_input(inp: dict) -> DomainCredential:
    return DomainCredential(
        username=inp["username"], domain=inp.get("domain", ""),
        password=inp.get("password"), ntlm_hash=inp.get("ntlm_hash"),
    )


def _execute_tool(engagement_id: str, dc_ip: str, domain: str, name: str, inp: dict) -> list[dict]:
    """도구 하나를 실행하고 tool_result content를 만든다. 텍스트로만 응답 -
    JSON 직렬화해서 모델이 다음 판단에 바로 쓸 수 있게 한다."""
    append_finding(engagement_id, stage="ad_agent", event="tool_call", target=dc_ip, tool=name)
    import json

    if name == "enumerate_domain":
        cred = _cred_from_input(inp) if inp.get("username") else None
        result = enumerate_domain(engagement_id, dc_ip, domain, cred)
        return [{"type": "text", "text": json.dumps(result, ensure_ascii=False)[:3000]}]

    if name == "collect_bloodhound":
        result = collect_bloodhound_data(engagement_id, dc_ip, domain, _cred_from_input(inp))
        return [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]

    if name == "find_kerberoast_targets":
        result = find_kerberoast_targets(engagement_id, dc_ip, domain, _cred_from_input(inp))
        return [{"type": "text", "text": result[:3000] or "(빈 출력)"}]

    if name == "find_asrep_roastable":
        result = find_asrep_roastable_users(engagement_id, dc_ip, domain, inp.get("usernames", []))
        return [{"type": "text", "text": result[:3000] or "(빈 출력)"}]

    if name == "try_credential":
        result = try_credential_on_target(engagement_id, _cred_from_input(inp), inp["target"])
        return [{"type": "text", "text": json.dumps(asdict(result), ensure_ascii=False)}]

    if name == "execute_command":
        output = execute_command(engagement_id, _cred_from_input(inp), inp["target"], inp["command_to_run"])
        return [{"type": "text", "text": output[:3000] or "(빈 출력)"}]

    if name == "dump_secrets":
        result = dump_local_secrets(engagement_id, _cred_from_input(inp), inp["target"])
        return [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]

    if name == "list_known_credentials":
        creds = read_credentials(engagement_id)
        return [{"type": "text", "text": json.dumps(creds, ensure_ascii=False)}]

    return [{"type": "text", "text": f"알 수 없는 도구: {name}"}]


_KEEP_LAST_PAIRS = 5  # 최근 5턴(assistant+tool_result)만 원문 유지, 그 이전은 요약으로 대체


def _trim_messages(messages: list[dict]) -> list[dict]:
    """오래된 턴을 요약으로 대체해서 대화 길이를 억제한다 - web_agent.py의
    같은 함수와 동일한 이유(DESIGN.md 61절): 비용/컨텍스트 절약 + 누적된
    공격 관련 텍스트가 계속 쌓이면서 거부 확률이 올라갈 수 있다는 우려에 대한
    정상적인 엔지니어링 대응. tool_use/tool_result 쌍 단위로만 자른다."""
    body = messages[1:]
    if len(body) <= _KEEP_LAST_PAIRS * 2:
        return messages
    kept = body[-(_KEEP_LAST_PAIRS * 2):]
    dropped_pairs = (len(body) - len(kept)) // 2
    summary = {"role": "user", "content": f"(이전 {dropped_pairs}개 턴 생략 - 상세 기록은 findings.jsonl의 ad_agent 단계 참고)"}
    return [messages[0], summary] + kept


def explore_and_move(
    engagement_id: str, dc_ip: str, domain: str,
    initial_username: str, initial_password: str | None = None, initial_ntlm_hash: str | None = None,
    scope_hosts: list[str] | None = None,
) -> dict:
    """알려진 크레덴셜 하나로 시작해서 AD 환경을 열거/확장한다. 최종
    dict(summary/compromised_hosts)를 반환 - MAX_ITERATIONS 안에
    finish를 못 받으면 미완료로 폴백."""
    scope_hosts = scope_hosts or [dc_ip]
    progress.info(f"ad_agent: {domain} 탐색 시작 (시작 크레덴셜: {initial_username}, 최대 {MAX_ITERATIONS}회)")

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        domain=domain, dc_ip=dc_ip, username=initial_username, scope_hosts=", ".join(scope_hosts),
    )
    messages = [{"role": "user", "content": system_prompt}]

    for i in range(MAX_ITERATIONS):
        messages = _trim_messages(messages)
        response = call_with_tools(messages, tools=TOOLS, model=MODEL)
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "refusal":
            # judge_attempt()/exploit_doctor.py와 같은 이유(DESIGN.md 46/51절) -
            # 거부는 재시도해도 대개 또 거부되므로 바로 포기하고 사람에게 넘김.
            append_finding(engagement_id, stage="ad_agent", event="explore_refused", target=dc_ip)
            progress.warn("ad_agent: 안전 정책 거부(refusal) - 탐색 중단, 사람이 직접 확인 필요")
            return {"summary": "모델이 안전 정책으로 거부해서 자동 탐색을 진행할 수 없었음", "compromised_hosts": [], "refused": True}

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            break

        tool_results = []
        finished: dict | None = None
        for block in tool_uses:
            if block.name == "finish":
                finished = block.input
                tool_results.append({
                    "type": "tool_result", "tool_use_id": block.id,
                    "content": [{"type": "text", "text": "보고 접수함"}],
                })
                continue
            progress.info(f"ad_agent [{i + 1}/{MAX_ITERATIONS}] {block.name}({block.input.get('target', block.input.get('username', ''))})")
            content = _execute_tool(engagement_id, dc_ip, domain, block.name, block.input)
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": content})

        messages.append({"role": "user", "content": tool_results})

        if finished is not None:
            append_finding(
                engagement_id, stage="ad_agent", event="explore_complete", target=dc_ip,
                summary=finished.get("summary"), compromised_hosts=finished.get("compromised_hosts", []),
            )
            progress.info(f"ad_agent: 탐색 완료 - {finished.get('summary', '')}")
            return finished

    fallback = {
        "summary": f"{MAX_ITERATIONS}회 반복 안에 finish를 못 받음",
        "compromised_hosts": [],
    }
    append_finding(engagement_id, stage="ad_agent", event="explore_incomplete", target=dc_ip)
    return fallback


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 5:
        print("usage: python -m modules.ad_agent <engagement_id> <dc_ip> <domain> <username> [password]")
        sys.exit(1)

    eid, dc, dom, user = sys.argv[1:5]
    pw = sys.argv[5] if len(sys.argv) > 5 else None
    result = explore_and_move(eid, dc, dom, user, initial_password=pw)
    print(result)
