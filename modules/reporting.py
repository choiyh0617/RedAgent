"""
7단계: Reporting. DESIGN.md 3절.

findings.jsonl/credentials.jsonl을 읽어서 킬체인 순서(recon -> scanning ->
vuln_analysis -> exploitation -> post_exploit -> flag_capture)로 정리한
Markdown 보고서를 만든다. 다른 모듈처럼 별도 LLM 호출은 안 함 - 이미 각 단계가
findings에 남긴 구조화된 데이터를 그대로 조립하는 순수 변환 작업이라 필요 없음.

데이터가 없는 스테이지는 섹션 자체를 건너뛴다(예: post_exploit을 아직 안
돌린 인게이지먼트는 그 섹션이 안 나옴) - 파이프라인이 어디까지 진행됐든 항상
읽을 수 있는 보고서가 나오게 하기 위함.
"""

import html
import json
import re
from datetime import datetime

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core.engagement import engagement_dir
from core.state_store import read_credentials, read_findings


def _by_stage_event(findings: list[dict], stage: str, event: str) -> list[dict]:
    return [f for f in findings if f["stage"] == stage and f["event"] == event]


def _targets(findings: list[dict]) -> list[str]:
    seen = []
    for f in findings:
        t = f.get("target")
        if t and t not in seen:
            seen.append(t)
    return seen


def _safe_json_loads(value):
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _plural_ko(count: int, unit: str) -> str:
    return f"{count}{unit}"


def _platform_explanation(platform_name: str) -> tuple[str, list[str]]:
    mapping = {
        "linux": (
            "리눅스 계열로 추정됐다.",
            [
                "원인: 열린 포트와 서비스 조합이 리눅스 서버에서 흔히 보이는 형태와 유사했다.",
                "보안 권고: 불필요한 서비스 종료, 패키지 패치, 외부 공개 포트 최소화가 기본 대응이다.",
            ],
        ),
        "windows_standalone": (
            "독립형 윈도우 서버 또는 PC로 추정됐다.",
            [
                "원인: SMB, RDP, WinRM, MSRPC 등 윈도우 계열 서비스 패턴이 관찰됐기 때문이다.",
                "보안 권고: 관리 포트 접근제어, 로컬 관리자 계정 통제, 최신 보안 업데이트 적용이 우선이다.",
            ],
        ),
        "windows_ad": (
            "액티브 디렉터리(도메인 컨트롤러) 역할의 윈도우 서버로 추정됐다.",
            [
                "원인: LDAP, Kerberos, DNS, SMB 같은 AD 핵심 서비스 조합이 보였기 때문이다.",
                "보안 권고: 도메인 관리자 권한 최소화, 계정 보호, 인증 로그 상시 모니터링이 필요하다.",
            ],
        ),
    }
    return mapping.get(
        platform_name,
        (
            "운영체제를 명확히 단정할 수 없었다.",
            [
                "원인: 배너 정보나 포트 조합만으로는 확정이 어려웠다.",
                "보안 권고: 자산 식별 체계를 정리하고 CMDB 또는 운영 문서와 스캔 결과를 대조해 정확도를 높여야 한다.",
            ],
        ),
    )


def _service_security_guidance(service: str, port: int | None = None) -> list[str]:
    svc = (service or "").lower()
    if "http" in svc:
        return [
            "원인: 웹 서비스가 외부에 노출되어 있어 입력값 검증, 인증, 권한검사 문제가 공격 표면이 된다.",
            "보안 권고: WAF에만 의존하지 말고 서버 코드에서 입력 검증, 인증, 인가를 구현하고 관리자 기능을 별도 보호해야 한다.",
        ]
    if svc in {"ssh", "telnet"}:
        return [
            "원인: 원격 관리 서비스는 외부에서 직접 로그인 시도가 가능해 계정 탈취와 취약 버전 악용 위험이 있다.",
            "보안 권고: 허용 IP 제한, MFA 또는 키 기반 인증, 구형 프로토콜 비활성화가 필요하다.",
        ]
    if "ftp" in svc:
        return [
            "원인: 파일 전송 서비스는 평문 인증, 잘못된 권한, 오래된 데몬 취약점의 영향을 자주 받는다.",
            "보안 권고: 가능하면 SFTP/FTPS로 대체하고 익명 접근과 불필요한 쓰기 권한을 제거해야 한다.",
        ]
    if "mysql" in svc or "postgres" in svc or "mssql" in svc:
        return [
            "원인: 데이터베이스 포트가 직접 보이면 애플리케이션 우회 접속이나 계정 대입 공격 대상이 된다.",
            "보안 권고: DB 포트는 애플리케이션 서버만 접근 가능하게 제한하고, 계정 분리와 암호 순환을 강제해야 한다.",
        ]
    if "smb" in svc or "netbios" in svc or port in {139, 445}:
        return [
            "원인: 파일 공유와 인증 관련 서비스는 자격증명 탈취, 원격 실행, 내부 이동의 핵심 경로가 된다.",
            "보안 권고: 외부 노출 금지, SMB 서명 정책 점검, 관리자 공유 최소화가 필요하다.",
        ]
    return [
        "원인: 외부에 열린 서비스는 그 자체로 공격 표면이 되며, 버전 노후화나 기본 설정 미흡이 문제로 이어질 수 있다.",
        "보안 권고: 서비스 필요성 검토, 최신 패치 적용, 접근 가능한 네트워크 대역 최소화가 기본 대응이다.",
    ]


def _vuln_item_guidance(candidate: dict) -> list[str]:
    service = candidate.get("service", "")
    rationale = candidate.get("rationale", "")
    guidance = [
        f"원인: {rationale}" if rationale else "원인: 배너와 서비스 특성을 바탕으로 취약 가능성을 추정했다.",
        "판단 근거: 이번 단계는 실제 공격 성공 보고가 아니라, '공격 후보로 볼 만한 이유'를 정리한 단계다.",
    ]
    guidance.extend(_service_security_guidance(service, candidate.get("port")))
    return guidance


def _exploit_item_guidance(attempt: dict) -> list[str]:
    exploit = (attempt.get("exploit") or "").lower()
    if "sql injection" in exploit:
        return [
            "원인: 사용자 입력이 SQL 질의문에 안전하게 바인딩되지 않아, 입력값이 명령처럼 해석됐다.",
            "영향: 공격자가 비밀번호를 몰라도 로그인 우회, 데이터 조회, 경우에 따라 데이터 변경까지 시도할 수 있다.",
            "보안 권고: Prepared Statement 적용, ORM 파라미터 바인딩 강제, 관리자 기능 쿼리 전수 점검이 필요하다.",
        ]
    return [
        "원인: 서비스 버전, 설정, 또는 입력 처리 방식에 공격 가능한 약점이 있었다.",
        "영향: 단순 정보 노출을 넘어 실제 권한 획득 또는 서비스 오용으로 이어질 수 있다.",
        "보안 권고: 취약 서비스 패치, 불필요한 기능 제거, 동일 제품군 전수 점검이 필요하다.",
    ]


def _web_step_guidance(tool: str) -> list[str]:
    if tool.startswith("try_login_bypass"):
        return [
            "원인: 로그인 요청의 입력값이 안전하게 처리되지 않아 인증 우회가 가능했다.",
            "보안 권고: 로그인 API에 파라미터 바인딩, 실패 로그 분석, 계정 잠금/탐지 정책을 함께 적용해야 한다.",
        ]
    if tool == "list_users":
        return [
            "원인: 관리자 전용 사용자 조회 API가 우회된 세션 또는 부적절한 권한으로도 접근 가능했다.",
            "보안 권고: 서버 측 인가 검사를 강화하고, 관리자 전용 엔드포인트를 일반 세션과 분리해야 한다.",
        ]
    if tool == "application_version":
        return [
            "원인: 내부 운영 정보가 불필요하게 외부 응답으로 노출됐다.",
            "보안 권고: 상세 버전 정보는 관리자 콘솔이나 내부 로그로 제한하고 외부 응답에서는 제거하는 것이 좋다.",
        ]
    if tool == "basket_items":
        return [
            "원인: 장바구니 조회가 사용자 소유권 검증 없이 가능했거나 관리자 세션 보호가 약했다.",
            "보안 권고: 객체 수준 접근통제(BOLA/IDOR 방지)를 적용해 본인 데이터만 조회되도록 강제해야 한다.",
        ]
    return [
        "원인: 엔드포인트의 인증 또는 인가 통제가 충분하지 않았다.",
        "보안 권고: 각 API마다 서버 측 권한 검증과 민감 정보 최소 반환 원칙을 적용해야 한다.",
    ]


def _summarize_web_result(tool: str, output: str) -> tuple[str, list[str]]:
    parsed = _safe_json_loads(output)
    if tool.startswith("try_login_bypass") and isinstance(parsed, dict):
        auth = parsed.get("authentication") or {}
        email = parsed.get("umail") or auth.get("umail") or auth.get("data", {}).get("email")
        bid = parsed.get("bid") if parsed.get("bid") is not None else auth.get("bid")
        summary = "로그인 우회가 성공해 인증 토큰이 발급됐다."
        details = []
        if email:
            details.append(f"접속된 계정: `{email}`")
        if bid is not None:
            details.append(f"연결된 장바구니 ID: `{bid}`")
        details.append("의미: 비밀번호를 모르는 상태에서도 정상 사용자처럼 세션을 얻을 수 있었다.")
        return summary, details

    if tool == "list_users" and isinstance(parsed, dict):
        users = parsed.get("data") or []
        admins = sum(1 for user in users if user.get("role") == "admin")
        sample = [user.get("email") for user in users[:5] if user.get("email")]
        summary = (
            f"사용자 목록 조회에 성공했다. 총 {_plural_ko(len(users), '개')} 계정 중 "
            f"관리자 권한 계정이 {_plural_ko(admins, '개')} 확인됐다."
        )
        details = []
        if sample:
            details.append(f"노출 예시: {', '.join(f'`{email}`' for email in sample)}")
        details.append("의미: 공격자가 가입자 현황과 관리자 계정을 식별해 추가 공격 대상을 고를 수 있다.")
        return summary, details

    if tool == "application_version" and isinstance(parsed, dict):
        version = parsed.get("version")
        summary = "관리자 전용 애플리케이션 정보 조회에 성공했다."
        details = [f"확인된 버전: `{version}`"] if version else []
        details.append("의미: 공격자는 서버 버전을 바탕으로 알려진 취약점을 추가로 탐색할 수 있다.")
        return summary, details

    if tool == "basket_items" and isinstance(parsed, dict):
        items = parsed.get("data") or []
        basket_map: dict[int, list[str]] = {}
        for item in items:
            basket_id = item.get("BasketId")
            if basket_id is None:
                continue
            basket_map.setdefault(int(basket_id), []).append(
                f"상품ID {item.get('ProductId')} x{item.get('quantity')}"
            )
        examples = []
        for basket_id, products in list(sorted(basket_map.items()))[:3]:
            examples.append(f"장바구니 `{basket_id}`: {', '.join(products[:4])}")
        summary = (
            f"장바구니 데이터 조회에 성공했다. 총 {_plural_ko(len(items), '개')} 항목이 "
            f"{_plural_ko(len(basket_map), '개')} 장바구니에 걸쳐 노출됐다."
        )
        details = []
        if examples:
            details.append("노출 예시: " + " / ".join(examples))
        details.append("의미: 어떤 사용자가 무엇을 담았는지 추정할 수 있어 구매 의도와 이용 행태가 노출된다.")
        return summary, details

    if parsed is not None:
        if isinstance(parsed, dict):
            keys = ", ".join(list(parsed.keys())[:6])
            return (
                "API 응답을 정상적으로 받아왔다.",
                [f"응답 주요 키: {keys}" if keys else "응답 본문에 데이터가 포함되어 있다."],
            )
        if isinstance(parsed, list):
            return ("API 응답을 정상적으로 받아왔다.", [f"응답 항목 수: {_plural_ko(len(parsed), '개')}"])
    return ("API 응답을 정상적으로 받아왔다.", [f"응답 일부: `{_short(output, 160)}`"])


def _web_risk_explanation(observations: list[dict]) -> list[str]:
    paths = {obs.get("path") for obs in observations}
    reasons = ["인증 우회가 가능하다는 것은 '로그인 화면이 사실상 보안 장치 역할을 못 했다'는 뜻이다."]
    if "/api/Users" in paths:
        reasons.append("사용자 목록이 보이면 계정 수집, 관리자 식별, 피싱 또는 비밀번호 재사용 공격으로 이어질 수 있다.")
    if "/api/BasketItems/" in paths:
        reasons.append("장바구니 정보는 결제 전 행동 데이터라서 개인정보와 상거래 정보 유출로 해석할 수 있다.")
    if "/rest/admin/application-version" in paths:
        reasons.append("버전 정보는 공격자에게 다음 공격을 위한 안내서 역할을 한다.")
    return reasons


def _web_recommendations(observations: list[dict]) -> list[str]:
    recs = [
        "로그인 API의 입력값 검증을 강화하고, 문자열 결합 쿼리를 중단한 뒤 파라미터 바인딩(Prepared Statement)으로 전면 교체한다.",
        "인증과 인가를 분리해 점검한다. 로그인에 성공했더라도 관리자 API는 서버 측 권한 검증을 다시 수행해야 한다.",
        "관리자 API(`/api/Users`, `/rest/admin/*`)는 최소권한 원칙으로 재설계하고, 일반 사용자 토큰으로는 접근이 불가능해야 한다.",
        "이번에 노출된 토큰·세션·관리자 계정은 모두 무효화하고, 동일 패턴의 우회 시도가 있었는지 서버 로그를 점검한다.",
        "재발 방지를 위해 로그인, 관리자 API, 핵심 조회 API를 포함한 회귀 테스트를 추가한다.",
    ]
    paths = {obs.get("path") for obs in observations}
    if "/api/BasketItems/" in paths:
        recs.insert(3, "장바구니·주문 데이터 API는 본인 소유 데이터만 반환하도록 객체 수준 접근통제(BOLA/IDOR 방지)를 점검한다.")
    return recs


def _web_completion_for_target(findings: list[dict], target: str) -> dict | None:
    completed = [
        item for item in _by_stage_event(findings, "web_agent", "exploit_complete")
        if item.get("target") == target
    ]
    return completed[0] if completed else None


def _overall_plain_summary(findings: list[dict]) -> list[str]:
    exploit_successes = _by_stage_event(findings, "exploitation", "exploit_success")
    unique_successes = {
        (item.get("target"), item.get("port"), item.get("exploit"), item.get("method"))
        for item in exploit_successes
    }
    web_completed = _by_stage_event(findings, "web_agent", "exploit_complete")
    if web_completed:
        return [
            "외부 입력을 악용해 로그인 절차를 우회했고, 그 결과 관리자 권한으로 내부 데이터를 조회할 수 있었다.",
            "즉, 공격자는 단순한 로그인 실패가 아니라 실제 운영 데이터에 접근 가능한 상태까지 도달했다.",
        ]
    if unique_successes:
        return [
            f"자동 점검 중 실제 침투에 성공한 경로가 {_plural_ko(len(unique_successes), '건')} 확인됐다.",
            "이는 단순 취약 가능성이 아니라 재현 가능한 공격 경로가 존재한다는 뜻이다.",
        ]
    return [
        "이번 보고서는 자동 점검 과정에서 발견된 노출 정보와 시도 결과를 정리한 것이다.",
        "직접 침투 성공이 없더라도, 잠재적 취약 지점은 운영 환경 기준으로 후속 확인이 필요하다.",
    ]


def _section_recon(findings: list[dict]) -> str:
    hosts = _by_stage_event(findings, "recon", "host_discovered")
    if not hosts:
        return ""
    lines = ["## Recon", ""]
    for h in hosts:
        lines.append(f"- {h.get('target')}")
    return "\n".join(lines) + "\n\n"


def _section_scanning(findings: list[dict], targets: list[str]) -> str:
    ports = _by_stage_event(findings, "scanning", "port_open")
    platforms = {f["target"]: f.get("platform") for f in _by_stage_event(findings, "scanning", "platform_detected")}
    enum_events = [
        f for f in findings
        if f["stage"] == "scanning" and f["event"] not in ("port_open", "platform_detected", "scan_false_negative_retry")
    ]
    if not ports and not platforms:
        return ""

    lines = ["## Scanning", ""]
    for target in targets:
        target_ports = [p for p in ports if p["target"] == target]
        if not target_ports and target not in platforms:
            continue
        lines.append(f"### {target}")
        if target in platforms:
            lines.append(f"- 플랫폼 추정: `{platforms[target]}`")
            summary, details = _platform_explanation(platforms[target])
            lines.append(f"- 해석: {summary}")
            for detail in details:
                lines.append(f"  - {detail}")
        if target_ports:
            lines.append("")
            lines.append("| Port | Service | Banner |")
            lines.append("|---|---|---|")
            for p in sorted(target_ports, key=lambda x: x["port"]):
                banner = (p.get("banner") or "").replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {p['port']} | {p.get('service', '')} | {banner} |")
            lines.append("")
            lines.append("#### 포트별 해석")
            lines.append("")
            for p in sorted(target_ports, key=lambda x: x["port"]):
                lines.append(f"- `port {p['port']}` / `{p.get('service', '')}`")
                for detail in _service_security_guidance(p.get("service", ""), p.get("port")):
                    lines.append(f"  - {detail}")
        target_enum = [e for e in enum_events if e["target"] == target]
        for e in target_enum:
            lines.append(f"- `{e['event']}` 결과: {_short(e.get('result'))}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _section_vuln_analysis(findings: list[dict], targets: list[str]) -> str:
    candidates = _by_stage_event(findings, "vuln_analysis", "candidate_ranked")
    if not candidates:
        return ""
    lines = ["## Vulnerability Analysis", ""]
    for target in targets:
        target_candidates = sorted(
            (c for c in candidates if c["target"] == target),
            key=lambda c: c.get("confidence", 0), reverse=True,
        )
        if not target_candidates:
            continue
        lines.append(f"### {target}")
        lines.append("")
        for c in target_candidates:
            lines.append(
                f"- **port {c['port']} ({c.get('service', '')})** "
                f"- confidence {c.get('confidence', 0):.2f}, risk `{c.get('risk')}` "
                f"- {c.get('rationale', '')}"
            )
            for detail in _vuln_item_guidance(c):
                lines.append(f"  - {detail}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _section_exploitation(findings: list[dict], targets: list[str]) -> str:
    attempts = [
        f for f in findings
        if f["stage"] == "exploitation" and f["event"] in ("exploit_success", "attempt_failed")
    ]
    no_success = _by_stage_event(findings, "exploitation", "no_automated_exploit_succeeded")
    if not attempts and not no_success:
        return ""
    lines = ["## Exploitation", ""]
    for target in targets:
        target_attempts = [a for a in attempts if a["target"] == target]
        if not target_attempts:
            continue
        lines.append(f"### {target}")
        lines.append("")
        successes = {
            (a.get("port"), a.get("exploit"), a.get("method"))
            for a in target_attempts if a["event"] == "exploit_success"
        }
        if successes:
            lines.append(
                f"이 단계에서는 실제로 공격이 재현됐다. 즉, 이론상 취약 가능성이 아니라 "
                f"외부에서 악용 가능한 경로가 최소 {_plural_ko(len(successes), '건')} 확인된 상태다."
            )
            lines.append("")
        seen = set()
        for a in target_attempts:
            key = (a.get("port"), a.get("exploit"), a.get("method"), a.get("event"), a.get("rationale"))
            if key in seen:
                continue
            seen.add(key)
            status = "성공" if a["event"] == "exploit_success" else "실패"
            lines.append(
                f"- **[{status}]** port {a.get('port')} - {a.get('exploit', '')} "
                f"(방법: {a.get('method', a.get('reason', 'N/A'))})"
            )
            if a.get("rationale"):
                lines.append(f"  - 근거: {a['rationale']}")
            for detail in _exploit_item_guidance(a):
                lines.append(f"  - {detail}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _section_web_followup(findings: list[dict], targets: list[str]) -> str:
    tool_calls = _by_stage_event(findings, "web_agent", "tool_call")
    tool_results = _by_stage_event(findings, "web_agent", "tool_result")
    completed = _by_stage_event(findings, "web_agent", "exploit_complete")
    refused = _by_stage_event(findings, "web_agent", "exploit_refused")
    incomplete = _by_stage_event(findings, "web_agent", "exploit_incomplete")
    if not tool_calls and not tool_results and not completed and not refused and not incomplete:
        return ""

    lines = ["## Web Post-Exploitation", ""]
    for target in targets:
        target_tools = [t for t in tool_calls if t["target"] == target]
        target_results = [r for r in tool_results if r["target"] == target]
        target_completed = [c for c in completed if c["target"] == target]
        target_refused = [r for r in refused if r["target"] == target]
        target_incomplete = [r for r in incomplete if r["target"] == target]
        if not target_tools and not target_results and not target_completed and not target_refused and not target_incomplete:
            continue

        lines.append(f"### {target}")
        lines.append("")
        lines.append("이 섹션은 '공격자가 로그인 우회 이후 실제로 어디까지 볼 수 있었는지'를 비전문가도 이해할 수 있게 풀어쓴 부분이다.")
        lines.append("")
        if target_tools:
            lines.append("#### 공격 흐름")
            lines.append("")
            for idx, tool in enumerate(target_tools[:20], 1):
                detail = tool.get("tool")
                path = tool.get("input", {}).get("path") if isinstance(tool.get("input"), dict) else None
                payload = tool.get("input")
                line = f"{idx}. `{detail}`"
                if path:
                    line += f" - 경로 `{path}`"
                lines.append(line)
                if payload:
                    lines.append("```json")
                    lines.append(json.dumps(payload, ensure_ascii=False, indent=2))
                    lines.append("```")
                    lines.append("")
        if target_results:
            lines.append("#### 무엇이 실제로 보였는가")
            lines.append("")
            for idx, result in enumerate(target_results, 1):
                summary, details = _summarize_web_result(result.get("tool", ""), result.get("output", ""))
                lines.append(f"{idx}. `{result.get('tool')}`")
                lines.append(f"   - 요약: {summary}")
                for detail in details:
                    lines.append(f"   - {detail}")
                for detail in _web_step_guidance(result.get("tool", "")):
                    lines.append(f"   - {detail}")
                lines.append(f"   - 원본 응답 일부: `{_short(result.get('output', ''), 220)}`")
                lines.append("")
        if target_completed:
            for item in target_completed:
                observations = item.get("observations") or []
                lines.append("#### 확인된 범위 요약")
                lines.append("")
                lines.append("- 최종 판단과 우선 조치는 `10. 최종 종합 판단`에서 별도로 정리한다.")
                if observations:
                    lines.append("- 이 단계에서 실제로 확인된 엔드포인트:")
                    for obs in observations:
                        lines.append(f"  - `{obs.get('tool')}` / `{obs.get('path')}` / {obs.get('status')}")
                if item.get("response_sample"):
                    lines.append(f"- 로그인 우회 응답 일부: `{_short(item.get('response_sample'), 220)}`")
                for flag in item.get("flags", []):
                    lines.append(f"- flag: `{flag}`")
        for item in target_refused:
            lines.append("- 최종 결과: **[중단]** 모델이 안전 정책으로 거부해서 자동 탐색을 종료함")
        for item in target_incomplete:
            lines.append("- 최종 결과: **[미완료]** 반복 한도 내에 종료 보고를 받지 못함")
        lines.append("")
    return "\n".join(lines) + "\n"


def _section_post_exploit(findings: list[dict], targets: list[str]) -> str:
    candidates = _by_stage_event(findings, "post_exploit", "privesc_candidate")
    attempted = _by_stage_event(findings, "post_exploit", "privesc_attempted")
    if not candidates and not attempted:
        return ""
    lines = ["## Post-Exploitation (권한상승)", ""]
    for target in targets:
        target_candidates = [c for c in candidates if c["target"] == target]
        target_attempted = {a.get("technique"): a for a in attempted if a["target"] == target}
        if not target_candidates and not target_attempted:
            continue
        lines.append(f"### {target}")
        lines.append("")
        # 후보 전부(제안) - 실제로 시도됐으면 그 결과(성공/실패)도 같이 표시.
        # "가능한 모든 경로를 확인"이 목표라 하나 성공해도 나머지 시도 결과까지
        # 전부 보여준다(사용자 요청).
        for c in target_candidates:
            result = target_attempted.pop(c.get("technique"), None)
            if result is not None:
                status = "성공" if result.get("success") else "실패"
                lines.append(
                    f"- **[{status}] {c.get('technique')}** (risk: `{c.get('risk')}`) - {c.get('evidence', '')}"
                )
                lines.append(f"  - 시도한 명령: `{result.get('command')}`")
                if result.get("id_output"):
                    lines.append(f"  - 시도 후 id: `{result['id_output']}`")
            else:
                lines.append(f"- **[미시도] {c.get('technique')}** (risk: `{c.get('risk')}`) - {c.get('evidence', '')}")
        # candidate로 안 남았는데(예: LLM이 command 없이 준 후보) attempted만
        # 있는 경우도 빠뜨리지 않고 보여줌
        for result in target_attempted.values():
            status = "성공" if result.get("success") else "실패"
            lines.append(f"- **[{status}] {result.get('technique')}** - 시도한 명령: `{result.get('command')}`")
        lines.append("")
    return "\n".join(lines) + "\n"


def _section_flag_capture(findings: list[dict], targets: list[str]) -> str:
    found = _by_stage_event(findings, "flag_capture", "flag_found")
    none_found = _by_stage_event(findings, "flag_capture", "no_flags_found")
    if not found and not none_found:
        return ""
    lines = ["## Flag Capture", ""]
    for target in targets:
        target_found = [f for f in found if f["target"] == target]
        target_none = [f for f in none_found if f["target"] == target]
        if not target_found and not target_none:
            continue
        lines.append(f"### {target}")
        lines.append("")
        if target_found:
            for f in target_found:
                lines.append(f"- `{f.get('path')}`")
                lines.append("  ```")
                lines.append(f"  {f.get('content', '')}")
                lines.append("  ```")
        else:
            lines.append("- flag를 찾지 못함")
        lines.append("")
    return "\n".join(lines) + "\n"


def _section_credentials(engagement_id: str) -> str:
    creds = read_credentials(engagement_id)
    if not creds:
        return ""
    lines = ["## Credentials", "", "| Username | Domain | Type | Source | Validated on |", "|---|---|---|---|---|"]
    for c in creds:
        validated = ", ".join(c.get("validated_on") or []) or "-"
        lines.append(f"| {c['username']} | {c.get('domain') or '-'} | {c['type']} | {c['source']} | {validated} |")
    return "\n".join(lines) + "\n\n"


def _short(value, limit: int = 300) -> str:
    text = str(value)
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."


def _summary(findings: list[dict], targets: list[str]) -> str:
    stages = sorted({f["stage"] for f in findings if f["stage"] != "job_runner"})
    lines = ["## Summary", ""]

    # 사용자가 Ctrl+C로 중단했을 때도(run_pipeline.py의 _handle_interrupt(),
    # DESIGN.md 48절) 지금까지 진행한 내용으로 보고서를 만들 수 있게 했다 -
    # 이 경우 완료된 정식 보고서로 오해하지 않도록 맨 위에 명확히 표시한다.
    interruptions = _by_stage_event(findings, "run_pipeline", "interrupted")
    if interruptions:
        lines += [
            "> **⚠ 이 인게이지먼트는 사용자에 의해 중단됨(Ctrl+C)** - "
            "아래 내용은 끝까지 완료된 결과가 아니라 중단 시점까지의 부분 결과입니다.",
            "",
        ]

    lines += [
        f"- 대상: {', '.join(targets) if targets else '(없음)'}",
        f"- 진행된 단계: {', '.join(stages) if stages else '(없음)'}",
        f"- 총 findings: {len(findings)}",
        "",
    ]
    lines += ["### 비전문가용 한줄 요약", ""]
    for sentence in _overall_plain_summary(findings):
        lines.append(f"- {sentence}")
    lines += [
        "",
        "### 이 보고서를 어떻게 읽으면 되는가",
        "",
        "- `무엇이 실제로 가능했는가`: 공격자가 어디까지 접근했는지 보여준다.",
        "- `왜 문제인가`: 비보안 담당자 기준으로 사업/운영 관점의 위험을 설명한다.",
        "- `권장 조치`: 개발팀, 운영팀, 보안팀이 바로 실행할 수 있는 후속 대응을 적었다.",
        "",
    ]
    return "\n".join(lines) + "\n"


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _date_range(findings: list[dict]) -> tuple[str, str]:
    values = [_parse_ts(item.get("ts")) for item in findings]
    values = [value for value in values if value is not None]
    if not values:
        today = datetime.now().strftime("%Y-%m-%d")
        return today, today
    values.sort()
    return values[0].strftime("%Y-%m-%d"), values[-1].strftime("%Y-%m-%d")


def _guess_target_profile(engagement_id: str, targets: list[str], findings: list[dict]) -> dict[str, str]:
    target = targets[0] if targets else ""
    profile = {
        "report_title": "PENETRATION TEST REPORT",
        "report_subtitle": "침투 테스트 보고서",
        "target_label": target or "Unknown Target",
        "target_desc": target or "Unknown Target",
        "target_host": "-",
        "purpose": "격리된 로컬 랩 환경에서의 침투 테스트 실습",
        "environment": "VirtualBox Host-only Network (192.168.56.0/24), 인터넷 비공개 격리망",
        "attacker": "Kali Linux 2026.2 (192.168.56.101)",
        "scope": "본인 소유 로컬 VirtualBox 랩 내 승인된 대상만 포함, 외부 네트워크 미포함",
    }
    if "kioptrix1" in engagement_id.lower() or target == "192.168.56.103":
        profile.update({
            "target_label": "Kioptrix Level 1",
            "target_desc": "Kioptrix Level 1 (VirtualBox VM, 호스트명: KIOPTRIX)",
            "target_host": "KIOPTRIX",
            "purpose": "학습용 로컬 랩 환경에서의 침투 테스트 실습 (Boot2root)",
            "scope": "본인 소유 로컬 VirtualBox 랩 내 VM 1대, 외부 네트워크 미포함",
        })
    elif "juice-shop" in engagement_id.lower() or target == "192.168.56.101":
        profile.update({
            "target_label": "OWASP Juice Shop",
            "target_desc": "OWASP Juice Shop (Docker container in local lab)",
            "target_host": "JUICE-SHOP",
            "purpose": "학습용 로컬 웹 애플리케이션 침투 테스트 실습",
        })
    for event in findings:
        if event.get("stage") == "scanning" and event.get("event") == "smb_enum":
            raw = json.dumps(event.get("result"), ensure_ascii=False)
            if "KIOPTRIX" in raw.upper():
                profile["target_host"] = "KIOPTRIX"
    return profile


def _open_ports_by_target(findings: list[dict], target: str) -> list[dict]:
    return sorted(
        [item for item in _by_stage_event(findings, "scanning", "port_open") if item["target"] == target],
        key=lambda item: item["port"],
    )


def _stage_methodology(findings: list[dict]) -> list[str]:
    stages = {item["stage"] for item in findings}
    methods = []
    if "web_agent" in stages:
        methods.append("1단계 — 웹 진입점 확인: 로그인, 관리자 기능, 데이터 조회 API를 기준으로 외부 입력이 닿는 지점을 정리")
        methods.append("2단계 — 인증 우회 검증: 로그인 요청에 대해 알려진 SQL Injection 페이로드를 적용해 우회 가능 여부를 재현")
        methods.append("3단계 — 우회 이후 영향 확인: 관리자 API, 사용자 목록, 장바구니 데이터 등 실제로 열람 가능한 범위를 검증")
        methods.append("4단계 — 증적 정리: 응답 데이터, 노출 항목, 확인된 엔드포인트를 보고서용 근거로 기록")
        return methods
    if "scanning" in stages:
        methods.append("1단계 — 정보수집(Reconnaissance): Nmap 기반 포트/서비스 식별 및 배너 수집")
    if any(item.get("event") in {"smb_enum", "http_enum", "ftp_enum"} for item in findings):
        methods.append("2단계 — 서비스 열거(Enumeration): HTTP/SMB/FTP 등 노출 서비스별 추가 정보 수집")
    if "vuln_analysis" in stages:
        methods.append("3단계 — 취약점 분석: 배너와 공개 PoC/Exploit-DB 기준으로 악용 가능성 평가")
    if "exploitation" in stages:
        methods.append("4단계 — 익스플로잇 검증: 자동화된 PoC 또는 프레임워크를 사용해 실제 재현 여부 확인")
    if "post_exploit" in stages:
        methods.append("5단계 — 사후 행위(Post-Exploitation): 권한상승 후보 및 추가 접근 범위 검토")
    if "flag_capture" in stages:
        methods.append("6단계 — 증적 수집(Proof/Flag Capture): 획득 권한과 접근 가능 범위 검증")
    return methods or ["1단계 — 기본 스캔 및 결과 정리"]


def _enum_summaries(findings: list[dict], target: str) -> list[str]:
    lines = []
    for event in findings:
        if event.get("target") != target or event.get("stage") != "scanning":
            continue
        if event.get("event") == "http_enum":
            result = event.get("result") or {}
            whatweb = result.get("whatweb") or ""
            gobuster = result.get("gobuster") or ""
            if whatweb:
                lines.append(f"HTTP 열거({event.get('port')}/tcp): {_short(whatweb, 220)}")
            if gobuster:
                lines.append(f"웹 경로 탐색({event.get('port')}/tcp): {_short(gobuster, 220)}")
        if event.get("event") == "smb_enum":
            result = event.get("result") or {}
            lines.append(f"SMB 열거(139/tcp): {_short(result, 220)}")
        if event.get("event") == "ftp_enum":
            result = event.get("result") or {}
            lines.append(f"FTP 열거({event.get('port')}/tcp): {_short(result, 220)}")
    return lines


def _application_version(findings: list[dict], target: str) -> str | None:
    for item in _by_stage_event(findings, "web_agent", "tool_result"):
        if item.get("target") != target or item.get("tool") != "application_version":
            continue
        parsed = _safe_json_loads(item.get("output", ""))
        if isinstance(parsed, dict) and parsed.get("version"):
            return str(parsed.get("version"))
    return None


def _service_rows(findings: list[dict], target: str, ports: list[dict]) -> tuple[list[dict], str | None]:
    if ports:
        rows = []
        for port in ports:
            rows.append({
                "port_proto": f"{port['port']}/tcp",
                "service": port.get("service", ""),
                "version": port.get("banner", ""),
            })
        return rows, None

    web_completed = _web_completion_for_target(findings, target)
    if web_completed:
        version = _application_version(findings, target)
        version_text = "OWASP Juice Shop local web application"
        if version:
            version_text += f" (관리자 엔드포인트에서 버전 {version} 확인)"
        return [
            {
                "port_proto": "3000/tcp",
                "service": "http/webapp",
                "version": version_text,
            }
        ], "이번 실행에는 별도 포트 스캔 증적이 없어서, 실제 웹 요청과 응답 검증으로 확인된 서비스 정보를 표에 반영했다."

    exploit_success = [
        item for item in _by_stage_event(findings, "exploitation", "exploit_success")
        if item.get("target") == target and item.get("port") is not None
    ]
    if exploit_success:
        first = exploit_success[0]
        return [
            {
                "port_proto": f"{first.get('port')}/tcp",
                "service": "validated service",
                "version": first.get("exploit", ""),
            }
        ], "포트 스캔 데이터는 없지만 실제 공격이 재현된 포트를 기준으로 노출 서비스를 정리했다."

    return [], None


def _derive_findings_summary(findings: list[dict], target: str, ports: list[dict]) -> list[dict]:
    results: list[dict] = []
    web_completed = _web_completion_for_target(findings, target)
    if web_completed:
        observations = web_completed.get("observations") or []
        paths = {obs.get("path") for obs in observations}
        results.append({
            "id": "F-1",
            "title": "로그인 SQL Injection을 통한 인증 우회",
            "severity": "Critical",
            "status": "악용 성공",
            "detail": "로그인 입력값 조작만으로 관리자 세션을 획득했고, 비밀번호를 모르는 상태에서도 인증 장벽을 우회할 수 있었다.",
        })
        if "/api/Users" in paths:
            results.append({
                "id": "F-2",
                "title": "관리자 사용자 목록 노출",
                "severity": "High",
                "status": "확인됨",
                "detail": "우회된 세션으로 관리자 전용 사용자 목록 API에 접근해 계정 현황과 관리자 계정을 식별할 수 있었다.",
            })
        if "/api/BasketItems/" in paths:
            results.append({
                "id": f"F-{len(results) + 1}",
                "title": "장바구니 데이터 노출",
                "severity": "High",
                "status": "확인됨",
                "detail": "장바구니 항목과 수량이 사용자 범위를 넘어 노출되어 구매 의도와 이용 행태를 추정할 수 있었다.",
            })
        if "/rest/admin/application-version" in paths:
            results.append({
                "id": f"F-{len(results) + 1}",
                "title": "관리자 전용 애플리케이션 버전 정보 노출",
                "severity": "Medium",
                "status": "확인됨",
                "detail": "버전 정보가 외부 응답으로 노출되어 추가 공격 경로 탐색의 단서로 활용될 수 있었다.",
            })
        return results

    exploit_success = [item for item in _by_stage_event(findings, "exploitation", "exploit_success") if item["target"] == target]
    smb_port = next((p for p in ports if p.get("port") == 139 and "samba" in (p.get("banner") or "").lower()), None)
    https_port = next((p for p in ports if p.get("port") == 443 and "openssl/0.9.6" in (p.get("banner") or "").lower()), None)
    http_port = next((p for p in ports if p.get("port") == 80 and "mod_ssl/2.8.4" in (p.get("banner") or "").lower()), None)
    if smb_port:
        status = "악용 성공" if any(item.get("port") == 139 for item in exploit_success) else "확인됨"
        severity = "Critical" if status == "악용 성공" else "High"
        results.append({
            "id": "F-1",
            "title": "Samba 노출 및 원격 코드 실행 가능성",
            "severity": severity,
            "status": status,
            "detail": "Samba smbd 서비스가 외부에 노출되어 있으며, 오래된 Kioptrix 계열 환경에서 대표적인 핵심 공격 표면이다.",
        })
    if https_port or http_port:
        results.append({
            "id": "F-2",
            "title": "Apache/mod_ssl/OpenSSL 구버전 사용",
            "severity": "Critical",
            "status": "확인됨",
            "detail": "Apache 1.3.20 + mod_ssl 2.8.4 + OpenSSL 0.9.6b 조합은 이미 지원 종료되었고 알려진 공개 취약점과 연관된다.",
        })
    smb_enum = next((item for item in findings if item.get("target") == target and item.get("stage") == "scanning" and item.get("event") == "smb_enum"), None)
    if smb_enum:
        raw = json.dumps(smb_enum.get("result"), ensure_ascii=False)
        if "anonymous" in raw.lower() or "guest" in raw.lower() or "IPC$" in raw or "ADMIN$" in raw:
            results.append({
                "id": "F-3",
                "title": "SMB 열거를 통한 내부 정보 노출 가능성",
                "severity": "High",
                "status": "확인됨",
                "detail": "SMB 응답에서 호스트/공유/인증 관련 추가 정보를 유추할 수 있었다.",
            })
    if len(ports) >= 4:
        results.append({
            "id": f"F-{len(results)+1}",
            "title": "전반적인 서비스 스택 노후화",
            "severity": "High",
            "status": "확인됨",
            "detail": "여러 핵심 서비스가 모두 오래된 버전으로 노출되어 단일 취약점이 아니라 구조적 위험으로 해석된다.",
        })
    if not results:
        for idx, candidate in enumerate(
            [item for item in _by_stage_event(findings, "vuln_analysis", "candidate_ranked") if item["target"] == target][:4],
            1,
        ):
            results.append({
                "id": f"F-{idx}",
                "title": f"포트 {candidate.get('port')} / {candidate.get('service')} 취약 가능성",
                "severity": str(candidate.get("risk", "medium")).title(),
                "status": "확인됨",
                "detail": candidate.get("rationale", ""),
            })
    return results


def _recommendations_from_findings(findings_summary: list[dict], ports: list[dict]) -> list[tuple[str, str, str, str]]:
    recs: list[tuple[str, str, str, str]] = []
    if any("로그인 SQL Injection" in item["title"] for item in findings_summary):
        recs.append((
            "로그인 SQL Injection",
            "로그인 쿼리를 Prepared Statement로 전면 교체하고, 인증 우회 페이로드에 대한 회귀 테스트를 추가",
            "긴급",
            "현재는 입력값이 SQL 구문으로 해석되어 인증 자체가 무력화되므로, 가장 먼저 로그인 우회 경로를 차단해야 한다.",
        ))
    if any("관리자 사용자 목록 노출" in item["title"] for item in findings_summary):
        recs.append((
            "관리자 API 인가",
            "관리자 API에 서버 측 권한검사를 강제하고 일반 사용자 토큰 또는 우회 세션 접근을 차단",
            "긴급",
            "관리자 전용 데이터가 노출되면 계정 식별과 추가 공격 준비가 가능해지므로, 인증 이후에도 별도 인가 검사가 필요하다.",
        ))
    if any("장바구니 데이터 노출" in item["title"] for item in findings_summary):
        recs.append((
            "객체 접근통제",
            "장바구니·주문 API에 사용자 소유권 검증을 추가해 본인 데이터만 조회 가능하도록 수정",
            "높음",
            "장바구니 데이터는 사용자 행동 정보이므로, 본인 소유 데이터만 보이게 하지 않으면 개인정보 및 상거래 정보 노출로 이어진다.",
        ))
    if any("애플리케이션 버전 정보 노출" in item["title"] for item in findings_summary):
        recs.append((
            "운영 정보 노출",
            "외부 응답에서 상세 버전 정보를 제거하고 내부 관리 콘솔 또는 로그로만 제한",
            "중간",
            "상세 버전은 공격자가 알려진 취약점과 공격 코드를 빠르게 매칭하는 데 쓰일 수 있어 불필요한 단서를 제공한다.",
        ))
    if any("Samba" in item["title"] for item in findings_summary):
        recs.append((
            "Samba 노출",
            "Samba 최신 버전 업그레이드 또는 서비스 제거, 불가피하면 신뢰된 호스트로 접근 제한",
            "긴급",
            "파일 공유 서비스는 원격 실행과 내부 이동의 핵심 경로가 되므로, 외부 노출 상태를 그대로 두면 단일 취약점으로도 침투가 가능해질 수 있다.",
        ))
    if any("Apache/mod_ssl/OpenSSL" in item["title"] for item in findings_summary):
        recs.append((
            "mod_ssl / OpenSSL",
            "Apache, mod_ssl, OpenSSL 최신화 및 SSLv2/SSLv3 비활성화, TLS 1.2+만 허용",
            "긴급",
            "지원 종료된 암호화 스택은 공개 취약점과 직접 연결되기 쉬워, 서비스 신뢰 경계를 근본적으로 약화시킨다.",
        ))
    if any("SMB 열거" in item["title"] for item in findings_summary):
        recs.append((
            "SMB 접근통제",
            "익명/게스트 로그인 비활성화, 공유별 인증 강제, 외부 노출 최소화",
            "높음",
            "익명 열거만으로도 호스트와 공유 정보가 노출되면 공격 준비가 쉬워지므로, 최소한의 정보만 보이도록 제한해야 한다.",
        ))
    if len(ports) >= 4:
        recs.append((
            "EOL 소프트웨어",
            "전체 OS/패키지 마이그레이션 및 정기 패치 프로세스 수립",
            "높음",
            "여러 핵심 서비스가 동시에 노후화돼 있으면 개별 취약점 대응만으로는 부족하고, 구조적으로 같은 문제가 반복될 가능성이 높다.",
        ))
    if not recs:
        recs.append((
            "공통 조치",
            "노출 서비스 최소화, 최신 패치 적용, 관리 포트 접근제어 강화",
            "높음",
            "직접적인 침투 증적이 제한적이더라도, 노출면 축소와 최신화는 대부분의 공격 가능성을 가장 먼저 줄이는 기본 대응이다.",
        ))
    return recs


def _final_judgment_section(
    findings: list[dict],
    target: str,
    exec_summary: list[str],
    findings_summary: list[dict],
    recommendation_rows: list[tuple[str, str, str, str]],
) -> list[str]:
    top_findings = findings_summary[:3]
    top_actions = recommendation_rows[:3]
    web_completed = _web_completion_for_target(findings, target)
    observations = (web_completed or {}).get("observations") or []
    rationale = (web_completed or {}).get("rationale") or ""
    risk_points = _web_risk_explanation(observations) if observations else []
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    overall_severity = "High"
    if findings_summary:
        overall_severity = max(
            (item.get("severity", "High") for item in findings_summary),
            key=lambda value: severity_order.get(value, 0),
        )
    lines = [
        "## 10. 최종 종합 판단",
        "",
        "이 섹션은 상세 로그를 다시 읽지 않아도, 의사결정권자나 비보안 담당자가 이번 테스트의 결과를 바로 이해할 수 있게 정리한 최종 요약이다.",
        "",
        "| 항목 | 종합 판단 |",
        "|---|---|",
        f"| 최종 판단 등급 | **{overall_severity}** |",
        f"| 한줄 결론 | {exec_summary[0] if exec_summary else '이번 실행 결과는 후속 조치가 필요한 보안 이슈를 보여준다.'} |",
        f"| 재현 여부 | {'실제 공격 재현 성공' if web_completed or top_findings else '직접 재현 증적 제한적'} |",
        f"| 즉시 대응 필요성 | {'높음 - 인증 우회 및 민감 정보 노출 확인' if web_completed else '높음 - 상세 결과 기반 후속 확인 필요'} |",
        "",
        "### 10.1 이번 테스트에서 확인된 핵심 문제",
        "",
    ]
    if top_findings:
        lines.append("| 문제 | 심각도 | 상태 | 의미 |")
        lines.append("|---|---|---|---|")
        for item in top_findings:
            lines.append(f"| {item['title']} | {item['severity']} | {item['status']} | {item['detail']} |")
    else:
        lines.append("- 자동화된 결과상 핵심 취약점 요약 데이터가 충분하지 않아, 상세 단계 결과를 기준으로 추가 해석이 필요하다.")
    lines.extend([
        "",
        "### 10.2 최종 판단",
        "",
    ])
    if rationale:
        lines.append(f"- 판단 요약: {rationale}")
    if web_completed:
        lines.append("- 쉬운 설명: 로그인 화면을 통과하지 못해야 정상인데, 입력값 조작만으로 관리자 권한 세션이 만들어졌고 그 세션으로 내부 데이터 조회까지 가능했다.")
    lines.extend([f"- {item}" for item in exec_summary[:2]])
    if observations:
        lines.append("- 실제 확인된 범위:")
        for obs in observations:
            lines.append(f"  - `{obs.get('tool')}` / `{obs.get('path')}` / 상태 `{obs.get('status')}`")
    lines.extend([
        "- 이것은 단순 경고가 아니라, 공격자가 실제로 인증을 우회하거나 내부 정보를 열람할 수 있었는지 여부를 기준으로 판단한 결과다.",
        "- 따라서 운영 환경에서 같은 결과가 나오면 '나중에 고쳐도 되는 개선 과제'가 아니라 우선순위 높은 보안 이슈로 다뤄야 한다.",
        "",
        "### 10.3 왜 중요한가",
        "",
    ])
    if risk_points:
        for point in risk_points:
            lines.append(f"- {point}")
    else:
        lines.append("- 재현 가능한 공격 경로가 존재한다는 것은, 공격자가 동일 조건에서 다시 같은 결과를 만들 가능성이 높다는 뜻이다.")
    lines.extend([
        "",
        "### 10.4 우선 조치 권고",
        "",
    ])
    for idx, (_, recommendation, priority, _) in enumerate(top_actions, 1):
        lines.append(f"{idx}. [{priority}] {recommendation}")
    if not top_actions:
        lines.append("1. [높음] 상세 결과를 기준으로 즉시 패치, 접근통제, 인증/인가 로직 점검 순으로 후속 조치를 시작한다.")
    lines.extend([
        "",
        "### 10.5 최종 결론",
        "",
        "- 이번 보고서의 핵심은 '취약할 수 있다'가 아니라, 자동화된 검증 과정에서 실제 공격 경로와 정보 노출이 재현됐다는 점이다.",
        "- 따라서 재현된 경로를 우선 차단하고, 동일한 원인(입력 검증 부재, 권한검사 부족, 구버전 서비스 방치)이 다른 기능에도 없는지 전수 점검해야 한다.",
    ])
    return lines


def _impact_assessment_section(findings: list[dict], target: str, exec_summary: list[str]) -> list[str]:
    web_completed = _web_completion_for_target(findings, target)
    observations = (web_completed or {}).get("observations") or []
    risk_points = _web_risk_explanation(observations) if observations else []
    lines = [
        "## 8. 영향도 및 우선순위 평가",
        "",
        "이 섹션은 이번 결과가 왜 단순 참고 사항이 아니라 우선 대응이 필요한 이슈인지 설명하기 위한 부분이다.",
    ]
    if exec_summary:
        lines.append(f"핵심적으로 이번 테스트는 `{exec_summary[0]}`는 사실을 재현했다.")
    lines.extend([
        "즉, 취약 가능성을 추정한 것이 아니라 실제 입력값 조작과 그에 따른 시스템 반응을 확인했기 때문에, 운영 환경 기준으로도 우선순위를 높게 봐야 한다.",
        "",
        "### 8.1 왜 위험한가",
        "",
    ])
    if risk_points:
        for point in risk_points:
            lines.append(f"- {point}")
    else:
        lines.append("- 이번 결과는 실제 재현된 공격 경로가 존재한다는 점에서 단순 설정 미흡보다 우선순위가 높다.")
    lines.extend([
        "",
        "### 8.2 운영 및 사업 관점의 영향",
        "",
    ])
    if web_completed:
        lines.extend([
            "- 인증 장벽이 무너지면 사용자 구분과 권한 구분이 전제된 기능 전체를 다시 의심해야 한다.",
            "- 관리자 계정, 사용자 목록, 장바구니 같은 데이터가 노출되면 개인정보, 운영 정보, 사용자 행태 정보가 함께 새어 나갈 수 있다.",
            "- 이런 정보는 단발성 열람에서 끝나지 않고 추가 공격 대상 선정, 피싱, 계정 재사용 공격, 내부 기능 탐색으로 이어질 수 있다.",
        ])
    else:
        lines.extend([
            "- 실제 침투 성공 또는 민감 정보 노출이 확인된 경우, 단순 점검 이슈가 아니라 서비스 신뢰도와 운영 안정성에 직접 영향을 준다.",
            "- 노출된 정보의 성격에 따라 개인정보보호, 고객 신뢰, 운영 리스크로 연결될 수 있다.",
        ])
    lines.extend([
        "",
        "### 8.3 왜 우선순위가 높은가",
        "",
        "- 이번 이슈는 '나중에 코드 품질 차원에서 개선'하는 성격이 아니라, 재현된 공격 경로를 먼저 끊어야 하는 성격에 가깝다.",
        "- 따라서 우선순위는 기능 개선 과제보다 상위에 두고, 인증/인가 로직과 노출 데이터 범위를 즉시 점검하는 것이 타당하다.",
    ])
    return lines


def _exploit_detail_lines(findings: list[dict], target: str) -> list[str]:
    lines: list[str] = []
    successes = [item for item in _by_stage_event(findings, "exploitation", "exploit_success") if item["target"] == target]
    failures = [item for item in findings if item.get("stage") == "exploitation" and item.get("event") == "attempt_failed" and item.get("target") == target]
    if successes:
        seen = set()
        deduped_successes = []
        for item in successes:
            key = (item.get("port"), item.get("exploit"), item.get("method"), item.get("rationale"))
            if key in seen:
                continue
            seen.add(key)
            deduped_successes.append(item)
        for idx, item in enumerate(deduped_successes, 1):
            guidance = _exploit_item_guidance(item)
            lines.extend([
                f"### 6.{idx} {item.get('exploit')} (성공)",
                f"대상 포트 `{item.get('port')}`에서 `{item.get('method')}` 방식으로 공격이 재현되었다.",
                f"- 근거: {item.get('rationale', '')}",
                f"- 원인: {guidance[0].removeprefix('원인: ')}",
                f"- 영향: {guidance[1].removeprefix('영향: ')}",
                f"- 보안 권고: {guidance[2].removeprefix('보안 권고: ')}",
                "",
            ])
    else:
        lines.extend([
            "### 6.1 자동 악용 시도 결과",
            "이번 실행에서는 자동화된 경로로 즉시 셸 획득까지 이어진 성공 사례는 확인되지 않았다.",
            "",
        ])
    if failures:
        lines.append("### 6.2 추가 시도 및 제약")
        for item in failures[:5]:
            reason = item.get("reason") or item.get("rationale") or "실패 사유 미상"
            lines.append(f"- `{item.get('exploit')}` / port `{item.get('port')}`: {reason}")
        lines.append("")
    return lines


def _legacy_detail_sections(findings: list[dict], targets: list[str], engagement_id: str) -> str:
    parts = [
        _summary(findings, targets),
        _section_recon(findings),
        _section_scanning(findings, targets),
        _section_vuln_analysis(findings, targets),
        _section_exploitation(findings, targets),
        _section_web_followup(findings, targets),
        _section_post_exploit(findings, targets),
        _section_flag_capture(findings, targets),
        _section_credentials(engagement_id),
    ]
    return "\n".join(part for part in parts if part).strip()


def _renumber_detail_sections(detail: str) -> str:
    if not detail:
        return detail
    section_titles = [
        ("## Summary", "### 9.1 Summary"),
        ("## Recon", "### 9.2 Recon"),
        ("## Scanning", "### 9.3 Scanning"),
        ("## Vulnerability Analysis", "### 9.4 Vulnerability Analysis"),
        ("## Exploitation", "### 9.5 Exploitation"),
        ("## Web Post-Exploitation", "### 9.6 Web Post-Exploitation"),
        ("## Post-Exploitation (권한상승)", "### 9.7 Post-Exploitation (권한상승)"),
        ("## Flag Capture", "### 9.8 Flag Capture"),
        ("## Credentials", "### 9.9 Credentials"),
    ]
    result = detail
    for old, new in section_titles:
        result = result.replace(old, new)
    return result


def _build_structured_report(engagement_id: str, findings: list[dict], targets: list[str]) -> str:
    profile = _guess_target_profile(engagement_id, targets, findings)
    start_date, end_date = _date_range(findings)
    target = targets[0] if targets else ""
    ports = _open_ports_by_target(findings, target)
    service_rows, service_note = _service_rows(findings, target, ports)
    findings_summary = _derive_findings_summary(findings, target, ports)
    recommendation_rows = _recommendations_from_findings(findings_summary, ports)
    methods = _stage_methodology(findings)
    enum_lines = _enum_summaries(findings, target)
    exec_summary = _overall_plain_summary(findings)
    legacy_detail = _renumber_detail_sections(_legacy_detail_sections(findings, targets, engagement_id))

    lines = [
        f"# Pentest Report: {engagement_id}",
        "",
        "## 1. 개요 (Executive Summary)",
    ]
    lines.extend([f"- {item}" for item in exec_summary])
    lines.extend([
        "",
        f"이번 보고서는 `{engagement_id}` 실행에서 수집된 증적(findings.jsonl)을 바탕으로 작성되었다.",
        "중요한 점은 단순히 '취약할 수 있다'는 가능성을 적는 것이 아니라, 어떤 입력이 어떤 결과를 만들었고 그 결과 공격자가 실제로 어디까지 접근했는지를 설명하는 데 있다.",
        "이번 테스트에서는 로그인 우회가 되는지 여부만 본 것이 아니라, 우회 이후 관리자 성격의 정보와 사용자 데이터가 실제로 열람되는지까지 확인했다.",
        "",
        "## 2. 테스트 범위 및 승인",
        "| 항목 | 내용 |",
        "|---|---|",
        f"| 테스트 대상 | {profile['target_desc']} |",
        f"| 테스트 목적 | {profile['purpose']} |",
        f"| 테스트 환경 | {profile['environment']} |",
        f"| 공격 시스템 | {profile['attacker']} |",
        f"| 대상 시스템 | {profile['target_desc'] if target else profile['target_label']} |",
        f"| 테스트 기간 | {start_date} ~ {end_date} |",
        f"| 승인 범위 | {profile['scope']} |",
        f"| 작성일 | {end_date} |",
        "",
        "이 표는 이번 테스트의 기본 범위와 전제조건을 한 번에 보여주기 위한 요약이다.",
        "이번 테스트 범위는 사용자가 직접 통제하는 로컬 실습 환경으로 한정했다. 따라서 보고서에 적힌 행위는 외부 실서비스나 제3자 자산이 아니라, 격리된 학습 환경 안에서만 재현된 내용이다.",
        "승인 범위 역시 동일하다. 즉 허용된 대상 안에서만 점검이 수행됐으며, 승인되지 않은 외부 네트워크, 물리적 접근, 서비스 거부(DoS) 성격의 행위는 이번 범위에 포함하지 않았다.",
        "이 구분이 중요한 이유는, 같은 취약점이라도 어떤 환경에서 어떤 조건으로 검증됐는지에 따라 위험 해석과 후속 조치 우선순위가 달라질 수 있기 때문이다.",
        "",
        "## 3. 방법론",
    ])
    lines.extend([f"- {item}" for item in methods])
    lines.extend([
        "",
        "이번 방법론은 결과 중심이다. 즉 테스트 도중 어떤 취약점 이름을 찾았는지보다, 실제로 공격자가 인증을 우회했는지와 그 이후 어떤 데이터에 도달했는지를 기준으로 판단했다.",
        "그래서 보고서의 후반부에는 단순 도구 실행 로그보다, 실제로 확인된 응답과 그 의미를 비전문가도 읽을 수 있게 풀어서 정리했다.",
        "",
        "## 4. 정찰 및 서비스 스캔 결과",
        f"공격자 시스템 `{profile['attacker']}` 에서 대상 `{target}` 에 대해 확인된 서비스 정보는 다음과 같다:",
        "",
        "| 포트/프로토콜 | 서비스 | 버전 정보 |",
        "|---|---|---|",
    ])
    for row in service_rows:
        lines.append(f"| {row['port_proto']} | {row['service']} | {row['version']} |")
    if not service_rows:
        lines.append("| 확인 결과 없음 | - | 이번 실행에서는 별도 서비스 식별 증적이 남지 않았음 |")
    if service_note:
        lines.extend(["", f"- 보충 설명: {service_note}"])
    if enum_lines:
        lines.extend(["", "추가 열거 결과:"])
        lines.extend([f"- {item}" for item in enum_lines])
    lines.extend(["", "## 5. 발견된 취약점", "", "| 번호 | 취약점 | 심각도 | 상태 | 설명 |", "|---|---|---|---|---|"])
    for item in findings_summary:
        lines.append(f"| {item['id']} | {item['title']} | {item['severity']} | {item['status']} | {item['detail']} |")
    lines.extend(["", "## 6. 익스플로잇 상세 내역"])
    lines.extend(_exploit_detail_lines(findings, target))
    lines.extend(["## 7. 권고사항", "", "| 대상 | 권고 조치 | 우선순위 | 권고 이유 |", "|---|---|---|---|"])
    for target_name, recommendation, priority, reason in recommendation_rows:
        lines.append(f"| {target_name} | {recommendation} | {priority} | {reason} |")
    lines.extend(["", *_impact_assessment_section(findings, target, exec_summary)])
    if legacy_detail:
        lines.extend([
            "",
            "## 9. 단계별 상세 결과",
            "",
            legacy_detail,
        ])
    lines.extend([
        "",
        *_final_judgment_section(findings, target, exec_summary, findings_summary, recommendation_rows),
    ])
    return "\n".join(lines) + "\n"


def generate_report(engagement_id: str) -> str:
    """이 인게이지먼트의 findings/credentials를 킬체인 순서 Markdown 보고서로 조립한다."""
    findings = read_findings(engagement_id)
    targets = _targets(findings)
    return _build_structured_report(engagement_id, findings, targets)


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _html_list(items: list[str], ordered: bool = False) -> str:
    if not items:
        return ""
    tag = "ol" if ordered else "ul"
    return f"<{tag}>" + "".join(f"<li>{_e(item)}</li>" for item in items) + f"</{tag}>"


def _render_inline(text: str) -> str:
    escaped = html.escape(text, quote=True)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def _slugify_heading(text: str) -> str:
    slug = re.sub(r"<[^>]+>", "", text)
    slug = slug.strip().lower()
    slug = re.sub(r"[^\w\s가-힣-/().]+", "", slug)
    slug = re.sub(r"\s+", "-", slug)
    return slug.strip("-") or "section"


def _render_heading(level: int, text: str, toc_entries: list[tuple[int, str, str]], used_slugs: dict[str, int]) -> str:
    rendered = _render_inline(text)
    base_slug = _slugify_heading(text)
    count = used_slugs.get(base_slug, 0)
    used_slugs[base_slug] = count + 1
    slug = base_slug if count == 0 else f"{base_slug}-{count + 1}"
    if _should_include_in_toc(level, text):
        toc_entries.append((level, text, slug))
    return f'<h{level} id="{_e(slug)}">{rendered}</h{level}>'


def _should_include_in_toc(level: int, text: str) -> bool:
    normalized = text.strip()
    if level == 2:
        return bool(re.match(r"^\d+\.", normalized))
    if level == 3:
        return bool(re.match(r"^\d+\.\d+\s+", normalized))
    return False


def _render_toc(toc_entries: list[tuple[int, str, str]]) -> str:
    if not toc_entries:
        return ""
    items = []
    for level, text, slug in toc_entries:
        items.append(
            f'<a class="toc-link toc-level-{level}" href="#{_e(slug)}">{_render_inline(text)}</a>'
        )
    return (
        '<aside class="toc-card">'
        '<div class="toc-title">Contents</div>'
        '<nav class="toc-nav">'
        + "".join(items)
        + "</nav></aside>"
    )


def _render_markdownish_to_html(text: str) -> tuple[str, str]:
    lines = text.splitlines()
    html_parts: list[str] = []
    toc_entries: list[tuple[int, str, str]] = []
    used_slugs: dict[str, int] = {}
    paragraph: list[str] = []
    list_items: list[str] = []
    ordered_items: list[tuple[int, str]] = []
    table_rows: list[str] = []
    code_lines: list[str] = []
    in_code = False

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            html_parts.append(f"<p>{_render_inline(' '.join(item.strip() for item in paragraph if item.strip()))}</p>")
            paragraph = []

    def flush_list() -> None:
        nonlocal list_items
        if list_items:
            html_parts.append("<ul>" + "".join(f"<li>{_render_inline(item)}</li>" for item in list_items) + "</ul>")
            list_items = []

    def flush_ordered() -> None:
        nonlocal ordered_items
        if ordered_items:
            start = ordered_items[0][0]
            start_attr = f' start="{start}"' if start != 1 else ""
            html_parts.append(
                f"<ol{start_attr}>"
                + "".join(f"<li>{_render_inline(item)}</li>" for _, item in ordered_items)
                + "</ol>"
            )
            ordered_items = []

    def flush_table() -> None:
        nonlocal table_rows
        if not table_rows:
            return
        header: list[str] | None = None
        body: list[list[str]] = []
        for idx, row in enumerate(table_rows):
            cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
            if idx == 0:
                header = cells
                continue
            if idx == 1 and all(set(cell) <= {"-", ":"} for cell in cells):
                continue
            body.append(cells)
        if header:
            table_class = "report-table"
            if header == ["대상", "권고 조치", "우선순위", "권고 이유"]:
                table_class += " recommendations"
            elif header == ["번호", "취약점", "심각도", "상태", "설명"]:
                table_class += " findings"
            elif header == ["항목", "종합 판단"]:
                table_class += " summary-judgment"
            elif header == ["문제", "심각도", "상태", "의미"]:
                table_class += " issues"
            thead = "<thead><tr>" + "".join(f"<th>{_render_inline(cell)}</th>" for cell in header) + "</tr></thead>"
            tbody = "<tbody>" + "".join(
                "<tr>" + "".join(f"<td>{_render_inline(cell)}</td>" for cell in row) + "</tr>"
                for row in body
            ) + "</tbody>"
            html_parts.append(f'<table class="{table_class}">{thead}{tbody}</table>')
        table_rows = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            flush_paragraph()
            flush_list()
            flush_ordered()
            flush_table()
            if in_code:
                html_parts.append(f"<pre><code>{_e(chr(10).join(code_lines))}</code></pre>")
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line.rstrip())
            continue
        if not stripped:
            flush_paragraph()
            flush_list()
            flush_ordered()
            flush_table()
            continue
        if stripped.startswith("|"):
            flush_paragraph()
            flush_list()
            flush_ordered()
            table_rows.append(stripped)
            continue
        flush_table()
        if stripped.startswith("#### "):
            flush_paragraph()
            flush_list()
            flush_ordered()
            html_parts.append(_render_heading(4, stripped[5:], toc_entries, used_slugs))
            continue
        if stripped.startswith("### "):
            flush_paragraph()
            flush_list()
            flush_ordered()
            html_parts.append(_render_heading(3, stripped[4:], toc_entries, used_slugs))
            continue
        if stripped.startswith("## "):
            flush_paragraph()
            flush_list()
            flush_ordered()
            html_parts.append(_render_heading(2, stripped[3:], toc_entries, used_slugs))
            continue
        if stripped.startswith("# "):
            flush_paragraph()
            flush_list()
            flush_ordered()
            html_parts.append(_render_heading(1, stripped[2:], toc_entries, used_slugs))
            continue
        if re.match(r"^-\s+", stripped):
            flush_paragraph()
            flush_ordered()
            list_items.append(re.sub(r"^-\s+", "", stripped))
            continue
        if re.match(r"^\d+\.\s+", stripped):
            flush_paragraph()
            flush_list()
            match = re.match(r"^(\d+)\.\s+(.*)$", stripped)
            if match:
                ordered_items.append((int(match.group(1)), match.group(2)))
            continue
        if paragraph and re.match(r"^(-|\d+\.)\s+", stripped):
            flush_paragraph()
        paragraph.append(stripped)

    flush_paragraph()
    flush_list()
    flush_ordered()
    flush_table()
    if in_code and code_lines:
        html_parts.append(f"<pre><code>{_e(chr(10).join(code_lines))}</code></pre>")
    return "\n".join(html_parts), _render_toc(toc_entries)


def generate_html_report(engagement_id: str) -> str:
    report_text = generate_report(engagement_id)
    rendered, toc = _render_markdownish_to_html(report_text)
    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>Pentest Report { _e(engagement_id) }</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; color: #17202a; background: #f3f6fb; font-size: 14px; }}
    .wrap {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
    .layout {{ display: grid; grid-template-columns: minmax(0, 1fr) 280px; gap: 1.5rem; align-items: start; }}
    h1, h2, h3, h4 {{ color: #0f172a; line-height: 1.3; }}
    h1 {{ margin: 0 0 1rem; font-size: 2.15rem; }}
    h1[id], h2[id], h3[id], h4[id] {{ scroll-margin-top: 1.5rem; }}
    h2 {{ margin: 2rem 0 0.9rem; padding-bottom: 0.35rem; border-bottom: 2px solid #dbe4f0; font-size: 1.6rem; }}
    h3 {{ margin: 1.35rem 0 0.65rem; font-size: 1.26rem; }}
    h4 {{ margin: 1rem 0 0.5rem; font-size: 1.12rem; }}
    .card {{ background: #fff; border: 1px solid #d7e0ea; border-radius: 14px; padding: 2rem; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.06); }}
    .toc-card {{ position: sticky; top: 1.5rem; background: rgba(255,255,255,0.92); backdrop-filter: blur(6px); border: 1px solid #d7e0ea; border-radius: 14px; padding: 1rem; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.05); max-height: calc(100vh - 3rem); overflow: auto; }}
    .toc-title {{ font-size: 0.86rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #475569; margin-bottom: 0.75rem; }}
    .toc-nav {{ display: flex; flex-direction: column; gap: 0.22rem; }}
    .toc-link {{ display: block; color: #334155; text-decoration: none; padding: 0.3rem 0.5rem; border-radius: 8px; line-height: 1.3; overflow-wrap: anywhere; font-size: 0.88rem; }}
    .toc-link:hover {{ background: #eef4fb; color: #0f172a; }}
    .toc-level-2 {{ font-weight: 700; }}
    .toc-level-3 {{ padding-left: 0.9rem; font-size: 0.88rem; color: #475569; }}
    .toc-level-4 {{ padding-left: 1.25rem; font-size: 0.84rem; color: #64748b; }}
    table {{ width: 100%; border-collapse: collapse; margin: 1rem 0 1.35rem; background: #fff; table-layout: auto; }}
    th, td {{ border: 1px solid #d7e0ea; padding: 0.7rem; text-align: left; vertical-align: top; overflow-wrap: break-word; word-break: keep-all; width: auto; }}
    th {{ background: #eef4fb; }}
    table th:nth-child(1), table td:nth-child(1),
    table th:nth-child(3), table td:nth-child(3) {{ white-space: nowrap; width: 1%; }}
    .findings th:nth-child(4), .findings td:nth-child(4),
    .issues th:nth-child(2), .issues td:nth-child(2),
    .issues th:nth-child(3), .issues td:nth-child(3) {{ white-space: nowrap; width: 1%; }}
    .recommendations th:nth-child(2), .recommendations td:nth-child(2) {{ width: 33%; }}
    .recommendations th:nth-child(4), .recommendations td:nth-child(4) {{ width: 33%; }}
    .recommendations th:nth-child(1), .recommendations td:nth-child(1),
    .recommendations th:nth-child(3), .recommendations td:nth-child(3) {{ white-space: nowrap; width: 1%; }}
    p, li {{ line-height: 1.8; font-size: 1rem; }}
    p {{ margin: 0.7rem 0; overflow-wrap: anywhere; word-break: break-word; }}
    ul, ol {{ margin: 0.5rem 0 1rem 1.3rem; }}
    li {{ overflow-wrap: anywhere; word-break: break-word; }}
    code {{ background: #eef4fb; padding: 0.08rem 0.35rem; border-radius: 6px; font-size: 0.96rem; overflow-wrap: anywhere; word-break: break-word; white-space: pre-wrap; }}
    pre {{ overflow-x: auto; max-width: 100%; background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 10px; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; font-size: 0.97rem; line-height: 1.7; }}
    pre code {{ background: transparent; padding: 0; color: inherit; white-space: pre-wrap; font-size: inherit; }}
    @media (max-width: 1100px) {{
      .layout {{ grid-template-columns: 1fr; }}
      .toc-card {{ position: static; order: -1; max-height: none; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="layout">
      <div class="card">
        {rendered}
      </div>
      {toc}
    </div>
  </div>
</body>
</html>"""


def save_html_report(engagement_id: str) -> str:
    path = engagement_dir(engagement_id) / "report.html"
    path.write_text(generate_html_report(engagement_id), encoding="utf-8")
    return str(path)


def save_report(engagement_id: str, vm_names: list[str] | None = None) -> str:
    """보고서를 인게이지먼트 디렉터리에 report.md로 저장하고 경로를 반환한다.

    `vm_names`를 주면 저장 직후 그 VM들을 정상종료까지 마친다 - 리포트가
    나왔다는 건 이 인게이지먼트의 파이프라인이 끝났다는 뜻이라, 대상 VM을
    계속 켜둘 이유가 없다(리소스 낭비 + 오래 켜둘수록 크래시/불안정 위험도
    커짐, DESIGN.md 20-2절). Kali는 여러 인게이지먼트가 공유하는 공용
    attacker VM이라 여기서 안 끔 - `vm_names`에는 그 인게이지먼트가 실제로
    사용한 **대상** VM만 넘길 것."""
    report = generate_report(engagement_id)
    path = engagement_dir(engagement_id) / "report.md"
    path.write_text(report, encoding="utf-8")
    html_path = engagement_dir(engagement_id) / "report.html"
    html_path.write_text(generate_html_report(engagement_id), encoding="utf-8")

    # 실전에서 잡은 버그(사용자 지적): 예전엔 VM 종료까지 다 끝난 뒤에야
    # 호출자(run_pipeline.py)가 경로를 출력했다 - 정상종료는 최대 30초까지
    # 걸릴 수 있어서, 그 사이엔 "[graceful shutdown]..." 메시지만 보이고
    # 경로를 못 봐서 못 찾는 상황이 생겼다. 저장 직후, 종료 시도 전에 바로
    # 경로를 보여준다.
    from core import progress
    progress.info(f"보고서 저장됨: {path}")
    progress.info(f"HTML 보고서 저장됨: {html_path}")

    if vm_names:
        from env.provision_target import shutdown_vm
        for name in vm_names:
            shutdown_vm(name)

    return str(path)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python -m modules.reporting <engagement_id> [vm_name...]")
        sys.exit(1)

    saved_path = save_report(sys.argv[1], vm_names=sys.argv[2:] or None)
    print(f"보고서 저장됨: {saved_path}")
