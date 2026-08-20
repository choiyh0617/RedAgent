"""
전체 킬체인 오케스트레이터. DESIGN.md 30절.

대상 하나에 대해 (VM 기동+도달성 확인) -> recon(scope 등록) -> scanning ->
vuln_analysis -> exploitation -> post_exploit -> flag_capture -> reporting을
순서대로 실행한다. 각 단계는 이미 실전 검증된 모듈 함수를 그대로 호출할 뿐
새 로직을 추가하지 않는다 - 이 파일이 하는 일은 순서 배선 + `core.progress`로
진행상황을 보여주는 것뿐.

README의 수동 사용법은 0단계(랩 네트워크 준비)/1단계(대상 VM 임포트+기동)를
recon 이전에 사람이 직접 한다고 가정하는데, 오케스트레이터는 그 중 **VM
기동+도달성 확인**까지는 자동으로 한다(임포트 자체는 안 함 - vmdk 경로를
몰라서 매번 다르고, 보통 한 번만 하는 작업이라 오케스트레이터 책임 밖으로
둠). `vm_name`을 주면 꺼져있을 때 자동으로 켜고, 대상이 ping에 응답할 때까지
기다린다.

**주의**: 이 오케스트레이터 자체는 아직 실전 end-to-end 테스트를 못 했다
(개별 단계 함수들은 전부 검증됐지만, 이렇게 이어붙인 전체 흐름을 한 번에
돌려본 적은 없음 - DESIGN.md 30절 TODO 참고).

post_exploit/flag_capture는 **Metasploit 경로로 성공한 경우에만** 실행한다 -
둘 다 msfconsole -x 세션을 이어받아야 해서 PoC 스크립트로 얻은 셸에는 못 쓴다
(shell_manager.py의 알려진 한계와 같음). Metasploit 모듈/포트는 exploitation.py가
findings.jsonl에 남긴 `exploit_success` 이벤트의 `method`/`port` 필드에서
다시 읽어온다(exploitation.py의 ExploitAttempt 자체엔 method가 없어서 -
이미 검증된 exploitation.py 코드를 건드리지 않으려고 findings를 통해 우회함).

**정책 변경(사용자 요청)**: "가능한 모든 취약점을 분석하는 게 목표"라는 방침에
따라, 예전처럼 첫 성공에서 멈추지 않는다.
  - `exploit_target()`을 `stop_at_first_success=False`로 호출 - 랭킹된 후보를
    전부 시도한다(exploitation.py 기본값도 이제 False로 바뀜).
  - Metasploit로 성공한 **모든** 경로에 대해 post_exploit(linpeas 분석 +
    권한상승 후보 전부 실제 시도)을 반복한다 - 예전엔 첫 성공 경로 하나만 썼음.
  - flag_capture는 대상 파일시스템 전체를 훑는 거라 경로(어떤 포트로
    들어갔는지)와 무관하게 결과가 같으므로, 성공한 경로 중 아무거나 하나로
    한 번만 실행한다(반복해도 같은 flag만 또 찾을 뿐이라 낭비).

사용법:
  python run_pipeline.py                                   # 대화형 - 등록된 VM 목록에서 골라서 실행
  python run_pipeline.py <target_ip> [vm_name] [--label 라벨]   # 스크립팅/자동화용
"""

import re
import sys
import time

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core import progress
from core.engagement import new_engagement_id
from core.state_store import read_findings
from env.health_check import check_target_reachability, ensure_kali_running
from env.provision_target import is_running, start_target_vm
from modules.reporting import save_report

TOTAL_STAGES = 9  # Web Post-Exploitation(SQLi 있을 때만 도는 조건부 단계) 포함 - 없을 땐 8/9로 살짝 덜 채워진 채 끝남(과도하게 넘치는 것보단 나음)
VM_BOOT_SERVICE_GRACE_SEC = 60  # ping 성공 이후 서비스 초기화를 더 기다리는 시간 - 실측 근거는 아래 run_pipeline() 주석 참고

# Juice Shop 같은 대상은 VM이 아니라 Kali 안의 Docker 컨테이너라서(DESIGN.md
# 38절) 위 VM 목록엔 아예 안 잡힌다 - 사용자 지적("juice shop 같은 건 kali
# docker에 있다며. 그거도 다 보여줘야 할거 같은데")으로 인터랙티브 메뉴에
# 별도 섹션으로 추가. IP/포트가 이미 고정돼 있어(Kali 자신의 hostonly IP에
# 바인딩) VM 기동이나 MAC 기반 IP 탐색이 필요 없다.
DOCKER_TARGETS = [
    {
        "label": "Juice Shop",
        "ip": "192.168.56.101",
        "port": 3000,
        "login_path": "/rest/user/login",
        "login_body": {"email": "test@test.com", "password": "x"},
        "local_only": True,
    },
]

_METHOD_MODULE_RE = re.compile(r"^Metasploit\((.+)\)$")


def _find_all_msf_successes(engagement_id: str, target: str) -> list[tuple[str, int]]:
    """exploitation.py가 findings에 남긴 exploit_success 이벤트 중, Metasploit
    경로로 성공한 **전부**의 (module, port) 목록을 반환한다(중복 (module,port)
    제거) - "가능한 모든 경로를 확인"하는 게 목표라 하나만 쓰지 않는다."""
    seen: set[tuple[str, int]] = set()
    results: list[tuple[str, int]] = []
    for f in read_findings(engagement_id):
        if f["stage"] != "exploitation" or f["event"] != "exploit_success" or f["target"] != target:
            continue
        m = _METHOD_MODULE_RE.match(f.get("method") or "")
        if m:
            key = (m.group(1), f["port"])
            if key not in seen:
                seen.add(key)
                results.append(key)
    return results


def _clear_orphaned_sessions_if_any() -> None:
    """guestcontrol orphan 세션이 쌓여있으면 정리한다.

    실전에서 잡은 버그(Kioptrix1 반복 검증 중 발견): searchsploit 조회가
    "Error starting guest session", "VERR_DUPLICATE", "session terminated"
    같은 VBoxManage 에러로 무더기 실패했는데, 메모리/부하는 정상이었고
    원인은 **orphan guestcontrol 세션 9개 누적**이었다 - VirtualBox의 동시
    세션 개수 제한에 걸려서 새 세션 요청 자체가 거부된 것. ensure_kali_running()
    은 VM 상태/게스트 응답성만 보고 이 케이스는 못 잡는다(응답은 되니까) -
    별도로 확인/정리한다."""
    from env.guest_control import close_all_sessions
    from env.health_check import check_orphaned_sessions

    orphaned = check_orphaned_sessions()
    if orphaned > 0:
        progress.warn(f"orphan guestcontrol 세션 {orphaned}개 발견 - 정리 중")
        close_all_sessions()
        progress.info("세션 정리 완료")


def _handle_interrupt(engagement_id: str | None, vm_name: str | None) -> None:
    """Ctrl+C(KeyboardInterrupt) 중단 시 무작정 죽지 않고 안전 처리 선택지를
    준다(사용자 요청: "사용중에 종료나 홀드하고 싶을 수 있잖아") - 그냥 죽으면
    대상 VM이 켜진 채로 방치되거나 게스트 쪽 job이 orphan으로 남을 수 있다.

    "이어서 진행"은 같은 파이썬 프로세스가 끊긴 스테이지 중간부터 재개하는 게
    아니다(예: 스캔 도중 끊으면 스캔 자체는 다음에 처음부터 다시 함) - 대신
    env.host_power.hold()로 VM을 savestate(RAM 상태 그대로 디스크에 저장)해서
    다음에 VM 부팅 자체는 건너뛸 수 있게 하는 방식이다."""
    if engagement_id:
        from core.state_store import append_finding
        # 리포트 생성 여부와 무관하게 항상 남긴다(감사 기록) - reporting.py가
        # 이 이벤트를 보고 "부분 결과"라는 경고를 보고서 맨 위에 붙인다(48절).
        append_finding(engagement_id, stage="run_pipeline", event="interrupted", target=vm_name)

    print("\n\n⚠ 중단 감지됨 (Ctrl+C). 어떻게 할까요?")
    print("  1) 안전하게 홀드 - VM을 일시정지(savestate)하고 나중에 이어서 진행 (기본값)")
    print("  2) 완전 종료 - 대상 VM 끄고 나가기")
    print("  3) 그냥 나가기 (VM은 켜진 채로 둠)")
    try:
        choice = input("번호 입력 (기본 1, Enter): ").strip() or "1"
    except (KeyboardInterrupt, EOFError):
        choice = "3"
        print("\n(재중단 감지 - 정리 없이 바로 종료)")

    if choice == "1":
        from env.host_power import hold
        print("[run_pipeline] VM 홀드 중...")
        if hold():
            print(
                "[run_pipeline] 완료. 나중에 이어서 하려면:\n"
                "  1) python -c \"from env.host_power import resume; resume()\"  (VM 복원)\n"
                "  2) python run_pipeline.py  (다시 실행 - 스캔 등은 처음부터 다시 돌지만 VM 부팅은 건너뜀)"
            )
        else:
            print("[run_pipeline] 홀드 실패 - python -m env.health_check로 직접 상태 확인 필요")
    elif choice == "2":
        if vm_name:
            from env.provision_target import shutdown_vm
            print(f"[run_pipeline] {vm_name} 완전 종료 중...")
            shutdown_vm(vm_name, graceful_timeout=30)
        else:
            print("[run_pipeline] 대상 VM 이름을 몰라서 종료 못 함(Kali 안의 Docker 대상 등)")
    else:
        print("[run_pipeline] VM 상태 그대로 둠 - 나중에 python -m env.health_check로 확인하세요.")

    _offer_partial_report(engagement_id)

    if engagement_id:
        print(f"[run_pipeline] 인게이지먼트 {engagement_id} (findings.jsonl 확인 가능)")
    sys.exit(130)  # 유닉스 관례: 128 + SIGINT(2)


def _offer_partial_report(engagement_id: str | None) -> None:
    """중단 시점까지 진행한 내용만으로도 보고서를 만들지 물어본다(사용자 요청).
    engagement_id가 아직 없으면(파이프라인 진입 전, 즉 findings가 하나도 없는
    상태에서 중단) 물어볼 것 자체가 없다."""
    if not engagement_id:
        return
    try:
        answer = input("지금까지 진행한 내용으로 보고서를 만들까요? (Y/n): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        answer = "n"
    if answer in ("n", "no"):
        print("[run_pipeline] 보고서 생성 건너뜀")
        return

    from modules.reporting import save_report
    # vm_names=None - VM 처리(홀드/완전종료/그대로 둠)는 위에서 이미 선택했으므로
    # save_report()가 별도로 또 종료를 시도하지 않게 한다(특히 "홀드"를 골랐으면
    # savestate된 VM을 save_report()가 다시 shutdown_vm으로 끄면 안 됨).
    path = save_report(engagement_id, vm_names=None)
    print(f"[run_pipeline] 부분 보고서 저장됨: {path}")


def run_pipeline(target: str, vm_name: str | None = None, label: str = "pipeline") -> str:
    """대상 하나에 대해 전체 킬체인을 실행하고 engagement_id를 반환한다."""
    progress.start_pipeline(TOTAL_STAGES)
    engagement_id = new_engagement_id(label)
    progress.info(f"engagement: {engagement_id}, target: {target}")

    try:
        return _run_pipeline_stages(engagement_id, target, vm_name)
    except KeyboardInterrupt:
        _handle_interrupt(engagement_id, vm_name)


def _run_pipeline_stages(engagement_id: str, target: str, vm_name: str | None) -> str:
    from modules.exploitation import _kali_ip, capture_privesc_proof, exploit_target
    from modules.flag_capture import search_and_capture_flags
    from modules.post_exploit import analyze_privesc_candidates, attempt_privesc_candidates, run_linpeas_via_msf_session
    from modules.recon import write_scope
    from modules.scanning import scan_target
    from modules.vuln_analysis import analyze

    progress.stage("환경 확인 (VM 기동 + 도달성)")

    # 대상 VM의 IP 확인/도달성 체크(_resolve_target_ip, check_target_reachability)가
    # 전부 run_in_kali()로 Kali "안에서" 실행되므로, Kali 자신이 꺼져있거나
    # 응답불능이면 이 시점부터 전부 낮은 레벨의 VBoxManage 에러나 "IP를 못 찾음"
    # 같은 헷갈리는 메시지로 실패한다 - 진짜 원인(Kali가 꺼져있음)을 사람이
    # 유추해야 했음(사용자 지적: "kali가 죽어있을 수도 있잖아"). job_runner.py의
    # start_job()은 이미 이 체크를 하지만, IP 해석 단계는 그걸 안 거쳐서
    # 사각지대였다 - 여기서 제일 먼저 확인/필요시 자동 재기동한다.
    if not ensure_kali_running(auto_restart=True):
        # 재시도까지 다 실패했을 때만 마지막 수단으로 setup_doctor를 부른다
        # (사용자 요청: "프로그램 사용중에 셋업닥터가 필요할 때 불려지도록
        # 고쳐") - 매번 쓰기엔 비용/시간이 크고(에이전틱 툴콜 루프, 항상
        # 종량제 API), 이미 ensure_kali_running() 자체가 표준 재기동을
        # 시도했으니 그걸로 안 풀린 경우만 원인이 매번 다른 클래스의 문제
        # (DESIGN.md 33절)라서 진짜로 에이전틱 진단이 필요한 지점이다 -
        # 이게 이 프로젝트의 "전환 포인트" 기준(1절)에 실제로 해당하는 첫
        # 자동 호출임(그동안은 사람이 수동으로만 불렀음, DESIGN.md 50절).
        progress.warn("kali가 응답하지 않음 - setup_doctor로 자동 진단 시도(시간이 걸릴 수 있음)")
        from env.guest_control import KALI_VM
        from env.setup_doctor import diagnose
        diagnosis = diagnose(engagement_id, KALI_VM, "guestcontrol이 응답하지 않고 표준 재기동도 실패함")
        progress.info(f"진단: {diagnosis['root_cause']} (고침: {diagnosis['fixed']})")
        if not diagnosis["fixed"] or not ensure_kali_running(auto_restart=False):
            raise RuntimeError(
                f"kali 복구 실패 - setup_doctor 진단: {diagnosis.get('next_steps', '수동 확인 필요')}"
            )
    progress.info("kali 정상 확인됨")
    _clear_orphaned_sessions_if_any()

    freshly_started = False
    if vm_name:
        if is_running(vm_name):
            progress.info(f"{vm_name} 이미 실행 중")
        else:
            progress.info(f"{vm_name} 꺼져있음 - 기동 시도")
            start_target_vm(vm_name)
            freshly_started = True
    reachable = check_target_reachability([target], retries=15, delay=10)
    if not reachable.get(target):
        if not vm_name:
            raise RuntimeError(f"{target}에 도달 불가 (VM 이름을 몰라서 setup_doctor로 진단 못 함)")
        progress.warn(f"{target} 도달 불가 - setup_doctor로 자동 진단 시도(시간이 걸릴 수 있음)")
        from env.setup_doctor import diagnose
        diagnosis = diagnose(
            engagement_id, vm_name, f"{target}에 ping이 안 됨 - VM 부팅/네트워크 문제로 추정"
        )
        progress.info(f"진단: {diagnosis['root_cause']} (고침: {diagnosis['fixed']})")
        reachable = check_target_reachability([target], retries=10, delay=10)
        if not reachable.get(target):
            raise RuntimeError(
                f"{target}에 도달 불가 (setup_doctor로도 해결 안 됨: {diagnosis.get('next_steps', '수동 확인 필요')})"
            )

    if freshly_started:
        # 실전에서 잡은 버그: ping은 커널 네트워크 스택이 뜨자마자 응답하지만,
        # 실제 취약한 서비스들(vsftpd/apache/mysql 등)은 SysV init 스크립트가
        # 순서대로 도는 옛날 이미지(Metasploitable2 등)에서 그보다 한참 늦게
        # 뜬다. 실측: VM 기동 34초 만에 ping은 성공했는데, 그 직후 바로 시작한
        # nmap -p- 풀스캔이 rpcbind(111)/rpc.statd 딱 2개만 찾고 나머지 28개
        # 서비스는 전부 놓쳤다 - nmap이 각 포트를 지나간 시점에 아직 안 떠있던
        # 것으로 추정(DESIGN.md 43절 재확인/45절). scanning.py의 "0 hosts up"
        # 재시도 로직은 "포트가 조금이라도 열려있으면" 정상으로 보므로 이 경우를
        # 못 잡는다 -> 방금 기동한 VM이면 스캔 시작 전에 여유 시간을 둔다.
        progress.info(f"{vm_name} 방금 기동함 - 서비스 초기화 대기 {VM_BOOT_SERVICE_GRACE_SEC}s")
        time.sleep(VM_BOOT_SERVICE_GRACE_SEC)

    progress.done(f"{target} 도달 확인")

    progress.stage("Recon (scope 등록)")
    write_scope([target])
    progress.done(f"{target}를 scope.yaml에 등록함")

    progress.stage(f"Scanning: {target}")
    scan_result = scan_target(engagement_id, target)
    progress.info(f"열린 포트 {len(scan_result['open_ports'])}개, 플랫폼 추정: {scan_result['platform']}")
    progress.done()

    progress.stage("Vulnerability Analysis")
    verdicts = analyze(engagement_id, target)
    progress.info(f"취약점 후보 {len(verdicts)}개 랭킹 완료")
    progress.done()

    progress.stage("Exploitation")
    attempts = exploit_target(engagement_id, target, vm_name=vm_name, stop_at_first_success=False)
    succeeded = [a for a in attempts if a.success]
    progress.info(f"시도 {len(attempts)}개(전부 시도, 첫 성공에서 안 멈춤), 성공 {len(succeeded)}개")

    # web_exploit.py(sqlmap --forms)가 그동안 run_pipeline.py에 안 끼워져 있었다
    # (사용자 지적: "여전히 익스플로잇 코드를 작성하지 못해서 플래그까지 가져온
    # 적이 없어" - 원인 조사 결과, Claude가 코드 작성을 거부해서가 아니라 애초에
    # 자동 흐름이 이 클래스의 취약점을 시도조차 안 하고 있었음). Kioptrix2의 실제
    # 알려진 공격 경로(로그인 폼 SQLi)가 정확히 이 종류인데, vuln_analysis.py
    # (searchsploit)/exploitation.py(Metasploit)는 CVE 번호가 없는 애플리케이션
    # 로직 결함이라 원천적으로 못 찾는다(exploitation.py 18절) - web_exploit.py
    # 는 sqlmap이라는 결정론적 도구를 쓰므로 LLM이 코드를 작성/거부할 여지 자체가
    # 없다. http(s) 계열 포트마다 자동으로 --forms 크롤링을 시도한다.
    # 실전에서 잡은 버그(Kioptrix1 검증 중 발견, DESIGN.md 55절): nmap이 SSL로
    # 감싼 HTTPS를 "ssl/http"가 아니라 "ssl/https"로 태그하는 경우가 있어서
    # (실측: 포트 443이 "ssl/https") 원래 튜플에 없던 태그라 그 포트가 아예
    # 스킵됐다 - 두 표기 다 포함하도록 방어적으로 넓힘.
    _WEB_SERVICE_TAGS = ("http", "https", "ssl/http", "ssl/https")
    web_sqli_found = 0
    web_ports = [p for p in scan_result["open_ports"] if p["service"] in _WEB_SERVICE_TAGS]
    web_sqli_leads = []  # (port, https, parameter) - Web Post-Exploitation 단계에서 씀
    if web_ports:
        from modules.web_exploit import probe_web_app
        progress.checklist_start([f"포트 {p['port']} ({p['service']}) - sqlmap --forms 크롤링" for p in web_ports])
        for i, p in enumerate(web_ports, 1):
            https = p["service"] in ("https", "ssl/http", "ssl/https")
            web_findings = probe_web_app(engagement_id, target, p["port"], https=https)
            web_sqli_found += len(web_findings)
            for wf in web_findings:
                web_sqli_leads.append((p["port"], https, wf.get("parameter", "")))
            label = f"SQLi {len(web_findings)}건" if web_findings else "확인 안 됨"
            progress.checklist_item(i, len(web_ports), f"포트 {p['port']} - {label}")
        progress.info(f"web_exploit(sqlmap --forms): 폼 기반 SQLi {web_sqli_found}건")
    progress.done()

    # SQLi "확인"에서 멈추지 않고 셸/플래그까지 이어본다(사용자 지적: "SQLi를
    # 찾은 건 성공이었는데 그 다음이 없었다" - Kioptrix2 실전 검증 중 발견,
    # DESIGN.md 60절). Metasploit 성공은 이미 오래전부터 post_exploit.py로
    # 이어졌는데, web_exploit.py의 SQLi 성공은 이어주는 다리가 아예 없었다 -
    # modules/web_agent.py(로그인 우회 -> 인증된 기능 탐색 -> 커맨드 인젝션 ->
    # 플래그, 에이전틱)로 연결. 로그인 폼은 보통 사이트 루트에 있어서
    # login_path="/"를 기본으로 씀(probe_web_app이 --crawl=1로 루트부터
    # 크롤링하므로 대체로 맞음 - 정확한 폼 URL을 sqlmap 결과에서 못 뽑아서
    # 근사한 것, 안 맞으면 web_agent가 fetch_authenticated_page로 직접
    # 둘러봄).
    if web_sqli_leads:
        from modules.web_agent import exploit_post_sqli
        progress.stage("Web Post-Exploitation (SQLi -> 셸/플래그)")
        for i, (port, https, param) in enumerate(web_sqli_leads, 1):
            progress.info(f"[{i}/{len(web_sqli_leads)}] 포트 {port} (파라미터 {param}) SQLi 후속 공격 시도")
            web_result = exploit_post_sqli(engagement_id, target, port, "/", param, https=https)
            status = "성공" if web_result.get("success") else "실패"
            progress.info(f"  {status} - {web_result.get('rationale', '')}")
            if web_result.get("flags"):
                progress.info(f"  flag {len(web_result['flags'])}개 발견: {web_result['flags']}")
        progress.done()

    msf_successes = _find_all_msf_successes(engagement_id, target)

    if msf_successes:
        kali_ip = _kali_ip()

        progress.stage("Post-Exploitation (권한상승)")
        for i, (module, port) in enumerate(msf_successes, 1):
            progress.info(f"[경로 {i}/{len(msf_successes)}] {module} (포트 {port})로 재접속해서 권한상승 분석")
            linpeas_output = run_linpeas_via_msf_session(engagement_id, target, module, port, kali_ip)
            candidates = analyze_privesc_candidates(engagement_id, target, linpeas_output)
            progress.info(f"  권한상승 후보 {len(candidates)}개 - 전부 실제 시도")
            attempts_result = attempt_privesc_candidates(engagement_id, target, module, port, kali_ip, candidates)
            succeeded_privesc = [r for r in attempts_result if r["success"]]
            progress.info(f"  시도 {len(attempts_result)}개, 성공 {len(succeeded_privesc)}개")
        progress.done(f"성공 경로 {len(msf_successes)}개 전부 분석 완료")

        progress.stage("Flag Capture")
        # flag는 대상 파일시스템 전체를 훑는 거라 어느 경로로 들어갔든 결과가
        # 같음 - 성공한 경로 중 첫 번째로 한 번만 실행(반복 실행은 낭비).
        module, port = msf_successes[0]
        flags = search_and_capture_flags(engagement_id, target, module, port, kali_ip)
        progress.info(f"flag {len(flags)}개 발견")
        if not flags:
            # Metasploitable2처럼 애초에 flag 파일이 없는 대상(59절 확인)에서도
            # "root는 확실히 땄다"는 증거는 남겨야 한다(사용자 요청) - id/hostname
            # 출력을 다시 받아서 이미지로 남긴다.
            progress.info("flag 없음 - 권한상승 증거 이미지 생성 중")
            proof_output = capture_privesc_proof(engagement_id, target, port, module, kali_ip)
            from modules.proof import generate_proof_image
            proof_path = generate_proof_image(engagement_id, target, f"Metasploit({module})", proof_output)
            progress.info(f"증거 이미지: {proof_path}")
        progress.done()
    else:
        progress.stage("Post-Exploitation (권한상승)")
        progress.warn("Metasploit 경로로 성공한 게 없어서 건너뜀 (PoC 성공만으론 세션을 못 이어받음)")

        progress.stage("Flag Capture")
        progress.warn("같은 이유로 건너뜀")

    progress.stage("Reporting")
    report_path = save_report(engagement_id, vm_names=[vm_name] if vm_name else None)
    progress.done(f"보고서: {report_path}")

    return engagement_id


def _resolve_target_ip(vm_name: str, retries: int = 15, delay: int = 10) -> str:
    """vm_name의 MAC 주소로 랩 서브넷을 스캔해서 실제 IP를 찾는다. DHCP가 VM을
    켤 때마다 다른 IP를 줄 수 있어서(Kioptrix2 실전에서 실제로 겪음 - VM 이름은
    아는데 IP는 매번 nmap으로 MAC 매칭해서 찾아야 했음, DESIGN.md 28절 근처
    작업 기록 참고), VM 이름만으로 대상 IP를 안전하게 얻는 방법."""
    from env.guest_control import run_in_kali
    from env.provision_target import get_mac_address
    from modules.recon import HOSTONLY_SUBNET

    mac = get_mac_address(vm_name)
    progress.info(f"{vm_name}의 MAC 주소: {mac} - 서브넷에서 매칭되는 IP 찾는 중")

    for _ in range(retries):
        result = run_in_kali(f"nmap -sn {HOSTONLY_SUBNET} 2>&1", timeout=40)
        for block in re.split(r"Nmap scan report for ", result.stdout)[1:]:
            ip = block.split()[0]
            if mac in block.upper():
                return ip
        time.sleep(delay)
    raise RuntimeError(f"{vm_name}(MAC {mac})의 IP를 {retries * delay}초 안에 못 찾음 - 부팅이 오래 걸리는 중일 수 있음")


def _run_docker_target(dt: dict) -> str:
    """Juice Shop 같은 Docker 대상 전용 경로 - VM 기동/MAC IP 탐색이 필요 없고
    (IP:포트가 이미 고정돼 있음), 일반 8단계 파이프라인(scanning/vuln_analysis/
    exploitation)을 그대로 태우지도 않는다. 이유: scanning.py로 Kali 자신의
    IP를 스캔하면 Juice Shop 컨테이너 포트뿐 아니라 Kali 자신의 다른 서비스
    (SSH, msfrpcd 등)까지 같이 잡혀서 결과가 지저분해지고(recon.py의
    KNOWN_NON_TARGETS가 애초에 이 IP를 자동 탐지에서 빼는 이유와 같음), 더
    중요하게는 vuln_analysis.py(searchsploit)/exploitation.py(Metasploit)가
    Juice Shop의 실제 취약점(로그인 SQLi 같은 애플리케이션 로직 결함, CVE
    번호가 없음)을 원천적으로 못 찾는다(DESIGN.md 18/38/39절) - "돌렸는데
    아무것도 안 나왔다"는 오해를 줄 뿐이다. 그래서 이 대상이 실제로 검증된
    경로(modules.web_exploit.probe_json_endpoint)로 바로 간다."""
    from modules.web_agent import exploit_post_sqli
    from modules.web_exploit import follow_up_juice_shop_sqli_local, probe_json_endpoint, probe_known_juice_shop_login_sqli_local
    from modules.reporting import save_report

    engagement_id = new_engagement_id(dt["label"].lower().replace(" ", "-"))
    progress.start_pipeline(3)  # Web Exploit + Web Post-Exploitation + Reporting
    progress.info(f"engagement: {engagement_id}, target: {dt['ip']}:{dt['port']} ({dt['label']})")
    progress.info(
        "이 대상은 VM이 아니라 Kali 안의 Docker 컨테이너라, 일반 8단계 파이프라인 대신 "
        "알려진 애플리케이션 취약점(로그인 SQLi)을 직접 확인합니다."
    )
    progress.stage(f"Web Exploit: {dt['login_path']}")
    if dt.get("local_only"):
        findings = probe_known_juice_shop_login_sqli_local(
            engagement_id,
            target=dt["ip"],
            port=dt["port"],
            path=dt["login_path"],
        )
    else:
        findings = probe_json_endpoint(
            engagement_id, dt["ip"], dt["port"], dt["login_path"], dt["login_body"],
        )
    if findings:
        progress.done(f"SQLi {len(findings)}건 확인됨")
    else:
        progress.warn("SQLi 확인 안 됨 (알려진 취약점 기준 - 다른 엔드포인트는 web_exploit.py로 직접 추가 확인 가능)")

    if findings:
        progress.stage("Web Post-Exploitation (SQLi -> 후속 탐색)")
        for i, finding in enumerate(findings, 1):
            param = finding.get("parameter", "")
            progress.info(f"[{i}/{len(findings)}] 파라미터 {param} 기준 후속 탐색 시작")
            if dt.get("local_only"):
                result = follow_up_juice_shop_sqli_local(
                    engagement_id,
                    target=dt["ip"],
                    port=dt["port"],
                    path=dt["login_path"],
                )
            else:
                result = exploit_post_sqli(
                    engagement_id,
                    dt["ip"],
                    dt["port"],
                    dt["login_path"],
                    param,
                    local_mode=False,
                )
            status = "성공" if result.get("success") else "실패"
            progress.info(f"  {status} - {result.get('rationale', '')}")
            if result.get("flags"):
                progress.info(f"  flag {len(result['flags'])}개 발견: {result['flags']}")
        progress.done()
    else:
        progress.stage("Web Post-Exploitation (SQLi -> 후속 탐색)")
        progress.warn("선행 SQLi 확인이 없어 건너뜀")

    progress.stage("Reporting")
    # vm_names=None - Kali는 여러 인게이지먼트가 공유하는 상시 attacker VM이라
    # 여기서 끄면 안 됨(Docker 컨테이너 자체도 VM이 아니라 shutdown_vm 대상이 아님).
    report_path = save_report(engagement_id, vm_names=None)
    progress.done(f"보고서: {report_path}")

    return engagement_id


def _run_interactive() -> str:
    """인자 없이 실행하면 등록된 VM 목록을 보여주고 골라서 대상을 정하게 한다 -
    IP를 몰라도 되고, CLI 인자를 외울 필요도 없게(사용자 요청). VM 목록 아래에
    Kali 안의 Docker 대상(Juice Shop 등)도 별도 섹션으로 같이 보여준다."""
    from env.provision_target import is_running, list_target_vms, start_target_vm

    # 대상 VM 목록 자체는 VirtualBox 레지스트리 조회라 Kali 없이도 되지만,
    # 이 다음에 이어지는 IP 해석/도달성 확인은 전부 Kali "안에서" 실행되므로
    # (run_in_kali) 여기서 미리 확인/필요시 자동 재기동해둔다(사용자 지적:
    # "kali가 죽어있을 수도 있잖아") - 안 그러면 메뉴 다 고르고 나서야
    # 헷갈리는 에러로 실패한다.
    print("kali 상태 확인 중...")
    if not ensure_kali_running(auto_restart=True):
        print("kali VM이 응답하지 않고 재기동도 실패함 - python -m env.health_check로 직접 확인하세요.")
        sys.exit(1)
    print("kali 정상 확인됨")
    _clear_orphaned_sessions_if_any()
    print()

    vms = list_target_vms()
    if not vms and not DOCKER_TARGETS:
        print("등록된 대상이 없습니다. env.provision_target.import_target_vm()으로 먼저 VM을 임포트하세요.")
        sys.exit(1)

    print("사용 가능한 대상 VM:")
    for i, name in enumerate(vms, 1):
        state = "실행 중" if is_running(name) else "꺼짐"
        print(f"  {i}. {name}  [{state}]")

    if DOCKER_TARGETS:
        print("\nKali 안의 Docker 대상 (VM 아님, Kali와 함께 항상 실행 중):")
        for j, dt in enumerate(DOCKER_TARGETS, len(vms) + 1):
            print(f"  {j}. {dt['label']}  [{dt['ip']}:{dt['port']}]")

    total_options = len(vms) + len(DOCKER_TARGETS)
    choice = input("어떤 대상을 선택할까요? (번호 입력): ").strip()
    # 실전에서 잡은 버그: 파이썬 리스트는 음수 인덱스를 허용해서(vms[-1] == 마지막
    # 항목), "0"을 입력하면 int("0")-1 == -1이 돼서 IndexError 없이 조용히
    # 마지막 VM이 선택돼버렸다(사용자가 실제로 겪음) - 1 이상인지 명시적으로
    # 먼저 검사해서 막는다.
    idx = int(choice) if choice.lstrip("-").isdigit() else None
    if idx is None or not (1 <= idx <= total_options):
        print("잘못된 번호입니다.")
        sys.exit(1)

    if idx > len(vms):
        return _run_docker_target(DOCKER_TARGETS[idx - len(vms) - 1])

    vm_name = vms[idx - 1]

    print(f"\n{vm_name}을(를) 기동하고 IP를 확인합니다...")
    try:
        was_running = is_running(vm_name)
        if not was_running:
            start_target_vm(vm_name)
        target = _resolve_target_ip(vm_name)
        print(f"대상 IP: {target}")

        if not was_running:
            # run_pipeline()이 자체적으로 VM을 기동시킨 경우에만 부팅 유예시간을
            # 두는데(45-1절), 여기서 미리 기동시켜버리면 run_pipeline()이 볼 땐
            # 이미 "실행 중"이라 그 유예시간이 발동을 안 한다 - 인터랙티브 모드가
            # IP를 알아내려고 스스로 먼저 부팅시키는 구조라 생기는 사각지대라서,
            # 여기서 직접 같은 유예시간을 적용한다(사용자 지적으로 발견).
            print(f"방금 기동함 - 서비스 초기화 대기 {VM_BOOT_SERVICE_GRACE_SEC}s")
            time.sleep(VM_BOOT_SERVICE_GRACE_SEC)
        print()
    except KeyboardInterrupt:
        # 여기서 끊기면 아직 engagement_id가 없다(run_pipeline() 진입 전) -
        # 그래도 VM은 이미 켜져 있을 수 있으니 같은 정리 선택지를 준다.
        _handle_interrupt(None, vm_name)
        return ""  # _handle_interrupt가 sys.exit()로 끝내므로 여기 도달 안 함

    return run_pipeline(target, vm_name=vm_name, label=vm_name.lower())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        eid = _run_interactive()
    else:
        args = [a for a in sys.argv[1:] if not a.startswith("--label")]
        label_arg = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--label=")), "pipeline")

        target_arg = args[0]
        vm_name_arg = args[1] if len(args) > 1 else None

        eid = run_pipeline(target_arg, vm_name=vm_name_arg, label=label_arg)

    print(f"\n인게이지먼트 완료: {eid}")
