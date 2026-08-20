"""
2단계: Scanning & Enumeration (Linux 경로). DESIGN.md 5절/7절 참고.

대상 1개만 처리한다 (여러 대상을 원하면 프로세스를 여러 번 실행 — 이 모듈 안에
멀티 타겟 오케스트레이션을 넣지 않는다). 서비스별 서브모듈(HTTP/SMB/FTP)은
로직상 서로 독립적이지만 **순차 실행**한다 - 전부 run_in_kali()를 거치고
run_in_kali()는 크로스프로세스 세션 락으로 전역 직렬화되므로, 예전처럼
ThreadPoolExecutor로 "병렬" 실행해봤자 실제로는 락만 다투는 구조였다.
느린 서브모듈(gobuster, 최대 180초)이 락을 쥐고 있는 동안 빠른 서브모듈
(enum4linux)이 락 대기(90초)만에 타임아웃돼서 통째로 실패하는 경쟁 조건이
실전에서 있었다(Kioptrix1 검증 중 실측, DESIGN.md 55절) - 순차 실행으로
바꿔서 이 경쟁 자체를 없앴다.

흐름:
  1. nmap -sV(전체 포트) -> 열린 포트에만 -sC (2단계로 나눈 이유는 full_port_scan 참고)
  2. 열린 포트 조합으로 platform(linux/windows_standalone/windows_ad) 판정
     -> post_exploit.py/vuln_analysis.py가 이 값으로 도구 세트를 분기한다
  3. 감지된 서비스에 맞춰 서브모듈(HTTP/SMB/FTP) 순차 실행
  4. 전 과정을 core.state_store로 findings.jsonl에 기록
"""

import re
import time

from core.state_store import append_finding
from env.guest_control import run_in_kali
from env.job_runner import start_job, wait_for_job

# [ \t]+ 를 쓴다 (\s+ 아님) - \s는 개행도 포함해서, 뒤에 추가 정보가 없는 포트 줄
# (예: "111/tcp  open  rpcbind"만 있고 끝)에서 마지막 옵셔널 그룹의 \s+가 줄바꿈을
# 삼키고 (.*) 가 다음 줄 전체를 그 포트의 배너로 잘못 캡처하는 버그를 실제로 겪음.
PORT_LINE_RE = re.compile(r"^(\d+)/tcp[ \t]+(open|closed|filtered)[ \t]+(\S+)(?:[ \t]+(.*))?$", re.MULTILINE)
NMAP_PROGRESS_RE = r"About ([\d.]+)% done"
HTTP_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def _run_nmap_job(engagement_id: str, target: str, label: str, flags: str, hard_timeout: int) -> str:
    job_id = f"nmap-{label}-{target}-{int(time.time())}"
    handle = start_job(engagement_id, job_id, f"nmap {flags} {target}")
    result = wait_for_job(engagement_id, handle, progress_regex=NMAP_PROGRESS_RE, hard_timeout=hard_timeout)
    if not result.finished or result.exit_code != 0:
        raise RuntimeError(f"nmap({label}) did not complete cleanly: reason={result.reason}, killed={result.killed}")
    return result.output


def full_port_scan(engagement_id: str, target: str, ports: str = "-p-", max_retries: int = 3) -> str:
    """2단계로 나눠서 스캔한다: 먼저 -sC 없이 전체 포트 범위에서 열린 포트/서비스만
    찾고, 그 다음 찾은 포트에만 -sC(스크립트)를 돌린다.

    실전에서 discovery 단계가 몇 초 만에 "0 hosts up"으로 끝나버리는 걸 여러 번
    봤다. -sC 유무/-sV/-T4 어느 조합이든 재현돼서 특정 플래그 버그가 아니라,
    VirtualBox 가상 네트워크(hostonly) 자체가 순간적으로 지연/패킷 손실을 일으키고
    (ping RTT가 1ms~80ms까지 튀는 걸 확인함) 그 타이밍에 nmap의 판정이 맞물리면
    오판하는 것으로 보인다 (recon.py가 이미 살아있다고 확인한 대상인데도 이런
    오판이 남). 그래서 "0 hosts up"이 나오면 바로 실패로 보지 않고, ping으로
    재확인 후 재시도한다.

    -Pn: recon.py가 이미 host discovery로 생존을 확인했으므로 재확인 생략(위 이유로
    자체 host discovery가 오히려 불안정해서 끔).
    """
    for attempt in range(1, max_retries + 1):
        discovery_output = _run_nmap_job(
            engagement_id, target, "discover",
            f"-sV -T4 -Pn --stats-every 10s {ports}",
            hard_timeout=1800,
        )
        open_ports = [p["port"] for p in parse_open_ports(discovery_output)]
        # 실전에서 두 가지 거짓음성을 봤음: (1) "0 hosts up" - ARP/ping 레벨 손실로
        # 호스트 자체를 놓침, (2) 스캔된 포트가 전부 filtered - SYN 응답이 전부
        # 안 와서 실제로는 열린 포트도 필터링당한 것처럼 보임. 둘 다 이 VirtualBox
        # 가상 네트워크의 순간적 패킷 손실(호스트 부하)이 원인으로 보임 -> 재시도.
        all_filtered = bool(re.findall(r"^\d+/tcp\s+filtered", discovery_output, re.MULTILINE)) and not open_ports
        if open_ports or ("0 hosts up" not in discovery_output and not all_filtered):
            break

        ping = run_in_kali(f"ping -c2 -W2 {target}", timeout=15)
        append_finding(
            engagement_id, stage="scanning", event="scan_false_negative_retry", target=target,
            attempt=attempt, target_reachable_now=ping.ok, all_filtered=all_filtered,
        )
        if attempt == max_retries:
            return discovery_output
    if not open_ports:
        return discovery_output

    port_list = ",".join(str(p) for p in open_ports)
    script_output = _run_nmap_job(
        engagement_id, target, "scripts",
        f"-sC -Pn -p {port_list}",
        hard_timeout=300,
    )
    return discovery_output + "\n" + script_output


def parse_open_ports(nmap_output: str) -> list[dict]:
    """discovery+script 두 단계 출력을 합친 텍스트를 넘길 수 있어서, 같은 포트가
    양쪽 표에 다 나올 수 있다 -> 포트 번호로 중복 제거(첫 등장 = -sV 붙은 discovery
    단계 결과를 우선 채택, 배너 정보가 더 풍부함)."""
    seen: dict[int, dict] = {}
    for m in PORT_LINE_RE.finditer(nmap_output):
        port, state, service, extra = m.groups()
        if state != "open":
            continue
        port = int(port)
        if port not in seen:
            seen[port] = {"port": port, "service": service, "banner": (extra or "").strip()}
    return list(seen.values())


def detect_platform(open_ports: list[dict]) -> str:
    """DESIGN.md 7절: 사용자가 미리 지정하지 않고 스캔 결과로 자동 판정.

    실전에서 잡은 버그: Metasploitable2(Linux + Samba)가 139/445가 열려있다는
    이유만으로 windows_standalone으로 오판됐다(run_pipeline.py 첫 end-to-end
    실전 검증 중 실측 확인, DESIGN.md 43절) - Samba는 Linux에서도 흔해서
    SMB 포트만으로는 Windows를 특정할 수 없다. 반면 포트 22(OpenSSH)는
    Windows에 기본으로는 없어서(옵션으로 설치 가능하지만 드묾) Linux를
    특정하는 신호로 더 강하다 -> 22 체크를 139/445보다 먼저 본다."""
    port_nums = {p["port"] for p in open_ports}
    if ({88, 389} & port_nums) and ({445, 3268} & port_nums):
        return "windows_ad"
    if 22 in port_nums:
        return "linux"
    if {139, 445} & port_nums:
        return "windows_standalone"
    return "unknown"


def http_enum(target: str, port: int) -> dict:
    scheme = "https" if port == 443 else "http"
    base = f"{scheme}://{target}:{port}"
    whatweb = run_in_kali(f"whatweb -a 1 --color=never {base}", timeout=60)
    gobuster = run_in_kali(f"gobuster dir -u {base} -w {HTTP_WORDLIST} -q -t 20", timeout=180)
    return {"whatweb": whatweb.stdout.strip(), "gobuster": gobuster.stdout.strip()}


def smb_enum(target: str) -> dict:
    result = run_in_kali(f"enum4linux -a {target}", timeout=180)
    return {"enum4linux": result.stdout.strip()}


def ftp_anon_check(target: str, port: int = 21) -> dict:
    result = run_in_kali(
        f"curl -s --max-time 15 ftp://{target}:{port}/ --user anonymous:anonymous", timeout=30
    )
    return {"anonymous_login_ok": result.ok, "listing": result.stdout.strip()}


def scan_target(engagement_id: str, target: str, ports: str = "-p-") -> dict:
    raw = full_port_scan(engagement_id, target, ports)
    open_ports = parse_open_ports(raw)

    for p in open_ports:
        append_finding(
            engagement_id, stage="scanning", event="port_open", target=target,
            port=p["port"], service=p["service"], banner=p["banner"],
        )

    platform = detect_platform(open_ports)
    append_finding(engagement_id, stage="scanning", event="platform_detected", target=target, platform=platform)

    # 실전에서 잡은 버그(Kioptrix1 검증 중 발견, DESIGN.md 55절): 서브모듈을
    # ThreadPoolExecutor로 "병렬" 실행했지만, 전부 run_in_kali()를 거치고
    # run_in_kali()는 크로스프로세스 세션 락(_KaliSessionLock, 90초 대기)으로
    # 전역 직렬화된다 - 진짜 병렬이 아니라 그냥 하나씩 락을 다투는 구조였다.
    # gobuster(최대 180초)가 락을 오래 쥐고 있는 동안 enum4linux는 90초 대기
    # 만에 타임아웃돼서 통째로 실패했다(실측: smb_enum 결과가 "Kali 세션 락을
    # 90s 넘게 못 얻음" 에러만 남음 - Samba 버전 정보를 아예 못 얻어서
    # vuln_analysis.py가 실제 취약점(trans2open)을 후보로도 못 뽑는 연쇄
    # 실패로 이어짐). 순차 실행으로 바꿔서 이 경쟁 자체를 없앤다 - 어차피
    # 진짜 병렬이 아니었으므로 전체 소요 시간은 크게 안 늘어난다.
    smb_submitted = False
    results = {}
    for p in open_ports:
        svc, port = p["service"], p["port"]
        if svc in ("http", "https", "ssl/http", "ssl/https"):
            name, data = "http_enum", _run_submodule(http_enum, target, port)
        elif port in (139, 445) and not smb_submitted:
            smb_submitted = True
            name, data = "smb_enum", _run_submodule(smb_enum, target)
        elif svc == "ftp":
            name, data = "ftp_enum", _run_submodule(ftp_anon_check, target, port)
        else:
            continue
        append_finding(engagement_id, stage="scanning", event=name, target=target, port=port, result=data)
        results[f"{name}:{port}"] = data

    return {"target": target, "platform": platform, "open_ports": open_ports, "submodule_results": results}


def _run_submodule(func, *args) -> dict:
    try:
        return func(*args)
    except Exception as exc:  # noqa: BLE001 - 서브모듈 실패를 findings에 남기기 위해 포괄적으로 잡음
        return {"error": str(exc)}


if __name__ == "__main__":
    import sys

    from core.engagement import new_engagement_id

    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.104"
    ports = sys.argv[2] if len(sys.argv) > 2 else "-p-"

    eid = new_engagement_id(target.replace(".", "-"))
    print(f"engagement: {eid}")
    scan_result = scan_target(eid, target, ports)
    print(f"platform: {scan_result['platform']}")
    print(f"open ports: {[p['port'] for p in scan_result['open_ports']]}")
    print(f"submodules run: {list(scan_result['submodule_results'].keys())}")
