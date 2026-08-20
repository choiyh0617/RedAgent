"""
1단계: Recon (호스트 탐지).

Kali 안에서 hostonly 서브넷을 스캔해 살아있는 호스트를 찾고,
호스트(192.168.56.1)/Kali 자신(192.168.56.101)을 제외한 새 호스트를 Target 후보로 본다.
탐지된 후보는 scope.yaml에 기록해서, 이후 모든 단계(스캐닝/익스플로잇)의 안전 가드로 쓴다.
"""

import re
from pathlib import Path

from env.guest_control import run_in_kali

HOSTONLY_SUBNET = "192.168.56.0/24"
KNOWN_NON_TARGETS = {"192.168.56.1", "192.168.56.101"}
SCOPE_FILE = Path(__file__).resolve().parent.parent / "scope.yaml"


def discover_hosts(subnet: str = HOSTONLY_SUBNET) -> list[str]:
    result = run_in_kali(f"nmap -sn {subnet} -oG - | grep Up")
    if not result.ok:
        raise RuntimeError(f"host discovery failed: {result.stderr}")
    return re.findall(r"Host: (\S+) \(\)\s+Status: Up", result.stdout)


def find_new_targets(subnet: str = HOSTONLY_SUBNET) -> list[str]:
    hosts = discover_hosts(subnet)
    return [h for h in hosts if h not in KNOWN_NON_TARGETS]


def write_scope(targets: list[str], subnet: str = HOSTONLY_SUBNET, path: Path = SCOPE_FILE) -> None:
    """탐지된 대상을 scope.yaml에 기록. 이후 모듈은 여기 없는 IP는 절대 건드리면 안 된다."""
    lines = [f"allowed_subnet: {subnet}", "targets:"]
    lines.extend(f"- {target}" for target in targets)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    targets = find_new_targets()
    print("targets:", targets)
    write_scope(targets)
    print(f"scope written to {SCOPE_FILE}")
