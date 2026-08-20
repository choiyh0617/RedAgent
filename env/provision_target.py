"""
CTF 대상 VM 프로비저닝 (Environment Provisioning, 파이프라인 0단계).

사용자가 .vmdk 파일만 넘기면:
  1. VM이 이미 등록되어 있는지 확인 (idempotent)
  2. 없으면 Kioptrix1과 동일한 스펙으로 새 VM 생성 + vmdk attach
  3. 랩 hostonly 네트워크(provision_network.ensure_lab_network로 보장)에 연결
  4. headless로 기동

기존 수동 설정(Kioptrix1)을 그대로 프로파일로 재사용한다:
  memory=1024MB, cpus=1, chipset=piix3, firmware=BIOS, IDE 컨트롤러(PIIX4)
"""

import re
import subprocess
import time
from dataclasses import dataclass

from core import config  # noqa: F401 - import 시점에 stdout/stderr를 UTF-8로 고정
from core.host_platform import get_vboxmanage_path
from env.provision_network import ensure_lab_network

VBOXMANAGE = get_vboxmanage_path()


@dataclass
class TargetProfile:
    memory_mb: int = 1024
    cpus: int = 1
    # 주의: VBoxManage createvm --ostype 은 showvminfo가 보여주는 설명 텍스트
    # ("Oracle Linux (32-bit)")가 아니라 짧은 ID("Oracle")를 요구한다 - 예전에
    # 설명 텍스트를 그대로 기본값에 넣었던 게 지금까지 잠복 버그로 남아있었음
    # (Kioptrix2 임포트 때는 항상 ostype을 직접 지정해서 이 기본값이 한 번도
    # 실행된 적이 없어 안 드러났음). `VBoxManage list ostypes`로 정확한 ID 확인 가능.
    ostype: str = "Oracle"
    # VirtualBox 기본값(e1000, Intel PRO/1000)은 2010년대 초반 커널에 드라이버가
    # 없어서 NIC 자체를 못 잡는 걸 실제로 겪었다(Kioptrix1) - 오래된 CTF 이미지가
    # 대부분 지원하는 구형 카드로 기본값을 바꿔둔다. 아래 HARDWARE_PROFILES 참고.
    nictype: str = "Am79C973"


# 대상의 배포 연도/커널 세대에 맞는 하드웨어 프로파일을 이름으로 골라 쓴다 -
# 새 CTF VM을 임포트하기 전에 이 중 하나를 고르는 걸 절차로 삼는다(사용자 요청,
# DESIGN.md 20-2절 참고). 판단 기준: VulnHub 페이지의 배포 연도, vmx 파일의
# guestOS 필드, 파일명의 배포판/버전 등으로 짐작 - 애매하면 "legacy"가 안전한
# 기본값이다(PCnet 드라이버는 거의 모든 리눅스 커널 역사에 걸쳐 지원됨, e1000은
# 대략 2004년/커널 2.6.5 이전 이미지엔 없을 수 있음).
HARDWARE_PROFILES = {
    # ~2008년 이전 이미지 (Kioptrix1 등). PCnet은 오래된 커널도 대부분 지원.
    "legacy": TargetProfile(nictype="Am79C973"),
    # ~2008~2012년 이미지 (Metasploitable2 등, Ubuntu 8.04 기반). e1000 지원됨.
    "2008-2012": TargetProfile(nictype="e1000"),
    # 그 이후 최신 배포판. e1000이나 virtio 계열 다 지원.
    "modern": TargetProfile(nictype="e1000"),
}


def _run(*args: str) -> str:
    proc = subprocess.run([VBOXMANAGE, *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"VBoxManage {' '.join(args)} failed:\n{proc.stderr}")
    return proc.stdout


def _list_names(list_cmd: str) -> set[str]:
    out = _run("list", list_cmd)
    return set(re.findall(r'^"([^"]+)"', out, re.MULTILINE))


def vm_exists(name: str) -> bool:
    return name in _list_names("vms")


def is_running(name: str) -> bool:
    return name in _list_names("runningvms")


def list_target_vms(exclude: set[str] = frozenset({"kali"})) -> list[str]:
    """등록된 VM 중 공격자 VM(kali)을 제외한 대상 후보 목록. run_pipeline.py의
    대화형 모드에서 사용자에게 고르게 할 때 씀."""
    return sorted(n for n in _list_names("vms") if n.lower() not in {e.lower() for e in exclude})


def get_mac_address(name: str, nic: int = 1) -> str:
    """VM의 NIC MAC 주소를 콜론 구분 대문자 형식으로 반환(예: 08:00:27:7F:FC:55)
    - nmap -sn 결과의 "MAC Address: ..." 줄과 바로 비교할 수 있는 형식."""
    out = _run("showvminfo", name, "--machinereadable")
    m = re.search(rf'macaddress{nic}="([0-9A-Fa-f]+)"', out)
    if not m:
        raise RuntimeError(f"{name}의 NIC{nic} MAC 주소를 못 찾음")
    raw = m.group(1)
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2)).upper()


def import_target_vm(name: str, vmdk_path: str, profile: TargetProfile = TargetProfile()) -> None:
    """대상 VM을 Kioptrix1과 같은 프로파일로 생성하고 vmdk를 attach한다. 이미 있으면 건너뜀."""
    if vm_exists(name):
        print(f"[skip] VM '{name}' already registered")
        return

    print(f"[create] {name}")
    _run("createvm", "--name", name, "--ostype", profile.ostype, "--register")
    _run(
        "modifyvm", name,
        "--memory", str(profile.memory_mb),
        "--cpus", str(profile.cpus),
        "--chipset", "piix3",
        "--firmware", "BIOS",
    )
    _run("storagectl", name, "--name", "IDE", "--add", "ide")
    _run(
        "storageattach", name,
        "--storagectl", "IDE", "--port", "0", "--device", "0",
        "--type", "hdd", "--medium", vmdk_path,
    )

    adapter = ensure_lab_network()
    _run(
        "modifyvm", name,
        "--nic1", "hostonly", "--hostonlyadapter1", adapter, "--nictype1", profile.nictype,
    )
    print(f"[ok] {name} imported and attached to {adapter} (nictype={profile.nictype})")


def start_target_vm(name: str, headless: bool = True) -> None:
    if is_running(name):
        print(f"[skip] VM '{name}' already running")
        return
    print(f"[start] {name}")
    _run("startvm", name, "--type", "headless" if headless else "gui")


def graceful_shutdown(name: str, timeout: int = 60) -> bool:
    """ACPI 전원 버튼 신호로 정상 종료를 시도한다.

    `controlvm poweroff`는 전원 플러그를 뽑는 것과 같은 강제 종료다 - 오래된
    CTF 이미지들은 저널링이 약한 파일시스템을 쓰는 경우가 많아서, 반복된 강제
    종료가 실제로 파일시스템/서비스 설정을 손상시키는 걸 겪었다(Kioptrix1이
    로그인 프롬프트까지는 뜨는데 네트워크 서비스가 하나도 안 뜨는 상태가 됨 -
    원인을 완전히 확정하진 못했지만 가장 유력한 설명이었음). 그래서 정상 종료를
    기본으로 하고, 시간 안에 안 꺼지면 호출자가 force_poweroff()로 넘어갈지
    판단하게 한다."""
    print(f"[graceful shutdown] {name} (ACPI)")
    _run("controlvm", name, "acpipowerbutton")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_running(name):
            return True
        time.sleep(3)
    return False


def force_poweroff(name: str) -> None:
    """마지막 수단 - 정상 종료가 실패하거나(게스트가 응답 없음) 시간이 없을 때만.
    graceful_shutdown()을 항상 먼저 시도할 것."""
    print(f"[force poweroff] {name} (정상 종료 실패/불가 - 마지막 수단)")
    _run("controlvm", name, "poweroff")


def shutdown_vm(name: str, graceful_timeout: int = 60) -> None:
    """정상 종료를 시도하고, 시간 안에 안 꺼지면 강제 종료로 폴백한다.
    VM을 끄고 싶을 때는 이 함수를 쓸 것 (poweroff를 직접 호출하지 말 것)."""
    if not is_running(name):
        print(f"[skip] '{name}' already off")
        return
    if not graceful_shutdown(name, timeout=graceful_timeout):
        force_poweroff(name)


PRE_EXPLOIT_SNAPSHOT = "pre-exploit"


def snapshot_before_exploit(name: str, snapshot_name: str = PRE_EXPLOIT_SNAPSHOT) -> None:
    """exploitation.py 진입 직전에 호출. 이미 있으면 건너뜀(idempotent) -
    같은 인게이지먼트를 여러 번 재시도해도 최초 상태로 롤백 기준점이 유지된다.

    스냅샷이 하나도 없는 상태(맨 처음)에서는 VBoxManage가 "This machine does not
    have any snapshots"를 exit code 1로 출력한다 - 진짜 에러가 아니라 정상적인
    빈 목록이라 별도로 처리해야 한다(실제로 겪음, _run()이 exit != 0을 전부
    에러로 취급해서 크래시났었음).
    """
    proc = subprocess.run(
        [VBOXMANAGE, "snapshot", name, "list", "--machinereadable"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0 and "does not have any snapshots" not in proc.stdout + proc.stderr:
        raise RuntimeError(f"VBoxManage snapshot list failed:\n{proc.stderr}")

    if f'SnapshotName="{snapshot_name}"' in proc.stdout:
        print(f"[skip] snapshot '{snapshot_name}' already exists on {name}")
        return
    print(f"[snapshot] {name} -> {snapshot_name}")
    _run("snapshot", name, "take", snapshot_name)


def rollback_to_snapshot(name: str, snapshot_name: str = PRE_EXPLOIT_SNAPSHOT, restart: bool = True) -> None:
    """박스가 익스플로잇으로 죽었을 때 호출. 스냅샷 복원은 VM이 꺼진 상태에서만
    되므로 종료(정상 종료 우선, 안 되면 강제) -> restore -> (필요시) startvm
    순서로 진행한다. 익스플로잇 직후라 게스트가 이미 크래시해서 ACPI 신호에
    응답을 못 할 수도 있으니 정상 종료 대기 시간은 짧게 둔다."""
    shutdown_vm(name, graceful_timeout=15)
    print(f"[restore] {name} -> {snapshot_name}")
    _run("snapshot", name, "restore", snapshot_name)
    if restart:
        start_target_vm(name)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("usage: python provision_target.py <vm_name> <vmdk_path>")
        sys.exit(1)

    vm_name, vmdk = sys.argv[1], sys.argv[2]
    import_target_vm(vm_name, vmdk)
    start_target_vm(vm_name)
