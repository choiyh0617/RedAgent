"""
Host-Only 랩 네트워크 프로비저닝.

지금은 192.168.56.0/24 Host-Only 네트워크(+DHCP)와 Kali의 NIC 연결이 이미
수동으로 되어 있지만, 이 코드가 다른 환경에 배포되면 그게 하나도 없는 상태로
시작할 수 있다. 그래서 이 모듈은 다음 세 가지를 전부 확인하고, 없으면 만든다
(idempotent — 이미 있으면 그대로 재사용):

  1. Host-Only 인터페이스 (예: "VirtualBox Host-Only Ethernet Adapter")
  2. 그 인터페이스에 붙는 DHCP 서버 (Target VM이 자동으로 IP를 받게)
  3. Kali VM의 NIC 하나가 그 인터페이스에 붙어 있는지

Target VM 자체는 이 모듈이 건드리지 않는다 (provision_target.py 담당).
"""

import re
import subprocess

from core.host_platform import get_vboxmanage_path

VBOXMANAGE = get_vboxmanage_path()

LAB_IP = "192.168.56.1"
LAB_NETMASK = "255.255.255.0"
DHCP_LOWER_IP = "192.168.56.101"
DHCP_UPPER_IP = "192.168.56.254"

KALI_VM = "kali"


def _run(*args: str) -> str:
    proc = subprocess.run([VBOXMANAGE, *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"VBoxManage {' '.join(args)} failed:\n{proc.stderr}")
    return proc.stdout


def _list_hostonly_networks() -> list[dict[str, str]]:
    """`VBoxManage list hostonlyifs` 출력을 빈 줄 기준 블록으로 파싱."""
    out = _run("list", "hostonlyifs")
    networks: list[dict[str, str]] = []
    block: dict[str, str] = {}
    for line in out.splitlines():
        if not line.strip():
            if block:
                networks.append(block)
                block = {}
            continue
        key, _, value = line.partition(":")
        block[key.strip()] = value.strip()
    if block:
        networks.append(block)
    return networks


def find_hostonly_adapter(ip: str = LAB_IP) -> str | None:
    """지정한 IP를 쓰는 host-only 어댑터 이름을 찾는다. 없으면 None."""
    for net in _list_hostonly_networks():
        if net.get("IPAddress") == ip:
            return net.get("Name")
    return None


def ensure_hostonly_network(ip: str = LAB_IP, netmask: str = LAB_NETMASK) -> str:
    """랩 네트워크 어댑터가 있으면 이름을 반환, 없으면 새로 만들고 반환."""
    existing = find_hostonly_adapter(ip)
    if existing:
        print(f"[skip] host-only network '{existing}' ({ip}) already exists")
        return existing

    print(f"[create] host-only network for {ip}/{netmask}")
    out = _run("hostonlyif", "create")
    # 출력 예: "Interface 'VirtualBox Host-Only Ethernet Adapter #2' was successfully created"
    match = re.search(r"Interface '([^']+)'", out)
    if not match:
        raise RuntimeError(f"failed to parse created adapter name from: {out}")
    name = match.group(1)

    _run("hostonlyif", "ipconfig", name, "--ip", ip, "--netmask", netmask)
    print(f"[ok] host-only network '{name}' configured as {ip}/{netmask}")
    return name


def _dhcp_server_enabled(adapter_name: str) -> bool | None:
    """해당 어댑터용 DHCP 서버가 있는지/켜져 있는지. 없으면 None."""
    out = _run("list", "dhcpservers")
    target = f"HostInterfaceNetworking-{adapter_name}"
    for chunk in re.split(r"(?=^NetworkName:)", out, flags=re.MULTILINE):
        if target not in chunk:
            continue
        enabled = re.search(r"^Enabled:\s*(\S+)", chunk, re.MULTILINE)
        return bool(enabled and enabled.group(1) == "Yes")
    return None


def ensure_dhcp_server(
    adapter_name: str,
    server_ip: str = LAB_IP,
    netmask: str = LAB_NETMASK,
    lower_ip: str = DHCP_LOWER_IP,
    upper_ip: str = DHCP_UPPER_IP,
) -> None:
    """Target VM이 붙자마자 자동으로 IP를 받도록 DHCP 서버를 보장."""
    status = _dhcp_server_enabled(adapter_name)
    if status is True:
        print(f"[skip] dhcp server for '{adapter_name}' already enabled")
        return
    if status is False:
        print(f"[fix] dhcp server for '{adapter_name}' exists but disabled -> enabling")
        _run("dhcpserver", "modify", "--interface", adapter_name, "--enable")
        return

    print(f"[create] dhcp server for '{adapter_name}' ({lower_ip}-{upper_ip})")
    _run(
        "dhcpserver", "add",
        f"--interface={adapter_name}",
        f"--server-ip={server_ip}",
        f"--netmask={netmask}",
        f"--lower-ip={lower_ip}",
        f"--upper-ip={upper_ip}",
        "--enable",
    )


def ensure_kali_attached(adapter_name: str, kali_vm: str = KALI_VM) -> None:
    """Kali의 NIC 하나가 랩 네트워크에 붙어 있는지 확인하고, 아니면 고친다.

    주의: VM이 켜져 있는 동안에는 hostonly 어댑터 재배정이 막힐 수 있다.
    그 경우 Kali를 한 번 종료(poweroff)한 뒤 다시 실행해야 한다.
    """
    out = _run("showvminfo", kali_vm, "--machinereadable")

    nic_idx = None
    for m in re.finditer(r'^nic(\d)="hostonly"', out, re.MULTILINE):
        nic_idx = m.group(1)
        break

    if nic_idx is None:
        # hostonly로 잡힌 NIC이 없으면 2번 슬롯(1번은 보통 NAT)을 새로 붙인다
        nic_idx = "2"
        print(f"[fix] {kali_vm} has no hostonly NIC -> attaching nic{nic_idx}")
        _run("modifyvm", kali_vm, f"--nic{nic_idx}", "hostonly")

    current = re.search(rf'^hostonlyadapter{nic_idx}="([^"]*)"', out, re.MULTILINE)
    if current and current.group(1) == adapter_name:
        print(f"[skip] {kali_vm} nic{nic_idx} already on '{adapter_name}'")
        return

    print(f"[fix] attaching {kali_vm} nic{nic_idx} -> '{adapter_name}'")
    _run("modifyvm", kali_vm, f"--hostonlyadapter{nic_idx}", adapter_name)


def ensure_lab_network() -> str:
    """랩 네트워크 전체(어댑터+DHCP+Kali 연결)를 보장하고 어댑터 이름을 반환."""
    adapter = ensure_hostonly_network()
    ensure_dhcp_server(adapter)
    ensure_kali_attached(adapter)
    return adapter


if __name__ == "__main__":
    name = ensure_lab_network()
    print("lab network ready:", name)
