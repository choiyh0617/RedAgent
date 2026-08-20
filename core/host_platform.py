"""
호스트 운영체제 선택 및 호스트별 경로 해석.

처음 실행 시 사용자에게 Windows/Mac 중 하나를 묻고, 선택 결과를 state 파일에
저장한다. 현재는 VirtualBox CLI 경로 해석에 사용한다.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path


_STATE_PATH = Path(__file__).resolve().parent.parent / "state" / "_host_platform.json"
_WINDOWS = "windows"
_MAC = "mac"

_VBOXMANAGE_BY_OS = {
    _WINDOWS: r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    _MAC: "/Applications/VirtualBox.app/Contents/MacOS/VBoxManage",
}


def _detect_default_choice() -> str:
    system = platform.system().lower()
    if "darwin" in system:
        return _MAC
    return _WINDOWS


def _prompt_for_host_os() -> str:
    default_choice = _detect_default_choice()
    default_label = "2" if default_choice == _MAC else "1"
    print(
        "\n[host setup] 호스트 운영체제를 선택하세요.\n"
        "  1. Windows\n"
        "  2. Mac"
    )
    try:
        answer = input(f"번호 입력 (기본 {default_label}): ").strip()
    except (KeyboardInterrupt, EOFError):
        answer = ""
    if answer == "2":
        return _MAC
    if answer == "1":
        return _WINDOWS
    return default_choice


def _save_host_os(host_os: str) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(json.dumps({"host_os": host_os}, ensure_ascii=False, indent=2), encoding="utf-8")


def get_host_os() -> str:
    if _STATE_PATH.exists():
        try:
            data = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
            host_os = str(data.get("host_os") or "").lower()
            if host_os in (_WINDOWS, _MAC):
                return host_os
        except (OSError, json.JSONDecodeError):
            pass
    host_os = _prompt_for_host_os()
    _save_host_os(host_os)
    return host_os


def get_vboxmanage_path() -> str:
    return _VBOXMANAGE_BY_OS[get_host_os()]


def is_mac_host() -> bool:
    return get_host_os() == _MAC
