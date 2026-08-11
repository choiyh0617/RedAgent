from __future__ import annotations

import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Literal

from app.core.config import Settings
from app.core.models import NetworkScanResult, PortInfo
from app.core.scope import ScopeGuard
from app.security.guardrails import GuardedAction, GuardrailService


def network_scan(
    target: str,
    scope_guard: ScopeGuard,
    settings: Settings,
    mode: Literal["quick", "service"] = "quick",
) -> NetworkScanResult:
    GuardrailService(scope_guard).enforce_scope(GuardedAction(tool_name="network_scan", target=target))
    target_info = scope_guard.parse_target(target)

    if not settings.network_scan_enabled:
        return NetworkScanResult(
            target=target_info.normalized,
            resolved_ip=target_info.ip,
            mode=mode,
            success=False,
            error="network scan disabled by configuration",
        )

    command = _build_nmap_command(target_info.hostname, target_info.port, mode)
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.network_scan_timeout_seconds,
            check=False,
        )
    except FileNotFoundError:
        return NetworkScanResult(
            target=target_info.normalized,
            resolved_ip=target_info.ip,
            mode=mode,
            scan_duration_ms=int((time.perf_counter() - start) * 1000),
            success=False,
            error="nmap is not installed",
        )
    except subprocess.TimeoutExpired:
        return NetworkScanResult(
            target=target_info.normalized,
            resolved_ip=target_info.ip,
            mode=mode,
            scan_duration_ms=int((time.perf_counter() - start) * 1000),
            success=False,
            error=f"nmap timed out after {settings.network_scan_timeout_seconds} seconds",
        )

    duration_ms = int((time.perf_counter() - start) * 1000)
    ports, resolved_ip = _parse_nmap_xml(completed.stdout)
    success = completed.returncode == 0
    error = None if success else _sanitize_error(completed.stderr) or "nmap scan failed"

    return NetworkScanResult(
        target=target_info.normalized,
        resolved_ip=resolved_ip or target_info.ip,
        mode=mode,
        ports=ports,
        scan_duration_ms=duration_ms,
        success=success,
        error=error,
        raw_summary=_summarize_ports(ports),
    )


def _build_nmap_command(hostname: str, port: int, mode: Literal["quick", "service"]) -> list[str]:
    ports = sorted({port, 80, 443, 3000, 5000, 8000, 8080, 8443})
    command = [
        "nmap",
        "-Pn",
        "-T3",
        "--open",
        "-p",
        ",".join(str(candidate) for candidate in ports),
        "-oX",
        "-",
    ]
    if mode == "service":
        command.extend(["-sV", "--version-light"])
    command.append(hostname)
    return command


def _parse_nmap_xml(output: str) -> tuple[list[PortInfo], str | None]:
    if not output.strip():
        return [], None

    root = ET.fromstring(output)
    address = root.find(".//host/address[@addrtype='ipv4']")
    resolved_ip = address.attrib.get("addr") if address is not None else None
    ports: list[PortInfo] = []

    for port_node in root.findall(".//host/ports/port"):
        state_node = port_node.find("state")
        service_node = port_node.find("service")
        ports.append(
            PortInfo(
                port=int(port_node.attrib.get("portid", "0")),
                protocol=port_node.attrib.get("protocol", "tcp"),
                state=state_node.attrib.get("state", "unknown") if state_node is not None else "unknown",
                service=service_node.attrib.get("name") if service_node is not None else None,
                product=service_node.attrib.get("product") if service_node is not None else None,
                version=service_node.attrib.get("version") if service_node is not None else None,
            )
        )
    return ports, resolved_ip


def _sanitize_error(value: str | None) -> str | None:
    if not value:
        return None
    return " ".join(value.strip().split())[:300] or None


def _summarize_ports(ports: list[PortInfo]) -> str | None:
    if not ports:
        return None
    return ", ".join(f"{port.port}/{port.protocol} {port.service or 'unknown'}" for port in ports[:10])
