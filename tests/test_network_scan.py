from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from app.core.config import Settings
from app.core.scope import ScopeGuard, ScopeViolationError
from app.tools.network_scan import _build_nmap_command, _parse_nmap_xml, network_scan


NMAP_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open" />
        <service name="http" product="Node.js" version="18.x" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


class NetworkScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings()
        self.scope_guard = ScopeGuard(self.settings)

    def test_build_nmap_command_uses_safe_flags(self) -> None:
        command = _build_nmap_command("127.0.0.1", 3000, "service")
        self.assertEqual(command[0], "nmap")
        self.assertIn("-Pn", command)
        self.assertIn("--open", command)
        self.assertIn("-sV", command)
        self.assertNotIn("--script", command)

    def test_scope_validation_runs_before_scan(self) -> None:
        with self.assertRaises(ScopeViolationError):
            network_scan("http://example.com", self.scope_guard, self.settings)

    def test_nmap_missing_returns_structured_error(self) -> None:
        with patch("app.tools.network_scan.subprocess.run", side_effect=FileNotFoundError):
            result = network_scan("http://127.0.0.1:3000", self.scope_guard, self.settings)

        self.assertFalse(result.success)
        self.assertEqual(result.error, "nmap is not installed")

    def test_nmap_timeout_returns_structured_error(self) -> None:
        with patch(
            "app.tools.network_scan.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=20),
        ):
            result = network_scan("http://127.0.0.1:3000", self.scope_guard, self.settings)

        self.assertFalse(result.success)
        self.assertIn("timed out", result.error or "")

    def test_nmap_output_is_parsed(self) -> None:
        ports, ip_address = _parse_nmap_xml(NMAP_XML)
        self.assertEqual(ip_address, "127.0.0.1")
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0].service, "http")
        self.assertEqual(ports[0].product, "Node.js")

    def test_network_scan_invokes_subprocess_without_shell(self) -> None:
        completed = subprocess.CompletedProcess(args=["nmap"], returncode=0, stdout=NMAP_XML, stderr="")
        with patch("app.tools.network_scan.subprocess.run", return_value=completed) as mocked_run:
            result = network_scan("http://127.0.0.1:3000", self.scope_guard, self.settings, mode="quick")

        self.assertTrue(result.success)
        _, kwargs = mocked_run.call_args
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["timeout"], self.settings.network_scan_timeout_seconds)
