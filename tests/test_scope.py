from __future__ import annotations

import unittest

from app.core.config import Settings
from app.core.scope import ScopeGuard, ScopeViolationError


class ScopeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope_guard = ScopeGuard(Settings())

    def test_allows_loopback_targets(self) -> None:
        decision = self.scope_guard.validate("http://127.0.0.1:3000")
        self.assertTrue(decision.allowed)

    def test_blocks_external_targets(self) -> None:
        with self.assertRaises(ScopeViolationError):
            self.scope_guard.validate("http://example.com")

    def test_blocks_unsupported_schemes(self) -> None:
        with self.assertRaises(ScopeViolationError):
            self.scope_guard.validate("ftp://127.0.0.1")

    def test_allows_configured_private_range(self) -> None:
        guard = ScopeGuard(Settings(allowed_networks=["192.168.56.0/24"]))
        decision = guard.validate("http://192.168.56.10:8080")
        self.assertTrue(decision.allowed)
