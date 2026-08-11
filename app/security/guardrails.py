from __future__ import annotations

from dataclasses import dataclass

from app.core.scope import ScopeGuard


@dataclass(slots=True)
class GuardedAction:
    tool_name: str
    target: str


class GuardrailService:
    def __init__(self, scope_guard: ScopeGuard) -> None:
        self.scope_guard = scope_guard

    def enforce_scope(self, action: GuardedAction) -> None:
        self.scope_guard.validate(action.target)
