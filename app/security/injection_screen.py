from __future__ import annotations

import re

from app.llm.models import InjectionScreenResult

SUSPICIOUS_RULES = {
    "ignore_previous_instructions": re.compile(r"\bignore previous instructions\b", re.IGNORECASE),
    "system_prompt_reference": re.compile(r"\bsystem prompt\b", re.IGNORECASE),
    "run_this_command": re.compile(r"\brun this command\b", re.IGNORECASE),
    "identity_rewrite": re.compile(r"\byou are now\b", re.IGNORECASE),
}


def label_untrusted(source: str, content: str, limit: int = 4000) -> dict[str, object]:
    return {
        "source": source,
        "trusted_as_instruction": False,
        "content": content[:limit],
    }


def screen_text(content: str) -> InjectionScreenResult:
    matched = [name for name, pattern in SUSPICIOUS_RULES.items() if pattern.search(content)]
    if matched:
        return InjectionScreenResult(
            is_suspicious=True,
            reason="matched prompt-injection style pattern",
            matched_rules=matched,
        )
    return InjectionScreenResult(is_suspicious=False, reason=None, matched_rules=[])
