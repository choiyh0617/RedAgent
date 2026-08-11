from __future__ import annotations

import re

from app.validation.models import ValidationEvidence


SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[a-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)\b(eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+)\b"),
    re.compile(r"(?i)\b(api[_-]?key|token|password|secret)=([^&\s]+)"),
]


class EvidenceSanitizer:
    def sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        sanitized: dict[str, str] = {}
        for name, value in headers.items():
            sanitized[name] = "[REDACTED]" if name.lower() in SENSITIVE_HEADERS else self.sanitize_text(value)
        return sanitized

    def sanitize_text(self, value: str | None, max_length: int = 240) -> str:
        if not value:
            return ""
        cleaned = " ".join(str(value).split())
        for pattern in SENSITIVE_PATTERNS:
            cleaned = pattern.sub(lambda match: match.group(1) + "[REDACTED]" if match.lastindex else "[REDACTED]", cleaned)
        return cleaned[:max_length]

    def sanitize_evidence(self, evidence: ValidationEvidence) -> ValidationEvidence:
        request = evidence.request
        response = evidence.response
        if request is not None:
            request = request.model_copy(
                update={
                    "headers": self.sanitize_headers(request.headers),
                }
            )
        if response is not None:
            response = response.model_copy(
                update={
                    "selected_headers": self.sanitize_headers(response.selected_headers),
                    "redirect_location": self.sanitize_text(response.redirect_location, 200) or None,
                    "title": self.sanitize_text(response.title, 160) or None,
                }
            )
        return evidence.model_copy(
            update={
                "request": request,
                "response": response,
                "observation": self.sanitize_text(evidence.observation, 320),
            }
        )
