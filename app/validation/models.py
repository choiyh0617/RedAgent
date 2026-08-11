from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class ValidationActionType(str, Enum):
    COMPARE_HTTP_RESPONSE = "compare_http_response"
    CHECK_SECURITY_HEADER = "check_security_header"
    CHECK_STATUS_BEHAVIOR = "check_status_behavior"
    CHECK_REDIRECT_BEHAVIOR = "check_redirect_behavior"
    CHECK_ENDPOINT_ACCESSIBILITY = "check_endpoint_accessibility"
    CHECK_AUTH_BEHAVIOR = "check_auth_behavior"
    CHECK_METHOD_BEHAVIOR = "check_method_behavior"
    CHECK_CONTENT_DIFFERENCE = "check_content_difference"


ValidationStatus = Literal["verified", "unverified", "false_positive", "validation_skipped"]


class ValidationRequestSummary(BaseModel):
    method: str
    path: str
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)


class ValidationResponseSummary(BaseModel):
    status_code: int | None = None
    content_type: str | None = None
    body_length: int = 0
    body_hash: str | None = None
    title: str | None = None
    selected_headers: dict[str, str] = Field(default_factory=dict)
    redirect_location: str | None = None
    blocked_redirect: bool = False


class ValidationEvidence(BaseModel):
    type: str
    request: ValidationRequestSummary | None = None
    response: ValidationResponseSummary | None = None
    observation: str


class ValidationRequest(BaseModel):
    finding_id: str
    recommended_type: str | None = None
    reason: str | None = None
    endpoint: str
    method: str
    analysis_status: str | None = None
    confidence_before: float = Field(ge=0.0, le=1.0)
    attempt: int = 1


class ValidationResult(BaseModel):
    finding_id: str
    status: ValidationStatus
    validator: str | None = None
    confidence_before: float = Field(ge=0.0, le=1.0)
    confidence_after: float = Field(ge=0.0, le=1.0)
    evidence: list[ValidationEvidence] = Field(default_factory=list)
    reason: str
    requests_made: int = 0
    duration_ms: int = 0
    engine_version: str = "v1"
    cached: bool = False


class ValidationMetrics(BaseModel):
    validation_attempted_count: int = 0
    validation_verified_count: int = 0
    validation_false_positive_count: int = 0
    validation_unverified_count: int = 0
    validation_skipped_count: int = 0
    validation_request_count: int = 0
    validation_duration: int = 0

    def record(self, result: ValidationResult) -> None:
        self.validation_attempted_count += 1
        self.validation_request_count += result.requests_made
        self.validation_duration += result.duration_ms
        if result.status == "verified":
            self.validation_verified_count += 1
        elif result.status == "false_positive":
            self.validation_false_positive_count += 1
        elif result.status == "unverified":
            self.validation_unverified_count += 1
        else:
            self.validation_skipped_count += 1


class ValidationCacheEntry(BaseModel):
    cache_key: str
    version: str
    result: ValidationResult


class ResponseFingerprint(BaseModel):
    status_code: int
    body_length: int
    body_hash: str
    content_type: str | None = None
    title: str | None = None
    selected_headers: dict[str, str] = Field(default_factory=dict)
    redirect_location: str | None = None
    blocked_redirect: bool = False

    def stable_fields(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
