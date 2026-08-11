from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from app.core.scope import ScopeGuard, ScopeViolationError
from app.eval.metrics import RuntimeMetricsCollector
from app.llm.models import FindingAnalysis
from app.storage.cache import SQLiteJSONCache
from app.tools.http_utils import HTTPFetchResult, inspect_html, perform_request
from app.validation.models import (
    ResponseFingerprint,
    ValidationActionType,
    ValidationEvidence,
    ValidationRequest,
    ValidationRequestSummary,
    ValidationResponseSummary,
    ValidationResult,
)
from app.validation.sanitizer import EvidenceSanitizer


ALLOWED_VALIDATION_METHODS = {"GET", "HEAD", "OPTIONS"}
SELECTED_RESPONSE_HEADERS = ("Content-Type", "Location", "Cache-Control", "Content-Security-Policy")


class Validator(Protocol):
    name: ValidationActionType

    def validate(self, request: ValidationRequest, context: "ValidationContext") -> ValidationResult:
        ...


@dataclass(slots=True)
class ValidationContext:
    settings: object
    scope_guard: ScopeGuard
    sanitizer: EvidenceSanitizer
    finding_title: str
    finding_evidence: list[str]
    base_url: str
    per_finding_limit: int
    scan_remaining_requests: int
    requests_made: int = 0

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> HTTPFetchResult:
        normalized_method = method.upper()
        if normalized_method not in ALLOWED_VALIDATION_METHODS:
            raise ValueError(f"forbidden_method:{normalized_method}")
        if self.requests_made >= self.per_finding_limit or self.requests_made >= self.scan_remaining_requests:
            raise ValueError("request_budget_exceeded")
        _enforce_same_origin(self.base_url, url)
        self.requests_made += 1
        result = perform_request(
            url,
            tool_name="validation",
            scope_guard=self.scope_guard,
            settings=self.settings,
            method=normalized_method,
            headers=headers,
            timeout_seconds=self.settings.validation_timeout_seconds,
        )
        if result.redirect_location:
            redirect_url = urljoin(url, result.redirect_location)
            if not _same_origin(url, redirect_url):
                result.blocked_redirect = True
        return result


class BaseValidator:
    name: ValidationActionType

    def _request_summary(self, url: str, method: str, headers: dict[str, str] | None = None) -> ValidationRequestSummary:
        parsed = urlparse(url)
        return ValidationRequestSummary(
            method=method,
            path=parsed.path or "/",
            query={key: value for key, value in parse_qsl(parsed.query, keep_blank_values=True)},
            headers=headers or {},
        )

    def _response_summary(self, response: HTTPFetchResult) -> ValidationResponseSummary:
        fingerprint = fingerprint_response(response)
        return ValidationResponseSummary(
            status_code=fingerprint.status_code,
            content_type=fingerprint.content_type,
            body_length=fingerprint.body_length,
            body_hash=fingerprint.body_hash,
            title=fingerprint.title,
            selected_headers=fingerprint.selected_headers,
            redirect_location=fingerprint.redirect_location,
            blocked_redirect=fingerprint.blocked_redirect,
        )


class SecurityHeaderValidator(BaseValidator):
    name = ValidationActionType.CHECK_SECURITY_HEADER

    def validate(self, request: ValidationRequest, context: ValidationContext) -> ValidationResult:
        started = time.perf_counter()
        header_name = infer_security_header_name(context.finding_title, context.finding_evidence)
        if header_name is None:
            return ValidationResult(
                finding_id=request.finding_id,
                status="validation_skipped",
                validator=self.name.value,
                confidence_before=request.confidence_before,
                confidence_after=request.confidence_before,
                reason="header_not_supported",
                requests_made=0,
                duration_ms=0,
                engine_version=context.settings.validation_engine_version,
            )
        try:
            response = context.request(request.endpoint, method="GET")
        except Exception as exc:
            return _failure_result(request, context, self.name, exc, started)
        headers = {name.lower(): value for name, value in response.headers}
        observed = headers.get(header_name.lower())
        status = "verified" if not observed else "false_positive"
        confidence_after = update_confidence(context.settings, request.confidence_before, status)
        evidence = context.sanitizer.sanitize_evidence(
            ValidationEvidence(
                type="http_observation",
                request=self._request_summary(request.endpoint, "GET"),
                response=self._response_summary(response).model_copy(
                    update={"selected_headers": {header_name: observed or "missing"}}
                ),
                observation=f"{header_name} {'missing' if not observed else 'present'} on GET {urlparse(request.endpoint).path or '/'}",
            )
        )
        return ValidationResult(
            finding_id=request.finding_id,
            status=status,
            validator=self.name.value,
            confidence_before=request.confidence_before,
            confidence_after=confidence_after,
            evidence=[evidence],
            reason="header_missing_confirmed" if status == "verified" else "header_present_in_response",
            requests_made=context.requests_made,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine_version=context.settings.validation_engine_version,
        )


class ResponseComparisonValidator(BaseValidator):
    name = ValidationActionType.COMPARE_HTTP_RESPONSE

    def validate(self, request: ValidationRequest, context: ValidationContext) -> ValidationResult:
        started = time.perf_counter()
        try:
            baseline = context.request(request.endpoint, method="GET")
            alternate_url = build_controlled_alternate_url(request.endpoint)
            alternate = context.request(alternate_url, method="GET")
        except Exception as exc:
            return _failure_result(request, context, self.name, exc, started)
        baseline_fp = fingerprint_response(baseline)
        alternate_fp = fingerprint_response(alternate)
        changed = baseline_fp.stable_fields() != alternate_fp.stable_fields()
        status = "verified" if changed else "unverified"
        reason = "controlled_difference_observed" if changed else "no_stable_difference_observed"
        evidence = [
            context.sanitizer.sanitize_evidence(
                ValidationEvidence(
                    type="http_observation",
                    request=self._request_summary(request.endpoint, "GET"),
                    response=self._response_summary(baseline),
                    observation="Baseline response captured for deterministic comparison.",
                )
            ),
            context.sanitizer.sanitize_evidence(
                ValidationEvidence(
                    type="http_observation",
                    request=self._request_summary(alternate_url, "GET"),
                    response=self._response_summary(alternate),
                    observation="Controlled alternate response captured with predefined harmless parameter.",
                )
            ),
        ]
        return ValidationResult(
            finding_id=request.finding_id,
            status=status,
            validator=self.name.value,
            confidence_before=request.confidence_before,
            confidence_after=update_confidence(context.settings, request.confidence_before, status),
            evidence=evidence,
            reason=reason,
            requests_made=context.requests_made,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine_version=context.settings.validation_engine_version,
        )


class EndpointAccessibilityValidator(BaseValidator):
    name = ValidationActionType.CHECK_ENDPOINT_ACCESSIBILITY

    def validate(self, request: ValidationRequest, context: ValidationContext) -> ValidationResult:
        started = time.perf_counter()
        try:
            response = context.request(request.endpoint, method="GET")
        except Exception as exc:
            return _failure_result(request, context, self.name, exc, started)
        summary = self._response_summary(response)
        if response.status_code in {200, 204} and not response.blocked_redirect:
            status = "verified"
            reason = "endpoint_accessible"
            observation = f"Endpoint returned HTTP {response.status_code} without authentication context."
        elif response.status_code in {401, 403, 404} or _looks_like_login_redirect(summary.redirect_location):
            status = "false_positive"
            reason = "endpoint_not_accessible"
            observation = f"Endpoint returned HTTP {response.status_code} or redirected to login."
        else:
            status = "unverified"
            reason = "endpoint_access_inconclusive"
            observation = f"Endpoint returned HTTP {response.status_code} with inconclusive exposure evidence."
        evidence = context.sanitizer.sanitize_evidence(
            ValidationEvidence(
                type="http_observation",
                request=self._request_summary(request.endpoint, "GET"),
                response=summary,
                observation=observation,
            )
        )
        return ValidationResult(
            finding_id=request.finding_id,
            status=status,
            validator=self.name.value,
            confidence_before=request.confidence_before,
            confidence_after=update_confidence(context.settings, request.confidence_before, status),
            evidence=[evidence],
            reason=reason,
            requests_made=context.requests_made,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine_version=context.settings.validation_engine_version,
        )


class AuthBehaviorValidator(BaseValidator):
    name = ValidationActionType.CHECK_AUTH_BEHAVIOR

    def validate(self, request: ValidationRequest, context: ValidationContext) -> ValidationResult:
        started = time.perf_counter()
        auth_header = getattr(context.settings, "validation_auth_header", None)
        if not auth_header:
            return ValidationResult(
                finding_id=request.finding_id,
                status="validation_skipped",
                validator=self.name.value,
                confidence_before=request.confidence_before,
                confidence_after=request.confidence_before,
                reason="missing_auth_context",
                requests_made=0,
                duration_ms=0,
                engine_version=context.settings.validation_engine_version,
            )
        try:
            unauth = context.request(request.endpoint, method="GET")
            auth = context.request(request.endpoint, method="GET", headers={"Authorization": auth_header})
        except Exception as exc:
            return _failure_result(request, context, self.name, exc, started)
        status = "verified" if _auth_difference_is_meaningful(unauth, auth) else "false_positive"
        reason = "auth_context_changes_behavior" if status == "verified" else "auth_context_does_not_change_behavior"
        evidence = [
            context.sanitizer.sanitize_evidence(
                ValidationEvidence(
                    type="http_observation",
                    request=self._request_summary(request.endpoint, "GET"),
                    response=self._response_summary(unauth),
                    observation="Unauthenticated response captured.",
                )
            ),
            context.sanitizer.sanitize_evidence(
                ValidationEvidence(
                    type="http_observation",
                    request=self._request_summary(request.endpoint, "GET", headers={"Authorization": auth_header}),
                    response=self._response_summary(auth),
                    observation="Authenticated response captured with configured safe session context.",
                )
            ),
        ]
        return ValidationResult(
            finding_id=request.finding_id,
            status=status,
            validator=self.name.value,
            confidence_before=request.confidence_before,
            confidence_after=update_confidence(context.settings, request.confidence_before, status),
            evidence=evidence,
            reason=reason,
            requests_made=context.requests_made,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine_version=context.settings.validation_engine_version,
        )


class MethodBehaviorValidator(BaseValidator):
    name = ValidationActionType.CHECK_METHOD_BEHAVIOR

    def validate(self, request: ValidationRequest, context: ValidationContext) -> ValidationResult:
        started = time.perf_counter()
        try:
            baseline = context.request(request.endpoint, method="GET")
            head_response = context.request(request.endpoint, method="HEAD")
            options_response = context.request(request.endpoint, method="OPTIONS")
        except Exception as exc:
            return _failure_result(request, context, self.name, exc, started)
        evidence = [
            context.sanitizer.sanitize_evidence(
                ValidationEvidence(
                    type="http_observation",
                    request=self._request_summary(request.endpoint, "GET"),
                    response=self._response_summary(baseline),
                    observation="GET baseline captured for safe method comparison.",
                )
            ),
            context.sanitizer.sanitize_evidence(
                ValidationEvidence(
                    type="http_observation",
                    request=self._request_summary(request.endpoint, "HEAD"),
                    response=self._response_summary(head_response),
                    observation="HEAD response captured for safe method comparison.",
                )
            ),
            context.sanitizer.sanitize_evidence(
                ValidationEvidence(
                    type="http_observation",
                    request=self._request_summary(request.endpoint, "OPTIONS"),
                    response=self._response_summary(options_response),
                    observation="OPTIONS response captured for safe method comparison.",
                )
            ),
        ]
        return ValidationResult(
            finding_id=request.finding_id,
            status="unverified",
            validator=self.name.value,
            confidence_before=request.confidence_before,
            confidence_after=update_confidence(context.settings, request.confidence_before, "unverified"),
            evidence=evidence,
            reason="safe_method_differences_are_not_sufficient_for_verification",
            requests_made=context.requests_made,
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine_version=context.settings.validation_engine_version,
        )


def fingerprint_response(response: HTTPFetchResult) -> ResponseFingerprint:
    title, _, _, _ = inspect_html(response.body)
    selected_headers = {
        name: value
        for name, value in response.headers
        if name in SELECTED_RESPONSE_HEADERS
    }
    return ResponseFingerprint(
        status_code=response.status_code,
        body_length=response.body_length,
        body_hash=hashlib.sha256(response.body).hexdigest(),
        content_type=dict(response.headers).get("Content-Type"),
        title=title,
        selected_headers=selected_headers,
        redirect_location=response.redirect_location,
        blocked_redirect=response.blocked_redirect,
    )


def build_controlled_alternate_url(url: str) -> str:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_pairs.append(("pentestflow_probe", "1"))
    return urlunparse(parsed._replace(query=urlencode(query_pairs)))


def infer_security_header_name(title: str, evidence: list[str]) -> str | None:
    supported = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    haystack = " ".join([title, *evidence]).lower()
    for header in supported:
        if header.lower() in haystack:
            return header
    return None


def update_confidence(settings, previous: float, status: str) -> float:
    if status == "verified":
        return max(previous, settings.validation_verified_confidence_floor)
    if status == "false_positive":
        return min(previous, settings.validation_false_positive_confidence_ceiling)
    if status == "unverified":
        return max(0.0, previous - settings.validation_unverified_confidence_decay)
    return previous


def build_validation_cache_key(
    *,
    finding_id: str,
    validator_type: str,
    endpoint: str,
    method: str,
    reason: str | None,
    engine_version: str,
) -> str:
    payload = {
        "finding_id": finding_id,
        "validator_type": validator_type,
        "endpoint": endpoint,
        "method": method,
        "reason": reason,
        "engine_version": engine_version,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


class ValidationRouter:
    def __init__(self) -> None:
        self.registry: dict[str, Validator] = {
            ValidationActionType.COMPARE_HTTP_RESPONSE.value: ResponseComparisonValidator(),
            ValidationActionType.CHECK_SECURITY_HEADER.value: SecurityHeaderValidator(),
            ValidationActionType.CHECK_STATUS_BEHAVIOR.value: ResponseComparisonValidator(),
            ValidationActionType.CHECK_REDIRECT_BEHAVIOR.value: EndpointAccessibilityValidator(),
            ValidationActionType.CHECK_ENDPOINT_ACCESSIBILITY.value: EndpointAccessibilityValidator(),
            ValidationActionType.CHECK_AUTH_BEHAVIOR.value: AuthBehaviorValidator(),
            ValidationActionType.CHECK_METHOD_BEHAVIOR.value: MethodBehaviorValidator(),
            ValidationActionType.CHECK_CONTENT_DIFFERENCE.value: ResponseComparisonValidator(),
        }

    def resolve(self, requested_type: str | None) -> Validator | None:
        if not requested_type:
            return None
        return self.registry.get(requested_type)

    def supported_types(self) -> list[str]:
        return list(self.registry)


class ValidationService:
    def __init__(self, settings, scope_guard: ScopeGuard, metrics_collector: RuntimeMetricsCollector | None = None) -> None:
        self.settings = settings
        self.scope_guard = scope_guard
        self.router = ValidationRouter()
        self.sanitizer = EvidenceSanitizer()
        self.metrics_collector = metrics_collector
        self.cache = SQLiteJSONCache(
            settings.sqlite_path.parent / ".pentestflow-validation-cache.sqlite3",
            table_name="validation_cache",
        )

    def validate_candidate(self, candidate, analysis: FindingAnalysis | None, *, remaining_scan_requests: int) -> ValidationResult:
        if analysis is None:
            return self._skipped_result(candidate.id, None, candidate.confidence, "analysis_unavailable")
        if not self.settings.validation_enabled:
            return self._skipped_result(candidate.id, analysis.recommended_validation, analysis.final_confidence, "validation_disabled")
        if remaining_scan_requests <= 0:
            return self._skipped_result(candidate.id, analysis.recommended_validation, analysis.final_confidence, "scan_request_budget_exceeded")
        if not should_validate(analysis.status, candidate.severity.value if hasattr(candidate.severity, "value") else str(candidate.severity)):
            return self._skipped_result(candidate.id, analysis.recommended_validation, analysis.final_confidence, "validation_not_selected")
        validator = self.router.resolve(analysis.recommended_validation.type if analysis.recommended_validation else None)
        if validator is None:
            return self._skipped_result(candidate.id, analysis.recommended_validation, analysis.final_confidence, "unsupported_validator")

        request = ValidationRequest(
            finding_id=candidate.id,
            recommended_type=analysis.recommended_validation.type if analysis.recommended_validation else None,
            reason=analysis.recommended_validation.reason if analysis.recommended_validation else None,
            endpoint=candidate.endpoint,
            method=candidate.method,
            analysis_status=analysis.status,
            confidence_before=analysis.final_confidence,
        )
        cache_key = build_validation_cache_key(
            finding_id=candidate.id,
            validator_type=validator.name.value,
            endpoint=candidate.endpoint,
            method=candidate.method,
            reason=request.reason,
            engine_version=self.settings.validation_engine_version,
        )
        cached = self.cache.get(cache_key) if self.settings.validation_cache_enabled else None
        if cached:
            if self.metrics_collector:
                self.metrics_collector.record_cache("validation", True)
            return ValidationResult.model_validate(cached).model_copy(update={"cached": True})
        if self.metrics_collector:
            self.metrics_collector.record_cache("validation", False)

        context = ValidationContext(
            settings=self.settings,
            scope_guard=self.scope_guard,
            sanitizer=self.sanitizer,
            finding_title=candidate.title,
            finding_evidence=candidate.evidence,
            base_url=candidate.endpoint,
            per_finding_limit=self.settings.max_validation_requests_per_finding,
            scan_remaining_requests=remaining_scan_requests,
        )
        result = validator.validate(request, context)
        if self.settings.validation_cache_enabled and should_cache_result(result):
            self.cache.set(cache_key, result.model_dump(mode="json"), ttl_seconds=self.settings.validation_cache_ttl_seconds)
        return result

    def _skipped_result(self, finding_id: str, recommended_validation, confidence_before: float, reason: str) -> ValidationResult:
        return ValidationResult(
            finding_id=finding_id,
            status="validation_skipped",
            validator=getattr(recommended_validation, "type", None),
            confidence_before=confidence_before,
            confidence_after=confidence_before,
            reason=reason,
            requests_made=0,
            duration_ms=0,
            engine_version=self.settings.validation_engine_version,
        )


def should_validate(analysis_status: str, severity: str) -> bool:
    if severity == "INFO":
        return False
    if analysis_status == "needs_validation":
        return True
    if analysis_status == "likely":
        return True
    if analysis_status == "insufficient_evidence":
        return True
    if analysis_status == "likely_false_positive":
        return True
    return False


def should_cache_result(result: ValidationResult) -> bool:
    if result.status == "validation_skipped":
        return False
    return result.reason not in {"request_timeout", "connection_error", "scope_violation", "request_budget_exceeded"}


def _failure_result(
    request: ValidationRequest,
    context: ValidationContext,
    validator_type: ValidationActionType,
    exc: Exception,
    started: float,
) -> ValidationResult:
    reason = map_exception_to_reason(exc)
    confidence_after = request.confidence_before if reason in {"scope_violation", "missing_auth_context"} else update_confidence(
        context.settings, request.confidence_before, "unverified"
    )
    status = "validation_skipped" if reason in {"scope_violation", "request_budget_exceeded"} else "unverified"
    return ValidationResult(
        finding_id=request.finding_id,
        status=status,
        validator=validator_type.value,
        confidence_before=request.confidence_before,
        confidence_after=confidence_after,
        reason=reason,
        requests_made=context.requests_made,
        duration_ms=int((time.perf_counter() - started) * 1000),
        engine_version=context.settings.validation_engine_version,
    )


def map_exception_to_reason(exc: Exception) -> str:
    text = str(exc)
    if isinstance(exc, ScopeViolationError):
        return "scope_violation"
    if "timed out" in text.lower():
        return "request_timeout"
    if "request failed" in text.lower():
        return "connection_error"
    if "request_budget_exceeded" in text:
        return "request_budget_exceeded"
    if "forbidden_method" in text:
        return "forbidden_method"
    return "unexpected_response"


def _auth_difference_is_meaningful(unauth: HTTPFetchResult, auth: HTTPFetchResult) -> bool:
    unauth_denied = unauth.status_code in {401, 403} or _looks_like_login_redirect(unauth.redirect_location)
    auth_allowed = auth.status_code in {200, 204}
    return unauth_denied and auth_allowed


def _looks_like_login_redirect(location: str | None) -> bool:
    return bool(location and "login" in location.lower())


def _same_origin(left: str, right: str) -> bool:
    a = urlparse(left)
    b = urlparse(right)
    left_port = a.port or (443 if a.scheme == "https" else 80)
    right_port = b.port or (443 if b.scheme == "https" else 80)
    return (a.scheme, a.hostname, left_port) == (b.scheme, b.hostname, right_port)


def _enforce_same_origin(base_url: str, candidate_url: str) -> None:
    if not _same_origin(base_url, candidate_url):
        raise ScopeViolationError(f"Cross-origin validation blocked: {candidate_url}")
