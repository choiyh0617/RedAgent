from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class ToolExecution(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None
    duration_ms: int = 0
    success: bool = False
    error: str | None = None


class ScopeDecision(BaseModel):
    target: str
    normalized_target: str
    allowed: bool
    reason: str


class TargetInfo(BaseModel):
    original: str
    normalized: HttpUrl
    scheme: str
    hostname: str
    port: int
    ip: str | None = None


class HTTPHeader(BaseModel):
    name: str
    value: str


class RedirectHop(BaseModel):
    from_url: str
    to_url: str
    status_code: int
    blocked: bool = False


class SecurityHeader(BaseModel):
    name: str
    present: bool
    value: str | None = None


class WebProbeResult(BaseModel):
    target: HttpUrl
    in_scope: bool
    final_url: str
    status_code: int
    reason_phrase: str
    ip: str | None = None
    port: int
    scheme: str
    title: str | None = None
    server: str | None = None
    content_type: str | None = None
    headers: list[HTTPHeader] = Field(default_factory=list)
    security_headers: list[SecurityHeader] = Field(default_factory=list)
    meta_tags: dict[str, str] = Field(default_factory=dict)
    script_urls: list[str] = Field(default_factory=list)
    body_preview: str | None = None
    body_length: int = 0
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    redirect_location: str | None = None
    blocked_redirect: bool = False
    response_time_ms: int = 0


class ServiceInfo(BaseModel):
    name: str | None = None
    product: str | None = None
    version: str | None = None


class PortInfo(BaseModel):
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


class NetworkScanResult(BaseModel):
    target: HttpUrl
    resolved_ip: str | None = None
    mode: str
    ports: list[PortInfo] = Field(default_factory=list)
    scan_duration_ms: int = 0
    success: bool = False
    error: str | None = None
    raw_summary: str | None = None


class TechnologyEvidence(BaseModel):
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class RobotsTxtResult(BaseModel):
    target: HttpUrl
    url: str
    status_code: int | None = None
    exists: bool = False
    allow: list[str] = Field(default_factory=list)
    disallow: list[str] = Field(default_factory=list)
    sitemaps: list[str] = Field(default_factory=list)
    redirect_location: str | None = None
    blocked_redirect: bool = False


class EndpointProbeResult(BaseModel):
    path: str
    url: str
    method: str
    status_code: int | None = None
    content_type: str | None = None
    redirect_location: str | None = None
    blocked_redirect: bool = False
    exists: bool = False


class CrawlForm(BaseModel):
    action: str
    method: str = "GET"
    fields: list[str] = Field(default_factory=list)


class CrawlPageResult(BaseModel):
    url: str
    depth: int
    status_code: int
    title: str | None = None
    content_type: str | None = None
    links: list[str] = Field(default_factory=list)
    forms: list[CrawlForm] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    script_urls: list[str] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)


class CrawlResult(BaseModel):
    target: HttpUrl
    pages: list[CrawlPageResult] = Field(default_factory=list)
    discovered_urls: list[str] = Field(default_factory=list)
    total_requests: int = 0
    max_depth_reached: int = 0
    success: bool = False
    error: str | None = None


class NucleiScanResult(BaseModel):
    target: HttpUrl
    command: list[str] = Field(default_factory=list)
    candidates: list["FindingCandidate"] = Field(default_factory=list)
    success: bool = False
    scan_duration_ms: int = 0
    error: str | None = None
    raw_summary: str | None = None


class ReconResult(BaseModel):
    target: HttpUrl
    target_ip: str | None = None
    http_services: list[WebProbeResult] = Field(default_factory=list)
    network_scan: NetworkScanResult | None = None
    open_ports: list[PortInfo] = Field(default_factory=list)
    technologies: list[TechnologyEvidence] = Field(default_factory=list)
    robots_txt: RobotsTxtResult | None = None
    common_endpoints: list[EndpointProbeResult] = Field(default_factory=list)
    crawl: CrawlResult | None = None
    nuclei: NucleiScanResult | None = None
    finding_candidates: list["FindingCandidate"] = Field(default_factory=list)
    tool_executions: list[ToolExecution] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    validation_metrics: dict[str, Any] | None = None
    runtime_metrics: dict[str, Any] | None = None


class FindingCandidate(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    endpoint: str
    method: str
    evidence: list[str] = Field(default_factory=list)
    source_tool: str
    confidence: float = Field(ge=0.0, le=1.0)
    raw_reference: str | None = None
    rag_context: dict[str, Any] | None = None
    analysis: dict[str, Any] | None = None
    validation: dict[str, Any] | None = None
    final_status: str = "candidate"


class ScanRequest(BaseModel):
    target: HttpUrl


class ScanRecord(BaseModel):
    scan_id: str
    target: HttpUrl
    status: ScanStatus
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scope: list[str] = Field(default_factory=list)
    recon: ReconResult | None = None
    finding_candidates: list[FindingCandidate] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    tools_used: list[ToolExecution] = Field(default_factory=list)
    validation_metrics: dict[str, Any] | None = None
    runtime_metrics: dict[str, Any] | None = None
