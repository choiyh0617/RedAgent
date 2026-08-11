from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "PentestFlow"
    app_env: str = "development"
    log_level: str = "INFO"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allowed_networks: list[str] = Field(default_factory=list)
    web_request_timeout_seconds: float = 5.0
    network_scan_enabled: bool = True
    network_scan_timeout_seconds: float = 20.0
    max_endpoint_probes: int = 10
    nuclei_enabled: bool = True
    nuclei_timeout_seconds: float = 30.0
    rag_enabled: bool = True
    rag_top_k: int = 3
    rag_chunk_size: int = 800
    rag_chunk_overlap: int = 120
    rag_embedding_model: str = "local-hashing-v1"
    rag_collection_name: str = "pentestflow-security"
    rag_cache_enabled: bool = True
    llm_enabled: bool = True
    llm_provider: str = "ollama"
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_small_model: str = ""
    ollama_large_model: str = ""
    llm_timeout_seconds: float = 20.0
    llm_max_input_chars: int = 4000
    model_cascading_enabled: bool = True
    analysis_confidence_high: float = 0.85
    analysis_confidence_low: float = 0.55
    analysis_weight_scanner: float = 0.35
    analysis_weight_model: float = 0.4
    analysis_weight_rag: float = 0.15
    analysis_weight_evidence: float = 0.1
    injection_screen_enabled: bool = True
    analysis_cache_enabled: bool = True
    analysis_prompt_version: str = "v1"
    validation_enabled: bool = True
    max_validation_requests_per_finding: int = 3
    max_validation_requests_per_scan: int = 20
    validation_timeout_seconds: float = 5.0
    max_validation_attempts: int = 2
    validation_auth_header: str | None = None
    validation_cache_enabled: bool = True
    validation_cache_ttl_seconds: int = 3600
    validation_engine_version: str = "v1"
    validation_verified_confidence_floor: float = 0.9
    validation_false_positive_confidence_ceiling: float = 0.2
    validation_unverified_confidence_decay: float = 0.05
    max_redirects: int = 0
    max_crawl_depth: int = 2
    max_crawl_pages: int = 25
    max_agent_steps: int = 10
    max_tool_calls: int = 20
    reports_dir: Path = Path("reports")
    eval_dir: Path = Path("eval")
    sqlite_path: Path = Path("pentestflow.db")
    user_agent: str = "PentestFlow/0.1"
    max_precision_drop: float = 0.03
    max_recall_drop: float = 0.05
    max_runtime_increase_percent: float = 20.0
    max_llm_call_increase_percent: float = 20.0

    @classmethod
    def from_env(cls) -> "Settings":
        allowed_hosts = _split_csv(os.getenv("PENTESTFLOW_ALLOWED_HOSTS")) or ["127.0.0.1", "localhost"]
        allowed_networks = _split_csv(os.getenv("PENTESTFLOW_ALLOWED_NETWORKS"))
        return cls(
            app_env=os.getenv("PENTESTFLOW_ENV", "development"),
            log_level=os.getenv("PENTESTFLOW_LOG_LEVEL", "INFO"),
            allowed_hosts=allowed_hosts,
            allowed_networks=allowed_networks,
            web_request_timeout_seconds=float(
                os.getenv("PENTESTFLOW_WEB_REQUEST_TIMEOUT", os.getenv("PENTESTFLOW_REQUEST_TIMEOUT", "5.0"))
            ),
            network_scan_enabled=_get_bool(os.getenv("PENTESTFLOW_NETWORK_SCAN_ENABLED"), True),
            network_scan_timeout_seconds=float(os.getenv("PENTESTFLOW_NETWORK_SCAN_TIMEOUT", "20.0")),
            max_endpoint_probes=int(os.getenv("PENTESTFLOW_MAX_ENDPOINT_PROBES", "10")),
            nuclei_enabled=_get_bool(os.getenv("PENTESTFLOW_NUCLEI_ENABLED"), True),
            nuclei_timeout_seconds=float(os.getenv("PENTESTFLOW_NUCLEI_TIMEOUT", "30.0")),
            rag_enabled=_get_bool(os.getenv("PENTESTFLOW_RAG_ENABLED"), True),
            rag_top_k=int(os.getenv("PENTESTFLOW_RAG_TOP_K", "3")),
            rag_chunk_size=int(os.getenv("PENTESTFLOW_RAG_CHUNK_SIZE", "800")),
            rag_chunk_overlap=int(os.getenv("PENTESTFLOW_RAG_CHUNK_OVERLAP", "120")),
            rag_embedding_model=os.getenv("PENTESTFLOW_RAG_EMBEDDING_MODEL", "local-hashing-v1"),
            rag_collection_name=os.getenv("PENTESTFLOW_RAG_COLLECTION_NAME", "pentestflow-security"),
            rag_cache_enabled=_get_bool(os.getenv("PENTESTFLOW_RAG_CACHE_ENABLED"), True),
            llm_enabled=_get_bool(os.getenv("PENTESTFLOW_LLM_ENABLED"), True),
            llm_provider=os.getenv("PENTESTFLOW_LLM_PROVIDER", "ollama"),
            ollama_base_url=os.getenv("PENTESTFLOW_OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
            ollama_small_model=os.getenv("PENTESTFLOW_OLLAMA_SMALL_MODEL", ""),
            ollama_large_model=os.getenv("PENTESTFLOW_OLLAMA_LARGE_MODEL", ""),
            llm_timeout_seconds=float(os.getenv("PENTESTFLOW_LLM_TIMEOUT_SECONDS", "20.0")),
            llm_max_input_chars=int(os.getenv("PENTESTFLOW_LLM_MAX_INPUT_CHARS", "4000")),
            model_cascading_enabled=_get_bool(os.getenv("PENTESTFLOW_MODEL_CASCADING_ENABLED"), True),
            analysis_confidence_high=float(os.getenv("PENTESTFLOW_ANALYSIS_CONFIDENCE_HIGH", "0.85")),
            analysis_confidence_low=float(os.getenv("PENTESTFLOW_ANALYSIS_CONFIDENCE_LOW", "0.55")),
            analysis_weight_scanner=float(os.getenv("PENTESTFLOW_ANALYSIS_WEIGHT_SCANNER", "0.35")),
            analysis_weight_model=float(os.getenv("PENTESTFLOW_ANALYSIS_WEIGHT_MODEL", "0.4")),
            analysis_weight_rag=float(os.getenv("PENTESTFLOW_ANALYSIS_WEIGHT_RAG", "0.15")),
            analysis_weight_evidence=float(os.getenv("PENTESTFLOW_ANALYSIS_WEIGHT_EVIDENCE", "0.1")),
            injection_screen_enabled=_get_bool(os.getenv("PENTESTFLOW_INJECTION_SCREEN_ENABLED"), True),
            analysis_cache_enabled=_get_bool(os.getenv("PENTESTFLOW_ANALYSIS_CACHE_ENABLED"), True),
            analysis_prompt_version=os.getenv("PENTESTFLOW_ANALYSIS_PROMPT_VERSION", "v1"),
            validation_enabled=_get_bool(os.getenv("PENTESTFLOW_VALIDATION_ENABLED"), True),
            max_validation_requests_per_finding=int(
                os.getenv("PENTESTFLOW_MAX_VALIDATION_REQUESTS_PER_FINDING", "3")
            ),
            max_validation_requests_per_scan=int(os.getenv("PENTESTFLOW_MAX_VALIDATION_REQUESTS_PER_SCAN", "20")),
            validation_timeout_seconds=float(os.getenv("PENTESTFLOW_VALIDATION_TIMEOUT_SECONDS", "5.0")),
            max_validation_attempts=int(os.getenv("PENTESTFLOW_MAX_VALIDATION_ATTEMPTS", "2")),
            validation_auth_header=os.getenv("PENTESTFLOW_VALIDATION_AUTH_HEADER"),
            validation_cache_enabled=_get_bool(os.getenv("PENTESTFLOW_VALIDATION_CACHE_ENABLED"), True),
            validation_cache_ttl_seconds=int(os.getenv("PENTESTFLOW_VALIDATION_CACHE_TTL_SECONDS", "3600")),
            validation_engine_version=os.getenv("PENTESTFLOW_VALIDATION_ENGINE_VERSION", "v1"),
            validation_verified_confidence_floor=float(
                os.getenv("PENTESTFLOW_VALIDATION_CONFIDENCE_VERIFIED", "0.9")
            ),
            validation_false_positive_confidence_ceiling=float(
                os.getenv("PENTESTFLOW_VALIDATION_CONFIDENCE_FALSE_POSITIVE", "0.2")
            ),
            validation_unverified_confidence_decay=float(
                os.getenv("PENTESTFLOW_VALIDATION_CONFIDENCE_UNVERIFIED_DECAY", "0.05")
            ),
            max_redirects=int(os.getenv("PENTESTFLOW_MAX_REDIRECTS", "0")),
            max_crawl_depth=int(os.getenv("PENTESTFLOW_MAX_CRAWL_DEPTH", "2")),
            max_crawl_pages=int(os.getenv("PENTESTFLOW_MAX_CRAWL_PAGES", "25")),
            max_agent_steps=int(os.getenv("PENTESTFLOW_MAX_AGENT_STEPS", "10")),
            max_tool_calls=int(os.getenv("PENTESTFLOW_MAX_TOOL_CALLS", "20")),
            reports_dir=Path(os.getenv("PENTESTFLOW_REPORTS_DIR", "reports")),
            eval_dir=Path(os.getenv("PENTESTFLOW_EVAL_DIR", "eval")),
            sqlite_path=Path(os.getenv("PENTESTFLOW_SQLITE_PATH", "pentestflow.db")),
            user_agent=os.getenv("PENTESTFLOW_USER_AGENT", "PentestFlow/0.1"),
            max_precision_drop=float(os.getenv("PENTESTFLOW_MAX_PRECISION_DROP", "0.03")),
            max_recall_drop=float(os.getenv("PENTESTFLOW_MAX_RECALL_DROP", "0.05")),
            max_runtime_increase_percent=float(os.getenv("PENTESTFLOW_MAX_RUNTIME_INCREASE_PERCENT", "20.0")),
            max_llm_call_increase_percent=float(os.getenv("PENTESTFLOW_MAX_LLM_CALL_INCREASE_PERCENT", "20.0")),
        )

    def parsed_allowed_networks(self) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(network, strict=False) for network in self.allowed_networks]

    @property
    def request_timeout_seconds(self) -> float:
        return self.web_request_timeout_seconds


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _get_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()
