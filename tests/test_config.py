from __future__ import annotations

import os
import unittest

from app.core.config import Settings


class SettingsTests(unittest.TestCase):
    def test_from_env_uses_safe_defaults(self) -> None:
        original_hosts = os.environ.pop("PENTESTFLOW_ALLOWED_HOSTS", None)
        original_networks = os.environ.pop("PENTESTFLOW_ALLOWED_NETWORKS", None)
        try:
            settings = Settings.from_env()
        finally:
            if original_hosts is not None:
                os.environ["PENTESTFLOW_ALLOWED_HOSTS"] = original_hosts
            if original_networks is not None:
                os.environ["PENTESTFLOW_ALLOWED_NETWORKS"] = original_networks

        self.assertEqual(settings.allowed_hosts, ["127.0.0.1", "localhost"])
        self.assertEqual(settings.allowed_networks, [])

    def test_from_env_parses_csv_values(self) -> None:
        os.environ["PENTESTFLOW_ALLOWED_HOSTS"] = "127.0.0.1, localhost"
        os.environ["PENTESTFLOW_ALLOWED_NETWORKS"] = "192.168.56.0/24"
        os.environ["PENTESTFLOW_NETWORK_SCAN_ENABLED"] = "false"
        os.environ["PENTESTFLOW_NETWORK_SCAN_TIMEOUT"] = "12.5"
        os.environ["PENTESTFLOW_WEB_REQUEST_TIMEOUT"] = "7.5"
        os.environ["PENTESTFLOW_MAX_ENDPOINT_PROBES"] = "4"
        os.environ["PENTESTFLOW_NUCLEI_ENABLED"] = "false"
        os.environ["PENTESTFLOW_NUCLEI_TIMEOUT"] = "22.0"
        os.environ["PENTESTFLOW_RAG_ENABLED"] = "true"
        os.environ["PENTESTFLOW_RAG_TOP_K"] = "4"
        os.environ["PENTESTFLOW_RAG_CHUNK_SIZE"] = "900"
        os.environ["PENTESTFLOW_RAG_CHUNK_OVERLAP"] = "110"
        os.environ["PENTESTFLOW_RAG_EMBEDDING_MODEL"] = "local-test-v1"
        os.environ["PENTESTFLOW_RAG_COLLECTION_NAME"] = "pentestflow-test"
        os.environ["PENTESTFLOW_RAG_CACHE_ENABLED"] = "false"
        os.environ["PENTESTFLOW_LLM_ENABLED"] = "true"
        os.environ["PENTESTFLOW_LLM_PROVIDER"] = "ollama"
        os.environ["PENTESTFLOW_OLLAMA_BASE_URL"] = "http://127.0.0.1:11434"
        os.environ["PENTESTFLOW_OLLAMA_SMALL_MODEL"] = "small"
        os.environ["PENTESTFLOW_OLLAMA_LARGE_MODEL"] = "large"
        os.environ["PENTESTFLOW_LLM_TIMEOUT_SECONDS"] = "12.0"
        os.environ["PENTESTFLOW_LLM_MAX_INPUT_CHARS"] = "3500"
        os.environ["PENTESTFLOW_ANALYSIS_CONFIDENCE_HIGH"] = "0.9"
        os.environ["PENTESTFLOW_ANALYSIS_CONFIDENCE_LOW"] = "0.6"
        os.environ["PENTESTFLOW_ANALYSIS_WEIGHT_SCANNER"] = "0.3"
        os.environ["PENTESTFLOW_ANALYSIS_WEIGHT_MODEL"] = "0.45"
        os.environ["PENTESTFLOW_ANALYSIS_WEIGHT_RAG"] = "0.15"
        os.environ["PENTESTFLOW_ANALYSIS_WEIGHT_EVIDENCE"] = "0.1"
        os.environ["PENTESTFLOW_INJECTION_SCREEN_ENABLED"] = "false"
        os.environ["PENTESTFLOW_ANALYSIS_CACHE_ENABLED"] = "false"
        os.environ["PENTESTFLOW_ANALYSIS_PROMPT_VERSION"] = "v2"
        os.environ["PENTESTFLOW_VALIDATION_ENABLED"] = "true"
        os.environ["PENTESTFLOW_MAX_VALIDATION_REQUESTS_PER_FINDING"] = "4"
        os.environ["PENTESTFLOW_MAX_VALIDATION_REQUESTS_PER_SCAN"] = "12"
        os.environ["PENTESTFLOW_VALIDATION_TIMEOUT_SECONDS"] = "6.5"
        os.environ["PENTESTFLOW_MAX_VALIDATION_ATTEMPTS"] = "3"
        os.environ["PENTESTFLOW_VALIDATION_AUTH_HEADER"] = "Bearer local"
        os.environ["PENTESTFLOW_VALIDATION_CACHE_ENABLED"] = "false"
        os.environ["PENTESTFLOW_VALIDATION_CACHE_TTL_SECONDS"] = "1800"
        os.environ["PENTESTFLOW_VALIDATION_ENGINE_VERSION"] = "v9"
        try:
            settings = Settings.from_env()
        finally:
            os.environ.pop("PENTESTFLOW_ALLOWED_HOSTS", None)
            os.environ.pop("PENTESTFLOW_ALLOWED_NETWORKS", None)
            os.environ.pop("PENTESTFLOW_NETWORK_SCAN_ENABLED", None)
            os.environ.pop("PENTESTFLOW_NETWORK_SCAN_TIMEOUT", None)
            os.environ.pop("PENTESTFLOW_WEB_REQUEST_TIMEOUT", None)
            os.environ.pop("PENTESTFLOW_MAX_ENDPOINT_PROBES", None)
            os.environ.pop("PENTESTFLOW_NUCLEI_ENABLED", None)
            os.environ.pop("PENTESTFLOW_NUCLEI_TIMEOUT", None)
            os.environ.pop("PENTESTFLOW_RAG_ENABLED", None)
            os.environ.pop("PENTESTFLOW_RAG_TOP_K", None)
            os.environ.pop("PENTESTFLOW_RAG_CHUNK_SIZE", None)
            os.environ.pop("PENTESTFLOW_RAG_CHUNK_OVERLAP", None)
            os.environ.pop("PENTESTFLOW_RAG_EMBEDDING_MODEL", None)
            os.environ.pop("PENTESTFLOW_RAG_COLLECTION_NAME", None)
            os.environ.pop("PENTESTFLOW_RAG_CACHE_ENABLED", None)
            os.environ.pop("PENTESTFLOW_LLM_ENABLED", None)
            os.environ.pop("PENTESTFLOW_LLM_PROVIDER", None)
            os.environ.pop("PENTESTFLOW_OLLAMA_BASE_URL", None)
            os.environ.pop("PENTESTFLOW_OLLAMA_SMALL_MODEL", None)
            os.environ.pop("PENTESTFLOW_OLLAMA_LARGE_MODEL", None)
            os.environ.pop("PENTESTFLOW_LLM_TIMEOUT_SECONDS", None)
            os.environ.pop("PENTESTFLOW_LLM_MAX_INPUT_CHARS", None)
            os.environ.pop("PENTESTFLOW_ANALYSIS_CONFIDENCE_HIGH", None)
            os.environ.pop("PENTESTFLOW_ANALYSIS_CONFIDENCE_LOW", None)
            os.environ.pop("PENTESTFLOW_ANALYSIS_WEIGHT_SCANNER", None)
            os.environ.pop("PENTESTFLOW_ANALYSIS_WEIGHT_MODEL", None)
            os.environ.pop("PENTESTFLOW_ANALYSIS_WEIGHT_RAG", None)
            os.environ.pop("PENTESTFLOW_ANALYSIS_WEIGHT_EVIDENCE", None)
            os.environ.pop("PENTESTFLOW_INJECTION_SCREEN_ENABLED", None)
            os.environ.pop("PENTESTFLOW_ANALYSIS_CACHE_ENABLED", None)
            os.environ.pop("PENTESTFLOW_ANALYSIS_PROMPT_VERSION", None)
            os.environ.pop("PENTESTFLOW_VALIDATION_ENABLED", None)
            os.environ.pop("PENTESTFLOW_MAX_VALIDATION_REQUESTS_PER_FINDING", None)
            os.environ.pop("PENTESTFLOW_MAX_VALIDATION_REQUESTS_PER_SCAN", None)
            os.environ.pop("PENTESTFLOW_VALIDATION_TIMEOUT_SECONDS", None)
            os.environ.pop("PENTESTFLOW_MAX_VALIDATION_ATTEMPTS", None)
            os.environ.pop("PENTESTFLOW_VALIDATION_AUTH_HEADER", None)
            os.environ.pop("PENTESTFLOW_VALIDATION_CACHE_ENABLED", None)
            os.environ.pop("PENTESTFLOW_VALIDATION_CACHE_TTL_SECONDS", None)
            os.environ.pop("PENTESTFLOW_VALIDATION_ENGINE_VERSION", None)

        self.assertEqual(settings.allowed_hosts, ["127.0.0.1", "localhost"])
        self.assertEqual(settings.allowed_networks, ["192.168.56.0/24"])
        self.assertFalse(settings.network_scan_enabled)
        self.assertEqual(settings.network_scan_timeout_seconds, 12.5)
        self.assertEqual(settings.web_request_timeout_seconds, 7.5)
        self.assertEqual(settings.max_endpoint_probes, 4)
        self.assertFalse(settings.nuclei_enabled)
        self.assertEqual(settings.nuclei_timeout_seconds, 22.0)
        self.assertTrue(settings.rag_enabled)
        self.assertEqual(settings.rag_top_k, 4)
        self.assertEqual(settings.rag_chunk_size, 900)
        self.assertEqual(settings.rag_chunk_overlap, 110)
        self.assertEqual(settings.rag_embedding_model, "local-test-v1")
        self.assertEqual(settings.rag_collection_name, "pentestflow-test")
        self.assertFalse(settings.rag_cache_enabled)
        self.assertTrue(settings.llm_enabled)
        self.assertEqual(settings.llm_provider, "ollama")
        self.assertEqual(settings.ollama_base_url, "http://127.0.0.1:11434")
        self.assertEqual(settings.ollama_small_model, "small")
        self.assertEqual(settings.ollama_large_model, "large")
        self.assertEqual(settings.llm_timeout_seconds, 12.0)
        self.assertEqual(settings.llm_max_input_chars, 3500)
        self.assertEqual(settings.analysis_confidence_high, 0.9)
        self.assertEqual(settings.analysis_confidence_low, 0.6)
        self.assertEqual(settings.analysis_weight_scanner, 0.3)
        self.assertEqual(settings.analysis_weight_model, 0.45)
        self.assertEqual(settings.analysis_weight_rag, 0.15)
        self.assertEqual(settings.analysis_weight_evidence, 0.1)
        self.assertFalse(settings.injection_screen_enabled)
        self.assertFalse(settings.analysis_cache_enabled)
        self.assertEqual(settings.analysis_prompt_version, "v2")
        self.assertTrue(settings.validation_enabled)
        self.assertEqual(settings.max_validation_requests_per_finding, 4)
        self.assertEqual(settings.max_validation_requests_per_scan, 12)
        self.assertEqual(settings.validation_timeout_seconds, 6.5)
        self.assertEqual(settings.max_validation_attempts, 3)
        self.assertEqual(settings.validation_auth_header, "Bearer local")
        self.assertFalse(settings.validation_cache_enabled)
        self.assertEqual(settings.validation_cache_ttl_seconds, 1800)
        self.assertEqual(settings.validation_engine_version, "v9")
