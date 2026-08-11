from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.eval.metrics import RuntimeMetricsCollector
from app.rag.chunker import chunk_documents
from app.rag.embeddings import EmbeddingProvider, LocalEmbeddingProvider
from app.rag.loader import load_documents
from app.rag.models import KnowledgeBaseStatus, RAGContext, RetrievedKnowledge, SecurityChunk


class KnowledgeBase:
    def __init__(
        self,
        settings: Settings,
        *,
        embedding_provider: EmbeddingProvider | None = None,
        knowledge_root: Path | None = None,
        metrics_collector: RuntimeMetricsCollector | None = None,
    ) -> None:
        self.settings = settings
        self.embedding_provider = embedding_provider or LocalEmbeddingProvider(model_name=settings.rag_embedding_model)
        self.knowledge_root = knowledge_root or Path("knowledge")
        self.storage_dir = settings.sqlite_path.parent / ".pentestflow-rag"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.storage_dir / f"{settings.rag_collection_name}.json"
        self.manifest_path = self.storage_dir / f"{settings.rag_collection_name}.manifest.json"
        self.cache_db_path = self.storage_dir / "rag-cache.sqlite3"
        self.metrics_collector = metrics_collector

    def rebuild(self) -> KnowledgeBaseStatus:
        load_result = load_documents(self.knowledge_root)
        chunks = chunk_documents(
            load_result.documents,
            chunk_size=self.settings.rag_chunk_size,
            chunk_overlap=self.settings.rag_chunk_overlap,
        )
        embeddings = self.embedding_provider.embed_texts([chunk.content for chunk in chunks])
        version = _compute_version(load_result.documents, chunks)
        payload = {
            "knowledge_base_version": version,
            "embedding_provider": self.embedding_provider.name,
            "vector_store": _vector_store_name(),
            "documents": [document.model_dump(mode="json") for document in load_result.documents],
            "chunks": [chunk.model_dump(mode="json") for chunk in chunks],
            "embeddings": embeddings,
            "warnings": [warning.model_dump(mode="json") for warning in load_result.warnings],
        }
        self.index_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        status = KnowledgeBaseStatus(
            collection_name=self.settings.rag_collection_name,
            vector_store=_vector_store_name(),
            embedding_provider=self.embedding_provider.name,
            knowledge_base_version=version,
            document_count=len(load_result.documents),
            chunk_count=len(chunks),
        )
        self.manifest_path.write_text(json.dumps(status.model_dump(mode="json"), indent=2), encoding="utf-8")
        if self.settings.rag_cache_enabled:
            self._clear_cache_for_version(version)
        return status

    def status(self) -> KnowledgeBaseStatus:
        if not self.manifest_path.exists():
            return KnowledgeBaseStatus(
                collection_name=self.settings.rag_collection_name,
                vector_store=_vector_store_name(),
                embedding_provider=self.embedding_provider.name,
                knowledge_base_version="unbuilt",
                document_count=0,
                chunk_count=0,
                indexed_at=None,
            )
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        return KnowledgeBaseStatus.model_validate(data)

    def search(self, query: str, top_k: int = 3, filters: dict[str, str] | None = None) -> RAGContext:
        top_k = min(max(1, top_k), 5)
        start = time.perf_counter()
        index = self._load_index()
        version = index["knowledge_base_version"]
        normalized_filters = dict(filters or {})
        cache_key = _cache_key(query, version, normalized_filters)
        cached = self._load_cache(cache_key)
        if cached is not None:
            if self.metrics_collector:
                self.metrics_collector.record_cache("rag", True)
            return RAGContext.model_validate(cached)
        if self.metrics_collector:
            self.metrics_collector.record_cache("rag", False)

        chunks = [SecurityChunk.model_validate(item) for item in index["chunks"]]
        embeddings = index["embeddings"]
        query_embedding = self.embedding_provider.embed_query(query)
        ranked = []
        preferred_chunks = _filter_chunks(chunks, normalized_filters)
        pool = preferred_chunks or chunks
        for chunk, vector in zip(chunks, embeddings, strict=False):
            if pool is not chunks and chunk.id not in {preferred.id for preferred in pool}:
                continue
            ranked.append(
                RetrievedKnowledge(
                    document_id=chunk.document_id,
                    chunk_id=chunk.id,
                    source=chunk.source,
                    title=chunk.title,
                    content=chunk.content[: self.settings.rag_chunk_size],
                    score=_cosine_similarity(query_embedding, vector),
                    metadata={
                        **chunk.metadata,
                        "category": chunk.category,
                        "cwe_id": chunk.cwe_id,
                        "owasp_category": chunk.owasp_category,
                        "reference": chunk.reference,
                    },
                    trusted_as_instruction=False,
                )
            )
        ranked.sort(key=lambda item: item.score, reverse=True)
        results = _dedupe_results(ranked)[:top_k]
        context = RAGContext(
            query=query,
            results=results,
            retrieval_duration_ms=int((time.perf_counter() - start) * 1000),
            knowledge_base_version=version,
        )
        if self.settings.rag_cache_enabled:
            self._store_cache(cache_key, context)
        return context

    def _load_index(self) -> dict[str, Any]:
        if not self.index_path.exists():
            self.rebuild()
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def _db(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.cache_db_path)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS rag_cache (
                cache_key TEXT PRIMARY KEY,
                knowledge_base_version TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        return connection

    def _load_cache(self, cache_key: str) -> dict[str, Any] | None:
        if not self.settings.rag_cache_enabled:
            return None
        connection = self._db()
        try:
            row = connection.execute(
                "SELECT result_json FROM rag_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        finally:
            connection.close()
        return json.loads(row[0]) if row else None

    def _store_cache(self, cache_key: str, context: RAGContext) -> None:
        connection = self._db()
        try:
            connection.execute(
                "INSERT OR REPLACE INTO rag_cache(cache_key, knowledge_base_version, result_json) VALUES (?, ?, ?)",
                (
                    cache_key,
                    context.knowledge_base_version,
                    json.dumps(context.model_dump(mode="json")),
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def _clear_cache_for_version(self, version: str) -> None:
        connection = self._db()
        try:
            connection.execute(
                "DELETE FROM rag_cache WHERE knowledge_base_version != ?",
                (version,),
            )
            connection.commit()
        finally:
            connection.close()


def initialize_knowledge_base(settings: Settings | None = None) -> KnowledgeBaseStatus:
    configured_settings = settings or Settings()
    return KnowledgeBase(configured_settings).rebuild()


def _compute_version(documents: list[Any], chunks: list[SecurityChunk]) -> str:
    payload = json.dumps(
        {
            "documents": [document.model_dump(mode="json") for document in documents],
            "chunks": [chunk.id for chunk in chunks],
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _cache_key(query: str, version: str, filters: dict[str, str]) -> str:
    payload = json.dumps({"query": query.strip().lower(), "version": version, "filters": filters}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right:
        return 0.0
    return sum(a * b for a, b in zip(left, right, strict=False))


def _dedupe_results(results: list[RetrievedKnowledge]) -> list[RetrievedKnowledge]:
    deduped: list[RetrievedKnowledge] = []
    seen: set[str] = set()
    for result in results:
        key = f"{result.document_id}:{result.content}"
        if key in seen:
            continue
        seen.add(key)
        deduped.append(result)
    return deduped


def _filter_chunks(chunks: list[SecurityChunk], filters: dict[str, str]) -> list[SecurityChunk]:
    if not filters:
        return []
    filtered = []
    for chunk in chunks:
        if all(str(getattr(chunk, key, None) or chunk.metadata.get(key) or "").upper() == str(value).upper() for key, value in filters.items()):
            filtered.append(chunk)
    return filtered


def _vector_store_name() -> str:
    try:
        import chromadb  # noqa: F401
    except ImportError:
        return "local-json-fallback"
    return "ChromaDB-compatible"
