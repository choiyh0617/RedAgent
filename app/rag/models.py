from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class SecurityDocument(BaseModel):
    id: str
    source: str
    title: str
    content: str
    category: str
    cwe_id: str | None = None
    owasp_category: str | None = None
    reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    trusted_as_instruction: bool = False


class DocumentLoadWarning(BaseModel):
    path: str
    reason: str


class DocumentLoadResult(BaseModel):
    documents: list[SecurityDocument] = Field(default_factory=list)
    warnings: list[DocumentLoadWarning] = Field(default_factory=list)


class SecurityChunk(BaseModel):
    id: str
    document_id: str
    source: str
    title: str
    content: str
    category: str
    cwe_id: str | None = None
    owasp_category: str | None = None
    reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    chunk_index: int
    trusted_as_instruction: bool = False


class RetrievedKnowledge(BaseModel):
    document_id: str
    chunk_id: str
    source: str
    title: str
    content: str
    score: float
    metadata: dict[str, Any] = Field(default_factory=dict)
    trusted_as_instruction: bool = False


class RAGContext(BaseModel):
    query: str
    results: list[RetrievedKnowledge] = Field(default_factory=list)
    retrieval_duration_ms: int = 0
    knowledge_base_version: str


class KnowledgeBaseStatus(BaseModel):
    collection_name: str
    vector_store: str
    embedding_provider: str
    knowledge_base_version: str
    document_count: int = 0
    chunk_count: int = 0
    indexed_at: datetime | None = Field(default_factory=lambda: datetime.now(timezone.utc))

