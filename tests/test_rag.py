from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from app.core.config import Settings
from app.core.models import FindingCandidate, Severity
from app.rag.chunker import chunk_documents
from app.rag.embeddings import LocalEmbeddingProvider
from app.rag.knowledge_base import KnowledgeBase
from app.rag.loader import load_documents
from app.rag.models import SecurityDocument
from app.rag.retriever import SecurityRetriever, build_retrieval_query


class RAGTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture_root = Path("tests/fixtures/knowledge")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.settings = Settings(
            sqlite_path=Path(self.temp_dir.name) / "pentestflow.db",
            rag_collection_name="test-security",
            reports_dir=Path(self.temp_dir.name) / "reports",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_document_loading_and_malformed_handling(self) -> None:
        result = load_documents(self.fixture_root)
        self.assertGreaterEqual(len(result.documents), 4)
        self.assertEqual(len(result.warnings), 1)
        self.assertIn("missing content", result.warnings[0].reason)

    def test_chunking_preserves_metadata_and_deduplicates(self) -> None:
        documents = [
            SecurityDocument(
                id="doc-1",
                source="OWASP",
                title="Security Headers",
                content="A" * 900,
                category="headers",
                cwe_id="CWE-16",
                metadata={"path": "owasp/security-headers.md"},
            ),
            SecurityDocument(
                id="doc-2",
                source="OWASP",
                title="Duplicate",
                content="A" * 900,
                category="headers",
            ),
        ]
        chunks = chunk_documents(documents, chunk_size=400, chunk_overlap=50)
        self.assertGreaterEqual(len(chunks), 2)
        self.assertEqual(chunks[0].cwe_id, "CWE-16")
        self.assertEqual(chunks[0].metadata["path"], "owasp/security-headers.md")
        unique_contents = {chunk.content for chunk in chunks}
        self.assertEqual(len(unique_contents), len(chunks))

    def test_local_embedding_provider_is_deterministic(self) -> None:
        provider = LocalEmbeddingProvider()
        first = provider.embed_query("sql injection")
        second = provider.embed_query("sql injection")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 128)

    def test_vector_indexing_and_semantic_retrieval(self) -> None:
        knowledge_base = KnowledgeBase(self.settings, knowledge_root=self.fixture_root)
        status = knowledge_base.rebuild()
        context = knowledge_base.search("SQL injection", top_k=3)
        self.assertEqual(status.document_count, 5)
        self.assertGreaterEqual(status.chunk_count, 4)
        self.assertTrue(context.results)
        self.assertEqual(context.results[0].document_id, "cwe-89")

    def test_exact_cwe_preference_and_top_k_enforcement(self) -> None:
        knowledge_base = KnowledgeBase(self.settings, knowledge_root=self.fixture_root)
        knowledge_base.rebuild()
        retriever = SecurityRetriever(knowledge_base, top_k=7)
        finding = FindingCandidate(
            id="F-001",
            title="Possible XSS CWE-79",
            category="Injection",
            severity=Severity.MEDIUM,
            endpoint="/search",
            method="GET",
            evidence=["reflected payload observed", "CWE-79"],
            source_tool="nuclei",
            confidence=0.7,
            raw_reference="CWE-79",
        )
        context = retriever.retrieve_for_finding(finding)
        self.assertIsNotNone(context)
        self.assertEqual(context.results[0].document_id, "cwe-79")
        self.assertLessEqual(len(context.results), 5)

    def test_retrieval_cache_and_version_invalidation(self) -> None:
        knowledge_base = KnowledgeBase(self.settings, knowledge_root=self.fixture_root)
        first_status = knowledge_base.rebuild()
        first = knowledge_base.search("broken access control", top_k=2)
        second = knowledge_base.search("broken access control", top_k=2)
        self.assertEqual(first.results[0].document_id, second.results[0].document_id)
        self.assertEqual(second.knowledge_base_version, first_status.knowledge_base_version)

        custom_doc = self.fixture_root / "custom" / "new-note.txt"
        custom_doc.write_text("SQL injection prevention also requires least privilege.", encoding="utf-8")
        second_status = knowledge_base.rebuild()
        refreshed = knowledge_base.search("least privilege sql injection", top_k=2)
        self.assertNotEqual(first_status.knowledge_base_version, second_status.knowledge_base_version)
        self.assertEqual(refreshed.knowledge_base_version, second_status.knowledge_base_version)
        custom_doc.unlink()

    def test_finding_candidate_query_builder_and_result_structure(self) -> None:
        knowledge_base = KnowledgeBase(self.settings, knowledge_root=self.fixture_root)
        knowledge_base.rebuild()
        retriever = SecurityRetriever(knowledge_base, top_k=3)
        finding = FindingCandidate(
            id="F-002",
            title="Missing Content-Security-Policy",
            category="Security Misconfiguration",
            severity=Severity.MEDIUM,
            endpoint="/",
            method="GET",
            evidence=["Content-Security-Policy header missing"],
            source_tool="nuclei",
            confidence=0.82,
            raw_reference="weak-csp-detect",
        )
        query = build_retrieval_query(finding)
        context = retriever.retrieve_for_finding(finding)
        self.assertIn("Missing Content-Security-Policy", query)
        self.assertIsNotNone(context)
        self.assertEqual(context.results[0].trusted_as_instruction, False)
        self.assertIn("category", context.results[0].metadata)

    def test_no_retrieval_when_candidate_is_not_meaningful(self) -> None:
        knowledge_base = KnowledgeBase(self.settings, knowledge_root=self.fixture_root)
        knowledge_base.rebuild()
        retriever = SecurityRetriever(knowledge_base, top_k=3)
        finding = FindingCandidate(
            id="F-003",
            title="Administrative Endpoint Discovered",
            category="Attack Surface",
            severity=Severity.INFO,
            endpoint="/admin",
            method="GET",
            evidence=["crawler discovered endpoint /admin"],
            source_tool="crawler",
            confidence=0.35,
        )
        self.assertIsNone(retriever.retrieve_for_finding(finding))

    def test_status_reports_unbuilt_and_built_states(self) -> None:
        knowledge_base = KnowledgeBase(self.settings, knowledge_root=self.fixture_root)
        unbuilt = knowledge_base.status()
        self.assertEqual(unbuilt.knowledge_base_version, "unbuilt")
        built = knowledge_base.rebuild()
        current = knowledge_base.status()
        self.assertEqual(current.knowledge_base_version, built.knowledge_base_version)

    def test_index_payload_is_structured_json(self) -> None:
        knowledge_base = KnowledgeBase(self.settings, knowledge_root=self.fixture_root)
        knowledge_base.rebuild()
        payload = json.loads(knowledge_base.index_path.read_text(encoding="utf-8"))
        self.assertIn("documents", payload)
        self.assertIn("chunks", payload)
        self.assertIn("embeddings", payload)
