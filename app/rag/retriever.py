from __future__ import annotations

from app.core.models import FindingCandidate
from app.rag.knowledge_base import KnowledgeBase
from app.rag.models import RAGContext


class SecurityRetriever:
    def __init__(self, knowledge_base: KnowledgeBase, *, top_k: int = 3) -> None:
        self.knowledge_base = knowledge_base
        self.top_k = min(max(1, top_k), 5)

    def retrieve_for_finding(self, finding: FindingCandidate) -> RAGContext | None:
        query = build_retrieval_query(finding)
        if not query:
            return None
        filters = {}
        cwe_id = extract_cwe_id(finding)
        if cwe_id:
            filters["cwe_id"] = cwe_id
        return self.knowledge_base.search(query=query, top_k=self.top_k, filters=filters or None)


def build_retrieval_query(finding: FindingCandidate) -> str | None:
    if finding.source_tool == "crawler" and finding.category in {"Attack Surface", "Security Observation"}:
        return None

    parts: list[str] = []
    if finding.title:
        parts.append(finding.title)
    if finding.category and finding.category.lower() not in finding.title.lower():
        parts.append(finding.category)
    cwe_id = extract_cwe_id(finding)
    if cwe_id:
        parts.append(cwe_id)
    if finding.raw_reference and finding.raw_reference not in parts:
        parts.append(finding.raw_reference)
    query = " ".join(part.strip() for part in parts if part and part.strip())
    return query or None


def extract_cwe_id(finding: FindingCandidate) -> str | None:
    candidates = [finding.raw_reference, finding.title, *finding.evidence]
    for value in candidates:
        if not value:
            continue
        text = str(value).upper()
        marker = "CWE-"
        if marker not in text:
            continue
        suffix = text.split(marker, 1)[1]
        digits = []
        for char in suffix:
            if char.isdigit():
                digits.append(char)
            else:
                break
        if digits:
            return f"CWE-{''.join(digits)}"
    return None


def retrieve(query: str, limit: int = 5) -> list[dict]:
    raise NotImplementedError("use SecurityRetriever with a configured KnowledgeBase")
