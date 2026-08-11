from __future__ import annotations

from app.rag.models import SecurityChunk, SecurityDocument


def chunk_documents(
    documents: list[SecurityDocument],
    *,
    chunk_size: int = 800,
    chunk_overlap: int = 120,
) -> list[SecurityChunk]:
    chunks: list[SecurityChunk] = []
    seen_contents: set[str] = set()
    for document in documents:
        parts = _split_content(document.content, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        for index, part in enumerate(parts):
            normalized_part = part.strip()
            if not normalized_part or normalized_part in seen_contents:
                continue
            seen_contents.add(normalized_part)
            chunks.append(
                SecurityChunk(
                    id=f"{document.id}:chunk:{index + 1}",
                    document_id=document.id,
                    source=document.source,
                    title=document.title,
                    content=normalized_part,
                    category=document.category,
                    cwe_id=document.cwe_id,
                    owasp_category=document.owasp_category,
                    reference=document.reference,
                    metadata=dict(document.metadata),
                    chunk_index=index,
                    trusted_as_instruction=False,
                )
            )
    return chunks


def _split_content(content: str, *, chunk_size: int, chunk_overlap: int) -> list[str]:
    text = content.strip()
    if not text:
        return []
    if len(text) <= chunk_size:
        return [text]

    paragraphs = [paragraph.strip() for paragraph in text.split("\n\n") if paragraph.strip()]
    if not paragraphs:
        paragraphs = [text]

    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        candidate = paragraph if not current else f"{current}\n\n{paragraph}"
        if len(candidate) <= chunk_size:
            current = candidate
            continue
        if current:
            chunks.append(current)
            overlap = current[-chunk_overlap:] if chunk_overlap > 0 else ""
            current = f"{overlap}{paragraph}".strip()
            if len(current) <= chunk_size:
                continue
        while len(paragraph) > chunk_size:
            slice_end = chunk_size
            chunks.append(paragraph[:slice_end].strip())
            paragraph = paragraph[max(0, slice_end - chunk_overlap):].strip()
        current = paragraph

    if current:
        chunks.append(current.strip())
    return chunks
