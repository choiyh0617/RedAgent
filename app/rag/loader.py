from __future__ import annotations

import json
from pathlib import Path

from app.rag.models import DocumentLoadResult, DocumentLoadWarning, SecurityDocument


def load_documents(knowledge_root: Path) -> DocumentLoadResult:
    documents: list[SecurityDocument] = []
    warnings: list[DocumentLoadWarning] = []
    for path in sorted(knowledge_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".txt", ".md", ".json"}:
            continue
        try:
            loaded = _load_file(path, knowledge_root)
            documents.extend(loaded)
        except ValueError as exc:
            warnings.append(DocumentLoadWarning(path=str(path), reason=str(exc)))
    return DocumentLoadResult(documents=documents, warnings=warnings)


def _load_file(path: Path, knowledge_root: Path) -> list[SecurityDocument]:
    if path.suffix.lower() == ".json":
        return _load_json_documents(path)

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        raise ValueError("empty document")

    source = _source_from_path(path, knowledge_root)
    title = _title_from_text(path, content)
    return [
        SecurityDocument(
            id=path.stem.lower(),
            source=source,
            title=title,
            content=content,
            category=_category_from_path(path),
            metadata={"path": str(path.relative_to(knowledge_root))},
        )
    ]


def _load_json_documents(path: Path) -> list[SecurityDocument]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw if isinstance(raw, list) else raw.get("documents") if isinstance(raw, dict) and "documents" in raw else [raw]
    if not isinstance(items, list):
        raise ValueError("json document must be an object, list, or {'documents': [...]}")

    documents: list[SecurityDocument] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"json item {index} must be an object")
        content = str(item.get("content") or "").strip()
        if not content:
            raise ValueError(f"json item {index} missing content")
        metadata = item.get("metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError(f"json item {index} metadata must be an object")
        documents.append(
            SecurityDocument(
                id=str(item.get("id") or f"{path.stem}-{index}"),
                source=str(item.get("source") or "CUSTOM"),
                title=str(item.get("title") or path.stem.replace("-", " ").title()),
                content=content,
                category=str(item.get("category") or path.stem.replace("-", " ")),
                cwe_id=_optional_string(item.get("cwe_id")),
                owasp_category=_optional_string(item.get("owasp_category")),
                reference=_optional_string(item.get("reference")),
                metadata=metadata,
            )
        )
    return documents


def _source_from_path(path: Path, knowledge_root: Path) -> str:
    try:
        top_level = path.relative_to(knowledge_root).parts[0]
    except IndexError:
        top_level = "custom"
    mapping = {"owasp": "OWASP", "cwe": "CWE", "custom": "CUSTOM"}
    return mapping.get(top_level.lower(), top_level.upper())


def _title_from_text(path: Path, content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
        if stripped:
            return stripped[:80]
    return path.stem.replace("-", " ").title()


def _category_from_path(path: Path) -> str:
    stem = path.stem.replace("-", " ").replace("_", " ").strip().lower()
    return stem or "security"


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
