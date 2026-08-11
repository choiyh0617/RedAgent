from __future__ import annotations

import abc
import hashlib
import math
import re

TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_]+")


class EmbeddingProvider(abc.ABC):
    name: str

    @abc.abstractmethod
    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError

    def embed_query(self, text: str) -> list[float]:
        return self.embed_texts([text])[0]


class LocalEmbeddingProvider(EmbeddingProvider):
    def __init__(self, *, dimensions: int = 128, model_name: str = "local-hashing-v1") -> None:
        self.dimensions = dimensions
        self.name = model_name

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_single(text) for text in texts]

    def _embed_single(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in TOKEN_PATTERN.findall(text.lower()):
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            weight = 1.0 + (digest[5] / 255.0)
            vector[bucket] += sign * weight
        return _normalize(vector)


def embed_texts(texts: list[str]) -> list[list[float]]:
    return LocalEmbeddingProvider().embed_texts(texts)


def _normalize(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return vector
    return [value / norm for value in vector]
