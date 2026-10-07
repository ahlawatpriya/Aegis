"""Vector store backends for the Aegis RAG system.

Production: PgVectorStore (pgvector extension on Postgres).
Demo: InMemoryVectorStore (dict-based, pure-Python cosine similarity).
"""

import json
import logging
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    from pgvector.sqlalchemy import Vector
    HAS_PGVECTOR = True
except ImportError:
    HAS_PGVECTOR = False
    Vector = None


@dataclass
class SearchResult:
    source_type: str
    source_id: str
    content_text: str
    score: float
    metadata: dict = field(default_factory=dict)


class VectorStoreBase(ABC):

    @abstractmethod
    async def upsert(
        self,
        source_type: str,
        source_id: str,
        text: str,
        embedding: list[float],
        metadata: dict | None = None,
    ) -> None:
        ...

    @abstractmethod
    async def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        source_types: list[str] | None = None,
    ) -> list[SearchResult]:
        ...

    @abstractmethod
    async def delete(self, source_type: str, source_id: str) -> None:
        ...


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class InMemoryVectorStore(VectorStoreBase):

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}

    def _key(self, source_type: str, source_id: str) -> str:
        return f"{source_type}::{source_id}"

    async def upsert(
        self,
        source_type: str,
        source_id: str,
        text: str,
        embedding: list[float],
        metadata: dict | None = None,
    ) -> None:
        key = self._key(source_type, source_id)
        self._store[key] = {
            "source_type": source_type,
            "source_id": source_id,
            "content_text": text,
            "embedding": embedding,
            "metadata": metadata or {},
        }

    async def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        source_types: list[str] | None = None,
    ) -> list[SearchResult]:
        scored: list[tuple[float, dict]] = []
        for entry in self._store.values():
            if source_types and entry["source_type"] not in source_types:
                continue
            score = _cosine_similarity(query_embedding, entry["embedding"])
            scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for score, entry in scored[:top_k]:
            results.append(SearchResult(
                source_type=entry["source_type"],
                source_id=entry["source_id"],
                content_text=entry["content_text"],
                score=score,
                metadata=entry["metadata"],
            ))
        return results

    async def delete(self, source_type: str, source_id: str) -> None:
        key = self._key(source_type, source_id)
        self._store.pop(key, None)

    def load_bulk(self, items: list[dict]) -> None:
        for item in items:
            key = self._key(item["source_type"], item["source_id"])
            self._store[key] = item


class PgVectorStore(VectorStoreBase):

    def __init__(self) -> None:
        if not HAS_PGVECTOR:
            raise ImportError(
                "pgvector is not installed. Install with: pip install 'aegis[rag]'"
            )

    async def upsert(
        self,
        source_type: str,
        source_id: str,
        text: str,
        embedding: list[float],
        metadata: dict | None = None,
    ) -> None:
        from sqlalchemy import text as sa_text

        from aegis.db.engine import get_session

        async with get_session() as session:
            await session.execute(
                sa_text("""
                    INSERT INTO aegis_embedding
                        (source_type, source_id, content_text, embedding, metadata, created_at)
                    VALUES
                        (:source_type, :source_id, :content_text, :embedding, :metadata, NOW())
                    ON CONFLICT (source_type, source_id)
                    DO UPDATE SET
                        content_text = EXCLUDED.content_text,
                        embedding = EXCLUDED.embedding,
                        metadata = EXCLUDED.metadata
                """),
                {
                    "source_type": source_type,
                    "source_id": source_id,
                    "content_text": text,
                    "embedding": str(embedding),
                    "metadata": json.dumps(metadata or {}),
                },
            )
            await session.commit()

    async def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        source_types: list[str] | None = None,
    ) -> list[SearchResult]:
        from sqlalchemy import text as sa_text

        from aegis.db.engine import get_session

        if source_types:
            type_filter = "AND source_type = ANY(:types)"
            params = {
                "q": str(query_embedding),
                "k": top_k,
                "types": source_types,
            }
        else:
            type_filter = ""
            params = {"q": str(query_embedding), "k": top_k}

        query = sa_text(f"""
            SELECT source_type, source_id, content_text, metadata,
                   1 - (embedding <=> :q) AS score
            FROM aegis_embedding
            WHERE 1=1 {type_filter}
            ORDER BY embedding <=> :q
            LIMIT :k
        """)

        async with get_session() as session:
            rows = await session.execute(query, params)
            results = []
            for row in rows:
                results.append(SearchResult(
                    source_type=row.source_type,
                    source_id=row.source_id,
                    content_text=row.content_text,
                    score=float(row.score),
                    metadata=row.metadata or {},
                ))
            return results

    async def delete(self, source_type: str, source_id: str) -> None:
        from sqlalchemy import text as sa_text

        from aegis.db.engine import get_session

        async with get_session() as session:
            await session.execute(
                sa_text(
                    "DELETE FROM aegis_embedding "
                    "WHERE source_type = :st AND source_id = :sid"
                ),
                {"st": source_type, "sid": source_id},
            )
            await session.commit()
