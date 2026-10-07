"""Retrieval layer — wraps embedder + store into high-level query methods.

Production: Retriever (real embeddings + vector search).
Demo: MockRetriever (keyword-matched mock results).
"""

import logging
from dataclasses import dataclass, field

from aegis.rag.embedder import EmbedderBase
from aegis.rag.store import VectorStoreBase

logger = logging.getLogger(__name__)


@dataclass
class RetrievalResult:
    content: str
    score: float
    source_type: str
    source_id: str
    metadata: dict = field(default_factory=dict)


class Retriever:

    def __init__(self, embedder: EmbedderBase, store: VectorStoreBase) -> None:
        self._embedder = embedder
        self._store = store

    async def retrieve(
        self,
        query: str,
        source_types: list[str] | None = None,
        top_k: int = 5,
    ) -> list[RetrievalResult]:
        embedding = await self._embedder.embed(query)
        results = await self._store.search(embedding, top_k=top_k, source_types=source_types)
        return [
            RetrievalResult(
                content=r.content_text,
                score=r.score,
                source_type=r.source_type,
                source_id=r.source_id,
                metadata=r.metadata,
            )
            for r in results
        ]

    async def retrieve_similar_incidents(
        self,
        article_text: str,
        top_k: int = 3,
    ) -> list[RetrievalResult]:
        return await self.retrieve(article_text, source_types=["news"], top_k=top_k)

    async def retrieve_remediation_context(
        self,
        vuln_type: str,
        ecosystem: str,
        package_name: str,
    ) -> list[RetrievalResult]:
        query = f"{vuln_type} {ecosystem} {package_name} remediation fix upgrade"
        return await self.retrieve(query, source_types=["remediation", "news"], top_k=5)


class MockRetriever:

    def __init__(self) -> None:
        from aegis.demo.rag_data import (
            MOCK_CHAT_RESPONSES,
            MOCK_REMEDIATION_RESULTS,
            MOCK_SIMILAR_INCIDENTS,
        )
        self._chat_responses = MOCK_CHAT_RESPONSES
        self._similar_incidents = MOCK_SIMILAR_INCIDENTS
        self._remediation_results = MOCK_REMEDIATION_RESULTS

    def _match_key(self, text: str) -> str | None:
        text_lower = text.lower()
        keyword_map = {
            "axios": ["axios", "npm compromise", "supply chain attack", "npm supply"],
            "gpl": ["gpl", "license"],
            "critical": ["critical", "vulnerability", "vuln", "cve"],
            "remediation": ["remediation", "fix", "upgrade", "patch", "what should"],
            "sbom": ["sbom", "component", "inventory", "repo", "how many"],
            "kubernetes": ["kubernetes", "k8s", "grafana", "infrastructure"],
        }
        for key, keywords in keyword_map.items():
            if any(kw in text_lower for kw in keywords):
                return key
        return None

    async def retrieve(
        self,
        query: str,
        source_types: list[str] | None = None,
        top_k: int = 5,
    ) -> list[RetrievalResult]:
        key = self._match_key(query)
        if key and key in self._chat_responses:
            resp = self._chat_responses[key]
            results = []
            for src in resp.get("sources", [])[:top_k]:
                results.append(RetrievalResult(
                    content=src.get("title", ""),
                    score=src.get("score", 0.8),
                    source_type=src.get("type", "news"),
                    source_id=src.get("title", ""),
                    metadata={"title": src.get("title", "")},
                ))
            return results
        return []

    async def retrieve_similar_incidents(
        self,
        article_text: str,
        top_k: int = 3,
    ) -> list[RetrievalResult]:
        text_lower = article_text.lower()
        for pkg_name, incidents in self._similar_incidents.items():
            if pkg_name.lower() in text_lower:
                return [
                    RetrievalResult(
                        content=inc["summary"],
                        score=inc["relevance_score"],
                        source_type="news",
                        source_id=inc["title"],
                        metadata={
                            "title": inc["title"],
                            "resolution": inc.get("resolution", ""),
                        },
                    )
                    for inc in incidents[:top_k]
                ]
        return []

    async def retrieve_remediation_context(
        self,
        vuln_type: str,
        ecosystem: str,
        package_name: str,
    ) -> list[RetrievalResult]:
        key = package_name.lower()
        if key in self._remediation_results:
            rem = self._remediation_results[key]
            return [RetrievalResult(
                content=rem["summary"],
                score=0.95,
                source_type="remediation",
                source_id=f"remediation:{key}",
                metadata={"priority": rem["priority"]},
            )]
        return []
