"""Ingest pipeline — indexes data into the RAG vector store.

Indexes news articles, SBOM components, match results,
and static remediation guides into the vector store for retrieval.
"""

import logging

from aegis.rag.embedder import EmbedderBase
from aegis.rag.knowledge import REMEDIATION_GUIDES
from aegis.rag.store import VectorStoreBase

logger = logging.getLogger(__name__)


async def index_remediation_guides(
    embedder: EmbedderBase,
    store: VectorStoreBase,
) -> int:
    texts = [g["content"] for g in REMEDIATION_GUIDES]
    embeddings = await embedder.embed_batch(texts)
    for guide, emb in zip(REMEDIATION_GUIDES, embeddings):
        await store.upsert(
            source_type="remediation",
            source_id=guide["id"],
            text=guide["content"],
            embedding=emb,
            metadata={
                "title": guide["title"],
                "vuln_type": guide["vuln_type"],
                "ecosystem": guide["ecosystem"],
            },
        )
    logger.info("Indexed %d remediation guides", len(REMEDIATION_GUIDES))
    return len(REMEDIATION_GUIDES)


async def index_news_article(
    embedder: EmbedderBase,
    store: VectorStoreBase,
    article: dict,
) -> None:
    text = f"{article.get('title', '')} {article.get('summary', '')} {article.get('body', '')}"
    embedding = await embedder.embed(text)
    await store.upsert(
        source_type="news",
        source_id=article.get("url", article.get("id", "")),
        text=text[:4000],
        embedding=embedding,
        metadata={
            "title": article.get("title", ""),
            "url": article.get("url", ""),
            "published": article.get("published", ""),
            "classification": article.get("classification", ""),
        },
    )


async def index_sbom_component(
    embedder: EmbedderBase,
    store: VectorStoreBase,
    component: dict,
    repo_name: str,
) -> None:
    text = (
        f"Package {component.get('name', '')} version {component.get('version', '')} "
        f"in repo {repo_name}. Type: {component.get('type', '')}. "
        f"PURL: {component.get('purl', '')}. "
        f"Licenses: {', '.join(component.get('licenses', []))}."
    )
    source_id = f"sbom:{repo_name}:{component.get('purl', component.get('name', ''))}"
    embedding = await embedder.embed(text)
    await store.upsert(
        source_type="sbom",
        source_id=source_id,
        text=text,
        embedding=embedding,
        metadata={
            "name": component.get("name", ""),
            "version": component.get("version", ""),
            "repo": repo_name,
            "purl": component.get("purl", ""),
            "licenses": component.get("licenses", []),
        },
    )


async def index_match_result(
    embedder: EmbedderBase,
    store: VectorStoreBase,
    match: dict,
    article_title: str,
) -> None:
    text = (
        f"Security match: {article_title} affects {match.get('component_name', '')} "
        f"version {match.get('version_in_use', '')} in repo {match.get('repo', '')}. "
        f"Confidence: {match.get('confidence', 'unknown')}."
    )
    source_id = f"match:{match.get('repo', '')}:{match.get('component_name', '')}:{article_title[:50]}"
    embedding = await embedder.embed(text)
    await store.upsert(
        source_type="match",
        source_id=source_id,
        text=text,
        embedding=embedding,
        metadata={
            "title": article_title,
            "component": match.get("component_name", ""),
            "repo": match.get("repo", ""),
            "confidence": match.get("confidence", ""),
        },
    )


async def index_vulnerability(
    embedder: EmbedderBase,
    store: VectorStoreBase,
    vuln: dict,
) -> None:
    text = (
        f"Vulnerability {vuln.get('id', '')}: {vuln.get('summary', '')} "
        f"Severity: {vuln.get('severity', 'unknown')}. "
        f"Affected: {', '.join(p.get('name', '') for p in vuln.get('affected_packages', []))}."
    )
    embedding = await embedder.embed(text)
    await store.upsert(
        source_type="vulnerability",
        source_id=vuln.get("id", ""),
        text=text,
        embedding=embedding,
        metadata={
            "title": vuln.get("id", ""),
            "severity": vuln.get("severity", ""),
            "cvss": vuln.get("cvss_score", 0),
        },
    )


async def full_ingest(
    embedder: EmbedderBase,
    store: VectorStoreBase,
    news_articles: list[dict] | None = None,
    sbom_components: list[tuple[str, dict]] | None = None,
    match_results: list[tuple[str, dict]] | None = None,
    vulnerabilities: list[dict] | None = None,
) -> dict:
    counts = {"guides": 0, "news": 0, "sbom": 0, "matches": 0, "vulns": 0}

    counts["guides"] = await index_remediation_guides(embedder, store)

    if news_articles:
        for article in news_articles:
            await index_news_article(embedder, store, article)
        counts["news"] = len(news_articles)

    if sbom_components:
        for repo_name, component in sbom_components:
            await index_sbom_component(embedder, store, component, repo_name)
        counts["sbom"] = len(sbom_components)

    if match_results:
        for article_title, match in match_results:
            await index_match_result(embedder, store, match, article_title)
        counts["matches"] = len(match_results)

    if vulnerabilities:
        for vuln in vulnerabilities:
            await index_vulnerability(embedder, store, vuln)
        counts["vulns"] = len(vulnerabilities)

    logger.info("Full ingest complete: %s", counts)
    return counts
