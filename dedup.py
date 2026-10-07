"""Three-phase deduplication for the Aegis news ingestion pipeline.

Phase 1 — exact URL match (free DB lookup)
Phase 2 — fuzzy title + CVE match (zero LLM cost)
Phase 3 — LLM semantic dedup + impact scoring (single Claude call, batched)
"""

import json
import logging
import re
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stopwords for title normalisation
# ---------------------------------------------------------------------------

STOPWORDS: set[str] = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "shall", "can", "need", "dare",
    "this", "that", "these", "those", "it", "its", "not", "no", "nor",
    "so", "yet", "both", "each", "few", "more", "most", "other", "some",
    "such", "than", "too", "very", "just", "about", "above", "after",
    "again", "all", "also", "any", "because", "before", "below", "between",
    "during", "how", "if", "into", "new", "now", "only", "over", "same",
    "then", "there", "through", "under", "up", "what", "when", "where",
    "which", "while", "who", "whom", "why", "via",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

MIN_IMPACT_SCORE = 4
JACCARD_THRESHOLD = 0.70


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_title(title: str) -> set[str]:
    """Lowercase, strip punctuation, split on whitespace/hyphens, drop stopwords."""
    title = title.lower()
    title = re.sub(r"[^\w\s-]", " ", title)
    words = re.split(r"[\s\-]+", title)
    return {w for w in words if w and w not in STOPWORDS}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _extract_cves(text: str) -> list[str]:
    return [m.upper() for m in _CVE_RE.findall(text)]


# ---------------------------------------------------------------------------
# Phase 1 — exact URL
# ---------------------------------------------------------------------------

async def exact_url_match(url: str, session: AsyncSession) -> bool:
    result = await session.execute(
        text("SELECT 1 FROM aegis_news WHERE url = :url LIMIT 1"),
        {"url": url},
    )
    return result.scalar() is not None


# ---------------------------------------------------------------------------
# Phase 2 — fuzzy title + CVE
# ---------------------------------------------------------------------------

def fuzzy_title_cve_match(
    title: str,
    existing_titles: list[str],
    existing_cves: list[str],
) -> bool:
    """Return True if the article is a duplicate by title similarity or CVE overlap."""
    title_words = _normalise_title(title)

    for existing in existing_titles:
        existing_words = _normalise_title(existing)
        if _jaccard(title_words, existing_words) >= JACCARD_THRESHOLD:
            logger.debug("Fuzzy title dup: '%s' ~ '%s'", title[:60], existing[:60])
            return True

    article_cves = _extract_cves(title)
    if article_cves:
        existing_cve_set = {c.upper() for c in existing_cves}
        for cve in article_cves:
            if cve in existing_cve_set:
                logger.debug("CVE dup: %s already tracked", cve)
                return True

    return False


# ---------------------------------------------------------------------------
# Phase 3 — LLM semantic dedup + impact scoring
# ---------------------------------------------------------------------------

_DEDUP_SYSTEM_PROMPT = """\
You are a security-news deduplication and scoring engine for an engineering \
organisation's supply-chain risk tracker.

You will receive:
1. A list of CANDIDATE articles (new, not yet stored).
2. A list of EXISTING article titles already in the database.

For each candidate, do two things in one pass:
(a) Determine if it is a semantic duplicate of any existing title OR another \
    candidate (different headline, same underlying incident). When multiple \
    outlets cover the same compromise, keep ONLY the richest write-up.
(b) Score it 1-10 for relevance/impact to an org running: Node.js, Python, \
    Go, Java, Rust, Kubernetes, AWS, Docker, Terraform, GitHub Actions, \
    React, Next.js.  Reject low-impact noise (CVE in a CMS we don't use, \
    vendor marketing, generic ransomware with no supply-chain angle).

Return STRICT JSON — an array with one object per candidate:
[
  {
    "index": 0,
    "is_duplicate": false,
    "duplicate_of": null,
    "impact_score": 8,
    "reason": "Active npm supply-chain compromise affecting axios"
  }
]
If is_duplicate is true, set duplicate_of to the existing title or candidate \
index it duplicates. Only JSON, no markdown fences."""


async def llm_semantic_dedup(
    candidates: list[dict],
    existing_titles: list[str],
    llm_client: Any,
) -> list[dict]:
    """Use LLM to catch semantic duplicates and score impact.

    Returns only non-duplicate candidates whose impact_score >= MIN_IMPACT_SCORE.
    """
    if not candidates:
        return []

    candidate_block = "\n".join(
        f"[{i}] {c['title']} — {c.get('summary', '')[:200]}"
        for i, c in enumerate(candidates)
    )
    existing_block = "\n".join(existing_titles[-50:]) if existing_titles else "(none)"

    user_msg = (
        f"CANDIDATES:\n{candidate_block}\n\n"
        f"EXISTING TITLES (last 50):\n{existing_block}"
    )

    try:
        raw = await llm_client.generate(
            system=_DEDUP_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
            max_tokens=2048,
        )
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```\w*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        verdicts: list[dict] = json.loads(raw)
    except Exception as exc:
        logger.error("LLM dedup failed, keeping all candidates: %s", exc)
        return candidates

    kept: list[dict] = []
    for verdict in verdicts:
        idx = verdict.get("index", -1)
        if idx < 0 or idx >= len(candidates):
            continue
        if verdict.get("is_duplicate", False):
            logger.debug(
                "LLM marked dup [%d] '%s' → '%s'",
                idx,
                candidates[idx]["title"][:60],
                verdict.get("duplicate_of", "?"),
            )
            continue
        score = verdict.get("impact_score", 0)
        if score < MIN_IMPACT_SCORE:
            logger.debug(
                "LLM low-impact [%d] '%s' score=%d",
                idx,
                candidates[idx]["title"][:60],
                score,
            )
            continue
        article = candidates[idx].copy()
        article["impact_score"] = score
        kept.append(article)

    logger.info(
        "LLM dedup: %d candidates → %d kept",
        len(candidates),
        len(kept),
    )
    return kept


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

async def deduplicate(
    articles: list[dict],
    session: AsyncSession,
    llm_client: Any,
) -> list[dict]:
    """Run all three dedup phases in order, cheapest first."""
    if not articles:
        return []

    # Load recent DB titles + CVEs for phases 2–3
    rows = await session.execute(
        text(
            "SELECT title, affected_packages FROM aegis_news "
            "ORDER BY created_at DESC LIMIT 200"
        )
    )
    existing_titles: list[str] = []
    existing_cves: list[str] = []
    for row in rows:
        existing_titles.append(row[0])
        pkgs = row[1]
        if pkgs:
            if isinstance(pkgs, str):
                try:
                    pkgs = json.loads(pkgs)
                except (json.JSONDecodeError, TypeError):
                    pkgs = []
            if isinstance(pkgs, list):
                for pkg in pkgs:
                    cve = pkg.get("cve_id") if isinstance(pkg, dict) else None
                    if cve:
                        existing_cves.append(cve)
        for cve in _extract_cves(row[0]):
            existing_cves.append(cve)

    # Phase 1 — exact URL
    phase1: list[dict] = []
    for article in articles:
        if await exact_url_match(article["url"], session):
            logger.debug("Phase 1 dup (URL): %s", article["url"][:80])
        else:
            phase1.append(article)
    logger.info("Dedup phase 1: %d → %d", len(articles), len(phase1))

    # Phase 2 — fuzzy title + CVE
    phase2: list[dict] = []
    for article in phase1:
        if fuzzy_title_cve_match(article["title"], existing_titles, existing_cves):
            logger.debug("Phase 2 dup: %s", article["title"][:80])
        else:
            phase2.append(article)
    logger.info("Dedup phase 2: %d → %d", len(phase1), len(phase2))

    # Phase 3 — LLM semantic dedup + scoring
    phase3 = await llm_semantic_dedup(phase2, existing_titles, llm_client)
    logger.info("Dedup phase 3: %d → %d", len(phase2), len(phase3))

    return phase3
