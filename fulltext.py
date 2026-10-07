"""Full article fetch with Jina Reader fallback for JS-rendered pages.

When an RSS summary is too thin to contain version numbers, this module
fetches the full page, checks for version patterns, and falls back to
Jina Reader for client-side-rendered content."""

import logging
import re
from html.parser import HTMLParser
from typing import Any

import httpx

from aegis.config import get_settings

settings = get_settings()
from aegis.news.enricher import enrich_article, needs_version_recovery

logger = logging.getLogger(__name__)

_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
_FETCH_TIMEOUT = 20.0


# ---------------------------------------------------------------------------
# Simple HTML → text extractor
# ---------------------------------------------------------------------------

class _HTMLTextExtractor(HTMLParser):
    """Minimal HTML-to-text converter that strips tags."""

    _SKIP_TAGS = {"script", "style", "noscript", "svg", "head"}

    def __init__(self) -> None:
        super().__init__()
        self._pieces: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in self._SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._pieces.append(data)

    def get_text(self) -> str:
        return " ".join(self._pieces)


def _html_to_text(html: str) -> str:
    extractor = _HTMLTextExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    return extractor.get_text()


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------

async def fetch_full_article(url: str) -> str | None:
    """Fetch the full article page and extract text.

    Returns the extracted text, or None on failure.
    """
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(_FETCH_TIMEOUT),
        follow_redirects=True,
        headers={"User-Agent": "Aegis/0.1 (supply-chain-risk-tracker)"},
    ) as client:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.warning("Full fetch %s returned %d", url[:80], resp.status_code)
                return None
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
            logger.warning("Full fetch %s failed: %s", url[:80], exc)
            return None

    text = _html_to_text(resp.text)
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) < 200:
        logger.debug("Full fetch %s: very short text (%d chars), likely JS-rendered", url[:80], len(text))
        return None

    if not _VERSION_RE.search(text):
        logger.debug("Full fetch %s: no version patterns found, trying Jina", url[:80])
        return await fetch_via_jina(url)

    return text


async def fetch_via_jina(url: str) -> str | None:
    """Use Jina Reader to get clean markdown from a JS-rendered page."""
    jina_url = f"{settings.jina_reader_url}/{url}"

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(_FETCH_TIMEOUT),
        follow_redirects=True,
    ) as client:
        try:
            resp = await client.get(jina_url)
            if resp.status_code != 200:
                logger.warning("Jina Reader returned %d for %s", resp.status_code, url[:80])
                return None
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
            logger.warning("Jina Reader failed for %s: %s", url[:80], exc)
            return None

    text = resp.text.strip()
    if len(text) < 100:
        logger.debug("Jina Reader returned very short text for %s", url[:80])
        return None

    return text


# ---------------------------------------------------------------------------
# Version recovery pipeline
# ---------------------------------------------------------------------------

async def recover_versions(article: dict, llm_client: Any) -> dict | None:
    """Attempt to recover specific version numbers for packages tagged "all".

    1. Fetch full article text (plain HTTP → Jina fallback).
    2. If no version patterns found even after Jina → drop (return None).
    3. Re-run LLM enrichment with full text + explicit recovery instruction.
    4. If still "all" after recovery → drop the package rather than false-alarm.
    5. Return updated article, or None if nothing actionable remains.
    """
    url = article.get("url", "")
    logger.info("Version recovery for '%s'", article.get("title", "")[:60])

    full_text = await fetch_full_article(url)
    if not full_text:
        logger.warning("Could not fetch full text for version recovery: %s", url[:80])
        return None

    if not _VERSION_RE.search(full_text):
        logger.warning("No version patterns in full text for %s — dropping", url[:80])
        return None

    recovered = await enrich_article(
        article,
        llm_client,
        full_text=full_text,
        recovery=True,
    )

    if needs_version_recovery(recovered):
        logger.warning(
            "Version recovery still returned 'all' for '%s' — dropping packages",
            article.get("title", "")[:60],
        )
        recovered["affected_packages"] = [
            pkg for pkg in recovered.get("affected_packages", [])
            if pkg.get("vulnerable_versions", "").strip().lower() != "all"
        ]
        if not recovered["affected_packages"]:
            recovered["classification"] = "threat_intel"
            return recovered

    logger.info(
        "Version recovery succeeded for '%s': %d packages",
        article.get("title", "")[:60],
        len(recovered.get("affected_packages", [])),
    )
    return recovered
