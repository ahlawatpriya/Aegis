"""Efficient HTTP fetching with conditional GET, high-water marks, and hash-based
change detection for the Aegis news ingestion pipeline."""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import feedparser
import httpx

from aegis.config import get_settings

settings = get_settings()
from aegis.news.feeds import ALL_FEEDS, API_SOURCES, Feed

logger = logging.getLogger(__name__)

FETCH_TIMEOUT = 30.0
MAX_RETRIES = 2


@dataclass
class FeedState:
    etag: str | None = None
    last_modified: str | None = None
    high_water_mark: datetime | None = None
    content_hash: str | None = None


@dataclass
class FetchResult:
    articles: list[dict] = field(default_factory=list)
    state: FeedState = field(default_factory=FeedState)


def _parse_published(entry: dict) -> datetime | None:
    """Try to extract a timezone-aware published datetime from a feedparser entry."""
    for key in ("published_parsed", "updated_parsed"):
        tp = entry.get(key)
        if tp:
            try:
                from time import mktime
                return datetime.fromtimestamp(mktime(tp), tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                continue
    raw = entry.get("published") or entry.get("updated")
    if raw:
        for fmt in (
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
        ):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


class FeedFetcher:
    """Fetches RSS feeds and API sources with conditional GET and dedup guards."""

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(FETCH_TIMEOUT),
                follow_redirects=True,
                headers={"User-Agent": "Aegis/0.1 (supply-chain-risk-tracker)"},
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # RSS feeds
    # ------------------------------------------------------------------

    async def fetch_feed(
        self, feed: Feed, state: FeedState | None = None
    ) -> FetchResult:
        state = state or FeedState()
        client = await self._get_client()

        headers: dict[str, str] = {}
        if state.etag:
            headers["If-None-Match"] = state.etag
        if state.last_modified:
            headers["If-Modified-Since"] = state.last_modified

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = await client.get(feed.url, headers=headers)
                break
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
                if attempt == MAX_RETRIES:
                    logger.warning("Feed %s failed after %d attempts: %s", feed.name, MAX_RETRIES, exc)
                    return FetchResult(state=state)
                logger.debug("Retry %d for %s: %s", attempt, feed.name, exc)

        if resp.status_code == 304:
            logger.debug("Feed %s: 304 Not Modified", feed.name)
            return FetchResult(state=state)

        if resp.status_code != 200:
            logger.warning("Feed %s returned %d", feed.name, resp.status_code)
            return FetchResult(state=state)

        new_state = FeedState(
            etag=resp.headers.get("ETag", state.etag),
            last_modified=resp.headers.get("Last-Modified", state.last_modified),
            high_water_mark=state.high_water_mark,
            content_hash=state.content_hash,
        )

        parsed = feedparser.parse(resp.text)
        articles: list[dict] = []
        newest_ts = state.high_water_mark

        for entry in parsed.entries:
            pub = _parse_published(entry)
            if state.high_water_mark and pub and pub <= state.high_water_mark:
                continue

            link = entry.get("link", "")
            title = entry.get("title", "")
            summary = entry.get("summary", "")

            if not link or not title:
                continue

            articles.append(
                {
                    "title": title,
                    "url": link,
                    "summary": summary,
                    "published": pub,
                    "source": feed.name,
                    "tier": feed.tier,
                }
            )

            if pub and (newest_ts is None or pub > newest_ts):
                newest_ts = pub

        new_state.high_water_mark = newest_ts
        logger.info("Feed %s: %d new entries", feed.name, len(articles))
        return FetchResult(articles=articles, state=new_state)

    # ------------------------------------------------------------------
    # NVD API
    # ------------------------------------------------------------------

    async def fetch_nvd_api(self, state: FeedState | None = None) -> FetchResult:
        state = state or FeedState()
        client = await self._get_client()

        now = datetime.now(timezone.utc)
        twelve_hours_ago = now - timedelta(hours=12)

        params: dict[str, str] = {
            "pubStartDate": twelve_hours_ago.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "cvssV3Severity": "CRITICAL",
        }
        headers: dict[str, str] = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = await client.get(
                    API_SOURCES[0].url, params=params, headers=headers
                )
                break
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
                if attempt == MAX_RETRIES:
                    logger.warning("NVD API failed after %d attempts: %s", MAX_RETRIES, exc)
                    return FetchResult(state=state)

        if resp.status_code != 200:
            logger.warning("NVD API returned %d", resp.status_code)
            return FetchResult(state=state)

        data = resp.json()
        articles: list[dict] = []

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "",
            )
            published_str = cve.get("published", "")
            pub: datetime | None = None
            if published_str:
                try:
                    pub = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            articles.append(
                {
                    "title": f"{cve_id} — Critical CVE",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "summary": desc[:500],
                    "published": pub,
                    "source": "NVD",
                    "tier": 0,
                }
            )

        logger.info("NVD API: %d critical CVEs in last 12h", len(articles))
        return FetchResult(articles=articles, state=state)

    # ------------------------------------------------------------------
    # CVE Crowd API
    # ------------------------------------------------------------------

    async def fetch_cve_crowd(self, state: FeedState | None = None) -> FetchResult:
        state = state or FeedState()
        client = await self._get_client()

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = await client.get(API_SOURCES[1].url)
                break
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
                if attempt == MAX_RETRIES:
                    logger.warning("CVE Crowd API failed after %d attempts: %s", MAX_RETRIES, exc)
                    return FetchResult(state=state)

        if resp.status_code != 200:
            logger.warning("CVE Crowd API returned %d", resp.status_code)
            return FetchResult(state=state)

        data = resp.json()
        cve_list = data if isinstance(data, list) else data.get("cves", data.get("data", []))

        cve_ids = sorted(
            item.get("cve_id", item.get("id", "")) for item in cve_list if isinstance(item, dict)
        )
        content_hash = hashlib.sha256(",".join(cve_ids).encode()).hexdigest()

        if content_hash == state.content_hash:
            logger.debug("CVE Crowd: no change (hash match)")
            return FetchResult(state=FeedState(content_hash=content_hash))

        articles: list[dict] = []
        for item in cve_list:
            if not isinstance(item, dict):
                continue
            cve_id = item.get("cve_id", item.get("id", ""))
            if not cve_id:
                continue
            articles.append(
                {
                    "title": f"{cve_id} — Trending on CVE Crowd",
                    "url": f"https://www.cvecrowd.com/cve/{cve_id}",
                    "summary": item.get("description", item.get("summary", "")),
                    "published": datetime.now(timezone.utc),
                    "source": "CVE Crowd",
                    "tier": 0,
                }
            )

        new_state = FeedState(content_hash=content_hash)
        logger.info("CVE Crowd: %d trending CVEs", len(articles))
        return FetchResult(articles=articles, state=new_state)

    # ------------------------------------------------------------------
    # Fetch everything
    # ------------------------------------------------------------------

    async def fetch_all(
        self, feeds: list[Feed] | None = None, states: dict[str, FeedState] | None = None
    ) -> tuple[list[dict], dict[str, FeedState]]:
        """Fetch all RSS feeds and API sources concurrently.

        Returns (combined_articles, updated_states).
        """
        import asyncio

        feeds = feeds or ALL_FEEDS
        states = states or {}

        tasks = []
        keys: list[str] = []

        for feed in feeds:
            keys.append(feed.url)
            tasks.append(self.fetch_feed(feed, states.get(feed.url)))

        keys.append("__nvd__")
        tasks.append(self.fetch_nvd_api(states.get("__nvd__")))

        keys.append("__cve_crowd__")
        tasks.append(self.fetch_cve_crowd(states.get("__cve_crowd__")))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_articles: list[dict] = []
        new_states: dict[str, FeedState] = {}

        for key, result in zip(keys, results):
            if isinstance(result, Exception):
                logger.error("Fetch error for %s: %s", key, result)
                continue
            all_articles.extend(result.articles)
            new_states[key] = result.state

        def _sort_key(a):
            pub = a.get("published")
            if pub is None:
                return datetime.min.replace(tzinfo=timezone.utc)
            if pub.tzinfo is None:
                return pub.replace(tzinfo=timezone.utc)
            return pub

        all_articles.sort(key=_sort_key, reverse=True)
        logger.info("Total articles fetched: %d", len(all_articles))
        return all_articles, new_states
