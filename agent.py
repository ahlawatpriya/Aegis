"""Main orchestrator for the Aegis news ingestion pipeline.

Runs on a configurable interval (default 30 minutes):
  fetch all feeds → filter → dedup → enrich → fulltext recovery → insert →
  notify Slack → trigger SBOM match → save state.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.config import get_settings

settings = get_settings()
from aegis.llm import LLMClient
from aegis.news.dedup import deduplicate
from aegis.news.enricher import enrich_article, needs_version_recovery
from aegis.news.feeds import ALL_FEEDS
from aegis.news.fetcher import FeedFetcher
from aegis.news.filter import filter_article
from aegis.news.fulltext import recover_versions
from aegis.news.state import StateManager

logger = logging.getLogger(__name__)


class NewsIngestionAgent:
    """Scheduled agent that reads security news, filters noise, and produces
    structured vulnerability data for the Aegis match engine."""

    def __init__(self) -> None:
        self._fetcher = FeedFetcher()
        self._state_mgr = StateManager()
        self._llm_client: LLMClient | None = None

    def _get_llm_client(self) -> LLMClient:
        if self._llm_client is None:
            self._llm_client = LLMClient()
        return self._llm_client

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    async def _upsert_article(self, article: dict, session: AsyncSession) -> int | None:
        """Insert or update an article in aegis_news.  Returns the row id."""
        now = datetime.now(timezone.utc)
        affected = article.get("affected_packages", [])
        affected_json = json.dumps(affected) if affected else None

        result = await session.execute(
            text(
                "INSERT INTO aegis_news "
                "(title, url, source, summary, classification, affected_packages, "
                " impact_score, created_at, processed_at) "
                "VALUES (:title, :url, :source, :summary, :classification, "
                "        :affected_packages, :impact_score, :created_at, :processed_at) "
                "ON CONFLICT (url) DO UPDATE SET "
                "  title = EXCLUDED.title, "
                "  summary = EXCLUDED.summary, "
                "  classification = EXCLUDED.classification, "
                "  affected_packages = EXCLUDED.affected_packages, "
                "  impact_score = EXCLUDED.impact_score, "
                "  processed_at = EXCLUDED.processed_at "
                "RETURNING id"
            ),
            {
                "title": article.get("title", "")[:500],
                "url": article["url"],
                "source": article.get("source", ""),
                "summary": (
                    article.get("enriched_summary")
                    or article.get("summary", "")
                )[:2000],
                "classification": article.get("classification", "general_info"),
                "affected_packages": affected_json,
                "impact_score": article.get("impact_score"),
                "created_at": now,
                "processed_at": now,
            },
        )
        row = result.fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------------
    # Single cycle
    # ------------------------------------------------------------------

    async def run_once(self, session: AsyncSession) -> dict:
        """Execute one full news-ingestion cycle.

        Returns a summary dict with counts at each pipeline stage.
        """
        client = self._get_llm_client()
        summary = {
            "fetched": 0,
            "after_filter": 0,
            "after_dedup": 0,
            "enriched": 0,
            "supply_chain_vulns": 0,
            "threat_intel": 0,
            "general_info": 0,
            "inserted": 0,
            "errors": 0,
        }

        # 1. Load feed states
        states = await self._state_mgr.load_states(session)

        # 2. Fetch all feeds
        articles, new_states = await self._fetcher.fetch_all(ALL_FEEDS, states)
        summary["fetched"] = len(articles)
        logger.info("Fetched %d articles from %d sources", len(articles), len(ALL_FEEDS) + 2)

        if not articles:
            await self._state_mgr.save_states(new_states, session)
            logger.info("No new articles — cycle complete")
            return summary

        # 3. Filter
        filtered: list[dict] = []
        for article in articles:
            passes, matched_kw = filter_article(
                article.get("title", ""), article.get("summary", "")
            )
            if passes:
                article["matched_keywords"] = matched_kw
                filtered.append(article)
        summary["after_filter"] = len(filtered)
        logger.info("After filter: %d / %d", len(filtered), len(articles))

        if not filtered:
            await self._state_mgr.save_states(new_states, session)
            return summary

        # 4. Deduplicate
        deduped = await deduplicate(filtered, session, client)
        summary["after_dedup"] = len(deduped)
        logger.info("After dedup: %d / %d", len(deduped), len(filtered))

        if not deduped:
            await self._state_mgr.save_states(new_states, session)
            return summary

        # 5. Enrich via LLM
        enriched: list[dict] = []
        for article in deduped:
            try:
                result = await enrich_article(article, client)
                enriched.append(result)
            except Exception as exc:
                logger.error(
                    "Enrichment error for '%s': %s",
                    article.get("title", "")[:60],
                    exc,
                )
                summary["errors"] += 1

        summary["enriched"] = len(enriched)

        # 6. Fulltext version recovery for supply_chain_vuln with "all"
        final: list[dict] = []
        for article in enriched:
            if (
                article.get("classification") == "supply_chain_vuln"
                and needs_version_recovery(article)
            ):
                try:
                    recovered = await recover_versions(article, client)
                    if recovered:
                        final.append(recovered)
                    else:
                        article["classification"] = "threat_intel"
                        article["affected_packages"] = []
                        final.append(article)
                except Exception as exc:
                    logger.error(
                        "Version recovery error for '%s': %s",
                        article.get("title", "")[:60],
                        exc,
                    )
                    article["classification"] = "threat_intel"
                    article["affected_packages"] = []
                    final.append(article)
                    summary["errors"] += 1
            else:
                final.append(article)

        # 7. Insert into DB
        inserted_articles: list[dict] = []
        for article in final:
            try:
                row_id = await self._upsert_article(article, session)
                if row_id:
                    article["db_id"] = row_id
                    inserted_articles.append(article)
                    summary["inserted"] += 1

                    cls = article.get("classification", "general_info")
                    if cls == "supply_chain_vuln":
                        summary["supply_chain_vulns"] += 1
                    elif cls == "threat_intel":
                        summary["threat_intel"] += 1
                    else:
                        summary["general_info"] += 1
            except Exception as exc:
                logger.error(
                    "DB insert error for '%s': %s",
                    article.get("title", "")[:60],
                    exc,
                )
                summary["errors"] += 1

        await session.commit()

        # 8. Post to Slack + trigger SBOM match for supply_chain_vuln
        for article in inserted_articles:
            try:
                await self._notify_and_match(article, session)
            except Exception as exc:
                logger.error(
                    "Notify/match error for '%s': %s",
                    article.get("title", "")[:60],
                    exc,
                )
                summary["errors"] += 1

        # 9. Save updated feed states
        await self._state_mgr.save_states(new_states, session)

        logger.info(
            "Cycle complete — fetched=%d filter=%d dedup=%d enriched=%d "
            "inserted=%d (scv=%d ti=%d gi=%d) errors=%d",
            summary["fetched"],
            summary["after_filter"],
            summary["after_dedup"],
            summary["enriched"],
            summary["inserted"],
            summary["supply_chain_vulns"],
            summary["threat_intel"],
            summary["general_info"],
            summary["errors"],
        )
        return summary

    # ------------------------------------------------------------------
    # Notify + match
    # ------------------------------------------------------------------

    async def _notify_and_match(self, article: dict, session: AsyncSession) -> None:
        """Post a Slack alert and trigger SBOM matching for supply_chain_vuln."""
        from aegis.notify.slack import SlackNotifier

        notifier = SlackNotifier()
        slack_ts = await notifier.post_article_alert(article)

        if slack_ts:
            await session.execute(
                text("UPDATE aegis_news SET slack_ts = :ts WHERE id = :id"),
                {"ts": slack_ts, "id": article.get("db_id")},
            )
            await session.commit()
            article["slack_ts"] = slack_ts

        if article.get("classification") == "supply_chain_vuln":
            from aegis.match.engine import MatchEngine

            engine = MatchEngine()
            match_results = await engine.match_article(article, session)
            if match_results and slack_ts:
                await notifier.post_match_results(slack_ts, match_results)

    # ------------------------------------------------------------------
    # Continuous loop
    # ------------------------------------------------------------------

    async def run_continuous(self, session_factory: Any) -> None:
        """Run the news ingestion agent on a loop.

        Parameters
        ----------
        session_factory : async_sessionmaker
            SQLAlchemy async session factory — a new session is created per cycle.
        """
        interval = settings.feed_poll_interval_minutes * 60
        logger.info(
            "Starting continuous news ingestion (interval=%dm)",
            settings.feed_poll_interval_minutes,
        )

        while True:
            try:
                async with session_factory() as session:
                    await self.run_once(session)
            except Exception as exc:
                logger.exception("Cycle failed: %s", exc)

            logger.info("Sleeping %d seconds until next cycle", interval)
            await asyncio.sleep(interval)

    async def close(self) -> None:
        await self._fetcher.close()
