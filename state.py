"""Per-feed state persistence for the Aegis news ingestion pipeline.

Manages ETags, Last-Modified headers, high-water marks, and content hashes
so the fetcher can skip already-seen content efficiently."""

import logging
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.news.fetcher import FeedState

logger = logging.getLogger(__name__)


class StateManager:
    """Load and save per-feed fetch state from/to the aegis_feed_state table."""

    async def load_states(self, session: AsyncSession) -> dict[str, FeedState]:
        """Load all feed states from the database."""
        result = await session.execute(
            text(
                "SELECT feed_url, etag, last_modified, high_water_mark, content_hash "
                "FROM aegis_feed_state"
            )
        )
        states: dict[str, FeedState] = {}
        for row in result:
            feed_url, etag, last_modified, hwm, content_hash = row
            states[feed_url] = FeedState(
                etag=etag,
                last_modified=last_modified,
                high_water_mark=hwm,
                content_hash=content_hash,
            )
        logger.info("Loaded %d feed states", len(states))
        return states

    async def save_state(
        self, feed_url: str, state: FeedState, session: AsyncSession
    ) -> None:
        """Upsert a single feed state into the database."""
        now = datetime.now(timezone.utc)
        await session.execute(
            text(
                "INSERT INTO aegis_feed_state "
                "(feed_url, etag, last_modified, high_water_mark, content_hash, updated_at) "
                "VALUES (:feed_url, :etag, :last_modified, :high_water_mark, :content_hash, :updated_at) "
                "ON CONFLICT (feed_url) DO UPDATE SET "
                "etag = EXCLUDED.etag, "
                "last_modified = EXCLUDED.last_modified, "
                "high_water_mark = EXCLUDED.high_water_mark, "
                "content_hash = EXCLUDED.content_hash, "
                "updated_at = EXCLUDED.updated_at"
            ),
            {
                "feed_url": feed_url,
                "etag": state.etag,
                "last_modified": state.last_modified,
                "high_water_mark": state.high_water_mark,
                "content_hash": state.content_hash,
                "updated_at": now,
            },
        )

    async def save_states(
        self, states: dict[str, FeedState], session: AsyncSession
    ) -> None:
        """Batch-save all feed states."""
        for feed_url, state in states.items():
            await self.save_state(feed_url, state, session)
        await session.commit()
        logger.info("Saved %d feed states", len(states))
