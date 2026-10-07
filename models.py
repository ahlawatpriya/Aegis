from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Sbom(Base):
    __tablename__ = "aegis_sbom"
    __table_args__ = (
        UniqueConstraint("repo", "purl", name="uq_aegis_sbom_repo_purl"),
        Index("ix_aegis_sbom_purl", "purl"),
        Index("ix_aegis_sbom_ecosystem", "ecosystem"),
        Index("ix_aegis_sbom_component", "component_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo: Mapped[str] = mapped_column(String(512), nullable=False)
    component_name: Mapped[str] = mapped_column(String(512), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    purl: Mapped[str] = mapped_column(String(1024), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class SbomLicense(Base):
    __tablename__ = "aegis_sbom_licenses"
    __table_args__ = (
        UniqueConstraint("purl", "source", name="uq_aegis_sbom_licenses_purl_source"),
        Index("ix_aegis_sbom_licenses_purl", "purl"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    purl: Mapped[str] = mapped_column(String(1024), nullable=False)
    license: Mapped[str] = mapped_column(String(256), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    resolved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class PurlLicenseCache(Base):
    __tablename__ = "aegis_purl_license_cache"
    __table_args__ = (Index("ix_aegis_purl_license_cache_purl", "purl", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    purl: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    license: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    resolved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    ecosystem: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class News(Base):
    __tablename__ = "aegis_news"
    __table_args__ = (
        Index("ix_aegis_news_url", "url", unique=True),
        Index("ix_aegis_news_classification", "classification"),
        Index("ix_aegis_news_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(1024), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    source: Mapped[str] = mapped_column(String(256), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    body_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    affected_packages: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(
        JSON, nullable=True
    )
    impact_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    slack_ts: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    processed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    match_results: Mapped[list[MatchResult]] = relationship(
        back_populates="news_entry", cascade="all, delete-orphan"
    )


class FeedState(Base):
    __tablename__ = "aegis_feed_state"
    __table_args__ = (Index("ix_aegis_feed_state_feed_url", "feed_url", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    feed_url: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    etag: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    last_modified: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    high_water_mark: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    content_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class MatchResult(Base):
    __tablename__ = "aegis_match_result"
    __table_args__ = (
        Index("ix_aegis_match_result_news_id", "news_id"),
        Index("ix_aegis_match_result_repo", "repo"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    news_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("aegis_news.id", ondelete="CASCADE"), nullable=False
    )
    repo: Mapped[str] = mapped_column(String(512), nullable=False)
    component_name: Mapped[str] = mapped_column(String(512), nullable=False)
    version_in_use: Mapped[str] = mapped_column(String(128), nullable=False)
    vulnerable_versions: Mapped[str] = mapped_column(String(512), nullable=False)
    is_vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    purl: Mapped[str] = mapped_column(String(1024), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(64), nullable=False)
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    news_entry: Mapped[News] = relationship(back_populates="match_results")


# ---------------------------------------------------------------------------
# RAG tables
# ---------------------------------------------------------------------------

class Embedding(Base):
    __tablename__ = "aegis_embedding"
    __table_args__ = (
        UniqueConstraint("source_type", "source_id", name="uq_aegis_embedding_source"),
        Index("ix_aegis_embedding_source_type", "source_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[str] = mapped_column(String(512), nullable=False)
    content_text: Mapped[str] = mapped_column(Text, nullable=False)
    extra_metadata: Mapped[Optional[dict]] = mapped_column("metadata", JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ChatSession(Base):
    __tablename__ = "aegis_chat_session"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    messages: Mapped[list[ChatMessage]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


class ChatMessage(Base):
    __tablename__ = "aegis_chat_message"
    __table_args__ = (
        Index("ix_aegis_chat_message_session_id", "session_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("aegis_chat_session.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    context_refs: Mapped[Optional[list[dict]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    session: Mapped[ChatSession] = relationship(back_populates="messages")


class RemediationGuide(Base):
    __tablename__ = "aegis_remediation_guide"
    __table_args__ = (
        Index("ix_aegis_remediation_guide_vuln_type", "vuln_type"),
        Index("ix_aegis_remediation_guide_ecosystem", "ecosystem"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    steps: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    commands: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    references: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
