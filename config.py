from __future__ import annotations

import functools
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = "postgresql+asyncpg://aegis:aegis_dev@localhost:5432/aegis_db"

    # Slack
    slack_bot_token: str = ""
    slack_channel_id: str = ""

    # Anthropic / Claude
    anthropic_api_key: str = ""

    # NVD
    nvd_api_key: str = ""

    # AWS
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    s3_bucket: str = ""

    # Jina Reader
    jina_reader_url: str = "https://r.jina.ai"

    # GitHub
    github_token: str = ""

    # Feed polling
    feed_poll_interval_minutes: int = 30

    # ECS (Validator)
    ecs_cluster: str = ""
    ecs_task_definition: str = ""
    ecs_subnets: str = ""
    ecs_security_groups: str = ""

    # LLM Provider
    llm_provider: str = "gemini"
    gemini_api_key: str = ""

    # RAG
    voyage_api_key: str = ""
    rag_embedding_model: str = "gemini-embedding-001"
    rag_embedding_dimensions: int = 3072
    rag_top_k: int = 5
    rag_chat_model: str = "gemini-3.6-flash"

    # Logging
    log_level: str = "INFO"

    @property
    def ecs_subnet_list(self) -> list[str]:
        return [s.strip() for s in self.ecs_subnets.split(",") if s.strip()]

    @property
    def ecs_security_group_list(self) -> list[str]:
        return [s.strip() for s in self.ecs_security_groups.split(",") if s.strip()]


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
