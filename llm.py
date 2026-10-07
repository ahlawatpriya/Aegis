"""Unified async LLM client for Aegis.

Supports Google Gemini (free tier) as the default provider,
with optional Anthropic Claude support.
"""

import logging
import os
from collections.abc import AsyncIterator
from typing import Any

logger = logging.getLogger(__name__)

try:
    from google import genai
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


class LLMClient:
    """Provider-agnostic async LLM client.

    Default: Google Gemini (free tier, 15 RPM).
    Optional: Anthropic Claude (requires paid API key).
    """

    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        from aegis.config import get_settings
        _settings = get_settings()

        self._provider = provider or os.environ.get("LLM_PROVIDER", _settings.llm_provider)

        if self._provider == "gemini":
            if not HAS_GEMINI:
                raise ImportError("google-genai is not installed. pip install google-genai")
            key = api_key or os.environ.get("GEMINI_API_KEY", "") or _settings.gemini_api_key
            if not key:
                raise ValueError("GEMINI_API_KEY is required")
            self._gemini_client = genai.Client(api_key=key)
            self._model_name = model or _settings.rag_chat_model

        elif self._provider == "anthropic":
            if not HAS_ANTHROPIC:
                raise ImportError("anthropic is not installed. pip install anthropic")
            key = api_key or os.environ.get("ANTHROPIC_API_KEY", "") or _settings.anthropic_api_key
            if not key:
                raise ValueError("ANTHROPIC_API_KEY is required")
            self._anthropic_client = anthropic.AsyncAnthropic(api_key=key)
            self._model_name = model or "claude-sonnet-4-20250514"

        else:
            raise ValueError(f"Unknown LLM provider: {self._provider}")

    async def generate(
        self,
        system: str,
        messages: list[dict],
        max_tokens: int = 2048,
    ) -> str:
        if self._provider == "gemini":
            return await self._gemini_generate(system, messages, max_tokens)
        return await self._anthropic_generate(system, messages, max_tokens)

    async def stream(
        self,
        system: str,
        messages: list[dict],
        max_tokens: int = 2048,
    ) -> AsyncIterator[str]:
        if self._provider == "gemini":
            async for chunk in self._gemini_stream(system, messages, max_tokens):
                yield chunk
        else:
            async for chunk in self._anthropic_stream(system, messages, max_tokens):
                yield chunk

    # ------------------------------------------------------------------
    # Gemini (google.genai SDK)
    # ------------------------------------------------------------------

    def _build_gemini_contents(self, system: str, messages: list[dict]) -> list[dict]:
        contents = []
        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            contents.append(genai.types.Content(
                role=role,
                parts=[genai.types.Part(text=msg["content"])],
            ))
        return contents

    async def _gemini_generate(self, system: str, messages: list[dict], max_tokens: int) -> str:
        contents = self._build_gemini_contents(system, messages)
        config = genai.types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=max_tokens,
        )
        response = await self._gemini_client.aio.models.generate_content(
            model=self._model_name,
            contents=contents,
            config=config,
        )
        return response.text

    async def _gemini_stream(self, system: str, messages: list[dict], max_tokens: int) -> AsyncIterator[str]:
        contents = self._build_gemini_contents(system, messages)
        config = genai.types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=max_tokens,
        )
        async for chunk in self._gemini_client.aio.models.generate_content_stream(
            model=self._model_name,
            contents=contents,
            config=config,
        ):
            if chunk.text:
                yield chunk.text

    # ------------------------------------------------------------------
    # Anthropic
    # ------------------------------------------------------------------

    async def _anthropic_generate(self, system: str, messages: list[dict], max_tokens: int) -> str:
        resp = await self._anthropic_client.messages.create(
            model=self._model_name,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        return resp.content[0].text

    async def _anthropic_stream(self, system: str, messages: list[dict], max_tokens: int) -> AsyncIterator[str]:
        async with self._anthropic_client.messages.stream(
            model=self._model_name,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        ) as stream:
            async for text in stream.text_stream:
                yield text
