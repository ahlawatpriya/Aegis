"""Chat engine — powers the "Ask Aegis" security chatbot.

Production: ChatEngine (real retrieval + Claude streaming).
Demo: DemoChatEngine (keyword-matched mock answers).
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import AsyncIterator

logger = logging.getLogger(__name__)

_CHAT_SYSTEM_PROMPT = """\
You are Aegis, an AI security assistant for a supply-chain vulnerability \
tracking system. You answer questions about the organization's software \
dependencies, known vulnerabilities, security news, and remediation actions.

RULES:
1. Answer ONLY based on the provided CONTEXT below. Do not use outside knowledge.
2. Cite your sources — reference the source type and title when stating facts.
3. If the context does not contain enough information to answer confidently, \
   say "I don't have enough information in the current knowledge base to \
   answer that question."
4. Be concise and actionable. Security engineers want facts, not fluff.
5. When listing affected repos or packages, use bullet points.
6. For vulnerability questions, always mention severity and recommended actions.
"""


@dataclass
class ChatResponse:
    answer: str
    sources: list[dict] = field(default_factory=list)
    context_used: list[dict] = field(default_factory=list)


class ChatEngine:

    def __init__(self, retriever, llm_client):
        self._retriever = retriever
        self._client = llm_client

    async def answer(
        self,
        question: str,
        history: list[dict] | None = None,
    ) -> ChatResponse:
        results = await self._retriever.retrieve(question, top_k=5)

        context_parts = []
        sources = []
        context_used = []
        for r in results:
            source_label = f"[{r.source_type.upper()}] {r.metadata.get('title', r.source_id)}"
            context_parts.append(f"{source_label}\n{r.content}")
            sources.append({
                "type": r.source_type,
                "title": r.metadata.get("title", r.source_id),
                "score": round(r.score, 2),
            })
            context_used.append({
                "content": r.content[:200],
                "source_type": r.source_type,
            })

        context_block = "\n\n---\n\n".join(context_parts) if context_parts else "(no relevant context found)"

        system = f"{_CHAT_SYSTEM_PROMPT}\n\nCONTEXT:\n{context_block}"

        messages = []
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": question})

        answer_text = await self._client.generate(
            system=system,
            messages=messages,
            max_tokens=2048,
        )

        if not answer_text:
            answer_text = "I was unable to generate an answer."

        return ChatResponse(answer=answer_text, sources=sources, context_used=context_used)

    async def stream_answer(
        self,
        question: str,
        history: list[dict] | None = None,
    ) -> AsyncIterator[dict]:
        results = await self._retriever.retrieve(question, top_k=5)

        context_parts = []
        sources = []
        for r in results:
            source_label = f"[{r.source_type.upper()}] {r.metadata.get('title', r.source_id)}"
            context_parts.append(f"{source_label}\n{r.content}")
            sources.append({
                "type": r.source_type,
                "title": r.metadata.get("title", r.source_id),
                "score": round(r.score, 2),
            })

        context_block = "\n\n---\n\n".join(context_parts) if context_parts else "(no relevant context found)"
        system = f"{_CHAT_SYSTEM_PROMPT}\n\nCONTEXT:\n{context_block}"

        messages = []
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": question})

        yield {"type": "sources", "sources": sources}

        async for chunk in self._client.stream(
            system=system,
            messages=messages,
            max_tokens=2048,
        ):
            yield {"type": "token", "text": chunk}

        yield {"type": "done"}


class DemoChatEngine:

    def __init__(self) -> None:
        from aegis.demo.rag_data import MOCK_CHAT_RESPONSES
        self._responses = MOCK_CHAT_RESPONSES

    def _match(self, question: str) -> dict:
        q = question.lower()
        keyword_map = [
            ("axios", ["axios", "npm compromise", "supply chain attack", "npm supply", "hijack"]),
            ("gpl", ["gpl", "license compliance", "license"]),
            ("critical", ["critical", "vulnerability", "vuln", "cve", "severe"]),
            ("remediation", ["remediation", "fix", "upgrade", "patch", "what should we do"]),
            ("sbom", ["sbom", "component", "inventory", "repo", "how many", "packages"]),
            ("kubernetes", ["kubernetes", "k8s", "grafana", "infrastructure", "deployed"]),
        ]
        for key, keywords in keyword_map:
            if any(kw in q for kw in keywords):
                if key in self._responses:
                    return self._responses[key]
        return self._responses.get("default", {
            "answer": "I don't have specific information about that in the current knowledge base. "
                      "Try asking about:\n- Active vulnerabilities (e.g., 'Are we affected by axios?')\n"
                      "- License compliance (e.g., 'Do we have GPL packages?')\n"
                      "- SBOM inventory (e.g., 'How many components do we track?')\n"
                      "- Remediation steps (e.g., 'How do we fix the axios issue?')",
            "sources": [],
            "context_used": [],
        })

    async def answer(
        self,
        question: str,
        history: list[dict] | None = None,
    ) -> ChatResponse:
        matched = self._match(question)
        return ChatResponse(
            answer=matched["answer"],
            sources=matched.get("sources", []),
            context_used=matched.get("context_used", []),
        )

    async def stream_answer(
        self,
        question: str,
        history: list[dict] | None = None,
    ) -> AsyncIterator[dict]:
        matched = self._match(question)
        sources = matched.get("sources", [])
        yield {"type": "sources", "sources": sources}

        answer = matched["answer"]
        chunk_size = 3
        for i in range(0, len(answer), chunk_size):
            yield {"type": "token", "text": answer[i : i + chunk_size]}
            await asyncio.sleep(0.02)

        yield {"type": "done"}
