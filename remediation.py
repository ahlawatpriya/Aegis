"""Remediation engine — generates actionable fix recommendations.

Production: RemediationEngine (RAG retrieval + Claude).
Demo: DemoRemediationEngine (pre-built mock results).
"""

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_REMEDIATION_SYSTEM_PROMPT = """\
You are Aegis, a supply-chain security remediation advisor. Given a \
vulnerability report, match results, and remediation guides, generate \
specific, actionable fix steps for each affected repository.

Return JSON with this schema:
{
  "summary": "1-2 sentence summary of what happened and the fix",
  "priority": "P0 | P1 | P2 | P3",
  "steps": [
    {
      "description": "What to do",
      "commands": {"repo_name": "shell command to run"},
      "explanation": "Why this step matters",
      "risk_level": "critical | high | medium | low"
    }
  ]
}

RULES:
- P0 = active exploitation / backdoor / credential theft — fix within hours
- P1 = known vuln with public exploit — fix within 24h
- P2 = known vuln, no public exploit — fix within 1 week
- P3 = informational / low risk — fix in next sprint
- Commands must be copy-pasteable (exact package names, versions, repo paths).
- Always include credential rotation for supply-chain compromises.
- Always include audit steps (npm audit, pip audit, etc.)."""


@dataclass
class RemediationStep:
    description: str
    commands: dict = field(default_factory=dict)
    explanation: str = ""
    risk_level: str = "medium"


@dataclass
class RemediationResult:
    summary: str
    priority: str
    steps: list[RemediationStep] = field(default_factory=list)
    per_repo: dict = field(default_factory=dict)


class RemediationEngine:

    def __init__(self, retriever, llm_client):
        self._retriever = retriever
        self._client = llm_client

    async def recommend(
        self,
        vuln_info: dict,
        match_results: list[dict],
    ) -> RemediationResult:
        packages = vuln_info.get("affected_packages", [])
        pkg_name = packages[0]["name"] if packages else "unknown"
        ecosystem = packages[0].get("ecosystem", "") if packages else ""

        guides = await self._retriever.retrieve_remediation_context(
            vuln_type="compromised_package",
            ecosystem=ecosystem,
            package_name=pkg_name,
        )

        similar = await self._retriever.retrieve_similar_incidents(
            f"{pkg_name} {ecosystem} vulnerability compromise",
            top_k=2,
        )

        guide_text = "\n\n".join(
            f"GUIDE: {g.metadata.get('title', g.source_id)}\n{g.content}"
            for g in guides
        ) or "(no remediation guides found)"

        similar_text = "\n\n".join(
            f"PAST INCIDENT: {s.metadata.get('title', s.source_id)}\n{s.content}"
            for s in similar
        ) or "(no similar incidents found)"

        repos_text = "\n".join(
            f"- {m.get('repo', '?')}: {m.get('component_name', pkg_name)}@{m.get('version_in_use', '?')}"
            for m in match_results
        )

        user_msg = (
            f"VULNERABILITY: {vuln_info.get('title', pkg_name)}\n"
            f"PACKAGE: {pkg_name} ({ecosystem})\n"
            f"VULNERABLE VERSIONS: {packages[0].get('vulnerable_versions', '?') if packages else '?'}\n\n"
            f"AFFECTED REPOS:\n{repos_text}\n\n"
            f"REMEDIATION GUIDES:\n{guide_text}\n\n"
            f"SIMILAR PAST INCIDENTS:\n{similar_text}"
        )

        try:
            raw = await self._client.generate(
                system=_REMEDIATION_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
                max_tokens=2048,
            )
            if not raw:
                raw = "{}"
            raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            data = json.loads(raw)
        except Exception:
            logger.exception("Remediation generation failed, returning fallback")
            return RemediationResult(
                summary=f"Upgrade {pkg_name} to the latest safe version across all affected repos.",
                priority="P1",
                steps=[RemediationStep(
                    description=f"Upgrade {pkg_name} in all affected repositories",
                    commands={},
                    explanation="Fallback recommendation — LLM generation failed.",
                    risk_level="high",
                )],
            )

        steps = []
        for s in data.get("steps", []):
            steps.append(RemediationStep(
                description=s.get("description", ""),
                commands=s.get("commands", {}),
                explanation=s.get("explanation", ""),
                risk_level=s.get("risk_level", "medium"),
            ))

        return RemediationResult(
            summary=data.get("summary", ""),
            priority=data.get("priority", "P1"),
            steps=steps,
        )


class DemoRemediationEngine:

    def __init__(self) -> None:
        from aegis.demo.rag_data import MOCK_REMEDIATION_RESULTS
        self._results = MOCK_REMEDIATION_RESULTS

    async def recommend(
        self,
        vuln_info: dict,
        match_results: list[dict],
    ) -> RemediationResult:
        packages = vuln_info.get("affected_packages", [])
        pkg_name = packages[0]["name"].lower() if packages else ""

        if pkg_name in self._results:
            data = self._results[pkg_name]
        else:
            for key in self._results:
                if key in pkg_name or pkg_name in key:
                    data = self._results[key]
                    break
            else:
                data = {
                    "summary": f"Upgrade {pkg_name} to the latest safe version.",
                    "priority": "P1",
                    "steps": [{"description": f"Upgrade {pkg_name}", "commands": {}, "explanation": "", "risk_level": "high"}],
                }

        steps = [
            RemediationStep(
                description=s["description"],
                commands=s.get("commands", {}),
                explanation=s.get("explanation", ""),
                risk_level=s.get("risk_level", "medium"),
            )
            for s in data.get("steps", [])
        ]

        return RemediationResult(
            summary=data["summary"],
            priority=data["priority"],
            steps=steps,
        )
