"""
SBOM matching engine — the bridge between threat intelligence and inventory.

For each supply_chain_vuln news entry, queries the SBOM inventory to determine
whether any of our repos actually use the affected package at a vulnerable version.

Match flow per package:
  1. Exact name lookup scoped to ecosystem
  2. Exact name lookup without ecosystem (catches misclassification)
  3. Fuzzy name match (catches typos / naming divergence)
  4. "Not found in any SBOM" → marked safe

For each SBOM hit:
  - Compare installed version against the vulnerable range
  - Classify as vulnerable, safe, or needs-manual-review
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert as pg_insert

from aegis.db.models import Sbom, MatchResult
from aegis.match.version import is_version_vulnerable

log = logging.getLogger(__name__)

_FUZZY_THRESHOLD = 85


class MatchEngine:
    """Matches threat-intel package data against the SBOM inventory."""

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    async def match_package(
        self,
        name: str,
        ecosystem: str,
        vulnerable_versions: str,
        session: AsyncSession,
    ) -> list[dict[str, Any]]:
        """Find every repo that uses *name* and check version vulnerability.

        Returns a list of result dicts, each with at least:
          - status: "not_found" | "found_not_vulnerable" | "found_vulnerable" | "manual_review"
          - Plus repo / version / purl details when a match exists.
        """
        if not name:
            return [{"status": "manual_review", "message": "Empty package name — route to manual review"}]

        if not vulnerable_versions or vulnerable_versions.strip().lower() in (
            "unknown",
            "unclear",
            "unspecified",
            "",
        ):
            log.warning("Non-actionable vulnerable_versions %r for %s — routing to manual review", vulnerable_versions, name)
            return [{"status": "manual_review", "message": f"Non-actionable version constraint '{vulnerable_versions}' for {name} — @appsec please check"}]

        # Step 1: exact lookup scoped to ecosystem
        rows = await self._exact_lookup(name, ecosystem, session)

        # Step 2: retry without ecosystem filter
        if not rows:
            log.debug("No match for %s in ecosystem %s — retrying without ecosystem", name, ecosystem)
            rows = await self._exact_lookup(name, None, session)

        # Step 3: fuzzy match
        if not rows:
            log.debug("No exact match for %s — trying fuzzy", name)
            rows = await self._fuzzy_lookup(name, session)

        # Step 4: nothing found anywhere
        if not rows:
            log.info("Package %s (%s) not found in any SBOM — marked safe", name, ecosystem)
            return [{"status": "not_found", "package": name, "ecosystem": ecosystem, "message": f"Package {name} not found in any SBOM — marked safe"}]

        # Evaluate each SBOM row against the vulnerable range
        results: list[dict[str, Any]] = []
        for row in rows:
            version_in_use = row["version"]
            try:
                vuln = is_version_vulnerable(version_in_use, vulnerable_versions)
            except Exception:
                log.exception("Version comparison failed for %s@%s against %r", name, version_in_use, vulnerable_versions)
                vuln = False

            results.append({
                "status": "found_vulnerable" if vuln else "found_not_vulnerable",
                "repo": row["repo"],
                "component_name": row["component_name"],
                "version_in_use": version_in_use,
                "purl": row["purl"],
                "ecosystem": row["ecosystem"],
                "is_vulnerable": vuln,
                "vulnerable_versions": vulnerable_versions,
            })

        vuln_count = sum(1 for r in results if r["is_vulnerable"])
        safe_count = len(results) - vuln_count
        log.info(
            "Package %s (%s): %d repos use it — %d vulnerable, %d safe",
            name, ecosystem, len(results), vuln_count, safe_count,
        )
        return results

    async def match_news_entry(
        self,
        news_entry: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        """Match all affected packages from a supply_chain_vuln news entry.

        Returns an aggregated summary with categories:
          - not_found:           package absent from all SBOMs (safe)
          - found_not_vulnerable: package present but version outside range
          - found_vulnerable:    package present AND version in range → ALERT
          - manual_review:       non-actionable version constraint
        """
        affected = news_entry.get("affected_packages") or []
        if not affected:
            log.info("News entry %s has no affected_packages — skipping match", news_entry.get("id", "?"))
            return {"not_found": [], "found_not_vulnerable": [], "found_vulnerable": [], "manual_review": []}

        summary: dict[str, list[dict]] = {
            "not_found": [],
            "found_not_vulnerable": [],
            "found_vulnerable": [],
            "manual_review": [],
        }

        for pkg in affected:
            pkg_name = pkg.get("name", "")
            pkg_eco = pkg.get("ecosystem", "")
            pkg_vuln_vers = pkg.get("vulnerable_versions", "")

            results = await self.match_package(pkg_name, pkg_eco, pkg_vuln_vers, session)

            for r in results:
                status = r.get("status", "manual_review")
                summary.setdefault(status, []).append(r)

                # Persist to DB
                if status in ("found_vulnerable", "found_not_vulnerable"):
                    await self._store_match_result(
                        news_id=news_entry.get("id"),
                        result=r,
                        session=session,
                    )

        vuln_repos = summary["found_vulnerable"]
        log.info(
            "News entry %s match complete: %d not_found, %d safe, %d VULNERABLE, %d manual_review",
            news_entry.get("id", "?"),
            len(summary["not_found"]),
            len(summary["found_not_vulnerable"]),
            len(vuln_repos),
            len(summary["manual_review"]),
        )
        return summary

    # ──────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────

    async def _exact_lookup(
        self,
        name: str,
        ecosystem: str | None,
        session: AsyncSession,
    ) -> list[dict[str, Any]]:
        """Exact name lookup in the SBOM table, optionally scoped to ecosystem."""
        stmt = select(
            Sbom.repo,
            Sbom.component_name,
            Sbom.version,
            Sbom.purl,
            Sbom.ecosystem,
        ).where(
            func.lower(Sbom.component_name) == name.lower()
        )
        if ecosystem:
            stmt = stmt.where(func.lower(Sbom.ecosystem) == ecosystem.lower())

        result = await session.execute(stmt)
        return [
            {
                "repo": row.repo,
                "component_name": row.component_name,
                "version": row.version,
                "purl": row.purl,
                "ecosystem": row.ecosystem,
            }
            for row in result.all()
        ]

    async def _fuzzy_lookup(
        self,
        name: str,
        session: AsyncSession,
    ) -> list[dict[str, Any]]:
        """Fuzzy name match against distinct component names in SBOM.

        Uses rapidfuzz for scoring.  Falls back to substring containment
        when rapidfuzz is not installed.
        """
        distinct_stmt = select(Sbom.component_name).distinct().limit(10000)
        result = await session.execute(distinct_stmt)
        all_names: list[str] = [row[0] for row in result.all()]

        if not all_names:
            return []

        matched_name: str | None = None
        try:
            from rapidfuzz import fuzz
            best_score = 0.0
            for candidate in all_names:
                score = fuzz.token_sort_ratio(name.lower(), candidate.lower())
                if score > best_score:
                    best_score = score
                    matched_name = candidate
            if best_score < _FUZZY_THRESHOLD:
                matched_name = None
                log.debug("Best fuzzy score for %r was %.1f (%s) — below threshold", name, best_score, matched_name)
        except ImportError:
            log.warning("rapidfuzz not installed — falling back to substring match")
            name_lower = name.lower()
            for candidate in all_names:
                if name_lower in candidate.lower() or candidate.lower() in name_lower:
                    matched_name = candidate
                    break

        if not matched_name:
            return []

        log.info("Fuzzy matched %r → %r", name, matched_name)
        stmt = select(
            Sbom.repo,
            Sbom.component_name,
            Sbom.version,
            Sbom.purl,
            Sbom.ecosystem,
        ).where(Sbom.component_name == matched_name)

        result = await session.execute(stmt)
        return [
            {
                "repo": row.repo,
                "component_name": row.component_name,
                "version": row.version,
                "purl": row.purl,
                "ecosystem": row.ecosystem,
            }
            for row in result.all()
        ]

    async def _store_match_result(
        self,
        news_id: int | None,
        result: dict[str, Any],
        session: AsyncSession,
    ) -> None:
        """Persist a single match result row."""
        if news_id is None:
            return
        try:
            stmt = pg_insert(MatchResult).values(
                news_id=news_id,
                repo=result["repo"],
                component_name=result["component_name"],
                version_in_use=result["version_in_use"],
                vulnerable_versions=result["vulnerable_versions"],
                is_vulnerable=result["is_vulnerable"],
                purl=result.get("purl", ""),
                ecosystem=result.get("ecosystem", ""),
                matched_at=datetime.now(timezone.utc),
            ).on_conflict_do_nothing()
            await session.execute(stmt)
            await session.commit()
        except Exception:
            log.exception("Failed to store match result for news_id=%s repo=%s", news_id, result.get("repo"))
            await session.rollback()
