from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from aegis.config import get_settings

settings = get_settings()

log = logging.getLogger(__name__)

DEPS_DEV_SYSTEM_MAP: dict[str, str] = {
    "npm": "NPM",
    "pypi": "PYPI",
    "golang": "GO",
    "maven": "MAVEN",
    "cargo": "CARGO",
    "gem": "RUBYGEMS",
    "nuget": "NUGET",
}

PATTERN_RULES: list[tuple[str, str, str | None]] = [
    # (prefix_or_glob, license, ecosystem_filter_or_None)
    ("golang.org/x/", "BSD-3-Clause", "golang"),
    ("google.golang.org/", "Apache-2.0", "golang"),
    ("github.com/golang/", "BSD-3-Clause", "golang"),
    ("cloud.google.com/go", "Apache-2.0", "golang"),
    ("k8s.io/", "Apache-2.0", "golang"),
    ("sigs.k8s.io/", "Apache-2.0", "golang"),
    ("@types/", "MIT", "npm"),
    ("@angular/", "MIT", "npm"),
    ("@babel/", "MIT", "npm"),
    ("@eslint/", "MIT", "npm"),
    ("@jest/", "MIT", "npm"),
    ("@testing-library/", "MIT", "npm"),
]

INTERNAL_PREFIXES: list[str] = [
    "@internal/",
    "@company/",
    "@org/",
    "internal-",
    "corp-",
]


class Licenser:
    """License enrichment module — 4-tier resolution pipeline.

    Renamed from the deps.dev enricher in the original Optimus system.
    Resolves licenses for SBOM components using deterministic pattern
    rules first, deps.dev API second, GitHub repo-license API as fallback,
    and an explicit 'unsupported-ecosystem' tag for anything still unresolved.
    """

    def __init__(
        self,
        github_token: str | None = None,
        concurrency: int = 20,
    ) -> None:
        self._github_token = github_token or settings.github_token
        self._semaphore = asyncio.Semaphore(concurrency)

    def _check_pattern_rules(self, name: str, ecosystem: str) -> str | None:
        for prefix in INTERNAL_PREFIXES:
            if name.startswith(prefix):
                return "Proprietary"

        for prefix, license_id, eco_filter in PATTERN_RULES:
            if eco_filter and eco_filter != ecosystem:
                continue
            if name.startswith(prefix):
                return license_id

        return None

    async def _query_deps_dev(self, ecosystem: str, name: str) -> str | None:
        system = DEPS_DEV_SYSTEM_MAP.get(ecosystem)
        if not system:
            return None

        encoded_name = name.replace("/", "%2F")
        url = f"https://api.deps.dev/v3/systems/{system}/packages/{encoded_name}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return None
                data = resp.json()

            versions = data.get("versions", [])
            if not versions:
                return None

            latest = versions[-1]
            licenses = latest.get("licenses", [])
            if licenses:
                return licenses[0]

            advisory_keys = latest.get("advisoryKeys", [])
            _ = advisory_keys

            return None

        except (httpx.HTTPError, KeyError, IndexError, ValueError):
            log.debug("deps.dev lookup failed for %s/%s", ecosystem, name)
            return None

    async def _query_github(self, name: str) -> str | None:
        if not self._github_token:
            return None

        owner_repo = ""
        if "/" in name and not name.startswith("@"):
            parts = name.split("/")
            if len(parts) >= 2:
                owner_repo = f"{parts[-2]}/{parts[-1]}"
        elif name.startswith("@"):
            stripped = name.lstrip("@")
            if "/" in stripped:
                owner_repo = stripped

        if not owner_repo:
            return None

        url = f"https://api.github.com/repos/{owner_repo}/license"
        headers = {
            "Authorization": f"token {self._github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    return None
                data = resp.json()

            lic = data.get("license", {})
            spdx_id = lic.get("spdx_id")
            if spdx_id and spdx_id != "NOASSERTION":
                return spdx_id
            return lic.get("name")

        except (httpx.HTTPError, KeyError, ValueError):
            log.debug("GitHub license lookup failed for %s", name)
            return None

    async def resolve_license(
        self, purl: str, ecosystem: str, name: str
    ) -> tuple[str | None, str]:
        pattern_result = self._check_pattern_rules(name, ecosystem)
        if pattern_result:
            return pattern_result, "pattern"

        deps_dev_result = await self._query_deps_dev(ecosystem, name)
        if deps_dev_result:
            return deps_dev_result, "deps_dev"

        github_result = await self._query_github(name)
        if github_result:
            return github_result, "github"

        if ecosystem not in DEPS_DEV_SYSTEM_MAP:
            return None, "unsupported-ecosystem"

        return None, "unresolved"

    async def _resolve_one(self, item: dict[str, Any]) -> dict[str, Any]:
        async with self._semaphore:
            purl = item.get("purl", "")
            ecosystem = item.get("ecosystem", "")
            name = item.get("name", "")

            lic, source = await self.resolve_license(purl, ecosystem, name)
            return {
                **item,
                "resolved_license": lic,
                "license_source": source,
            }

    async def enrich_batch(self, purls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        items_needing_resolution = []
        already_resolved = []

        for item in purls:
            existing = item.get("licenses", [])
            if existing:
                already_resolved.append(
                    {
                        **item,
                        "resolved_license": existing[0] if existing else None,
                        "license_source": "scanner",
                    }
                )
            else:
                items_needing_resolution.append(item)

        log.info(
            "Licenser: %d already have licenses, %d need resolution",
            len(already_resolved),
            len(items_needing_resolution),
        )

        tasks = [self._resolve_one(item) for item in items_needing_resolution]
        resolved = await asyncio.gather(*tasks, return_exceptions=True)

        results = list(already_resolved)
        for r in resolved:
            if isinstance(r, Exception):
                log.warning("License resolution failed: %s", r)
                continue
            results.append(r)

        resolved_count = sum(
            1 for r in results if r.get("resolved_license") is not None
        )
        log.info(
            "Licenser: resolved %d / %d total licenses",
            resolved_count,
            len(results),
        )
        return results
