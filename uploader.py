from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import boto3
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.config import get_settings

settings = get_settings()
from aegis.db.engine import get_session

log = logging.getLogger(__name__)


class SBOMUploader:
    """Persists SBOM scan results to S3 and Postgres.

    Uploads the merged CycloneDX JSON to S3 for archival, and upserts
    structured rows into Postgres tables (aegis_sbom, aegis_sbom_licenses)
    per repo.
    """

    def __init__(
        self,
        s3_bucket: str | None = None,
        aws_region: str | None = None,
    ) -> None:
        self._bucket = s3_bucket or settings.s3_bucket
        self._region = aws_region or settings.aws_region

    async def upload_to_s3(self, sbom_json: dict, repo_name: str) -> str:
        if not self._bucket:
            log.warning("S3 bucket not configured — skipping S3 upload")
            return ""

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        key = f"sbom/{repo_name}/{ts}/sbom.json"
        body = json.dumps(sbom_json, indent=2).encode("utf-8")

        try:
            s3 = boto3.client("s3", region_name=self._region)
            s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType="application/json",
            )
            log.info("Uploaded SBOM to s3://%s/%s", self._bucket, key)
            return key
        except Exception as exc:
            log.error("S3 upload failed: %s", exc)
            raise

    async def upsert_components(
        self, session: AsyncSession, components: list[dict], repo_name: str
    ) -> int:
        if not components:
            return 0

        upserted = 0
        for comp in components:
            purl = comp.get("purl", "")
            if not purl:
                continue

            await session.execute(
                text("""
                    INSERT INTO aegis_sbom
                        (repo, component_name, version, purl, ecosystem, category, scanned_at)
                    VALUES
                        (:repo, :name, :version, :purl, :ecosystem, :category, :scanned_at)
                    ON CONFLICT (repo, purl)
                    DO UPDATE SET
                        version = EXCLUDED.version,
                        ecosystem = EXCLUDED.ecosystem,
                        category = EXCLUDED.category,
                        scanned_at = EXCLUDED.scanned_at
                """),
                {
                    "repo": repo_name,
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "purl": purl,
                    "ecosystem": comp.get("ecosystem", ""),
                    "category": comp.get("type", "library"),
                    "scanned_at": datetime.now(timezone.utc),
                },
            )
            upserted += 1

        return upserted

    async def upsert_licenses(
        self, session: AsyncSession, licenses: list[dict]
    ) -> int:
        if not licenses:
            return 0

        upserted = 0
        for lic in licenses:
            purl = lic.get("purl", "")
            license_id = lic.get("license")
            source = lic.get("source", "unknown")
            if not purl or not license_id:
                continue

            await session.execute(
                text("""
                    INSERT INTO aegis_sbom_licenses
                        (purl, license, source, resolved_at)
                    VALUES
                        (:purl, :license, :source, :resolved_at)
                    ON CONFLICT (purl, source)
                    DO UPDATE SET
                        license = EXCLUDED.license,
                        resolved_at = EXCLUDED.resolved_at
                """),
                {
                    "purl": purl,
                    "license": license_id,
                    "source": source,
                    "resolved_at": datetime.now(timezone.utc),
                },
            )
            upserted += 1

        return upserted

    async def upload(
        self,
        sbom_json: dict,
        components: list[dict],
        vulnerabilities: list[dict],
        licenses: list[dict],
        repo_name: str,
    ) -> dict:
        s3_key = await self.upload_to_s3(sbom_json, repo_name)

        async with get_session() as session:
            comp_count = await self.upsert_components(session, components, repo_name)
            lic_count = await self.upsert_licenses(session, licenses)
            await session.commit()

        log.info(
            "Upload complete for %s: %d components, %d licenses upserted, S3 key=%s",
            repo_name,
            comp_count,
            lic_count,
            s3_key or "(skipped)",
        )

        return {
            "s3_key": s3_key,
            "components_upserted": comp_count,
            "licenses_upserted": lic_count,
        }
