from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from aegis.sbom.cartograph import Cartograph
from aegis.sbom.auditor import Auditor
from aegis.sbom.fuse import fuse_sboms
from aegis.sbom.sentinel import Sentinel
from aegis.sbom.licenser import Licenser
from aegis.sbom.uploader import SBOMUploader

log = logging.getLogger(__name__)


class SBOMScanner:
    """Orchestrates the full SBOM/SCA pipeline for a single repo.

    Pipeline stages:
      1. Cartograph  — discover all components (syft)
      2. Auditor     — discover components + license metadata (trivy)
      3. Fuse        — merge the two SBOMs by PURL union
      4. Sentinel    — match merged SBOM against vuln databases (grype)
      5. Licenser    — enrich any missing licenses via deps.dev / GitHub
      6. Upload      — persist to S3 + Postgres
    """

    def __init__(
        self,
        cartograph: Cartograph | None = None,
        auditor: Auditor | None = None,
        sentinel: Sentinel | None = None,
        licenser: Licenser | None = None,
        uploader: SBOMUploader | None = None,
    ) -> None:
        self._cartograph = cartograph or Cartograph()
        self._auditor = auditor or Auditor()
        self._sentinel = sentinel or Sentinel()
        self._licenser = licenser or Licenser()
        self._uploader = uploader or SBOMUploader()

    async def scan_repo(self, repo_path: str, repo_name: str) -> dict:
        log.info("=== SBOM scan starting for %s (%s) ===", repo_name, repo_path)

        tmp_dir = tempfile.mkdtemp(prefix="aegis_sbom_")
        cartograph_path = str(Path(tmp_dir) / "cartograph.json")
        auditor_path = str(Path(tmp_dir) / "auditor.json")
        fused_path = str(Path(tmp_dir) / "fused.json")

        try:
            # 1. Cartograph scan
            log.info("[1/6] Running Cartograph (component discovery)…")
            cartograph_sbom = await self._cartograph.scan(repo_path, cartograph_path)
            cartograph_components = Cartograph.parse_components(cartograph_sbom)

            # 2. Auditor scan
            log.info("[2/6] Running Auditor (license + component scan)…")
            auditor_sbom = await self._auditor.scan(repo_path, auditor_path)
            auditor_components = Auditor.parse_components(auditor_sbom)

            # 3. Fuse
            log.info("[3/6] Fusing SBOMs…")
            fused_sbom = fuse_sboms(cartograph_sbom, auditor_sbom)
            with open(fused_path, "w", encoding="utf-8") as f:
                json.dump(fused_sbom, f, indent=2)

            all_components = Cartograph.parse_components(fused_sbom)

            # 4. Sentinel vulnerability scan
            log.info("[4/6] Running Sentinel (vulnerability matching)…")
            vulnerabilities = await self._sentinel.scan(fused_path)

            # 5. Licenser enrichment
            log.info("[5/6] Running Licenser (license resolution)…")
            enriched_components = await self._licenser.enrich_batch(all_components)

            # 6. Upload
            log.info("[6/6] Uploading results…")
            license_rows = [
                {
                    "purl": c["purl"],
                    "license": c.get("resolved_license"),
                    "source": c.get("license_source", "unknown"),
                }
                for c in enriched_components
                if c.get("resolved_license")
            ]

            await self._uploader.upload(
                sbom_json=fused_sbom,
                components=enriched_components,
                vulnerabilities=vulnerabilities,
                licenses=license_rows,
                repo_name=repo_name,
            )

            licenses_resolved = sum(
                1 for c in enriched_components if c.get("resolved_license")
            )

            summary = {
                "repo": repo_name,
                "total_components": len(enriched_components),
                "cartograph_found": len(cartograph_components),
                "auditor_found": len(auditor_components),
                "vulnerabilities_found": len(vulnerabilities),
                "licenses_resolved": licenses_resolved,
                "licenses_unresolved": len(enriched_components) - licenses_resolved,
            }

            log.info(
                "=== SBOM scan complete for %s: %d components, %d vulns, %d licenses ===",
                repo_name,
                summary["total_components"],
                summary["vulnerabilities_found"],
                summary["licenses_resolved"],
            )
            return summary

        finally:
            for p in (cartograph_path, auditor_path, fused_path):
                Path(p).unlink(missing_ok=True)
            try:
                Path(tmp_dir).rmdir()
            except OSError:
                pass
