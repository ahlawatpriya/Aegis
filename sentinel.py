from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import time
from pathlib import Path

log = logging.getLogger(__name__)


class SentinelError(Exception):
    pass


class Sentinel:
    """Vulnerability matcher — wraps the grype CLI.

    Renamed from Grype in the original Optimus system. Takes a finished
    SBOM and matches every component against vulnerability databases
    (NVD, GitHub Advisories, distro feeds).
    """

    def __init__(self, grype_bin: str = "grype") -> None:
        self._bin = grype_bin

    async def scan(self, sbom_path: str) -> list[dict]:
        out_path = tempfile.mktemp(suffix=".json", prefix="sentinel_")
        cmd = [
            self._bin,
            f"sbom:{sbom_path}",
            "-o", "json",
            "--file", out_path,
        ]

        log.info("Sentinel: scanning SBOM %s for vulnerabilities", sbom_path)
        t0 = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except FileNotFoundError:
            raise SentinelError(
                f"'{self._bin}' not found on PATH. Install grype: "
                "https://github.com/anchore/grype#installation"
            )

        elapsed = time.monotonic() - t0

        if proc.returncode not in (0, 1):
            err_msg = stderr.decode(errors="replace").strip()
            raise SentinelError(
                f"Sentinel scan failed (exit {proc.returncode}): {err_msg}"
            )

        try:
            with open(out_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            raise SentinelError(f"Failed to read Sentinel output: {exc}")
        finally:
            Path(out_path).unlink(missing_ok=True)

        vulns = self.parse_vulnerabilities(raw)
        log.info(
            "Sentinel: finished in %.1fs — %d vulnerabilities found",
            elapsed,
            len(vulns),
        )
        return vulns

    @staticmethod
    def parse_vulnerabilities(grype_output: dict) -> list[dict]:
        results: list[dict] = []
        for match in grype_output.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            fixed_versions: list[str] = []
            fix_obj = vuln.get("fix", {})
            if fix_obj.get("versions"):
                fixed_versions = fix_obj["versions"]
            elif fix_obj.get("state") == "fixed" and fix_obj.get("version"):
                fixed_versions = [fix_obj["version"]]

            severity = vuln.get("severity", "Unknown")
            cvss_entries = vuln.get("cvss", [])
            cvss_score: float | None = None
            if cvss_entries:
                scores = [
                    entry.get("metrics", {}).get("baseScore")
                    for entry in cvss_entries
                    if entry.get("metrics", {}).get("baseScore") is not None
                ]
                if scores:
                    cvss_score = max(scores)

            data_source = ""
            related = match.get("relatedVulnerabilities", [])
            if related:
                data_source = related[0].get("dataSource", "")
            if not data_source:
                data_source = vuln.get("dataSource", "")

            results.append(
                {
                    "cve_id": vuln.get("id", ""),
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "package_name": artifact.get("name", ""),
                    "package_version": artifact.get("version", ""),
                    "package_purl": artifact.get("purl", ""),
                    "fixed_versions": fixed_versions,
                    "description": vuln.get("description", ""),
                    "data_source": data_source,
                }
            )
        return results
