from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import time
from pathlib import Path

from aegis.sbom.purl import parse_purl, PURL_TYPE_TO_ECOSYSTEM

log = logging.getLogger(__name__)


class CartographError(Exception):
    pass


class Cartograph:
    """SBOM component discovery tool — wraps the syft CLI.

    Renamed from Syft in the original Optimus system. Walks a repo or
    container image and lists every component it can find (npm packages,
    Go modules, OS packages, GitHub Actions, etc.).
    """

    def __init__(self, syft_bin: str = "syft") -> None:
        self._bin = syft_bin

    async def scan(self, target: str, output_path: str | None = None) -> dict:
        out_path = output_path or tempfile.mktemp(suffix=".json", prefix="cartograph_")
        cmd = [self._bin, target, "-o", f"cyclonedx-json={out_path}"]

        log.info("Cartograph: scanning %s", target)
        t0 = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except FileNotFoundError:
            raise CartographError(
                f"'{self._bin}' not found on PATH. Install syft: "
                "https://github.com/anchore/syft#installation"
            )

        elapsed = time.monotonic() - t0

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="replace").strip()
            raise CartographError(
                f"Cartograph scan failed (exit {proc.returncode}): {err_msg}"
            )

        try:
            with open(out_path, "r", encoding="utf-8") as f:
                sbom = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            raise CartographError(f"Failed to read Cartograph output: {exc}")
        finally:
            if not output_path:
                Path(out_path).unlink(missing_ok=True)

        component_count = len(sbom.get("components", []))
        log.info(
            "Cartograph: finished %s in %.1fs — %d components discovered",
            target,
            elapsed,
            component_count,
        )
        return sbom

    @staticmethod
    def parse_components(cyclonedx: dict) -> list[dict]:
        results: list[dict] = []
        for comp in cyclonedx.get("components", []):
            purl_str = comp.get("purl", "")
            ecosystem = ""
            if purl_str:
                try:
                    parsed = parse_purl(purl_str)
                    ecosystem = parsed.ecosystem
                except ValueError:
                    bom_ref_type = comp.get("type", "")
                    ecosystem = PURL_TYPE_TO_ECOSYSTEM.get(bom_ref_type, "")

            licenses_list: list[str] = []
            for lic_entry in comp.get("licenses", []):
                if "license" in lic_entry:
                    lic_obj = lic_entry["license"]
                    lic_id = lic_obj.get("id") or lic_obj.get("name", "")
                    if lic_id:
                        licenses_list.append(lic_id)
                elif "expression" in lic_entry:
                    licenses_list.append(lic_entry["expression"])

            results.append(
                {
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "purl": purl_str,
                    "ecosystem": ecosystem,
                    "licenses": licenses_list,
                    "group": comp.get("group", ""),
                    "type": comp.get("type", "library"),
                }
            )
        return results
