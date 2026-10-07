from __future__ import annotations

import copy
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def _component_key(comp: dict) -> str:
    purl = comp.get("purl", "")
    if purl:
        return purl
    name = comp.get("name", "")
    version = comp.get("version", "")
    group = comp.get("group", "")
    return f"{group}/{name}@{version}" if group else f"{name}@{version}"


def _has_license(comp: dict) -> bool:
    licenses = comp.get("licenses", [])
    if not licenses:
        return False
    for lic_entry in licenses:
        if "license" in lic_entry:
            lic_obj = lic_entry["license"]
            if lic_obj.get("id") or lic_obj.get("name"):
                return True
        if "expression" in lic_entry:
            return True
    return False


def merge_component_lists(list_a: list[dict], list_b: list[dict]) -> list[dict]:
    """Merge two CycloneDX component lists by PURL union.

    When both scanners found the same package, prefer the record that has
    a license field populated. If both have licenses, prefer list_a (Cartograph).
    """
    index: dict[str, dict] = {}

    for comp in list_a:
        key = _component_key(comp)
        index[key] = comp

    for comp in list_b:
        key = _component_key(comp)
        if key not in index:
            index[key] = comp
        else:
            existing = index[key]
            if not _has_license(existing) and _has_license(comp):
                index[key] = comp

    return list(index.values())


def fuse_sboms(cartograph_sbom: dict, auditor_sbom: dict) -> dict:
    """Merge Cartograph + Auditor CycloneDX SBOMs into one.

    Union by PURL as the key. When both tools found the same package,
    prefer the record that has a license field populated. Keeps the
    CycloneDX metadata envelope from the Cartograph SBOM and updates
    the component count.
    """
    merged = copy.deepcopy(cartograph_sbom)

    components_a = cartograph_sbom.get("components", [])
    components_b = auditor_sbom.get("components", [])

    count_a = len(components_a)
    count_b = len(components_b)

    merged_components = merge_component_lists(components_a, components_b)
    merged["components"] = merged_components

    if "metadata" not in merged:
        merged["metadata"] = {}

    tools = merged["metadata"].get("tools")
    aegis_tool = {"vendor": "aegis", "name": "fuse", "version": "0.1.0"}
    if isinstance(tools, list):
        tools.append(aegis_tool)
    elif isinstance(tools, dict):
        components_list = tools.get("components", [])
        components_list.append(aegis_tool)
        tools["components"] = components_list
    else:
        merged["metadata"]["tools"] = [aegis_tool]
    merged["metadata"]["timestamp"] = datetime.now(timezone.utc).isoformat()

    log.info(
        "Fuse: merged %d (Cartograph) + %d (Auditor) → %d unique components",
        count_a,
        count_b,
        len(merged_components),
    )
    return merged
