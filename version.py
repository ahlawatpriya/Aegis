"""
Semver-ish version comparator for vulnerability matching.

Determines whether a repo's installed version falls within a vulnerable range.

Version constraint syntax:
  - "all"                   → every version is vulnerable (typosquats only)
  - "1.14.1,0.30.4"        → exact versions, treated as OR (match any one)
  - "<4.19.1"              → operator constraint
  - ">=2.0.0,<2.3.1"      → multiple operator constraints, treated as AND (all must hold)
  - Mixed: "1.14.1,>=2.0.0,<2.3.1" → exact versions OR'd, operator constraints AND'd;
    the version is vulnerable if it matches ANY exact version OR satisfies ALL operator constraints.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache

log = logging.getLogger(__name__)

_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[.+\-].*)?$", re.IGNORECASE)
_OPERATOR_RE = re.compile(r"^(>=|<=|!=|>|<|=)\s*(.+)$")


def parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple of ints.

    Handles:
      - Standard semver: "1.2.3" → (1, 2, 3)
      - Two-part: "1.2" → (1, 2, 0)
      - Leading 'v': "v1.2.3" → (1, 2, 3)
      - Pre-release suffixes: "1.2.3-rc1" → (1, 2, 3) with a logged warning
      - Four-part: "1.2.3.4" → (1, 2, 3, 4)

    Raises ValueError if the string cannot be parsed.
    """
    stripped = version_str.strip()
    if not stripped:
        raise ValueError("Empty version string")

    m = _VERSION_RE.match(stripped)
    if not m:
        raise ValueError(f"Cannot parse version: {version_str!r}")

    if stripped != m.group(0) or m.group(0) != stripped.lstrip("vV"):
        pass  # suffix was present
    if any(c in version_str for c in ("-", "+")):
        log.debug("Stripped pre-release/build suffix from version %r", version_str)

    parts = tuple(int(p) for p in m.group(1).split("."))
    # Normalise to at least 3 components
    if len(parts) < 3:
        parts = parts + (0,) * (3 - len(parts))
    return parts


@lru_cache(maxsize=4096)
def _cached_parse(v: str) -> tuple[int, ...]:
    return parse_version(v)


def compare_versions(v1: tuple[int, ...], v2: tuple[int, ...]) -> int:
    """Compare two parsed version tuples.

    Returns:
      -1 if v1 < v2
       0 if v1 == v2
       1 if v1 > v2

    Pads the shorter tuple with zeros so (1,2) and (1,2,0) compare equal.
    """
    max_len = max(len(v1), len(v2))
    a = v1 + (0,) * (max_len - len(v1))
    b = v2 + (0,) * (max_len - len(v2))
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def version_matches_constraint(version: str, constraint: str) -> bool:
    """Check whether *version* satisfies a single operator constraint.

    Examples:
      version_matches_constraint("1.2.3", "<1.3.0")   → True
      version_matches_constraint("2.0.0", ">=2.0.0")  → True
      version_matches_constraint("1.9.9", "=2.0.0")   → False
    """
    constraint = constraint.strip()
    m = _OPERATOR_RE.match(constraint)
    if not m:
        raise ValueError(f"Invalid constraint: {constraint!r}")

    op, target_str = m.group(1), m.group(2).strip()
    try:
        v = _cached_parse(version)
        t = _cached_parse(target_str)
    except ValueError:
        log.warning("Unparseable version in constraint check: version=%r constraint=%r", version, constraint)
        return False

    cmp = compare_versions(v, t)

    if op == "<":
        return cmp < 0
    if op == "<=":
        return cmp <= 0
    if op == ">":
        return cmp > 0
    if op == ">=":
        return cmp >= 0
    if op == "=":
        return cmp == 0
    if op == "!=":
        return cmp != 0
    return False


def _is_operator_constraint(part: str) -> bool:
    """Return True if *part* starts with a comparison operator."""
    s = part.strip()
    return bool(s) and s[0] in "<>=!"


def is_version_vulnerable(version_in_use: str, vulnerable_versions: str) -> bool:
    """Determine whether *version_in_use* falls inside *vulnerable_versions*.

    Decision logic
    ──────────────
    1. ``"all"`` → always vulnerable (typosquats).
    2. Split *vulnerable_versions* on commas.
    3. Classify each segment as an **exact version** or an **operator constraint**.
    4. If *version_in_use* equals ANY exact version → **vulnerable** (OR).
    5. If ALL operator constraints are satisfied → **vulnerable** (AND).
    6. Otherwise → **not vulnerable**.

    Mixing exact versions and operator constraints is supported:
      ``"1.14.1,>=2.0.0,<2.3.1"``
    means "vulnerable if version is exactly 1.14.1 **or** in [2.0.0, 2.3.1)".

    Parameters
    ----------
    version_in_use : str
        The version currently installed in a repository.
    vulnerable_versions : str
        The vulnerability constraint string from threat intelligence.

    Returns
    -------
    bool
        True if the version is considered vulnerable.
    """
    version_in_use = version_in_use.strip()
    vulnerable_versions = vulnerable_versions.strip()

    if not version_in_use or not vulnerable_versions:
        log.warning("Empty input: version_in_use=%r vulnerable_versions=%r", version_in_use, vulnerable_versions)
        return False

    # ── Special case: typosquat / entirely malicious package ──
    if vulnerable_versions.lower() == "all":
        return True

    try:
        v_parsed = _cached_parse(version_in_use)
    except ValueError:
        log.warning("Cannot parse version_in_use %r — treating as not vulnerable", version_in_use)
        return False

    parts = [p.strip() for p in vulnerable_versions.split(",") if p.strip()]
    if not parts:
        return False

    exact_versions: list[str] = []
    operator_constraints: list[str] = []

    for part in parts:
        if _is_operator_constraint(part):
            operator_constraints.append(part)
        else:
            exact_versions.append(part)

    # ── OR check: any exact version match? ──
    for ev in exact_versions:
        try:
            ev_parsed = _cached_parse(ev)
            if compare_versions(v_parsed, ev_parsed) == 0:
                return True
        except ValueError:
            log.warning("Cannot parse exact vulnerable version %r — skipping", ev)

    # ── AND check: all operator constraints satisfied? ──
    if operator_constraints:
        all_satisfied = True
        for oc in operator_constraints:
            try:
                if not version_matches_constraint(version_in_use, oc):
                    all_satisfied = False
                    break
            except ValueError:
                log.warning("Invalid operator constraint %r — treating as not satisfied", oc)
                all_satisfied = False
                break
        if all_satisfied:
            return True

    return False
