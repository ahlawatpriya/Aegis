"""LLM enrichment via Claude API — turns prose security articles into structured,
matchable data for the Aegis supply-chain risk tracker."""

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_ENRICHMENT_SYSTEM_PROMPT = """\
You are a security-article classifier and structured-data extractor for a \
supply-chain vulnerability tracking system called Aegis.

Given an article (title, summary, and optionally body text), return STRICT \
JSON with this exact schema — no markdown fences, no commentary:

{
  "classification": "supply_chain_vuln" | "threat_intel" | "general_info",
  "summary": "2-3 sentence summary of the article",
  "impact_score": <1-10 integer>,
  "affected_packages": [
    {
      "name": "<real installable package name>",
      "ecosystem": "<npm|pypi|maven|golang|cargo|rubygems|nuget|composer|...>",
      "vulnerable_versions": "<version constraint>",
      "cve_id": "<CVE-YYYY-NNNNN or null>"
    }
  ]
}

CLASSIFICATION RULES:
- supply_chain_vuln — a vulnerability or compromise in something installed as \
  a DEPENDENCY via a package manager (shows up in package.json, \
  requirements.txt, go.mod, pom.xml, Cargo.toml, etc.).  This is the ONLY \
  classification that populates affected_packages.
- threat_intel — vulnerabilities in DEPLOYED infrastructure/tools \
  (Kubernetes, Jenkins, Grafana, Nginx, etc.), attack techniques, threat-actor \
  campaign writeups.  Grafana having an RCE is NOT supply_chain_vuln — you \
  don't npm-install Grafana, you deploy it.
- general_info — no actual vulnerability; news, funding, policy, tool \
  announcements.

AFFECTED_PACKAGES RULES (critical — these drive automated cross-repo alerts):
1. name MUST be the real, installable package name.  Vulnerability nicknames \
   are NOT package names.  "Log4Shell" → the package is \
   "org.apache.logging.log4j:log4j-core".  "React2Shell" → the package is \
   "next".  Get this wrong and the downstream SBOM match never fires.
2. vulnerable_versions MUST be an actual version constraint:
   - Exact comma-separated versions: "1.14.1,0.30.4"
   - Range operators: "<4.19.1", ">=2.0.0,<2.3.1"
   - NEVER the words "unknown", "unclear", "unspecified", "affected", "all \
     versions" as text.
3. "all" is reserved SPECIFICALLY for typosquats — a package that was \
   malicious from its very first published version.  For a legitimate package \
   that was compromised (maintainer account takeover, backdoored release), \
   you MUST extract the specific backdoored version numbers.  In the vast \
   majority of real incidents only 1-2 versions were ever poisoned.
4. If you genuinely cannot determine a version range from the article, DROP \
   the package from affected_packages entirely and reclassify the article as \
   threat_intel rather than guessing.  An unactionable "unknown" is worse \
   than no automated match at all.

Only JSON output.  No markdown fences."""


_RECOVERY_ADDENDUM = """

IMPORTANT: The previous pass returned vulnerable_versions as "all" which is \
only valid for typosquats.  This is the FULL article text.  You MUST extract \
the specific compromised version numbers.  If the article names specific \
versions, use them.  If it truly is a typosquat (malicious from first publish), \
keep "all".  If you still cannot determine specific versions, DROP the package \
from affected_packages entirely and set classification to "threat_intel"."""


def _build_enrichment_prompt(article: dict, full_text: str | None = None, recovery: bool = False) -> str:
    """Build the user message for the Claude enrichment call."""
    parts = [f"TITLE: {article['title']}"]

    summary = article.get("summary", "")
    if summary:
        parts.append(f"SUMMARY: {summary}")

    body = full_text or article.get("body_text", "")
    if body:
        parts.append(f"BODY TEXT (up to 3000 chars):\n{body[:3000]}")

    source = article.get("source", "")
    if source:
        parts.append(f"SOURCE: {source}")

    if recovery:
        parts.append(_RECOVERY_ADDENDUM)

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_VALID_CLASSIFICATIONS = {"supply_chain_vuln", "threat_intel", "general_info"}
_VALID_ECOSYSTEMS = {
    "npm", "pypi", "maven", "golang", "cargo", "rubygems", "nuget",
    "composer", "pub", "hex", "hackage", "cpan", "conda", "cocoapods",
    "swift", "crates.io",
}
_VERSION_PATTERN = re.compile(r"[\d.<>=!,^ ~*|]+")


def _validate_enrichment(result: dict) -> dict:
    """Validate and sanitise the LLM output.  Returns the cleaned dict."""
    classification = result.get("classification", "general_info")
    if classification not in _VALID_CLASSIFICATIONS:
        classification = "general_info"
    result["classification"] = classification

    score = result.get("impact_score", 5)
    if not isinstance(score, int) or score < 1:
        score = 1
    elif score > 10:
        score = 10
    result["impact_score"] = score

    if classification != "supply_chain_vuln":
        result["affected_packages"] = []
        return result

    packages = result.get("affected_packages", [])
    if not isinstance(packages, list):
        packages = []

    cleaned: list[dict] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name", "").strip()
        ecosystem = pkg.get("ecosystem", "").strip().lower()
        versions = pkg.get("vulnerable_versions", "").strip()
        cve_id = pkg.get("cve_id")

        if not name:
            continue

        # Normalise ecosystem
        if ecosystem == "crates.io":
            ecosystem = "cargo"
        if ecosystem not in _VALID_ECOSYSTEMS:
            ecosystem = ""

        # Reject vague version strings
        vague = {"unknown", "unclear", "unspecified", "affected", "n/a", ""}
        if versions.lower() in vague:
            logger.warning(
                "Dropping package '%s' — vague vulnerable_versions '%s'",
                name, versions,
            )
            continue

        if cve_id and not re.match(r"^CVE-\d{4}-\d+$", cve_id, re.IGNORECASE):
            cve_id = None

        cleaned.append({
            "name": name,
            "ecosystem": ecosystem,
            "vulnerable_versions": versions,
            "cve_id": cve_id,
        })

    if not cleaned:
        result["classification"] = "threat_intel"

    result["affected_packages"] = cleaned
    return result


# ---------------------------------------------------------------------------
# needs_version_recovery — flag packages with suspicious "all"
# ---------------------------------------------------------------------------

def needs_version_recovery(result: dict) -> bool:
    """Return True if any affected_package has vulnerable_versions == 'all'
    and the article doesn't look like a typosquat report."""
    typosquat_signals = {"typosquat", "typosquatting", "name confusion"}
    title_lower = result.get("title", "").lower()
    summary_lower = result.get("summary", "").lower()
    combined = f"{title_lower} {summary_lower}"

    if any(signal in combined for signal in typosquat_signals):
        return False

    for pkg in result.get("affected_packages", []):
        if pkg.get("vulnerable_versions", "").strip().lower() == "all":
            return True
    return False


# ---------------------------------------------------------------------------
# Main enrichment call
# ---------------------------------------------------------------------------

async def enrich_article(
    article: dict,
    llm_client: Any,
    full_text: str | None = None,
    recovery: bool = False,
) -> dict:
    """Send an article to the LLM for classification and structured extraction.

    Returns the article dict augmented with classification, affected_packages,
    impact_score, and a refined summary.
    """
    user_msg = _build_enrichment_prompt(article, full_text=full_text, recovery=recovery)

    try:
        raw = await llm_client.generate(
            system=_ENRICHMENT_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
            max_tokens=2048,
        )
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```\w*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        result: dict = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("LLM returned invalid JSON for '%s': %s", article["title"][:60], exc)
        return {
            **article,
            "classification": "general_info",
            "affected_packages": [],
            "impact_score": 1,
        }
    except Exception as exc:
        logger.error("LLM enrichment failed for '%s': %s", article["title"][:60], exc)
        return {
            **article,
            "classification": "general_info",
            "affected_packages": [],
            "impact_score": 1,
        }

    result = _validate_enrichment(result)

    enriched = {**article}
    enriched["classification"] = result["classification"]
    enriched["affected_packages"] = result.get("affected_packages", [])
    enriched["impact_score"] = result.get("impact_score", 5)
    if result.get("summary"):
        enriched["enriched_summary"] = result["summary"]

    return enriched
