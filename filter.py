"""Keyword-based relevance filter and vendor blocklist for the Aegis news
ingestion pipeline.  Cheap, deterministic, high-recall — runs before anything
touches the LLM."""

import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Relevance keywords grouped by category
# ---------------------------------------------------------------------------

RELEVANCE_KEYWORDS: dict[str, list[str]] = {
    "supply_chain": [
        "malicious package",
        "typosquatting",
        "typosquat",
        "dependency confusion",
        "supply chain attack",
        "supply-chain attack",
        "compromised package",
        "backdoor",
        "backdoored",
        "hijacked",
        "hijack",
        "package takeover",
        "protestware",
        "maintainer account",
        "account takeover",
        "poisoned",
        "trojanized",
        "trojan",
        "software supply chain",
        "dependency hijack",
        "star-jacking",
        "repo-jacking",
        "manifest confusion",
        "install script",
        "postinstall",
        "preinstall",
        "exfiltrate",
        "crypto miner",
        "cryptominer",
        "reverse shell",
    ],
    "ecosystems": [
        "npm",
        "pypi",
        "crates.io",
        "maven",
        "rubygems",
        "nuget",
        "go module",
        "cargo",
        "composer",
        "pip",
        "yarn",
        "pnpm",
        "packagist",
        "cocoapods",
        "hex.pm",
        "pub.dev",
        "hackage",
        "cpan",
        "anaconda",
        "conda",
        "docker hub",
        "ghcr.io",
        "github actions",
        "github action",
    ],
    "tech_stack": [
        "node",
        "nodejs",
        "node.js",
        "python",
        "golang",
        "java",
        "rust",
        "kubernetes",
        "k8s",
        "docker",
        "aws",
        "terraform",
        "github actions",
        "react",
        "next.js",
        "nextjs",
        "express",
        "fastapi",
        "flask",
        "django",
        "spring",
        "gin",
        "actix",
        "webpack",
        "vite",
        "esbuild",
        "deno",
        "bun",
    ],
    "ai_devtools": [
        "langchain",
        "openai",
        "huggingface",
        "hugging face",
        "pytorch",
        "tensorflow",
        "jupyter",
        "vscode extension",
        "vs code extension",
        "copilot",
        "llm",
        "large language model",
        "mlflow",
        "wandb",
        "transformers",
        "ollama",
        "llamaindex",
        "llama-index",
        "autogen",
        "crewai",
    ],
    "severity": [
        "critical",
        "cvss 9",
        "cvss 10",
        "cvss score 9",
        "cvss score 10",
        "zero-day",
        "zero day",
        "0-day",
        "0day",
        "actively exploited",
        "remote code execution",
        "rce",
        "arbitrary code execution",
        "arbitrary code",
        "pre-auth",
        "unauthenticated",
        "wormable",
        "cisa kev",
        "known exploited",
    ],
    "breach": [
        "data breach",
        "credential leak",
        "token leak",
        "secret exposed",
        "api key",
        "api key leak",
        "leaked credentials",
        "hardcoded secret",
        "hardcoded password",
        "exposed .env",
        ".env file",
        "secrets in code",
    ],
}

# Flatten for fast lookup — lowercased
_ALL_KEYWORDS: list[tuple[str, str]] = [
    (kw.lower(), category)
    for category, keywords in RELEVANCE_KEYWORDS.items()
    for kw in keywords
]

# ---------------------------------------------------------------------------
# Vendor blocklist — products this org does not run
# ---------------------------------------------------------------------------

VENDOR_BLOCKLIST: set[str] = {
    "citrix",
    "fortinet",
    "fortigate",
    "fortios",
    "sonicwall",
    "wordpress",
    "drupal",
    "joomla",
    "ivanti",
    "cisco asa",
    "cisco ios",
    "palo alto firewall",
    "pan-os",
    "siemens",
    "schneider electric",
    "rockwell",
    "honeywell",
    "abb",
    "moxa",
    "netgear",
    "tp-link",
    "d-link",
    "zyxel",
    "mikrotik",
    "qnap",
    "synology",
    "sap",
    "oracle fusion",
    "peoplesoft",
    "sharepoint",
    "exchange server",
    "magento",
    "woocommerce",
    "prestashop",
    "vmware horizon",
    "moveit",
    "progress moveit",
    "barracuda",
    "sophos utm",
    "watchguard",
    "juniper",
    "aruba",
    "f5 big-ip",
    "f5 big ip",
    "pulse secure",
    "atlassian confluence server",
}

# ---------------------------------------------------------------------------
# Blocklist overrides — cross-ecosystem terms that rescue an article
# ---------------------------------------------------------------------------

BLOCKLIST_OVERRIDES: set[str] = {
    "npm",
    "pypi",
    "supply chain",
    "supply-chain",
    "package",
    "dependency",
    "token leak",
    "credential",
    "github",
    "docker",
    "container image",
    "crates.io",
    "maven",
    "rubygems",
    "nuget",
    "pip",
    "go module",
    "backdoor",
}

# Pre-compile a regex for the vendor blocklist so we can check efficiently
_BLOCKLIST_RE = re.compile(
    "|".join(re.escape(v) for v in sorted(VENDOR_BLOCKLIST, key=len, reverse=True)),
    re.IGNORECASE,
)

_OVERRIDE_RE = re.compile(
    "|".join(re.escape(v) for v in sorted(BLOCKLIST_OVERRIDES, key=len, reverse=True)),
    re.IGNORECASE,
)


def filter_article(title: str, summary: str) -> tuple[bool, list[str]]:
    """Run the relevance filter on an article.

    Returns ``(passes, matched_keywords)`` where *passes* is True when the
    article should be kept for further processing.
    """
    text = f"{title} {summary}".lower()

    # Step 1 — keyword matching
    matched: list[str] = []
    for kw, category in _ALL_KEYWORDS:
        if kw in text:
            matched.append(kw)

    if not matched:
        logger.debug("Filtered out (no keyword match): %s", title[:80])
        return False, []

    # Step 2 — vendor blocklist
    blocklist_hit = _BLOCKLIST_RE.search(text)
    if blocklist_hit:
        # Step 3 — check override: does the article also mention something
        # cross-ecosystem relevant?
        override_hit = _OVERRIDE_RE.search(text)
        if not override_hit:
            logger.debug(
                "Filtered out (vendor blocklist '%s'): %s",
                blocklist_hit.group(),
                title[:80],
            )
            return False, matched
        logger.debug(
            "Blocklisted vendor '%s' overridden by '%s': %s",
            blocklist_hit.group(),
            override_hit.group(),
            title[:80],
        )

    return True, matched
