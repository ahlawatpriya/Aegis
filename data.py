"""Realistic mock data for the Aegis demo mode.

All data is self-contained — no external dependencies, no API calls.
Uses real package names, version numbers, PURL format, and CVE identifiers
so the demo output looks indistinguishable from a live run.
"""

# ---------------------------------------------------------------------------
# 1. SBOM inventory — ~40 components across 3 repos
# ---------------------------------------------------------------------------

MOCK_SBOM_COMPONENTS: list[dict] = [
    # ── checkout-service (Node.js backend) ──────────────────────────────
    {"repo": "checkout-service", "component_name": "axios", "version": "1.14.1",
     "purl": "pkg:npm/axios@1.14.1", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "express", "version": "4.18.2",
     "purl": "pkg:npm/express@4.18.2", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "lodash", "version": "4.17.21",
     "purl": "pkg:npm/lodash@4.17.21", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "jsonwebtoken", "version": "9.0.1",
     "purl": "pkg:npm/jsonwebtoken@9.0.1", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "stripe", "version": "14.1.0",
     "purl": "pkg:npm/stripe@14.1.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "winston", "version": "3.11.0",
     "purl": "pkg:npm/winston@3.11.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "uuid", "version": "9.0.0",
     "purl": "pkg:npm/uuid@9.0.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "dotenv", "version": "16.3.1",
     "purl": "pkg:npm/dotenv@16.3.1", "ecosystem": "npm", "license": "BSD-2-Clause"},
    {"repo": "checkout-service", "component_name": "cors", "version": "2.8.5",
     "purl": "pkg:npm/cors@2.8.5", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "helmet", "version": "7.1.0",
     "purl": "pkg:npm/helmet@7.1.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "compression", "version": "1.7.4",
     "purl": "pkg:npm/compression@1.7.4", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "cookie-parser", "version": "1.4.6",
     "purl": "pkg:npm/cookie-parser@1.4.6", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "mongoose", "version": "8.0.0",
     "purl": "pkg:npm/mongoose@8.0.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "redis", "version": "4.6.12",
     "purl": "pkg:npm/redis@4.6.12", "ecosystem": "npm", "license": "MIT"},
    {"repo": "checkout-service", "component_name": "bull", "version": "4.12.0",
     "purl": "pkg:npm/bull@4.12.0", "ecosystem": "npm", "license": "MIT"},

    # ── payments-web (Next.js frontend) ─────────────────────────────────
    {"repo": "payments-web", "component_name": "axios", "version": "1.14.1",
     "purl": "pkg:npm/axios@1.14.1", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "react", "version": "18.2.0",
     "purl": "pkg:npm/react@18.2.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "next", "version": "14.0.4",
     "purl": "pkg:npm/next@14.0.4", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "typescript", "version": "5.3.3",
     "purl": "pkg:npm/typescript@5.3.3", "ecosystem": "npm", "license": "Apache-2.0"},
    {"repo": "payments-web", "component_name": "tailwindcss", "version": "3.4.0",
     "purl": "pkg:npm/tailwindcss@3.4.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "@stripe/stripe-js", "version": "2.3.0",
     "purl": "pkg:npm/%40stripe/stripe-js@2.3.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "swr", "version": "2.2.4",
     "purl": "pkg:npm/swr@2.2.4", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "zod", "version": "3.22.4",
     "purl": "pkg:npm/zod@3.22.4", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "zustand", "version": "4.4.7",
     "purl": "pkg:npm/zustand@4.4.7", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "date-fns", "version": "3.0.0",
     "purl": "pkg:npm/date-fns@3.0.0", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "framer-motion", "version": "10.16.16",
     "purl": "pkg:npm/framer-motion@10.16.16", "ecosystem": "npm", "license": "MIT"},
    {"repo": "payments-web", "component_name": "lucide-react", "version": "0.303.0",
     "purl": "pkg:npm/lucide-react@0.303.0", "ecosystem": "npm", "license": "ISC"},

    # ── admin-portal (Vue.js frontend) ──────────────────────────────────
    {"repo": "admin-portal", "component_name": "axios", "version": "0.30.4",
     "purl": "pkg:npm/axios@0.30.4", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "vue", "version": "3.4.5",
     "purl": "pkg:npm/vue@3.4.5", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "vite", "version": "5.0.10",
     "purl": "pkg:npm/vite@5.0.10", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "pinia", "version": "2.1.7",
     "purl": "pkg:npm/pinia@2.1.7", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "element-plus", "version": "2.4.4",
     "purl": "pkg:npm/element-plus@2.4.4", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "@vueuse/core", "version": "10.7.1",
     "purl": "pkg:npm/%40vueuse/core@10.7.1", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "dayjs", "version": "1.11.10",
     "purl": "pkg:npm/dayjs@1.11.10", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "chart.js", "version": "4.4.1",
     "purl": "pkg:npm/chart.js@4.4.1", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "papaparse", "version": "5.4.1",
     "purl": "pkg:npm/papaparse@5.4.1", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "xlsx", "version": "0.18.5",
     "purl": "pkg:npm/xlsx@0.18.5", "ecosystem": "npm", "license": "Apache-2.0"},
    {"repo": "admin-portal", "component_name": "socket.io-client", "version": "4.7.2",
     "purl": "pkg:npm/socket.io-client@4.7.2", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "sass", "version": "1.69.6",
     "purl": "pkg:npm/sass@1.69.6", "ecosystem": "npm", "license": "MIT"},
    {"repo": "admin-portal", "component_name": "vitest", "version": "1.1.0",
     "purl": "pkg:npm/vitest@1.1.0", "ecosystem": "npm", "license": "MIT"},
]

# ---------------------------------------------------------------------------
# 2. RSS articles — 8 items, mix of real incidents and noise
# ---------------------------------------------------------------------------

MOCK_RSS_ARTICLES: list[dict] = [
    {
        "title": "Axios npm Package Compromised — Hijacked Maintainer Account Deploys Cross-Platform RAT",
        "url": "https://socket.dev/blog/axios-npm-compromised-2026",
        "summary": (
            "Security researchers at Socket have identified a supply-chain compromise "
            "in the popular axios HTTP client for Node.js. An attacker gained access to "
            "the maintainer's npm account via a credential-stuffing attack and published "
            "two backdoored releases: versions 1.14.1 and 0.30.4. The malicious payload "
            "exfiltrates environment variables (including API keys and database credentials) "
            "to an attacker-controlled C2 server and installs a cross-platform remote access "
            "trojan. The legitimate maintainer has confirmed the compromise and revoked the "
            "affected versions. Users on 1.14.1 or 0.30.4 should upgrade immediately to "
            "1.14.2, which is a verified safe release."
        ),
        "published": "2026-08-29T08:15:00Z",
        "source": "Socket.dev",
    },
    {
        "title": "Malicious PyPI Package 'reqeusts' Discovered — Typosquat of Popular 'requests' Library",
        "url": "https://snyk.io/blog/malicious-pypi-reqeusts-typosquat",
        "summary": (
            "Snyk's security research team has discovered a typosquat package on PyPI "
            "named 'reqeusts' (note the transposed 'u' and 'e') impersonating the widely "
            "used 'requests' library. Every published version of 'reqeusts' contains a "
            "credential harvester that intercepts HTTP Basic Auth headers and POST body "
            "data, exfiltrating them to a Telegram bot. The package was first published "
            "three weeks ago and has accumulated approximately 4,200 downloads. PyPI has "
            "removed the package, but any environment that installed it remains compromised."
        ),
        "published": "2026-08-29T09:30:00Z",
        "source": "Snyk",
    },
    {
        "title": "Critical Grafana RCE Allows Unauthenticated Remote Code Execution (CVE-2026-34070)",
        "url": "https://unit42.paloaltonetworks.com/grafana-rce-cve-2026-34070/",
        "summary": (
            "Palo Alto Unit42 researchers have disclosed a critical unauthenticated "
            "remote code execution vulnerability in Grafana (CVE-2026-34070, CVSS 9.8). "
            "The flaw exists in the dashboard snapshot API and allows an attacker to "
            "execute arbitrary commands on the Grafana server without authentication. "
            "All versions prior to 10.3.1 and 9.5.16 are affected. Grafana Labs has "
            "released patched versions. Active exploitation has been observed in the wild."
        ),
        "published": "2026-08-29T10:00:00Z",
        "source": "Unit42 (Palo Alto)",
    },
    {
        "title": "Kubernetes API Server SSRF Vulnerability Enables Cluster Takeover (CVE-2026-28901)",
        "url": "https://www.cisa.gov/news-events/alerts/2026/08/29/kubernetes-ssrf-cve-2026-28901",
        "summary": (
            "CISA has issued an advisory for CVE-2026-28901, a server-side request "
            "forgery (SSRF) vulnerability in the Kubernetes API server. An authenticated "
            "attacker with minimal privileges can exploit the flaw to access internal "
            "cluster services, read secrets, and potentially escalate to full cluster admin. "
            "Kubernetes versions prior to 1.29.2, 1.28.7, and 1.27.11 are affected. "
            "Patches are available. CISA urges immediate update."
        ),
        "published": "2026-08-29T11:00:00Z",
        "source": "CISA Advisories",
    },
    {
        "title": "CISA Releases Updated Software Bill of Materials Guidance for Federal Agencies",
        "url": "https://www.cisa.gov/news-events/news/2026/08/29/sbom-guidance-update",
        "summary": (
            "The Cybersecurity and Infrastructure Security Agency (CISA) has published "
            "updated guidance on Software Bill of Materials (SBOM) practices for federal "
            "agencies. The new document expands minimum element requirements to include "
            "dependency-graph depth, license metadata, and build provenance attestation. "
            "The guidance aligns with the NTIA SBOM minimum elements and adds specific "
            "recommendations for CycloneDX and SPDX format usage."
        ),
        "published": "2026-08-29T12:00:00Z",
        "source": "CISA News",
    },
    {
        "title": "Critical Citrix ADC Vulnerability Being Actively Exploited in the Wild",
        "url": "https://www.bleepingcomputer.com/news/security/citrix-adc-vulnerability-exploited/",
        "summary": (
            "A critical vulnerability in Citrix ADC (NetScaler) gateway appliances is "
            "being actively exploited by threat actors. The flaw, tracked as CVE-2026-41928, "
            "allows unauthenticated remote code execution on affected appliances. Citrix has "
            "released hotfixes and urges all customers to patch immediately. Mandiant reports "
            "observing exploitation by at least two distinct threat groups."
        ),
        "published": "2026-08-29T13:00:00Z",
        "source": "BleepingComputer",
    },
    {
        "title": "FortiGate VPN Flaw Allows Credential Theft — Patch Immediately",
        "url": "https://www.helpnetsecurity.com/2026/08/29/fortigate-vpn-credential-theft/",
        "summary": (
            "A newly disclosed vulnerability in Fortinet's FortiGate VPN appliance allows "
            "an unauthenticated attacker to extract VPN session tokens and user credentials. "
            "The flaw (CVE-2026-38812) has a CVSS score of 8.6 and affects FortiOS versions "
            "7.4.x before 7.4.3. Fortinet has released an urgent patch."
        ),
        "published": "2026-08-29T14:00:00Z",
        "source": "HelpNetSecurity",
    },
    {
        "title": "npm Package axios Backdoored After Developer Account Hijack",
        "url": "https://thehackernews.com/2026/08/axios-npm-backdoor-developer-hijack.html",
        "summary": (
            "The popular npm package axios has been compromised following the hijacking "
            "of a maintainer's account. Versions 1.14.1 and 0.30.4 were found to contain "
            "a backdoor that sends environment variables to an external server. The incident "
            "highlights ongoing risks in the npm supply chain. Users should upgrade to the "
            "latest patched version immediately."
        ),
        "published": "2026-08-29T15:30:00Z",
        "source": "The Hacker News",
    },
]


# ---------------------------------------------------------------------------
# 3. Pre-built LLM enrichment results (keyed by article URL)
# ---------------------------------------------------------------------------

MOCK_ENRICHMENT_RESULTS: dict[str, dict] = {
    # Axios compromise → supply_chain_vuln
    "https://socket.dev/blog/axios-npm-compromised-2026": {
        "classification": "supply_chain_vuln",
        "summary": (
            "The axios npm package (versions 1.14.1 and 0.30.4) was compromised via a "
            "maintainer account hijack. The backdoored releases contain a credential "
            "exfiltration payload and a cross-platform RAT. Users should upgrade to 1.14.2."
        ),
        "impact_score": 9,
        "affected_packages": [
            {
                "name": "axios",
                "ecosystem": "npm",
                "vulnerable_versions": "1.14.1,0.30.4",
                "cve_id": None,
            }
        ],
    },
    # PyPI typosquat → supply_chain_vuln
    "https://snyk.io/blog/malicious-pypi-reqeusts-typosquat": {
        "classification": "supply_chain_vuln",
        "summary": (
            "A malicious PyPI package 'reqeusts' (typosquat of 'requests') contains "
            "a credential harvester that intercepts authentication headers. All versions "
            "are malicious — the package was created solely for this attack."
        ),
        "impact_score": 8,
        "affected_packages": [
            {
                "name": "reqeusts",
                "ecosystem": "pypi",
                "vulnerable_versions": "all",
                "cve_id": None,
            }
        ],
    },
    # Grafana RCE → threat_intel (deployed infra, not an npm dep)
    "https://unit42.paloaltonetworks.com/grafana-rce-cve-2026-34070/": {
        "classification": "threat_intel",
        "summary": (
            "Critical unauthenticated RCE in Grafana (CVE-2026-34070, CVSS 9.8) via the "
            "dashboard snapshot API. Affects all versions before 10.3.1 and 9.5.16. "
            "Active exploitation observed."
        ),
        "impact_score": 8,
        "affected_packages": [],
    },
    # Kubernetes SSRF → threat_intel
    "https://www.cisa.gov/news-events/alerts/2026/08/29/kubernetes-ssrf-cve-2026-28901": {
        "classification": "threat_intel",
        "summary": (
            "Kubernetes API server SSRF (CVE-2026-28901) allows authenticated attackers "
            "to access internal services and escalate to cluster admin. Affects K8s before "
            "1.29.2. Patches available."
        ),
        "impact_score": 7,
        "affected_packages": [],
    },
    # CISA SBOM guidance → general_info
    "https://www.cisa.gov/news-events/news/2026/08/29/sbom-guidance-update": {
        "classification": "general_info",
        "summary": (
            "CISA published updated SBOM guidance for federal agencies, expanding minimum "
            "element requirements to include dependency-graph depth, license metadata, and "
            "build provenance attestation."
        ),
        "impact_score": 3,
        "affected_packages": [],
    },
}


# ---------------------------------------------------------------------------
# 4. CycloneDX-shaped SBOM scan result for checkout-service
# ---------------------------------------------------------------------------

MOCK_SBOM_SCAN_RESULT: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "version": 1,
    "metadata": {
        "timestamp": "2026-08-29T08:00:00Z",
        "tools": [
            {"vendor": "anchore", "name": "syft", "version": "1.4.1"},
        ],
        "component": {
            "type": "application",
            "name": "checkout-service",
            "version": "2.14.0",
        },
    },
    "components": [
        {
            "type": "library",
            "name": "axios",
            "version": "1.14.1",
            "purl": "pkg:npm/axios@1.14.1",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "express",
            "version": "4.18.2",
            "purl": "pkg:npm/express@4.18.2",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "jsonwebtoken",
            "version": "9.0.1",
            "purl": "pkg:npm/jsonwebtoken@9.0.1",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "stripe",
            "version": "14.1.0",
            "purl": "pkg:npm/stripe@14.1.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "winston",
            "version": "3.11.0",
            "purl": "pkg:npm/winston@3.11.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "mongoose",
            "version": "8.0.0",
            "purl": "pkg:npm/mongoose@8.0.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "redis",
            "version": "4.6.12",
            "purl": "pkg:npm/redis@4.6.12",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "helmet",
            "version": "7.1.0",
            "purl": "pkg:npm/helmet@7.1.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "cors",
            "version": "2.8.5",
            "purl": "pkg:npm/cors@2.8.5",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "uuid",
            "version": "9.0.0",
            "purl": "pkg:npm/uuid@9.0.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "dotenv",
            "version": "16.3.1",
            "purl": "pkg:npm/dotenv@16.3.1",
            "licenses": [{"license": {"id": "BSD-2-Clause"}}],
        },
    ],
}


# ---------------------------------------------------------------------------
# 5. Grype-shaped vulnerability scan results
# ---------------------------------------------------------------------------

MOCK_VULNERABILITIES: list[dict] = [
    {
        "cve_id": "CVE-2026-40112",
        "severity": "Critical",
        "cvss_score": 9.8,
        "package_name": "axios",
        "package_version": "1.14.1",
        "fixed_versions": ["1.14.2"],
        "description": (
            "Backdoored release containing credential exfiltration payload and "
            "cross-platform remote access trojan. Maintainer account was compromised "
            "via credential stuffing."
        ),
        "data_source": "github-advisories",
    },
    {
        "cve_id": "CVE-2025-29927",
        "severity": "High",
        "cvss_score": 7.5,
        "package_name": "jsonwebtoken",
        "package_version": "9.0.1",
        "fixed_versions": ["9.0.2"],
        "description": (
            "Algorithm confusion vulnerability allows an attacker to forge JWT tokens "
            "when asymmetric key verification is used."
        ),
        "data_source": "nvd",
    },
    {
        "cve_id": "CVE-2024-48930",
        "severity": "Medium",
        "cvss_score": 5.3,
        "package_name": "express",
        "package_version": "4.18.2",
        "fixed_versions": ["4.18.3"],
        "description": (
            "Open redirect vulnerability in the res.redirect() method when user-controlled "
            "input is passed as the redirect URL."
        ),
        "data_source": "nvd",
    },
]


# ---------------------------------------------------------------------------
# 6. Match engine results — what the bridge would produce
# ---------------------------------------------------------------------------

MOCK_MATCH_RESULTS: dict = {
    "axios": {
        "status": "found_vulnerable",
        "name": "axios",
        "ecosystem": "npm",
        "vulnerable_versions": "1.14.1,0.30.4",
        "total_repos_using": 40,
        "safe_repos_count": 37,
        "vulnerable_repos": [
            {
                "repo": "checkout-service",
                "component_name": "axios",
                "version_in_use": "1.14.1",
                "purl": "pkg:npm/axios@1.14.1",
                "is_vulnerable": True,
            },
            {
                "repo": "payments-web",
                "component_name": "axios",
                "version_in_use": "1.14.1",
                "purl": "pkg:npm/axios@1.14.1",
                "is_vulnerable": True,
            },
            {
                "repo": "admin-portal",
                "component_name": "axios",
                "version_in_use": "0.30.4",
                "purl": "pkg:npm/axios@0.30.4",
                "is_vulnerable": True,
            },
        ],
        "safe_repos_sample": [
            {"repo": "docs-site", "version_in_use": "1.6.7"},
            {"repo": "internal-tools", "version_in_use": "1.7.2"},
            {"repo": "analytics-dashboard", "version_in_use": "1.7.2"},
            {"repo": "notification-svc", "version_in_use": "1.6.0"},
            {"repo": "user-service", "version_in_use": "1.7.2"},
        ],
    },
    "reqeusts": {
        "status": "not_found",
        "name": "reqeusts",
        "ecosystem": "pypi",
        "vulnerable_versions": "all",
        "total_repos_using": 0,
        "safe_repos_count": 0,
        "vulnerable_repos": [],
        "safe_repos_sample": [],
    },
}


# ---------------------------------------------------------------------------
# 7. Feed names for the fetch-phase display
# ---------------------------------------------------------------------------

DEMO_FEED_NAMES: list[dict] = [
    # Tier 1 — supply-chain first responders
    {"name": "Socket.dev", "tier": 1},
    {"name": "StepSecurity", "tier": 1},
    {"name": "Aikido Security", "tier": 1},
    {"name": "GitGuardian", "tier": 1},
    {"name": "Snyk", "tier": 1},
    {"name": "Datadog Security Labs", "tier": 1},
    # Tier 2 — deep analysis
    {"name": "Wiz", "tier": 2},
    {"name": "Unit42 (Palo Alto)", "tier": 2},
    {"name": "Sonatype", "tier": 2},
    {"name": "CrowdStrike", "tier": 2},
    {"name": "Aqua Security", "tier": 2},
    {"name": "Semgrep", "tier": 2},
    # Tier 3 — government / CVE
    {"name": "CISA Advisories", "tier": 3},
    {"name": "CISA News", "tier": 3},
    {"name": "cvefeed.io", "tier": 3},
    {"name": "cvedaily.com", "tier": 3},
    # Tier 4 — general security press
    {"name": "The Hacker News", "tier": 4},
    {"name": "BleepingComputer", "tier": 4},
    {"name": "HelpNetSecurity", "tier": 4},
    {"name": "SecurityWeek", "tier": 4},
    # APIs
    {"name": "NVD API (cves/2.0)", "tier": 0},
    {"name": "CVE Crowd API (trending)", "tier": 0},
]
