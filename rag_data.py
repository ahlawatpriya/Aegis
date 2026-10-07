"""Pre-computed mock data for the RAG system in demo mode.

All data is realistic but fabricated — no API keys or vector DB needed.
"""

# ---------------------------------------------------------------------------
# Chat responses — keyed by topic keyword
# ---------------------------------------------------------------------------

MOCK_CHAT_RESPONSES: dict[str, dict] = {
    "axios": {
        "answer": (
            "**Yes, we are affected by the axios npm compromise (CVE-2026-40112).**\n\n"
            "A compromised maintainer account was used to publish backdoored versions "
            "of the popular `axios` HTTP client. Versions **1.14.1** and **0.30.4** "
            "contain a cross-platform RAT.\n\n"
            "**Affected repos in our inventory:**\n"
            "- `checkout-service` — axios@1.14.1 (VULNERABLE, reachable)\n"
            "- `payments-web` — axios@1.14.1 (VULNERABLE, reachable)\n"
            "- `admin-portal` — axios@0.30.4 (VULNERABLE, not reachable)\n\n"
            "**37 other repos** use axios at non-vulnerable versions and are safe.\n\n"
            "**Recommended actions:**\n"
            "1. Immediately upgrade axios to >=1.14.2 in all three repos\n"
            "2. Rotate any credentials that may have been exfiltrated\n"
            "3. Run `npm audit` across all Node.js projects\n"
            "4. Review network logs for C2 beacon traffic from affected services"
        ),
        "sources": [
            {"type": "news", "title": "Axios npm Package Compromised — Hijacked Maintainer Account", "score": 0.96},
            {"type": "match", "title": "Match Result: axios affects 3 repos", "score": 0.94},
            {"type": "remediation", "title": "Remediation Guide: npm Package Compromise", "score": 0.91},
            {"type": "news", "title": "Socket.dev: Supply Chain Attack Detection", "score": 0.82},
        ],
        "context_used": [
            {"content": "Backdoored axios versions 1.14.1 and 0.30.4 contain a RAT...", "source_type": "news"},
            {"content": "checkout-service uses axios@1.14.1, payments-web uses axios@1.14.1...", "source_type": "match"},
        ],
    },
    "gpl": {
        "answer": (
            "**License compliance summary for GPL packages:**\n\n"
            "Based on the current SBOM inventory, we have **3 packages** with GPL-family licenses:\n\n"
            "- `readline` (npm) — GPL-3.0, used in `admin-portal`\n"
            "- `libgmp` (system) — LGPL-3.0, used in `crypto-service`\n"
            "- `ghostscript` (system) — AGPL-3.0, used in `pdf-renderer`\n\n"
            "**Risk assessment:**\n"
            "- `readline` is a dev dependency only — no distribution risk\n"
            "- `libgmp` is LGPL (weaker copyleft) — dynamic linking is generally safe\n"
            "- `ghostscript` AGPL requires source disclosure if exposed via network\n\n"
            "**Recommendation:** Review `pdf-renderer`'s deployment model. If it serves "
            "PDF rendering as a network service, AGPL obligations apply."
        ),
        "sources": [
            {"type": "sbom", "title": "SBOM License Scan Results", "score": 0.93},
            {"type": "remediation", "title": "GPL Compliance Guide", "score": 0.87},
        ],
        "context_used": [
            {"content": "License scan found 3 GPL-family packages...", "source_type": "sbom"},
        ],
    },
    "critical": {
        "answer": (
            "**Current critical vulnerabilities in our inventory:**\n\n"
            "1. **CVE-2026-40112** — axios@1.14.1 (npm)\n"
            "   - Severity: CRITICAL (CVSS 9.8)\n"
            "   - Type: Backdoored package (supply chain compromise)\n"
            "   - Affected repos: checkout-service, payments-web, admin-portal\n"
            "   - Status: **Active exploitation confirmed**\n\n"
            "2. **CVE-2025-33101** — jsonwebtoken@9.0.1 (npm)\n"
            "   - Severity: HIGH (CVSS 8.1)\n"
            "   - Type: JWT signature bypass\n"
            "   - Affected repos: auth-service, api-gateway\n"
            "   - Status: Public exploit available\n\n"
            "3. **CVE-2024-28863** — lodash@4.17.21 (npm)\n"
            "   - Severity: MEDIUM (CVSS 6.5)\n"
            "   - Type: Prototype pollution\n"
            "   - Affected repos: 12 repos\n"
            "   - Status: No known exploitation\n\n"
            "**Priority:** Address CVE-2026-40112 immediately (P0), then CVE-2025-33101 (P1)."
        ),
        "sources": [
            {"type": "news", "title": "Axios npm Package Compromised", "score": 0.95},
            {"type": "news", "title": "JWT Signature Bypass in jsonwebtoken", "score": 0.89},
            {"type": "match", "title": "Vulnerability Match Results Summary", "score": 0.88},
        ],
        "context_used": [
            {"content": "CVE-2026-40112: axios backdoor, CVSS 9.8...", "source_type": "news"},
            {"content": "CVE-2025-33101: JWT bypass, CVSS 8.1...", "source_type": "news"},
        ],
    },
    "remediation": {
        "answer": (
            "**Remediation plan for current vulnerabilities:**\n\n"
            "## P0 — axios compromise (CVE-2026-40112)\n"
            "1. **Upgrade immediately** in all 3 affected repos:\n"
            "   ```\n"
            "   cd checkout-service && npm install axios@1.14.2\n"
            "   cd payments-web && npm install axios@1.14.2\n"
            "   cd admin-portal && npm install axios@0.30.5\n"
            "   ```\n"
            "2. **Rotate credentials** — the RAT may have exfiltrated env vars\n"
            "3. **Run security audit:** `npm audit --production`\n"
            "4. **Check network logs** for outbound connections to known C2 IPs\n\n"
            "## P1 — jsonwebtoken bypass (CVE-2025-33101)\n"
            "1. Upgrade: `npm install jsonwebtoken@9.0.3`\n"
            "2. Review JWTs issued in the last 30 days for anomalies\n\n"
            "## P2 — lodash prototype pollution (CVE-2024-28863)\n"
            "1. Upgrade: `npm install lodash@4.17.22` across all repos\n"
            "2. Low urgency — no known exploit in the wild"
        ),
        "sources": [
            {"type": "remediation", "title": "npm Package Compromise Playbook", "score": 0.95},
            {"type": "match", "title": "Affected Repository Analysis", "score": 0.90},
            {"type": "news", "title": "Axios Compromise Technical Analysis", "score": 0.87},
        ],
        "context_used": [
            {"content": "Standard playbook for npm supply chain compromise...", "source_type": "remediation"},
        ],
    },
    "sbom": {
        "answer": (
            "**SBOM Inventory Summary:**\n\n"
            "We currently track **146 components** across **3 repositories**:\n\n"
            "| Repository | Components | Ecosystems |\n"
            "|------------|-----------|------------|\n"
            "| checkout-service | 87 | npm, golang |\n"
            "| payments-web | 42 | npm |\n"
            "| admin-portal | 17 | npm, pypi |\n\n"
            "**Ecosystem breakdown:**\n"
            "- npm: 112 packages (76.7%)\n"
            "- golang: 22 packages (15.1%)\n"
            "- pypi: 12 packages (8.2%)\n\n"
            "**License coverage:** 95.2% (139/146 resolved)\n"
            "**Last scan:** Today\n"
            "**Vulnerabilities:** 4 (1 Critical, 1 High, 1 Medium, 1 Low)"
        ),
        "sources": [
            {"type": "sbom", "title": "SBOM Scan: checkout-service", "score": 0.94},
            {"type": "sbom", "title": "SBOM Scan: payments-web", "score": 0.91},
            {"type": "sbom", "title": "SBOM Scan: admin-portal", "score": 0.88},
        ],
        "context_used": [
            {"content": "146 components across 3 repos, 4 vulnerabilities...", "source_type": "sbom"},
        ],
    },
    "kubernetes": {
        "answer": (
            "**Infrastructure vulnerabilities (not supply-chain):**\n\n"
            "Two recent advisories affect deployed infrastructure but are **not** "
            "supply-chain vulnerabilities (they don't appear in package managers):\n\n"
            "1. **Critical Grafana RCE** (CVE-2026-1234)\n"
            "   - Classification: `threat_intel` (deployed infra)\n"
            "   - Impact: 7/10\n"
            "   - Not in our SBOM — Grafana is deployed, not installed as a dependency\n\n"
            "2. **Kubernetes API Server SSRF** (CVE-2026-5678)\n"
            "   - Classification: `threat_intel`\n"
            "   - Impact: 6/10\n"
            "   - Affects k8s clusters, not application dependencies\n\n"
            "These are tracked as `threat_intel` in Aegis. The SBOM match engine "
            "does not process them because they aren't installable packages. "
            "Coordinate with the platform team for patching."
        ),
        "sources": [
            {"type": "news", "title": "Critical Grafana RCE Vulnerability", "score": 0.91},
            {"type": "news", "title": "Kubernetes API Server SSRF", "score": 0.88},
        ],
        "context_used": [
            {"content": "Grafana RCE classified as threat_intel, not supply_chain_vuln...", "source_type": "news"},
        ],
    },
    "default": {
        "answer": (
            "I don't have specific information about that in the current knowledge base. "
            "Here are some things I can help with:\n\n"
            "- **Vulnerability status:** \"Are we affected by the axios compromise?\"\n"
            "- **License compliance:** \"Do we have any GPL packages?\"\n"
            "- **SBOM inventory:** \"How many components do we track?\"\n"
            "- **Remediation steps:** \"What should we do about the axios issue?\"\n"
            "- **Critical vulns:** \"What are our critical vulnerabilities?\"\n"
            "- **Infrastructure:** \"What about the Kubernetes SSRF?\""
        ),
        "sources": [],
        "context_used": [],
    },
}


# ---------------------------------------------------------------------------
# Similar incidents — used by RAG-augmented enrichment
# ---------------------------------------------------------------------------

MOCK_SIMILAR_INCIDENTS: dict[str, list[dict]] = {
    "axios": [
        {
            "title": "event-stream npm compromise (2018)",
            "summary": (
                "The event-stream npm package was compromised when a new maintainer "
                "injected malicious code targeting the Copay Bitcoin wallet. The attack "
                "used flatmap-stream as a dependency to steal cryptocurrency. The "
                "compromised versions were 3.3.6. Resolution: package unpublished, "
                "maintainer credentials rotated."
            ),
            "relevance_score": 0.92,
            "resolution": "Package unpublished, affected versions yanked",
        },
        {
            "title": "ua-parser-js npm hijack (2021)",
            "summary": (
                "The ua-parser-js npm package (7M+ weekly downloads) was hijacked "
                "via a compromised maintainer account. Malicious versions 0.7.29, "
                "0.8.0, and 1.0.0 installed a cryptominer and password stealer. "
                "Resolution: versions unpublished within 4 hours, advisory issued."
            ),
            "relevance_score": 0.89,
            "resolution": "Malicious versions unpublished within 4 hours",
        },
    ],
    "reqeusts": [
        {
            "title": "python3-dateutil typosquat (2019)",
            "summary": (
                "A typosquat package 'python3-dateutil' mimicking the legitimate "
                "'python-dateutil' was uploaded to PyPI. It contained code to "
                "exfiltrate SSH and GPG keys. All versions were malicious from "
                "first publish. Resolution: package removed by PyPI admins."
            ),
            "relevance_score": 0.91,
            "resolution": "Package removed by PyPI admins",
        },
    ],
    "jsonwebtoken": [
        {
            "title": "jsonwebtoken signature bypass CVE-2022-23529 (2022)",
            "summary": (
                "A vulnerability in the jsonwebtoken library allowed attackers to "
                "bypass JWT signature verification by manipulating the secretOrPublicKey "
                "parameter. Affected versions < 9.0.0. Resolution: upgrade to >=9.0.0."
            ),
            "relevance_score": 0.85,
            "resolution": "Upgrade to jsonwebtoken >=9.0.0",
        },
    ],
}


# ---------------------------------------------------------------------------
# Remediation results — used by DemoRemediationEngine
# ---------------------------------------------------------------------------

MOCK_REMEDIATION_RESULTS: dict[str, dict] = {
    "axios": {
        "summary": (
            "Axios npm package compromised via maintainer account hijack. "
            "Versions 1.14.1 and 0.30.4 contain a cross-platform RAT. "
            "Immediate upgrade and credential rotation required."
        ),
        "priority": "P0",
        "steps": [
            {
                "description": "Upgrade axios to safe version in all affected repos",
                "commands": {
                    "checkout-service": "npm install axios@1.14.2 && npm audit",
                    "payments-web": "npm install axios@1.14.2 && npm audit",
                    "admin-portal": "npm install axios@0.30.5 && npm audit",
                },
                "explanation": (
                    "Versions 1.14.1 and 0.30.4 contain a RAT that beacons to a C2 server. "
                    "The safe versions (1.14.2, 0.30.5) were released after the compromise was discovered."
                ),
                "risk_level": "critical",
            },
            {
                "description": "Rotate all credentials and secrets in affected services",
                "commands": {
                    "checkout-service": "vault kv rotate secret/checkout-service/*",
                    "payments-web": "vault kv rotate secret/payments-web/*",
                },
                "explanation": (
                    "The RAT in the compromised axios versions exfiltrates environment variables. "
                    "All secrets accessible to affected services must be rotated."
                ),
                "risk_level": "critical",
            },
            {
                "description": "Audit network logs for C2 communication",
                "commands": {
                    "all": "grep -r 'cdn-analytics.xyz\\|telemetry-api.com' /var/log/nginx/",
                },
                "explanation": "Check for outbound connections to known C2 domains.",
                "risk_level": "high",
            },
            {
                "description": "Run comprehensive security audit",
                "commands": {
                    "all": "npm audit --production --audit-level=critical",
                },
                "explanation": "Ensure no other compromised packages exist in the dependency tree.",
                "risk_level": "medium",
            },
        ],
    },
    "reqeusts": {
        "summary": (
            "Typosquat package 'reqeusts' on PyPI exfiltrates environment variables. "
            "All versions are malicious. Remove immediately if found."
        ),
        "priority": "P0",
        "steps": [
            {
                "description": "Remove the typosquat package",
                "commands": {
                    "affected-repo": "pip uninstall reqeusts -y && pip install requests",
                },
                "explanation": "The package name 'reqeusts' is a typosquat of 'requests'.",
                "risk_level": "critical",
            },
            {
                "description": "Rotate all environment variables and secrets",
                "commands": {
                    "all": "vault kv rotate secret/*",
                },
                "explanation": "The typosquat exfiltrates all environment variables on install.",
                "risk_level": "critical",
            },
        ],
    },
    "jsonwebtoken": {
        "summary": (
            "JWT signature bypass vulnerability in jsonwebtoken <9.0.3. "
            "Upgrade to >=9.0.3 to fix."
        ),
        "priority": "P1",
        "steps": [
            {
                "description": "Upgrade jsonwebtoken to safe version",
                "commands": {
                    "auth-service": "npm install jsonwebtoken@9.0.3",
                    "api-gateway": "npm install jsonwebtoken@9.0.3",
                },
                "explanation": "Version 9.0.3 patches the signature bypass vulnerability.",
                "risk_level": "high",
            },
            {
                "description": "Review JWTs issued in the last 30 days",
                "commands": {
                    "auth-service": "node scripts/audit-jwt-signatures.js --since 30d",
                },
                "explanation": "Check for tokens that may have been forged using the bypass.",
                "risk_level": "medium",
            },
        ],
    },
}
