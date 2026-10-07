"""Static remediation knowledge base.

Contains expert-curated guides for common supply-chain vulnerability types.
Indexed into the vector store at startup / ingest time.
"""

REMEDIATION_GUIDES: list[dict] = [
    {
        "id": "guide:npm-supply-chain",
        "title": "NPM Supply-Chain Compromise Response",
        "vuln_type": "compromised_package",
        "ecosystem": "npm",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Pin the affected package to the last known-safe version in package.json.\n"
            "2. Run `npm cache clean --force` to purge cached malicious tarballs.\n"
            "3. Audit install scripts with `npm audit` and review postinstall hooks.\n"
            "4. Rotate any credentials, tokens, or API keys that may have been exfiltrated.\n"
            "5. Check for unexpected outbound network traffic in CI/CD and production.\n\n"
            "LONG-TERM:\n"
            "- Enable npm provenance checks (`npm audit signatures`).\n"
            "- Use a lockfile (`package-lock.json`) and review diffs in PRs.\n"
            "- Consider a private registry or proxy (Verdaccio, Artifactory) for critical deps.\n"
            "- Set up SBOM-based continuous monitoring with Aegis."
        ),
    },
    {
        "id": "guide:pypi-supply-chain",
        "title": "PyPI Supply-Chain Compromise Response",
        "vuln_type": "compromised_package",
        "ecosystem": "pypi",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Pin the affected package to a known-safe version in requirements.txt / pyproject.toml.\n"
            "2. Clear pip caches: `pip cache purge`.\n"
            "3. Review setup.py / pyproject.toml install hooks of the compromised version.\n"
            "4. Rotate credentials, especially PyPI tokens, cloud keys, and DB passwords.\n"
            "5. Scan CI runners and production hosts for persistence mechanisms.\n\n"
            "LONG-TERM:\n"
            "- Use hash-pinned requirements (`--require-hashes`).\n"
            "- Enable PEP 740 attestations where available.\n"
            "- Mirror critical packages to a private index.\n"
            "- Monitor with `pip audit` and Aegis SBOM matching."
        ),
    },
    {
        "id": "guide:cve-critical",
        "title": "Critical CVE Response Playbook",
        "vuln_type": "critical_vulnerability",
        "ecosystem": "*",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Confirm affected versions using the CVE advisory and your SBOM.\n"
            "2. Assess blast radius: which repos and deployments use the vulnerable version?\n"
            "3. Apply the vendor-recommended upgrade or patch.\n"
            "4. If no patch is available, apply mitigations (WAF rules, config changes, feature flags).\n"
            "5. Monitor exploit activity via Aegis news feed and threat intel sources.\n\n"
            "COMMUNICATION:\n"
            "- Notify the security team and affected service owners.\n"
            "- Update the incident tracker with timeline and remediation status.\n"
            "- Post an all-hands update if the CVE has public exploitation."
        ),
    },
    {
        "id": "guide:license-violation",
        "title": "License Compliance Violation Response",
        "vuln_type": "license_violation",
        "ecosystem": "*",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Identify all repos using the non-compliant package via Aegis SBOM scan.\n"
            "2. Assess license type: copyleft (GPL, AGPL) vs. permissive (MIT, Apache).\n"
            "3. For GPL in proprietary code: replace with a permissive-licensed alternative.\n"
            "4. For AGPL in a SaaS context: evaluate whether source disclosure is required.\n\n"
            "LONG-TERM:\n"
            "- Maintain an approved-licenses allowlist in CI.\n"
            "- Use `license-checker` (npm) or `pip-licenses` (Python) in pre-commit hooks.\n"
            "- Configure Aegis to flag new packages with restricted licenses."
        ),
    },
    {
        "id": "guide:container-vuln",
        "title": "Container Image Vulnerability Response",
        "vuln_type": "container_vulnerability",
        "ecosystem": "docker",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Identify the base image and vulnerable OS packages.\n"
            "2. Rebuild with an updated base image (e.g., `alpine:latest`, `ubuntu:22.04`).\n"
            "3. Run `docker scan` or `trivy image` to verify the fix.\n"
            "4. Re-deploy affected services with the patched image.\n\n"
            "LONG-TERM:\n"
            "- Use distroless or minimal base images.\n"
            "- Pin base image digests, not just tags.\n"
            "- Integrate image scanning into CI/CD with Aegis Auditor.\n"
            "- Set up auto-rebuild pipelines for base image updates."
        ),
    },
    {
        "id": "guide:dependency-confusion",
        "title": "Dependency Confusion Attack Response",
        "vuln_type": "dependency_confusion",
        "ecosystem": "*",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Check if internal package names have been squatted on public registries.\n"
            "2. Claim/reserve your internal package names on npm, PyPI, etc.\n"
            "3. Configure scoped registries (npm `@org/` scopes, pip `--index-url`).\n"
            "4. Audit recent installs for unexpected versions from public registries.\n\n"
            "LONG-TERM:\n"
            "- Use a private registry proxy that prioritizes internal packages.\n"
            "- Add `.npmrc` / `pip.conf` to all repos with explicit registry URLs.\n"
            "- Monitor for new public packages matching your internal naming."
        ),
    },
    {
        "id": "guide:typosquatting",
        "title": "Typosquatting Package Response",
        "vuln_type": "typosquatting",
        "ecosystem": "*",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Verify the correct canonical package name from official documentation.\n"
            "2. Remove the typosquat and install the legitimate package.\n"
            "3. Audit what the malicious package executed (install scripts, imports).\n"
            "4. Rotate any credentials the package could have accessed.\n\n"
            "DETECTION:\n"
            "- Compare package names against a known-good allowlist.\n"
            "- Flag new dependencies with Levenshtein distance < 2 from popular packages.\n"
            "- Use `npm audit` / `pip audit` — many typosquats get reported quickly."
        ),
    },
    {
        "id": "guide:credential-exposure",
        "title": "Credential Exposure in Dependencies",
        "vuln_type": "credential_exposure",
        "ecosystem": "*",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Rotate ALL exposed credentials immediately — tokens, passwords, API keys.\n"
            "2. Audit access logs for unauthorized usage during the exposure window.\n"
            "3. Remove hardcoded secrets; move to environment variables or a vault.\n"
            "4. Scan the repo history with `trufflehog` or `gitleaks`.\n\n"
            "LONG-TERM:\n"
            "- Enable pre-commit hooks for secret detection.\n"
            "- Use a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager).\n"
            "- Set up GitHub secret scanning alerts."
        ),
    },
    {
        "id": "guide:outdated-deps",
        "title": "Outdated Dependencies Remediation",
        "vuln_type": "outdated_dependency",
        "ecosystem": "*",
        "content": (
            "ASSESSMENT:\n"
            "1. Use Aegis SBOM to inventory all dependencies and their ages.\n"
            "2. Prioritize: EOL runtimes > 2+ major versions behind > minor lag.\n"
            "3. Check changelogs for breaking changes before upgrading.\n\n"
            "UPGRADE STRATEGY:\n"
            "- Update one major dependency at a time with full test suite.\n"
            "- Use `npm outdated`, `pip list --outdated`, or `go list -m -u all`.\n"
            "- Set up Dependabot / Renovate for automated PR-based updates.\n"
            "- Lock files should be committed and reviewed in PRs."
        ),
    },
    {
        "id": "guide:sbom-best-practices",
        "title": "SBOM Generation Best Practices",
        "vuln_type": "sbom_management",
        "ecosystem": "*",
        "content": (
            "GENERATION:\n"
            "- Generate SBOMs from lock files, not just manifests.\n"
            "- Include transitive dependencies (Aegis Cartograph does this by default).\n"
            "- Use CycloneDX format for maximum tool compatibility.\n"
            "- Generate at build time and store alongside artifacts.\n\n"
            "MAINTENANCE:\n"
            "- Re-scan on every PR merge and release.\n"
            "- Diff SBOMs between versions to catch unexpected additions.\n"
            "- Store historical SBOMs for audit trails.\n"
            "- Cross-reference SBOMs against the Aegis news feed continuously."
        ),
    },
    {
        "id": "guide:malicious-maintainer",
        "title": "Compromised Maintainer Account Response",
        "vuln_type": "compromised_maintainer",
        "ecosystem": "*",
        "content": (
            "IMMEDIATE ACTIONS:\n"
            "1. Identify which versions were published by the compromised account.\n"
            "2. Pin to the last version published before the compromise.\n"
            "3. Audit the diff between safe and suspicious versions for backdoors.\n"
            "4. Report to the registry (npm, PyPI) for removal.\n\n"
            "INDICATORS:\n"
            "- Unexpected new release with minimal changelog.\n"
            "- New install/postinstall scripts in the package.\n"
            "- Obfuscated code or base64-encoded payloads.\n"
            "- Network calls to unfamiliar domains in package code."
        ),
    },
    {
        "id": "guide:zero-day-response",
        "title": "Zero-Day Vulnerability Emergency Response",
        "vuln_type": "zero_day",
        "ecosystem": "*",
        "content": (
            "IMMEDIATE (within 1 hour):\n"
            "1. Aegis SBOM match to identify all affected deployments.\n"
            "2. If actively exploited: isolate affected services, enable WAF rules.\n"
            "3. Assess: is a patch available? If not, identify workarounds.\n\n"
            "SHORT-TERM (within 24 hours):\n"
            "4. Apply vendor patch or workaround across all affected repos.\n"
            "5. Verify fix with Aegis Auditor re-scan.\n"
            "6. Check for indicators of compromise in logs.\n\n"
            "COMMUNICATION:\n"
            "- Activate incident response process.\n"
            "- Brief leadership if customer data is at risk.\n"
            "- Prepare external comms if the service is public-facing."
        ),
    },
]
