"""Demo orchestrator — simulates the full Aegis pipeline with realistic
terminal output.  Zero external dependencies required (no DB, no APIs, no CLI
tools).  Run with ``aegis demo`` or ``python -m aegis.demo.runner``."""

import time
from datetime import datetime, timezone

import click


# ── helper formatting ────────────────────────────────────────────────────────

class DemoRunner:

    def __init__(self, fast: bool = False) -> None:
        self._fast = fast

    def _header(self, text: str) -> None:
        width = 59
        click.echo()
        click.echo(click.style("=" * width, fg="bright_white", bold=True))
        for line in text.strip().splitlines():
            click.echo(click.style(f"  {line}", fg="bright_white", bold=True))
        click.echo(click.style("=" * width, fg="bright_white", bold=True))
        click.echo()

    def _step(self, text: str) -> None:
        click.echo(click.style(f"  {text}", fg="white"))

    def _ok(self, text: str) -> None:
        click.echo(click.style(f"  ✓ {text}", fg="green"))

    def _warn(self, text: str) -> None:
        click.echo(click.style(f"  ⚠ {text}", fg="yellow"))

    def _alert(self, text: str) -> None:
        click.echo(click.style(f"  🚨 {text}", fg="red", bold=True))

    def _info(self, text: str) -> None:
        click.echo(click.style(f"  ℹ {text}", fg="cyan"))

    def _detail(self, text: str) -> None:
        click.echo(click.style(f"        {text}", fg="bright_black"))

    def _pass_line(self, title: str, keywords: str) -> None:
        click.echo(
            click.style("        ✓ PASS  ", fg="green")
            + click.style(f'"{title}"', fg="white")
            + click.style(f"  [{keywords}]", fg="bright_black")
        )

    def _block_line(self, title: str, reason: str) -> None:
        click.echo(
            click.style("        ✗ BLOCK ", fg="red")
            + click.style(f'"{title}"', fg="white")
            + click.style(f"  [{reason}]", fg="bright_black")
        )

    def _pause(self, seconds: float = 0.8) -> None:
        if not self._fast:
            time.sleep(seconds)

    def _divider(self) -> None:
        click.echo()
        click.echo(click.style("  " + "─" * 55, fg="bright_black"))
        click.echo()

    def _box(self, lines: list[str]) -> None:
        width = 59
        click.echo(click.style(f"  ┌{'─' * width}┐", fg="cyan"))
        for line in lines:
            padded = line.ljust(width)[:width]
            click.echo(click.style("  │ ", fg="cyan") + padded + click.style(" │", fg="cyan"))
        click.echo(click.style(f"  └{'─' * width}┘", fg="cyan"))

    def _vuln_line(self, severity: str, pkg: str, desc: str) -> None:
        color = {
            "CRITICAL": "red",
            "HIGH": "yellow",
            "MEDIUM": "bright_yellow",
            "LOW": "bright_black",
        }.get(severity, "white")
        click.echo(
            click.style(f"        {severity:<10}", fg=color, bold=(severity == "CRITICAL"))
            + click.style(f"{pkg:<22}", fg="white")
            + click.style(f"— {desc}", fg="bright_black")
        )

    # ── SBOM pipeline demo ───────────────────────────────────────────────

    def run_sbom_demo(self) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        self._header("SIDE A: SBOM / SCA Pipeline\nScanning repository: checkout-service")

        # Step 1 — Cartograph
        self._step("[1/6] Running Cartograph scan (wraps syft)...")
        self._detail("Target: ./checkout-service")
        self._detail("Format: CycloneDX JSON")
        self._pause(1.0)
        self._ok("Cartograph found 142 components (0.8s)")
        click.echo()

        # Step 2 — Auditor
        self._step("[2/6] Running Auditor scan (wraps trivy)...")
        self._detail("Target: ./checkout-service")
        self._detail("Scanners: license")
        self._pause(1.2)
        self._ok("Auditor found 138 components with 96 licenses (1.2s)")
        click.echo()

        # Step 3 — Fuse
        self._step("[3/6] Fusing SBOMs (union by PURL)...")
        self._detail("Cartograph: 142 | Auditor: 138 | Overlap: 134")
        self._pause(0.4)
        self._ok("Merged SBOM: 146 unique components")
        click.echo()

        # Step 4 — Sentinel
        self._step("[4/6] Running Sentinel vulnerability scan (wraps grype)...")
        self._detail("Input: merged SBOM (146 components)")
        self._detail("Databases: NVD, GitHub Advisories, distro feeds")
        self._pause(1.5)
        self._ok("Found 4 vulnerabilities")
        self._vuln_line("CRITICAL", "axios@1.14.1", "Backdoored release (CVE-2026-40112)")
        self._vuln_line("HIGH", "jsonwebtoken@9.0.1", "JWT signature bypass (CVE-2025-33101)")
        self._vuln_line("MEDIUM", "lodash@4.17.21", "Prototype pollution (CVE-2024-28863)")
        self._vuln_line("LOW", "express@4.18.2", "Open redirect (CVE-2024-43796)")
        click.echo()

        # Step 5 — Licenser
        self._step("[5/6] Running Licenser enrichment...")
        self._pause(0.3)
        self._detail("Tier 1 — Pattern rules:     12 resolved")
        self._pause(0.3)
        self._detail("Tier 2 — deps.dev API:      118 resolved")
        self._pause(0.3)
        self._detail("Tier 3 — GitHub API:        9 resolved")
        self._pause(0.3)
        self._detail("Tier 4 — Unsupported:       7 remaining")
        self._ok("License coverage: 139/146 (95.2%)")
        click.echo()

        # Step 6 — Upload
        self._step("[6/6] Uploading results...")
        self._detail(f"→ S3: s3://aegis-sboms/checkout-service/{today}.json")
        self._detail("→ Postgres: 146 rows upserted to aegis_sbom")
        self._pause(0.6)
        self._ok("Upload complete")

        # Summary
        self._divider()
        click.echo(click.style("  ─── SBOM Scan Summary ──────────────────────────────", fg="bright_white", bold=True))
        click.echo(click.style("  Repository:       ", fg="bright_black") + click.style("checkout-service", fg="white"))
        click.echo(click.style("  Components:       ", fg="bright_black") + click.style("146", fg="white"))
        click.echo(
            click.style("  Vulnerabilities:  ", fg="bright_black")
            + click.style("4", fg="red", bold=True)
            + click.style(" (1 Critical, 1 High, 1 Medium, 1 Low)", fg="bright_black")
        )
        click.echo(click.style("  License coverage: ", fg="bright_black") + click.style("95.2%", fg="green"))
        click.echo()

    # ── News ingestion demo ──────────────────────────────────────────────

    def run_news_demo(self) -> None:
        self._header("SIDE B: News Ingestion Agent\nCycle starting...")

        # Step 1 — Fetch
        self._step("[1/7] Fetching 22 sources (20 RSS + 2 APIs)...")
        tiers = [
            ("Tier 1", ["Socket.dev", "StepSecurity", "Aikido", "GitGuardian", "Snyk", "Datadog"]),
            ("Tier 2", ["Wiz", "Unit42", "Sonatype", "CrowdStrike", "Aqua", "Semgrep"]),
            ("Tier 3", ["CISA Advisories", "CISA News", "cvefeed.io", "cvedaily.com"]),
            ("Tier 4", ["The Hacker News", "BleepingComputer", "HelpNetSecurity", "SecurityWeek"]),
        ]
        for tier_label, sources in tiers:
            marks = "  ".join(f"{s} ✓" for s in sources)
            self._detail(f"{tier_label}: {marks}")
            self._pause(0.3)
        self._detail("APIs:   NVD (critical, last 12h) ✓  CVE Crowd (trending) ✓")
        self._pause(0.5)
        self._ok("Fetched 8 new articles")
        click.echo()

        # Step 2 — Filter
        self._step("[2/7] Relevance filter (keywords + vendor blocklist)...")
        self._pause(0.3)
        self._pass_line("Axios npm Package Compromised...", "npm, compromised, hijacked")
        self._pass_line("Malicious PyPI Package 'reqeusts'...", "pypi, malicious package, typosquatting")
        self._pass_line("Critical Grafana RCE...", "critical, rce, cvss 9")
        self._pass_line("Kubernetes API Server SSRF...", "kubernetes, critical")
        self._pass_line("CISA Releases Updated SBOM Guidance...", "sbom")
        self._block_line("Critical Citrix ADC Vulnerability...", "vendor blocklist: citrix")
        self._block_line("FortiGate VPN Flaw Allows...", "vendor blocklist: fortinet")
        self._pass_line("npm Package axios Backdoored...", "npm, backdoor")
        self._pause(0.3)
        self._ok("After filter: 6 / 8 articles (2 blocked by vendor blocklist)")
        click.echo()

        # Step 3 — Dedup
        self._step("[3/7] Deduplication (3 phases)...")
        click.echo()
        self._detail("Phase 1 — Exact URL match:")
        self._detail("  6 candidates, 0 exact URL duplicates")
        self._pause(0.3)
        click.echo()
        self._detail("Phase 2 — Fuzzy title + CVE match:")
        self._detail('  "npm Package axios Backdoored..." ↔ "Axios npm Package Compromised..."')
        click.echo(
            click.style("        ", fg="bright_black")
            + click.style("  Jaccard similarity: 0.73", fg="yellow")
            + click.style(" (threshold: 0.70) → ", fg="bright_black")
            + click.style("DUPLICATE", fg="red", bold=True)
        )
        self._pause(0.4)
        click.echo()
        self._detail("Phase 3 — LLM semantic dedup + scoring:")
        self._detail("  Sending 5 candidates to Claude...")
        self._pause(1.2)
        self._detail("  All 5 are unique incidents. Scores: 9, 8, 7, 6, 3")
        self._pause(0.3)
        self._ok("After dedup: 5 / 6 articles (1 duplicate removed)")
        click.echo()

        # Step 4 — LLM enrichment
        self._step("[4/7] LLM enrichment via Claude...")
        click.echo()

        enrichments = [
            (
                "Axios npm Package Compromised...",
                "supply_chain_vuln",
                "axios (npm) versions 1.14.1,0.30.4",
                9,
                None,
            ),
            (
                "Malicious PyPI Package 'reqeusts'...",
                "supply_chain_vuln",
                'reqeusts (pypi) versions "all" (typosquat)',
                8,
                None,
            ),
            (
                "Critical Grafana RCE...",
                "threat_intel",
                None,
                7,
                "(deployed infra, not a dependency)",
            ),
            (
                "Kubernetes API Server SSRF...",
                "threat_intel",
                None,
                6,
                None,
            ),
            (
                "CISA Releases Updated SBOM Guidance...",
                "general_info",
                None,
                3,
                None,
            ),
        ]

        for title, cls, pkgs, score, note in enrichments:
            click.echo(click.style(f'        "{title}"', fg="white"))
            cls_color = {
                "supply_chain_vuln": "red",
                "threat_intel": "yellow",
                "general_info": "bright_black",
            }.get(cls, "white")
            cls_display = cls
            if note:
                cls_display += f"  {note}"
            click.echo(
                click.style("          → classification: ", fg="bright_black")
                + click.style(cls_display, fg=cls_color, bold=(cls == "supply_chain_vuln"))
            )
            if pkgs:
                click.echo(
                    click.style("          → packages: ", fg="bright_black")
                    + click.style(pkgs, fg="white")
                )
            click.echo(
                click.style("          → impact: ", fg="bright_black")
                + click.style(f"{score}/10", fg="white")
            )
            click.echo()
            self._pause(0.6)

        self._ok("Enriched: 5 articles (2 supply_chain_vuln, 2 threat_intel, 1 general_info)")
        click.echo()

        # Step 5 — Version recovery
        self._step("[5/7] Version recovery check...")
        self._detail('"reqeusts" has vulnerable_versions="all" — checking if typosquat...')
        self._pause(0.5)
        self._detail('Title contains "typosquat" → confirmed typosquat, "all" is valid')
        self._ok("No version recovery needed")
        click.echo()

        # Step 6 — DB insert
        self._step("[6/7] Inserting into database...")
        self._detail("→ aegis_news: 5 rows upserted")
        self._pause(0.4)
        self._ok("Database updated")
        click.echo()

        # Step 7 — Slack
        self._step("[7/7] Slack notifications...")
        self._pause(0.5)

        click.echo()
        self._box([
            click.style("🔴 Axios npm Package Compromised — Hijacked Maintainer", fg="red", bold=True),
            click.style("   Account Deploys Cross-Platform RAT", fg="red", bold=True),
            "",
            "A compromised maintainer account on npm was used to",
            "publish backdoored versions of the popular axios HTTP",
            "client. Versions 1.14.1 and 0.30.4 contain a RAT.",
            "",
            click.style("Source: ", fg="bright_black") + "Socket.dev"
            + click.style("  |  Type: ", fg="bright_black") + "supply_chain_vuln"
            + click.style("  |  Impact: ", fg="bright_black")
            + click.style("9/10", fg="red", bold=True),
            "",
            click.style("Affected packages:", fg="white", bold=True),
            "  • axios (npm) — versions: 1.14.1,0.30.4",
        ])
        click.echo()

        self._box([
            click.style("🟡 Malicious PyPI Package 'reqeusts' — Typosquat", fg="yellow", bold=True),
            "",
            "A typosquat package mimicking 'requests' was found on",
            "PyPI. The package exfiltrates environment variables on",
            "install. All versions are malicious.",
            "",
            click.style("Source: ", fg="bright_black") + "Snyk"
            + click.style("  |  Type: ", fg="bright_black") + "supply_chain_vuln"
            + click.style("  |  Impact: ", fg="bright_black")
            + click.style("8/10", fg="yellow", bold=True),
            "",
            click.style("Affected packages:", fg="white", bold=True),
            '  • reqeusts (pypi) — versions: all (typosquat)',
        ])
        click.echo()

        self._ok("Slack alerts posted (2 supply_chain_vuln, 2 threat_intel, 1 general_info)")
        click.echo()

    # ── Match engine demo ────────────────────────────────────────────────

    def run_match_demo(self) -> None:
        self._header("BRIDGE: Match Engine\nMatching supply_chain_vuln entries against SBOM inventory")

        # ── axios ──
        click.echo(click.style("  Processing: ", fg="white")
                   + click.style("axios", fg="white", bold=True)
                   + click.style(" (npm) — vulnerable versions: ", fg="bright_black")
                   + click.style("1.14.1,0.30.4", fg="red"))
        click.echo()

        self._step("[1/4] Exact PURL lookup (scoped to npm)...")
        self._detail("Query: SELECT * FROM aegis_sbom WHERE component_name='axios' AND ecosystem='npm'")
        self._pause(0.5)
        self._ok("Found 40 repos using axios")
        click.echo()

        self._step("[2/4] Version comparison...")
        self._pause(0.3)

        vuln_repos = [
            ("checkout-service", "1.14.1", True),
            ("payments-web", "1.14.1", True),
            ("admin-portal", "0.30.4", True),
            ("api-gateway", "1.7.3", False),
            ("user-service", "1.6.8", False),
        ]
        for repo, ver, is_vuln in vuln_repos:
            status = click.style("🚨 VULNERABLE", fg="red", bold=True) if is_vuln else click.style("✓ safe", fg="green")
            click.echo(
                click.style(f"        {repo:<20}", fg="white")
                + click.style(f"— axios@{ver:<10}", fg="bright_black")
                + click.style(" vs  1.14.1,0.30.4  → ", fg="bright_black")
                + status
            )
            self._pause(0.15)
        click.echo(click.style("        ... (35 more repos using safe versions)", fg="bright_black"))
        click.echo()

        self._step("[3/4] Posting results to Slack thread...")
        self._pause(0.6)
        click.echo()

        self._box([
            click.style("🚨 3 potentially vulnerable usages found:", fg="red", bold=True),
            "",
            "  • checkout-service  — axios@1.14.1",
            "  • payments-web      — axios@1.14.1",
            "  • admin-portal      — axios@0.30.4",
            "",
            "37 other repos use axios at non-vulnerable versions.",
            "",
            click.style("Spawning validation agent(s)...", fg="cyan"),
        ])
        click.echo()

        # ── reqeusts ──
        self._divider()
        click.echo(click.style("  Processing: ", fg="white")
                   + click.style("reqeusts", fg="white", bold=True)
                   + click.style(" (pypi) — vulnerable versions: ", fg="bright_black")
                   + click.style("all (typosquat)", fg="red"))
        click.echo()

        self._step("[1/4] Exact PURL lookup (scoped to pypi)...")
        self._pause(0.5)
        self._ok("Not found in any SBOM")
        click.echo()

        self._box([
            click.style("✅ Marked Safe", fg="green", bold=True)
            + " — reqeusts not found in any SBOM.",
            "No action needed.",
        ])
        click.echo()

    # ── Validator demo ───────────────────────────────────────────────────

    def run_validator_demo(self) -> None:
        self._header("VALIDATOR: Reachability Analysis\nSpawning ECS Fargate tasks for vulnerable repos")

        self._step("[4/4] Spawning validators (ECS Fargate)...")
        tasks = [
            ("checkout-service", "axios@1.14.1", "abc123"),
            ("payments-web", "axios@1.14.1", "def456"),
            ("admin-portal", "axios@0.30.4", "ghi789"),
        ]
        for repo, pkg, task_id in tasks:
            self._detail(f"Task: {repo:<20} ({pkg})  → arn:aws:ecs:us-east-1:123456:task/aegis/{task_id}")
            self._pause(0.2)
        click.echo()

        self._info("Running reachability analysis...")
        self._pause(2.0)
        click.echo()

        # Results
        click.echo(
            click.style("  🚨 ", fg="red")
            + click.style("checkout-service: ", fg="white", bold=True)
            + click.style("REACHABLE", fg="red", bold=True)
            + click.style(" — axios.post() called in src/api/payment.js:42", fg="bright_black")
        )
        click.echo(click.style("     → vulnerable code path is actively used", fg="red"))
        self._pause(0.5)
        click.echo()

        click.echo(
            click.style("  🚨 ", fg="red")
            + click.style("payments-web: ", fg="white", bold=True)
            + click.style("REACHABLE", fg="red", bold=True)
            + click.style(" — axios.get() called in src/hooks/useApi.ts:18", fg="bright_black")
        )
        click.echo(click.style("     → vulnerable code path is actively used", fg="red"))
        self._pause(0.5)
        click.echo()

        click.echo(
            click.style("  ✅ ", fg="green")
            + click.style("admin-portal: ", fg="white", bold=True)
            + click.style("NOT REACHABLE", fg="green", bold=True)
            + click.style(" — axios imported but not called in any code path", fg="bright_black")
        )
        click.echo(click.style("     → vulnerable module present but not exercised", fg="green"))
        click.echo()

        # Slack thread replies
        self._step("Posting validator results to Slack thread...")
        self._pause(0.5)
        click.echo()

        self._box([
            click.style("🚨 REACHABLE — vulnerable code path confirmed", fg="red", bold=True)
            + " for checkout-service",
            "   axios.post() called in src/api/payment.js:42",
            "",
            click.style("🚨 REACHABLE — vulnerable code path confirmed", fg="red", bold=True)
            + " for payments-web",
            "   axios.get() called in src/hooks/useApi.ts:18",
            "",
            click.style("✅ Not reachable", fg="green", bold=True)
            + " for admin-portal",
            "   Vulnerable module present but not exercised.",
        ])
        click.echo()

    # ── RAG / Ask Aegis demo ───────────────────────────────────────────

    def run_rag_demo(self) -> None:
        self._header("ASK AEGIS: RAG-Powered Security Chatbot")

        self._step("[1/4] Initializing knowledge base...")
        self._detail("Loading: news articles, SBOM inventory, match results, remediation guides")
        self._pause(0.6)
        self._ok("Knowledge base loaded (146 SBOM components, 5 news articles, 12 remediation guides)")
        click.echo()

        self._step('[2/4] Demo question: "Are we affected by the axios npm compromise?"')
        self._pause(0.5)
        self._detail("Searching vector store for relevant context...")
        self._pause(0.8)
        self._detail("Retrieved 4 sources:")
        self._detail("  [NEWS]        Axios npm Package Compromised (96% match)")
        self._detail("  [MATCH]       Match Result: axios affects 3 repos (94% match)")
        self._detail("  [REMEDIATION] npm Package Compromise Playbook (91% match)")
        self._detail("  [NEWS]        Socket.dev: Supply Chain Attack Detection (82% match)")
        self._pause(0.5)
        self._ok("Context retrieved — generating answer...")
        click.echo()

        self._step("[3/4] Streaming response...")
        self._pause(0.3)
        answer_lines = [
            "Yes, we are affected by the axios npm compromise (CVE-2026-40112).",
            "",
            "Affected repos in our inventory:",
            "  • checkout-service — axios@1.14.1 (VULNERABLE, reachable)",
            "  • payments-web    — axios@1.14.1 (VULNERABLE, reachable)",
            "  • admin-portal    — axios@0.30.4 (VULNERABLE, not reachable)",
            "",
            "37 other repos use axios at non-vulnerable versions and are safe.",
            "",
            "Recommended actions:",
            "  1. Immediately upgrade axios to >=1.14.2 in all three repos",
            "  2. Rotate any credentials that may have been exfiltrated",
            "  3. Run npm audit across all Node.js projects",
        ]
        for line in answer_lines:
            self._info(line)
            self._pause(0.05)
        click.echo()

        self._step("[4/4] RAG-augmented enrichment demo...")
        self._pause(0.5)
        self._detail("Finding similar past incidents for context...")
        self._pause(0.6)
        self._detail("  Similar: event-stream npm compromise (2018) — 92% relevance")
        self._detail("  Similar: ua-parser-js npm hijack (2021) — 89% relevance")
        self._ok("Historical context added to enrichment prompt")
        self._pause(0.5)
        self._detail("Generating remediation recommendations...")
        self._pause(0.8)

        self._box([
            click.style("Remediation: axios compromise (Priority: P0)", fg="cyan", bold=True),
            "",
            "  Step 1: Upgrade axios in all 3 affected repos",
            "    checkout-service: npm install axios@1.14.2",
            "    payments-web:     npm install axios@1.14.2",
            "    admin-portal:     npm install axios@0.30.5",
            "",
            "  Step 2: Rotate all credentials and secrets",
            "  Step 3: Audit network logs for C2 communication",
            "  Step 4: Run npm audit --production",
        ])
        click.echo()
        self._ok("Remediation plan generated")
        click.echo()

    # ── Full end-to-end demo ─────────────────────────────────────────────

    def run_full_demo(self) -> None:
        click.echo()
        click.echo(click.style("╔═══════════════════════════════════════════════════════════╗", fg="cyan", bold=True))
        click.echo(click.style("║                                                           ║", fg="cyan", bold=True))
        click.echo(click.style("║", fg="cyan", bold=True)
                   + click.style("        AEGIS — Supply Chain Risk Tracker              ", fg="bright_white", bold=True)
                   + click.style("║", fg="cyan", bold=True))
        click.echo(click.style("║", fg="cyan", bold=True)
                   + click.style("              Full Pipeline Demo                       ", fg="bright_black")
                   + click.style("║", fg="cyan", bold=True))
        click.echo(click.style("║                                                           ║", fg="cyan", bold=True))
        click.echo(click.style("╚═══════════════════════════════════════════════════════════╝", fg="cyan", bold=True))
        click.echo()

        click.echo(click.style("  This demo simulates a real-world supply-chain incident:", fg="white"))
        click.echo(click.style("  An axios npm package compromise flowing through the full", fg="white"))
        click.echo(click.style("  Aegis pipeline — from SBOM scan to Slack alert.", fg="white"))
        click.echo()
        click.echo(click.style("  No API keys, database, or external tools required.", fg="bright_black"))
        click.echo(click.style("  All data is realistic but simulated.", fg="bright_black"))
        click.echo()

        click.echo(click.style("  Pipeline stages:", fg="cyan"))
        click.echo(click.style("    1. SBOM/SCA Pipeline   — scan repos, find dependencies", fg="bright_black"))
        click.echo(click.style("    2. News Ingestion      — fetch, filter, dedup, enrich", fg="bright_black"))
        click.echo(click.style("    3. Match Engine        — cross-reference news × SBOM", fg="bright_black"))
        click.echo(click.style("    4. Validator           — reachability analysis", fg="bright_black"))
        click.echo(click.style("    5. Ask Aegis (RAG)     — chatbot, enrichment, remediation", fg="bright_black"))
        click.echo()

        self._pause(1.5)

        self.run_sbom_demo()
        self._pause(1.0)

        self.run_news_demo()
        self._pause(1.0)

        self.run_match_demo()
        self._pause(1.0)

        self.run_validator_demo()
        self._pause(1.0)

        self.run_rag_demo()

        # Wrap-up
        click.echo()
        click.echo(click.style("═" * 59, fg="cyan", bold=True))
        click.echo(click.style("  DEMO COMPLETE", fg="green", bold=True))
        click.echo(click.style("═" * 59, fg="cyan", bold=True))
        click.echo()
        click.echo(click.style("  End-to-end incident summary:", fg="white", bold=True))
        click.echo(click.style("  ────────────────────────────", fg="bright_black"))
        click.echo(
            click.style("  Incident:   ", fg="bright_black")
            + click.style("Axios npm package compromised (CVE-2026-40112)", fg="white")
        )
        click.echo(
            click.style("  Source:     ", fg="bright_black")
            + click.style("Socket.dev RSS → detected within 30 minutes", fg="white")
        )
        click.echo(
            click.style("  SBOM match: ", fg="bright_black")
            + click.style("40 repos scanned, ", fg="white")
            + click.style("3 vulnerable", fg="red", bold=True)
            + click.style(", 37 safe", fg="green")
        )
        click.echo(
            click.style("  Reachability:", fg="bright_black")
            + click.style(" 2 repos actively calling vulnerable code paths", fg="red")
        )
        click.echo(
            click.style("  RAG:        ", fg="bright_black")
            + click.style("Chatbot answered with 4 sources, remediation plan generated", fg="white")
        )
        click.echo(
            click.style("  Action:     ", fg="bright_black")
            + click.style("Slack alerts sent, validators confirmed blast radius", fg="white")
        )
        click.echo()
        click.echo(click.style("  The key insight: a threat-intel feed becomes valuable", fg="cyan"))
        click.echo(click.style("  exactly at the point it stops being about the world and", fg="cyan"))
        click.echo(click.style('  starts being about you — "does this actually affect', fg="cyan"))
        click.echo(click.style('  something I actually run?"', fg="cyan", bold=True))
        click.echo()


# ── Entry point ──────────────────────────────────────────────────────────

def run_demo(section: str = "full") -> None:
    """Entry point called by the CLI."""
    runner = DemoRunner()
    sections = {
        "full": runner.run_full_demo,
        "sbom": runner.run_sbom_demo,
        "news": runner.run_news_demo,
        "match": runner.run_match_demo,
        "validator": runner.run_validator_demo,
        "chat": runner.run_rag_demo,
    }
    fn = sections.get(section)
    if fn is None:
        click.secho(f"Unknown demo section: {section!r}. Choose from: {', '.join(sections)}", fg="red")
        raise SystemExit(1)
    fn()


if __name__ == "__main__":
    run_demo("full")
