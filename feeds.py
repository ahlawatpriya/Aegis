"""RSS feed and API source definitions for the Aegis news ingestion pipeline."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    tier: int
    feed_type: str = "rss"


# Tier 1 — supply-chain first responders
# These outlets specifically hunt for compromised packages and typosquats.
TIER_1_FEEDS = [
    Feed("Socket.dev", "https://socket.dev/blog/feed", tier=1),
    Feed("StepSecurity", "https://www.stepsecurity.io/blog/rss.xml", tier=1),
    Feed("Aikido Security", "https://www.aikido.dev/blog/rss.xml", tier=1),
    Feed("GitGuardian", "https://blog.gitguardian.com/rss/", tier=1),
    Feed("Snyk", "https://snyk.io/blog/feed/", tier=1),
    Feed("Datadog Security Labs", "https://securitylabs.datadoghq.com/rss/feed.xml", tier=1),
]

# Tier 2 — deep analysis
# Slower but more thorough: full writeups, IOCs, root-cause analysis.
TIER_2_FEEDS = [
    Feed("Wiz", "https://www.wiz.io/blog/rss.xml", tier=2),
    Feed("Unit42", "https://unit42.paloaltonetworks.com/feed/", tier=2),
    Feed("Sonatype", "https://blog.sonatype.com/rss.xml", tier=2),
    Feed("CrowdStrike", "https://www.crowdstrike.com/blog/feed/", tier=2),
    Feed("Aqua Security", "https://blog.aquasec.com/rss.xml", tier=2),
    Feed("Semgrep", "https://semgrep.dev/blog/rss.xml", tier=2),
]

# Tier 3 — government / CVE
# Authoritative CVE disclosure feeds.
TIER_3_FEEDS = [
    Feed("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", tier=3),
    Feed("CISA News", "https://www.cisa.gov/news.xml", tier=3),
    Feed("CVE Feed", "https://cvefeed.io/rssfeed/latest.xml", tier=3),
    Feed("CVE Daily", "https://cvedaily.com/feed.xml", tier=3),
]

# Tier 4 — general security press
# Broad coverage, catches things the specialist feeds don't carry.
TIER_4_FEEDS = [
    Feed("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", tier=4),
    Feed("BleepingComputer", "https://www.bleepingcomputer.com/feed/", tier=4),
    Feed("HelpNetSecurity", "https://www.helpnetsecurity.com/feed/", tier=4),
    Feed("SecurityWeek", "https://feeds.feedburner.com/securityweek", tier=4),
]

ALL_FEEDS: list[Feed] = TIER_1_FEEDS + TIER_2_FEEDS + TIER_3_FEEDS + TIER_4_FEEDS


@dataclass(frozen=True)
class APISource:
    name: str
    url: str
    source_type: str


API_SOURCES = [
    APISource(
        name="NVD",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        source_type="nvd",
    ),
    APISource(
        name="CVE Crowd",
        url="https://api.cvecrowd.com/v1/cves/trending",
        source_type="cve_crowd",
    ),
]
