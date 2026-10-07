from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote

ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "pypi": "pypi",
    "pip": "pypi",
    "python": "pypi",
    "golang": "golang",
    "go": "golang",
    "maven": "maven",
    "java": "maven",
    "cargo": "cargo",
    "rust": "cargo",
    "rubygems": "gem",
    "gem": "gem",
    "ruby": "gem",
    "nuget": "nuget",
    "dotnet": "nuget",
    "csharp": "nuget",
    "composer": "composer",
    "php": "composer",
    "swift": "swift",
    "cocoapods": "cocoapods",
    "hex": "hex",
    "elixir": "hex",
    "pub": "pub",
    "dart": "pub",
    "hackage": "hackage",
    "haskell": "hackage",
    "cran": "cran",
    "r": "cran",
    "apk": "apk",
    "deb": "deb",
    "rpm": "rpm",
    "github": "github",
}

PURL_TYPE_TO_ECOSYSTEM: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "golang": "golang",
    "maven": "maven",
    "cargo": "cargo",
    "gem": "gem",
    "nuget": "nuget",
    "composer": "composer",
    "swift": "swift",
    "cocoapods": "cocoapods",
    "hex": "hex",
    "pub": "pub",
    "hackage": "hackage",
    "cran": "cran",
    "apk": "apk",
    "deb": "deb",
    "rpm": "rpm",
    "github": "github",
    "generic": "generic",
}


@dataclass(frozen=True)
class ParsedPURL:
    type: str
    namespace: str | None
    name: str
    version: str | None
    qualifiers: dict[str, str]
    subpath: str | None
    ecosystem: str

    @property
    def canonical(self) -> str:
        return build_purl(self.ecosystem, self.name, self.version or "", self.namespace)


def normalize_ecosystem(eco: str) -> str:
    return ECOSYSTEM_MAP.get(eco.lower().strip(), eco.lower().strip())


def parse_purl(purl_str: str) -> ParsedPURL:
    if not purl_str.startswith("pkg:"):
        raise ValueError(f"Invalid PURL (must start with 'pkg:'): {purl_str}")

    remainder = purl_str[4:]

    subpath: str | None = None
    if "#" in remainder:
        remainder, subpath = remainder.rsplit("#", 1)
        subpath = unquote(subpath)

    qualifiers: dict[str, str] = {}
    if "?" in remainder:
        remainder, qs = remainder.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[unquote(k)] = unquote(v)

    version: str | None = None
    if "@" in remainder:
        remainder, version = remainder.rsplit("@", 1)
        version = unquote(version)

    parts = remainder.split("/")
    purl_type = parts[0].lower()

    if len(parts) == 1:
        raise ValueError(f"Invalid PURL (no name segment): {purl_str}")

    namespace: str | None = None
    if len(parts) > 2:
        namespace = "/".join(unquote(p) for p in parts[1:-1])
        name = unquote(parts[-1])
    else:
        name = unquote(parts[1])

    if purl_type == "npm" and namespace:
        name = f"@{namespace}/{name}" if not namespace.startswith("@") else f"{namespace}/{name}"
        namespace = None

    ecosystem = PURL_TYPE_TO_ECOSYSTEM.get(purl_type, purl_type)

    return ParsedPURL(
        type=purl_type,
        namespace=namespace,
        name=name,
        version=version,
        qualifiers=qualifiers,
        subpath=subpath,
        ecosystem=ecosystem,
    )


def build_purl(ecosystem: str, name: str, version: str, namespace: str | None = None) -> str:
    eco_lower = normalize_ecosystem(ecosystem)
    purl_type = eco_lower

    for pt, mapped_eco in PURL_TYPE_TO_ECOSYSTEM.items():
        if mapped_eco == eco_lower:
            purl_type = pt
            break

    encoded_name: str
    ns_part = ""

    if purl_type == "npm" and name.startswith("@"):
        match = re.match(r"^(@[^/]+)/(.+)$", name)
        if match:
            ns_part = f"/{quote(match.group(1), safe='@')}"
            encoded_name = quote(match.group(2), safe="")
        else:
            encoded_name = quote(name, safe="@/")
    elif purl_type == "maven" and namespace:
        ns_part = f"/{quote(namespace, safe='.')}"
        encoded_name = quote(name, safe=".")
    elif purl_type == "golang":
        encoded_name = quote(name, safe="/.-_")
    else:
        if namespace:
            ns_part = f"/{quote(namespace, safe='.-_')}"
        encoded_name = quote(name, safe=".-_")

    version_part = f"@{quote(version, safe='.-_+')}" if version else ""

    return f"pkg:{purl_type}{ns_part}/{encoded_name}{version_part}"


def extract_name_and_ecosystem(purl_str: str) -> tuple[str, str]:
    parsed = parse_purl(purl_str)
    return parsed.name, parsed.ecosystem
