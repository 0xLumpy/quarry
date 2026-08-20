#!/usr/bin/env python3
"""Render docs/tools.md from the tool registry (data/tools.yaml).

The tool index is a generated credit/reference page — do not hand-edit `docs/tools.md`.
Run `python scripts/gen_tool_index.py --write` to regenerate; `tests/test_tool_index.py`
fails if the committed page has drifted from the registry.

Runtime environments and pure dependencies are excluded (a tool with `dependency: true`,
plus `massdns`, which exists only as puredns's resolver backend). Everything else is an
actionable tool the framework integrates, and gets a row with its upstream link — the credit.

Role text is authored here, not copied from the registry, so the page reads as documentation
rather than operator shorthand.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "src" / "quarry_recon" / "data" / "tools.yaml"
PAGE = ROOT / "docs" / "tools.md"

#: not an actionable tool: puredns's built-from-source resolver backend, credited on puredns's row.
_EXCLUDE = {"massdns"}

#: phase order for the human-browsable grouping, with a heading per phase.
_PHASES = [
    ("osint", "OSINT — apex / org / leak discovery"),
    ("horizontal", "Horizontal — ASN / CIDR / cert / SAN"),
    ("vertical", "Vertical — subdomain discovery"),
    ("probe", "Probe — fingerprint / screenshots / ports"),
    ("crawl", "Crawl — URL / archive / JS mining"),
    ("content", "Content discovery"),
    ("params", "Params — lightweight scanning"),
    ("oob", "Out-of-band interaction"),
    ("monitor", "Monitoring — continuous layer (not part of a run)"),
]

#: documentation-grade one-line roles, authored here (present tense, no shorthand).
_ROLE = {
    "porch-pirate": "Searches public Postman workspaces for the target's exposed API endpoints and secrets.",
    "whois": "Queries domain registration records for passive ownership and contact context.",
    "dig": "Queries DNS records used by passive OSINT and scope corroboration.",
    "asnmap": "Maps an ASN to its announced CIDR ranges (scope context).",
    "mapcidr": "Expands and condenses CIDR ranges to individual IPs.",
    "tlsx": "Harvests TLS SAN/CN hostnames from IP ranges.",
    "caduceus": "Scans ASN/CIDR ranges for live TLS certificates to recover hostnames behind a CDN.",
    "shosubgo": "Discovers subdomains from Shodan.",
    "subfinder": "Passive subdomain enumeration across many sources.",
    "github-subdomains": "Finds subdomains referenced in public GitHub code.",
    "puredns": "Brute-forces and validates DNS names (via the massdns backend).",
    "alterx": "Generates subdomain permutations for resolution.",
    "dnsgen": "Generates subdomain permutations (classic alternative to alterx).",
    "dnsx": "Fast DNS resolver, PTR lookups, and record enrichment.",
    "httpx": ("Probes and fingerprints HTTP services and records CDN detector state; a negative is only "
              "a direct-service candidate, not origin proof."),
    "cdncheck": "Classifies IPs as CDN / WAF / cloud, offline.",
    "gowitness": "Captures screenshots of live web hosts.",
    "naabu": "Fast SYN/CONNECT port scanner.",
    "nmap": "Service and version detection on discovered open ports.",
    "katana": "Crawls live hosts for URLs and JavaScript (standard and headless).",
    "gau": "Collects historical URLs from web archives.",
    "waymore": "Fetches archived URLs and responses from web archives.",
    "hakrawler": "Fast link spider (secondary crawler).",
    "smap": "Passive, Shodan-backed port scan — no packets to the target.",
    "jsluice": "Extracts URLs and secrets from JavaScript.",
    "xnLinkFinder": "Extracts links, parameters, and secrets from JavaScript and archived responses.",
    "js-beautify": "Reformats minified JavaScript for extraction.",
    "gitleaks": "Scans files for secrets.",
    "trufflehog": "Detects secrets across a filesystem.",
    "jxscout-chunks": "Recovers lazy-loaded webpack chunk URLs from downloaded bundles.",
    "jxscout-ast": "AST analysis of downloaded JavaScript for endpoints and sinks.",
    "ffuf": "Candidate-driven content and path discovery over live hosts.",
    "gf": "Buckets URLs into vulnerability-class candidate queues by pattern.",
    "arjun": "Discovers hidden request parameters on endpoints.",
    "nuclei": "Broad active vulnerability verification with built-in out-of-band checks.",
    "dalfox": "Reflected-XSS candidate scanning.",
    "interactsh-client": "Opens and polls Quarry's out-of-band callback session (public or configured Interactsh server).",
    "gungnir": "Continuous CT-log monitoring for new certificates and subdomains.",
}


def _actionable(tool: dict) -> bool:
    return not tool.get("dependency") and tool.get("bin") not in _EXCLUDE


def _upstream(tool: dict) -> str:
    label = tool.get("repo") or tool["doc"].replace("https://", "").replace("github.com/", "").rstrip("/")
    return f"[{label}]({tool['doc']})"


def _row(tool: dict) -> str:
    bin_ = tool["bin"]
    cls = "optional" if tool.get("optional") else "standard"
    return f"| `{bin_}` | {_ROLE[bin_]} | {cls} | {_upstream(tool)} |"


def render() -> str:
    tools = [t for t in yaml.safe_load(REGISTRY.read_text())["tools"] if _actionable(t)]
    missing = [t["bin"] for t in tools if t["bin"] not in _ROLE]
    if missing:
        raise SystemExit(f"no authored role for {missing} — add to _ROLE in scripts/gen_tool_index.py")
    by_phase: dict[str, list] = {}
    for t in tools:
        by_phase.setdefault(t.get("phase", "other"), []).append(t)

    out = [
        "# Tools",
        "",
        "Every actionable tool the framework integrates, with a link to its upstream project. Runtime "
        "environments and backends (`bun`, `massdns`) are omitted; monitoring tools belong to the "
        "continuous layer, not a recon run.",
        "",
        "> Generated from `src/quarry_recon/data/tools.yaml` by `scripts/gen_tool_index.py`. Do not edit by "
        "hand — edit the registry and regenerate.",
        "",
        "Quarry is built on the work of the open-source security community. Thank you to the maintainers "
        "and contributors of every project listed here for publishing and sustaining the tools that make "
        "this framework possible. Each project remains the work of its respective authors.",
        "",
        "Credential ownership and setup live in [secrets.md](secrets.md) and "
        "[external-integrations.md](external-integrations.md), not here.",
        "",
    ]
    seen = set()
    for phase, title in _PHASES:
        rows = by_phase.get(phase)
        if not rows:
            continue
        out += [f"## {title}", "", "| Tool | Quarry role | Class | Upstream |", "|------|------|------|------|"]
        out += [_row(t) for t in rows]
        out.append("")
        seen.add(phase)
    leftover = sorted(set(by_phase) - seen)
    if leftover:
        raise SystemExit(f"tools.yaml has tools in unlisted phase(s) {leftover} — add them to _PHASES")
    return "\n".join(out).rstrip() + "\n"


def main(argv: list[str]) -> int:
    page = render()
    if "--write" in argv:
        PAGE.write_text(page)
        print(f"wrote {PAGE.relative_to(ROOT)} ({page.count(chr(10))} lines)")
    else:
        sys.stdout.write(page)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
