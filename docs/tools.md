# Tools

Every actionable tool the framework integrates, with a link to its upstream project. Runtime environments and backends (`bun`, `massdns`) are omitted; monitoring tools belong to the continuous layer, not a recon run.

> Generated from `src/quarry_recon/data/tools.yaml` by `scripts/gen_tool_index.py`. Do not edit by hand — edit the registry and regenerate.

Quarry is built on the work of the open-source security community. Thank you to the maintainers and contributors of every project listed here for publishing and sustaining the tools that make this framework possible. Each project remains the work of its respective authors.

Credential ownership and setup live in [secrets.md](secrets.md) and [external-integrations.md](external-integrations.md), not here.

## OSINT — apex / org / leak discovery

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `porch-pirate` | Searches public Postman workspaces for the target's exposed API endpoints and secrets. | optional | [WatchDogSecurity/porch-pirate](https://github.com/WatchDogSecurity/porch-pirate) |

## Horizontal — ASN / CIDR / cert / SAN

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `asnmap` | Maps an ASN to its announced CIDR ranges (scope context). | standard | [projectdiscovery/asnmap](https://github.com/projectdiscovery/asnmap) |
| `mapcidr` | Expands and condenses CIDR ranges to individual IPs. | standard | [projectdiscovery/mapcidr](https://github.com/projectdiscovery/mapcidr) |
| `tlsx` | Harvests TLS SAN/CN hostnames from IP ranges. | standard | [projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx) |
| `caduceus` | Scans ASN/CIDR ranges for live TLS certificates to recover hostnames behind a CDN. | optional | [g0ldencybersec/Caduceus](https://github.com/g0ldencybersec/Caduceus) |

## Vertical — subdomain discovery

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `shosubgo` | Discovers subdomains from Shodan. | optional | [incogbyte/shosubgo](https://github.com/incogbyte/shosubgo) |
| `subfinder` | Passive subdomain enumeration across many sources. | standard | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| `github-subdomains` | Finds subdomains referenced in public GitHub code. | optional | [gwen001/github-subdomains](https://github.com/gwen001/github-subdomains) |
| `puredns` | Brute-forces and validates DNS names (via the massdns backend). | standard | [d3mondev/puredns](https://github.com/d3mondev/puredns) |
| `alterx` | Generates subdomain permutations for resolution. | standard | [projectdiscovery/alterx](https://github.com/projectdiscovery/alterx) |
| `dnsgen` | Generates subdomain permutations (classic alternative to alterx). | optional | [AlephNullSK/dnsgen](https://github.com/AlephNullSK/dnsgen) |
| `dnsx` | Fast DNS resolver, PTR lookups, and record enrichment. | standard | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) |

## Probe — fingerprint / screenshots / ports

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `httpx` | Probes and fingerprints HTTP services and tags CDN vs origin. | standard | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| `cdncheck` | Classifies IPs as CDN / WAF / cloud, offline. | standard | [projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck) |
| `gowitness` | Captures screenshots of live web hosts. | standard | [sensepost/gowitness](https://github.com/sensepost/gowitness) |
| `naabu` | Fast SYN/CONNECT port scanner. | standard | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) |
| `nmap` | Service and version detection on discovered open ports. | optional | [nmap.org/book/output-formats-xml-output.html](https://nmap.org/book/output-formats-xml-output.html) |
| `smap` | Passive, Shodan-backed port scan — no packets to the target. | optional | [s0md3v/smap](https://github.com/s0md3v/smap) |

## Crawl — URL / archive / JS mining

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `jxscout-chunks` | Recovers lazy-loaded webpack chunk URLs from downloaded bundles. | optional | [francisconeves97/jxscout](https://github.com/francisconeves97/jxscout) |
| `jxscout-ast` | AST analysis of downloaded JavaScript for endpoints and sinks. | optional | [francisconeves97/jxscout](https://github.com/francisconeves97/jxscout) |
| `katana` | Crawls live hosts for URLs and JavaScript (standard and headless). | standard | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) |
| `gau` | Collects historical URLs from web archives. | standard | [lc/gau](https://github.com/lc/gau) |
| `waymore` | Fetches archived URLs and responses from web archives. | standard | [xnl-h4ck3r/waymore](https://github.com/xnl-h4ck3r/waymore) |
| `hakrawler` | Fast link spider (secondary crawler). | optional | [hakluke/hakrawler](https://github.com/hakluke/hakrawler) |
| `jsluice` | Extracts URLs and secrets from JavaScript. | standard | [BishopFox/jsluice](https://github.com/BishopFox/jsluice) |
| `xnLinkFinder` | Extracts links, parameters, and secrets from JavaScript and archived responses. | standard | [xnl-h4ck3r/xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) |
| `js-beautify` | Reformats minified JavaScript for extraction. | optional | [beautifier/js-beautify](https://github.com/beautifier/js-beautify) |
| `gitleaks` | Scans files for secrets. | standard | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| `trufflehog` | Detects secrets across a filesystem. | standard | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |

## Content discovery

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `ffuf` | Candidate-driven content and path discovery over live hosts. | standard | [ffuf/ffuf](https://github.com/ffuf/ffuf) |

## Params — lightweight scanning

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `gf` | Buckets URLs into vulnerability-class candidate queues by pattern. | optional | [tomnomnom/gf](https://github.com/tomnomnom/gf) |
| `arjun` | Discovers hidden request parameters on endpoints. | standard | [s0md3v/Arjun](https://github.com/s0md3v/Arjun) |
| `nuclei` | Template-based non-intrusive scanning with built-in out-of-band checks. | standard | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| `dalfox` | Reflected-XSS candidate scanning. | standard | [hahwul/dalfox](https://github.com/hahwul/dalfox) |

## Out-of-band interaction

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `interactsh-client` | Opens and polls Quarry's out-of-band callback session (public or configured Interactsh server). | standard | [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) |

## Monitoring — continuous layer (not part of a run)

| Tool | Quarry role | Class | Upstream |
|------|------|------|------|
| `gungnir` | Continuous CT-log monitoring for new certificates and subdomains. | optional | [g0ldencybersec/gungnir](https://github.com/g0ldencybersec/gungnir) |
