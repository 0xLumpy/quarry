# Target prep — manual OSINT to fill `target.yaml`

The framework automates the recon pipeline (subdomain discovery, probing, crawling, JS mining) from the
seeds you give it. On bigger targets, the high-value work it can't fully automate is the
**horizontal** seed-gathering: deciding *which apexes, IP ranges, and ASNs are in scope and
authorized*. That's judgment + OSINT.

This guide covers the scope **anchors** (`APEX_DOMAINS` / `OOS` / `CIDR` / `ASN`, plus `ORG_NAMES`, which
broadens OSINT, and `BRANDS`, which seeds active cloud-bucket discovery) and where to find them — not every profile field or
mode (the `target.yaml` comments and `example.md` cover those). Do as much or as little as the target
warrants — a single in-scope domain needs none of this; a wide program rewards all of it.

> **Scope discipline first.** Only add an apex/CIDR/ASN you have **confirmed is authorized and in
> program scope** — authorization is the gate, and an authorized asset need not be target-owned. `CIDR`
> enables *active* IP work (tlsx, Caduceus, and — with `MODES.PORTSCAN` — naabu→nmap); `ASN` is context
> only, never a scan trigger. Out-of-scope = out.

What the framework already does for you (so you don't have to do it by hand):
`kaeferjaeger` SNI dumps (local files), a native guarded CSP fetch, `subfinder` +
`crt.sh`/`certspotter`/Censys CT sources, `puredns` brute + `alterx` permutation, DNS-record enrichment,
Shodan favicon/cert pivots, and — if you provide `CIDR` — `tlsx`/`Caduceus`/reverse-DNS. The manual work
below produces the **seeds** those phases build on.

---

## What the `quarry osint` pre-flight automates (and the keys it needs)

Run **`quarry osint -t <project>`** *before* `quarry run`. It automates the parts of this
guide that *can* be scripted and writes `osint-report.md` + `target.suggested.yaml` (+ `candidates.jsonl`
/ `intel.jsonl`) to the project's `osint/latest/`. **It never edits scope** — everything it finds is a
candidate; you confirm and uncomment the good ones into `target.yaml` yourself, then run recon.

| Source | What it finds | API key? | Key location |
|--------|---------------|----------|--------------|
| **azmap.dev** M365 tenant | related/sibling apex domains | no | — |
| **whois** | registrant org/email (→ whoxy seed) | no | — |
| **DMARC** (`dig _dmarc`) | related apexes via `rua`/`ruf` (3rd-party processors flagged) | no | — |
| **whoxy** reverse-whois | sibling apexes by registrant email/org | **yes** | `secrets.yaml` → `whoxy:` |
| **CAIDA ASRank** | candidate ASNs from `ORG_NAMES` (graph search) | no | — |
| **RDAP** (rdap.org) | owning `CIDR` for each resolved apex IP | no | — |
| **asnmap** | prefixes for any `ASN` you already set | no* | `secrets.yaml` → `projectdiscovery:` |
| **porch-pirate** | public Postman endpoints/globals (intel, not scope) | no | — |
| (vertical) **github-subdomains** / **shosubgo** | github subdomains · shodan subdomains | **yes** | `secrets.yaml` → `github:` · `shodan:` |
| (vertical) **Censys** cert search | subdomains from `cert.names` | **yes** | `secrets.yaml` → `censys: {token, org}` |

Add these keys to `~/.config/quarry/secrets.yaml` and `quarry doctor` will show them as set. No key = most
sources are skipped and **recorded** (visible in the run). A few skip **silently** by design until
configured: Censys (needs both `token` **and** `org`), OpenINTEL, and `shosubgo` (missing binary or unset
`shodan:` key). *(asnmap uses the ProjectDiscovery/`chaos` key if present, but runs without it.)*

**Still manual** (no good automation — judgment/login/paywall; do these by hand, then add to
the profile): bgp.he.net free-form ASN search, ARIN/RIPE full-text, Crunchbase/Tracxn/Pitchbook/OCCRP
acquisitions, builtwith ad/analytics relationships, merklemap CT search. Everything below covers those —
ASRank/RDAP/asnmap give you a first pass, these go deeper.

---

## `APEX_DOMAINS` — every authorized in-scope apex

The most important field. Each apex multiplies the whole pipeline. Sources, in rough priority:

**1. Program scope / brief.** Start with what's explicitly in scope. Note wildcard vs exact.

**2. Microsoft 365 / Azure tenant → domains.** If the org uses M365, the tenant lists all
verified domains:
```
https://azmap.dev/api/tenant?domain=<DOMAIN>&extract=true
```
- also: https://micahvandeusen.com/tools/tenant-domains/ (web) and
  `github.com/TheArqsz/tenant-domains` (automated)
- `osint.aadinternals.com` needs a work MS account
- (check `email_domains` in the response — those are extra apexes)

**3. Reverse WHOIS — domains by the same registrant.**
- GUI: https://www.whoxy.com (search by org name or registrant email)
- API: `curl 'https://api.whoxy.com/?key=APIKEY&reverse=whois&email=<EMAIL>'`
- `github.com/awerqo/whoxy` handles whoxy's inflated page counts so you don't burn credits
- run discovered domains through `httpx` to see what's live before adding

**4. Acquisitions & subsidiaries → new apexes.** Folded-in IT often keeps legacy infra:
- https://www.crunchbase.com — acquisitions tab
- https://tracxn.com — more detail than Crunchbase (can replace it)
- https://pitchbook.com/profiles — subsidiaries (some free)
- https://aleph.occrp.org — search the target, find the **"US SEC CorpWatch"** entry
- https://sec-api.io — subsidiary API (US public companies only)
- EU equivalent: https://www.bundesanzeiger.de (Germany) or national registry
- ongoing: Google Alerts for `"<Target> acquires"` / `"<Target> acquisition"`

**5. Cloud-certificate recon → apexes + internal names.** (Also auto-run by the framework,
but manual passes find more on big orgs.)
- kaeferjaeger weekly cloud cert dumps: https://kaeferjaeger.gay/?dir=sni-ip-ranges — grep your name:
  ```bash
  cat *.txt | grep -F ".target.com" | awk -F'-- ' '{print $2}' \
    | tr ' ' '\n' | tr '[' ' ' | sed 's/ //' | sed 's/\]//' \
    | grep -F ".target.com" | sort -u
  ```
- Caduceus (ASN/CIDR → live cert scan): `github.com/g0ldencybersec/Caduceus`
- https://www.merklemap.com (CT search engine; has a CLI + live-domains API)
- https://platform.censys.io (Censys Platform cert search — the framework can query this in the
  vertical phase; set `censys: {token, org}` in `secrets.yaml`, advanced/optional)

**6. DMARC, reverse-IP, ad/analytics, CSP.**
- DMARC shared records: https://dmarcly.com/tools/dmarc-checker + `github.com/Tedixx/dmarc-subdomains`
- reverse IP / virtual hosts: https://host.io/<domain>
- ad/analytics relationships (shared GA/NewRelic codes): https://builtwith.com → **Relationships** tab
- CSP `connect-src`/`script-src` domains: `csprecon` (the framework does its own guarded CSP fetch in horizontal — this is for manual OSINT)

**7. Dorks.**
- `"© <YEAR> <Company Name>" inurl:<target>` — related hosts by copyright string
- `"Help us get an idea of what this vulnerability is about"` — finds embedded private programs

**Put it in the profile:**
```yaml
APEX_DOMAINS:
  - target.com
  - target.net
  - acquired-brand.com      # from acquisitions
  - target-cloud.com        # from cert recon
```

---

## `OOS` — out-of-scope patterns

From the program brief's exclusions. These are matched against the full canonical host using Quarry's
bounded pattern grammar: literals, `.`, character classes, edge anchors, and at most one single-atom
`*`, `+`, or `?` repetition. Groups, alternation, lookaround, backreferences, counted repetition, and
nested repetition are refused when the profile is loaded. The framework still retains matching names
passively, but the scope planner makes them ineligible for active work. The separate connect-time
boundary must prove that the actual peer honors that decision.

```yaml
OOS:
  - '^jobs\.'                       # exclude jobs.* / careers.*
  - '^careers\.'
  - 'reverse\.target-cloud\.com'    # a specific OOS host
  - '\.partner\.target\.com$'       # an OOS branch
```

Tip: prefer anchored, specific patterns. `quarry oos` validates the same grammar as the profile loader
before writing, so an unsupported imported pattern must be migrated to exact/suffix/glob-style rules.

---

## `CIDR` — in-scope authorized IP ranges

Only worth it when the target **has its own IP space** (large orgs, not SaaS-hosted small targets).
Setting `CIDR` turns on tlsx SAN harvest, Caduceus cert scan, and reverse DNS; the naabu→nmap infra
portscan additionally needs `MODES.PORTSCAN: true` (both gates, so CIDR alone never sends a portscan).

**Find the ranges:**
- https://bgp.he.net — search the org name. Also try a **free-form description search** of
  the org name; it can surface ranges the name search misses.
- https://asrank.caida.org — pivot to related ASNs (go 2-3 levels deep).
- **Registrars** (full-text search for the org):
  - US: https://whois.arin.net/ui/query.do
  - EU / Central Asia: https://apps.db.ripe.net/db-web-ui/#/fulltextsearch
- **Real CIDR owner** for a given IP (not just a /24 guess):
  `https://search.arin.net/rdap/?query=<ip>`
- Cross-check bgp.he.net against https://dnschecker.org and expand ranges.
- From a confirmed ASN: `echo AS<NUMBER> | asnmap -silent` prints its prefixes.

```yaml
CIDR:
  - 55.55.0.0/16
  - 203.0.113.0/24
```

> Empty `CIDR` is fine and common — horizontal IP steps just skip. Only fill it with ranges
> you've verified are **authorized and in scope**.

---

## `ASN` — manual ASN seeds

Confirmed, authorized Autonomous System Numbers (ownership is a lead; authorization is the gate).

- https://bgp.he.net — org name → ASN(s)
- https://asrank.caida.org — related ASNs

The framework treats `ASN` as seeds: `quarry osint` expands them to `CIDR` candidates via `asnmap`, and
the horizontal phase records ASN context. Active range scanning happens **only** for `CIDR` you
explicitly list — an `ASN` alone never triggers a scan. Leave empty to have ASN candidates only
suggested for review (ASRank finds them from `ORG_NAMES`).

```yaml
ASN:
  - AS12345
  - AS67890
```

---

## Related companies / acquisitions

There is **no separate field** — acquisitions and subsidiaries become **new
`APEX_DOMAINS`** (and sometimes new `ASN`/`CIDR` if the acquired entity runs its own infra).
Use the §4 sources above. Keep a side-note in `NOTES:` of which apexes came from which parent
so scope decisions stay auditable.

```yaml
NOTES:
  - acquired-brand.com via Crunchbase (2024 acquisition)
  - target-cloud.com via kaeferjaeger cert grep
```

---

## Cloud ranges

For cert-based apex/host discovery on cloud-hosted targets. Mostly feeds the **cert recon**
step (§5) rather than a profile field directly — but an authorized in-scope cloud block can go in
`CIDR`.

- all major cloud provider ranges: `github.com/lord-alfred/ipranges` → `all/ipv4_merged.txt`
- AWS active EC2 ranges: http://ec2-reachability.amazonaws.com/
- kaeferjaeger SNI dumps (weekly, per provider) — the framework greps these automatically
- feed owned ASN ranges into **Caduceus** for a targeted cert scan

---

## The recursive chain (do this on big targets)

Horizontal discovery feeds itself. Each new apex can have its own ASN/ranges:

```
ASN lookup (bgp.he.net) ─▶ IP ranges (asnmap / RDAP)
        │                        │
        ▼                        ▼
   asrank related ASNs      Caduceus / kaeferjaeger cert scan
        │                        │
        └──────────┬─────────────┘
                   ▼
            new APEX domains  ──▶ back into APEX_DOMAINS
                   │
                   ▼
        subfinder / httpx (the framework takes over here)
```

Loop until no new in-scope apexes/ranges appear. Then hand the seeds to the framework.

---

## Worked example (wide target)

```yaml
TARGET: acme

APEX_DOMAINS:        # 1 from scope + 2 from reverse-whois + 1 acquisition + 1 cert-recon
  - acme.com
  - acme.net
  - acme-labs.com
  - boughtco.io
  - acmecloud.dev

OOS:
  - '^status\.'
  - 'sandbox\.acme\.com$'

CIDR:                # confirmed via bgp.he.net + RDAP owner check
  - 198.51.100.0/24

ASN:                 # confirmed on bgp.he.net
  - AS64500

RATELIMIT:
  HTTP:          # empty => tool defaults (fast); set only for a program's RoE cap

PORTS:
  HTTP:              # blank → full methodology port set

MODES:
  PASSIVE_ONLY: false
  SCREENSHOTS: true
  PORTSCAN: true       # opt-in for the infra CIDR→nmap scan (default false); needs CIDR set.
                       # The web-port SYN prefilter is a separate active-recon step (naabu-based; runs
                       # when naabu + eligible IPs are present, else httpx probes directly).
  TAKEOVER: true

NOTES:
  - boughtco.io via Crunchbase acquisition 2023
  - acmecloud.dev via kaeferjaeger cert grep
  - AS64500 / 198.51.100.0/24 authorized + in scope (ownership confirmed via RDAP)
```

Then:

```bash
quarry run -t acme
```

With `CIDR`/`ASN` set, the horizontal phase now also runs `mapcidr`, `tlsx` SAN harvest,
reverse DNS, and `Caduceus` cert scan on the authorized in-scope ranges — surfacing hosts no passive source
would find. See `example.md` for the full command-by-command trace of a run.

---

## Quick source map

| Profile field | Primary sources |
|---------------|-----------------|
| `APEX_DOMAINS` | scope · azmap.dev / tenant-domains (M365) · whoxy reverse-whois · crunchbase/tracxn/pitchbook/OCCRP/sec-api (acquisitions) · kaeferjaeger/Caduceus/merklemap (certs) · builtwith relationships · csprecon · dorks |
| `OOS` | program brief exclusions |
| `CIDR` | bgp.he.net · asrank.caida.org · ARIN/RIPE full-text · RDAP owner check · `asnmap` |
| `ASN` | bgp.he.net · asrank.caida.org |
| acquisitions → apexes | crunchbase · tracxn · pitchbook · OCCRP Aleph · sec-api.io · bundesanzeiger · Google Alerts |
| cloud ranges | lord-alfred/ipranges · ec2-reachability · kaeferjaeger · Caduceus |

All of this is optional. The minimum viable profile is one in-scope `APEX_DOMAINS` entry —
the framework does the rest.
