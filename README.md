# Quarry

**Methodology-driven reconnaissance automation.** A single CLI (`quarry`) that automates a
deep-recon methodology end-to-end on your own tool pipeline — deploy to a blank VPS, point it
at a scope, get back ranked, traceable, manual-validation queues.

The goal is **not** to wrap an existing recon framework or stitch together shell snippets. It
turns a proven manual recon workflow into one repeatable framework that explains what it did,
what it found, what failed, and what needs a human next.

The one failure mode it exists to kill is **silent thin output** — a recon run that returns
very little and gives no useful reason why. Every result is:

- **traceable** — each normalized entity links back to the raw evidence that produced it
- **explainable** — every tool run is classified `success / empty / partial / blocked / timed-out / failed / skipped`
- **rerunnable** — structured JSONL is the source of truth; flat files are disposable exports
- **scope-safe** — fixed to your `APEX_DOMAINS`; active phases obey your rate limit; `--passive` blocks all probing

## Status

`v0.2` (stabilization) — command surface, installer, OSINT pre-flight, recon run, structured
JSONL store, exports, reports, and checkpointing are wired and verified. Next milestone: prove
the install + OSINT + full run on a clean Ubuntu VPS, then the v0.3 resume/checkpoint layer.
See `notes/ROADMAP.md`.

## Safety and scope

Built for **authorized reconnaissance only**. It does not autonomously exploit. It **maps**
where a human should look harder:

- subdomain-takeover candidates · likely-origin (non-CDN/WAF) hosts
- auth / API / admin / upload / file / export surfaces
- IDOR / SSRF / SQLi / XSS / redirect / SSTI parameter queues
- source-map candidates · JavaScript endpoints and secrets
- scanner candidates — always marked **unconfirmed**

Scope stays fixed: horizontal findings on owned IP space are recorded as review candidates,
never auto-pivoted to new roots. BAC/IDOR object swaps, WAF bypasses, and the manual Burp
testing of methodology Phase 9 remain human work.

## Install

Blank VPS → fully provisioned in one command:

```bash
cd quarry
./install.sh          # pipx-installs quarry, then `quarry install` provisions everything else
quarry doctor           # audit tools, versions, deps, keys, wordlists
```

Common commands:

```bash
quarry install                # full provision (idempotent)
quarry install --dry-run      # preview the whole plan, change nothing
quarry install --tools-only   # skip system pkgs / Go / data files
quarry install --only httpx   # a single tool
quarry install --phase vertical
quarry update                 # refresh tools + nuclei templates + resolvers
```

`quarry install` owns the whole lifecycle and runs five stages:

1. **system packages** — OS-detected (apt/dnf/pacman/brew): build toolchain, `libpcap-dev`,
   chromium + headless libs, `libxml2/xslt`, `nmap`, `pipx`, … (per-tool deps merged in)
2. **Go toolchain** — installs current Go to `/usr/local/go` if missing **or too old**
3. **tools** — every binary in the registry (Go install / pipx / massdns from source).
   Tools already on `PATH` are recorded as external and left untouched
4. **data files** — trickest resolvers + n0kovo 3M DNS wordlist → `~/.config/quarry/`
5. **extras** — gf patterns (`~/.gf`), nuclei templates

Anything that can't be automated (no sudo, unsupported OS, API-key/login-gated tools) is
reported with its doc link — never silently skipped.

## API keys

Never stored in profiles. Configure each tool where it expects them (`quarry doctor` prints
the path for every key-needing tool):

| Tool | Location | Keys |
|------|----------|------|
| subfinder | `~/.config/subfinder/provider-config.yaml` | chaos, github, shodan, securitytrails, netlas, c99, dnsdumpster |
| waymore | `~/.config/waymore/config.yml` | URLScan, VirusTotal |
| github-subdomains | `~/.config/quarry/github-tokens.txt` | GitHub PATs (use burners) |
| shosubgo | `~/.config/quarry/shodan-key.txt` | Shodan |

## Target profile

One YAML per engagement. Empty sections skip cleanly.

```yaml
TARGET: acme

APEX_DOMAINS:          # scope anchored to these (suffix match)
  - acme.com

OOS:                   # regex vs full host; collected passively, never scanned
  - '^jobs\.'

CIDR:                  # empty => horizontal IP/port scanning skipped
  # - 192.0.2.0/24

ASN:                   # empty => only SUGGESTS candidates; active scan needs explicit CIDR/ASN
  # - AS12345

RATELIMIT:
  HTTP: 5              # req/s for httpx/katana/nuclei/dalfox (RoE wins). 0 => omit flag
  DNS:                 # puredns/massdns qps; empty => tool default
  PORTSCAN:            # naabu rate; empty => tool default

PORTS:
  HTTP:               # empty => full methodology port set (~90). Populate to narrow.

LIMITS:
  WAYMORE_RESPONSES: 5000   # max archived responses waymore downloads per apex (0 = all)

MODES:
  PASSIVE_ONLY: false  # true => no active probing/scanning at all
  HEADLESS: false      # true => katana headless SPA crawl (RAM-heavy)
  SCREENSHOTS: true
  PORTSCAN: true       # ignored if CIDR empty
  TAKEOVER: true       # collect CNAMEs + run nuclei takeover templates

NOTES:
  - Official program rate limit is 5 req/s.
```

The profile compiles into a **scope matcher** every phase consults (apex suffix, OOS regex,
CIDR membership) — replacing regex-in-every-script.

> On bigger targets, see **`docs/target-prep.md`** — an OSINT guide mapping each profile
> field (apexes, OOS, CIDR, ASN, acquisitions, cloud ranges) to where to find the data. For a
> full command-by-command trace of a run, see **`docs/example.md`**.

## Workflow

```bash
quarry init-target acme -o targets/acme.yaml          # 1. profile skeleton
$EDITOR targets/acme.yaml                            # 2. fill anchors (apex + optional asn/org/brands)
quarry osint -t targets/acme.yaml                      # 3. pre-flight: discover scope candidates
#   → review osint/acme/latest/osint-report.md + target.suggested.yaml
#   → confirm ownership/scope, copy approved candidates into targets/acme.yaml
quarry run -t targets/acme.yaml                        # 4. recon on CONFIRMED scope
```

The **`osint`** step is optional but recommended on bigger targets — it discovers related
apexes / ASNs / org context and never edits scope (candidates are review-only). The **`run`**
step:

```bash
quarry run -t targets/acme.yaml --phases vertical    # validate one phase at a time
quarry run -t targets/acme.yaml                       # all phases
quarry run -t targets/acme.yaml --passive             # no active probing
quarry report                                         # regenerate reports from a stored run
```

Detached VPS run:

```bash
setsid nohup quarry run -t targets/acme.yaml > run.log 2>&1 & disown
```

## Command surface

| Command | Purpose |
|---------|---------|
| `quarry install` | Full blank-VPS provision (system pkgs → Go → tools → wordlists/templates) |
| `quarry update` | Update managed tools, nuclei templates, resolvers, gf patterns |
| `quarry doctor` | Audit tools, versions, per-tool deps, API keys, resolvers, wordlists |
| `quarry init-target <name>` | Write an editable target profile from the template |
| `quarry osint -t <profile>` | **Pre-flight** OSINT — discover scope candidates + intel (review-only, never edits scope) |
| `quarry run -t <profile>` | Run recon phases against the confirmed scope |
| `quarry report` | Regenerate hotlist + exports + delta from a stored run (no scanning) |

## Phases (methodology mapping)

> OSINT is **not** a run phase — it's a separate pre-flight (`quarry osint`, see below) that
> discovers scope candidates for human review. The recon run acts only on confirmed scope.

| Phase | Does | Key tools |
|-------|------|-----------|
| **horizontal** | ASN/CIDR confirm, kaeferjaeger SNI dataset, tlsx SAN (443/8443/4443), reverse DNS, CSP-recon, **Caduceus ASN→cert** | mapcidr, tlsx, dnsx, asnmap, csprecon, caduceus |
| **vertical** | passive scrape (`-stats`) + GitHub + Shodan + DNS brute + **recursive word-cloud permutation→resolve loop** (alterx `-enrich -mode both`, converges) + **CNAME collect** | subfinder, github-subdomains, shosubgo, puredns, alterx, dnsx |
| **probe** | HTTP fingerprint (full methodology flag set), CDN/origin tag, screenshots, **naabu → nmap -sV**, passive smap | httpx, cdncheck, gowitness, naabu, nmap, smap |
| **crawl** | active crawl (+headless SPA, stored responses), archive URLs, JS download/beautify/mine, **waymore `-mode B` + xnLinkFinder over responses** | katana, gau, waymore, jsluice, xnLinkFinder, gitleaks, trufflehog |
| **params** | gf vuln-class buckets, param discovery, non-intrusive scan + OOB, **subdomain takeover**, reflected XSS/redirect | gf, arjun, nuclei (interactsh + takeover), dalfox |

Raw tool output is preserved before parsing; normalized results keep provenance so any result
traces back to the tool and raw file that produced it.

## Output

```text
~/.quarry/ (default; override with --home or $QUARRY_HOME)
  runs/<id>/manifest.json          run record + per-tool status taxonomy
  runs/<id>/raw/<phase>/<tool>/    raw evidence (preserved before parsing)
  runs/<id>/normalized/*.jsonl     entities with provenance (the source of truth)
  runs/<id>/exports/*.txt          flat compat views (subdomains/resolved/live/urls/js/…)
  runs/<id>/reports/HOTLIST.md     ranked manual-validation queues + rationale
  runs/<id>/reports/delta.md       per-source contribution + new-since-last-run
  runs/<id>/reports/checkpoints.md thin/blocked-output warnings with stated causes
  state/current -> latest run
  state/history/<id>.json
```

**HOTLIST** ranks: scanner candidates (unconfirmed), likely-origin (non-CDN) hosts,
auth/api/admin/file buckets, IDOR/SSRF/SQLi/XSS param candidates (common-vuln lists), secrets, and
gf/sourcemap queues.

## Anti-thin-output checks

Each tool run is classified `success / empty / partial / failed / timed-out / blocked /
skipped`. Zero output is **not** always "nothing found" — it can mean missing API keys, a bad
resolver set, WAF blocking, rate limits, no Chromium, a timeout, or an install problem.
Checkpoints make those failures visible with a stated cause instead of a silent zero.

## Design

- **Tool registry** (`src/quarry_recon/data/tools.yaml`) — every tool documented before use: install
  command, doc source, exact safe flags, deps, required keys, failure modes.
- **Runner** — executes tools with timeout + `stdin=DEVNULL`, captures stdout/stderr/exit/
  duration, stores raw evidence before parsing, classifies the result.
- **Asset store** — append-only JSONL entities with provenance; flat exports are views.
- **Checkpoint engine** — turns silent zeros into explained warnings.
- **Triage** — ranks candidates with stated rationale (vuln-class param lists, heat map).

Each phase reruns independently; the install/update lifecycle is owned by the tool.

## Troubleshooting

Start with `quarry doctor`. Common issues:

- `subfinder` finds little → configure provider API keys (run shows `-stats` per source).
- `puredns` skipped → add `~/.config/quarry/dns-wordlist.txt`.
- weak DNS results → check resolvers / trusted resolvers.
- `httpx` returns nothing → check scope, rate limits, WAF blocking, tool status in manifest.
- screenshots fail → check Chromium / headless deps (`quarry doctor` flags chromium-needing tools).
- Go tools fail to install → installer reinstalls Go if too old; confirm `/usr/local/go`.
- waymore huge → lower `LIMITS.WAYMORE_RESPONSES` or run `--passive` first.

## Roadmap

Intentionally not first-version. Add after the core is understood on real targets:

- content discovery (ffuf/gobuster/dirsearch) · 403-bypass mapping · vhost enumeration
- COTS/known-path discovery · mobile/APK path extraction
- confidence scoring over normalized entities
- gungnir continuous CT monitoring
- SQLite/DuckDB query layer over the JSONL store
- distributed / axiom-style fan-out
