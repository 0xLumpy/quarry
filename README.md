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

`v0.2.9` (milestone — methodology + evidence + production-readiness) — command surface, installer,
OSINT pre-flight, the full recon run (**nine phases** including DNS-record enrichment, late-host
enrichment, CDN origin-IP correlation, and candidate-driven content discovery), active **evidence extraction** (exposed-file secret pull,
GraphQL introspection, actuator interrogation, OpenAPI parsing, SSTI confirmation), enrichment
across the pipeline (**DNS records, TLS certs/SANs, CT logs, favicon + cert-fingerprint pivots, cloud-bucket + vhost candidates**),
a structured JSONL store, exports, reports, a redacted structured **digest** with first-class evidence queues,
runtime telemetry, `doctor` readiness + opt-in notifications, and checkpointing — all wired and
verified end-to-end against a purpose-built test range. Scale/reliability (resumable/parallel runs)
and the attack/AI layer come next.

## Safety and scope

Built for **authorized reconnaissance only**. It does not autonomously exploit. It **maps**
where a human should look harder:

- subdomain-takeover candidates · likely-origin (non-CDN/WAF) hosts
- auth / API / admin / upload / file / export surfaces
- IDOR / SSRF / SQLi / XSS / redirect / SSTI parameter queues
- source-map candidates · JavaScript endpoints and secrets
- DNS context (MX/NS/TXT-SPF/DMARC/CAA/ASN) · cert SANs · cloud-bucket + related-host + vhost candidates (**verify-ownership**)
- scanner candidates — always marked **unconfirmed**

Scope stays fixed: horizontal findings on owned IP space are recorded as review candidates,
never auto-pivoted to new roots. BAC/IDOR object swaps, WAF bypasses, and the manual Burp
testing of methodology Phase 9 remain human work.

## Requirements

Built to run on a **VPS** — recon runs are long, and heavy DNS scanning from a home IP can get
you rate-limited or blocked. `quarry install` checks the host and tiers it:

| Resource | Minimum | Recommended | Why |
|----------|---------|-------------|-----|
| CPU | 2 vCPU | 4 vCPU | parallel DNS/HTTP probing |
| RAM | 4 GB | 8 GB | headless crawl + 3M-entry wordlists |
| Disk (free) | 5 GB to install · 10 GB to run | 40 GB+ | crawl, screenshots, raw JSONL, nuclei output, repeated runs grow fast; **80 GB+** for large targets |

Install needs little (a full provision measured ~4 GB — the Go build cache is transient, freed
afterward); a **run** needs more headroom as output grows (crawl, screenshots, JSONL, nuclei), and
`quarry run` does its own pre-run free-space check. Below **minimum** → install aborts (override
with `--yes`); between minimum and recommended → proceeds with a warning. OS: Debian/Ubuntu ·
Fedora · Arch (apt/dnf/pacman); macOS (brew) best-effort.

## Install

Blank VPS → fully provisioned in one command:

```bash
cd quarry
bash install.sh       # pipx-installs quarry, then `quarry install` provisions everything else
quarry doctor         # audit tools, versions, keys, wordlists, resources
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

`quarry install` owns the whole lifecycle and runs six stages (preceded by the system-spec
check — see [Requirements](#requirements); `--yes` installs even below minimum):

1. **system packages** — OS-detected (apt/dnf/pacman/brew): build toolchain, `libpcap-dev`,
   chromium + headless libs, `libxml2/xslt`, `nmap`, `pipx`, … (per-tool deps merged in)
2. **Go toolchain** — installs current Go to `/usr/local/go` if missing **or too old**
3. **tools** — every binary in the registry (Go install / pipx / massdns from source).
   Tools already on `PATH` are recorded as external and left untouched
4. **data files** — trickest resolvers + n0kovo 3M DNS wordlist (`~/.config/quarry/wordlists/`) +
   `secrets.yaml` and `config.yaml` → `~/.config/quarry/` (both created once, never overwritten)
5. **extras** — gf patterns (`~/.gf`), nuclei templates
6. **cleanup** — reclaim disk (`go clean -cache -modcache -testcache`, pip/apt caches)

Anything that can't be automated (no sudo, unsupported OS, API-key/login-gated tools) is
reported with its doc link — never silently skipped.

## Configuration — three stores, three jobs

Settings are split by *what kind of thing they are*, so each lives in one obvious place:

| Store | Scope | Holds |
|-------|-------|-------|
| `projects/<t>/target.yaml` | the **engagement** | scope (apexes/OOS/CIDR), `RATELIMIT` = pressure on the *target*, modes |
| `~/.config/quarry/config.yaml` | the **machine** | `PERFORMANCE` (concurrency profile + per-tool worker overrides), advanced local tool paths (openintel) |
| `~/.config/quarry/secrets.yaml` | **credentials** | API keys / tokens / webhooks only (redacted from all logs + manifests) |

The line that matters: **rate ≠ concurrency**. *Rate* (how hard we hit the target) is an engagement
property and stays in `target.yaml`; *concurrency* (how many local lanes a tool uses) is a machine
property and lives in `config.yaml`. `config.yaml` is optional — unset = safe defaults; `quarry
doctor` shows the active profile under `[config]`.

## API keys

Never stored in target profiles or run manifests — secret values are redacted out of recorded
commands and logs. Keys live in two places:

**`~/.config/quarry/secrets.yaml`** (`chmod 600`, created at install) — keys the framework passes
to tools itself. `quarry doctor` shows which are set. Back up before editing:
`cp ~/.config/quarry/secrets.yaml ~/.config/quarry/secrets.yaml.bak`.

| Key | Used by |
|-----|---------|
| `github` (list) | github-subdomains — use burner PATs |
| `shodan` | shosubgo, favicon-hash + cert-fingerprint pivots |
| `certspotter` | extra CT-log subdomains (optional — free tier keyless) |
| `censys` | extra CT-log subdomains via Censys Platform (advanced/optional — silent unless `token`+`org` set) |
| `whoxy` | osint reverse-whois |
| `projectdiscovery` | exported as `PDCP_API_KEY` (chaos) for subfinder, asnmap, … |
| `notify` | opt-in run notifications (Slack/Discord/Telegram/webhook) — off by default; `quarry notify --test` |
| `oob` | out-of-band — **one Quarry-owned layer** (interactsh-client managed internally). **Backend**: default built-in public interactsh, or override with a private server via `interactsh_server`/`interactsh_token` (replaces the backend, not a separate channel). Quarry-owned probes (`params.oob_probe`) issue per-source callbacks correlated to source/target/param; `quarry oob poll -t <target>` pulls delayed ones. `quarry oob import` is **compatibility-only** for external logs (Burp/XSSHunter/manual/old dalfox `-b`), uncorrelated unless a token matches. `blind_xss_url` → dalfox `-b` (operator collector; folds into the owned layer later). nuclei keeps its own native OAST (tool-owned). |

**Tool-native configs** — these tools read their own file; put their keys there:

| Tool | Location | Keys |
|------|----------|------|
| subfinder | `~/.config/subfinder/provider-config.yaml` | chaos, github, shodan, securitytrails, netlas, c99, dnsdumpster |
| waymore | `~/.config/waymore/config.yml` | URLScan, VirusTotal |

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
  HTTP:                # empty => tool defaults (fast). Set only for a program's RoE cap — a low
                       # cap makes nuclei slow (templates x hosts). 0 => omit flag entirely
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
  PORTSCAN: false      # INFRA scan only (naabu top-1000 CIDR -> nmap): opt-in, needs true + CIDR.
                       # The fast web-port SYN prefilter is separate + always on (see note below).
  TAKEOVER: true       # collect CNAMEs + run nuclei takeover templates
  CONTENT_DISCOVERY: "off"  # off | light | balanced | deep — candidate-driven path brute (default off)
  CONTENT_RECURSION: 0      # recursion depth for content discovery (0 = off; pairs with balanced/deep)
  DEEP_EVIDENCE: false      # true => DOWNLOAD + mine heavy artifacts (actuator heapdump) vs just flagging

NOTES:
  - Free-form reminders (e.g. "program caps requests at 5 req/s → set RATELIMIT.HTTP: 5").
```

The profile compiles into a **scope matcher** every phase consults (apex suffix, OOS regex,
CIDR membership) — replacing regex-in-every-script.

> **Two independent port-scan lanes — don't confuse them.** Quarry runs a fast **web-port SYN
> prefilter** (naabu SYN over each live host's *resolved public IPs* × the HTTP ports, then httpx
> probes only the open ones) on every active run — it's main-river and always on when `naabu` is
> installed, and is **not** controlled by `MODES.PORTSCAN`. Separately, `MODES.PORTSCAN` gates the
> **infra port scan** (naabu `top-1000` over `CIDR` → `nmap -sV`) — the slow, potentially days-long
> side-stream. It is **off by default**: set `PORTSCAN: true` *and* provide `CIDR` to opt in. So
> adding CIDR scope alone never arms the infra scan.

> On bigger targets, see **`docs/target-prep.md`** — an OSINT guide mapping each profile
> field (apexes, OOS, CIDR, ASN, acquisitions, cloud ranges) to where to find the data. For a
> full command-by-command trace of a run, see **`docs/example.md`**.

## Workflow

```bash
quarry init acme.com                       # 1. creates projects/acme.com/target.yaml (apex auto-seeded for a domain)
$EDITOR projects/acme.com/target.yaml      # 2. (optional) add CIDR / ASN / org
quarry oos -t acme.com careers.acme.com    #    (optional) seed out-of-scope hosts from the CLI
quarry osint -t acme.com                    # 3. pre-flight: discover scope candidates
#   → review projects/acme.com/osint/latest/osint-report.md + target.suggested.yaml
#   → confirm ownership/scope, copy approved candidates into the profile
quarry run  -t acme.com                     # 4. recon on CONFIRMED scope
```

`-t` takes a **project name** (`acme.com` → `projects/acme.com/target.yaml`), a project dir, or a
full `target.yaml` path — all equivalent. Put a project somewhere else with
`quarry init acme.com -o /data/acme`, then `quarry run -t /data/acme`.

The **`osint`** step is optional but recommended on bigger targets — it discovers related
apexes / ASNs / org context and never edits scope (candidates are review-only). The **`run`**
step:

```bash
quarry run -t acme.com --phases vertical    # validate one phase at a time
quarry run -t acme.com                       # all phases
quarry run -t acme.com --passive             # no active probing
quarry report -t acme.com                    # regenerate reports from a stored run
```

Detached VPS run:

```bash
setsid nohup quarry run -t acme.com > run.log 2>&1 & disown
```

## Command surface

| Command | Purpose |
|---------|---------|
| `quarry install` | Full blank-VPS provision (system pkgs → Go → tools → wordlists/templates) |
| `quarry update` | Update managed tools, nuclei templates, resolvers, gf patterns |
| `quarry doctor` | Audit tools & versions, API keys (`[secrets]`), resolvers, wordlists, disk (`[system]`) — ends with a readiness verdict |
| `quarry init <name>` | Create a project (`projects/<name>/target.yaml`); `-o <dir>` for a custom location |
| `quarry oos -t <target> <host…>` | Add out-of-scope patterns (bare label → subdomain-prefix; FQDN → apex-scoped; regex kept verbatim) |
| `quarry osint -t <profile>` | **Pre-flight** OSINT — discover scope candidates + intel (review-only, never edits scope) |
| `quarry run -t <profile>` | Run recon phases against the confirmed scope |
| `quarry report -t <profile>` | Regenerate hotlist + exports + delta from a stored run (no scanning) |
| `quarry notify --test` | Validate opt-in run notifications (secrets.yaml `notify:`) |

## Phases (methodology mapping)

> OSINT is **not** a run phase — it's a separate pre-flight (`quarry osint`, see below) that
> discovers scope candidates for human review. The recon run acts only on confirmed scope.

| Phase | Does | Key tools |
|-------|------|-----------|
| **horizontal** | ASN/CIDR confirm, kaeferjaeger SNI dataset, tlsx SAN (443/8443/4443), reverse DNS, native CSP fetch (guarded, no redirect-follow), **Caduceus ASN→cert**, **S3/GCS cloud-bucket candidates (verify-ownership)** | mapcidr, tlsx, dnsx, asnmap, caduceus |
| **vertical** | passive scrape (`-stats`) + GitHub + Shodan + **direct CT logs (crt.sh + certspotter + Censys)** + DNS brute + **recursive word-cloud permutation→resolve loop** (alterx `-enrich -mode both`, converges) + **CNAME collect** | subfinder, github-subdomains, shosubgo, crt.sh, certspotter, censys, puredns, alterx, dnsx |
| **dns** | DNS-record enrichment over resolved in-scope hosts — **A/AAAA/CNAME/MX/NS/TXT/SOA/CAA + ASN/CDN** as first-class `dns_record` entities (context, not re-discovery; puredns kept for brute/validate) | dnsx |
| **probe** | HTTP fingerprint (full methodology flag set), CDN/origin tag, **CSP-sibling discovery (response headers)**, **tlsx cert SAN harvest (sibling hosts) + `certificate` context**, **Shodan favicon-hash + cert-fingerprint pivots (related hosts)**, **vhost enumeration (ffuf Host-fuzz over origin IPs)**, **deserialization/token fingerprint (Set-Cookie + headers)**, screenshots, **naabu → nmap -sV**, passive smap | httpx, tlsx, ffuf, cdncheck, gowitness, naabu, nmap, smap |
| **crawl** | active crawl (+headless SPA, stored responses), archive URLs, JS download/mine + redacted secret scan, **waymore `-mode B` + xnLinkFinder over responses**, link-discovered host promotion | katana, gau, waymore, jsluice, xnLinkFinder, gitleaks, trufflehog |
| **enrich** | catch-up over hosts found *after* probe (crawl links, CSP siblings): resolve, **dangling-CNAME takeover**, HTTP fingerprint, WAF, screenshots, smap; **target-specific wordlist re-brute** (crawl-mined vocabulary fed back into apex + wildcard-zone brute — "teach the target") | dnsx, httpx, puredns, nuclei, gowitness, smap |
| **origin** | **CDN/origin-IP correlation (map-only)** — for CDN/WAF-fronted hosts, propose candidate origin IPs by favicon-hash twin + cert-sha1 twin + cert-SAN match against non-CDN hosts; emitted as `verify-ownership` review leads, never scanned | (correlation over `live`/`certificate`) |
| **content** | candidate-driven path/dir discovery (**off by default**; light/balanced/deep + capped recursion) over live in-scope hosts, autocalibrated against catch-alls, **always merges a curated config-leak/secret-path quick-hunt list** | ffuf |
| **params** | gf vuln-class buckets, param discovery, non-intrusive scan + OOB, **subdomain takeover**, reflected XSS/redirect, and **evidence extraction** (fetch exposed files → secrets, GraphQL introspection, actuator interrogation, **tech-conditional framework debug/admin endpoint probe**, OpenAPI parse, SSTI confirm) | gf, arjun, nuclei (interactsh + takeover), dalfox |

Raw tool output is preserved before parsing; normalized results keep provenance so any result
traces back to the tool and raw file that produced it.

## Output

Everything for a target lives in **one project dir** (`~/projects/<target>/`) — profile,
OSINT, and recon together. Clean to `rsync` down to your local machine for manual testing.

```text
projects/<target>/
  target.yaml                              the profile (scope lives here)
  osint/<ts>/                              quarry osint pre-flight
    candidates.jsonl  intel.jsonl  osint-report.md  target.suggested.yaml
  osint/latest -> <ts>
  recon/<run_id>/                          quarry run output
    manifest.json                          run record + per-tool status taxonomy + failure summary + metrics pointer
    raw/<phase>/<tool>/                    raw evidence (preserved before parsing)
    normalized/*.jsonl                     entities with provenance (the source of truth)
    exports/*.txt                          flat compat views (subdomains/live/urls/js/…)
    metrics/summary.json                   runtime telemetry (per-phase/tool timing, long poles)
    reports/HOTLIST.md                     ranked manual-validation queues + rationale (human)
    reports/digest.json                    same queues as structured, redacted JSON (provenance + raw refs)
    reports/delta.md                       per-source contribution + new-since-last-run
    reports/checkpoints.md                 thin/blocked-output warnings with stated causes
  recon/state/current -> latest run
  recon/state/history/<run_id>.json
```

(Projects root defaults to `~/projects/` (home-anchored, so runs don't depend on your cwd); override
with `--projects-dir` / `$QUARRY_PROJECTS` on `quarry init`. Keys stay global in `~/.config/quarry/`;
wordlists in `~/.config/quarry/wordlists/`.)

**HOTLIST** ranks: scanner candidates (unconfirmed), likely-origin (non-CDN) hosts,
auth/api/admin/file buckets, IDOR/SSRF/SQLi/XSS param candidates (common-vuln lists), secrets,
gf/sourcemap queues, subdomain-takeover candidates, and tagged surface classes. **`digest.json`**
is the same content in structured, redacted JSON with first-class **evidence queues** (graphql
introspection, actuator exposure, websocket/api-base endpoints, SSTI, api-doc, auth-flow, framework
**debug**-endpoint exposure, **deser**ialization/token fingerprints, **vhost** candidates, and a
**tech-intel** reference of known CVEs/primitives per fingerprinted framework — the attack-layer
handoff) — every item carries provenance and a raw-evidence reference; secret values are previews
only and sensitive URL parameters (tokens, OAuth `code`/`state`, …) are masked.

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
- `puredns` skipped → add `~/.config/quarry/wordlists/dns.txt`.
- weak DNS results → check resolvers / trusted resolvers.
- `httpx` returns nothing → check scope, rate limits, WAF blocking, tool status in manifest.
- screenshots fail → check Chromium / headless deps (`quarry doctor` flags chromium-needing tools).
- a tool fails mid-install → during large installs an individual Go or pipx tool may fail from
  temporary network, upstream-module, or rate-limit issues. Let the install finish, set PATH,
  then retry the failed tools individually: `quarry install --only <tool>`.
- Go tools still fail → installer reinstalls Go if too old; confirm `/usr/local/go` on PATH.
- waymore huge → lower `LIMITS.WAYMORE_RESPONSES` or run `--passive` first.
- **run killed / OOM on a big target** → headless crawl, nuclei, and large wordlists can exhaust
  RAM on wide scopes (the kernel kills the process instantly — no in-tool warning is possible).
  Add swap before retrying:
  ```bash
  sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile          # make permanent: add to /etc/fstab
  ```
  8 GB RAM + 4 GB swap clears most targets. (Resumable runs — pick up where a crash left off —
  are planned for a later release.)

## Roadmap

Shipped since first version: content discovery, OpenAPI/Swagger parsing, the evidence-extraction
layer, the redacted digest contract, runtime telemetry, `doctor` readiness, vhost enumeration, and
Censys / cert-fingerprint pivots. Next:

- scale / reliability — resumable runs · selective retry · parallel workers · per-tool job state
- the attack/AI layer — consume the digest, prove primitives (human-in-loop)
- code-host intelligence (scan-at-depth, no clone) · 403-bypass mapping
- SQLite/DuckDB query layer over the JSONL store · gungnir continuous CT monitoring
