# Quarry

Reconnaissance automation for bug bounty and authorized security testing.

Quarry runs a full recon methodology from one CLI: subdomain discovery, DNS and HTTP
fingerprinting, crawling, JS analysis, content discovery and parameter scanning — across 38 tools
and 66 sources, into one structured JSONL store you can grep, export and hand to a human.

It is built for long runs on real targets. Every tool run is classified, the bounded lanes report
what they covered and what they skipped, and omitted input is counted rather than dropped.

> [!IMPORTANT]
> Quarry performs active network and application testing by default. Use it only on systems you are
> authorized to test, and review the target profile before starting a run.

Quarry is under active development. Commands, schemas, and report formats may still change.

---

## Features

- **Nine phases** — horizontal, vertical, dns, probe, crawl, enrich, origin, content, params —
  selectable per run with `--phases`
- **Structured store** — 23 entity types as append-only JSONL with provenance back to raw evidence
- **Coverage accounting** — the bounded lanes report eligible / tested / omitted with a reason
- **OSINT pre-flight** — a separate command that proposes scope candidates for human review
- **Ranked output** — HOTLIST for humans, `digest.json` for tooling
- **Pinned installs** — every managed tool has a version, ref or digest (`nmap` is distro-managed
  by policy); `install` and `update` cannot reach `@latest`
- **Scope enforcement** — one matcher every phase consults; out-of-scope hosts are collected but
  never contacted
- **Cost control** — paid sources have credit reserves and per-project evidence reuse

## Requirements

Run Quarry on a VPS. Reconnaissance runs can be long, and high-volume DNS traffic may be throttled
or blocked on residential connections.

Python 3.10+, `sudo` for system packages, and outbound internet access.

| | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disk free | 5 GB install · 10 GB run | 40 GB (80 GB+ for large targets) |

Below minimum, install aborts (`--yes` overrides). Debian/Ubuntu, Fedora and Arch are supported
(apt/dnf/pacman); macOS is best-effort.

## Install

```bash
git clone https://github.com/0xLumpy/quarry.git
cd quarry
bash install.sh
quarry doctor
```

`install.sh` installs Quarry with pipx, then `quarry install` provisions the rest: system packages,
the Go and bun runtimes, the 38 registry tools, wordlists and resolvers, gf patterns and nuclei
templates.

```bash
quarry install --dry-run          # preview, change nothing
quarry install --include-optional # the 14 optional tools (install.sh does this for you)
quarry install --only httpx       # one tool
quarry install --tools-only       # skip system packages and data files
quarry update                     # reinstall tools at their pins, refresh managed data
quarry doctor                     # tools, versions, keys, wordlists, disk
```

## Quick start

```bash
quarry init acme.com                       # create ~/projects/acme.com/target.yaml
$EDITOR ~/projects/acme.com/target.yaml    # set scope
quarry osint -t acme.com                   # optional: propose scope candidates
quarry run -t acme.com                     # run recon on confirmed scope
```

Results land in `~/projects/acme.com/recon/<run_id>/`. Start with `reports/HOTLIST.md`.

## Configuration

Three files, three jobs.

| File | Holds |
|---|---|
| `~/projects/<name>/target.yaml` | scope, rate limits, modes — per engagement |
| `~/.config/quarry/config.yaml` | concurrency, budgets, credit reserves — per machine |
| `~/.config/quarry/secrets.yaml` | API keys and webhooks |

Rate is how hard you hit the target and lives in `target.yaml`. Concurrency is how many local lanes
a tool uses and lives in `config.yaml`.

Both are optional, but unset does not mean passive: a default run probes actively, takes
screenshots, checks takeovers, contacts in-scope names that resolve to private addresses, and uses
each tool's own rate. Read the target profile before the first run.

### Target profile

```yaml
TARGET: acme

APEX_DOMAINS:
  - acme.com

OOS:                          # regex against the full host
  - '^jobs\.'

CIDR:                         # empty: no horizontal IP scanning
ASN:                          # empty: candidates are suggested, never scanned

RATELIMIT:
  HTTP:                       # req/s; empty means tool defaults
  DNS:
  PORTSCAN:

LIMITS:
  WAYMORE_RESPONSES: 5000     # archived responses per apex (0 = all)

MODES:
  PASSIVE_ONLY: false
  HEADLESS: false             # headless SPA crawl
  SCREENSHOTS: true
  PORTSCAN: false             # infra scan: needs true AND CIDR
  TAKEOVER: true
  CONTENT_DISCOVERY: "off"    # off | light | balanced | deep
  CONTENT_RECURSION: 0
  BLOCK_PRIVATE_TARGETS: false
  SECRET_VERIFICATION: false  # sends found credentials to their providers
  BLIND_XSS: false            # stored payloads that fire later
  DEEP_EVIDENCE: false        # downloads heapdumps instead of flagging them
  JS_AST: false               # AST analysis of JS bundles
  JS_CHUNK_BRUTE: 0           # guessed chunk ids (each one is a new request)
```

`SECRET_VERIFICATION`, `BLIND_XSS`, `DEEP_EVIDENCE` and `JS_CHUNK_BRUTE` enable additional active or
credential-using work and are off by default. See [docs/target-prep.md](docs/target-prep.md) for what
each mode does and when to arm it.

### API keys and webhooks

`~/.config/quarry/secrets.yaml`, mode 600, created at install. Everything here is optional. Most lanes that need an unset key are recorded as skipped — but a few skip silently (Censys, OpenINTEL,
shosubgo), and CertSpotter and ProjectDiscovery tools run without their optional keys.

| Entry | Used by |
|---|---|
| `github` | github-subdomains |
| `shodan` | shosubgo, favicon and certificate pivots, per-IP host records |
| `certspotter` | CT-log subdomains |
| `censys` | certificate search (needs `token` and `org`) |
| `whoxy` | `quarry osint` reverse-whois |
| `projectdiscovery` | exported as `PDCP_API_KEY` for ProjectDiscovery tools |
| `notify` | run notifications (Slack/Discord/Telegram/webhook) |
| `oob` | out-of-band callback server (defaults to the public interactsh pool) |

Your keys never appear in run manifests, logs or recorded commands.

## Phases

| Phase | Does | Tools |
|---|---|---|
| horizontal | active cloud-bucket checks; with `CIDR`: range expansion, certificate SANs, reverse DNS and configured-ASN context | mapcidr, tlsx, dnsx, asnmap, caduceus |
| vertical | passive sources, CT logs, DNS brute force, permutations, wildcard handling | subfinder, github-subdomains, shosubgo, puredns, alterx, dnsx |
| dns | A/AAAA/CNAME/MX/NS/TXT/SOA/CAA plus ASN and CDN as first-class records | dnsx |
| probe | HTTP fingerprinting, CDN detection, certificate harvest, Shodan pivots, vhosts, screenshots, port scan | httpx, tlsx, ffuf, cdncheck, gowitness, naabu, nmap, smap |
| crawl | crawling, archived URLs, JS download and mining, chunk discovery, AST analysis | katana, gau, waymore, jsluice, xnLinkFinder, gitleaks, trufflehog, jxscout |
| enrich | catch-up on hosts found after probe: resolve, takeover, fingerprint, targeted re-brute | dnsx, httpx, puredns, nuclei, gowitness |
| origin | correlate CDN-fronted hosts to candidate origin IPs (map-only) | — |
| content | path and directory discovery, off by default | ffuf |
| params | parameter discovery, vulnerability-class buckets, scanning, XSS, evidence extraction | gf, arjun, nuclei, dalfox |

Phases share one run's store and feed each other: `params` works on what `probe` and `crawl` found
in the *same* run. `--phases` selects a subset for a fresh run, it does not continue an earlier one.

OSINT is not a phase. `quarry osint` runs before the recon run and only proposes candidates —
it never edits scope.

## Output

```text
~/projects/<target>/
  target.yaml
  osint/<ts>/            candidates, intel, report, suggested profile
  recon/<run_id>/
    run.json             immutable creation record (run id, target, start)
    manifest.json        run record, per-tool status, coverage, failures
    events.jsonl         append-only execution + coverage events (what `status` reads)
    raw/                 tool output, preserved before parsing
    normalized/*.jsonl   entities with provenance
    exports/*.txt        flat lists (subdomains, live, urls, js)
    reports/HOTLIST.md   ranked queues for manual testing
    reports/digest.json  the same content, structured
    reports/delta.md     what is new since the previous run
  recon/state/           run history and lane rotations, shared across runs
  state/                 purchased Shodan pages — paid evidence, reused by later runs
  osint/state/           purchased Whoxy pages — paid evidence, reused by later runs
```

The two `state/` directories hold evidence you paid credits for. Delete them and a later run that
needs the same page has to buy it again.

Findings are recorded at full value — a secret you cannot read is not a finding. Your own configured
credentials are stripped from recorded commands, notes, manifests and notifications. Separately,
single oversized bodies are not kept: JS above 15 MB and sourcemaps above 20 MB are skipped and
counted as an omission.

## Commands

| Command | Purpose |
|---|---|
| `quarry init <name>` | create a project |
| `quarry oos -t <t> <host>` | add out-of-scope patterns |
| `quarry osint -t <t>` | OSINT pre-flight, review-only |
| `quarry run -t <t>` | run recon |
| `quarry status -t <t>` | per-source state of the last run |
| `quarry report -t <t>` | regenerate reports from a stored run |
| `quarry policy` | show the effective coverage policy |
| `quarry plan` | show what would run on this machine |
| `quarry doctor` | audit the local setup |
| `quarry install` / `update` | provision tools and managed data; reinstall at the pins |
| `quarry lock` | report installed versions, drift, and pin-ready lines for the registry |
| `quarry set <name>` | refresh one wordlist or resolver file |
| `quarry oob poll` / `import` | pull or import out-of-band callbacks |
| `quarry notify` | run notifications (Slack/Discord/Telegram/webhook) |

`report`, `status`, and `oob poll` accept `--run <run-id>` and otherwise use the latest run.

### Run flags

| Flag | Effect |
|---|---|
| `--phases <list>` | run only these phases |
| `--passive` | disable active probing; passive sources still run |
| `--timeout <s>` | minimum time allowance per tool; tools may extend it for larger workloads (`0` removes Quarry's per-tool deadline) |
| `--unbound` | relax eligible bounds; scope, rates, concurrency and spending remain unchanged |
| `--settle` | start child runs while work advances; paid acquisition is limited to the first child |

## How results are qualified

Every tool run is classified `success`, `empty`, `partial`, `blocked`, `timed-out`, `failed` or
`skipped`. Zero output is never reported as "nothing found" when it could be a missing key, a bad
resolver set, a WAF, a rate limit or a timeout.

The bounded lanes — vertical, probe, crawl, content, params and the A1d brute in enrich — also
report coverage: how much input they were eligible for, how much they tested, and what they omitted
(capped, timed out, sampled, limited by a provider, declined by the tool, or unmeasurable). Such a
lane never claims `complete` when it could not measure itself; it says `unknown`. The horizontal,
dns and origin phases are not instrumented yet and report tool status only.

Some work carries across runs and some does not:

| | Carries over |
|---|---|
| scheduling rotations, provider progress, purchased pages | yes — a later run continues |
| chunked scan progress, per-run ledgers | no — each run gets a new directory |

There is no `--resume <run_id>`.

## Scope and safety

For authorized testing only. Quarry maps attack surface. It does not chain or weaponize what it
finds, but several opt-in modes do act on the target — see the mode table above.

- Scope is `APEX_DOMAINS` plus any `CIDR` you configure. Related hosts found on owned
  infrastructure are recorded as review candidates, never scanned as new roots.
- Out-of-scope hosts are collected as evidence and never contacted.
- The scan host itself, loopback, link-local and cloud metadata addresses are always withheld.
- In-scope names that resolve to private, CGNAT or ULA addresses **are** contacted by default.
  Set `MODES.BLOCK_PRIVATE_TARGETS: true` when the engagement or your scan location requires
  otherwise.
- Blind XSS persists a payload that can fire later in someone else's browser, and secret
  verification sends discovered target credentials to their providers. Both are off by default.
- An active `params` run confirms SSTI candidates with a benign arithmetic payload. This is not
  gated by a mode; `--passive` or `PASSIVE_ONLY` is what stops it.
- Scanner results are leads, marked unconfirmed until a human validates them.

### Out-of-band callbacks

With no server configured, Quarry uses the public interactsh service — ProjectDiscovery operates it
and can see raw callbacks. Set `oob.callback_server` (and `oob.auth_token` if it needs auth) to
point at one you host. Setting a server replaces the backend everywhere; it is not a second
channel. Quarry's own probes, nuclei and dalfox keep separate sessions and correlation even on the
same backend.

`quarry oob import` exists for compatibility only: it ingests external callback logs (Burp
Collaborator, XSSHunter, a manual interactsh session). Imported rows are evidence but stay
uncorrelated unless they carry a Quarry-issued token.

## Documentation

- [docs/target-prep.md](docs/target-prep.md) — building a target profile
- [docs/example.md](docs/example.md) — a full run, command by command
- [docs/osint-broadening.md](docs/osint-broadening.md) — widening scope safely
- [docs/design/](docs/design/) — architecture and contracts
- Templates: [target](src/quarry_recon/data/target.template.yaml) ·
  [config](src/quarry_recon/data/config.template.yaml) ·
  [secrets](src/quarry_recon/data/secrets.template.yaml)

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate   # Debian/Ubuntu/Kali enforce PEP 668
pip install -e '.[dev]'
pytest                        # offline by default; network is blocked
bash scripts/verify-quarry.sh
```

The default selection excludes the opt-in markers: `-m integration` runs real binaries against
fixtures, `-m live` contacts the network, `-m requires_tool` needs a binary on PATH.

## Status

`v0.3.9`. The nine phases and the store layout have been in place since v0.2; v0.3 added coverage
accounting, resumable scheduling, provider cost control and pinned installs. A query layer over the
store is the next milestone.
