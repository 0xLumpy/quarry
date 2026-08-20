# Quarry

Reconnaissance automation for bug bounty and authorized security testing.

Quarry runs a full recon methodology from one CLI: subdomain discovery, DNS and HTTP
fingerprinting, crawling, JS analysis, content discovery and parameter scanning — across 38 tools
and 67 sources, into one structured JSONL store you can grep, export and hand to a human.

It is built for long runs on real targets. Typed tool outcomes, explicit coverage, durable evidence and
honest remainder are core contracts. `v0.3.9` does not yet enforce those contracts uniformly across every
lane; the pending integrity release tracks the gaps instead of presenting them as complete.

> [!IMPORTANT]
> Quarry performs active network and application testing by default. Use it only on systems you are
> authorized to test, and review the target profile before starting a run.

Quarry is under active development. Commands, schemas, and report formats may still change.

---

## Features

- **Nine phases** — horizontal, vertical, dns, probe, crawl, enrich, origin, content, params —
  selectable per run with `--phases`
- **Structured store** — 23 entity types as append-only observation JSONL, folded by canonical identity
  with provenance back to raw evidence
- **Coverage accounting** — instrumented bounded lanes report eligible / tested / omitted with a reason
- **OSINT pre-flight** — a separate command that proposes scope candidates for human review
- **Ranked output** — inertly encoded HOTLIST for humans, `digest.json` queues, and a lossless
  `private-report.json` projection with stable observation/artifact references
- **Version-managed installs** — registry tools declare a version, ref or digest (`nmap` is
  distro-managed by policy); complete activation rollback and runtime-identity enforcement remain
  release gates
- **Scope model** — engagement matchers separate authorized contact from passive candidates; uniform
  connect-time protected-destination enforcement remains a release gate
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

OOS:                          # bounded pattern against the full canonical host
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
  OOB_ENABLED: true           # set false to disable network OOB callback transport
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

Quarry masks exact configured key values in its recorded text as defense in depth. In `v0.3.9` this is
literal replacement, not a guarantee for encoded, transformed, or split representations. The pending
integrity release tracks the stronger boundary: each child receives only its declared credentials, and
Quarry-owned credentials are excluded by construction from manifests, logs, reports, and recorded
commands. Target-discovered secrets are evidence and **must** remain complete in private output; current
lossy paths are tracked as release defects rather than documented as acceptable redaction.

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
    state.json           lifecycle and derived-view publication generations
    events.jsonl         append-only execution + coverage events (what `status` reads)
    raw/                 tool output, preserved before parsing
    normalized/*.jsonl   append-only canonical observation rows with provenance
    exports/*.txt        flat lists (subdomains, live, urls, js)
    reports/HOTLIST.md   ranked queues for manual testing
    reports/digest.json  ranked queue projection, structured
    reports/private-report.json  every effective private observation with certified provenance
    reports/delta.md     what is new since the previous run
    revisions/
      revision.json      pointer to the certified late-evidence combined view
      revNNNN/           append-only supplement plus its reports/exports
  recon/state/           run history and lane rotations, shared across runs
  state/                 purchased Shodan pages — paid evidence, reused by later runs
  osint/state/           purchased Whoxy pages — paid evidence, reused by later runs
```

The two `state/` directories hold evidence you paid credits for. Delete them and a later run that
needs the same page has to buy it again.

The output contract requires target evidence and private operator reports to be full-fidelity — a
discovered secret you cannot read is not useful evidence. Quarry-owned API/provider, notification and OOB
credentials are operational inputs, not evidence, and must not enter operational records. A normal private
report is not a share-safe or AI-safe export: those surfaces require separately requested, policy-labelled
derived views and never replace canonical evidence. `v0.3.9` still has open implementation gaps against
these boundaries, recorded in the [current-HEAD audit](docs/audit/CURRENT-HEAD.md#head-08-truthful-lossless-private-reports-and-complete-provenance).
Separately, single oversized bodies are not kept: JS above 15 MB and sourcemaps above 20 MB are skipped and
counted as an omission. See [outputs and coverage](docs/outputs-and-coverage.md).

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

Migrated tool lanes classify execution as `success`, `empty`, `partial`, `blocked`, `timed-out`, `failed`
or `skipped`. Instrumented coverage distinguishes zero observations from missing credentials, bad
resolvers, target/tool blocking, limits and timeouts. `v0.3.9` still has silent or lossy paths, so these are
not yet universal guarantees; see the [current audit](docs/audit/CURRENT-HEAD.md).

Instrumented bounded lanes in vertical, probe, crawl, content, params and enrich also
report coverage: how much input they were eligible for, how much they tested, and what they omitted
(capped, timed out, sampled, limited by a provider, declined by the tool, or unmeasurable). Such a
record can say `unknown` when it cannot measure itself. This does not prove that every lane emitted a
record; horizontal, dns and origin remain less completely instrumented.

Some work carries across runs and some does not:

| | Carries over |
|---|---|
| scheduling rotations, provider progress, purchased pages | yes — a later run continues |
| chunked scan progress, per-run ledgers | no — each run gets a new directory |

There is no `--resume <run_id>`.

## Scope and safety

For authorized testing only. Quarry maps attack surface and performs active verification. Its accepted
broad Nuclei policy can issue state-changing requests, file writes or command payloads on a matching
vulnerable target; several additional impact-sensitive modes are opt-in. Review the program rules and
profile before execution.

- Scope is `APEX_DOMAINS` plus any `CIDR` you configure. Related hosts found on owned
  infrastructure are recorded as review candidates, never scanned as new roots.
- The scope matcher withholds out-of-scope hostnames from planned active work while retaining passive
  observations. Uniform enforcement by the actual connected peer is an open integrity gate.
- Scanner-self, loopback, link-local and cloud-metadata destinations are protected by policy. `v0.3.9`
  does not yet prove that exclusion at connect time across rebinding, proxy, direct-IP and CIDR paths.
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

Set `MODES.OOB_ENABLED: false` for one global network-OOB opt-out. It adds Nuclei's no-Interactsh
control, prevents Quarry callback issue/poll, and disables Dalfox blind OOB; local `quarry oob import`
remains available and `BLOCK_PRIVATE_TARGETS` is unchanged. `quarry plan -t <target>` reports the
resolved off/public/self-hosted backend for every owner from a detached planning snapshot.

The run-scoped Nuclei policy hashes the exact engine, configuration, ignore file, corpus, selected
templates, and referenced helpers. Template digest markers are inventoried but are **not** verified as
publisher signatures: the artifact reports `unverified-inventory-only-not-an-authorship-claim` and must
not be read as an official-signer assertion. Because the pinned engine applies signature-dependent load
behavior to JavaScript templates, every owner forces `-ept javascript`; those templates remain inventoried
as `load-excluded` but are never claimed as executed coverage.

`quarry oob import` exists for compatibility only: it ingests external callback logs (Burp
Collaborator, XSSHunter, a manual interactsh session). Imported rows are evidence but stay
uncorrelated unless they carry a Quarry-issued token.

## Documentation

- [docs/governance/PRODUCT-CONTRACT.md](docs/governance/PRODUCT-CONTRACT.md) — current product and evidence invariants
- [docs/audit/CURRENT-HEAD.md](docs/audit/CURRENT-HEAD.md) — audited current-HEAD closure and open blockers
- [docs/releases/v0.3.10.md](docs/releases/v0.3.10.md) — stabilization scope and status
- [docs/releases/RELEASE-GATES.md](docs/releases/RELEASE-GATES.md) — release evidence and promotion contract
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
pytest                        # positive H0 default (`-m offline`)
pytest -m integration         # H1 named-tool diagnostics; no live target
bash scripts/verify-quarry.sh # offline-only development diagnostics
# authorized operator only; never CI:
QUARRY_LIVE_APPROVED=1 RANGE_APEX=fixture.example bash scripts/verify-quarry-live.sh
```

Every collected pytest node must carry exactly one primary marker: `offline`, `integration`, `corpus`,
`packaging`, or `live`. `requires_tool("name")` is a named H1/P0 capability, not a selectable safety lane;
`synthetic_process` is a constrained H0-only exception for a controlled current-interpreter child. The
default development runs select H0 positively; CI separately selects H0, H1, and P0 and never selects
the live lane. The H0 Python deny hooks are development tripwires, not the OS containment or
candidate-bound evidence required by the still-open
[release gates](docs/releases/RELEASE-GATES.md). A separate Linux runner now produces an exact-candidate,
bubblewrap-isolated collect-only development diagnostic; its host runtime is untrusted and it emits no
release-gate record. See [tests/README.md](tests/README.md) for exact counts, commands, and limitations.

## Status

`v0.3.9`. The nine phases and the store layout have been in place since v0.2; v0.3 added coverage
accounting, resumable scheduling, provider cost control and pinned installs. The next release is the
foundational v0.3.10 integrity/truth stabilization; its current promotion status is tracked in the
[release register](docs/releases/v0.3.10.md). A query layer follows that stabilization rather than serving
as its substitute.
