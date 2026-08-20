# Example run — `0xlumpy.cc`, start to finish

A complete walk-through of what `quarry` **would** execute against `0xlumpy.cc`, traced from
the current command builders, in phase order. Nothing here was run — it documents the tool
invocations, the order, the scope/skip gating, and the artifacts produced. Exact flag values that come
from machine config or the governor (concurrency, budgets) are shown as representative defaults.

Assumptions:

- Authorized target `0xlumpy.cc` — single apex, **no CIDR in scope** (common bug-bounty case)
- Tools installed (`quarry install` done), API keys configured where available
- `PATH` includes `~/go/bin` and `~/.local/bin`
- Output lands in the project dir `~/projects/0xlumpy/` (profile + osint + recon together)
- Illustrative run id: `20260620-120000-a1b2c3d4` (timestamp + 8 hex)

---

## 0. One-time setup

```bash
# Full blank-VPS installation
git clone https://github.com/0xLumpy/quarry.git
cd quarry
./install.sh                                # system pkgs → Go → tools → wordlists/templates → the `quarry` command
quarry doctor                               # audit: tools, versions, deps, keys, resolvers
```

> If `quarry` is not found after installation, run `source ~/.bashrc` or open a new shell, then run
> `quarry doctor` again.

Or, when `pipx` is already available:

```bash
pipx install "git+https://github.com/0xLumpy/quarry.git"
pipx ensurepath
quarry install --include-optional           # provision the toolset (+ optional tools)
```

`doctor` confirms recon tools on `PATH`, chromium present (gowitness needs it), and
`~/.config/quarry/{resolvers.txt,trusted-resolvers.txt}` and `~/.config/quarry/wordlists/dns.txt` exist.

---

## 1. Create the target profile

```bash
quarry init 0xlumpy
```

`~/projects/0xlumpy/target.yaml`:

```yaml
TARGET: 0xlumpy

APEX_DOMAINS:
  - 0xlumpy.cc

OOS:
  - '^jobs\.'
  - '^careers\.'

CIDR:          # empty → horizontal IP/range steps + infra portscan SKIPPED
ASN:           # empty → ASN only suggests candidates (never scans)

RATELIMIT:
  HTTP:        # empty → tool defaults (fast); set only for a program's RoE cap
  DNS:         # empty → puredns/massdns default (no --rate-limit)
  PORTSCAN:    # empty → naabu default

PORTS:
  HTTP:        # empty → full methodology port set (94 ports)

LIMITS:
  WAYMORE_RESPONSES: 5000    # 0 = all

MODES:
  PASSIVE_ONLY: false
  HEADLESS: false            # katana SPA pass (RAM-heavy); default off
  SCREENSHOTS: true          # default true
  TAKEOVER: true             # default true — CNAME collection + takeover templates
  PORTSCAN: false            # infra naabu→nmap; needs true AND CIDR. (The web-port SYN prefilter is a separate
                             # active-recon step — see probe below — not this flag.)
  # advanced opt-ins (all default off): JS_AST, BLIND_XSS, SECRET_VERIFICATION, DEEP_EVIDENCE,
  # BLOCK_PRIVATE_TARGETS, CONTENT_DISCOVERY (off|light|balanced|deep), CONTENT_RECURSION, JS_CHUNK_BRUTE
```

> Bigger target? See `target-prep.md` for how to fill `APEX_DOMAINS`/`OOS`/`CIDR`/`ASN`/`ORG_NAMES`
> from OSINT (M365 tenant, reverse-whois, ASN lookups, acquisitions, cloud cert dumps).

---

## 2. Launch

```bash
quarry run -t 0xlumpy
```

Run phases execute in order
`horizontal → vertical → dns → probe → crawl → enrich → origin → content → params`
(OSINT is a separate pre-flight — §3 — run *before* this, on the confirmed scope). Each tool call captures
stdout/stderr/exit/duration, writes raw output under `raw/<phase>/<tool>/`, classifies the
result, and normalizes parsed entities into `normalized/*.jsonl`. After each phase the
checkpoint engine evaluates coverage. Run dir: `~/projects/0xlumpy/recon/20260620-120000-a1b2c3d4/`.

```
══ Quarry run 20260620-120000-a1b2c3d4 · target=0xlumpy · ACTIVE ══
   apexes=1 cidr=0 ports=[80, 443, 81, 300, …  (94 ports)]  http_rl=default
   ── effective coverage policy ──
     …bounds and their values (see `quarry policy`)…
```

---

## 3. Pre-flight — `quarry osint` (separate command, run before §2)

```bash
quarry osint -t 0xlumpy   # → ~/projects/0xlumpy/osint/<ts>/{osint-report.md, target.suggested.yaml, candidates.jsonl, intel.jsonl}
```

Apex/ASN/CIDR/org/leak discovery (all passive — queries third parties, not the target). Discovered
apexes/ASNs/CIDRs are **candidates** written to a review report + `target.suggested.yaml` (commented,
never auto-scoped) plus `candidates.jsonl`; Postman findings go to `intel.jsonl`. You confirm + uncomment
the good ones into `target.yaml`, then run §2. Per-apex first, then session-wide:

**azmap.dev M365/Azure tenant** (in-process HTTP, no key):
```
GET https://azmap.dev/api/tenant?domain=0xlumpy.cc&extract=true
```
→ `related_domains` / `email_domains` → candidate `apex`; tenant name → org context.

**whois** (no key) — registrant org/email (the email seeds whoxy):
```bash
whois 0xlumpy.cc        # registrant org → org context; emails → whoxy anchors
```

**DMARC pivot** (no key) — related apexes from rua/ruf addresses:
```bash
dig +short TXT _dmarc.0xlumpy.cc     # rua=mailto:..@DOMAIN → apex candidate (3rd-party processors flagged)
```

**whoxy reverse-whois** (only if `whoxy:` set) — sibling apexes by registrant email/org, paginated under a
credit reserve/budget. Without the key: `skipped` (recorded).
```
GET https://api.whoxy.com/?key=<KEY>&reverse=whois&email=<registrant-email>&page=N
```

**CAIDA ASRank** (no key) — candidate ASNs from `ORG_NAMES` via GraphQL:
```
POST https://api.asrank.caida.org/v2/graphql    # org → member ASNs → candidate ASN (verify-ownership)
```

**asnmap** (only if `ASN` already set + asnmap present) — ASN → prefixes → candidate `CIDR`.

**RDAP** (no key) — resolve each apex's IPs, look up the owning netblock:
```
GET https://rdap.org/ip/<ip>     # cidr0_cidrs → candidate CIDR; org → org context
```

**porch-pirate** (only if installed; no key) — public Postman leaks, recorded as **intel** (not scope):
```bash
porch-pirate -s 0xlumpy.cc --urls      # endpoints → intel; --globals → intel key=value
```

```
══ Quarry osint · target=0xlumpy (pre-flight, review-only) ══
  azmap[0xlumpy.cc]: N related + M e-mail domain(s)
  …
══ osint <verdict> · ~/projects/0xlumpy/osint/<ts>
   report:    …/osint-report.md
   suggested: …/target.suggested.yaml
   N apex candidate(s) — review, confirm scope, add to target.yaml
```

> Candidates are **suggestions** — review `osint-report.md`, confirm authorization + scope,
> uncomment approved entries from `target.suggested.yaml` into `target.yaml`, then run §2.
> See `target-prep.md`.

---

## 4. Phase 1 — horizontal

No CIDR → all IP-range steps skip. What runs:

**kaeferjaeger SNI dataset** (passive, **operator-provided LOCAL files — NO remote fetch**). Optional
one-time setup: download the provider SNI dumps you want to `~/.config/quarry/kaeferjaeger/`. Each run
streams whatever `*.txt` is there line-by-line (whole file, bounded RAM) for `0xlumpy.cc`. No dataset →
recorded skip.
→ raw `raw/horizontal/kaeferjaeger/matches.txt` · in-scope hosts → `subdomain`.

**native CSP fetch** (guarded, no external tool — *not* csprecon): fetch each apex root's CSP via
`fetch.scoped_headers` (per-hop resolve+scope guarded, never auto-follows a redirect off-scope), read all
CSP header variants + `<meta http-equiv>`:
→ raw `raw/horizontal/csp/csp.txt` · in-scope CSP domains → `subdomain`.

**cloud bucket enum** (runs even without CIDR, domain-only) — surfaces cloud storage from org/brand names.

**Skipped** (no CIDR): the horizontal phase returns early once it sees no CIDR — `mapcidr`, `tlsx` SAN,
`dnsx -ptr`, `caduceus`, and the ASN-context `asnmap` step are all skipped together. (ASN expansion still
happens independently in `quarry osint`, §3.)

> With `CIDR` set, these would also run:
> ```bash
> mapcidr -cidr 192.0.2.0/24 -silent
> tlsx -l <ips> -san -cn -silent -p 443,8443,4443 -resp-only
> dnsx -l <ips> -ptr -resp-only -silent
> caduceus -i <cidr> -p 443,8443,4443 -j        # CIDR→cert, behind-CDN hostnames
> ```
> and with `ASN` set: `echo AS<N> | asnmap -silent` (context).

```
▸ Horizontal discovery (ASN/CIDR/cert/SAN)
  kaeferjaeger: +N in-scope hosts
  csp: +N in-scope host(s) from apex Content-Security-Policy
  no CIDR in profile — skipping ASN/range/tls-SAN/revdns steps
```

---

## 5. Phase 2 — vertical

**subfinder** (passive, all sources), **once per apex** (subfinder applies `-max-time` per domain):
```bash
subfinder -d 0xlumpy.cc -all -max-time <SUBFINDER_MAX_TIME> -stats -silent
```
→ `raw/vertical/subfinder/passive_0xlumpy.cc.txt` · in-scope → `subdomain`.

**crt.sh + certspotter** — native CT-log HTTP lanes per apex (certspotter token-gated for higher limits).
A `*.X` wildcard cert becomes a `wildcard_zone` candidate.

**Censys** (only if `censys: {token, org}` — needs **both**, silent otherwise) — Platform v3 cert search
`cert.names:"0xlumpy.cc"` → `subdomain`.

**github-subdomains** (only if `github:` set), per apex:
```bash
github-subdomains -d 0xlumpy.cc -t <tokens from secrets.yaml>
```

**shosubgo** (only if installed + `shodan:` set) — Shodan subdomain API:
```bash
shosubgo -f <work>/roots.txt -s <shodan-key> -o raw/vertical/shosubgo/sho.txt -fail
```

**puredns brute force** (n0kovo 3M wordlist; trusted resolvers always, public if present; no `--rate-limit`
since `DNS` blank), per apex:
```bash
puredns bruteforce ~/.config/quarry/wordlists/dns.txt 0xlumpy.cc \
  --resolvers-trusted ~/.config/quarry/trusted-resolvers.txt -q
```

**recursive permute → resolve loop** (`alterx` word-cloud mutations; ≤`MAX_ITERS`=3 iterations, stops on
convergence). Each iteration seeds from the **growing** known set, mines patterns, resolves, feeds new hits
back:
```bash
alterx -l <work>/known_N.txt -enrich -mode both -silent
puredns resolve <work>/all_candidates_N.txt \
  --resolvers-trusted ~/.config/quarry/trusted-resolvers.txt --write-massdns … -q
```
→ `resolved` set grows recursively. Console: `recursion iter N: resolved=… (+M new)`.

**CNAME collection** (`TAKEOVER: true`) — feeds takeover analysis in params:
```bash
dnsx -l <work>/resolved_hosts.txt -cname -a -json -silent
```
→ `raw/vertical/dnsx/cnames.jsonl` · each `host → cname` → `review` (klass `cname`; a dangling CNAME —
CNAME with no A — flagged `takeover_candidate`).

```
▸ Vertical subdomain discovery
  subfinder: +N in-scope (… raw, success)
  cnames: N (takeover analysis in params phase)
  subdomains: N  resolved: N
```

---

## 6. Phase 3 — dns

**dnsx record enrichment** over the in-scope resolved set (one pass, wildcard-filtered):
```bash
dnsx -l <work>/resolved.txt -a -aaaa -cname -mx -ns -txt -soa -caa -json -silent
```
→ `raw/dns/dnsx/records.jsonl` · per host → `dns_record` entities (A/AAAA/MX/NS/TXT/SOA/CAA).
No dnsx or no in-scope resolved hosts → recorded skip.

```
▸ DNS-record enrichment (dnsx: A/AAAA/MX/NS/TXT/SOA/CAA)
  dns_record: +N record(s) over M host(s)
```

---

## 7. Phase 4 — probe

**httpx** — full methodology flag set, full 94-port set, over resolved hosts (source of truth for live
services). When active recon is enabled in machine config, `naabu` is available, and hosts have eligible
IPs, a **web-port SYN prefilter** (`probe.naabu_web` → `web_port` entities) narrows the port list first and
httpx probes only the open ones; otherwise httpx probes hosts directly (never a thin run):
```bash
httpx -l <work>/probe_targets.txt -json -silent \
  -ports 80,443,81,300,591,593,832,981,1010,1311,1099,2082,…  (94-port set) \
  -td -title -sc -cl -favicon -cdn -web-server -asn -location -ip -cname -irh \
  -follow-host-redirects -random-agent -timeout 7 -retries 0 -deny <self-deny-list> -t 15
```
→ `raw/probe/httpx/httpx.jsonl` · → `live` (+ `tech` per fingerprint). `-irh` response headers surface CSP
siblings → `subdomain`; deserialization headers → `review` (klass `deser`). `-follow-host-redirects`
follows only same-host 30x; cross-host `Location` is recorded, not followed.

**tlsx certs** over live hosts → `certificate` (+ `subdomain` from SANs).

**Shodan pivots** (only if `shodan:` set; silent otherwise) — two facet lanes, no packets to target:
- `probe.favicon` — `http.favicon.hash` facet over `live` favicons → in-scope `subdomain`, off-scope `review` (related-host).
- `probe.cert` — `ssl.cert.fingerprint` facet over collected cert sha1s → same.

**WAF fingerprint** — nuclei waf-detect templates over live hosts (names the WAF; recon-side, no bypass):
```bash
nuclei -l <work>/waf_targets.txt -pt http,dns -tags waf -jsonl -o raw/probe/nuclei/waf.jsonl
```
→ `tech` (`WAF:<name>`). `httpx -cdn` records detected / detector-negative / unknown CDN state;
none of those states alone asserts that a WAF is absent or that a service is an origin.

**gowitness** screenshots (`SCREENSHOTS: true`):
```bash
gowitness scan file -f <work>/live.txt \
  --screenshot-path raw/probe/gowitness \
  --write-jsonl --write-jsonl-file raw/probe/gowitness/gowitness.jsonl
```
→ `.jpeg`/`.png` → `screenshot`.

**infra ports** — **skipped** (needs `PORTSCAN: true` AND CIDR). With both set:
```bash
naabu -list <cidr> -top-ports 1000 -silent
nmap -sV -Pn -T4 -iL <naabu_ips> -p <open-ports-csv> -oX raw/probe/nmap/service.xml
```
→ `port`.

**smap** passive port scan (only if installed; Shodan-backed, no packets to target):
```bash
smap -iL <work>/smap_targets.txt -oJ raw/probe/smap/smap.json
```
→ `port` (passive).

**shodan_host** (only if `shodan:` set) — the **free** `/shodan/host/{ip}` per-IP passive record lane; runs
last, over every observed in-scope address. No packets to target.
→ `port` (passive) · associated hostnames → `review` (related-host) · banner-inferred CVEs → `review` (shodan-vuln).

```
▸ Probe / fingerprint / screenshots / ports
  httpx: N live services (success)
  waf: N hosts fingerprinted
```

---

## 8. Phase 5 — crawl

**katana** active crawl, storing responses for later mining:
```bash
katana -list <work>/crawl_targets.txt -jc -d 2 -kf all -c 10 -p 10 -timeout 15 -silent \
  -srd raw/crawl/katana_resp  <scope-flags>
```
→ `raw/crawl/katana/katana.txt` · in-scope URLs → `url` (+ `js_url` for `.js`).
(`HEADLESS: false` → the katana `-headless -system-chrome` SPA pass is skipped.)

**gau** passive URLs:
```bash
gau --subs --threads 5 0xlumpy.cc            # → raw/crawl/gau/gau.txt
```

**waymore `-mode B`** — archive URLs **and** responses + inline JS, capped at `WAYMORE_RESPONSES`, per apex
(`-mode U`, URLs only, in passive mode):
```bash
waymore -i 0xlumpy.cc -mode B -oU raw/crawl/waymore/0xlumpy.cc/waymore.txt \
  -f -ci d -p 3 -oR raw/crawl/waymore/0xlumpy.cc -oijs -l 5000
```
The response directory is queued for xnLinkFinder (mined offline, below).

**JS files** — attempt every eligible `.js` URL, host-fair, under a throughput budget (`JS_FETCH_BUDGET_S`);
dedup by content hash, drop <100 bytes or >15 MiB (per-item guard) → `raw/crawl/js_files/`, then beautify
each with `js-beautify -r`. Membership is never capped, but some URLs may remain for a later run (budget),
fail contact, or exceed the guard. A lazy-chunk lane (`jxscout-chunks`) recovers webpack chunk URLs → `js_url`.

**source-map recovery** — scan `sourceMappingURL=` refs + append `.map` to JS URLs, recover
`sourcesContent`, re-mine it → `review` (klass `sourcemap`).

**jsluice** — URLs + secrets from the JS blob (per-sub lanes):
```bash
jsluice urls    -j < <each JS + recovered file>     # → endpoint
jsluice secrets -j < <each JS + recovered file>     # → secret
```

**secret scanners** on the JS dir:
```bash
gitleaks dir raw/crawl/js_files -r raw/crawl/gitleaks/report.json -f json
trufflehog filesystem raw/crawl/js_files --json --no-update --no-verification   # --no-verification dropped if SECRET_VERIFICATION
```
→ `secret` (trufflehog `verified` flag preserved; only sent to provider APIs if `SECRET_VERIFICATION` armed).

**xnLinkFinder** — one source lifecycle (`crawl.xnlinkfinder`) that mines each collected unit
**separately** (JS dir, katana responses, each waymore-response dir, recovered sourcemaps), each fed via
**stdin**, `-d 0` (extract-only, never fetches — its `-sf` scope regex isn't end-anchored, so crawling
archived third-party bodies would reach off-scope hosts). Per-unit state is project-owned and re-ingested
each run:
```bash
# once per unit, under the single lifecycle:
{ printf '\n'; cat <unit files>; } | xnLinkFinder \
  -sp <work>/roots.txt -sf <work>/roots.txt \
  -o links.txt -op params.txt -all -mfs 0 -ow -d 0 \
  [-spo]  [-owl wordlist.txt -os secrets.json]     # -spo per-unit; -owl/-os only on small units
```
`-owl`/`-os` are skipped on large inputs (they hang) — a large dir gets a derived wordlist and its secrets
come from trufflehog/gitleaks/jsluice; `-spo` depends on the unit.
→ `endpoint` + `parameter` (+ `secret` / `review`).

**AST analysis** (`crawl.jxscout_ast`, tool `jxscout-ast`) — **default off** (`MODES.JS_AST`). When armed,
runs last over the JS bundles → `path_observation` + `sink_observation` (client-side sink/flow evidence,
triage reads them).

```
▸ Crawl + URL/archive + JS mining
  katana: +N urls
  gau: +N urls
  JS files downloaded: N
  sourcemap candidates: N (fetch .map -> unminified src)
  urls: N  js: N  endpoints: N  params: N  secrets: N
```

---

## 9. Phase 6 — enrich

Catch-up over hosts discovered *after* vertical + probe (CSP siblings from probe, link-only needles from
crawl). Skipped in passive mode. It re-runs the vertical/probe treatment on the late arrivals, plus the
**A1d recursive brute** (`enrich.a1d_brute` / `enrich.wildcard_a1d`): the crawl-mined, target-specific
vocabulary is re-brute-forced with `puredns` over apexes and any wildcard zones — a scheduled, resumable
sweep bounded per apex. Then `dnsx -a` resolve, `dnsx -cname -a` takeover, and an `httpx` probe over what
resolves.

```
▸ Enrich late-discovered hosts (resolve/takeover/probe)
  A1d: N target-specific word(s) mined from crawl → scheduled re-brute
  enrich: +N resolved · +N live
```

---

## 10. Phase 7 — origin

**Map-only, no packets.** Correlates already-collected evidence (httpx `-cdn`/`-favicon`, tlsx certs) to
propose **CDN de-fronting candidates** — a CDN-fronted host paired with a candidate origin IP:
→ `review` (klass `origin-ip`, `<cdn_host> -> <ip> (matches <host>)`). Skipped in passive mode or when
there are no CDN-fronted hosts to de-front. Confirmation (actually hitting the origin) is deliberately left
to manual/attack work.

---

## 11. Phase 8 — content

**Content discovery — default off** (`MODES.CONTENT_DISCOVERY: off|light|balanced|deep`). When on,
candidate-driven `ffuf` against live, in-scope, active-allowed hosts (CDN-detector-negative-first,
never capped), with a
curated config/secret/VCS/dangerous-endpoint wordlist:
```bash
ffuf -u <live-url>/FUZZ -w <curated-wordlist> -ac -timeout 7 -t 40 -noninteractive …
```
`-ac` autocalibration always (kills wildcard/catch-all floods); `http_rl` → `-rate`. Map-don't-exploit:
results are `url` + `review`. Recursion depth via `MODES.CONTENT_RECURSION` (capped at 5).

---

## 12. Phase 9 — params

**gf vuln-class buckets** over the in-scope URL corpus (**9 patterns**):
```bash
gf xss  < <work>/all_inscope_urls.txt        # then: sqli ssrf redirect lfi idor rce ssti interestingparams
```
→ `review` candidate queues per class.

**subdomain takeover** (`TAKEOVER: true`) — nuclei takeover templates over resolved subs:
```bash
nuclei -l <work>/takeover_targets.txt -pt http,dns -tags takeover -jsonl -o raw/params/nuclei/takeover.jsonl
```
→ `finding` (severity high, `confirmed:false`).

**nuclei broad active verification** with Interactsh OOB over live hosts (chunked/resumable). The selected
medium-through-critical template corpus excludes the `intrusive`, `fuzz`, `dos`, and `brute-force` tags,
but matching templates can still issue state-changing requests, write files, or execute a payload:
```bash
nuclei -l <work>/nuclei_targets.txt -pt <accepted-protocol-lane> -jsonl -o raw/params/nuclei/findings.<lane>.jsonl \
  -etags intrusive,fuzz,dos,brute-force -s critical,high,medium -stats -si 30 \
  -c 25 -bs 25 -nmhe          # -nmhe = full host-error depth (default); -mhe <n> if PERFORMANCE.NUCLEI_MAX_HOST_ERROR set
```
Quarry runs each non-empty accepted protocol lane separately, checkpoints it independently, then publishes
their deterministic union as `raw/params/nuclei/findings.jsonl`.
→ `finding` (`confirmed:false`). Self-hosted interactsh if `oob.callback_server` is set, else nuclei's
public server. stderr → `nuclei.run.log`.

**arjun** param discovery on param-less endpoints (one target per process, bounded/resumable):
```bash
arjun -u <endpoint> -oT raw/params/arjun/<host>.txt -t <n>
```
→ `parameter` / `url` / `review`.

**dalfox — split into three lanes** (dalfox does XSS only; redirect is native):
- `params.dalfox_xss_fast` — dalfox v3 reflected-XSS over canonicalized xss candidates:
  ```bash
  dalfox scan -i file <work>/dalfox_in.txt -o raw/params/dalfox/dalfox_xss_<chunk>.jsonl \
         -f jsonl -S --skip-mining --dedup-urls signature \
         --include-request --include-response --max-targets-per-host <chunk> \
         --workers 30 --max-concurrent-targets 4 [--rate-limit <http_rl>]
  ```
  → `finding` tiered by dalfox's verdict — `V`→`xss-verified`, `R`→`xss-candidate`, `A`→`dom-xss-static` —
  all `confirmed:false`. Exit: 0=no findings, 1=findings, ≥2=error. **Blind XSS** (`--blind-oob`) is armed
  only when `MODES.BLIND_XSS` is set (default off; the secret rides an ephemeral `--config`, never argv).
- `params.redirect_confirm` — **native** single-request open-redirect probe (NO dalfox, NO chromium): inject
  a canary host into redirect-ish params, read the `Location` header **without following it** →
  `finding` (open-redirect-candidate, `confirmed:false`).
- `params.oob_probe` — Quarry-owned interactsh callback on SSRF-ish params → `oob_interaction`.

```
▸ Params + lightweight scanning (nuclei OOB)
  gf candidates: N
  nuclei: N candidate findings (UNCONFIRMED — manual validation required)
```

---

## 13. Reports & exports (always, end of `run`)

```bash
# flat compatibility exports (views over the JSONL store)
exports/{subdomains,resolved,live,urls,js_urls,endpoints,parameters}.txt
exports/secrets.jsonl                       # only if secrets exist

reports/HOTLIST.md       # ranked manual-validation queues with rationale
reports/digest.json      # structured run digest (schema 1.0) — machine-readable HOTLIST
reports/delta.md         # per-source contribution + new-since-previous-run
reports/checkpoints.md   # thin/blocked/timed-out warnings with causes (only if any raised)
manifest.json            # per-tool status taxonomy + entity counts + verdict + profile + notes
metrics/summary.json     # timing/throughput metrics (pointer stored in manifest)
```

State pointers: `recon/state/current → recon/20260620-120000-a1b2c3d4`,
`recon/state/history/20260620-120000-a1b2c3d4.json`.

```
══ complete · ~/projects/0xlumpy/recon/20260620-120000-a1b2c3d4
   HOTLIST: …/reports/HOTLIST.md
   exports: subdomains.txt=N, resolved.txt=N, live.txt=N, urls.txt=N, …
```

(The banner reads `complete`, `complete WITH LIMITS` (a provider/operator bound was hit), or
`complete WITH GAPS` (something failed) — the run's coverage verdict.)

---

## 14. Full output tree

```
~/projects/0xlumpy/
  target.yaml
  osint/<ts>/     candidates.jsonl  intel.jsonl  manifest.json  osint-report.md
                  target.suggested.yaml    # candidate blocks, commented — never auto-scoped
  osint/latest -> <ts>
  recon/20260620-120000-a1b2c3d4/
    manifest.json  run.json
    raw/
      horizontal/{kaeferjaeger/matches.txt, csp/csp.txt}
      vertical/{subfinder/passive_*.txt, crtsh/…, certspotter/…, censys/…, github-subdomains/…,
                shosubgo/…, puredns/{brute-*,resolved.txt}, alterx/perms.txt, dnsx/cnames.jsonl}
      dns/dnsx/records.jsonl
      probe/{httpx/httpx.jsonl, naabu/…, tlsx/…, nuclei/waf.jsonl, gowitness/*.jpeg+gowitness.jsonl,
             smap/smap.json, shodan/…}
      crawl/{katana/katana.txt, katana_resp/…, gau/gau.txt, waymore/0xlumpy.cc/…, js_files/*.js,
             sourcemaps/…, jsluice/{urls,secrets}.jsonl, xnLinkFinder/*, gitleaks/report.json,
             trufflehog/out.jsonl}
      enrich/{puredns/…, dnsx/…, httpx/…}
      content/ffuf/…              # only if CONTENT_DISCOVERY on
      params/{gf/*.txt, nuclei/{findings,takeover}.jsonl+nuclei.run.log, arjun/*.txt, dalfox/*.jsonl}
      oob/session/session.json    # if the OOB callback lane opened a session
    normalized/                   # one .jsonl per entity (23 types):
      subdomain resolved dns_record live url js_url endpoint parameter secret ip certificate port
      web_port finding screenshot tech review wildcard_zone ownership_transition gadget_candidate
      path_observation sink_observation oob_interaction
    exports/   …flat .txt views + secrets.jsonl
    reports/   HOTLIST.md  digest.json  delta.md  checkpoints.md
    metrics/summary.json
    work/      …intermediate input lists (roots.txt, all_candidates.txt, …)
    events.jsonl                  # per-source lifecycle event stream
  recon/state/current -> recon/20260620-120000-a1b2c3d4
  recon/campaigns/<id>/           # only from `--settle` (ledger.json + union)
```

---

## 15. Variations

```bash
# passive only — no active probing (httpx/katana-active/nuclei/dalfox/naabu/waf/enrich/origin skipped;
# kaeferjaeger, subfinder, CT lanes, gau, waymore -mode U still run)
quarry run -t 0xlumpy --passive

# one or more phases
quarry run -t 0xlumpy --phases vertical
quarry run -t 0xlumpy --phases probe,crawl

# lift free-tool volume ceilings (obtains no new sources; never changes scope/rate/spend)
quarry run -t 0xlumpy --unbound

# supervisor: keep creating child runs while resumable work still advances (acquisition closed from child 2)
quarry run -t 0xlumpy --settle --settle-max-runs 10 --settle-budget 7200

# static dry-run — explain what would run (registry + machine settings), scan nothing
quarry plan

# regenerate HOTLIST/digest/delta + exports from a stored run, no scanning
quarry report -t 0xlumpy

# per-source state of the latest run (from events.jsonl)
quarry status -t 0xlumpy

# out-of-band callbacks: pull delayed interactsh hits, or import an external -json log
quarry oob poll -t 0xlumpy --wait 8
quarry oob import interactsh.jsonl -t 0xlumpy

# effective coverage policy (bounds, values, who set them) — runs nothing
quarry policy -t 0xlumpy

# detached on a VPS
setsid nohup quarry run -t 0xlumpy > run.log 2>&1 & disown
```

---

### Notes on this trace

- Most tools are gated with a **recorded** `skipped` (missing tool, passive-only, no CIDR, no key —
  visible, not silent). A few lanes skip **silently** by design when their tool/key is absent: Censys and
  OpenINTEL (advanced opt-ins), and `shosubgo` (missing binary or unset `shodan:` key).
- Scanner output (`nuclei`/`dalfox`/takeover) is stored as `finding` with `confirmed:false` —
  candidates for manual validation, never asserted as bugs. Shodan pivots, origin correlation, and
  content discovery are **map-only**.
- WAF handling is recon-side: `httpx -cdn` records a CDN detector state, the `-tags waf` pass can
  positively name a WAF, and the checkpoint flags a WAF-*blocked* nuclei. Detector-negative and
  unknown results never become "no WAF" or proven-origin claims. Bypass (nomore403/nowafpls/NewTowner) is
  intentionally human/Burp work.
