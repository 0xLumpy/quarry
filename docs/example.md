# Example run — `0xlumpy.cc`, start to finish

A complete walk-through of what `quarry` **would** execute against `0xlumpy.cc`, traced from
the current code, command by command, in order. Nothing here was run — it documents the exact
tool invocations, the order, the scope/skip gating, and the artifacts produced.

Assumptions:

- Authorized target `0xlumpy.cc` — single apex, **no CIDR in scope** (common bug-bounty case)
- Tools installed (`quarry install` done), API keys configured where available
- `PATH` includes `~/go/bin` and `~/.local/bin`
- Output lands in the project dir `./projects/0xlumpy/` (profile + osint + recon together)
- Illustrative run id: `20260620-120000`

---

## 0. One-time setup

```bash
pipx install /home/kali/workspace/quarry    # installs the `quarry` command
quarry install                              # system pkgs → Go (latest stable) → tools → wordlists/templates
quarry doctor                               # audit: tools, versions, deps, keys, resolvers
```

`doctor` confirms recon tools on `PATH`, chromium present (gowitness needs it), and
`~/.config/quarry/{resolvers.txt,trusted-resolvers.txt} and ~/.config/quarry/wordlists/dns.txt` exist.

---

## 1. Create the target profile

```bash
quarry init 0xlumpy
```

`projects/0xlumpy/target.yaml`:

```yaml
TARGET: 0xlumpy

APEX_DOMAINS:
  - 0xlumpy.cc

OOS:
  - '^jobs\.'
  - '^careers\.'

CIDR:          # empty → horizontal IP/port steps SKIPPED
ASN:           # empty → ASN only suggests candidates

RATELIMIT:
  HTTP:        # empty → tool defaults (fast); set only for a program's RoE cap
  DNS:         # empty → puredns/massdns default (no --rate-limit)
  PORTSCAN:    # empty → naabu default

PORTS:
  HTTP:        # empty → full methodology port set (~94 ports)

LIMITS:
  WAYMORE_RESPONSES: 5000

MODES:
  PASSIVE_ONLY: false
  HEADLESS: false
  SCREENSHOTS: true
  PORTSCAN: true
  TAKEOVER: true
```

> Bigger target? See `target-prep.md` for how to fill `APEX_DOMAINS`/`OOS`/`CIDR`/`ASN` from
> OSINT (M365 tenant, reverse-whois, ASN lookups, acquisitions, cloud cert dumps).

---

## 2. Launch

```bash
quarry run -t projects/0xlumpy/target.yaml
```

Run phases execute in order `horizontal → vertical → probe → crawl → params` (OSINT is a
separate pre-flight — §3 — run *before* this, on the confirmed scope). Each tool call captures
stdout/stderr/exit/duration, writes raw output under `raw/<phase>/<tool>/`, classifies the
result, and normalizes parsed entities into `normalized/*.jsonl`. After each phase the
checkpoint engine evaluates coverage. Run dir: `projects/0xlumpy/recon/20260620-120000/`.

```
══ Quarry run 20260620-120000 · target=0xlumpy · ACTIVE ══
   apexes=1 cidr=0 ports=[80, 443, 81, 300, …  (94 ports)]  http_rl=default
```

---

## 3. Pre-flight — `quarry osint` (separate command, run before §2)

```bash
quarry osint -t projects/0xlumpy/target.yaml      # → projects/0xlumpy/osint/<ts>/{osint-report.md, target.suggested.yaml, …}
```

Apex/org/leak discovery (all passive — queries third parties, not the target). Discovered
apexes are **candidates** written to a review report + `target.suggested.yaml` — **never
auto-added to scope**. You confirm + copy the good ones into `target.yaml`, then run §2.
Sub-steps below show what it does:

**0.1 azmap.dev M365/Azure tenant** (in-process HTTP, no key) — related/sibling apexes:
```
GET https://azmap.dev/api/tenant?domain=0xlumpy.cc&extract=true
```
→ `related_domains` → `review` (klass `apex-candidate`) + the tenant name → `org-context`.

**0.2 whois** (no key) — registrant org/email (the email seeds whoxy):
```bash
whois 0xlumpy.cc        # → raw/osint/whois/0xlumpy.cc.txt; registrant org → org-context
```

**0.3 DMARC pivot** (no key) — related apexes from the rua/ruf addresses:
```bash
dig +short TXT _dmarc.0xlumpy.cc     # rua=mailto:..@DOMAIN → apex-candidate (3rd-party processors flagged)
```

**0.4 whoxy reverse-whois** (only if `whoxy:` is set in secrets.yaml) — sibling apexes
by registrant email:
```
GET https://api.whoxy.com/?key=<KEY>&reverse=whois&email=<registrant-email>
```
→ `domainsList` → `review` (apex-candidate). Without the key: `skipped` (recorded).

**0.5 porch-pirate** (only if installed; no key) — public Postman API leaks:
```bash
porch-pirate -s 0xlumpy.cc --urls      # in-scope URLs → endpoint; out-of-scope → review
```

```
══ Quarry osint · target=0xlumpy (pre-flight, review-only) ══
  azmap[0xlumpy.cc]: N related domains
══ osint done · projects/0xlumpy/osint/<ts>
   report:    …/osint-report.md
   suggested: …/target.suggested.yaml
   N apex candidate(s) — review, confirm scope, add to target.yaml
```

> Candidates are **suggestions** — review `osint-report.md`, confirm ownership + scope,
> uncomment approved entries from `target.suggested.yaml` into `target.yaml`, then run §2.
> See `target-prep.md`.

---

## 4. Phase 1 — horizontal

No CIDR → all IP-range steps skip. Two things run:

**3.1 kaeferjaeger SNI dataset** (passive, in-process HTTP — not a shelled tool). Downloads
each provider's cert dump, greps for `0xlumpy.cc`:

```
GET https://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_merged_sni.txt
GET https://kaeferjaeger.gay/sni-ip-ranges/google/ipv4_merged_sni.txt
GET https://kaeferjaeger.gay/sni-ip-ranges/microsoft/ipv4_merged_sni.txt
GET https://kaeferjaeger.gay/sni-ip-ranges/oracle/ipv4_merged_sni.txt
GET https://kaeferjaeger.gay/sni-ip-ranges/digitalocean/ipv4_merged_sni.txt
```
→ raw `raw/horizontal/kaeferjaeger/sni.txt` · in-scope hosts → `subdomain`.

**3.2 csprecon** (only if installed; light HTTP, reads CSP headers):

```bash
csprecon -l <work>/roots.txt -s
```
→ raw `raw/horizontal/csprecon/csp.txt` · in-scope CSP domains → `subdomain`.

**Skipped** (no CIDR): `mapcidr`, `tlsx` SAN, `dnsx -ptr`, `caduceus`, `asnmap` — each
recorded `skipped` with a reason in the manifest.

> With `CIDR` set, these would also run:
> ```bash
> mapcidr -cidr 192.0.2.0/24 -silent
> tlsx -l <ips> -san -cn -silent -p 443,8443,4443 -resp-only
> dnsx -l <ips> -ptr -resp-only -silent
> caduceus -i <cidr> -p 443,8443,4443 -j        # ASN→cert, behind-CDN hostnames
> ```
> and with `ASN` set: `echo AS<N> | asnmap -silent` (context).

```
▸ Horizontal discovery (ASN/CIDR/cert/SAN)
  kaeferjaeger: +N in-scope hosts
  csprecon: +N in-scope hosts from CSP
  no CIDR in profile — skipping ASN/range/tls-SAN/revdns steps
```

---

## 5. Phase 2 — vertical

**4.1 subfinder** (passive, all sources, `-stats` → per-key health to stderr):

```bash
subfinder -dL <work>/roots.txt -all -recursive -stats -silent
```
→ raw `raw/vertical/subfinder/passive.txt` · in-scope → `subdomain`.

**4.2 github-subdomains** (only if `github:` is set in secrets.yaml), per apex:

```bash
github-subdomains -d 0xlumpy.cc -t <tokens materialized from secrets.yaml>
```

**4.3 shosubgo** (only if installed + `shodan:` set in secrets.yaml):

```bash
shosubgo -f <work>/roots.txt -s <shodan-key> -o raw/vertical/shosubgo/sho.txt
```

**4.4 puredns brute force** (n0kovo 3M wordlist; trusted resolvers always, public resolvers
if present; no `--rate-limit` since `DNS` blank), per apex:

```bash
puredns bruteforce ~/.config/quarry/wordlists/dns.txt 0xlumpy.cc \
  --resolvers-trusted ~/.config/quarry/trusted-resolvers.txt \
  -r ~/.config/quarry/resolvers.txt -q
```

**4.5 recursive permute → resolve loop** (word-cloud mutations; ≤3 iterations, stops on
convergence). Each iteration seeds from the **growing** known set (subdomains + apexes +
already-resolved), mines target-specific patterns, resolves, feeds new hits back:

```bash
# iteration N (N = 1..3):
alterx -l <work>/known_N.txt -enrich -mode both -silent      # word-cloud: extract + mine patterns
puredns resolve <work>/all_candidates_N.txt \
  --resolvers-trusted ~/.config/quarry/trusted-resolvers.txt \
  -r ~/.config/quarry/resolvers.txt -q
# newly-resolved permutations → added as subdomains → seed iteration N+1
# loop ends when an iteration resolves nothing new (or after 3)
```
→ `resolved` set grows recursively. `-enrich` extracts words from observed names; `-mode both`
= default + target-mined patterns (target-specific mutation). Console: `recursion iter N:
resolved=… (+M new)`.

**4.7 CNAME collection** (`TAKEOVER: true`) — feeds takeover analysis in params:

```bash
dnsx -l <work>/resolved_hosts.txt -cname -json -silent
```
→ raw `raw/vertical/dnsx/cnames.jsonl` · each `host → cname` → `review` (klass `cname`).

```
▸ Vertical subdomain discovery
  subfinder: +N in-scope (… raw, success)
  cnames: N (takeover analysis in params phase)
  subdomains: N  resolved: N
```

---

## 6. Phase 3 — probe

**5.1 httpx** — full methodology flag set, full ~94-port set, RoE rate 5, over resolved hosts
(source of truth for live services):

```bash
httpx -l <work>/probe_targets.txt -json -silent \
  -ports 80,443,81,300,591,593,832,981,1010,1311,1099,2082,…  (full 94-port set) \
  -td -title -sc -cl -favicon -cdn -web-server -asn -location -ip -cname \
  -follow-redirects -no-fallback -probe-all-ips -random-agent -t 15
```
→ raw `raw/probe/httpx/httpx.jsonl` · → `live` entities (+ `tech` per fingerprint).

**5.2 WAF fingerprint** — nuclei waf-detect templates over live hosts (which WAF fronts each
host; recon-side only, no bypass):

```bash
nuclei -l <work>/waf_targets.txt -tags waf -jsonl -o raw/probe/nuclei/waf.jsonl
```
→ `tech` entities (`WAF:<name>`). `httpx -cdn` already tags CDN vs origin; this names the WAF.

**5.3 gowitness** screenshots (`SCREENSHOTS: true`):

```bash
gowitness scan file -f <work>/live.txt \
  --screenshot-path raw/probe/gowitness \
  --write-db --write-jsonl --write-jsonl-file raw/probe/gowitness/gowitness.jsonl
```
→ `.jpeg`/`.png` → `screenshot` entities.

**5.4 ports** — **skipped** (no CIDR): `skipped("naabu", "no in-scope CIDR")`.

> With `CIDR` set, naabu runs, then nmap only on the open ports it finds:
> ```bash
> naabu -list <cidr> -top-ports 1000 -silent
> nmap -sV -Pn -T4 -iL <naabu_ips> -p <open-ports-csv> -oN raw/probe/nmap/service.txt
> ```

**5.5 smap** passive port scan (only if installed; Shodan-backed, no packets to target):

```bash
smap -iL <work>/smap_targets.txt             # → raw/probe/smap/smap.txt
```

```
▸ Probe / fingerprint / screenshots / ports
  httpx: N live services (success)
  waf: N hosts fingerprinted
```

---

## 7. Phase 4 — crawl

**6.1 katana** active crawl, storing responses for later mining:

```bash
katana -list <work>/crawl_targets.txt -jc -d 2 -kf all -c 4 -p 3 -timeout 15 -silent \
  -srd raw/crawl/katana_resp
```
→ raw `raw/crawl/katana/katana.txt` · in-scope URLs → `url` (+ `js_url` for `.js`).
(`HEADLESS: false` → the `katana -headless -system-chrome` SPA pass is skipped.)

**6.2 gau** passive URLs:

```bash
gau --subs --threads 5 0xlumpy.cc            # → raw/crawl/gau/gau.txt
```

**6.3 waymore `-mode B`** — archive URLs **and** responses + inline JS, capped 5000, per apex:

```bash
waymore -i 0xlumpy.cc -mode B -oU raw/crawl/waymore/0xlumpy.cc/waymore.txt \
  -f -ci d -p 3 -oR raw/crawl/waymore/0xlumpy.cc -oijs -l 5000
```
Then xnLinkFinder mines that response directory (depth 3 — the "killer combo"):
```bash
xnLinkFinder -i raw/crawl/waymore/0xlumpy.cc \
  -sp <work>/roots.txt -sf <work>/roots.txt \
  -o  …waymore-0xlumpy_cc_links.txt -op …params.txt -os …secrets.json -owl …wordlist.txt \
  -inc -all -mfs 0 -orig -spo \
  -d 3 -u desktop mobile -insecure -s429 -s403 -sTO -sCE
```

**6.4 JS files** — download every discovered `.js` (≤2000), dedup by content hash, drop
<100 bytes → `raw/crawl/js_files/`, then beautify:

```bash
js-beautify -r raw/crawl/js_files/<hash>.js   # per file
```

**6.5 source-map recovery** — scan `sourceMappingURL=` refs + append `.map` to every JS URL →
`review` (klass `sourcemap`). Raw `raw/crawl/sourcemaps/candidates.txt`.

**6.6 jsluice** — URLs + secrets from the JS blob:

```bash
jsluice urls    -   < (all js_files)          # → endpoint entities
jsluice secrets -   < (all js_files)          # → secret entities
```

**6.7 xnLinkFinder over the JS dir** (depth 0, static):

```bash
xnLinkFinder -i raw/crawl/js_files -sp <work>/roots.txt -sf <work>/roots.txt \
  -o js_links.txt -op js_params.txt -os js_secrets.json -owl js_wordlist.txt -inc -all -mfs 0
```
→ `endpoint` + `parameter`.

**6.8 xnLinkFinder over katana's stored responses** (`-srd` dir from 6.1):

```bash
xnLinkFinder -i raw/crawl/katana_resp -sp <work>/roots.txt -sf <work>/roots.txt \
  -o katana-resp_links.txt -op …params.txt -os …json -owl …txt -inc -all -mfs 0 -orig
```

**6.9 secret scanners** on the JS dir:

```bash
gitleaks detect --no-git -s raw/crawl/js_files -r raw/crawl/gitleaks/report.json -f json
trufflehog filesystem raw/crawl/js_files --json --no-update   # → raw/crawl/trufflehog/out.jsonl
```
→ `secret` entities (trufflehog `verified` flag preserved).

```
▸ Crawl + URL/archive + JS mining
  katana: +N urls
  gau: +N urls
  JS files downloaded: N
  sourcemap candidates: N (fetch .map -> unminified src)
  urls: N  js: N  endpoints: N  params: N  secrets: N
```

---

## 8. Phase 5 — params

**7.1 gf vuln-class buckets** over the in-scope URL corpus (9 patterns):

```bash
gf xss               < <work>/all_inscope_urls.txt    # → review (klass xss)
gf sqli              < …
gf ssrf              < …
gf redirect          < …
gf lfi               < …
gf idor              < …
gf rce               < …
gf ssti              < …
gf interestingparams < …
```
→ `review` candidate queues per class. Raw `raw/params/gf/<pat>.txt`.

**7.2 subdomain takeover** (`TAKEOVER: true`) — nuclei takeover templates over resolved subs:

```bash
nuclei -l <work>/takeover_targets.txt -tags takeover -jsonl \
  -o raw/params/nuclei/takeover.jsonl
```
→ matches → `finding` (severity high, `confirmed:false`).

**7.3 nuclei** non-intrusive scan with built-in interactsh OOB over live hosts:

```bash
nuclei -l <work>/nuclei_targets.txt -jsonl -o raw/params/nuclei/findings.jsonl \
  -etags intrusive,fuzz,dos,brute-force -s critical,high,medium -stats -si 30 -c 25
```
→ `finding` (`confirmed:false`). stderr (filtering/blocking) → `nuclei.run.log`.

**7.4 arjun** param discovery on param-less API endpoints (≤40, throttled):

```bash
arjun -i <work>/arjun_targets.txt -oT raw/params/arjun/arjun.txt -t 5 -d 1
```

**7.5 dalfox** on the gf xss + redirect candidates (throttled):

```bash
dalfox file <work>/dalfox_in.txt --delay 250 -w 5 --skip-bav -o raw/params/dalfox/dalfox.txt
```
→ PoC lines → `finding` (`confirmed:false`).

```
▸ Params + lightweight scanning (nuclei OOB)
  gf candidates: N
  nuclei: N candidate findings (UNCONFIRMED — manual validation required)
```

---

## 9. Reports & exports (always, end of `run`)

```bash
# flat compatibility exports (views over the JSONL store)
exports/{subdomains,resolved,live,urls,js_urls,endpoints,parameters}.txt
exports/secrets.jsonl

reports/delta.md         # per-source contribution + new-since-previous-run
reports/HOTLIST.md       # ranked manual-validation queues with rationale
reports/checkpoints.md   # thin/blocked/timed-out warnings with stated causes
manifest.json            # per-tool status taxonomy + entity counts + profile + notes
```

State pointers: `recon/state/current → recon/20260620-120000`, `recon/state/history/20260620-120000.json`.

```
══ done · projects/0xlumpy/recon/20260620-120000
   HOTLIST: projects/0xlumpy/recon/20260620-120000/reports/HOTLIST.md
   exports: subdomains.txt=N, resolved.txt=N, live.txt=N, urls.txt=N, …
```

---

## 10. Full output tree

```
projects/0xlumpy/
  target.yaml
  osint/<ts>/      candidates.jsonl  intel.jsonl  osint-report.md  target.suggested.yaml
  osint/latest -> <ts>
  recon/20260620-120000/
    manifest.json
    raw/
      horizontal/{kaeferjaeger/sni.txt, csprecon/csp.txt}
      vertical/{subfinder/passive.txt, github-subdomains/…, puredns/{brute-*,resolved.txt},
                alterx/perms.txt, dnsx/cnames.jsonl}
      probe/{httpx/httpx.jsonl, nuclei/waf.jsonl, gowitness/*.jpeg+gowitness.jsonl, smap/smap.txt}
      crawl/{katana/katana.txt, katana_resp/…, gau/gau.txt, waymore/0xlumpy.cc/…,
             js_files/*.js, sourcemaps/candidates.txt, jsluice/{urls,secrets}.jsonl,
             xnLinkFinder/*, gitleaks/report.json, trufflehog/out.jsonl}
      params/{gf/*.txt, nuclei/{findings,takeover}.jsonl+nuclei.run.log, arjun/arjun.txt, dalfox/dalfox.txt}
    normalized/
      subdomain.jsonl  resolved.jsonl  live.jsonl  tech.jsonl  url.jsonl  js_url.jsonl
      endpoint.jsonl   parameter.jsonl secret.jsonl review.jsonl finding.jsonl  screenshot.jsonl
    exports/   …flat .txt views + secrets.jsonl
    reports/   HOTLIST.md  delta.md  checkpoints.md
    work/      …intermediate input lists (roots.txt, all_candidates.txt, …)
  recon/state/current -> recon/20260620-120000
```

---

## 11. Variations

```bash
# passive only — no active probing (httpx/katana-active/nuclei/dalfox/naabu/waf skipped;
# kaeferjaeger, subfinder, gau, waymore -mode U still run)
quarry run -t projects/0xlumpy/target.yaml --passive

# one phase at a time
quarry run -t projects/0xlumpy/target.yaml --phases vertical
quarry run -t projects/0xlumpy/target.yaml --phases probe

# regenerate reports/exports from the stored run, no scanning
quarry report

# detached on a VPS
setsid nohup quarry run -t projects/0xlumpy/target.yaml > run.log 2>&1 & disown
```

---

### Notes on this trace

- Every tool is gated: missing tool → `skipped` (recorded, not silent); passive-only → active
  tools skipped; no CIDR → IP-range steps skipped; no keys → key-gated sources skipped.
- Scanner output (`nuclei`/`dalfox`/takeover) is stored as `finding` with `confirmed:false` —
  candidates for manual validation, never asserted as bugs.
- WAF handling is recon-side: `httpx -cdn` tags CDN/origin, the `-tags waf` pass names the WAF,
  and the checkpoint flags a WAF-*blocked* nuclei. Bypass (nomore403/nowafpls/NewTowner) is
  intentionally human/Burp work.
```
