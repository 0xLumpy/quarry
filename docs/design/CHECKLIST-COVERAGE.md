# Quarry Coverage Tracker

> **Verified state 2026-08-03 (`2bcd00a`): LIVING DOCUMENT.** This is the TBHM Phase-1 coverage ledger — do not build a second one. Update a row when its status changes; open gaps belong in the operator's verified backlog, kept outside this repo.


Living map: `QUARRY-METHODOLOGY-VALIDATION.md` (the 17-phase methodology) → framework reality.
Build new work (esp. the Phase 13/14 digest) **against this**, not vibes. Update a row when its
status changes.

**Status:** ✅ implemented · 🟡 partial · 👤 manual (by-design prompt, surfaced to the human) ·
🔮 future (roadmap) · ⚔️ private (attack-side / downstream manual+AI handoff)

| Phase | Status | Quarry locus | Notes / gaps |
|------|:---:|---|---|
| 0 Scope review + profile | ✅ | `init` · `target.yaml` · `oos` · RATELIMIT · NOTES | gap: platform-scope API (H1/Bugcrowd/Intigriti) + disclosed-report dedup are 👤 |
| 1 Pre-flight OSINT | ✅ | `osint.py` + `docs/osint-broadening.md` | Automated: `asnmap`·`azmap`·`dig`-DMARC·`whois`·`whoxy`·`porch-pirate` + **RDAP candidate enrichment (1A)** + **key-health (1A)**; manifest now redacts cmd/note. Web-gated sources (bgp.he.net/CAIDA/RDAP-UI, acquisitions, BuiltWith, cloud-cert) → 👤 **documented playbook (1B)**, report points to it. 1C `osint --import` deferred. |
| 2 Scope consolidation | ✅ | human-confirm → `target.yaml` | the map-don't-exploit seam; humans approve candidates |
| 3 Passive subdomains | ✅ | vertical (`subfinder`·`github-subdomains`·`shosubgo`) | |
| 4 DNS brute/resolve/permute/recurse | ✅ | vertical (`puredns`·`alterx`·`dnsx` + recursion loop) | wildcard→HTTP differentiation still 🔮 (v0.3) |
| 5 Horizontal / cert + relationship loops | 🟡 | horizontal (`asnmap`·`mapcidr`·`tlsx`·`caduceus`·`csprecon`·kaeferjaeger) + CSP-via-probe | **watch items:** kaeferjaeger 403; Caduceus/tlsx fragility |
| 6 HTTP probe / fingerprint / screenshots | ✅ | probe (`httpx`·`gowitness`·`smap`) + enrich | core ✅; late hosts (crawl/CSP) now get WAF+screenshot+smap via enrich (verified 2026-07-04). Only the full recrawl loop is 🔮 |
| 7 Port scan / service | 🟡 | probe (`naabu`·`smap`) + enrich | ✅ when CIDR present; late hosts get enrich smap now. naabu still CIDR-gated |
| 8 Crawl / historical URLs / response mining | ✅ | crawl (`katana`·`gau`·`waymore`·`xnLinkFinder`) | |
| 9 JS collect / beautify / endpoint extract | ✅ | crawl (`jsluice` · downloads · **beautify** · **sourcemap unpack 9.1** · **deep-mine 9.2**) | unpacks `.map`→recovered source + re-mines; extracts graphql/websocket/api-base. Follow-on: surface those `kind`s in `digest.json` (tracked in M2-DIGEST-DESIGN) |
| 10 Endpoint + parameter consolidation | ✅ | crawl·params·enrich (`jsluice`·`gf`·`arjun`→`dalfox`) | strong after arjun→dalfox + enrich feedback |
| 11 Content discovery / path brute | ✅ | `content` phase (ffuf, off by default) | candidate-driven, scope-safe, `-ac` autocalibration; `MODES.CONTENT_DISCOVERY: off\|light\|balanced\|deep` + `CONTENT_RECURSION` (balanced/deep). Design: PHASE11-DESIGN.md. Follow-ons: digest surfacing, tailored wordlist |
| 12 Scanner candidates / LHF | ✅ | params (`nuclei`·`dalfox`·takeover) | candidates only, `confirmed=false` |
| 13 Prioritization / heat map | 🟡 | `triage.py` (INTEREST·VULN_PARAMS·heat) | → fuller digest **v0.4**. **Highest-leverage next build.** |
| 14 Pre-hunt intel / handoff | 🟡 | `exports.py`·`triage.py` | AI/digest handoff = v0.4; the bridge to quarry-attack/hackbots |
| 15 Manual vuln testing queues | ⚔️ | `review_item` / `private_test_queue` entities | attack-side + 👤 manual; **not** quarry-recon scope |
| 16 Reporting / continuous | 🟡 | `manifest.json`·`exports`·`osint_report.py` | PoC/report builder = 🔮 future |

## Cross-cutting watch items
- **enrich follow-on** (Phase 6/7/8): late-discovered hosts reach params/nuclei but get **no screenshot, WAF detection, smap, or recrawl** this run. Logged in ROADMAP.
- **kaeferjaeger 403** + **Caduceus/tlsx fragility** (Phase 5) — keep an eye; CSP-via-probe partly compensates.
- **wildcard→HTTP differentiation** (Phase 4) — 🔮 v0.3.
- **secret redaction** — ✅ done (mask+fingerprint across gitleaks/trufflehog/jsluice).

## Highest-leverage automatable gaps (build order, rough)
1. **Phase 13/14 digest + handoff** (v0.4) — ranked, provenance-rich, quarry-attack/hackbot-ready output. The bridge to the offensive side.
2. **Phase 1 OSINT automation** — convert `MANUAL_TODO` items that *can* be automated (RDAP/ASN, linked-seeds, Shodan-passive); leave inherently-web ones (bgp.he.net browsing) as prompts.
3. **Phase 11 content discovery** (v0.5) — the one whole missing phase.
4. **Phase 9 JS depth** — sourcemap unpacking, beautify, deeper route mining.
5. **Phase 6/7 enrich follow-on** — screenshot/WAF/smap/recrawl for late hosts.
6. **Phase 0 platform-scope API** + **Phase 16 report builder**.

## Framework validation rubric (apply per phase)
Systemic answers to the checklist's per-phase QA questions:
- raw evidence ✅ · normalized output ✅ · provenance (source/reason/confidence/raw-ref) ✅
- OOS + passive respected ✅ · rate-limits only-when-configured ✅
- failures/timeouts/blocks distinguishable from empty ✅ (status taxonomy)
- scanner findings marked unconfirmed ✅ (`confirmed=false`)
- candidate scope expansions human-reviewed ✅ (osint is review-only)
- private-layer separate from immutable recon evidence ✅ (`review_item`/`private_test_queue`)
- newly-discovered fed into correct queues 🟡 (enrich closed crawl/CSP→resolve/takeover; recrawl loop 🔮)
- report shows confidence/reason/source 🟡 (→ digest v0.4)
- API-docs/GraphQL/WS/mobile/OAuth-JWT/cloud/CICD normalized into queues 🔮 (mostly not yet)
- OOB approved+configured before any callback 🔮

## Tool-integration discipline
Per-tool mini-record required before add/change (Tool·Purpose·docs·install·version·deps·keys·
cmd·IO·exit-codes·failure-modes·timeout/rate·security·entities·raw·normalizer·consumers·verify).
Known special cases — status:
- gitleaks nonzero = leaks found ✅ · dnsx CNAME incl. non-A-resolved known subs ✅ ·
  httpx response headers for CSP ✅ · katana response-store→xnLinkFinder ✅ · waymore response mode ✅
- dalfox consumes clean candidate lists ✅ · ffuf same 🔮 (v0.5)
- subfinder `-stats` key-health 🔮 · nuclei knobs documented 🟡
- porch-pirate/Swagger must feed normalized endpoint/param stores (not just write a file) → ✅ **DONE (parse_openapi writes endpoint/parameter entities into the store)**
- GitHub code-search qualifiers + source refs 🔮 · interactsh config/redaction/approval 🔮
- source-code public-intel vs in-scope distinction 🔮 (code-host-intel)

## Open validation gaps → status
- Re-probe CSP/crawl hosts same run → ✅ DONE (enrich) · output-hygiene spot-check → ✅ DONE (v0.2)
- CNAME-only brute discovery → 🔮 ROADMAP · OOB/interactsh integration → 🔮 ROADMAP
- RDAP automation IP→owner→CIDR → ✅ **DONE (osint.py RDAP candidate enrichment)** · acquisition/subsidiary scoring → 🔮 (Phase 1)
- tool-native key-health beyond subfinder → 🔮
- private AI digest schema (files consumed/created, immutable evidence) → 🔮 v0.4
- platform scope retrieval schema (H1/Bugcrowd/Intigriti, platform-neutral) → 🔮 (Phase 0)
- API-doc parsing (Swagger/OpenAPI/Postman/GraphQL → normalized endpoints/params) → ✅ **DONE for OpenAPI/Swagger (evidence.parse_openapi → endpoint+param corpus) + GraphQL introspection (probe_graphql); Postman = porch-pirate in osint**
- source-code/changelog/disclosed-report intel: public-recon vs private-attack split → 🔮 (code-host-intel + ⚔️)
- OAuth/OIDC/JWT classification (tag auth-flow endpoints, never test) → 🔮 NEW
- cloud/container/mobile candidate queues (map, don't expand scope) → 🔮 NEW

## NEW items surfaced (not yet in ROADMAP)
API-doc parsing → normalized endpoints · OAuth/JWT endpoint tagging · cloud/mobile candidate
queues · RDAP automation · acquisition scoring · tool key-health · platform-scope schema ·
private-AI-digest schema definition. (Feed these into the ROADMAP re-sequencing.)

---
*Source: the 17-phase methodology validation checklist (operator-private, kept outside this repo). Pair every phase/step with implemented/partial/manual/future/private as the framework evolves.*
