# Quarry methodology coverage snapshot (historical)

> **Status (audited 2026-08-11 at `4e4825c`): historical self-assessment; not a current closure or
> release ledger.** The symbols below record claimed feature presence at the 2026-08-03 snapshot. They do
> not prove correctness, completeness, current behavior, or release readiness.

The current authorities are the [product contract](../governance/PRODUCT-CONTRACT.md),
[`CURRENT-HEAD.md`](../audit/CURRENT-HEAD.md), the [`v0.3.10` release ledger](../releases/v0.3.10.md), and
the [roadmap](../roadmap.md). Future methodology gaps must be recorded there rather than in an
operator-private off-repository backlog. This snapshot remains useful for reconstructing design intent.

Historical map: the operator-private `QUARRY-METHODOLOGY-VALIDATION.md` (17-phase methodology) → the
framework state claimed at that time. Do not update these symbols as current closure evidence.

**Historical status legend:** ✅ implemented · 🟡 partial · 👤 manual (by-design prompt, surfaced to the human) ·
🔮 future (roadmap) · ⚔️ private (attack-side / downstream manual+AI handoff)

| Phase | Status | Quarry locus | Notes / gaps |
|------|:---:|---|---|
| 0 Scope review + profile | ✅ | `init` · `target.yaml` · `oos` · RATELIMIT · NOTES | gap: platform-scope API (H1/Bugcrowd/Intigriti) + disclosed-report dedup are 👤 |
| 1 Pre-flight OSINT | ✅ | `osint.py` + `docs/osint-broadening.md` | Automated: `asnmap`·`azmap`·`dig`-DMARC·`whois`·`whoxy`·`porch-pirate` + **RDAP candidate enrichment (1A)** + **key-health (1A)**. The snapshot's command/note masking is not proof of the current credential/evidence boundary: canonical/private target evidence must remain lossless while Quarry-owned credentials are excluded by construction. Web-gated sources (bgp.he.net/CAIDA/RDAP-UI, acquisitions, BuiltWith, cloud-cert) → 👤 **documented playbook (1B)**, report points to it. 1C `osint --import` deferred. |
| 2 Scope consolidation | ✅ | human-confirm → `target.yaml` | the map-don't-exploit seam; humans approve candidates |
| 3 Passive subdomains | ✅ | vertical (`subfinder`·`github-subdomains`·`shosubgo`) | |
| 4 DNS brute/resolve/permute/recurse | ✅ | vertical (`puredns`·`alterx`·`dnsx` + recursion loop) | The snapshot's “wildcard→HTTP differentiation future” note is superseded: `vertical.wildcard_http` exists in current source. Current release conformance remains open. |
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

- **enrich follow-on** (Phase 6/7/8): the old “no screenshot/WAF/smap” note is superseded by the current
  `enrich` implementation; recrawl remains absent. This source observation is not release verification.
- **kaeferjaeger 403** + **Caduceus/tlsx fragility** (Phase 5) — keep an eye; CSP-via-probe partly compensates.
- **wildcard→HTTP differentiation** (Phase 4) — present as `vertical.wildcard_http`; release verification open.
- **credential/evidence separation** — the snapshot implemented mask+fingerprint, but that is not closure.
  Current policy requires lossless target-secret evidence in canonical/private surfaces, credential
  exclusion from operational surfaces, and separate policy-derived share/AI views (`C-SECRETS`).

## Highest-leverage automatable gaps (build order, rough)

1. **Phase 13/14 digest + handoff** (v0.4) — ranked, provenance-rich, quarry-attack/hackbot-ready output. The bridge to the offensive side.
2. **Phase 1 OSINT automation** — convert `MANUAL_TODO` items that *can* be automated (RDAP/ASN, linked-seeds, Shodan-passive); leave inherently-web ones (bgp.he.net browsing) as prompts.
3. **Phase 11 content discovery** — the old “whole missing phase” claim is superseded by the current
   candidate-driven `content` phase; digest surfacing, tailored wordlists, and release verification remain.
4. **Phase 9 JS depth** — sourcemap unpacking, beautify, deeper route mining.
5. **Phase 6/7 enrich follow-on** — recrawl for late hosts and release verification of the existing
   screenshot/WAF/smap paths.
6. **Phase 0 platform-scope API** + **Phase 16 report builder**.

## Historical framework validation rubric

These are the snapshot's self-assessed answers to the checklist's per-phase QA questions. They are useful
requirements and hypotheses, not current release evidence; each claim must be re-established through the
applicable gate.

- raw evidence ✅ · normalized output ✅ · provenance (source/reason/confidence/raw-ref) ✅
- OOS + passive respected ✅ · rate-limits only-when-configured ✅
- failures/timeouts/blocks distinguishable from empty ✅ (status taxonomy)
- scanner findings marked unconfirmed ✅ (`confirmed=false`)
- candidate scope expansions human-reviewed ✅ (osint is review-only)
- private-layer separate from immutable recon evidence ✅ (`review_item`/`private_test_queue`)
- newly-discovered fed into correct queues 🟡 (enrich closed crawl/CSP→resolve/takeover; recrawl loop 🔮)
- report shows confidence/reason/source 🟡 (→ digest v0.4)
- API-docs/GraphQL/WS/mobile/OAuth-JWT/cloud/CICD normalized into queues 🔮 (mostly not yet)
- OOB public-default posture is accepted by design; backend provenance and independent per-owner disable
  controls remain open

## Tool-integration discipline

Per-tool mini-record required before add/change (Tool·Purpose·docs·install·version·deps·keys·
cmd·IO·exit-codes·failure-modes·timeout/rate·security·entities·raw·normalizer·consumers·verify).
Known special cases — status:

- gitleaks nonzero = leaks found ✅ · dnsx CNAME incl. non-A-resolved known subs ✅ ·
  httpx response headers for CSP ✅ · katana response-store→xnLinkFinder ✅ · waymore response mode ✅
- dalfox consumes clean candidate lists ✅ · current ffuf integration is candidate-driven; release
  verification remains open
- subfinder `-stats` key-health 🔮 · nuclei knobs documented 🟡
- porch-pirate/Swagger must feed normalized endpoint/param stores (not just write a file) → ✅ **DONE (parse_openapi writes endpoint/parameter entities into the store)**
- GitHub code-search qualifiers + source refs 🔮 · Interactsh backend provenance and independent disable
  controls remain open; public Interactsh as the default is accepted by design
- source-code public-intel vs in-scope distinction 🔮 (code-host-intel)

## Open validation gaps → status

- Re-probe CSP/crawl hosts same run → ✅ DONE (enrich) · output-hygiene spot-check → ✅ DONE (v0.2)
- CNAME-only brute discovery → 🔮 historical roadmap item · OOB/Interactsh backend provenance and
  independent disable controls → open; public default accepted by design
- RDAP automation IP→owner→CIDR → ✅ **DONE (osint.py RDAP candidate enrichment)** · acquisition/subsidiary scoring → 🔮 (Phase 1)
- tool-native key-health beyond subfinder → 🔮
- private AI digest schema (files consumed/created, immutable evidence) → 🔮 v0.4
- platform scope retrieval schema (H1/Bugcrowd/Intigriti, platform-neutral) → 🔮 (Phase 0)
- API-doc parsing (Swagger/OpenAPI/Postman/GraphQL → normalized endpoints/params) → ✅ **DONE for OpenAPI/Swagger (evidence.parse_openapi → endpoint+param corpus) + GraphQL introspection (probe_graphql); Postman = porch-pirate in osint**
- source-code/changelog/disclosed-report intel: public-recon vs private-attack split → 🔮 (code-host-intel + ⚔️)
- OAuth/OIDC/JWT classification (tag auth-flow endpoints, never test) → 🔮 NEW
- cloud/container/mobile candidate queues (map, don't expand scope) → 🔮 NEW

## Historical items surfaced

API-doc parsing → normalized endpoints · OAuth/JWT endpoint tagging · cloud/mobile candidate
queues · RDAP automation · acquisition scoring · tool key-health · platform-scope schema ·
private-AI-digest schema definition. Reconcile any surviving item into the current
[roadmap](../roadmap.md); this snapshot does not own sequencing.

---

*Source: the 17-phase methodology validation checklist (operator-private, kept outside this repo). The
implemented/partial/manual/future/private labels are preserved as the historical snapshot's vocabulary;
current status is maintained only in the authoritative ledgers linked above.*
