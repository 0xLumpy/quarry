# Provider quota / credit semantics — findings + design (raised 2026-07-27, Lumpy)

> **Current status (audited 2026-08-11 at `4e4825c`): B0/B1 implementation present; release
> verification open.** The Shodan credit coordinator, Whoxy paginator, and Censys entitlement lifecycle
> path remain in the tree. Censys Platform global search remains externally entitlement-gated; that fact
> does not close the adapter's release gates.

Originally a pre-Batch-B research note (2026-07-27), this is now a **historical research and
implementation-rationale record**. `DONE`, `BUILT`, `shipped`, and “verified” below refer to the cited
historical revisions, not current release-gate `verified` or `closed`. Current provider conformance is
governed by the [product contract](../governance/PRODUCT-CONTRACT.md),
[`CURRENT-HEAD.md`](../audit/CURRENT-HEAD.md), and `C-TOOLS`, `C-OUTPUT-CONTRACT`, `C-SECRETS`, and
`C-POLICY-TRACE` in the [release gates](../releases/RELEASE-GATES.md). Items still marked `MEASURE` were
assumptions to confirm against the live API.

## The principle (Lumpy's, adopted)

Provider quota exhaustion is **not a Quarry error and not a defect — but it IS incomplete coverage.**
It must be visible as an *external provider limit*, never as a tool failure and never as a clean zero.

    exhausted credits  ->  stop cleanly, preserve evidence, persist the unqueried pivots,
                           emit structured provider_quota coverage
    verdict            ->  complete_with_limits  ("X/Y pivots queried; credits exhausted")
    NOT                ->  FAILED / tool_failed / degraded-execution count / complete_with_gaps

Distinct classes, never collapsed (Lumpy r1):
  - `401` -> authentication
  - `403` -> forbidden/entitlement, pending provider-BODY classification
  - `429` -> **rate limit** (`classify_provider_error` returns `PROVIDER_RATE_LIMIT`, resolved)
  - quota exhaustion -> **proven from the provider's response body or balance endpoint, NEVER inferred
    from an HTTP status alone**
  - `transport` · `5xx server` unchanged

**Missing optional credentials are NOT COVERAGE_UNKNOWN** (Lumpy r2). An optional provider that was not
configured must not make every ordinary run incomplete. The current release contract requires each
planned obligation to have an explicit executed, omitted, refused, bounded, or not-applicable decision;
the present implementation is not uniform here, because some entirely unconfigured lanes remain silent.
A provider that is configured but cannot run because provider evidence proves the account lacks
entitlement contributes a provider limit. Full lifecycle reconciliation remains open under
`C-POLICY-TRACE`; silence must never be interpreted as completed coverage.

## Defects this addressed (all resolved in `2bcd00a`)

The four below were the state that motivated the build. Each is fixed; the shipped location is noted so a
reader arriving from a code citation does not read a resolved defect as current.

**1. `401` and `403` were the same class.** *Resolved:* `classify_provider_error` now splits 401->`auth`,
403->`forbidden`. Entitlement ("your plan cannot call this endpoint") is a *permanent capability*
fact; a bad key is an *operator* fact; neither is quota. Three different operator actions, one label.

**2. Censys ran silently skipped.** *Resolved:* `vertical.censys_entitlement_skip` records an explicit
provider skip when a token is configured without an org id. The lane still gates on `token AND org`:

    if cen.get("token") and cen.get("org"):

A Censys **Free** account has no organization ID, so the `token AND org` gate is not met. Previously the
lane was skipped silently — no source event, no skip record — which is why 100 Censys credits went
untouched unseen; it now emits an explicit provider skip, so the gap is visible. The remaining limit is
entitlement: the endpoint is Platform v3 **global search** (`/v3/global/search/query`), a paid tier, so a
Free PAT would get a pre-charge `403` even with an org id. MEASURE: what a Free PAT returns, and whether
any Free-reachable endpoint yields cert names.

**3. Whoxy reported credit exhaustion as a clean empty result.** *Resolved:* the `status:0` envelope in a
200 now maps to `complete_with_limits`, not a false empty. `osint.py` parses
`domainsList` / `search_result` straight out of the body. Whoxy answers **HTTP 200** with a
`{"status": 0, "status_reason": "..."}` envelope on failure (including out-of-credits). Previously both
keys were absent, `doms` became `[]`, and the lane echoed `whoxy[label]: 0 domains` — a **false empty**;
the envelope now maps to `complete_with_limits`. Whoxy is credit-based like Shodan, the same class as
the bug above.

Measured 2026-07-27 (HTTP 200 both times):

    balance:  {"status": 1, "live_whois_balance": 0, "whois_history_balance": 0,
               "reverse_whois_balance": 0}
    exhausted: {"status": 0, "status_reason": "Zero Account Balance"}

So the envelope is `status: 1` = success, `status: 0` + `status_reason` = failure, and the
credit-exhaustion case is a **string in the body of a 200**. This is ground truth to build B0 on — no
assumed HTTP code anywhere. `account=balance` is free and reports THREE separate balances
(live_whois / whois_history / reverse_whois), i.e. Whoxy meters each service independently.

**4. No provider read its remaining credits.** *Resolved for Shodan:* the budget now reads `/api-info`
(free) as its balance authority. Whoxy's free `account=balance` and other providers remain candidates.

## Shodan specifics

Endpoint in use: `/shodan/host/search` (`probe.py`) — the query-credit endpoint.

| credit type | what it buys | Quarry relevance |
|---|---|---|
| **Query credits** (100/mo) | `/shodan/host/search`, 1 credit per page of 100 results | the pivot lane's actual currency |
| **Scan credits** (100/mo) | `POST /shodan/scan` — asks **Shodan** to actively scan IPs, 1/IP | **see RoE below** |
| **Monitored IPs** (16) | network alerts on IPs — push when a new service appears | continuous/maestro layer, not a run |

**Free calls that change the design (VERIFIED as documented behaviour, MEASURE to confirm):**
  - `/api-info` — returns remaining `query_credits`, `scan_credits`, `monitored_ips`, plan. **No credit
    cost.** This is the budget's authority: read it at plan time instead of guessing, and read it again
    after the run to record actual consumption.
  - `/shodan/host/count` — identical to search but returns only totals + facets and **consumes no query
    credits**. Lets a pivot be *sized* for free before deciding whether it is worth a credit and how many
    pages it needs.
  - MEASURE: whether `/shodan/host/{ip}` lookups consume a credit, and the **exact** signal for
    exhaustion (HTTP code + body). Do not build the classifier on an assumed code.

**MEASURED 2026-07-27 (Lumpy's account, `/api-info`, free):**

    {"plan": "dev", "query_credits": 85, "scan_credits": 100, "monitored_ips": 0,
     "unlocked": true, "usage_limits": {"scan_credits": 100, "query_credits": 100, "monitored_ips": 16}}

Note `query_credits` 85/100 — the balance is a LIVE remaining count, not the plan allowance, and
`usage_limits` carries the allowance separately. Exactly the two numbers a budget needs, for free.

Consequence for the budget unit: a **monthly** quota is not protected by a **per-run** budget. Rather
than local cross-run bookkeeping (which drifts), `/api-info` is free — read the true remaining balance
each run and treat it as the ceiling. No accounting to keep in sync.

### Scan credits — recommend NOT wiring into the recon pipeline

They do not fetch data; they **cause Shodan to actively scan the target**. Three problems:
  1. **Attribution/RoE (the load-bearing objection).** The packets come from Shodan's infrastructure, on our request, against the
     target. That is active scanning by a third party — a different authorisation question from Quarry
     scanning it directly, and one most programme RoEs do not address.
  2. **Publication — UNVERIFIED, must be checked before it is stated as fact.** I asserted that results
     enter Shodan's public dataset; that is plausible (on-demand scan data is ingested the same way as
     Shodan's own crawl) but is NOT established by the on-demand-scanning docs we actually read. Treat as
     an open question, not a finding. If true it is decisive; if false, (1) and (3) still stand.
  3. **Async.** Results land later, out of band from the run.

This collides with Quarry's map-don't-exploit posture *and* with the "observe, never actively expand"
RoE boundary. Recommendation: **never automatic, never default.** If wanted at all, an explicit operator
command (`quarry shodan scan <ip>`), gated on a target-profile flag, with the publication consequence
stated in the prompt. Monitored IPs / alerts are a better fit for the future continuous layer than for a
run, and cost no query credits.

## Batch B — the shape that was built

1. `provider_quota` as a first-class coverage kind — soft limit -> `complete_with_limits`, carrying
   `eligible / queried / remaining_pivots` and the provider's own reported balance.
2. Split the error taxonomy: `auth401`, `entitlement403`, `ratelimit429`, `quota`, `transport`, `server`.
   Body-level signals count (Whoxy `status:0`, Shodan `error`), not just HTTP codes.
3. Pre-flight balance where the provider offers it free (`/api-info`, Whoxy `account=balance`);
   plan the run against the real number.
4. Free sizing before spending (`/shodan/host/count`) — **ranking ONLY** (Lumpy r3). It may estimate cost
   and order useful pivots first; every eligible pivot stays persisted as work. "Not worth a credit" must
   never become another hidden cap. Same rule as A1/A2: rank sets ORDER, never MEMBERSHIP.
5. Deterministic pivot ordering + persisted remainder, `0` = all eligible pivots (breadth policy intact —
   the provider's balance is the ceiling, not a Quarry cap).
6. The intended shape gives every planned optional-provider obligation an explicit **SKIPPED** or
   not-applicable disposition without making absence of optional credentials a coverage gap. The current
   Censys path explicitly records a configured token without the required organization; entirely
   unconfigured lanes are not yet uniform, so this is a release-gate requirement rather than a closure
   claim.

## Sequence (Lumpy, approved)

- **B0 — DONE (`883120e`, 6 rounds).** Shared taxonomy (`Status.LIMITED`, `COVERAGE_PROVIDER`,
  `provider_limits` -> `complete_with_limits` with gaps dominating), Whoxy envelope + schema validation,
  caps removed, per-query accounting, OSINT session verdict with subprocess-exit-code checks.
- **B1 — DONE at the cited historical revision.** Shodan `/api-info`, credential-safe operational error
  records while retaining full provider evidence in private raw artifacts, and credit-aware resumable
  pivots.
- **B2 — lifecycle correction implemented; capability still constrained.** The configured-token/no-org
  Censys state records an entitlement skip. Platform global search remains org-gated; a separate
  Free-reachable lookup lane for known assets is deferred.
- **xnLinkFinder** — afterwards, its own architectural batch.

## Whoxy is under-used (Lumpy, direction — NOT B0)

Quarry uses only Reverse WHOIS today. All three services feed the future relationship layer:

    known apex -> WHOIS Lookup (current) -> WHOIS History (previous registrants)
               -> registrant names/emails/orgs -> Reverse WHOIS -> related apex candidates
               -> human/AI ownership + scope review

  - **Lookup** gives structured current registration data, and could replace Quarry's brittle parsing of
    local `whois` output.
  - **History** is the genuinely new evidence: registrant identities from BEFORE a privacy service was
    applied.
  - **Reverse** turns those identities into related-domain candidates.

Boundaries: query registrable apexes and strong apex candidates only, never every subdomain; historical
ownership is EVIDENCE, not proof of current ownership; related domains stay review candidates and NEVER
auto-enter active scope; privacy services, registrars, hosts, transfers and common org names are
noise/conflict signals; ranking may prioritise candidates but must not silently discard them.

Staged: B0 (outcomes + false-empty fix) -> later Whoxy expansion (Lookup + History as structured OSINT
sources) -> v0.4 relationship layer (chain and reconcile identities, confidence, provenance, ownership
review). Test credits purchased: 1,000 Lookup / 400 History / 200 Reverse ($6) — enough to measure all
three contracts.

## MEASURED 2026-07-27 — the Whoxy no-match contract (open contract CLOSED)

A genuine reverse-whois no-match, live (HTTP 200):

    {"status": 1, "api_query": "reverse_whois",
     "search_identifier": {"company": "quarry-contract-no-match-1785160485"},
     "total_results": 0, "api_execution_time": 0.01}

Note what is **absent**: no `search_result`, no `current_page`, no `total_pages`. B0 as shipped required
all three and rejected this real, correct answer as schema drift — fail-CLOSED, but still a bug: "nobody
matched" is a COMPLETE answer, not an unreadable one. Fixed as a clean EMPTY (`rows=[]`, `total=0`, `truncated=False`) — but the FIRST fix was "any body whose
`total_results` is 0", far wider than the evidence: a bare `{"status":1,"total_results":0}`, an
`account_balance` reply, or a half-paged hybrid all passed, re-creating the false empty. **EXACTLY TWO
shapes are accepted, nothing in between:**

  - **A — the measured compact empty**: no result carrier and no pagination keys at all, AND the body must
    identify OUR question (`api_query == "reverse_whois"` plus a `search_identifier` echoing the
    param/value we sent). It carries no rows, so its echo of the request is the only thing tying it to the
    query — without that, an answer to a different anchor counted as "this anchor found nothing".
  - **B — a strict paged empty**: an empty result collection PLUS both pagination fields, valid, page 1.

Everything else fails closed: only an EXACT integer zero unlocks the path (`False == 0` in Python);
`total_results: 0` alongside rows in EITHER carrier (`search_result` or `domainsList`) is contradictory;
half-present pagination, a carrier without paging, or paging without a carrier is an unrecognised shape.
Any non-empty answer still owes the full strict result + pagination contract.

**Balance observation (NOT a general rule):** the reverse-whois balance read 200 before and 200 after this
query, so **this** no-match consumed no credit. That is one measurement about one call — it does NOT
establish that Whoxy queries are free, and nothing in the code assumes it.

Balances at the time (`account=balance`, free): live_whois 1000 · whois_history 400 · reverse_whois 200.

## MEASURED 2026-07-28 — Shodan endpoint costs (balance read before AND after each call)

    /shodan/host/count?query=product:nginx   HTTP 200  total 10,923,823  matches []
        query_credits 85 -> 85   => FREE, confirmed. The "size a pivot before spending" design rests
        on this, so it is now a measured fact rather than a documented claim.

    /shodan/host/8.8.8.8                      HTTP 200
        query_credits 85 -> 85   => this PLAIN host lookup consumed NO query credit.
        CAVEAT: one call, one IP, no `history`/`minify` parameters. Does not establish that every host
        lookup is free. Treat as "the plain form did not charge", not as a rule.

    INVALID key, BOTH /api-info and /shodan/host/search   HTTP 401, body is **HTML**:
        <html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1>...

        => Shodan does NOT use a JSON error envelope for auth. My assumption that provider errors are
        always a JSON error object was WRONG, and it matters structurally:

**TWO PROVIDER ERROR IDIOMS, and neither may be forced onto the other:**

  - **Whoxy** — HTTP **200** with a JSON envelope (`status:0` + `status_reason`). The STATUS CODE carries
    nothing; the BODY is authoritative. This is why B0 needed `whoxy_envelope()` at all.
  - **Shodan** — HTTP **401** with an **HTML** body. The STATUS CODE is authoritative; the body is
    unparseable noise.

**CORRECTION — I wrote "do not attempt body classification on a non-2xx Shodan response" here, and the
very next measurement proved it wrong.** See below: Shodan returns **401 for BOTH a bad key AND spent
credits**, and only the BODY tells them apart. The rule that actually holds is narrower: *a non-JSON error
body must fall back to the status-code class, never become a `parse` failure.*

## MEASURED 2026-07-28 — Shodan QUERY-CREDIT EXHAUSTION (account deliberately depleted)

    /shodan/host/search with a spent balance:

    HTTP 401
    {"error": "Insufficient query credits, please upgrade your API plan or wait for the monthly limit
               to reset"}

**This is the most important measurement of the batch, and it is the opposite of what a reasonable person
would assume.** Shodan uses **HTTP 401 for BOTH** cases:

    bad/invalid key   -> 401 + **HTML** body        => auth
    credits exhausted -> 401 + **JSON** {"error"}   => QUOTA

So for Shodan **the status code CANNOT distinguish auth from quota** — the body is the only discriminator,
and `401 -> auth` (which is correct for every other provider we have) would classify a depleted account as
a broken credential: the operator would go re-key a key that was never wrong, while the run reported a
failure instead of `complete_with_limits`.

**Three idioms now, not two:**

  - **Whoxy** — HTTP 200 + JSON envelope (`status:0`). Code says nothing; body is authoritative.
  - **Shodan auth** — HTTP 401 + HTML. Body is noise; code is authoritative.
  - **Shodan quota** — HTTP 401 + JSON `{"error": ...}`. Code is AMBIGUOUS; body REFINES it.

**B1 rule (measured, not assumed):** on a Shodan error response, attempt a JSON parse of the body; if it
yields an object with a string `error`, classify by that reason (the exhaustion phrase above -> quota);
otherwise fall back to the status-code class. A JSONDecodeError on an HTML body must NEVER become `parse`.

**The signal is STABLE, not a one-off** — a second search at zero returned the identical 401 + body.

### What still works at ZERO query credits (measured on the depleted account)

    /shodan/host/count?query=product:nginx   HTTP 200  {"matches": [], "total": 10923823}
    /shodan/host/8.8.8.8                     HTTP 200  full host record (ports, hostnames, isp, ...)
    /shodan/host/search                      HTTP 401  quota

**Query credits gate `/shodan/host/search` and NOTHING ELSE we use.** That is the design result of this
whole measurement pass, and it is bigger than the error string:

  - **Planning survives depletion.** `count` still answers, so a credit-exhausted run can still size and
    order its remaining pivots honestly instead of going blind.
  - **Enrichment survives depletion.** `host/{ip}` still returns full records, so for every IP Quarry
    ALREADY has, real Shodan data is still obtainable with no credits at all.

So the right B1 behaviour on exhaustion is **DEGRADE, not disable**: stop issuing searches, keep the
unqueried search pivots as a counted resumable remainder, and continue with the free operations. A lane
that shuts down entirely on `quota` would throw away coverage that is still free to collect — which would
be the same "bound the wrong axis" mistake as the input-set caps, one level up.

CAVEAT: measured on a `dev` plan. Another plan tier may meter these differently; re-measure before
assuming it holds elsewhere.

The Shodan and Whoxy exhaustion phrases are now in `contract._QUOTA_REASONS`, matched exactly by
`classify_provider_reason` — the wiring shipped with B1, so the data is no longer a "declaration with no
consumer".

## Measured signals (once open, now closed)

Shodan's exhaustion string ("insufficient query credits …") is measured and in `_QUOTA_REASONS`; an
unrecognised body still stays a visible generic error, never PROVIDER_QUOTA. Any new provider's signal
must be measured before it is added to the allow-list.

## PAGINATION (B1, credit-bound)

Whoxy pages reverse-whois at 100 results and **charges a credit per page**, so completing a large answer
is credit-budget work. B0 does not paginate: it DETECTS the shortfall (`total_results` > rows, or
`total_pages` > 1) and records the lane PARTIAL with `truncated_pages` + `coverage_incomplete`, so a
page-limited answer can never read as the whole answer. B1 fetches the remainder under the balance.

## Cheap verification plan

Most of this is testable **at zero credit cost**: `/api-info` and `/shodan/host/count` are free, and
Whoxy's balance endpoint is free. Only the *exhaustion* signal needs real spend — and that is one
deliberate query at a near-zero balance, not a hundred.

Providers to cover: **shodan, censys, whoxy** (Lumpy loading credits), plus **certspotter**
(`api.certspotter.com`, free tier is rate-limited -> 429). No-quota providers already in the tree:
kaeferjaeger (GCS), rdap.org.

---

## Reference: the outcome classes (moved out of `contract.py`, 2026-08-08)

One taxonomy for every external provider, whether it runs in the events pipeline or in the standalone
OSINT session. Each class implies a **different operator action**, so collapsing any two of them
destroys the only information the label carries.

| class | means | the operator's next move |
|---|---|---|
| `auth` | the credential is bad or missing | fix a key |
| `forbidden` | refused, reason unknown | treat as a failure until something proves otherwise |
| `entitlement` | the PLAN cannot, on provider evidence | an external limit |
| `rate_limit` | too fast right now | back off; the quota is untouched |
| `quota` | the account's credits are spent | an external limit; nothing to retry |
| `oversize` | OUR read ceiling stopped us | raise our own constant |
| `pace_busy` | OUR pacing refused to issue the request | retry later, free |
| `http` | an unclassified 4xx | investigate |
| `transport` / `server` / `parse` / `error` | ordinary failures | investigate |

Two rules the code enforces rather than assumes:

- **403 is `forbidden`, never `entitlement`.** A WAF, an IP allow-list, a permission error and a
  malformed request all answer 403. Calling any of them an expected limit lets a real defect pass the
  run as "the plan is just too small".
- **Quota and entitlement are never inferred from a status code.** They are proven from the provider's
  own response body or its balance endpoint.

### Measured provider shapes

These are why the envelope validation exists at all.

- **Whoxy** reports an exhausted account as `{"status":0,"status_reason":"Zero Account Balance"}`
  inside an **HTTP 200** (measured 2026-07-27). No status code could have revealed it. A genuine
  no-match is `{"status":1,"api_query":"reverse_whois","search_identifier":{...},"total_results":0}`
  — no `search_result`, no `current_page`, no `total_pages`.
- **Whoxy `total_results` varies by value**: a no-match answers the integer `0`, a non-empty
  reverse-whois answers the string `"39766"` (measured 2026-07-29).
- **Shodan** answers a spent balance with **HTTP 401** and a JSON body, the same status it returns for
  a bad key with an HTML body (measured 2026-07-28, by depleting a real account). The status alone
  cannot tell auth from quota.
- **Shodan `/shodan/host/{ip}`** answers an unseen IP with **404** and `{"error": "No information
  available for that IP."}`, at a zero query-credit balance (measured 2026-07-30). Without a rule for
  it, "not in Shodan" — the ordinary case for most eligible addresses — reports as a lane failure.
- **A 4 MiB read cap** truncated two paid Shodan pages mid-string and the run reported
  `JSONDecodeError` twice: our own ceiling, billed to the provider's reputation and to two credits.
  That is the distinction `oversize` exists to keep.

### Whoxy reverse-whois pagination (measured 2026-07-29, both query forms)

```
page 1 of a 39,766-result anchor:  {"status": 1, "api_query": "reverse_whois",
                                    "search_identifier": {"company": "<verbatim>"},
                                    "total_results": "39766",     <- a STRING when non-empty
                                    "total_pages": 398, "current_page": 1,
                                    "search_result": [ ...100 rows... ]}
one page past the end:             {"status": 0, "status_reason": "Invalid Page Number"}   COST 0
account=balance:                    FREE (two consecutive reads, no change)
```

`total_pages == ceil(total_results / 100)` on both forms (39766 -> 398, 355 -> 4). The row shape
differs between forms — the email form carries registrant and administrative contacts, the company form
carries `create_date`/`domain_status` — which is provider variation within one schema, not a schema
change. Both forms echo `search_identifier` verbatim on every page, which is what lets a stored page
identify itself during ownership enumeration.

**Lock order** (`whoxy_page.py`), fixed, because credits are account-wide while page state is per
project:

```
project lock (open_state)
  -> replay owned pages                 free, never waits on the account
  -> if paid work remains: spend lock   account-wide
       -> balance read
       -> purchases, journaled as they land
  -> final ledger compaction            project lock only
```

---

## Shodan coordinator: acquisition states, coverage kinds, and the position × cause matrix

Reference for `src/quarry_recon/shodan_sched.py`.

### Acquisition is committed separately from interpretation

Bytes landing on disk is not ownership. A response we paid for and could not parse, published only as a
rejection, is bought again by the next run — the double spend the store exists to prevent. So a receipt
records the purchase itself:

| state | meaning |
|---|---|
| `complete_parsed` | the page is ours and readable |
| `complete_unparsed` | the whole response is ours; this build would not parse it. Eligible for later processing from the artifact, never re-bought. |
| `incomplete_paid` | the transport or disk broke mid-body. The partial bytes are ours, and an automatic retry is refused — an operator decides whether to pay again. |

Every valid receipt blocks acquisition. A receipt without a usable page is evidence loss plus a refused
repair, never permission to buy. A page already paid for whose artifact no longer verifies is refused on
exactly the terms an aged page is: "gone" is not an authorisation, because buying it again is a fresh
charge.

### Who stopped us decides the coverage kind

| stop | kind | verdict |
|---|---|---|
| a proven provider boundary (quota, entitlement) | `provider` | soft limit |
| the operator's credit reserve | `sample` | soft limit |
| the operator's `max_pages` page ceiling | `cap` | gap — a ceiling that withheld pages is not "complete" |
| something failed (transport, auth, server, parse) | `timeout` | gap |

Collapsing any of them lets a broken run report `complete_with_limits`. `provider_stop:*` is a failure we
stopped requesting through — a gap, never a soft limit. `publish_failed`, `ledger_unwritable`,
`scheduler_invariant`, `ownership_unreadable` and `pace_busy` are ours; of those only `pace_busy` is not
a defect, since a boundary declining to burst is working as intended.

### Position × cause

Four measures, each naming only its own position's classes. A mid-flight quota is not a pivot the
provider refused outright, and a later-page transport failure is not our page budget. Without the split,
a run stopped dead by quota folds as `complete`: an attempted pivot is not "unqueried", and a pivot with
no total has no page remainder.

| position | cause | kind | verdict |
|---|---|---|---|
| first | broke | `COVERAGE_TIMEOUT` | gap (the target or network cost us the pivot) |
| first | refused | `COVERAGE_PROVIDER` | soft limit (nothing to retry this run) |
| later | broke | `COVERAGE_TIMEOUT` | gap |
| later | refused | `COVERAGE_PROVIDER` | soft limit |

A paid response we refused gets its own measure: the position measures answer "which pivots failed, first
or later, broken or refused", and an objection about a page's shape is neither. The credit is spent either
way, so it is emitted every lifecycle and says where the bytes went.

Total drift is telemetry, not a boundary: the index is live, so two pages of one pivot can report
different totals. The maximum is kept, `omitted` stays 0, and the count rides in the reason.

---

## OSINT pre-flight coverage (`osint.py`)

The `quarry osint` path has no events pipeline, so `OsintSession.outcome()` is its own coverage verdict.
Without it a provider limit lived only in a per-tool block nothing read, and the CLI printed a green
`osint done` over a run that never queried half its anchors.

**A limit and a gap are independent facts, and one tool result can carry both** — query 1 is
page-limited, query 2 exhausts the credits. They are recorded on independent lists, never `elif`, and
the status is chosen afterward. **Gaps dominate:** a limit may only lift an otherwise-clean session
(`complete_with_gaps` > `complete_with_limits` > `complete`). An unusable spending control is our own
defect and outranks both.

**Provider limit vs operator limit stay separate.** A credit reserve or a page budget is a limit the
session must state, but it is *ours* — folding it in with a provider refusal tells the operator the
provider refused us when our own policy did. `limit_origin` can name both, because one run can hit both:
the provider refused what was left, and we had withheld some of it anyway. A policy boundary explains a
remainder only when its allowance was actually spent (the scheduler counts that); a remainder our own
machinery stopped is not a limit anyone reached.

**Our bound is not their shortfall** (ASRank orgs, RDAP lookups, Whoxy pages). A throughput bound over
the matches the provider *reports* is an operator limit with a counted remainder; results the provider
*admitted to and did not send* are its shortfall, reported separately. Blaming our cap for work the
provider never sent tells an operator that raising the bound would recover results that are not there.
An unreadable provider count is **unknown coverage**, never `len(received)` — substituting what we
happened to receive turns malformed data into a certificate of complete coverage, because the shortfall
then computes to zero.

**A discarded provider field is not an absent one.** A field the provider did not send is an answer; a
field it sent in a shape we cannot read is evidence we discarded, and a lane that discards provider
evidence may not report success over it. The typed accessors (`_obj`, `_text`, `_asn_number`,
`_readable`) keep a malformed row from crashing the lane, and each discard is counted.

**A failed balance request as a balance outcome** (`_balance_from_error`): a proven limit is a refusal
whatever carried it; an HTTPError or an envelope failure is the provider having answered (except
`parse`, our inability to read it); anything else is a failure to read, not a refusal. Deriving refusal
from the error class alone would infer a provider response from a local exception that never reached it.
