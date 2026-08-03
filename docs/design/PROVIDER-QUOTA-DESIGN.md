# Provider quota / credit semantics — findings + design (raised 2026-07-27, Lumpy)

> **Verified state 2026-08-03 (`2bcd00a`): B0 + B1 BUILT** (Shodan credit budget across all pivot lanes, Whoxy paginator). B2 (Censys) is BLOCKED BY ENTITLEMENT, not by code — the Platform search API is org-gated. The quota SEMANTICS below still govern every provider lane.


Pre-Batch-B clarification. **B0 SHIPPED `883120e` + no-match follow-up `ca6d479` (both unpushed); B1/B2 not started.** Everything below marked VERIFIED was read in the tree or
measured; everything marked MEASURE is an assumption that must be confirmed against the live API before
it is built on.

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
  - `429` -> **rate limit** (NOT quota — `contract.py:56` currently calls it `quota`, which is wrong)
  - quota exhaustion -> **proven from the provider's response body or balance endpoint, NEVER inferred
    from an HTTP status alone**
  - `transport` · `5xx server` unchanged

**Missing optional credentials are NOT COVERAGE_UNKNOWN** (Lumpy r2). An unconfigured optional provider
emits an explicit **SKIPPED** lifecycle — it must not make every ordinary run read as incomplete. A
provider that IS configured but cannot run because the account lacks entitlement is `provider_entitlement`
and DOES contribute to `complete_with_limits`. (Supersedes my earlier "silence -> UNKNOWN" framing for
the Censys gate: the fix there is an explicit SKIPPED, not a gap.)

## VERIFIED defects in the current tree

**1. `401` and `403` are the same class.** `contract.classify_provider_error` maps both to `"auth"`
(`contract.py:52-53`). Entitlement ("your plan cannot call this endpoint") is a *permanent capability*
fact; a bad key is an *operator* fact; neither is quota. Three different operator actions, one label.

**2. Censys never ran — confirmed.** `vertical.py:597` gates the whole lane on `token AND org`:

    if cen.get("token") and cen.get("org"):

A Censys **Free** account has no organization ID, so the lane is skipped **silently** — no source event,
no skip record, nothing in the digest. That matches Lumpy's observation that 100 Censys credits have
never been touched. Two separate problems:
  - the silence itself ("we could not look" must not read as "nothing was there" — the same rule the
    A1/A2 lanes now follow with COVERAGE_UNKNOWN);
  - the endpoint used is Platform v3 **global search** (`/v3/global/search/query`), which is a paid tier.
    A Free PAT would get a pre-charge `403` even if the org gate were removed. MEASURE: what a Free PAT
    actually returns, and whether any Free-reachable endpoint yields cert names.

**3. Whoxy reports credit exhaustion as a clean empty result — SIGNAL NOW MEASURED.** `osint.py:240-251` parses
`domainsList` / `search_result` straight out of the body. Whoxy answers **HTTP 200** with a
`{"status": 0, "status_reason": "..."}` envelope on failure (including out-of-credits), so both keys are
absent, `doms` becomes `[]`, and the lane echoes `whoxy[label]: 0 domains` — a **false empty**, not even
a failure. The `except` branch only catches transport/JSON errors and echoes without recording a source
event. Whoxy is credit-based like Shodan, so this is the same class of bug.

Measured 2026-07-27 (HTTP 200 both times):

    balance:  {"status": 1, "live_whois_balance": 0, "whois_history_balance": 0,
               "reverse_whois_balance": 0}
    exhausted: {"status": 0, "status_reason": "Zero Account Balance"}

So the envelope is `status: 1` = success, `status: 0` + `status_reason` = failure, and the
credit-exhaustion case is a **string in the body of a 200**. This is ground truth to build B0 on — no
assumed HTTP code anywhere. `account=balance` is free and reports THREE separate balances
(live_whois / whois_history / reverse_whois), i.e. Whoxy meters each service independently.

**4. No provider anywhere reads its remaining credits.** No `/api-info`, no `account=balance`, no
pre-flight. Budgeting is blind.

## Shodan specifics

Endpoint in use: `/shodan/host/search` (`vertical.py:51`) — the query-credit endpoint.

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

## Proposed shape for Batch B (for approval, not built)

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
6. Every skipped-because-unconfigured provider emits an explicit **SKIPPED** lifecycle, never silence
   (Censys) — and never a coverage gap.

## Sequence (Lumpy, approved)

- **B0 — DONE (`883120e`, 6 rounds).** Shared taxonomy (`Status.LIMITED`, `COVERAGE_PROVIDER`,
  `provider_limits` -> `complete_with_limits` with gaps dominating), Whoxy envelope + schema validation,
  caps removed, per-query accounting, OSINT session verdict with subprocess-exit-code checks.
- **B1** — Shodan `/api-info`, sanitized error bodies, credit-aware resumable pivots.
- **B2** — Censys lifecycle correction; later, a separate Free *lookup* lane for known assets.
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

The exhaustion phrase is recorded here but deliberately NOT yet added to `_QUOTA_REASONS`: there is no
Shodan body-classifier call site until B1, and shipping the data without the wiring is exactly the
"declaration with no consumer" defect this batch hit five times.

## STILL UNMEASURED

Shodan's exact exhaustion signal (HTTP code + body), and the error-envelope shape of the endpoint B0/B1
actually use (`/shodan/host/search`) as opposed to `/api-info`. Do not build a classifier on either
until measured — an unrecognised body stays a visible generic error, never PROVIDER_QUOTA.

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
