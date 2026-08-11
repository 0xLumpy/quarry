# Quarry operator flags — the axis model (plan, 2026-08-02)

> **Current status (audited 2026-08-11 at `4e4825c`): steps 1–5 implemented; current release
> verification open.** `policy.py`, scoped overrides, effective-policy print/persist, `--unbound`, and
> `--settle` remain in the tree. `--preset` is not implemented and is outside the `v0.3.10` integrity
> release.

This is a **historical approved plan and implementation-rationale record**. It was revised 2026-08-02
after review and written against `1cb0a63`; `DONE`, `BUILT`, and “verified” below refer to the cited
historical milestones, not current release-gate closure. Current intent and status are governed by the
[product contract](../governance/PRODUCT-CONTRACT.md), [current audit ledger](../audit/CURRENT-HEAD.md),
[`v0.3.10` ledger](../releases/v0.3.10.md), and [release gates](../releases/RELEASE-GATES.md).

## 1. The four axes

| Axis | Control | Means |
|---|---|---|
| waiting | `--timeout 0` | no OUTER process deadline. Nothing else. |
| volume | `--unbound` | operator COVERAGE/THROUGHPUT ceilings go to their unbounded meaning, for this run |
| continuation | `--settle` | keep creating runs until no resumable work makes progress |
| capability / risk | (later) `--preset <name>` | breadth and intrusiveness. NOT a ceiling. |

They COMPOSE; none implies another. `--unbound` does not imply `--timeout 0`: unbounded volume at a
fixed rate is unbounded duration, which is the operator's call to make explicitly.

Reserved, deliberately unused for scheduler semantics: `--all`, `--complete`, `--deep`, `--heavy`,
`--full`, `--exhaustive`, `--invasive`. Other tools already spend those words on breadth or aggression.

## 2. The ownership boundary (Lumpy, 2026-08-02)

POLICY OWNERSHIP, not execution order — it holds however the phases are reordered later:

    ACQUISITION   provider enablement, balance, reserve and page policy decide what Quarry may OBTAIN
    OWNERSHIP     once evidence is acquired and stored, Quarry HAS it
    PROCESSING    `--unbound` may process all eligible RETAINED evidence through free downstream tools

If Shodan's policy buys five pages and those yield 100,000 names, `--unbound` does not buy page six — and
it does let the free downstream lanes work through all 100,000. Being free is not what puts a lane on the
processing side: `probe.shodan_host` is MEASURED free (`/shodan/host/{ip}`, zero-balance delta 0) and is
still excluded, because the provider owns what it may obtain.

## 2b. What `--unbound` may never touch

* rate limits and concurrency (pressure on the target / on this host),
* scope and OOS rules, the operator-selectable private-reach control, and the independent scanner-self and
  metadata exclusions,
* parser validation and evidence-surface contracts, including lossless canonical/private evidence and
  exclusion by construction of Quarry-owned credentials from operational telemetry,
* per-invocation chunk sizes (`MAX_BATCH_WORDS`, per-call caps) — they bound blast radius and memory,
  and the scheduler reaches every chunk anyway,
* admission cooldown and rotation fairness (ordering, not coverage),
* **every paid / external provider control.** `--unbound` is about USING WHAT WE HAVE, not buying more.
  Shodan favicon/certificate searches, Whoxy pages, credit reserves and page budgets keep their EXISTING
  policy — enablement, balance, reserve, per-run spending — separately authorised. The flag may neither
  alter nor reinterpret them, and no `--spend-all` path is built here (Lumpy, 2026-08-02).
* **`A1D_WORD_CAP` in v1** (Lumpy, 2026-08-02): its strict `0` bypass is gated on tightening the active
  DNS boundary to exact labels and on usefulness tiers. `--unbound` must not smuggle it in ahead of that
  work; the policy print names it as HELD BOUNDED so the exclusion is visible, never silent.

## 3. The identity rule (corrected — Codex review, verified)

The first draft said "every bound `--unbound` relaxes must be folded into its lane's work unit". That is
WRONG as a blanket rule, because Quarry has two persistence models and only one of them resumes by work
unit:

* **`work_unit` lanes** — subfinder per apex, the xnl units, the paid providers. Resume identity IS
  `events.work_unit`, so a bound that changes WHAT one invocation may cover must be in it, or a bounded
  completion claims work an unbound run never did. (subfinder folds its effective `-max-time`, `1098ce7`.)
* **`partition` lanes (the sweep)** — state is `recon/state/sched/v<SCHEMA>/<lane>.json`, keyed by lane and
  SCHEMA, with per-slot CONTENT-BOUND completion. Coverage is exact by construction, so a per-run
  allowance must NOT change identity: the rotation is supposed to CONTINUE when the allowance changes, and
  putting it in the identity only costs replay dedup. A spend bound is a middle case — it changes
  `alloc_cap`, so it changes slot BOUNDARIES, which schema 2's rank-only inheritance already self-heals.

So the registry carries the classification instead of one rule:

    identity:          none | work_unit | partition | state_schema
    persistence_model: which state a change invalidates (or does not)
    relaxable:         may `--unbound` touch it at all
    held_reason:       why not, when relaxable is false (printed, never silent)
    unbounded_value:   per knob (subfinder: 1440m, not 0)

**DECIDED (Lumpy, 2026-08-02; shipped).** `zones_per_run` is OUT of the differ's work unit — it only
limits how many zones this lifecycle admits, and changing it must continue the existing rotation without
re-identifying the source. `word_spend` STAYS, classified `identity=partition`: it changes `alloc_cap`,
slot boundaries, invocation contents and artifact grouping. That is EXECUTION and EVIDENCE identity, not
ownership of scheduler state — the same lane ledger stays in use, and schema 2 treats a record belonging to
a containing or contained slot as DIRTY rather than complete (`budget.py:594`, verified), so a
re-partitioned corpus is re-submitted, never certified from the parent's run.

Both regressions are pinned: changing the allowance keeps the work unit and continues the rotation;
changing the spend flips the work unit, keeps the ledger (nothing dropped), splits the slot, and
re-submits the split members.

## 4. The registry (build step 1) — DELIBERATELY NARROW

The registry holds FREE-TOOL coverage/throughput bounds that participate in `--unbound`, plus the held
exceptions that must be printed. It is not Quarry's universal limit table. Resource, parser, rate,
concurrency, engagement and paid-provider controls are EXCLUSIONS carrying a reason, never entries — the
test proves each ceiling was reasoned about, and the registry proves nothing else can be lifted.

Per entry: name · reader · lane · default · `unbounded_value` · `identity` · `persistence` · `relaxable` ·
`consumer_honours_unbounded` · `held_reason`. It drives `--unbound`, the startup print, the manifest
record, and a test that FAILS when any ceiling in `src/` is neither registered nor excluded.

The unbounded value is per knob, not a constant: subfinder's is 1440 minutes, because upstream feeds
`-max-time` into `context.WithTimeout` and 0 CANCELS. Encoding that once beats scattering `if knob <= 0`.

Current surface (audit, 2026-08-02):

* 8 lane budgets via `budget_seconds`: `A1D_BUDGET_S`, `ARJUN_BUDGET_S`, `CONTENT_FFUF_BUDGET_S`,
  `JS_FETCH_BUDGET_S`, `SHODAN_HOST_BUDGET_S`, `SOURCEMAP_BUDGET_S`, `VHOST_BUDGET_S`, `WILDCARD_BUDGET_S`
* `strict_int`: `SUBFINDER_MAX_TIME`, `NUCLEI_MAX_HOST_ERROR`, `WILDCARD_ZONES_PER_RUN`
* module caps: `A1D_WILDCARD_WORD_CAP`, `WILDCARD_WORD_CAP`, `CLOUD_NAME_CAP` (free, unauthenticated
  bucket probes; consumer does not yet honour 0), and `A1D_WORD_CAP` — the ONE held entry in v1
* RESOURCE controls, not coverage, never relaxable: `XNL_MAX_INPUT` (200 MB stdin blob), `XNL_WORDLIST_LIMIT`
  (10 MB), `MAX_BATCH_WORDS`, the per-tool concurrency caps. (The 4.1 retention caps `XNL_PARAM_CAP` /
  `XNL_WORDLIST_DERIVE_CAP` are GONE — the first draft's inventory was stale.)
* EXCLUDED with reasons: every paid-provider control (`SHODAN_HOST_BUDGET_S`, reserves, backoff, Whoxy
  guards), resource guards, parser ranges, rate/concurrency, engagement settings and slot identity

**Enforcement cannot be a call-site scan alone.** `strict_int` / `budget_seconds` call sites miss every
module-level cap (`A1D_WORD_CAP` is a plain module constant). The classification test therefore also walks
the AST of `src/` for module-level constants matching the bound-naming convention (`*_CAP`, `*_LIMIT`,
`*_MAX*`, `*_PER_RUN`, `*_BUDGET*`, `*_TARGETS`) and fails when one is unclassified.

## 5. Effective policy, printed and persisted

At run start: every knob, its effective value, its SOURCE (default / config.yaml / target.yaml / flag),
and whether it is at its unbounded meaning — plus which bounds `--unbound` changed and which are HELD.
Persisted in the manifest, so a run's ceilings are evidence rather than shell history. `quarry policy -t
TARGET [--unbound]` previews it without running anything.

Precedence, one strict reader, no exceptions: **flag > target.yaml > config.yaml > default**.

`settings.override()` (shipped `1cb0a63`) is the flag seam, but it is PROCESS-global and never restored —
so it leaks into a later invocation inside the same interpreter, which is exactly what a `--settle`
supervisor does (child runs in one process). Before it is used more widely it needs a snapshot/restore
context manager (`with settings.overrides({...}):`, restoring in `finally`), with the CLI wrapping ONE run
and the supervisor wrapping EACH child run. Same strict parser either way, so a flag can never introduce a
value the file could not hold.

## 6. The confirmed defect this cleans up — FIXED (step 2)

`vertical.py:38` used to read `if knob <= 0 or http_timeout == 0:`, so `--timeout 0` set subfinder's
COLLECTION budget to 1440m: an outer-kill flag deciding coverage, and moving the resume key while it did.
`--timeout` now removes only the outer process kill; `SUBFINDER_MAX_TIME` alone decides collection, and
`--unbound` is what lifts it.

## 7. `--settle` (designed later, after the volume axis)

The requirements below are retained as the pre-implementation acceptance sketch. They do not establish
that current settlement satisfies `HEAD-04` / `QR39-012`.

A SUPERVISOR over runs, not a knob inside one: Quarry's evidence contract is one run = one run dir = one
manifest = one verdict, and "preserve each attempt as its own run evidence" is exactly that. `quarry run
--settle` creates child runs and a campaign ledger over their ids.

The lifecycle-local wildcard continuation report (`1cb0a63`) is NOT this oracle and must not be mistaken
for one: `remaining = eligible - completed` counts THIS pass, so the second run of an eight-zone rotation
still says "3 remaining" after the rotation has covered everything. Before it feeds `--settle` it is either
relabelled as a per-run statement or recomputed cumulatively from the rotation ledger (zones holding any
incomplete slot).

It needs, before any code:

1. a PROGRESS ORACLE per lane — eligible-not-attempted = 0, and the last run produced no new entities;
2. a fixed point that stops SUCCESSFULLY (coverage complete, nothing new);
3. terminal classes that stop EXPLICITLY and are never retried: entitlement, missing dependency,
   machinery, unschedulable work;
4. a no-progress counter (N runs with no new entities and no new attempted pairs -> stop, say so);
5. every attempt kept as its own run evidence, with the ledger naming the stop cause.

## 8. Historical build order

Revised after Codex's review — semantics are fixed BEFORE they are printed, because a policy report that
publishes `--timeout 0` changing subfinder's volume would enshrine the defect it is meant to expose.

1. **registry + comprehensive classification test** (no behaviour change) — the approved first step
2. scoped overrides (`with settings.overrides(...)`) + decouple `--timeout` from `SUBFINDER_MAX_TIME`
   — DONE
3. policy preview (`quarry policy`), startup print, manifest persistence — DONE
4. widen `--unbound` to the registry (A1d word cap HELD, provider controls excluded) + repair the
   continuation report so "remaining" is cumulative rotation state, not one lifecycle's arithmetic — DONE
   The three consumers below were taught their unbounded value in that step and are now all
   `consumer_honours_unbounded=True` (verified in `policy.BOUNDS`); kept here for the record:
   `CLOUD_NAME_CAP` (slices `all_names[:120]`), `SPA_CAP` (function-local, slices `_spa_all[:10]`) and
   `MAX_ITERS` (0 = iterate to convergence). REQUIRED regressions for `MAX_ITERS` (Codex, 2026-08-02):
   an unbound CLEAN chain reaches round four and then CONVERGES, and a degraded resolver making no
   progress TERMINATES instead of looping for ever.
5. `--settle` design doc (`docs/design/SETTLE-DESIGN.md`, written 2026-08-02) — DONE, and BUILT through its own
   §7 build order (prerequisites A-D, the acquisition closure, the supervisor, the CLI driver `2bcd00a`).
   An INTERRUPTED campaign resumes from its ledger; one that recorded a stop is refused (`settle.AlreadyRun`).
6. `--preset` / capability posture — only once there is more than one thing to preset
