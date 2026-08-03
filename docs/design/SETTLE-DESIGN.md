# `--settle` — the continuation axis (design, 2026-08-02, rev 4)

> **Verified state 2026-08-03 (`2bcd00a`): BUILT** — `settle.py` + `campaign.py` + `quarry run --settle`. Everything here is implemented EXCEPT resuming a campaign, which is refused by design (`settle.AlreadyRun` carries the four-part protocol a real resume must satisfy).


Status: **DESIGN ONLY, NOT BUILT.** Step 5 of `docs/design/FLAG-AXIS-PLAN.md`; steps 1–4 are done. Written
against `d858e8c`. Rev 2 folded in six review findings, rev 3 seven more (two P0s), rev 4 five more
including the ACQUISITION OWNERSHIP RULE. Every claim below was checked in the code.

## 1. What it is

    quarry run -t TARGET --settle

Keep creating runs until no resumable work makes progress. It is a SUPERVISOR over runs, not a knob inside
one: Quarry's evidence contract is one run = one run dir = one manifest = one verdict, and "preserve each
attempt as its own run evidence" is exactly that. The supervisor adds a CAMPAIGN ledger over child run ids;
it never edits a child's evidence.

Composes with the other axes and implies none of them: `--unbound` widens each child, `--timeout` bounds
each child's tools. Each child enters its own `settings.overrides(...)` scope (step 2), so one child's
flags cannot leak into the next.

## 2. The progress oracle

### 2.1 Novelty is a SET difference, never a count

Rev 1 proposed diffing `manifest.entity_counts`. That is wrong: two children can both hold 100 entities
while the second holds 20 identities never seen before, and an enrichment that matters (a `resolved` host
gaining its A records) changes no count at all. Counts are telemetry.

The campaign therefore owns a UNION artifact — the only cross-run identity store, since entities are
RUN-SCOPED (verified: a second `Run.create` in the same project starts empty):

    recon/campaigns/<campaign_id>/union.jsonl
    {"kind": ..., "id": <canonical identity>, "record": <the canonical MERGED entity>, "fp": <digest>}

The union stores the RECORD, not just its digest — §2.3 has to import these into the next child, and a
`{kind,id,fp}` row carries no material fields, no provenance and no alternate observations to import. The
fingerprint is DERIVED from the stored record, so it can never disagree with it. Per child:

    new_identities   = ids(child) - ids(union)
    enriched         = ids where MERGING the child's record into the union's adds a material fact
    PROGRESS         = new_identities or enriched

`fp(child) != fp(union)` is NOT progress. A DNS answer, a title, a rotating certificate or two conflicting
scalar observations can alternate between children for ever, and an inequality test would score every
oscillation as new work. Progress is MONOTONIC: `merged = join(union[id], child[id])` under the store's own
merge semantics, and it counts only when `merged` strictly adds a fact the union did not hold. A child that
merely swaps one observation for another advances nothing.

**PREREQUISITE A — DONE.** `store.material()` / `fingerprint()` / `merge()` / `adds_material()` /
`fold_observations()`: the store's own canonicalisation and monotonic merge, exposed for a run nobody has
open, with `RUN_SCOPED_FIELDS` (`first_seen`, `last_seen`, `raw_ref`, `raw_refs`) excluded from material
content and list order normalised AT EVERY DEPTH. `fold_observations` returns a `FoldedLog` carrying a
STATUS — `absent` / `valid` / `degraded` / `unusable` — because a campaign may never read "unreadable" as
"empty": only a trustworthy view may stand in for a child's evidence. `fold_run_entity(run_dir, entity)`
adds the EVIDENCE claim on top of that parser claim, reconciling the folded count against the child's own
`manifest.entity_counts`: a deleted log is `unusable`, a cleanly truncated one `degraded`, a broken or
missing manifest `unknown`, and only a count that matches keeps the parser's verdict. The live reader
shares the same fold, so live and finished views cannot diverge. Progress asks the MERGE, never fingerprint inequality — an oscillating
title counts once, and a return to the earlier value adds nothing.

### 2.2 A remainder is only retriable if another child would ADVANCE it

A number is not a promise. `MAX_ITERS` is the proof: its remainder is real, and a later run restarts from an
empty frontier, so repetition can never reach it (that is why it belongs to `--unbound`). Every lane that
reports a remainder must therefore be classified by its CROSS-RUN progress model:

    project_progress   durable project state advances between runs, so another bounded child continues
                       where this one stopped (the sweep lanes: their rotation ledger is project-scoped)
    rerun_same_work    a later run repeats the same prefix — a remainder here is `--unbound`'s business,
                       never `--settle`'s (the permutation loop today)

A REFUSAL is not terminal. `RotationProgress.tier` ranks a refused target last for
`ADMISSION_COOLDOWN_GENS` generations and then asks again (`budget.py:585`) — "a transient refusal must not
become a permanent membership cap" is the shipped rule. So a guard refusal is RETRIABLE WITH COOLDOWN, and
the record carries the cooldown so the supervisor can tell "waiting" from "impossible". Calling it terminal
would end campaigns early on exactly the lanes the cooldown exists to retry.

That is the lane's CAPABILITY, and it is not the same question as what THIS remainder is made of. One
sweep can hold both at once: pairs a later child will schedule, and pairs no bound can ever admit or that a
guard refused. Collapsing them into one number lets impossible work keep a campaign alive for ever. The
record therefore carries the DISPOSITIONS separately — the sweep already computes exactly this partition
(`refused / unselectable / deferred / bound / stopped`, `1a2eefa`):

**PREREQUISITE B — DONE** (`remainder.py`): the record below is emitted as a `remainder` event and folded
into `manifest.summary.remainders`, LATEST per (lane, unit) so a finished rotation clears the one before
it, and ABSENT when a lane said nothing — which a supervisor reads as unknown, never zero. `LANE_MODEL`
declares each lane's cross-run model (test-enforced against the source registry), `Remainder.retriable` is
0 for a `rerun_same_work` lane however large its numbers, and `from_sweep()` maps the sweep's own partition
onto the dispositions: bound and deferred are retriable now, a refusal is retriable after its COOLDOWN, a
clock stop is retriable next child, and only unschedulable work, a machinery stop or a dependency stop is
terminal.

The record, per lane, in the manifest:

    {"lane": ..., "unit": ..., "measure": "targets|candidate_pairs|rounds|...",
     "model": "project_progress|rerun_same_work",
     "retriable": {"now": int, "cooldown": int},     # attemptable next child / waiting out a cooldown
     "terminal":  {"unschedulable": int, "entitlement": int, "dependency": int, "machinery": int}}

The MEASURE is mandatory: `retriable: 5` is meaningless — targets, candidate pairs and rounds are different
units, and "the remainder went down" cannot be computed across them. Two lanes' numbers are comparable only
within the same (lane, unit, measure), exactly like the coverage records they come from.

`run_sweep` already computes the numbers (`targets_remaining` cumulative and durability-aware, `68195e8`;
`pair_remainder()` for the causes); today they are printed, not persisted. The MODEL is a property of the
lane, declared once beside it — the same shape as the bound registry, and testable the same way: every lane
that can report a remainder must declare a model, and a lane with no record at all is UNKNOWN, never zero.

### 2.3 The union is also the child's INPUT (P0)

Each `Run.create()` starts an EMPTY, run-scoped entity store (`store.py:252`, verified). The union as an
oracle-only artifact would therefore be a trap: once acquisition closes after child 1 (§4), the hosts a
paid provider found would simply be ABSENT from child 2's corpus, the processing lanes would have nothing
to work through, and the campaign would call that a fixed point — `--settle` forgetting the very evidence
it exists to finish processing.

So the union is the campaign's CUMULATIVE STORE, and every child after the first is BOOTSTRAPPED from it
before any phase runs: each owned entity is imported with its provenance intact (`sources`, `raw_ref` and
the discovery context it was found with), marked as inherited so a child's own production is still
distinguishable from what it started with. A child that cannot be bootstrapped does not run — an empty
corpus is not a fixed point.

**PREREQUISITE C — DONE.** `campaign.Union` (`recon/campaigns/<id>/union.jsonl`): `absorb(run_dir)` merges
a finished child's TRUSTWORTHY entities and reports what it added (`new` / `enriched` / `unusable`, with
`progressed` false whenever any evidence could not be read), and `bootstrap(run)` seeds the next child with
provenance intact and `_inherited` set. `Run.inherit()` writes the seed without answering "NEW key", which
is what phases count as discovery — so a child never reports the union as its own find, and a second
bootstrap writes nothing. It preserves `_alt`, unlike the untrusted `add()` path: alternates are material
knowledge, and a child that starts without them starts with less than the campaign holds.

The union carries the SAME trust model as a child's evidence (`new` / `valid` / `degraded` / `unusable`)
and is published as immutable GENERATIONS behind ONE pointer (`union.json` naming `union-gen<N>.jsonl`):
the generation is written complete, the pointer is swapped last, and until it lands the previous generation
is still what the campaign reads. Every row's `kind`, `id` and `fp` are verified rather than trusted, and
the pointer's count and digest catch a clean line-boundary truncation or a same-count rewrite. An absent
pointer is "nothing known yet" only when someone asked to CREATE and no generation survives beside it.
`save()` refuses to publish from a union that is not already trustworthy — otherwise a truncated one would
rewrite the pointer for its survivors and reappear as a smaller healthy campaign — and `recover(reason)` is
the separate, explicitly named path that states what was lost — recorded as an entry in a `recoveries`
history that every later publication CARRIES FORWARD, so a campaign rebuilt after evidence loss can never
go back to looking like one that only ever accumulated. `Union.was_recovered` is what the campaign verdict
must consult before calling anything complete. `absorb()` commits its records only after
publication succeeds; `absorb()` and `bootstrap()` refuse an untrustworthy union by raising
`UnionUnusable`.

## 3. Stop rules, in the vocabulary Quarry actually emits

Manifest verdicts are `complete`, `complete_with_limits`, `complete_with_gaps` — there is no `failed`
(`store.py:533`). The campaign decides from structured fields, not from a verdict word:

    FIXED POINT   EVERY expected participating lane reported an authoritative record, all of them show
                  `retriable.now == 0` AND `retriable.cooldown == 0`, no terminal remainder is outstanding,
                  and the child added no new or enriched identity -> SUCCESS. Success requires KNOWN
                  zeroes: an absent or unknown record is not one, a terminal remainder is not one, and work
                  merely WAITING OUT a cooldown is not one either.
    TERMINAL      retriable work is exhausted but terminal remainders stand — unschedulable pairs, an
                  entitlement or a dependency stop. NOT a guard refusal (retriable with a cooldown, §2.2),
                  and NOT machinery: a machinery remainder is CHILD FAULT's, which is evaluated FIRST, so
                  one child can never be classified two ways. It stays in the terminal counts as DETAIL.
                  A distinct non-success outcome, named with its causes: the campaign finished what it
                  could and says what it could not.
    UNKNOWN       a lane that should have reported did not. Also non-success, also named: a supervisor
                  that reads silence as zero declares victory over work nobody measured. "Should have"
                  needs a machine-readable ROSTER — the lanes the child PLANNED to run, which the phase
                  registry and the mode/scope gating already determine — and every planned lane emits one
                  of known-zero / terminal / unknown. Silence establishes nothing.
    NO PROGRESS   N consecutive children with no new/enriched identity AND no reduction in the retriable
                  remainder -> stop and say so (default N = 2). This is what makes the loop safe — and it
                  OVERRIDES a pending cooldown by design: `ADMISSION_COOLDOWN_GENS` is 16 lane generations,
                  which two idle children will not outlast, and spinning children to burn generations is
                  traffic without discovery. A campaign stopped this way names the waiting cooldown in its
                  stop detail, so the operator can simply run again later — the rotation keeps its place.
                  (`cooldown > 0` therefore blocks SUCCESS but never keeps the loop running.)
    CHILD FAULT   (evaluated FIRST) `summary.phase_exceptions` non-empty, or a STRUCTURED machinery
                  failure — including a machinery remainder — -> stop.
                  Repeating a run that broke is not continuation. Note `summary.failures` does not today
                  separate machinery from an optional tool's failure, and a required MISSING tool arrives
                  in `summary.gaps` instead — so this rule reads `summary.faults` (PREREQUISITE D — DONE:
                  `{kind: machinery | optional_tool_failed | required_tool_missing | phase_exception,
                  where, detail}`), never prose. Provider SPEND per child is `summary.provider_spend`,
                  summed per (lane, provider, MEASURE) — pages and query credits are different currencies,
                  `pages_bought` is not charged requests, and an uncountable amount is reported as unknown
                  rather than as zero.
    BOUNDS        `--settle-max-runs` (default 10) and an optional `--settle-budget` wall clock, each a
                  named cause, never silent.

## 4. Provider acquisition is structurally child-1-only

Rev 1 made this a measurement question. It is not: even if today's Shodan and Whoxy state happens to
prevent a repeat purchase, `--settle` must not be the thing that AUTHORISES later acquisition. The
continuation axis may not make a spending decision (`docs/design/FLAG-AXIS-PLAN.md` §2).

### 4.0 What "acquisition" means (Lumpy, 2026-08-02)

    Quarry directly owns the provider call, the key or the budget   -> settle MUST gate it
    an external tool independently reads its OWN provider config    -> outside Quarry's accounting and
                                                                      authorisation model

`subfinder -all` may call whatever the operator configured inside subfinder, again, on every child. Quarry
neither parses nor polices another tool's private configuration, and pretending to would be a guarantee it
cannot keep. The same holds for opaque behaviour inside any other external tool. (If Quarry ever drives
recursion or paging INTO such a tool, that becomes Quarry's call again and the classification is revisited.)

`policy.PROVIDER_LANES` encodes that ownership line, and `policy.SOURCE_OWNERSHIP` classifies EVERY
registered source so an omission fails a test rather than hiding (`277556e`): our own HTTP
(`probe.favicon`, `probe.cert`, `probe.shodan_host`, `vertical.censys`, `vertical.certspotter`,
`vertical.crtsh`, `osint.whoxy`) and tools we hand a key to and enable ourselves (`vertical.shosubgo`,
`vertical.github_subs`) — and NOT `vertical.openintel`, which is `key`-defaulted for local dataset setup
and queries a local DB, nor the `external_tool` aggregators that read their own configuration.

**Settle still needs its own inventory, at CALL SITES.** The lane list answers "whose policy owns this
bound"; the settle gate answers "which CALL may run again in child 2", and a lane is not always one call:
`osint.whoxy` reaches its provider through plain HTTP in `osint.py` while `probe.favicon` goes through
`run_providers` and `vertical.shosubgo` through `run_contract` — three doors, one of them outside the
source registry entirely. A gate that lives in one of them is not a gate, so the settle inventory is built
and tested against call sites, with `SOURCE_OWNERSHIP` as its source of truth for WHICH lanes must have
one.

So: after child 1, acquisition is CLOSED for the campaign — BUILT: `campaign.acquisition_closed()` is a
restored, run-scoped instruction, `campaign.acquisition_allowed(lane)` refuses only `PROVIDER_LANES`, and
`contract.acquisition_open()` is consulted by BOTH registry doors (`_provider_start` for `run_provider` /
`run_providers`, and `run_contract`) while `osint.whoxy` gates its own direct-HTTP path. A refused lane
records a blocked event and a SKIP with its cause, and `run_providers` no longer runs the SHARED body — the
part that spends — when every lane was refused. Two corrections from the review, both material:

**The lane list has to be real.** It carried `probe.shodan_search`, which does not exist, and OMITTED
`probe.favicon` and `probe.cert` — the two lanes that actually spend Shodan query credits. Corrected and
pinned against the source registry: every name is a registered id, with `osint.whoxy` listed as an EXACT
out-of-registry exception rather than an `osint.*` prefix that would admit a typo.

**One gate is not enough, because there are three execution paths.** `probe.favicon` / `probe.cert` run
through `contract.run_providers` (`probe.py:1059`), `vertical.shosubgo` through `run_contract`
(`vertical.py:1619`), and Whoxy reverse-whois through plain HTTP in `osint.py` (`_whoxy_get`), which
touches neither. A gate in `run_provider` alone would let later children spend. The closure must be a
CHECK EVERY ACQUISITION PATH CONSULTS, with a completeness test in the shape of the bound registry's: every
call site that reaches an external provider is either behind the gate or explicitly classified as not
acquisition.

`--phases` remains far too coarse either way: those Shodan lanes share the `probe` phase with httpx, tlsx
and the rest of the processing this flag exists to continue (`sources.yaml:52-58`).

A closed lane reports itself as a SKIP with the cause ("acquisition closed for this campaign after child
1"), so a child's manifest still says why it did not run — never a silent absence.

Re-acquisition stays a separate, explicit authorisation, designed later. The measurement of §5 is still
worth doing, but it verifies that policy and evidence replay; it does not grant permission.

## 5. Still worth measuring (evidence, not authorisation)

Whether each paid lane's work-unit resume actually skips a repeat query in a NEW run directory — Whoxy
pages, Shodan search/facets, the credit reserve. The campaign ledger records per-child provider spend
either way, so a repeat purchase is visible rather than inferred.

## 6. The campaign ledger — durability and ownership

A supervisor that creates runs needs the same care the rotation got:

* **LOCK the PROJECT, not the campaign directory.** Two supervisors that mint different campaign ids would
  take different campaign-local locks and both spawn children against the same project. The exclusion lock
  is project/target-scoped and held for the WHOLE campaign (the `StateBusy` pattern already used by the
  rotation); a campaign-local lock may still guard ledger integrity;
* **ATOMIC** writes (temp + `os.replace`), like every other state file;
* **CHILD STATES**: `reserved` (id allocated, nothing launched) -> `started` (run dir created) ->
  `manifested` (manifest read, deltas computed). A crash between two of them leaves a child recorded in its
  last known state, so the next supervisor sees an INTERRUPTED child rather than an orphan run directory or
  a campaign that quietly claims it finished.

    recon/campaigns/<campaign_id>/ledger.json
    {campaign_id, target, started, finished, flags,
     children: [{run_id, state, verdict, new_identities, enriched, remainder_before, remainder_after,
                 provider_spend}],
     stop: {cause, detail}}

plus a `campaign` event per transition, so `quarry status` can show a live campaign.

## 7. Build order (after this design is approved)

1. **PREREQUISITE A** — canonical identity, MERGE and material fingerprint per entity kind, exposed for a
   finished run; no supervisor yet.
2. **PREREQUISITE C** — the provenance-preserving bootstrap of a child from the campaign's cumulative
   store, and the rule that an inherited entity is never re-emitted as this child's discovery.
3. **PREREQUISITE B** — the remainder record: per-lane MODEL plus separate retriable and terminal counts
   with their causes, declared and tested for completeness.
4. **PREREQUISITE D** — structured child-fault and provider-spend fields in the manifest, so the campaign
   never interprets prose.
5. the acquisition closure: one check consulted by EVERY acquisition path, with a call-site completeness
   test; plus the §5 measurement written up like the other measured contracts.
6. the campaign supervisor: project lock, ledger with child states, union artifact, stop rules.
7. `--settle-max-runs` / `--settle-budget`, and the `quarry status` view of a campaign.

**STEP 7 — BUILT** (`settle.py`, `quarry run --settle`). The loop is a supervisor over ordinary runs:
reserve -> bootstrap (child 2+) -> acquisition closed (child 2+) -> launch -> absorb -> decide -> record.
The CLI passes `launch`, so this module never owns what a run is. Both bounds are named outcomes, and
`--settle-budget` is asked only BETWEEN children: killing a running child is `--timeout`'s axis and would
destroy the evidence it was producing. `quarry status --campaign` reads the ledger, so a running, finished
and interrupted campaign read the same way, and an unreadable one says so instead of looking empty.

**RESUMING a campaign is NOT implemented, deliberately.** Every existing campaign is refused
(`settle.AlreadyRun`), interrupted ones included. Appending child N+1 to a ledger this process did not
build is not a resume: child 2 would start with acquisition CLOSED although nothing was ever acquired, the
interrupted child's evidence would never be absorbed, the loop's carried state (roster / previous
remainder / idle streak) would start empty, and one quiet child could then declare a FIXED POINT over a
ledger still holding an unfinished child. A real resume must first: reconcile the interrupted child and its
run directory; rebuild the carried state from the ledger; decide the acquisition closure from what was
RECORDED as executed rather than from the child number; and refuse success while any child is interrupted.

Two decisions the build forced:

* **The ROSTER is what the campaign has HEARD.** §3's UNKNOWN rule needs to know which lanes should have
  reported. A roster derived from the phase registry over-claims (a sweep lane with no wildcard zones never
  runs, and its silence would stop every campaign as unknown); one derived from evidence under-claims. So
  the campaign accumulates the lanes that have reported to it, and a lane that reported once and then goes
  silent is UNKNOWN. A lane nobody ever heard from cannot be missed —
* **...which is why a lane that RAN and could not measure now says so** (`remainder.unknown()`, emitted
  where `remainder_known` is false). Staying silent made "ran and cannot say" indistinguishable from "never
  ran", so the roster simply dropped it and the campaign could call a fixed point over work nobody
  measured. The record carries no model and no counts — every consumer classifies it as unreadable, which
  is what unknown means — while the lane's participation stays on the record.
