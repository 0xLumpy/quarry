# Step 4 — stable scheduling progress, separate from evidence (as-built; DESIGN v10 baseline)

> **Verified state 2026-08-03 (`2bcd00a`): BUILT** — `sweep.py` (SCHEMA 2, adaptive prefix subslots, batched invocation) + `budget.py` (the bounded-lane template).


Item 4 of the approved order. This is the design baseline that was
built (`2bcd00a`): `sweep.py` (SCHEMA 2) and `budget.py`. It records the reasoning; where the shipped
code diverged — adaptive prefix subslots and batched invocation — the as-built notes below say so.

## What this must fix

| defect (measured / reviewed) | consequence |
|---|---|
| a bounded run restarts from an empty map | the same deterministic prefix is re-submitted forever, the tail never runs |
| `budget.Ledger` binds item → durable artifact | it cannot express "selected but not yet run", and project-owned output would make evidence project-scoped |
| ordinal chunks (`words[i:i+N]`) | one new lexically-early word shifts every later chunk: the whole rotation invalidates |
| a word mined by two sources | submitted twice, or arbitrarily attributed |
| `Budget.exhausted()` only fires BETWEEN items | one `puredns`/`httpx` invocation per target is a single item — nothing can stop mid-list |

## The split

- **EVIDENCE — run-scoped, unchanged.** Discovered hosts, raw output, coverage: all in `ctx.run`.
- **SCHEDULING PROGRESS — project-scoped, durable, bounds nothing.** It only ORDERS. Losing it costs
  ordering quality, never coverage.

## The scheduling unit

    slot   = (lane, target, bucket)                       # target = apex (4.2) or zone (4.3)
    bucket = hash-prefix of the word, mod BUCKETS         # adding a word never moves another word's bucket

Source is not part of the slot: with it, 49,634 words over 3 sources and 256 buckets is ~65 words per
invocation and up to 768 invocations per apex instead of ~195 and 256. `BUCKETS` is schema-bound and set
by the timing pass.

A slot is not one invocation. The allocator batches several buckets of a target into one runner call
(`reserve_batch`, `chosen: [(bucket, words)]`), and a slot too large for the batch cap splits into
hash-prefix subslots. The wall-clock budget is checked between invocations, so `invocations` is its own
measure — runner calls that ran, not a slot count.

## Generations: the reservation is the authority

A monotonic `gen` per lane, incremented under the lane lock. Every reservation takes the next one; a
completion may only publish if its generation is still the newest for that slot.

    # THE WHOLE SWEEP RUNS UNDER THE LANE LOCK. `picked` is run-local, so it cannot keep a
    # SECOND lifecycle out of a slot this one already ran: two concurrent runs would each exclude only
    # their own picks and could execute every slot twice — duplicate traffic at the target, which no CAS
    # can prevent (CAS protects STATE from a stale completion, it is not an execution claim).
    # BEFORE the lock: the workload is a pure function of the corpus and the eligible
    # targets, so a CONTENDER can still report exact coverage — tested=0, omitted=eligible — instead of a
    # gap with no denominator.
    preflight_dependency()                          # no reservations at all if the tool is absent
    eligible = snapshot_slot_keys()                 # taken ONCE at lane start
    pairs    = sum(len(members(s)) for s in eligible)

    # ACQUISITION-ONLY contention handling. Wrapping the whole `with` in `except StateBusy`
    # would report a StateBusy raised by the SWEEP BODY as "another lifecycle owns this" — the same boundary
    # already corrected in Whoxy. Only the acquisition is inside the except.
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(lane_lock)          # non-blocking
        except budget.StateBusy as e:
            return contention_gap(pairs, e)         # zero evidence, exact denominator, FAILED terminal

        picked = set()                              # run-local: each slot is reserved at most once

        while not budget.exhausted() and (eligible - picked):
            state = load()
            gen   = state.next_gen()                # monotonic, durable
            slot  = rank_and_pick(exclude=picked)
            slot.reservation = {"gen": gen, "at": now}
            target.last_selected_seq = gen          # the cursor is the SEQUENCE, not the clock
            reservation_saved = state.save()
            picked.add(slot.key)
            reservations_persisted += 1 if reservation_saved else 0   # the ROTATION advanced by this many

            if not reservation_saved:               # FAIL CLOSED
                stop = "machinery: reservation state could not be saved"
                break                               # no request is issued for an unowned slot

            try:
                result = exec_tool(...)             # the lock is HELD across this: one sweeper per lane
            except (KeyboardInterrupt, SystemExit):
                raise                               # cancellation ends the run, never a slot outcome
            except Exception as e:                  #: `runner.run` can raise around Popen
                machinery.append(f"{slot.key}: {type(e).__name__}: {e}")
                stop = "machinery: the invocation raised"
                break                               # reservation stays persisted; NO completion, and this
                                                    # slot never enters the attempted denominator
            outcome.record(result)                  # slot_outcomes: obtained / classed loss
            match publish_held(state, slot, gen, result):        # HELD: never re-acquires
                case "published":
                    completions_published += 1
                case "failed":
                    completion_unpersisted += 1     # ran, evidence kept, may be selected again
                case "not_run":                     # the tool vanished mid-sweep
                    stop = "dependency: the tool did not run"
                    break
                case "invariant":                   # a bug, not a disposition
                    machinery.append(f"scheduler_invariant: {slot.key}")
                    stop = "machinery: scheduler invariant"
                    break

### One sweeper per lane

The lane lock is held for the WHOLE sweep, exactly as `whoxy_page.lifecycle_lock` does: acquisition is
non-blocking, so a second run records a zero-evidence gap ("another lifecycle owns this rotation") and
submits nothing rather than duplicating traffic. The runner is synchronous, so a crashed lifecycle cannot
return later and publish: within a sweep the generation check is an INVARIANT, and generations keep
their real job in the MERGE rule, where two snapshots of the same lane must be ordered.

The trade-off is explicit: under `budget = 0` (unbounded) the sweep can hold the lane for a long time, and
a concurrent run gets a gap rather than partial work. That is the same bargain every ledger-owning lane in
Quarry already makes, and the alternative — per-slot in-flight ownership with crash-safe release — is a
lease protocol this lane has no reason to invent.

### Each slot runs at most once per lifecycle

`eligible` is snapshotted at lane start and `picked` is run-local. Without it, ranking would happily
re-select the oldest CLEAN slot once every slot is clean: a long bounded run would cycle over completed
work, and an unbounded budget (`0`, the template default) would never terminate. The loop ends when the
budget is exhausted OR every eligible slot has been picked once — so an unbounded lifecycle performs
exactly one full sweep and stops.

### The reservation-save failure has ONE rule: fail closed

If the reservation cannot be persisted, the lane issues **no request** for that slot and stops with a
machinery gap. These lanes CONTACT the target; running work whose reservation nobody owns — while the
rotation has not advanced — is the wrong side to err on. (The run-local `picked` set means the same slot
would not be offered again in this lifecycle either way; the stop is about not spending on an unowned slot,
not about avoiding a loop.)

### Publishing a completion: four dispositions

    def publish_held(state, slot, gen, result) -> "published | failed | not_run | invariant":
        """Called WITH the lane lock already held — it must never acquire it again.
        `budget.state_lock` is flock-based: non-reentrant and non-blocking, so a nested acquisition in the
        SAME process raises `StateBusy` (proven by the Whoxy nested-lock regression). A publish that
        re-locked would exhaust its retries and report every completion as failed."""
        if result.status is SKIPPED:              # no process ran
            return "not_run"
        try:
            if state.slot.reservation.gen != gen:
                # UNREACHABLE while one sweeper owns the lane: nobody else can re-reserve. Kept as an
                # INVARIANT check, and a mismatch is machinery — `scheduler_invariant` — not a normal
                # disposition.
                raise SchedulerInvariant(f"{slot.key}: reservation gen moved under the holder")
            state.slot.done = {"gen": gen, "ran_at": now, "content": digest, "members": n}
            return "published" if state.save() else "failed"
        except (KeyboardInterrupt, SystemExit):
            raise                                 # cancellation is never contained
        except SchedulerInvariant:
            return "invariant"                    # NOT an ordinary publication failure
        except Exception:                         # a broken save, a raising serializer …
            return "failed"

Every ordinary failure after the evidence exists is contained here; only cancellation propagates. There is
no contention branch any more: the caller already holds the lock, so the only ways to fail are a broken
`save()` or a broken state, and both are contained with the evidence intact.

**`SKIPPED` is a dependency answer, not a scheduling one.** The tool's absence is checked
ONCE, before the first reservation, and the lane records a dependency gap and reserves nothing. The
post-call branch remains for the race (a binary removed mid-sweep): the disposition is `not_run`, it
records the dependency gap, it STOPS the lane — reserving every remaining slot against a tool that is not
there would burn the whole rotation — and it never enters the attempted denominator.

- **Generations order two SNAPSHOTS of the same lane.** Concurrent overlap is impossible (one sweeper per
  lane) and a crashed lifecycle cannot publish afterwards, so within a sweep the generation check is an
  invariant. Its real job is the merge rule below, when a lane file is restored, copied or written by an
  adopter of the shared primitive.
- **The completion is ONE tuple**, replaced whole and only by a newer generation. Field-wise max-wins is
  abandoned: it could assemble `ran_at`, digest and member count from three different runs.
- **A failed reservation save is not authoritative**, and nothing runs on it: see the fail-closed rule
  above.

### The completion boundary is its own fact

`reservation_saved` and `completion_saved` are tracked independently, because they mean different things:

| | meaning | consequence |
|---|---|---|
| reservation contention / save failure | we never owned the slot | FAIL CLOSED: issue no request, stop the lane with a machinery gap |
| completion save failure | the tool ALREADY RAN and its evidence exists | keep the evidence, keep the outcome counters, and report that this slot may be selected again |

A completion failure must never escape and abort the phase: it is contained, the evidence and the outcome
counters stand, and the affected slots are named.

**Three separate durability facts** — one lane-wide `durable=False` would claim the whole
remainder "restarts from the beginning", which is false when a single completion write failed:

| count | meaning | wording |
|---|---|---|
| `reservations_persisted` | slots whose reservation reached disk | the rotation advanced by this many |
| `completions_published` | returned slots whose completion reached disk | those slots are clean for the next sweep |
| `reservation_failed` | the slot whose reservation could not be saved (fail-closed stop) | "that slot is re-offered next run" |
| `completion_unpersisted` | returned slots whose completion could not be published | "N slot(s) ran but may be selected again" |
| `scheduler_invariant` | a reservation generation moved while THIS lifecycle held the lane | a bug, reported as machinery — not an expected disposition |

`rotation_advanced` as a lane-wide Boolean is wrong: ten persisted reservations followed by
one failure neither fully advanced nor restarted. The selection record names the COUNTS; the all-or-nothing
"restarts from the beginning" wording is reserved for the case where NO reservation persisted, or the state
became unusable altogether.

## The one launch fact we can observe

`runner.run()` returns only after the process completes, and it has no start hook. Measured shapes: a
missing binary returns `SKIPPED` with no process; a timeout returns `TIMED_OUT` after the process ran and
was killed; a cancellation re-raises and returns nothing at all.

So the unit is **runner invocations that RETURNED a process result** — i.e. `exec_tool` returned and the
status is not `SKIPPED`. `ran_at` is written for exactly that state, and the word "launched" is dropped
from the design: it names something the caller cannot see.

## Ranking: exact, sequence-driven

    tier(slot) = 0 if slot.done is None            # never RAN (incl. reserved-then-crashed)
                 1 if slot.done.content != today   # DIRTY: membership changed since the slot last ran
                 2 otherwise                       # clean

    t*      = min(tier(s) for every slot of every eligible target)      # TIERS FIRST, globally
    targets = [targets having a slot at t*]
    target  = min(targets, key=(target.last_selected_seq or 0, target_name))   # fairness INSIDE the tier
    slot    = min(target's slots at t*, key=(slot.reservation.gen or 0, bucket))

Tier dominates target fairness: a target holding only clean work must not run while another
target still has never-run or dirty work. Pinned case — target A clean and long-unselected, target B dirty
and recently selected: **B wins**.

The cursor is the reservation **sequence**, not wall time, so a clock that jumps backward cannot break the
alternation. Timestamps stay in the record for operators, never for ordering. Two targets with work IN THE
SAME TIER alternate A,B,A,B because the cursor advances on every pick.

"Dirty" means **membership changed since the slot last ran** — the reservation ordering cannot promise
"holds words never submitted".

## Ownership of shared words — accounting attribution only

    owner(word) = argmax over sources_that_produced(word) of sha256(word + "|" + source_id)

The argmax ranges ONLY over the sources that actually produced the word, so attribution can never name a
source that never saw it. Rendezvous hashing keeps it stable per word while that producer set is unchanged
(a new producer can move the word — documented and tested).

It is **accounting attribution**: it decides which source a submitted word is counted against, and nothing
else. Provenance is untouched — evidence keeps every source that produced a word, and overlapping-provenance
counts are reported separately.

Source proportionality is an EXPECTATION, not a guarantee: uniform hashing spreads sources across the whole
corpus, but the first k scheduled buckets need not preserve those proportions. The timing pass measures the
post-attribution distribution of scheduled PREFIXES.

## Coverage — three measures, and the stop cause lives in the terminal

**A raising invocation keeps everything already earned.** The slot's reservation stays on
disk (the rotation advanced), the failure is machinery, the lane stops, and every earlier slot's evidence
and outcome counters survive. The terminal is PARTIAL when this sweep produced evidence and FAILED when it
produced none — the same rule every other lane here uses.

**Contention is an ACQUISITION fact, not a body fact.** A `StateBusy` (or `OSError`) raised
INSIDE the sweep is machinery and is reported as such; only a failure to ENTER the lane lock is contention.
Both directions are pinned.

**A contender reports exact coverage.** Losing the lane lock is not "no data": the workload was computed
before the acquisition, so the contending run emits `candidate_pairs` with `tested=0, omitted=pairs`, a
`slot_outcomes` record with `attempted=0`, and a FAILED zero-evidence terminal naming the holder — the same
contract the other run-scoped lanes use.

1. **selection over candidate-target PAIRS** — `measure="candidate_pairs"`, eligible =
   `sum(len(members) for every slot of every eligible target)`, attempted = pairs in slots whose invocation
   returned. The record is rendered BY THE ACTUAL STOP: `COVERAGE_CAP` when a budget stopped us,
   `COVERAGE_TIMEOUT` when contention or a machinery failure did, `omitted=0` when the whole set ran.
   `budget.report_selection` words every omission as "budget exhausted", so it gains an explicit stop
   parameter (default = today's budget wording, so no existing caller changes).
2. **outcome over SLOTS** — `measure="slot_outcomes"`, attempted = invocations that returned, obtained =
   those whose tool completed cleanly, `classes` = error classes of the rest. "Cleanly" is a pinned status
   mapping, not prose:

   | status | counts as |
   |---|---|
   | `SUCCESS`, `EMPTY` | obtained (EMPTY is a clean answer: the bucket resolved nothing) |
   | `PARTIAL`, `FAILED`, `TIMED_OUT`, `BLOCKED` | attempted-but-lost, each its own class |
   | `SKIPPED` | never enters the attempted denominator (no process ran) |

Coverage is recorded in three measures: `candidate_pairs` (the selection denominator), `slot_outcomes`
(the per-slot classes above), and `tool_invocations` (runner calls — one call may carry several slots).
The stop CAUSE is not a further denominator: it is carried by the lane's terminal and the selection
record's wording, not by re-counting the same remainder.

## Storage

    <project>/recon/state/sched/v<SCHEMA>/a1d.json       + a1d.lock
    <project>/recon/state/sched/v<SCHEMA>/wildcard.json  + wildcard.lock

    {"lane": "a1d", "schema": N, "gen": 41,
     "targets": {"acme.com": {"last_selected_seq": 41,
                              "slots": {"07": {"res": {"gen": 41, "at": 1753…},
                                               "done": {"gen": 39, "ran_at": 1753…,
                                                        "c": "<digest>", "n": 195}}}}}}

`SCHEMA` binds `BUCKETS`, the hash algorithm and the record's meaning — changing any of them starts a fresh
rotation instead of misreading old records. Atomic save (temp + `os.replace`).

**Merge: a slot holds TWO independently ordered tuples.** Reservation gen 41 can sit beside
completion gen 39, so "newest generation wins per slot" is ambiguous and could erase a newer completion:

- `reservation` is replaced when the incoming `reservation.gen` is greater;
- `done` is replaced when the incoming `done.gen` is greater;
- each tuple is atomic — its fields are never merged field-by-field;
- the lane's `gen` and each `target.last_selected_seq` merge by `max`.

No `done` flag in the completion sense: scheduling knows recency and membership, never success.

## Shared primitive

Extract a GENERIC `budget.RotationProgress`, and make "the lock is already held" STRUCTURAL rather than a
caller convention — otherwise a `save()` that takes its own lock reintroduces exactly the
self-contention v8 fixed:

    with budget.rotation_session(state_dir, lane) as progress:   # takes the lane lock ONCE
        ...                                                      # progress.save() never re-acquires
        progress.save()

`rotation_session` yields `RotationProgress(held=True)`, mirroring `SweepProgress(held=…)`, which exists for
this precise reason (a nested flock in the same process is `StateBusy` — proven). A test pins that no save
inside a session performs a second acquisition, and that a save OUTSIDE a session takes the lock itself.

Beyond that: validated keys and records, schema-bound, generation-ordered merge, atomic save, best-effort
semantics. `shodan_host.SweepProgress`'s IP canonicalisation stays in a
Shodan adapter; only the mechanism is shared, and Shodan adopts it in its own commit.

## Open, for the timing pass (item 5)

- `BUCKETS` — from measured `puredns`/`httpx` wall-clock per invocation, including process startup;
- per-lane default budget seconds (an ACTIVE lane's default comes from measurement, not taste);
- post-attribution source distribution of the first k scheduled buckets;
- whether the wildcard baseline pair is re-probed per bucket (correctness) or once per zone per run (cost);
- whether invocation overhead is small enough to reconsider equal-share source fairness.

---

## Ledger ownership states

`Ledger.lost` holds items the snapshot recorded as done whose artifact no longer verifies: missing,
altered, or filed without a digest. Redoing them is correct, because the evidence really is gone. For
a paid lane "redo" means buy again, and a repurchase that looks identical to a first purchase is the
accidental spend the ownership store exists to prevent. The ledger keeps the loss as a fact and never
decides what it costs — the lane that knows whether an item is paid for decides that.

`Ledger.unreadable` holds the reason an ownership index that exists cannot be trusted: garbled,
truncated, or shaped wrong. Absent and unusable never collapse into the same empty dict. If they did,
a corrupt snapshot would read as a clean store, a paid lane would see nothing owned, and it would buy
every page again. The field is prose rather than a flag because the caller has to report why it
refused.

The same distinction appears one level down in the artifact store (`shodan_sched.ownership_view`) and
one level up in the run verdict: a failure to inspect ownership blocks spending, and never erases
ownership from the decision.

---

## Sweep dispositions

### The `run_sweep` bounds

`max_pairs_per_target` is a spend bound: a slot that would take a target past it is not submitted, so
the bound is never exceeded. `max_targets_per_run` bounds throughput, never membership — the rotation
decides which targets, so a later run continues instead of contacting the same first N for ever. Both
are 0 for unbounded.

`admit(target)` is an optional per-target admission check for work that is itself active. It runs after
the target's first batch is reserved and persisted, once per target per lifecycle. A refusal consumes
the allowance and excludes that target's remaining slots — no backfill, or many refusals would recreate
the traffic the allowance bounds. The reservation has already advanced the cursor, so a refused target
moves to the back of its tier, and the refusal is recorded on its own: never an invocation, never
attempted pairs.

### Classifying a run that ended before the rotation could be read

Every early exit reaches `_partition_unrun`. Nothing completed, so the eligible targets are what is
owed, and the only question is who holds them. A lane that returns without a partition publishes zeroes,
which a supervisor reads as a fixed point.

| what stopped it | class | why |
|---|---|---|
| dependency / machinery | terminal | repetition does not install a tool or unbreak a run |
| contention | retriable | another lifecycle is advancing this rotation |
| nothing schedulable | terminal, as `unschedulable` | only when a corpus exists at all |
| anything else | retriable | |

An eligible set that was never established stays unknown, which is not zero.
