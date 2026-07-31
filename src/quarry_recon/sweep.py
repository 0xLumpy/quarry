"""The SWEEP DRIVER — bounded, fair, resumable ACTIVE selection over a stable slot space.

`budget.py` bounds a lane's THROUGHPUT over an eligible set that is already known. This module answers the
harder half for lanes whose eligible set is a VOCABULARY crossed with TARGETS: which words does a bounded
run actually submit, in what order, and how does the next run continue rather than repeat?

The contract, argued out over ten review rounds (`notes/STEP4-SCHEDULING-DESIGN.md`):

  SLOT       (target, bucket), where `bucket = sha256(word) % BUCKETS`. A word's bucket depends on the WORD
             alone, so adding one word never moves another — the defect that made ordinal chunks
             (`words[i:i+N]`) invalidate a whole rotation on a single insertion.
  ONE SWEEP  the lane lock is held for the WHOLE sweep. `picked` is run-local and cannot keep a SECOND
             lifecycle out of a slot, so two concurrent runs would each exclude only their own picks and
             could contact every target twice. A contender reports a zero-evidence gap instead.
  ORDER      tier first (never-run -> dirty -> clean), target fairness INSIDE the tier. A target holding
             only clean work must not run while another has never-run work.
  FACTS      the reservation is written BEFORE the tool runs and the completion AFTER it returned. Nothing
             about SUCCESS is durable: outcomes are evidence, and evidence is run-scoped.

Coverage is two records with different denominators: candidate-target PAIRS (selection) and SLOTS
(outcome). A launched-but-failed bucket must not read as tested with no gap.
"""
from __future__ import annotations

import contextlib
import hashlib
import re
import time
from dataclasses import dataclass, field

from . import budget, events
from .runner import Status

#: bump when the SLOT SPACE changes meaning — the bucket count, the hash, or the id grammar. A bump starts
#: a fresh rotation rather than reading old records under new arithmetic. 2: adaptive prefix subslots.
SCHEMA = 2

#: how many buckets a lane's vocabulary is spread over. One bucket = one tool invocation, so this is the
#: granularity at which a wall-clock budget can stop us (`Budget.exhausted()` only fires BETWEEN items).
#: MEASURED input for the choice is the timing pass; 256 over the OTC corpus is ~195 candidates per call.
BUCKETS = 256


#: how many extension bits a slot id may carry beyond its root, and where they come from. `sha256` hex
#: digits 8..24 are the 64 bits after the four the root is taken from, consumed most-significant first.
EXT_BITS = 64

#: the id grammar schema 2 accepts: a three-digit root, optionally extended by `.` and up to `EXT_BITS`
#: binary digits. Anything else is not a slot this lane can rank, split or complete.
SLOT_RX = re.compile(rf"^[0-9]{{3}}(\.[01]{{1,{EXT_BITS}}})?$")


def slot_id_ok(slot: str, buckets: int | None = None) -> bool:
    """Whether a persisted id belongs to this slot space. Rank inheritance walks ids structurally, so an
    arbitrary dotted string must never take part in it (v25).

    `fullmatch`, not `match`: `$` also matches before a trailing newline, so `"158.0\n"` passed (v26#2).
    And the root is a bucket, not any three digits — `999` is not a slot of a 256-bucket space."""
    if not isinstance(slot, str) or not SLOT_RX.fullmatch(slot):
        return False
    return 0 <= int(slot.partition(".")[0]) < (buckets or BUCKETS)


def _parts_of(word: str) -> tuple:
    """(root, extension). The root is the historical bucket — digest bits 24..31 — and the extension is the
    next 64 bits. Splitting only ever lengthens the extension, so a word never moves sideways."""
    h = hashlib.sha256(word.encode("utf-8")).hexdigest()
    return int(h[:8], 16), int(h[8:24], 16)


def bucket_of(word: str, buckets: int | None = None) -> str:
    """The ROOT slot a word belongs to — extension depth 0. Stable per word: inserting words never moves
    the ones already placed.

    `BUCKETS` is read at CALL time, not bound as a default: a default argument would freeze the module
    constant at import, so changing the bucket count (which the timing pass may do, with a schema bump)
    would silently keep the old slot space."""
    return f"{_parts_of(word)[0] % (buckets or BUCKETS):03d}"


def slot_of(word: str, depth: int = 0, buckets: int | None = None) -> str:
    """The id of the slot holding this word at `depth` extension bits. Depth 0 is `bucket_of` exactly, and
    a deeper id only lengthens the prefix — every deeper slot is CONTAINED in the shallower one."""
    root, ext = _parts_of(word)
    depth = max(0, min(int(depth), EXT_BITS))
    bits = "".join(str((ext >> (EXT_BITS - 1 - k)) & 1) for k in range(depth))
    return f"{root % (buckets or BUCKETS):03d}" + (f".{bits}" if bits else "")


def _exact_cap(cap) -> int:
    """The bound is an EXACT non-negative int. `True` is not 1 and `-1` is not "unbounded" (v26#4): the
    documented contract is 0 = unbounded, and a negative bound meant "unbounded" to the allocator while
    the driver read it as a bound that nothing can satisfy — two answers to one question."""
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
        raise ValueError(f"the per-target bound must be an exact non-negative int (0 = unbounded), "
                         f"got {cap!r}")
    return cap


def allocate(words, *, cap: int) -> dict:
    """Group words into slots no larger than `cap`, splitting a slot that does not fit into its two hash
    children until it does. `cap=0` (unbounded) leaves the roots alone.

    This is what makes the per-target bound REACHABLE. `run_sweep` excludes a slot whose own size crosses
    the bound, so before this a corpus with a bucket bigger than the cap left those words permanently
    unselectable — measured: 87% of pairs unreachable at 525,000 words, and every lifecycle after that
    re-ran the same reachable minority for ever (timing pass, finding 2)."""
    cap = _exact_cap(cap)
    groups: dict = {}
    for word in words:
        groups.setdefault(bucket_of(word), []).append(word)
    if not cap:
        return groups
    out: dict = {}
    for root, members in groups.items():
        _split(root, "", members, out, cap)
    return out


def _split(root: str, bits: str, members: list, out: dict, cap: int) -> None:
    """One deterministic split step. An EMPTY child is not a slot, and the depth limit is a floor on how
    far this recurses — a residual over the cap there can only come from a 64-bit collision class, and it
    stays visible as an excluded slot rather than being silently dropped."""
    if len(members) <= cap or len(bits) >= EXT_BITS:
        out[root + (f".{bits}" if bits else "")] = members
        return
    shift = EXT_BITS - 1 - len(bits)
    zero: list = []
    one: list = []
    for word in members:
        (one if (_parts_of(word)[1] >> shift) & 1 else zero).append(word)
    for bit, part in (("0", zero), ("1", one)):
        if part:
            _split(root, bits + bit, part, out, cap)


def owner_of(word: str, sources) -> str:
    """ACCOUNTING attribution for a word produced by several sources — rendezvous (HRW) hashing.

    Not provenance: evidence keeps every source that produced a word. This decides which source a SUBMITTED
    word is counted against, and it de-duplicates a shared word to one submission. Stable per word while the
    producer set is unchanged, and it spreads shared words instead of handing them all to whichever source
    sorts first. The argmax ranges ONLY over sources that actually produced the word."""
    return max(sources, key=lambda s: hashlib.sha256(f"{word}|{s}".encode("utf-8")).hexdigest())


def content_digest(members) -> str:
    """The digest of the members SUBMITTED for a slot — what makes a later membership change visible."""
    h = hashlib.sha256()
    for word in sorted(members):
        h.update(word.encode("utf-8"))
        h.update(b"\\n")
    return h.hexdigest()


@dataclass
class SweepResult:
    """What the sweep did, in the vocabulary the terminal and the coverage records need."""
    eligible_pairs: int = 0
    attempted_pairs: int = 0            # candidates inside slots whose invocation RETURNED
    slots_attempted: int = 0
    slots_obtained: int = 0             # SUCCESS or EMPTY — a clean answer, including "nothing resolved"
    classes: dict = field(default_factory=dict)
    reservations_persisted: int = 0
    pending_completions: int = 0        # completions rescued by a later save are counted as published
    completions_published: int = 0
    completion_unpersisted: int = 0
    #: ACCOUNTING attribution. `eligible` is the whole corpus; `attempted` is the SCHEDULED PREFIX — the
    #: distribution the timing pass actually needs, since uniform hashing spreads sources over the CORPUS
    #: and says nothing about the first k buckets (review v14#3).
    per_source_eligible: dict = field(default_factory=dict)
    per_source_attempted: dict = field(default_factory=dict)
    machinery: list = field(default_factory=list)
    stop: str | None = None             # None = the whole eligible set ran
    #: what ENDED the sweep: None (nothing did), "budget", "machinery", "contention", "dependency". The
    #: coverage KIND follows from it (a budget or a candidate bound is a CAP we chose; everything else is
    #: a TIMEOUT-class gap),
    #: and the terminal needs the cause even when the wording is identical (review v14#4).
    stop_kind: str | None = None
    state_status: str = "missing"
    contended: bool = False

    @property
    def ran(self) -> bool:
        return self.slots_attempted > 0

    @property
    def durable(self) -> bool:
        """Whether the remainder is a RESUMABLE remainder rather than "this lane restarts from the
        beginning". review v14#2: one lane-wide False claimed the restart even after reservations and
        completions had persisted — the Boolean the design rejected. Rendered from the state and the
        counters instead:

        * unusable state -> False: nothing can be trusted, so nothing can be resumed;
        * a machinery stop that persisted NOTHING -> False: we tried to advance and could not;
        * anything else -> True, including contention (the holder is advancing it), a missing dependency
          (nothing was touched) and a machinery stop AFTER real progress."""
        if self.state_status == "unusable":
            return False
        return not (self.stop_kind == "machinery" and self.reservations_persisted == 0)


#: statuses that mean the tool answered. EMPTY is an answer ("this bucket resolved nothing"); SKIPPED never
#: enters the attempted denominator because no process ran (step-4 design v5#4 / v7#2).
_OBTAINED = (Status.SUCCESS, Status.EMPTY)


def run_sweep(*, lane: str, state_dir, targets, vocabulary, execute, budget_s: int,
              coverage_lane: str, dependency_ok=None, attribution=None, max_pairs_per_target: int = 0,
              now=time.time) -> SweepResult:
    """Drive one lane's sweep.

    `vocabulary(target) -> list[str]` is the eligible corpus for that target; the driver buckets it.
    `max_pairs_per_target` (0 = unbounded) is a SPEND bound in candidates per target: a slot that would
    take a target past it is not submitted, so the bound is never exceeded — a wall-clock budget cannot
    express "no more than N names per apex", which is what an existing lane's posture may already be.
    `execute(target, bucket, words) -> RunResult` submits one slot. `attribution(word) -> source` is
    optional ACCOUNTING only. Returns what happened, emits the two coverage records, and raises nothing but
    cancellation."""
    out = SweepResult()
    clock = budget.Budget(budget_s)

    # ── BEFORE the lock: the workload is a pure function of the corpus and the targets, so a CONTENDER can
    #    still report an exact denominator instead of a gap with no arithmetic (design v8#2). ──
    members: dict = {}
    seen_pairs: set = set()
    corpus: dict = {}
    for target in dict.fromkeys(targets):              # a repeated target is one target
        per_target: list = []
        for word in vocabulary(target) or []:
            if (target, word) in seen_pairs:           # review v14#5: one submission per word per target —
                continue                               # a duplicate would inflate the denominator, the
            seen_pairs.add((target, word))             # digest, the attribution AND the active payload
            per_target.append(word)
        corpus[target] = per_target
    # the DENOMINATOR is known before the bound is: every eligible pair exists whether or not we can
    # partition it (v27#2). Reporting 0/0 for a lane that had work would hide the omission entirely.
    out.eligible_pairs = sum(len(words) for words in corpus.values())

    try:
        max_pairs_per_target = _exact_cap(max_pairs_per_target)
    except ValueError as e:
        # the driver promises to raise nothing but cancellation, so a nonsense bound is a MACHINERY stop
        # with nothing submitted — never a silent "unbounded" and never a bound nothing can satisfy.
        out.stop, out.stop_kind = f"machinery: {e}", "machinery"
        _report(coverage_lane, out, clock)             # v27#1: coverage is filed under the REGISTERED
        return out                                     # source, never the scheduler's private lane name

    for target, per_target in corpus.items():
        partition = allocate(per_target, cap=max_pairs_per_target)
        placed = [word for group in partition.values() for word in group]
        if len(placed) != len(per_target) or set(placed) != set(per_target):
            # v28: a pair the partition dropped is not a RESUMABLE remainder — it is in no slot, so no
            # rotation will ever reach it, and reporting it as "left over" would promise a later run that
            # cannot happen. Membership, not counts: one dropped word and one duplicated word balance.
            out.stop = (f"machinery: the slot partition does not cover {target} "
                        f"({len(placed)} placed, {len(set(placed))} distinct, of {len(per_target)})")
            out.stop_kind = "machinery"
            _report(coverage_lane, out, clock)
            return out
        for slot, group in partition.items():
            members[(target, slot)] = group
    slots = sorted(members)
    # the denominator stays the CORPUS count taken above, not a re-count of the partition: if allocation
    # ever lost a word, that has to surface as an unattempted pair, not shrink the denominator to match.
    content = {slot: content_digest(words) for slot, words in members.items()}
    owners: dict = {}
    if attribution is not None:
        for words in members.values():
            for word in words:
                owners[word] = src = attribution(word)      # cached: the attempted split must be counted
                out.per_source_eligible[src] = out.per_source_eligible.get(src, 0) + 1

    if dependency_ok is not None and not dependency_ok():
        out.stop = "the tool is not installed"          # no reservations at all (design v7#2)
        out.stop_kind = "dependency"
        _report(coverage_lane, out, clock)
        return out

    with contextlib.ExitStack() as stack:
        try:
            progress = stack.enter_context(budget.rotation_session(state_dir, lane, schema=SCHEMA,
                                                                   slot_grammar=slot_id_ok))
        except budget.StateBusy as e:
            # ACQUISITION-only: a StateBusy raised by the sweep BODY is machinery, not contention (v10#2).
            out.contended = True
            out.stop = f"another lifecycle owns this rotation ({e})"
            out.stop_kind = "contention"       # nothing was submitted and NO completion state was lost
            _report(coverage_lane, out, clock)
            return out

        out.state_status = progress.state_status
        if progress.state_status == "degraded":
            out.machinery.append(f"rotation state degraded: {progress.state_reason}")
        picked: set = set()
        spent: dict = {}                                   # candidates submitted per target
        while not clock.exhausted() and len(picked) < len(slots):
            choice = _rank(progress, slots, content, picked)
            if choice is None:
                break
            target, bucket = choice
            words = members[choice]
            if max_pairs_per_target and spent.get(target, 0) + len(words) > max_pairs_per_target:
                # this target has spent what it may. Excluding the SLOT (not just skipping the pick) keeps
                # the loop terminating and leaves the remainder to the next run's rotation.
                picked.add(choice)
                out.stop_kind = out.stop_kind or "bound"
                out.stop = out.stop or (f"the per-target candidate bound ({max_pairs_per_target}) was "
                                        f"reached")
                continue
            picked.add(choice)
            spent[target] = spent.get(target, 0) + len(words)
            gen = progress.reserve(target, bucket, at=now())
            if not progress.save():
                # FAIL CLOSED: nothing is submitted for a slot whose reservation nobody owns (v6#2).
                out.stop = "machinery: the reservation could not be persisted"
                out.stop_kind = "machinery"
                break
            out.reservations_persisted += 1
            _rescue(out)                       # this save also carried any pending completion (v14#1)

            try:
                result = execute(target, bucket, words)
            except (KeyboardInterrupt, SystemExit):
                raise                                   # cancellation ends the run, never a slot outcome
            except Exception as e:                      # `runner.run` can raise around Popen (v10#1)
                out.machinery.append(f"{target}/{bucket}: {type(e).__name__}: {e}")
                out.stop = "machinery: the invocation raised"
                out.stop_kind = "machinery"
                break

            if result.status is Status.SKIPPED:          # no process ran — a dependency answer
                out.stop = "the tool did not run"
                out.stop_kind = "dependency"
                break
            out.slots_attempted += 1
            out.attempted_pairs += len(words)
            for word in words:                              # review v15#4: the two attempted totals must
                src = owners.get(word)                      # agree even when publication never happens
                if src is not None:
                    out.per_source_attempted[src] = out.per_source_attempted.get(src, 0) + 1
            if result.status in _OBTAINED:
                out.slots_obtained += 1
            else:
                key = str(getattr(result.status, "value", result.status))
                out.classes[key] = out.classes.get(key, 0) + 1

            try:
                progress.complete(target, bucket, gen, at=now(), content=content[choice],
                                  members=len(words))
                published = progress.save()
            except (KeyboardInterrupt, SystemExit):
                raise
            except budget.SchedulerInvariant as e:
                out.machinery.append(f"scheduler_invariant: {e}")
                out.stop = "machinery: scheduler invariant"
                out.stop_kind = "machinery"
                break
            except Exception as e:                      # the evidence exists; only the bookkeeping failed
                out.machinery.append(f"{target}/{bucket}: completion not published ({type(e).__name__})")
                published = False
            if published:
                out.completions_published += 1
                _rescue(out)
            else:
                # review v14#1: the `done` tuple stays in the in-memory map, so a LATER successful save
                # persists it. It is PENDING, not lost — and it is reclassified when that happens, instead
                # of the counters swearing nothing was published while the disk says otherwise.
                out.pending_completions += 1


        if out.stop_kind is None and clock.exhausted() and len(picked) < len(slots):
            # FIRST CAUSE WINS (review v15#1). A machinery stop that happened to cross the bound was being
            # relabelled "budget", which reads as an operator cap — laundering a failure into a choice.
            out.stop = f"budget exhausted after {clock.elapsed()}s of {clock.seconds}s"
            out.stop_kind = "budget"           # a CAP we chose, not a failure (v14#4)
    out.completion_unpersisted = out.pending_completions
    if out.completion_unpersisted:
        # review v15#2: a counter no emitted fact consumes is still silent loss. These slots RAN and their
        # evidence stands, but the rotation does not know it — they may be selected again.
        out.machinery.append(f"{out.completion_unpersisted} completion(s) not published — those slot(s) "
                             f"may be selected again")
    _report(coverage_lane, out, clock)
    return out


def _rescue(out: "SweepResult") -> None:
    """A successful save writes the WHOLE in-memory map, so it carries every pending completion with it."""
    if out.pending_completions:
        out.completions_published += out.pending_completions
        out.pending_completions = 0


def _rank(progress, slots, content, picked):
    """Tier FIRST (globally), then target fairness inside that tier, then the stalest slot.

    A target holding only clean work must not run while another target still has never-run or dirty work
    (design v5#1), and the cursor is a SEQUENCE, so a backward clock jump cannot reorder anything (v4#4)."""
    live = [s for s in slots if s not in picked]
    if not live:
        return None
    tiers = {s: progress.tier(s[0], s[1], content[s]) for s in live}
    best = min(tiers.values())
    in_tier = [s for s in live if tiers[s] == best]
    target = min({t for t, _ in in_tier}, key=lambda t: (progress.target_seq(t), t))
    return min([s for s in in_tier if s[0] == target],
               key=lambda s: (progress.slot_seq(*s), s[1]))


def _report(lane: str, out: SweepResult, clock) -> None:
    """SELECTION over candidate-target pairs, OUTCOME over slots — different denominators, never summed."""
    # a BUDGET stop keeps `report_selection`'s own CAP wording and kind; every other stop is named and
    # classed as a gap (v14#4).
    budget.report_selection(lane, measure="candidate_pairs", eligible=out.eligible_pairs,
                            attempted=out.attempted_pairs, budget=clock, noun="candidate",
                            durable=out.durable,
                            stop=None if out.stop_kind in (None, "budget", "bound") else out.stop,
                            # a candidate BOUND is a cap with its own wording: reusing the budget sentence
                            # would report "exhausted after 0s of 0s" on an unbounded clock (v17#5).
                            cap_reason=out.stop if out.stop_kind == "bound" else None)
    budget.report_outcome(lane, measure="slot_outcomes", attempted=out.slots_attempted,
                          obtained=out.slots_obtained, classes=out.classes or None, noun="slot")
    if out.per_source_eligible:
        # review v15#3: NOT a third coverage denominator — it would re-count the candidate remainder the
        # selection record already owns, and it would have to invent a `kind` for a stop it does not model.
        # It is structured METADATA about the same selection: who the scheduled prefix belonged to.
        # `produced` is RESERVED for real parser/store entity counts and a status view folds it as such —
        # selection counters there would read as output this lane produced (review v16#1). The whole
        # structure rides as its own field instead.
        events.ledger(lane, unit="attribution", produced=None,
                      selection_attribution={
                          "eligible": sum(out.per_source_eligible.values()),
                          "scheduled": sum(out.per_source_attempted.values()),
                          "per_source_eligible": dict(sorted(out.per_source_eligible.items())),
                          "per_source_scheduled": dict(sorted(out.per_source_attempted.items()))})
