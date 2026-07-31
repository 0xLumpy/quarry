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
import time
from dataclasses import dataclass, field

from . import budget, events
from .runner import Status

#: bump when the SLOT SPACE changes meaning — the bucket count or the hash. A bump starts a fresh rotation
#: rather than reading old records under new arithmetic.
SCHEMA = 1

#: how many buckets a lane's vocabulary is spread over. One bucket = one tool invocation, so this is the
#: granularity at which a wall-clock budget can stop us (`Budget.exhausted()` only fires BETWEEN items).
#: MEASURED input for the choice is the timing pass; 256 over the OTC corpus is ~195 candidates per call.
BUCKETS = 256


def bucket_of(word: str, buckets: int = BUCKETS) -> str:
    """The slot a word belongs to. Stable per word: inserting words never moves the ones already placed."""
    return f"{int(hashlib.sha256(word.encode('utf-8')).hexdigest()[:8], 16) % buckets:03d}"


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
    completions_published: int = 0
    completion_unpersisted: int = 0
    per_source: dict = field(default_factory=dict)
    machinery: list = field(default_factory=list)
    stop: str | None = None             # None = the whole eligible set ran
    durable: bool = True
    state_status: str = "missing"
    contended: bool = False

    @property
    def ran(self) -> bool:
        return self.slots_attempted > 0


#: statuses that mean the tool answered. EMPTY is an answer ("this bucket resolved nothing"); SKIPPED never
#: enters the attempted denominator because no process ran (step-4 design v5#4 / v7#2).
_OBTAINED = (Status.SUCCESS, Status.EMPTY)


def run_sweep(*, lane: str, state_dir, targets, vocabulary, execute, budget_s: int,
              coverage_lane: str, dependency_ok=None, attribution=None, now=time.time) -> SweepResult:
    """Drive one lane's sweep.

    `vocabulary(target) -> list[str]` is the eligible corpus for that target; the driver buckets it.
    `execute(target, bucket, words) -> RunResult` submits one slot. `attribution(word) -> source` is
    optional ACCOUNTING only. Returns what happened, emits the two coverage records, and raises nothing but
    cancellation."""
    out = SweepResult()
    clock = budget.Budget(budget_s)

    # ── BEFORE the lock: the workload is a pure function of the corpus and the targets, so a CONTENDER can
    #    still report an exact denominator instead of a gap with no arithmetic (design v8#2). ──
    members: dict = {}
    for target in targets:
        for word in vocabulary(target) or []:
            members.setdefault((target, bucket_of(word)), []).append(word)
    slots = sorted(members)
    out.eligible_pairs = sum(len(w) for w in members.values())
    content = {slot: content_digest(words) for slot, words in members.items()}
    if attribution is not None:
        for words in members.values():
            for word in words:
                src = attribution(word)
                out.per_source[src] = out.per_source.get(src, 0) + 1

    if dependency_ok is not None and not dependency_ok():
        out.stop = "the tool is not installed"          # no reservations at all (design v7#2)
        _report(coverage_lane, out, clock)
        return out

    with contextlib.ExitStack() as stack:
        try:
            progress = stack.enter_context(budget.rotation_session(state_dir, lane, schema=SCHEMA))
        except budget.StateBusy as e:
            # ACQUISITION-only: a StateBusy raised by the sweep BODY is machinery, not contention (v10#2).
            out.contended = True
            out.stop = f"another lifecycle owns this rotation ({e})"
            out.durable = False
            _report(coverage_lane, out, clock)
            return out

        out.state_status = progress.state_status
        if progress.state_status == "degraded":
            out.machinery.append(f"rotation state degraded: {progress.state_reason}")
        picked: set = set()
        while not clock.exhausted() and len(picked) < len(slots):
            choice = _rank(progress, slots, content, picked)
            if choice is None:
                break
            target, bucket = choice
            picked.add(choice)
            words = members[choice]
            gen = progress.reserve(target, bucket, at=now())
            if not progress.save():
                # FAIL CLOSED: nothing is submitted for a slot whose reservation nobody owns (v6#2).
                out.stop = "machinery: the reservation could not be persisted"
                out.durable = False
                break
            out.reservations_persisted += 1

            try:
                result = execute(target, bucket, words)
            except (KeyboardInterrupt, SystemExit):
                raise                                   # cancellation ends the run, never a slot outcome
            except Exception as e:                      # `runner.run` can raise around Popen (v10#1)
                out.machinery.append(f"{target}/{bucket}: {type(e).__name__}: {e}")
                out.stop = "machinery: the invocation raised"
                break

            if result.status is Status.SKIPPED:          # no process ran — a dependency answer
                out.stop = "the tool did not run"
                break
            out.slots_attempted += 1
            out.attempted_pairs += len(words)
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
                break
            except Exception as e:                      # the evidence exists; only the bookkeeping failed
                out.machinery.append(f"{target}/{bucket}: completion not published ({type(e).__name__})")
                published = False
            if published:
                out.completions_published += 1
            else:
                out.completion_unpersisted += 1

    _report(coverage_lane, out, clock)
    return out


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
    budget.report_selection(lane, measure="candidate_pairs", eligible=out.eligible_pairs,
                            attempted=out.attempted_pairs, budget=clock, noun="candidate",
                            durable=out.durable, stop=out.stop)
    budget.report_outcome(lane, measure="slot_outcomes", attempted=out.slots_attempted,
                          obtained=out.slots_obtained, classes=out.classes or None, noun="slot")
    if out.per_source:
        events.coverage_partial(lane, kind=events.COVERAGE_CAP, measure="vocabulary_attribution",
                                unit="attribution", eligible=sum(out.per_source.values()),
                                tested=sum(out.per_source.values()), omitted=0,
                                reason=f"accounting attribution per source: "
                                       f"{dict(sorted(out.per_source.items()))}")
