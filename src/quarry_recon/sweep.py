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

  BATCH      one INVOCATION carries the prefix of the rank order that stays inside one target and one
             tier. Slots keep their own reservation, completion and outcome; only the tool call is shared.

Coverage is three records with different denominators: candidate-target PAIRS (selection), SLOTS
(outcome) and tool INVOCATIONS. A launched-but-failed slot must not read as tested with no gap, and the
three are never read off one another.
"""
from __future__ import annotations

import contextlib
import hashlib
import re
import time
from dataclasses import dataclass, field, replace

from . import budget, events
from .runner import Status

#: bump when the SLOT SPACE changes meaning — the bucket count, the hash, or the id grammar. A bump starts
#: a fresh rotation rather than reading old records under new arithmetic. 2: adaptive prefix subslots.
SCHEMA = 2

#: how many ROOT slots a lane's vocabulary is spread over, before any adaptive split. A slot is the unit
#: of reservation, completion and rotation; an invocation may carry several of them, and the wall-clock
#: budget can stop us BETWEEN invocations (`Budget.exhausted()` only fires between items).
BUCKETS = 256


#: how many extension bits a slot id may carry beyond its root, and where they come from. `sha256` hex
#: digits 8..24 are the 64 bits after the four the root is taken from, consumed most-significant first.
EXT_BITS = 64

#: the largest number of candidates one INVOCATION may carry when no per-target bound applies. A blast
#: radius, not a measured optimum: the timing curve never stopped improving with size (49,634 candidates
#: were still the fastest per candidate), so this bounds what ONE failed or cancelled call can cost, not
#: what is fastest. A capped lane is bounded by its cap long before this.
MAX_BATCH_WORDS = 25000

#: how many refused slots `SweepResult.unselectable` describes individually. The COUNTERS are the fact;
#: this is detail for the operator, and an unbounded list of them is not more true.
_UNSELECTABLE_DETAIL = 20

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


def _exact_cap(cap, name: str = "the per-target bound") -> int:
    """A bound is an EXACT non-negative int. `True` is not 1 and `-1` is not "unbounded" (v26#4): the
    documented contract is 0 = unbounded, and a negative bound meant "unbounded" to the allocator while
    the driver read it as a bound that nothing can satisfy — two answers to one question.

    v59#3: the message names WHICH bound, so an invalid allowance stops diagnosing the candidate cap."""
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
        raise ValueError(f"{name} must be an exact non-negative int (0 = unbounded), got {cap!r}")
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


@dataclass(frozen=True)
class _Books:
    """The PUBLICATION books, swapped as a whole (v86).

    Two counters cannot be updated together: a cancellation lands between any two stores, and crediting a
    confirmed publication is exactly such a pair (`published += pending`, then `pending = 0`). Interrupted
    halfway, the same tuples were both published and — through the in-flight snapshot — unknown.

    So the transition is not a sequence of counter edits. The whole set of publication counters is one
    IMMUTABLE record, and every transition builds the next record and swaps it in with a single store: the
    books either still describe the state before the transition or fully describe the state after it.
    Nothing can observe a half-applied credit, and replaying a transition changes nothing."""
    published: int = 0
    pending: int = 0
    inflight: int = 0
    adm_pending: int = 0
    adm_inflight: int = 0


@dataclass
class SweepResult:
    """What the sweep did, in the vocabulary the terminal and the coverage records need."""
    eligible_pairs: int = 0
    attempted_pairs: int = 0            # candidates inside slots whose invocation RETURNED
    invocations: int = 0                    # runner calls that actually ran — NOT a slot count
    invocations_obtained: int = 0
    invocation_classes: dict = field(default_factory=dict)
    targets_eligible: int = 0               # every target the corpus offered
    #: CUMULATIVE, from the durable rotation: targets whose every slot is clean for its CURRENT content,
    #: and the ones that still owe work. A per-run count answers "what did this lifecycle do"; a
    #: continuation hint needs "what is still owed", which only the ledger knows (step 4).
    targets_complete: int = 0
    targets_remaining: int = 0
    targets_admitted: int = 0               # ...that the per-run allowance let this lifecycle start
    targets_refused: int = 0                # ...that the caller's admission check turned away
    #: admission answers whose save was interrupted: on disk or not, we cannot say (v83#1).
    admission_unknown: int = 0
    #: the publication counters live in one immutable record, so a transition over several of them is a
    #: single store (v86): `admission_inflight`, `inflight_completions`, `admission_pending`,
    #: `pending_completions` and `completions_published` below are views onto it.
    books: _Books = field(default_factory=_Books)
    #: ...and the settled count at the end of the lifecycle. `save()` reports durability through its
    #: RESULT, and ignoring it let the run claim an answer had landed while the older record stood (v81).
    admission_unpersisted: int = 0
    refused_pairs: int = 0
    refused: list = field(default_factory=list)
    targets_contacted: int = 0              # ...whose invocation actually ran (v59#2: not the same fact)
    #: targets the per-run allowance deferred to a later lifecycle, and the pairs they hold. An
    #: orthogonal DISPOSITION, never the stop: the run carries on with the targets it admitted (v59#1).
    deferred_targets: int = 0
    deferred_pairs: int = 0
    cap_reasons: list = field(default_factory=list)
    #: slots no bound can ever admit, and their pairs. NOT a stop: the run was not stopped by them, and
    #: whatever did stop it keeps the sentence. They are an orthogonal REMAINDER DISPOSITION (v34#1) —
    #: reported through `unretriable`, which also forces the coverage record to a gap class.
    unselectable_slots: int = 0
    unselectable_pairs: int = 0
    #: pairs the per-target SPEND bound excluded from this run, counted AS they were excluded (v65). A
    #: stop and a bound own different pairs, and only a recorded count can tell them apart.
    bound_pairs: int = 0
    #: STRUCTURED detail per refused slot, `{"target", "slot", "members"}` — bounded, with the counters
    #: above authoritative. It is deliberately NOT `machinery`: a consumer had to recognise unschedulable
    #: work by matching English in a machinery string, which a wording change breaks and an unrelated
    #: error carrying the same phrase defeats (v38).
    unselectable: list = field(default_factory=list)
    #: STRUCTURED identity for every exception this driver CONTAINED on a caller's behalf, keyed to the
    #: machinery sentence it produced: `{"index", "target", "unit", "phase", "exc"}`. A caller whose own
    #: callback raised has to be able to recognise ITS exception — matching the English of the sentence
    #: breaks on a wording change and catches unrelated errors that happen to share a phrase (v63#4,
    #: the same rule as `unselectable` above).
    contained: list = field(default_factory=list)
    slots_attempted: int = 0
    slots_obtained: int = 0             # SUCCESS or EMPTY — a clean answer, including "nothing resolved"
    classes: dict = field(default_factory=dict)
    reservations_persisted: int = 0
    completion_unpersisted: int = 0
    #: completions whose publication is UNKNOWN — the run ended between `complete_batch` and the save
    #: that would have made it durable. Different from PENDING, which a later save in the same lifecycle
    #: can still rescue: nothing rescues these, and the slot may run again (v69).
    completion_unknown: int = 0
    #: completions the run ended before ever STAGING — no `done` tuple exists, so nothing could publish
    #: them and nothing can rescue them. Distinct from pending, which is a real in-memory tuple (v71#3).
    completion_unstaged: int = 0
    #: whether the eligible set was ever established. A `vocabulary()` that raised leaves it UNKNOWN, and
    #: unknown is not zero (v71#1).
    eligibility_known: bool = False
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

    # ── views onto the publication books (v86) ────────────────────────────────────────────────────
    # Each setter is one store of a NEW record, so `x += n` cannot leave a half-applied state either: an
    # interruption between the read and the store simply means the increment did not happen.
    @property
    def completions_published(self) -> int:
        """Completions on disk. A pending one rescued by a later save is counted here."""
        return self.books.published

    @completions_published.setter
    def completions_published(self, n: int) -> None:
        self.books = replace(self.books, published=int(n))

    @property
    def pending_completions(self) -> int:
        """Real `done` tuples in memory that a later successful save can still carry."""
        return self.books.pending

    @pending_completions.setter
    def pending_completions(self, n: int) -> None:
        self.books = replace(self.books, pending=int(n))

    @property
    def inflight_completions(self) -> int:
        """Transient: pending completions a RUNNING save could carry."""
        return self.books.inflight

    @inflight_completions.setter
    def inflight_completions(self, n: int) -> None:
        self.books = replace(self.books, inflight=int(n))

    @property
    def admission_pending(self) -> int:
        """Admission ANSWERS — either kind — written in memory but not yet durable. Like a completion, a
        later successful save writes the WHOLE map and carries them, so this is PENDING, not lost (v82)."""
        return self.books.adm_pending

    @admission_pending.setter
    def admission_pending(self, n: int) -> None:
        self.books = replace(self.books, adm_pending=int(n))

    @property
    def admission_inflight(self) -> int:
        """Transient: admission answers whose save has not returned yet."""
        return self.books.adm_inflight

    @admission_inflight.setter
    def admission_inflight(self, n: int) -> None:
        self.books = replace(self.books, adm_inflight=int(n))

    def pair_remainder(self) -> dict:
        """Every eligible pair this run did not attempt, split by WHAT withheld it (v64#1).

        `eligible - attempted` is the TOTAL remainder and nothing more: it also holds the pairs an
        admission refusal turned away, the ones a deferred target still holds, work no bound can admit,
        and everything a stop left behind. Reporting that total as a policy bound's withholding tells the
        operator a cap fired when none did — and promises a rotation that a guard refusal will not deliver.

        The dispositions are taken in order and the remainder is what is left after them, so the parts
        always sum to the total. What is left belongs to the STOP when something stopped the run, and to
        the per-target spend bound when nothing did."""
        rest = max(0, self.eligible_pairs - self.attempted_pairs)
        parts = {}
        for key, value in (("refused", self.refused_pairs), ("unselectable", self.unselectable_pairs),
                           ("deferred", self.deferred_pairs), ("bound", self.bound_pairs)):
            parts[key] = min(rest, max(0, int(value)))
            rest -= parts[key]
        # v65: what is left after the RECORDED dispositions. A stop owns it when something stopped the
        # run — and when nothing did, it is the bound's: the last batch simply left the target's
        # allowance short of another slot, which no exclusion event marks.
        if self.stop_kind not in (None, "bound"):
            parts["stopped"] = rest
        else:
            parts["stopped"] = 0
            parts["bound"] += rest
        parts["total"] = max(0, self.eligible_pairs - self.attempted_pairs)
        return parts

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
              max_targets_per_run: int = 0, admit=None,
              now=time.time) -> SweepResult:
    """Drive one lane's sweep.

    `vocabulary(target) -> list[str]` is the eligible corpus for that target; the driver buckets it.
    `max_pairs_per_target` (0 = unbounded) is a SPEND bound in candidates per target: a slot that would
    take a target past it is not submitted, so the bound is never exceeded — a wall-clock budget cannot
    express "no more than N names per apex", which is what an existing lane's posture may already be.
    `max_targets_per_run` (0 = unbounded) is a THROUGHPUT bound on how many targets ONE lifecycle
    contacts. It never decides WHICH: the rotation does, so every target is eventually covered and a
    later run continues where this one stopped. That is the difference between bounding throughput and
    capping membership — a fixed "first N by name" cut contacts the same N for ever.
    `admit(target) -> bool` is an optional per-target ADMISSION check for work that is itself active — a
    contact guard, say. Its contract (design v64):
      1. it runs AFTER the target's first batch is reserved and persisted, so the reservation exists
         before anything active happens;
      2. once per target per lifecycle;
      3. a refusal CONSUMES the target's allowance and excludes that target's remaining slots for this
         lifecycle — no backfill, or many refusals would recreate the traffic the allowance bounds;
      4. the reservation already advanced the target's cursor, so a permanently refused target moves to
         the BACK of its tier instead of monopolising the front;
      5. a refusal is recorded on its own — never an invocation, never attempted pairs.
    `execute(target, unit, words) -> RunResult` submits ONE INVOCATION, which may carry several slots:
    `unit` names it (a lone slot keeps its own id) and `words` is their union. Its returned status attests
    every slot the invocation carried. `attribution(word) -> source` is optional ACCOUNTING only. Returns
    what happened, emits the three coverage records, and raises nothing but cancellation."""
    out = SweepResult()
    clock = budget.Budget(budget_s)

    # ── BEFORE the lock: the workload is a pure function of the corpus and the targets, so a CONTENDER can
    #    still report an exact denominator instead of a gap with no arithmetic (design v8#2). ──
    members: dict = {}
    seen_pairs: set = set()
    corpus: dict = {}
    try:
        for target in dict.fromkeys(targets):          # a repeated target is one target
            per_target: list = []
            raw = vocabulary(target) or []
            if isinstance(raw, (str, bytes, bytearray)):
                # v76#3: a bare string is ITERABLE — `"alpha"` became four candidates and `a`, `h`, `l`,
                # `p` were actively submitted. The contract is a COLLECTION of words.
                raise TypeError(f"vocabulary returned {_safe_name(raw)} {_safe_repr(raw)}, "
                                f"not a collection of words")
            for word in raw:
                if type(word) is not str or not word:
                    # v75#1: containing the CALL is not enough — a hashable non-string candidate survived
                    # corpus building and then crashed the allocator outside every boundary. The
                    # scheduler hashes and joins these: the contract is an EXACT non-empty str, since a
                    # subclass can override `encode` and escape from the allocator (v76#3).
                    raise TypeError(f"vocabulary returned {_safe_name(word)} {_safe_repr(word)}, "
                                    f"not a non-empty str")
                if (target, word) in seen_pairs:       # review v14#5: one submission per word per target —
                    continue                           # a duplicate would inflate the denominator, the
                seen_pairs.add((target, word))         # digest, the attribution AND the active payload
                per_target.append(word)
            corpus[target] = per_target
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:                 # v73#1: only CANCELLATION escapes this driver
        # v71#1: `vocabulary` is the CALLER's callable and it ran outside every boundary. A failure there
        # left the driver by the back door, and the eligible set is not zero — it is UNKNOWN.
        out.machinery.append(f"the corpus could not be built ({_safe_exc(e)})")
        out.stop, out.stop_kind = "machinery: the corpus could not be built", "machinery"
        _report_safely(coverage_lane, out, clock)
        return out
    out.eligibility_known = True
    # the DENOMINATOR is known before the bound is: every eligible pair exists whether or not we can
    # partition it (v27#2). Reporting 0/0 for a lane that had work would hide the omission entirely.
    out.eligible_pairs = sum(len(words) for words in corpus.values())
    out.targets_eligible = len([t for t, words in corpus.items() if words])

    try:
        max_pairs_per_target = _exact_cap(max_pairs_per_target)
        max_targets_per_run = _exact_cap(max_targets_per_run, "the per-run target allowance")
    except ValueError as e:
        # the driver promises to raise nothing but cancellation, so a nonsense bound is a MACHINERY stop
        # with nothing submitted — never a silent "unbounded" and never a bound nothing can satisfy.
        out.stop, out.stop_kind = f"machinery: {e}", "machinery"
        _report_safely(coverage_lane, out, clock)             # v27#1: coverage is filed under the REGISTERED
        return out                                     # source, never the scheduler's private lane name

    # v32#1: the batch maximum has to bound the SLOT, not just the batch — applied after a slot was
    # chosen it was no maximum at all, because a lone oversized slot bypassed it. The allocator splits
    # against the smaller of the two positive bounds, so no slot can exceed either.
    alloc_cap = min([b for b in (max_pairs_per_target, MAX_BATCH_WORDS) if b] or [0])
    for target, per_target in corpus.items():
        partition = allocate(per_target, cap=alloc_cap)
        placed = [word for group in partition.values() for word in group]
        if len(placed) != len(per_target) or set(placed) != set(per_target):
            # v28: a pair the partition dropped is not a RESUMABLE remainder — it is in no slot, so no
            # rotation will ever reach it, and reporting it as "left over" would promise a later run that
            # cannot happen. Membership, not counts: one dropped word and one duplicated word balance.
            out.stop = (f"machinery: the slot partition does not cover {target} "
                        f"({len(placed)} placed, {len(set(placed))} distinct, of {len(per_target)})")
            out.stop_kind = "machinery"
            _report_safely(coverage_lane, out, clock)
            return out
        # v33: a slot the allocator could not split below the bound can never be scheduled — not by this
        # run and not by any later one, until the corpus or the bounds change. It is removed HERE, in one
        # place, so neither the spend-bound check nor the batch loop can quietly reclassify it as an
        # ordinary cap or a resumable remainder.
        if alloc_cap:
            over = {slot: group for slot, group in partition.items() if len(group) > alloc_cap}
            room = max(0, _UNSELECTABLE_DETAIL - len(out.unselectable))   # a GLOBAL bound (v39#3)
            for slot, group in sorted(over.items())[:room]:
                out.unselectable.append({"target": target, "slot": slot, "members": len(group),
                                         "bound": alloc_cap})
            out.unselectable_slots += len(over)
            out.unselectable_pairs += sum(len(group) for group in over.values())
            partition = {slot: group for slot, group in partition.items() if slot not in over}
        for slot, group in partition.items():
            members[(target, slot)] = group
    slots = sorted(members)
    # the denominator stays the CORPUS count taken above, not a re-count of the partition: if allocation
    # ever lost a word, that has to surface as an unattempted pair, not shrink the denominator to match.
    content = {slot: content_digest(words) for slot, words in members.items()}
    owners: dict = {}
    _owners_stage: dict = {}
    _sources_stage: dict = {}
    try:
      if attribution is not None:
        # ELIGIBLE attribution is over the whole deduplicated corpus, not over what survived partitioning
        # (v35#1): a slot removed as unschedulable is still a pair this lane was eligible to submit, and
        # dropping it made the attribution denominator disagree with the selection record's. SCHEDULED
        # attribution is still counted per submitted word, inside the loop.
        for target, per_target in corpus.items():
            for word in per_target:
                # v72#2: STAGED, not published as we go. A failure on the second word used to leave a
                # partial map presented as the complete attribution of a corpus twice its size.
                _owners_stage[word] = src = attribution(word)
                _sources_stage[src] = _sources_stage.get(src, 0) + 1
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:                 # v73#1: only CANCELLATION escapes this driver
        # v71#1: accounting may not authorise or block work, but it may not escape either.
        out.machinery.append(f"attribution failed ({_safe_exc(e)})")
        out.stop, out.stop_kind = "machinery: attribution failed", "machinery"
        _report_safely(coverage_lane, out, clock)     # `per_source_eligible` stays EMPTY: nothing was published
        return out
    owners = _owners_stage                     # the whole corpus was attributed, or none of it is used
    out.per_source_eligible.update(_sources_stage)

    if not members:
        # NOTHING is schedulable — an empty corpus, or one whose every slot the bounds cannot admit. No
        # tool could have been invoked and no rotation state is needed, so neither a missing dependency
        # nor a busy lock is the reason for this run's remainder (v35#2).
        _report_safely(coverage_lane, out, clock)
        return out

    if dependency_ok is not None:
        try:
            ready = dependency_ok()
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as e:             # v73#1: only CANCELLATION escapes this driver
            out.machinery.append(f"the dependency check raised ({_safe_exc(e)})")
            out.stop, out.stop_kind = "machinery: the dependency check raised", "machinery"
            _report_safely(coverage_lane, out, clock)
            return out
        if ready is not True and ready is not False:
            # v71#1: this gate decides whether ACTIVE work happens. Truthiness let a value like
            # "missing" authorise it; the only answers are yes and no.
            out.machinery.append(f"the dependency check answered {_safe_name(ready)} "
                                 f"{_safe_repr(ready)}, not True or False")
            out.stop, out.stop_kind = "machinery: the dependency check gave no usable answer", "machinery"
            _report_safely(coverage_lane, out, clock)
            return out
        if ready is False:
            out.stop = "the tool is not installed"      # no reservations at all (design v7#2)
            out.stop_kind = "dependency"
            _report_safely(coverage_lane, out, clock)
            return out

    inflight = 0                          # slots whose publication is unresolved (v69)
    staged = False                        # ...and whether their `done` tuples were ever written (v70)
    try:
      with contextlib.ExitStack() as stack:
        try:
            progress = stack.enter_context(budget.rotation_session(state_dir, lane, schema=SCHEMA,
                                                                   slot_grammar=slot_id_ok))
        except budget.StateBusy as e:
            # ACQUISITION-only: a StateBusy raised by the sweep BODY is machinery, not contention (v10#2).
            out.contended = True
            out.stop = f"another lifecycle owns this rotation ({_safe_exc(e)})"
            out.stop_kind = "contention"       # nothing was submitted and NO completion state was lost
            _report_safely(coverage_lane, out, clock)
            return out
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as e:
            # v73#2: only StateBusy means another lifecycle. Anything else here — a read-only state
            # directory, say — is MACHINERY, and letting it escape contradicted the driver's contract
            # and threw away a denominator we already knew.
            out.machinery.append(f"the rotation could not be acquired ({_safe_exc(e)})")
            out.stop = "machinery: the rotation could not be acquired"
            out.stop_kind = "machinery"
            _report_safely(coverage_lane, out, clock)
            return out

        out.state_status = progress.state_status
        if progress.state_status == "degraded":
            out.machinery.append(f"rotation state degraded: {progress.state_reason}")
        picked: set = set()
        started_targets: set = set()                       # targets the allowance ADMITTED
        contacted: set = set()                             # ...whose invocation actually ran
        checked: set = set()                               # targets the admission hook has answered for
        spent: dict = {}                                   # candidates submitted per target
        submitted: set = set()                             # slots whose pairs went into `spent`
        refused_targets: set = set()                       # targets the admission hook turned away
        while not clock.exhausted() and len(picked) < len(slots):
            batch = _next_batch(progress, slots, content, members, picked, spent, out,
                                cap=max_pairs_per_target, max_words=MAX_BATCH_WORDS,
                                max_targets=max_targets_per_run, started=started_targets)
            if batch is None:
                break
            target, chosen = batch                         # chosen: [(bucket, words)] — ONE invocation
            started_targets.add(target)
            out.targets_admitted = len(started_targets)
            total = sum(len(words) for _b, words in chosen)
            unit = _unit_of(chosen)

            # RESERVE THE WHOLE BATCH BEFORE CONTACT, in one save (design v22#3, clause 2).
            try:
                gens = progress.reserve_batch(target, [b for b, _w in chosen], at=now())
                # v72#1: the SAVE is body work too and sat outside this boundary, so a `StateBusy` or an
                # `OSError` from it escaped the driver with no accounting at all.
                persisted = _persist(out, progress)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as e:         # v73#1: only CANCELLATION escapes this driver
                # v70: the CLOCK is a caller's callable too, and it was only guarded against the
                # scheduler's own refusals — an `OSError` from `now()` escaped the driver here.
                out.machinery.append(f"{target}/{unit}: reservation refused ({_safe_exc(e)})")
                out.stop = "machinery: the reservation was refused"
                out.stop_kind = "machinery"
                break
            if not persisted:
                # FAIL CLOSED: nothing is submitted for slots whose reservation nobody owns (v6#2).
                out.stop = "machinery: the reservation could not be persisted"
                out.stop_kind = "machinery"
                break
            out.reservations_persisted += len(chosen)
            spent[target] = spent.get(target, 0) + total
            submitted.update((target, bucket) for bucket, _w in chosen)   # SLOTS, not buckets

            if admit is not None and target not in checked:
                # ADMISSION (v64): after the reservation is durable, before anything active happens.
                checked.add(target)
                try:
                    allowed = admit(target)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except BaseException as e:     # v73#1: only CANCELLATION escapes this driver
                    out.machinery.append(f"{target}: admission check raised ({_safe_exc(e)})")
                    out.stop = "machinery: the admission check raised"
                    out.stop_kind = "machinery"
                    break
                if allowed is True:
                    # v79#1: an admission that SUCCEEDED supersedes any older refusal for the whole
                    # target — and it is persisted where it is learned (v80#2), because a raised,
                    # skipped or cancelled invocation would otherwise leave the older refusal
                    # authoritative on disk while the guard had just said yes.
                    _record_admission(out, progress, target, now, progress.admit_target,
                                      "the admission")
                if allowed is not True and allowed is not False:
                    # v65#1: a SAFETY boundary may not run on truthiness. A callback that returned a
                    # contact-state string or a tuple would have authorised traffic; the only answers
                    # this hook has are yes and no, and anything else fails closed.
                    out.machinery.append(f"{target}: the admission check answered "
                                         f"{_safe_name(allowed)} {_safe_repr(allowed)}, "
                                         f"not True or False")
                    out.stop = "machinery: the admission check gave no usable answer"
                    out.stop_kind = "machinery"
                    break
                if not allowed:
                    # v78: the refusal is RECORDED so it ranks behind work that can actually be
                    # attempted. Without it the target kept the front of tier 0 and starved every dirty
                    # zone, lifecycle after lifecycle. Best effort: losing the note costs ordering
                    # quality, never coverage.
                    # v83#2: the refusal is KNOWN the moment the hook answered. Its counters are
                    # committed before the fallible persistence, so a cancellation during that write
                    # cannot emit a ledger claiming nothing was refused.
                    out.targets_refused += 1
                    refused_targets.add(target)
                    if len(out.refused) < _UNSELECTABLE_DETAIL:
                        out.refused.append(target)
                    # v68: every SCHEDULABLE pair of this target is the refusal's. Skipping the slots
                    # already in `picked` missed the ones the candidate bound had excluded on the way —
                    # so a target the guard turned away without a single call still reported part of its
                    # work as withheld by the spend bound. Admission is target-wide: nothing was
                    # contacted, and no other bound got to decide anything here.
                    for slot in slots:                    # this target is done for THIS lifecycle
                        if slot[0] == target and slot not in submitted:
                            picked.add(slot)
                            out.refused_pairs += len(members[slot])
                    out.refused_pairs += total            # including the batch we had already picked
                    why = "target(s) refused by the caller's admission check"
                    if why not in out.cap_reasons:
                        out.cap_reasons.append(why)
                    _record_admission(out, progress, target, now, progress.refuse_target,
                                      "the refusal")
                    continue

            try:
                result = execute(target, unit, [word for _b, words in chosen for word in words])
            except (KeyboardInterrupt, SystemExit):
                raise                                   # cancellation ends the run, never a slot outcome
            except BaseException as e:                  # `runner.run` can raise around Popen (v10#1)
                out.contained.append({"index": len(out.machinery), "target": target, "unit": unit,
                                      "phase": "execute", "exc": _safe_name(e)})
                out.machinery.append(f"{target}/{unit}: {_safe_exc(e)}")
                out.stop = "machinery: the invocation raised"
                out.stop_kind = "machinery"
                break
            # v76#2: the status is read ONCE, inside containment. Re-reading `result.status` let a
            # property pass validation and then raise on its second access, escaping the driver.
            status = _safe_status(result)

            if status is Status.SKIPPED:                 # no process ran — a dependency answer
                out.stop = "the tool did not run"        # clause 3: it completes NO slot
                out.stop_kind = "dependency"
                break
            out.invocations += 1                         # clause 6: invocations are their own measure
            contacted.add(target)                        # an invocation that RAN, not one we planned
            out.targets_contacted = len(contacted)
            out.slots_attempted += len(chosen)
            out.attempted_pairs += total
            for _b, words in chosen:
                for word in words:                          # review v15#4: the two attempted totals must
                    src = owners.get(word)                  # agree even when publication never happens
                    if src is not None:
                        out.per_source_attempted[src] = out.per_source_attempted.get(src, 0) + 1
            if not isinstance(status, Status):
                # v75#1 / v76#1: the CALL returned, so the payload went out and every counter above is
                # true — but the outcome is unusable, and nothing was staged for it. It is a RETURNED
                # invocation with an invalid result, not a run that never happened.
                key = "invalid_result"
                out.classes[key] = out.classes.get(key, 0) + len(chosen)
                out.invocation_classes[key] = out.invocation_classes.get(key, 0) + 1
                out.completion_unstaged += len(chosen)
                out.machinery.append(f"{target}/{unit}: the invocation returned {_safe_name(result)} "
                                     f"{_safe_repr(result)} with no usable status")
                out.stop = "machinery: the invocation returned no usable status"
                out.stop_kind = "machinery"
                break
            if status in _OBTAINED:
                # clause 4: ONE result attests every slot it carried — completion means ATTEMPTED
                out.slots_obtained += len(chosen)
                out.invocations_obtained += 1
            else:
                key = str(getattr(status, "value", status))
                out.classes[key] = out.classes.get(key, 0) + len(chosen)
                # v32#2: the slot-weighted map cannot say how many CALLS failed once batches differ in
                # size — a 10-slot timeout and a 1-slot failure are 10 and 1 there, 1 and 1 here.
                out.invocation_classes[key] = out.invocation_classes.get(key, 0) + 1

            # v69: from here until the save resolves, this batch's publication is IN FLIGHT. A
            # cancellation in between leaves the tool result counted while the disk holds only the
            # reservation — the slot will run again, and nothing said so.
            inflight = len(chosen)
            staged = False
            try:
                progress.complete_batch(target, [(b, gens[b], content[(target, b)], len(words))
                                                for b, words in chosen], at=now())    # clause 5
                staged = True                           # the `done` tuples EXIST in memory from here
                published = _persist(out, progress)
            except (KeyboardInterrupt, SystemExit):
                raise
            except budget.SchedulerInvariant as e:
                out.machinery.append(f"scheduler_invariant: {_safe_exc(e)}")
                out.stop = "machinery: scheduler invariant"
                out.stop_kind = "machinery"
                inflight = 0
                break
            except BaseException as e:                  # v73#1: only CANCELLATION escapes this driver
                if not staged:
                    # v70: STAGING and PUBLICATION are different failures. Nothing was written to the
                    # in-memory map — `now()` raised, or `complete_batch` did — so there is no `done`
                    # tuple for a later save to carry, and calling it PENDING let `_rescue` publish a
                    # completion that does not exist.
                    # v72#3: it is still a slot that RAN and whose completion nobody holds — counted as
                    # unstaged rather than cleared and forgotten.
                    out.completion_unstaged += inflight
                    out.machinery.append(f"{target}/{unit}: completion not staged ({_safe_name(e)})")
                    out.stop = "machinery: the completion could not be staged"
                    out.stop_kind = "machinery"
                    inflight = 0
                    break
                out.machinery.append(f"{target}/{unit}: completion not published ({_safe_name(e)})")
                published = False                       # the evidence exists; the bookkeeping failed
            inflight = 0
            if published:
                out.completions_published += len(chosen)
            else:
                # review v14#1: the `done` tuples stay in the in-memory map, so a LATER successful save
                # persists them. They are PENDING, not lost — and reclassified when that happens, instead
                # of the counters swearing nothing was published while the disk says otherwise.
                out.pending_completions += len(chosen)


        # ── DISPOSITIONS, reconciled from the whole slot set ────────────────────────────────────
        deferred_slots: set = set()
        if max_targets_per_run and len(started_targets) >= max_targets_per_run:
            # v60#1: the deferral used to be counted only when ranking happened to REACH a disallowed
            # target, so a clock that fired right after the last admitted one left the allowance
            # invisible. Once the allowance is saturated, every unstarted target is deferred by it.
            unstarted = {tgt for tgt, _s in slots if tgt not in started_targets}
            if unstarted:
                deferred_slots = {s for s in slots if s[0] in unstarted}
                out.deferred_targets = len(unstarted)
                out.deferred_pairs = sum(len(words) for (tgt, _s), words in members.items()
                                         if tgt in unstarted)
                why = f"the per-run target allowance ({max_targets_per_run}) was reached"
                if why not in out.cap_reasons:
                    out.cap_reasons.append(why)

        # ── slots the per-target SPEND bound can no longer admit (v66) ──────────────────────────
        # Reconciled from the FINAL spend, never from how far the batch scan happened to get: a batch
        # returns at a tier boundary before the next slot ever reaches the cap check, so counting only
        # what the scan excluded left work that no remaining allowance could admit looking like the
        # clock's. What a target may still spend is a fact about the target, not about the scan.
        bound_slots: set = set()
        if max_pairs_per_target:
            # v67: capacity is consumed CUMULATIVELY, in the scheduler's own order. Testing every
            # remaining slot against the same final `spent` let two one-word slots both "fit" a single
            # remaining candidate, so the pair the cap would certainly have withheld was reported as the
            # stop's. This is a dry run of what the selection would do next: `_rank` picks exactly what
            # the loop would have picked, each admitted slot spends its own candidates, and the first
            # slot the remaining allowance cannot fit is the BOUND's — as are all that follow it.
            room = dict(spent)
            # everything another disposition already owns, or that ran: the dry run walks the REST
            trial = {s for s in slots
                     if s in submitted or s in deferred_slots or s[0] in refused_targets
                     or s[0] not in started_targets}
            while True:
                choice = _rank(progress, slots, content, trial)
                if choice is None:
                    break
                trial.add(choice)
                tgt, size = choice[0], len(members[choice])
                if room.get(tgt, 0) + size > max_pairs_per_target:
                    bound_slots.add(choice)     # this allowance can no longer admit it — nor what follows
                else:
                    room[tgt] = room.get(tgt, 0) + size      # the stop took this one, not the bound
        out.bound_pairs = sum(len(members[s]) for s in bound_slots)
        if bound_slots:
            # the bound withheld work whether or not the SCAN ever reached it, so it is named either way
            why = f"the per-target candidate bound ({max_pairs_per_target}) was reached"
            if why not in out.cap_reasons:
                out.cap_reasons.append(why)

        # ── CUMULATIVE completion, read from the durable rotation ───────────────────────────────
        # A target is COMPLETE when every slot it holds is clean for the content it holds NOW — so a
        # repartitioned corpus, a refused target and a deferred one all still owe work. This is what a
        # continuation hint must speak in: this lifecycle's own counts cannot say what is left.
        by_target: dict = {}
        for slot in slots:
            by_target.setdefault(slot[0], []).append(slot)
        done_targets = 0
        for tgt, group in by_target.items():
            try:
                if all(progress.tier(tgt, s, content[(tgt, s)]) == 2 for _t, s in group):
                    done_targets += 1
            except BaseException:                  # the ledger is best effort: a hint is never a stop
                break
        out.targets_complete = done_targets
        out.targets_remaining = max(0, out.targets_eligible - done_targets)

        # ── the STOP: what actually ended the run ───────────────────────────────────────────────
        # v60#2: an elapsed clock is not automatically the cause. It only stopped work if selectable
        # slots were LEFT — a slot a cap excluded is already classified and was never the clock's to
        # take. Otherwise a run whose last permitted call happened to cross the deadline reported
        # "budget exhausted" for an omission the candidate bound had already explained.
        # v61: a slot the ALLOWANCE deferred is already explained and was never the clock's to take
        # either — counting it here made a clock that prevented nothing the stop of a run whose whole
        # remainder belonged to the allowance.
        # v66: a slot the SPEND bound can no longer admit is not the clock's either, by the same rule.
        stopped_by_clock = clock.exhausted() and any(s not in picked and s not in deferred_slots
                                                     and s not in bound_slots for s in slots)
        if out.stop_kind is None and stopped_by_clock:
            # FIRST CAUSE WINS (review v15#1). A machinery stop that happened to cross the bound was being
            # relabelled "budget", which reads as an operator cap — laundering a failure into a choice.
            out.stop = f"budget exhausted after {clock.elapsed()}s of {clock.seconds}s"
            out.stop_kind = "budget"           # a CAP we chose, not a failure (v14#4)
        elif out.stop_kind is None and out.cap_reasons:
            # no failure and no clock-stopped work: a CAP we chose is what ended the run (v59#1)
            out.stop_kind = "bound"
            out.stop = "; ".join(out.cap_reasons)
    except (KeyboardInterrupt, SystemExit):
        # v66#2: the refusals, reservations and outcomes this lifecycle already accumulated are facts.
        # They are flushed before the cancellation continues; a failure to report them may not MASK the
        # cancellation, which stays the exception that leaves this function.
        if out.stop_kind is None:
            # v67#1: flushing without settling the disposition let the record claim "budget exhausted
            # after 0.0s of 0s" as a CAP — for a run a Ctrl-C ended.
            out.stop, out.stop_kind = "CANCELLED mid-sweep", "cancelled"
        _settle_completions(out, inflight=inflight, staged=staged)
        try:
            _report_safely(coverage_lane, out, clock)
        except BaseException:
            # v68#1: `Exception` alone let a reporting `GeneratorExit` REPLACE the cancellation being
            # handled. The bare `raise` below must always propagate the original one — including when
            # the sink raises a cancellation of its own (v74#1).
            pass
        raise
    _settle_completions(out)
    _report_safely(coverage_lane, out, clock)
    return out


def _settle_completions(out: "SweepResult", *, inflight: int = 0, staged: bool = True) -> None:
    """Close the books on publication — on EVERY exit (v69).

    review v15#2: a counter no emitted fact consumes is still silent loss. These slots RAN and their
    evidence stands, but the rotation does not know it, so they may be selected again. A batch caught
    mid-publication by a cancellation is worse than pending: nothing will rescue it, and whether it
    landed at all is unknown."""
    # v70: a batch cancelled BEFORE its tuples were staged definitely did not publish — that is not
    # unknown, it is simply not published. Only a staged one leaves the question open.
    if staged:
        out.completion_unknown += max(0, int(inflight))
    else:
        # v71#3: PENDING means a real in-memory tuple a later save can carry. An unstaged batch has no
        # tuple at all and the lifecycle is over — definitely unpublished, and nothing will rescue it.
        out.completion_unstaged += max(0, int(inflight))
    # v82: admission durability settles the same way — an answer a later save carried is NOT unpersisted,
    # and the machinery sentence is written from the FINAL state rather than the first failed write.
    if out.inflight_completions:
        # v84: a save that was interrupted could have carried these too — unknown, not lost.
        out.completion_unknown += out.inflight_completions
        out.pending_completions -= min(out.pending_completions, out.inflight_completions)
        out.inflight_completions = 0
    if out.admission_inflight:
        # v83#1: interrupted mid-write. Not "lost" — unknown, and the pending claim it came from is
        # withdrawn so the two are never counted twice.
        out.admission_unknown += out.admission_inflight
        out.admission_pending -= min(out.admission_pending, out.admission_inflight)
        out.admission_inflight = 0
    out.admission_unpersisted = out.admission_pending + out.admission_unknown
    if out.admission_unpersisted:
        parts = []
        if out.admission_pending:
            parts.append(f"{out.admission_pending} admission answer(s) not persisted")
        if out.admission_unknown:
            parts.append(f"{out.admission_unknown} admission answer(s) of UNKNOWN publication (the run "
                         f"ended mid-write)")
        out.machinery.append("; ".join(parts) + " — an older record may still stand for those target(s)")
    out.completion_unpersisted = (out.pending_completions + out.completion_unknown
                                  + out.completion_unstaged)
    if out.completion_unpersisted:
        parts = []
        if out.pending_completions:
            parts.append(f"{out.pending_completions} completion(s) not published")
        if out.completion_unknown:
            parts.append(f"{out.completion_unknown} completion(s) of UNKNOWN publication (the run ended "
                         f"mid-write)")
        if out.completion_unstaged:
            parts.append(f"{out.completion_unstaged} completion(s) never staged (the run ended before "
                         f"the record was written)")
        out.machinery.append("; ".join(parts) + " — those slot(s) may be selected again")


def _persist(out: "SweepResult", progress) -> bool:
    """`progress.save()` behind the publication contract (v84).

    EVERY save writes the WHOLE map, so it can carry every pending tuple — the current answer, older
    pending admission answers and older pending completions alike. While it runs they are all IN FLIGHT:
    an interruption cannot claim they did not land, and a confirmed success rescues them.

    v86: each step is ONE swap of the publication books, so a cancellation between them always lands on a
    whole state — never on a credit that has been half applied."""
    b = out.books
    out.books = replace(b, inflight=b.pending, adm_inflight=b.adm_pending)
    try:
        ok = progress.save()
    except (KeyboardInterrupt, SystemExit):
        raise                                  # in flight stays set: settled as UNKNOWN, never as lost
    except BaseException:
        _land(out)
        raise                                  # the caller owns its own containment
    if ok:
        _rescue(out)                           # this save carried every pending tuple with it
    else:
        _land(out)
    return ok


def _land(out: "SweepResult") -> None:
    """The save has resolved and nothing is in flight any more — pending stays pending."""
    out.books = replace(out.books, inflight=0, adm_inflight=0)


def _record_admission(out: "SweepResult", progress, target: str, now, write, what: str) -> None:
    """Write an admission answer and try to make it durable, contained (v82).

    Two failures, two meanings. If the WRITE fails there is no tuple at all — machinery, nothing to
    rescue. If only the SAVE fails the tuple is in memory and PENDING: a later successful save writes the
    whole map and carries it, exactly like a completion, so it is settled at the end rather than declared
    lost on the spot."""
    try:
        write(target, at=now())
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:
        out.machinery.append(f"{target}: {what} could not be recorded ({_safe_exc(e)})")
        return
    out.admission_pending += 1
    try:
        _persist(out, progress)                # v83#1/v84: in flight across the save, rescued on success
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:
        out.machinery.append(f"{target}: {what} could not be persisted ({_safe_exc(e)})")


def _rescue(out: "SweepResult") -> None:
    """A successful save writes the WHOLE in-memory map, so it carries every pending completion — and
    every pending admission answer (v82) — with it.

    v86: ONE store of the whole record. Crediting the publication and withdrawing the pending and in-flight
    claims are the SAME transition, so a cancellation can never leave the same tuples counted as published
    AND as unknown. Replaying it is a no-op: after it, there is nothing pending to credit."""
    b = out.books
    out.books = _Books(published=b.published + b.pending, pending=0, inflight=0,
                       adm_pending=0, adm_inflight=0)


def _safe_text(render) -> str:
    """Render a diagnostic without letting it escape the driver (v66#1 / v68#2).

    EVERY part of a diagnostic is attacker-adjacent: a returned object's `__repr__`, its type's
    `__name__` through a hostile metaclass, an exception's `__str__`. Cancellation is the only thing
    that leaves this function — anything else becomes a placeholder rather than a broken contract at
    the boundary that exists to fail closed."""
    try:
        return str(render())
    except (KeyboardInterrupt, SystemExit):
        raise                                  # cancellation is the ONLY thing that leaves this driver
    except BaseException:
        return "<unrepresentable>"


def _safe_status(result):
    """The result's status, read ONCE and contained (v76#2). A property can pass a check and then raise
    on its next access, so the driver must never look twice."""
    return _safe_call(lambda: getattr(result, "status", None))


def _safe_call(fn):
    """Call `fn`, containing everything but cancellation; `None` when it could not answer."""
    try:
        return fn()
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        return None


def _safe_repr(value) -> str:
    return _safe_text(lambda: repr(value))


def _safe_name(value) -> str:
    return _safe_text(lambda: type(value).__name__)


def _safe_exc(exc) -> str:
    """`Type: message`, both halves contained."""
    return f"{_safe_name(exc)}: {_safe_text(lambda: exc)}"


def _unit_of(chosen) -> str:
    """The id ONE invocation is reported and named by. A single slot keeps its own id, so a lane that never
    batches reads exactly as before."""
    first = chosen[0][0]
    return first if len(chosen) == 1 else f"{first}+{len(chosen) - 1}"


def _next_batch(progress, slots, content, members, picked, spent, out, *, cap: int, max_words: int,
                max_targets: int = 0, started=frozenset()):
    """The next INVOCATION: the prefix of the GLOBAL rank order that stays inside one target and one tier.

    The pinned batch protocol (design v22#3), clause by clause. Ranking is still global and re-evaluated
    for every member, so target fairness and tier dominance survive batching (clause 7) — the batch simply
    stops at the first slot that belongs to another target or another tier. A slot that alone cannot fit
    the per-target bound is still EXCLUDED (never withheld silently), and the batch-size policy never
    withholds a slot on its own: a single oversized slot still runs, or nothing would."""
    chosen: list = []
    target = tier = None
    total = 0
    while len(picked) < len(slots):
        choice = _rank(progress, slots, content, picked)
        if choice is None:
            break
        this_target, bucket = choice
        if max_targets and this_target not in started and len(started) >= max_targets:
            # this lifecycle has contacted its allowance of TARGETS. The slot is excluded (never silently
            # skipped) so the loop terminates, and the rotation hands this target to a later run — which
            # is what makes an allowance a throughput bound rather than a membership cap.
            # the slot is EXCLUDED (never silently skipped) so the loop terminates; the disposition
            # itself is reconciled from the whole slot set after the loop (v60#1).
            picked.add(choice)
            continue
        this_tier = progress.tier(this_target, bucket, content[choice])
        if chosen and (this_target != target or this_tier != tier):
            break                                       # clause 1: one target, one tier
        words = members[choice]
        if cap and spent.get(this_target, 0) + total + len(words) > cap:
            # This slot does not fit what the target may still spend. Excluding it (rather than merely
            # skipping the pick) keeps the loop terminating and leaves it to the next run's rotation —
            # and the scan CONTINUES, so a smaller slot behind it can still fill the remaining allowance
            # in the SAME invocation, exactly as the one-slot-per-call driver used to pack it (v31).
            # v68: the bound is NAMED by the reconciliation, which knows whether it really withheld
            # anything. Naming it here made a target the guard then refused report a spend bound that
            # decided nothing — the scan reached the check, but no pair was ever the bound's.
            picked.add(choice)
            continue
        if chosen and max_words and total + len(words) > max_words:
            break                                       # an oversized SLOT never reaches here: the
                                                        # allocator's own bound removed it (v33)
        target, tier = this_target, this_tier
        chosen.append((bucket, words))
        total += len(words)
        picked.add(choice)
    return (target, chosen) if chosen else None


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


def _report_safely(lane: str, out: SweepResult, clock) -> None:
    """`_report` behind the driver's contract (v74#1).

    The event sink is I/O: it can fail, and losing the accounting must not turn into an escape from a
    function that promises to raise nothing but cancellation. The failure becomes a machinery fact on the
    result — a caller that reads it still learns the run reported nothing."""
    try:
        _report(lane, out, clock)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:
        out.machinery.append(f"coverage could not be reported ({_safe_exc(e)})")
        if out.stop_kind is None:
            out.stop = "machinery: coverage could not be reported"
            out.stop_kind = "machinery"


def _report(lane: str, out: SweepResult, clock) -> None:
    """SELECTION over candidate-target pairs, OUTCOME over slots — different denominators, never summed."""
    if not out.eligibility_known:
        # v71#1: the corpus never finished building, so the eligible set is UNKNOWN — structured but
        # uncounted, which the reconciler admits as a gap instead of a clean 0/0/0.
        events.coverage_partial(lane, kind=events.COVERAGE_UNKNOWN, measure="candidate_pairs",
                                unit="candidate_pairs",
                                reason=f"{out.stop or 'the eligible set could not be determined'} — no "
                                       f"candidate denominator exists for this run")
        return
    # a BUDGET stop keeps `report_selection`'s own CAP wording and kind; every other stop is named and
    # classed as a gap (v14#4).
    budget.report_selection(lane, measure="candidate_pairs", eligible=out.eligible_pairs,
                            attempted=out.attempted_pairs, budget=clock, noun="candidate",
                            durable=out.durable,
                            stop=None if out.stop_kind in (None, "budget", "bound") else out.stop,
                            # a candidate BOUND is a cap with its own wording: reusing the budget sentence
                            # would report "exhausted after 0s of 0s" on an unbounded clock (v17#5).
                            cap_reason="; ".join(out.cap_reasons) if out.stop_kind == "bound" else None,
                            # every applicable CAP is named even when something ELSE ended the run
                            # (v59#1) — a clock that fired must not be blamed on an allowance, nor the
                            # allowance's remainder be laundered into a timeout.
                            extra="; ".join(out.cap_reasons) if out.stop_kind != "bound" else None,
                            # pairs in a slot no bound can admit are not a remainder anyone will retry
                            unretriable=out.unselectable_pairs)
    budget.report_outcome(lane, measure="slot_outcomes", attempted=out.slots_attempted,
                          obtained=out.slots_obtained, classes=out.classes or None, noun="slot")
    if out.invocations:
        # a THIRD outcome denominator, deliberately (design v22#3, clause 6): one invocation may carry
        # several slots, so "how many calls ran" and "how many slots were attempted" are different facts
        # and neither may be read off the other.
        budget.report_outcome(lane, measure="tool_invocations", attempted=out.invocations,
                              obtained=out.invocations_obtained,
                              classes=out.invocation_classes or None, noun="invocation")
    if out.completion_unpersisted:
        # v69: the counters die with the result, and a cancellation never returns one at all. Metadata,
        # not a coverage denominator: the slots RAN and their outcome record already says so.
        events.ledger(lane, unit="completion", produced=None,
                      completion={"pending": out.pending_completions,
                                  "unknown": out.completion_unknown,
                                  "unstaged": out.completion_unstaged,
                                  "unpersisted": out.completion_unpersisted})
    if out.targets_refused or out.admission_unpersisted:
        # v65#2: the counters and names die with the result otherwise, leaving only a generic sentence.
        # Metadata, NOT a fourth coverage denominator — a refusal is already inside the selection record.
        events.ledger(lane, unit="admission", produced=None,
                      admission={"targets": out.targets_refused, "pairs": out.refused_pairs,
                                 "detail": list(out.refused),
                                 "unpersisted": out.admission_unpersisted,
                                 "unknown": out.admission_unknown,
                                 "truncated": out.targets_refused > len(out.refused)})
    if out.unselectable_pairs:
        # the counters are the fact; this carries the operator detail INTO the run's evidence, because a
        # field on a value that disappears with the process is not something an operator retains (v39#2).
        events.ledger(lane, unit="unschedulable", produced=None,
                      unschedulable={"slots": out.unselectable_slots, "pairs": out.unselectable_pairs,
                                     "detail": list(out.unselectable),
                                     "truncated": out.unselectable_slots > len(out.unselectable)})
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
