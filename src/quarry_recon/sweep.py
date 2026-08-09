"""The sweep driver: bounded, fair, resumable active selection over a stable slot space.

A slot is `(target, bucket)` with `bucket = sha256(word) % BUCKETS`, so adding a word never changes
another word's bucket (a bucket may adaptively split into hash-prefix subslots, but membership is preserved). The lane lock is held for the whole sweep, order is tier first with target fairness inside the
tier, and a reservation is written before the tool runs while the completion is written after it
returns. Coverage is three records with different denominators — candidate-target pairs, slots and tool
invocations — and none may be read off another.

Design: docs/design/STEP4-SCHEDULING-DESIGN.md.
"""
from __future__ import annotations

import contextlib
import hashlib
import re
import time
from dataclasses import dataclass, field, replace

from . import budget, events
from .runner import Status

#: bump when the slot space changes meaning — bucket count, hash, or id grammar. A bump starts a fresh
#: rotation rather than reading old records under new arithmetic.
SCHEMA = 2

#: root slots a lane's vocabulary spreads over, before any adaptive split. A slot is the unit of
#: reservation, completion and rotation.
BUCKETS = 256


#: extension bits a slot id may carry beyond its root: `sha256` hex digits 8..24, most significant
#: first.
EXT_BITS = 64

#: candidates one invocation may carry when no per-target bound applies. A blast radius, not an
#: optimum.
MAX_BATCH_WORDS = 25000

#: how many refused slots `SweepResult.unselectable` describes individually. The counters are the
#: fact; this is operator detail.
_UNSELECTABLE_DETAIL = 20

#: the id grammar schema 2 accepts: a three-digit root, optionally extended by `.` and up to `EXT_BITS`
#: binary digits. Anything else is not a slot this lane can rank, split or complete.
SLOT_RX = re.compile(rf"^[0-9]{{3}}(\.[01]{{1,{EXT_BITS}}})?$")


def slot_id_ok(slot: str, buckets: int | None = None) -> bool:
    """Whether a persisted id belongs to this slot space. Rank inheritance walks ids structurally."""
    if not isinstance(slot, str) or not SLOT_RX.fullmatch(slot):
        return False
    return 0 <= int(slot.partition(".")[0]) < (buckets or BUCKETS)


def _parts_of(word: str) -> tuple:
    """(root, extension): the root is digest bits 24..31, the extension the next 64."""
    h = hashlib.sha256(word.encode("utf-8")).hexdigest()
    return int(h[:8], 16), int(h[8:24], 16)


def bucket_of(word: str, buckets: int | None = None) -> str:
    """The root slot a word belongs to. Stable per word, so inserting words never moves the ones already
    placed."""
    return f"{_parts_of(word)[0] % (buckets or BUCKETS):03d}"


def slot_of(word: str, depth: int = 0, buckets: int | None = None) -> str:
    root, ext = _parts_of(word)
    depth = max(0, min(int(depth), EXT_BITS))
    bits = "".join(str((ext >> (EXT_BITS - 1 - k)) & 1) for k in range(depth))
    return f"{root % (buckets or BUCKETS):03d}" + (f".{bits}" if bits else "")


def _exact_cap(cap, name: str = "the per-target bound") -> int:
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
        raise ValueError(f"{name} must be an exact non-negative int (0 = unbounded), got {cap!r}")
    return cap


def allocate(words, *, cap: int) -> dict:
    """Group words into slots no larger than `cap`, splitting a slot into its two hash children until it
    fits. `cap=0` leaves the root buckets alone."""
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
    """Accounting attribution for a word produced by several sources, by rendezvous hashing. Not
    provenance: evidence keeps every source."""
    return max(sources, key=lambda s: hashlib.sha256(f"{word}|{s}".encode("utf-8")).hexdigest())


def content_digest(members) -> str:
    h = hashlib.sha256()
    for word in sorted(members):
        h.update(word.encode("utf-8"))
        h.update(b"\\n")
    return h.hexdigest()


@dataclass(frozen=True)
class _Books:
    """The publication books, swapped as a whole: two counters cannot be updated together, and a cancellation
    between the two stores would read the same tuples as both published and unknown."""
    published: int = 0
    pending: int = 0
    inflight: int = 0
    adm_pending: int = 0
    adm_inflight: int = 0


@dataclass
class SweepResult:
    """What the sweep did, in the vocabulary the terminal and the coverage records need."""
    eligible_pairs: int = 0
    attempted_pairs: int = 0            # candidates inside slots whose invocation returned
    invocations: int = 0                # runner calls that ran, not a slot count
    invocations_obtained: int = 0
    invocation_classes: dict = field(default_factory=dict)
    targets_eligible: int = 0           # every target the corpus offered

    #: cumulative, from the durable rotation: a per-run count cannot say what is still owed
    targets_complete: int = 0
    targets_remaining: int = 0
    remaining_now: int = 0              # a later child would attempt it
    remaining_cooldown: int = 0         # ...once its admission cooldown expires
    remaining_terminal: dict = field(default_factory=dict)   # {cause: targets}
    remainder_known: bool = False       # False: nobody may read the partition's zeroes as a fixed point

    targets_admitted: int = 0           # ...that the per-run allowance let this lifecycle start
    targets_refused: int = 0            # ...that the caller's admission check turned away
    admission_unknown: int = 0          # answers whose save was interrupted: on disk or not, unknown
    #: one immutable record, so a transition across several counters is a single store
    books: _Books = field(default_factory=_Books)
    #: `save()` reports durability through its result, which is never ignored
    admission_unpersisted: int = 0
    refused_pairs: int = 0
    refused: list = field(default_factory=list)
    targets_contacted: int = 0          # ...whose invocation actually ran — not the same fact

    #: targets the per-run allowance deferred, and the pairs they hold. A disposition, never the stop.
    deferred_targets: int = 0
    deferred_pairs: int = 0
    cap_reasons: list = field(default_factory=list)
    #: slots no bound can ever admit — a remainder disposition, not a stop, reported through
    #: `unretriable`
    unselectable_slots: int = 0
    unselectable_pairs: int = 0
    #: pairs the per-target spend bound excluded, counted as they were: a stop and a bound own
    #: different pairs
    bound_pairs: int = 0
    #: structured detail per refused slot, `{"target", "slot", "members"}`; the counters are
    #: authoritative. Not `machinery`: a consumer must not match English.
    unselectable: list = field(default_factory=list)

    #: staged-but-unpublished is pending (a later save rescues it); never staged is unstaged and stays
    #: owed. Neither counts complete.
    pending_targets: set = field(default_factory=set)
    unstaged_targets: set = field(default_factory=set)
    #: structured identity for every exception this driver contained: `{"index", "target", "unit",
    #: "phase", "exc"}`. A caller must recognise its own without matching English.
    contained: list = field(default_factory=list)

    slots_attempted: int = 0
    slots_obtained: int = 0             # SUCCESS or EMPTY — a clean answer, including "nothing resolved"
    classes: dict = field(default_factory=dict)
    reservations_persisted: int = 0
    completion_unpersisted: int = 0
    #: publication unknown — the run ended between `complete_batch` and the save, and nothing rescues
    #: these
    completion_unknown: int = 0
    #: never staged: no `done` tuple exists, so nothing can publish or rescue them.
    completion_unstaged: int = 0
    #: whether the eligible set was ever established: unknown is not zero
    eligibility_known: bool = False
    #: accounting attribution: `eligible` is the whole corpus, `attempted` the scheduled prefix, and
    #: uniform hashing says nothing about the first k buckets
    per_source_eligible: dict = field(default_factory=dict)
    per_source_attempted: dict = field(default_factory=dict)

    machinery: list = field(default_factory=list)
    stop: str | None = None             # None = the whole eligible set ran
    #: what ended the sweep: None, "budget", "machinery", "contention", "dependency". A budget or
    #: candidate bound is a cap we chose; everything else is a gap.
    stop_kind: str | None = None
    state_status: str = "missing"
    contended: bool = False

    # ── views onto the publication books ─────────────────────────────────────────────────────────
    # each setter is one store of a new record, so an interruption means the increment did not happen
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
        """Transient: pending completions a running save could carry."""
        return self.books.inflight

    @inflight_completions.setter
    def inflight_completions(self, n: int) -> None:
        self.books = replace(self.books, inflight=int(n))

    @property
    def admission_pending(self) -> int:
        """Admission answers written in memory but not yet durable. A later successful save writes the
        whole map and carries them, so these are pending, not lost."""
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
        """Every eligible pair this run did not attempt, split by what withheld it. Dispositions are taken in
        order and the parts sum to `eligible - attempted`; reporting that total as a policy bound would tell
        the operator a cap fired when none did."""
        rest = max(0, self.eligible_pairs - self.attempted_pairs)
        parts = {}
        for key, value in (("refused", self.refused_pairs), ("unselectable", self.unselectable_pairs),
                           ("deferred", self.deferred_pairs), ("bound", self.bound_pairs)):
            parts[key] = min(rest, max(0, int(value)))
            rest -= parts[key]
        # a stop owns what is left when something stopped the run; otherwise the bound does
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
        """Whether the remainder is resumable. Rendered from the state and the counters: unusable state, or a
        machinery stop that persisted nothing, is not."""
        if self.state_status == "unusable":
            return False
        return not (self.stop_kind == "machinery" and self.reservations_persisted == 0)


#: statuses that mean the tool answered. `EMPTY` is an answer; `SKIPPED` never enters the attempted
#: denominator, because no process ran.
_OBTAINED = (Status.SUCCESS, Status.EMPTY)


def run_sweep(*, lane: str, state_dir, targets, vocabulary, execute, budget_s: int,
              coverage_lane: str, dependency_ok=None, attribution=None, max_pairs_per_target: int = 0,
              max_targets_per_run: int = 0, admit=None,
              now=time.time) -> SweepResult:
    """Drive one lane's sweep, emitting the three coverage records and raising nothing but cancellation.

    `vocabulary(target) -> [word]` is the eligible corpus; the driver buckets it. `execute(target, unit,
    words) -> RunResult` submits one invocation, whose status attests every slot it carried.
    `attribution(word) -> source` is accounting only. The bounds and the `admit` contract are in
    docs/design/STEP4-SCHEDULING-DESIGN.md.
    """
    out = SweepResult()
    clock = budget.Budget(budget_s)

    # ── before the lock: the workload is a pure function of the corpus and the targets, so a contender
    #    still reports an exact denominator ──
    members: dict = {}
    unselectable_slots: set = set()        # (target, slot) no bound can ever admit — a terminal fact
    seen_pairs: set = set()
    corpus: dict = {}
    try:
        for target in dict.fromkeys(targets):          # a repeated target is one target
            per_target: list = []
            raw = vocabulary(target) or []
            if isinstance(raw, (str, bytes, bytearray)):
                # the contract is a collection of words: a bare string is iterable, and `"alpha"` would submit
                # four single letters
                raise TypeError(f"vocabulary returned {_safe_name(raw)} {_safe_repr(raw)}, "
                                f"not a collection of words")
            for word in raw:
                if type(word) is not str or not word:
                    # an exact non-empty str: a subclass can override `encode` and escape the allocator
                    raise TypeError(f"vocabulary returned {_safe_name(word)} {_safe_repr(word)}, "
                                    f"not a non-empty str")
                if (target, word) in seen_pairs:       # one submission per word per target: a duplicate
                    continue                           # inflates the denominator, the digest, the
                seen_pairs.add((target, word))         # attribution and the active payload alike
                per_target.append(word)
            corpus[target] = per_target
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:                 # only cancellation escapes this driver
        # `vocabulary` is the caller's callable: a failure there leaves the eligible set unknown, not zero
        out.machinery.append(f"the corpus could not be built ({_safe_exc(e)})")
        out.stop, out.stop_kind = "machinery: the corpus could not be built", "machinery"
        _partition_unrun(out)
        _report_safely(coverage_lane, out, clock)
        return out
    out.eligibility_known = True
    # the denominator is known before the bound is: every eligible pair exists whether or not we can
    # partition it
    out.eligible_pairs = sum(len(words) for words in corpus.values())
    out.targets_eligible = len([t for t, words in corpus.items() if words])

    try:
        max_pairs_per_target = _exact_cap(max_pairs_per_target)
        max_targets_per_run = _exact_cap(max_targets_per_run, "the per-run target allowance")
    except ValueError as e:
        # nothing but cancellation escapes, so a nonsense bound is a machinery stop with nothing
        # submitted
        out.stop, out.stop_kind = f"machinery: {e}", "machinery"
        _report_safely(coverage_lane, out, clock)             # coverage is filed under the registered
        return out                                     # source, never the scheduler's private lane name

    # the batch maximum bounds the slot, not just the batch: applied after a slot is chosen, a lone
    # oversized slot would bypass it
    alloc_cap = min([b for b in (max_pairs_per_target, MAX_BATCH_WORDS) if b] or [0])
    for target, per_target in corpus.items():
        partition = allocate(per_target, cap=alloc_cap)
        placed = [word for group in partition.values() for word in group]
        if len(placed) != len(per_target) or set(placed) != set(per_target):
            # a pair the partition dropped is in no slot, so no rotation reaches it
            out.stop = (f"machinery: the slot partition does not cover {target} "
                        f"({len(placed)} placed, {len(set(placed))} distinct, of {len(per_target)})")
            out.stop_kind = "machinery"
            _partition_unrun(out)
            _report_safely(coverage_lane, out, clock)
            return out
        # a slot the allocator could not split below the bound is schedulable by no run. Removed here, in
        # one place, so nothing downstream reclassifies it as an ordinary cap.
        if alloc_cap:
            over = {slot: group for slot, group in partition.items() if len(group) > alloc_cap}
            room = max(0, _UNSELECTABLE_DETAIL - len(out.unselectable))   # a global bound
            for slot, group in sorted(over.items())[:room]:
                out.unselectable.append({"target": target, "slot": slot, "members": len(group),
                                         "bound": alloc_cap})
            out.unselectable_slots += len(over)
            out.unselectable_pairs += sum(len(group) for group in over.values())
            unselectable_slots.update((target, slot) for slot in over)
            partition = {slot: group for slot, group in partition.items() if slot not in over}
        for slot, group in partition.items():
            members[(target, slot)] = group
    slots = sorted(members)
    # the denominator stays the corpus count, not a re-count of the partition: a lost word must surface
    # as an unattempted pair
    content = {slot: content_digest(words) for slot, words in members.items()}
    owners: dict = {}
    _owners_stage: dict = {}
    _sources_stage: dict = {}
    try:
      if attribution is not None:
        # eligible attribution is over the whole corpus: an unschedulable slot is still a pair this lane
        # was eligible to submit
        for target, per_target in corpus.items():
            for word in per_target:
                # staged, not published as we go: a partial map is not a complete attribution
                _owners_stage[word] = src = attribution(word)
                _sources_stage[src] = _sources_stage.get(src, 0) + 1
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:                 # only cancellation escapes this driver
        # accounting may not authorise or block work, but it may not escape either.
        out.machinery.append(f"attribution failed ({_safe_exc(e)})")
        out.stop, out.stop_kind = "machinery: attribution failed", "machinery"
        _report_safely(coverage_lane, out, clock)     # `per_source_eligible` stays EMPTY: nothing was published
        return out
    owners = _owners_stage                     # the whole corpus was attributed, or none of it is used
    out.per_source_eligible.update(_sources_stage)

    if not members:
        # nothing is schedulable: no tool could have run, so neither a dependency nor a lock explains it
        _partition_unrun(out)
        _report_safely(coverage_lane, out, clock)
        return out

    if dependency_ok is not None:
        try:
            ready = dependency_ok()
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as e:             # only cancellation escapes this driver
            out.machinery.append(f"the dependency check raised ({_safe_exc(e)})")
            out.stop, out.stop_kind = "machinery: the dependency check raised", "machinery"
            _partition_unrun(out)
            _report_safely(coverage_lane, out, clock)
            return out
        if ready is not True and ready is not False:
            # this gate decides whether active work happens: the only answers are yes and no, never
            # truthiness
            out.machinery.append(f"the dependency check answered {_safe_name(ready)} "
                                 f"{_safe_repr(ready)}, not True or False")
            out.stop, out.stop_kind = "machinery: the dependency check gave no usable answer", "machinery"
            _partition_unrun(out)
            _report_safely(coverage_lane, out, clock)
            return out
        if ready is False:
            out.stop = "the tool is not installed"      # no reservations at all
            out.stop_kind = "dependency"
            _partition_unrun(out)
            _report_safely(coverage_lane, out, clock)
            return out

    inflight = 0                          # slots whose publication is unresolved
    staged = False                        # ...and whether their `done` tuples were ever written
    try:
      with contextlib.ExitStack() as stack:
        try:
            progress = stack.enter_context(budget.rotation_session(state_dir, lane, schema=SCHEMA,
                                                                   slot_grammar=slot_id_ok))
        except budget.StateBusy as e:
            # acquisition only: a `StateBusy` from the sweep body is machinery, not contention
            out.contended = True
            out.stop = f"another lifecycle owns this rotation ({_safe_exc(e)})"
            out.stop_kind = "contention"       # nothing was submitted and no completion state was lost
            _partition_unrun(out)
            _report_safely(coverage_lane, out, clock)
            return out
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as e:
            # only `StateBusy` means another lifecycle; anything else is machinery, and letting it escape
            # throws away a denominator we already knew
            out.machinery.append(f"the rotation could not be acquired ({_safe_exc(e)})")
            out.stop = "machinery: the rotation could not be acquired"
            out.stop_kind = "machinery"
            _partition_unrun(out)
            _report_safely(coverage_lane, out, clock)
            return out

        out.state_status = progress.state_status
        if progress.state_status == "degraded":
            out.machinery.append(f"rotation state degraded: {progress.state_reason}")
        picked: set = set()
        started_targets: set = set()                       # the allowance admitted
        contacted: set = set()                             # ...and the invocation ran
        checked: set = set()                               # the admission hook has answered
        spent: dict = {}                                   # candidates submitted per target
        submitted: set = set()                             # slots whose pairs went into `spent`
        refused_targets: set = set()                       # targets the admission hook turned away
        while not clock.exhausted() and len(picked) < len(slots):
            batch = _next_batch(progress, slots, content, members, picked, spent, out,
                                cap=max_pairs_per_target, max_words=MAX_BATCH_WORDS,
                                max_targets=max_targets_per_run, started=started_targets)
            if batch is None:
                break
            target, chosen = batch                         # chosen: [(bucket, words)] — one invocation
            started_targets.add(target)
            out.targets_admitted = len(started_targets)
            total = sum(len(words) for _b, words in chosen)
            unit = _unit_of(chosen)

            # reserve the whole batch before contact, in one save
            try:
                gens = progress.reserve_batch(target, [b for b, _w in chosen], at=now())
                # the save is body work: a `StateBusy` or `OSError` from it is machinery, and is accounted for
                persisted = _persist(out, progress)
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as e:         # only cancellation escapes this driver — the clock is a
                # caller's callable too, so an `OSError` from `now()` must not escape either
                out.machinery.append(f"{target}/{unit}: reservation refused ({_safe_exc(e)})")
                out.stop = "machinery: the reservation was refused"
                out.stop_kind = "machinery"
                break
            if not persisted:
                # fail closed: nothing is submitted for slots whose reservation nobody owns
                out.stop = "machinery: the reservation could not be persisted"
                out.stop_kind = "machinery"
                break
            out.reservations_persisted += len(chosen)
            spent[target] = spent.get(target, 0) + total
            submitted.update((target, bucket) for bucket, _w in chosen)   # slots, not buckets

            if admit is not None and target not in checked:
                # admission: after the reservation is durable, before anything active happens
                checked.add(target)
                try:
                    allowed = admit(target)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except BaseException as e:     # only cancellation escapes this driver
                    out.machinery.append(f"{target}: admission check raised ({_safe_exc(e)})")
                    out.stop = "machinery: the admission check raised"
                    out.stop_kind = "machinery"
                    break
                if allowed is True:
                    # an admission supersedes any older refusal for the whole target, and is persisted where it is
                    # learned: a cancelled invocation must not leave the refusal authoritative on disk
                    _record_admission(out, progress, target, now, progress.admit_target,
                                      "the admission")
                if allowed is not True and allowed is not False:
                    # a safety boundary may not run on truthiness: yes and no, and anything else fails closed
                    out.machinery.append(f"{target}: the admission check answered "
                                         f"{_safe_name(allowed)} {_safe_repr(allowed)}, "
                                         f"not True or False")
                    out.stop = "machinery: the admission check gave no usable answer"
                    out.stop_kind = "machinery"
                    break
                if not allowed:
                    # the refusal is recorded so the target ranks behind attemptable work; losing the note costs
                    # ordering, not coverage. Counters commit before the fallible write.
                    out.targets_refused += 1
                    refused_targets.add(target)
                    if len(out.refused) < _UNSELECTABLE_DETAIL:
                        out.refused.append(target)
                    # every schedulable pair of this target is the refusal's: admission is target-wide, and nothing
                    # was contacted
                    for slot in slots:                    # this target is done for this lifecycle
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
            except BaseException as e:                  # `runner.run` can raise around Popen
                out.contained.append({"index": len(out.machinery), "target": target, "unit": unit,
                                      "phase": "execute", "exc": _safe_name(e)})
                out.machinery.append(f"{target}/{unit}: {_safe_exc(e)}")
                out.stop = "machinery: the invocation raised"
                out.stop_kind = "machinery"
                break
            # read once, inside containment: a property can pass validation and raise on its second access
            status = _safe_status(result)

            if status is Status.SKIPPED:                 # no process ran — a dependency answer
                out.stop = "the tool did not run"        # clause 3: it completes no slot
                out.stop_kind = "dependency"
                break
            out.invocations += 1                         # clause 6: invocations are their own measure
            contacted.add(target)                        # an invocation that ran, not one we planned
            out.targets_contacted = len(contacted)
            out.slots_attempted += len(chosen)
            out.attempted_pairs += total
            for _b, words in chosen:
                for word in words:                          # the two attempted totals must
                    src = owners.get(word)                  # agree even when publication never happens
                    if src is not None:
                        out.per_source_attempted[src] = out.per_source_attempted.get(src, 0) + 1
            if not isinstance(status, Status):
                # the call returned, so the payload went out, but the outcome is unusable and nothing was staged
                key = "invalid_result"
                out.classes[key] = out.classes.get(key, 0) + len(chosen)
                out.invocation_classes[key] = out.invocation_classes.get(key, 0) + 1
                out.completion_unstaged += len(chosen)
                out.unstaged_targets.add(target)
                out.machinery.append(f"{target}/{unit}: the invocation returned {_safe_name(result)} "
                                     f"{_safe_repr(result)} with no usable status")
                out.stop = "machinery: the invocation returned no usable status"
                out.stop_kind = "machinery"
                break
            if status in _OBTAINED:
                # clause 4: one result attests every slot it carried, and completion means attempted
                out.slots_obtained += len(chosen)
                out.invocations_obtained += 1
            else:
                key = str(getattr(status, "value", status))
                out.classes[key] = out.classes.get(key, 0) + len(chosen)
                # the slot-weighted map cannot say how many calls failed once batches differ in size
                out.invocation_classes[key] = out.invocation_classes.get(key, 0) + 1

            # in flight until the save resolves: a cancellation here leaves the tool result counted while the
            # disk holds only the reservation
            inflight = len(chosen)
            staged = False
            try:
                progress.complete_batch(target, [(b, gens[b], content[(target, b)], len(words))
                                                for b, words in chosen], at=now())    # clause 5
                staged = True                           # the `done` tuples exist in memory from here
                published = _persist(out, progress)
            except (KeyboardInterrupt, SystemExit):
                raise
            except budget.SchedulerInvariant as e:
                out.machinery.append(f"scheduler_invariant: {_safe_exc(e)}")
                out.stop = "machinery: scheduler invariant"
                out.stop_kind = "machinery"
                inflight = 0
                break
            except BaseException as e:                  # only cancellation escapes this driver
                if not staged:
                    # staging and publication are different failures: nothing reached the in-memory map, so no save can
                    # carry it. Still a slot that ran — unstaged, not forgotten.
                    out.completion_unstaged += inflight
                    out.unstaged_targets.add(target)
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
                # the `done` tuples stay in the in-memory map, so a later save persists them: pending, not lost
                out.pending_completions += len(chosen)
                out.pending_targets.add(target)


        # ── dispositions, reconciled from the whole slot set ────────────────────────────────────
        deferred_slots: set = set()
        if max_targets_per_run and len(started_targets) >= max_targets_per_run:
            # once the allowance is saturated, every unstarted target is deferred by it, not only the ones
            # ranking reached
            unstarted = {tgt for tgt, _s in slots if tgt not in started_targets}
            if unstarted:
                deferred_slots = {s for s in slots if s[0] in unstarted}
                out.deferred_targets = len(unstarted)
                out.deferred_pairs = sum(len(words) for (tgt, _s), words in members.items()
                                         if tgt in unstarted)
                why = f"the per-run target allowance ({max_targets_per_run}) was reached"
                if why not in out.cap_reasons:
                    out.cap_reasons.append(why)

        # ── slots the per-target spend bound can no longer admit ────────────────────────────────
        # a dry run in the scheduler's order: against one final `spent`, two one-word slots would both fit
        bound_slots: set = set()
        if max_pairs_per_target:
            room = dict(spent)
            # everything another disposition already owns, or that ran: the dry run walks the rest
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
            # the bound withheld work whether or not the scan reached it, so it is named either way
            why = f"the per-target candidate bound ({max_pairs_per_target}) was reached"
            if why not in out.cap_reasons:
                out.cap_reasons.append(why)

        # ── cumulative completion, read from the durable rotation ────────────────────────────────
        # complete = every slot clean for the content it holds now; per-run counts cannot determine
        # cumulative completion
        by_target: dict = {}
        for slot in slots:
            by_target.setdefault(slot[0], []).append(slot)
        done_targets = 0
        complete_targets: set = set()
        for tgt, group in by_target.items():
            if tgt in out.pending_targets or tgt in out.unstaged_targets:
                # staged in memory but never confirmed is not complete: the next lifecycle selects the slot again
                continue
            try:
                if all(progress.tier(tgt, s, content[(tgt, s)]) == 2 for _t, s in group):
                    done_targets += 1
                    complete_targets.add(tgt)
            except BaseException:                  # the ledger is best effort: a hint is never a stop
                break
        out.targets_complete = done_targets
        out.targets_remaining = max(0, out.targets_eligible - done_targets)

        # ...and what holds each owed target, at target level. The universe is the corpus, not the slot
        # map: a target with only inadmissible work holds no slots, which is the signal.
        blocked_targets = {tgt for tgt, _slot in unselectable_slots}
        cooldown, blocked, live = [], [], []
        for tgt, words in corpus.items():
            if not words or tgt in complete_targets:
                continue
            if tgt in refused_targets:
                cooldown.append(tgt)
            elif not [s for s in by_target.get(tgt, []) if s not in submitted] and tgt in blocked_targets:
                blocked.append(tgt)            # nothing schedulable is left for it
            else:
                live.append(tgt)
        terminal: dict = {}
        if blocked:
            terminal["unschedulable"] = len(blocked)
        if live and out.stop_kind in ("machinery", "dependency"):
            terminal[out.stop_kind] = len(live)
            live = []
        out.remaining_cooldown = len(cooldown)
        out.remaining_terminal = terminal
        out.remaining_now = len(live)
        out.remainder_known = True

        # ── the stop: what actually ended the run ────────────────────────────────────────────────
        # an elapsed clock stopped work only if selectable slots were left; anything already classified was
        # never the clock's to take
        stopped_by_clock = clock.exhausted() and any(s not in picked and s not in deferred_slots
                                                     and s not in bound_slots for s in slots)
        if out.stop_kind is None and stopped_by_clock:
            # first cause wins: relabelling a machinery stop that crossed the bound as "budget" would launder
            # a failure into a choice
            out.stop = f"budget exhausted after {clock.elapsed()}s of {clock.seconds}s"
            out.stop_kind = "budget"           # a cap we chose, not a failure
        elif out.stop_kind is None and out.cap_reasons:
            # no failure and no clock-stopped work: a cap we chose ended the run
            out.stop_kind = "bound"
            out.stop = "; ".join(out.cap_reasons)
    except (KeyboardInterrupt, SystemExit):
        # what accumulated so far is fact: flushed before the cancellation continues, and a failure to
        # report it may not mask the cancellation
        if out.stop_kind is None:
            # settle the disposition first, or the record claims a cap for a run a Ctrl-C ended
            out.stop, out.stop_kind = "CANCELLED mid-sweep", "cancelled"
        _settle_completions(out, inflight=inflight, staged=staged)
        try:
            _report_safely(coverage_lane, out, clock)
        except BaseException:
            # `BaseException`, not `Exception`: the bare `raise` below always propagates the original
            pass
        raise
    _settle_completions(out)
    if not out.remainder_known:
        # the body ended before the durable partition ran: classify from what stopped it, or zeroes read
        # as a fixed point
        _partition_unrun(out)
    _report_safely(coverage_lane, out, clock)
    return out


def _settle_completions(out: "SweepResult", *, inflight: int = 0, staged: bool = True) -> None:
    """Close the books on publication, on every exit: these slots ran and their targets were contacted, so a
    counter no emitted fact consumes is silent loss."""
    # cancelled before staging is not unknown, it is unpublished; only a staged batch leaves the
    # question open
    if staged:
        out.completion_unknown += max(0, int(inflight))
    else:
        # pending means a real in-memory tuple a later save can carry; an unstaged batch has none
        out.completion_unstaged += max(0, int(inflight))
    # admission durability settles the same way, from the final state rather than the first failed
    # write
    if out.inflight_completions:
        # a save that was interrupted could have carried these too — unknown, not lost.
        out.completion_unknown += out.inflight_completions
        out.pending_completions -= min(out.pending_completions, out.inflight_completions)
        out.inflight_completions = 0
    if out.admission_inflight:
        # interrupted mid-write: unknown, and the pending claim it came from is withdrawn
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
    """`progress.save()` behind the publication contract. Every save writes the whole map, so it carries
    every pending tuple."""
    b = out.books
    out.books = replace(b, inflight=b.pending, adm_inflight=b.adm_pending)
    try:
        ok = progress.save()
    except (KeyboardInterrupt, SystemExit):
        raise                                  # in flight stays set: settled as unknown, never as lost
    except BaseException:
        _land(out)
        raise                                  # the caller owns its own containment
    if ok:
        _rescue(out)                           # this save carried every pending tuple with it
    else:
        _land(out)
    return ok


def _land(out: "SweepResult") -> None:
    out.books = replace(out.books, inflight=0, adm_inflight=0)


def _record_admission(out: "SweepResult", progress, target: str, now, write, what: str) -> None:
    """Write an admission answer and try to make it durable, contained. A failed write leaves no tuple; a
    failed save leaves one pending."""
    try:
        write(target, at=now())
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:
        out.machinery.append(f"{target}: {what} could not be recorded ({_safe_exc(e)})")
        return
    out.admission_pending += 1
    try:
        _persist(out, progress)                # in flight across the save, rescued on success
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:
        out.machinery.append(f"{target}: {what} could not be persisted ({_safe_exc(e)})")


def _rescue(out: "SweepResult") -> None:
    """A successful save carries every pending completion and admission answer with it, whatever failed
    earlier."""
    b = out.books
    out.books = _Books(published=b.published + b.pending, pending=0, inflight=0,
                       adm_pending=0, adm_inflight=0)
    # ...and no target still owes a completion this save carried
    out.pending_targets.clear()


def _safe_text(render) -> str:
    """Render a diagnostic without letting it escape the driver: every part of one is attacker-adjacent."""
    try:
        return str(render())
    except (KeyboardInterrupt, SystemExit):
        raise                                  # cancellation is the only thing that leaves this driver
    except BaseException:
        return "<unrepresentable>"


def _safe_status(result):
    return _safe_call(lambda: getattr(result, "status", None))


def _safe_call(fn):
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
    return f"{_safe_name(exc)}: {_safe_text(lambda: exc)}"


def _unit_of(chosen) -> str:
    """The id one invocation is reported and named by. A single slot keeps its own id."""
    first = chosen[0][0]
    return first if len(chosen) == 1 else f"{first}+{len(chosen) - 1}"


def _next_batch(progress, slots, content, members, picked, spent, out, *, cap: int, max_words: int,
                max_targets: int = 0, started=frozenset()):
    """The next invocation: the prefix of the global rank order that stays inside one target and one tier.
    Ranking stays global, so batching never reorders the sweep."""
    chosen: list = []
    target = tier = None
    total = 0
    while len(picked) < len(slots):
        choice = _rank(progress, slots, content, picked)
        if choice is None:
            break
        this_target, bucket = choice
        if max_targets and this_target not in started and len(started) >= max_targets:
            # the allowance of targets is spent. Excluded, not skipped, so the loop terminates and the rotation
            # hands this target to a later run — a throughput bound, not a membership cap.
            picked.add(choice)
            continue
        this_tier = progress.tier(this_target, bucket, content[choice])
        if chosen and (this_target != target or this_tier != tier):
            break                                       # clause 1: one target, one tier
        words = members[choice]
        if cap and spent.get(this_target, 0) + total + len(words) > cap:
            # does not fit what the target may still spend. Excluded rather than skipped so the loop
            # terminates, and the scan continues so a smaller slot behind it can still fit.
            picked.add(choice)
            continue
        if chosen and max_words and total + len(words) > max_words:
            break                                       # an oversized slot never reaches here: the
                                                        # allocator's own bound removed it
        target, tier = this_target, this_tier
        chosen.append((bucket, words))
        total += len(words)
        picked.add(choice)
    return (target, chosen) if chosen else None


def _rank(progress, slots, content, picked):
    """Tier first globally, then target fairness inside that tier, then the stalest slot."""
    live = [s for s in slots if s not in picked]
    if not live:
        return None
    tiers = {s: progress.tier(s[0], s[1], content[s]) for s in live}
    best = min(tiers.values())
    in_tier = [s for s in live if tiers[s] == best]
    target = min({t for t, _ in in_tier}, key=lambda t: (progress.target_seq(t), t))
    return min([s for s in in_tier if s[0] == target],
               key=lambda s: (progress.slot_seq(*s), s[1]))


def _partition_unrun(out: "SweepResult") -> None:
    """Classify a run that ended before the rotation could be read, from what stopped it. The mapping is in
    docs/design/STEP4-SCHEDULING-DESIGN.md; an eligible set that was never established stays unknown.
    """
    if not out.eligibility_known:
        return
    owed = int(out.targets_eligible)
    out.targets_remaining = owed
    out.remaining_now = out.remaining_cooldown = 0
    out.remaining_terminal = {}
    if owed:
        if out.stop_kind in ("dependency", "machinery"):
            out.remaining_terminal = {out.stop_kind: owed}
        elif out.stop_kind is None and not out.slots_attempted and out.unselectable_slots:
            out.remaining_terminal = {"unschedulable": owed}
        else:
            out.remaining_now = owed
    out.remainder_known = True


def _report_safely(lane: str, out: SweepResult, clock) -> None:
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
    """Selection over candidate-target pairs, outcome over slots — different denominators, never summed."""
    if not out.eligibility_known:
        # the corpus never finished building: structured but uncounted, which the reconciler admits as a
        # gap rather than a clean 0/0/0
        events.coverage_partial(lane, kind=events.COVERAGE_UNKNOWN, measure="candidate_pairs",
                                unit="candidate_pairs",
                                reason=f"{out.stop or 'the eligible set could not be determined'} — no "
                                       f"candidate denominator exists for this run")
        return
    # a budget stop keeps `report_selection`'s own cap wording; every other stop is a named gap
    budget.report_selection(lane, measure="candidate_pairs", eligible=out.eligible_pairs,
                            attempted=out.attempted_pairs, budget=clock, noun="candidate",
                            durable=out.durable,
                            stop=None if out.stop_kind in (None, "budget", "bound") else out.stop,
                            # a candidate bound is a cap with its own wording: the budget sentence would read "0s of 0s"
                            cap_reason="; ".join(out.cap_reasons) if out.stop_kind == "bound" else None,
                            # every applicable cap is named even when something else ended the run
                            extra="; ".join(out.cap_reasons) if out.stop_kind != "bound" else None,
                            # pairs in a slot no bound can admit are not a remainder anyone will retry
                            unretriable=out.unselectable_pairs)
    budget.report_outcome(lane, measure="slot_outcomes", attempted=out.slots_attempted,
                          obtained=out.slots_obtained, classes=out.classes or None, noun="slot")
    if out.invocations:
        # a third outcome denominator: one invocation may carry several slots, so calls and slots are
        # different facts
        budget.report_outcome(lane, measure="tool_invocations", attempted=out.invocations,
                              obtained=out.invocations_obtained,
                              classes=out.invocation_classes or None, noun="invocation")
    if out.completion_unpersisted:
        # metadata, not a denominator: the counters die with the result, and the slots' outcome record
        # already says they ran
        events.ledger(lane, unit="completion", produced=None,
                      completion={"pending": out.pending_completions,
                                  "unknown": out.completion_unknown,
                                  "unstaged": out.completion_unstaged,
                                  "unpersisted": out.completion_unpersisted})
    if out.targets_refused or out.admission_unpersisted:
        # metadata, not a fourth denominator: a refusal is already inside the selection record
        events.ledger(lane, unit="admission", produced=None,
                      admission={"targets": out.targets_refused, "pairs": out.refused_pairs,
                                 "detail": list(out.refused),
                                 "unpersisted": out.admission_unpersisted,
                                 "unknown": out.admission_unknown,
                                 "truncated": out.targets_refused > len(out.refused)})
    if out.unselectable_pairs:
        # the counters are the fact; this carries the operator detail into the run's evidence
        events.ledger(lane, unit="unschedulable", produced=None,
                      unschedulable={"slots": out.unselectable_slots, "pairs": out.unselectable_pairs,
                                     "detail": list(out.unselectable),
                                     "truncated": out.unselectable_slots > len(out.unselectable)})
    if out.per_source_eligible:
        # not a third denominator: metadata about the same selection. Its own field, because `produced` is
        # reserved for parser counts that a status view folds as output.
        events.ledger(lane, unit="attribution", produced=None,
                      selection_attribution={
                          "eligible": sum(out.per_source_eligible.values()),
                          "scheduled": sum(out.per_source_attempted.values()),
                          "per_source_eligible": dict(sorted(out.per_source_eligible.items())),
                          "per_source_scheduled": dict(sorted(out.per_source_attempted.items()))})
