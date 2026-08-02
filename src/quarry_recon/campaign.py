"""The campaign's CUMULATIVE STORE — settle prerequisite C.

Entities are RUN-SCOPED: a second `Run.create` in the same project starts empty. A supervisor that repeats
runs therefore needs somewhere for what earlier children learned to live, and — the part that is easy to
miss — every later child must START from it. Once acquisition closes after child 1
(`notes/SETTLE-DESIGN.md` §4), the hosts a provider found would otherwise simply be ABSENT from child 2's
corpus, the processing lanes would have nothing to work through, and the campaign would read that as a
fixed point: `--settle` forgetting the very evidence it exists to finish processing.

So the union is BOTH the oracle and the input:

    ABSORB      a finished child's trustworthy entities are merged in (monotonically, by the store's own
                rules), and the delta says whether that child made PROGRESS
    BOOTSTRAP   the next child is seeded from the union with provenance intact, marked INHERITED so its own
                production stays distinguishable from what it was handed

Nothing here creates runs or decides anything — the supervisor does not exist yet. This is the store the
supervisor will use, and the invariants it will rely on: absorbing is idempotent, bootstrapping is
idempotent, an inherited entity is never counted as the child's own discovery, and a child whose evidence
could not be read is never absorbed as if it were empty.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import store

#: marks an entity a child was HANDED rather than found. Bookkeeping about how this run got it, never a
#: fact about the world, so `store.RUN_SCOPED_FIELDS` excludes it from material content — an inherited
#: copy fingerprints exactly like the record it came from.
INHERITED = "_inherited"


@dataclass
class AbsorbResult:
    """What a child added to the union — the campaign's progress signal, per entity kind."""
    new: int = 0
    enriched: int = 0
    kinds: dict = field(default_factory=dict)          # {entity: {"new": int, "enriched": int}}
    unusable: dict = field(default_factory=dict)       # {entity: reason} — evidence we could NOT read
    absorbed: bool = False                             # whether the union was updated at all

    @property
    def progressed(self) -> bool:
        """A child made progress when it added an identity or enriched one. Never when its evidence could
        not be read: an unreadable child is a question, not a fixed point."""
        return self.absorbed and not self.unusable and bool(self.new or self.enriched)


#: exactly the keys a recovery entry may carry. An unknown key is not an extension to shrug at — this is
#: the campaign's audit record of lost evidence, and anything we cannot account for we do not certify.
_RECOVERY_KEYS = {"generation", "reason", "at"}


# ── acquisition: what a campaign may still OBTAIN ────────────────────────────────────────────────────
#: whether this process may run ACQUISITION lanes. A campaign closes it after its first child: repeating a
#: run repeats its provider calls, and a continuation flag may not make that spending decision
#: (`notes/FLAG-AXIS-PLAN.md` §2). Off by default — an ordinary `quarry run` acquires as it always has.
_acquisition_closed = False
#: why it was closed, so a blocked lane can say what stopped it rather than looking broken.
_acquisition_reason = ""


@contextlib.contextmanager
def acquisition_closed(reason: str = "acquisition is closed for this campaign after its first child"):
    """Close acquisition for the duration — restored afterwards, like every other run-scoped instruction."""
    global _acquisition_closed, _acquisition_reason
    before, before_reason = _acquisition_closed, _acquisition_reason
    _acquisition_closed, _acquisition_reason = True, reason
    try:
        yield
    finally:
        _acquisition_closed, _acquisition_reason = before, before_reason


def acquisition_allowed(source_id: str) -> tuple[bool, str]:
    """`(allowed, why_not)` for one lane. Only ACQUISITION lanes are ever refused — everything else is
    processing, which is exactly what a later child exists to do."""
    from . import policy
    if not _acquisition_closed or source_id not in policy.PROVIDER_LANES:
        return True, ""
    return False, _acquisition_reason


def _valid_recoveries(history, pointer_generation: int) -> bool:
    """A recovery history is readable only when it could actually have HAPPENED.

    `{generation: int > 0, reason: non-empty str, at: an aware ISO-8601 timestamp}`, entries strictly
    increasing and none from a generation this pointer has not reached. A duplicate, a descending pair or a
    recovery "from" generation 999 inside generation 3 is not a history — it is something we cannot read,
    and an audit record we cannot read may not certify a corpus."""
    if not isinstance(history, list):
        return False
    previous = 0
    for entry in history:
        if not isinstance(entry, dict) or set(entry) != _RECOVERY_KEYS:
            return False
        gen = entry.get("generation")
        if type(gen) is not int or gen <= 0 or gen <= previous or gen > pointer_generation:
            return False
        previous = gen
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            return False
        if not _aware_stamp(entry.get("at")):
            return False
    return True


def _aware_stamp(at) -> bool:
    """An audit timestamp is readable only when it says WHEN — a naive stamp does not."""
    if not isinstance(at, str) or not at.strip():
        return False
    try:
        when = datetime.fromisoformat(at)
    except ValueError:
        return False
    return when.tzinfo is not None and when.tzinfo.utcoffset(when) is not None


#: exactly the keys ONE campaign recovery may carry. `reason` is what the operator admits was lost; `cause`
#: is what the ledger itself said was wrong, kept so the admission cannot outlive its evidence.
_CAMPAIGN_RECOVERY_KEYS = {"index", "reason", "cause", "at"}


def _valid_campaign_recoveries(history) -> bool:
    """Same rule as the union's (`_valid_recoveries`): an audit record we cannot read may not certify a
    ledger. Ordered by an explicit ordinal rather than a generation — a campaign recovery ERASES the
    children, so there is no accumulating number to hang the order on, and a clock is not an order."""
    if not isinstance(history, list):
        return False
    for expected, entry in enumerate(history, start=1):
        if not isinstance(entry, dict) or set(entry) != _CAMPAIGN_RECOVERY_KEYS:
            return False
        if entry.get("index") != expected or type(entry["index"]) is not int:
            return False
        for name in ("reason", "cause"):
            if not isinstance(entry.get(name), str) or not entry[name].strip():
                return False
        if not _aware_stamp(entry.get("at")):
            return False
    return True


def _generation_file(generation: int) -> str:
    """The ONE filename a generation may have. Deriving it (rather than trusting the pointer's string) is
    what keeps a generation inside its campaign directory."""
    return f"union-gen{generation:06d}.jsonl"


class UnionUnusable(RuntimeError):
    """The union cannot stand in for what the campaign knows — so nothing may be built on it.

    Raised rather than returned: a supervisor that got an empty corpus back would bootstrap a smaller
    child, absorb its narrower result and call the difference a fixed point. Refusing loudly is the only
    answer that cannot be mistaken for progress."""


class Union:
    """The campaign's cumulative entity store, published as immutable GENERATIONS behind one pointer.

    `<project>/recon/campaigns/<id>/union.json` is the pointer; `union-gen<N>.jsonl` are the generations it
    names. Two files written separately are not one publication — a crash between them would leave a corpus
    with metadata describing a different one, and no last-known-good to fall back to. So a generation is
    written COMPLETE first, and the pointer is replaced last: until that single atomic replace lands, the
    previous generation is still what the campaign reads.

    Trust states, for the same reason a child's evidence has them — a union that quietly shrank would seed a
    smaller child, absorb the narrower result and call the difference a fixed point:

        new        deliberately created, with NO prior artifact of any kind; empty and authoritative
        valid      the pointer's generation loaded and every row verified against it
        degraded   rows were dropped, or the generation does not match what the pointer recorded
        unusable   there is no pointer, or nothing it names can be read
    """

    def __init__(self, path, *, create: bool = False):
        self.path = Path(path)                       # the POINTER
        self.dir = self.path.parent
        self.records: dict = {}          # {(kind, key): record}
        self.status = "unusable"
        self.dropped = 0
        self.reason = ""
        self.generation = 0
        #: every RECOVERY this campaign has ever made, carried forward in the pointer. A union rebuilt
        #: after evidence loss must never look like one that was only ever accumulated.
        self.recoveries: list = []
        self._load(create=create)

    @classmethod
    def for_campaign(cls, project_dir, campaign_id: str, *, create: bool = False) -> "Union":
        return cls(Path(project_dir) / "recon" / "campaigns" / campaign_id / "union.json", create=create)

    @property
    def trustworthy(self) -> bool:
        return self.status in ("valid", "new")

    @property
    def was_recovered(self) -> bool:
        """Whether this campaign's corpus was ever rebuilt after a loss. A supervisor may not declare a
        fixed point over a reconstructed union without saying so."""
        return bool(self.recoveries)

    def require(self) -> None:
        """Refuse to be used when the union is not trustworthy."""
        if not self.trustworthy:
            raise UnionUnusable(f"{self.path}: {self.status} — {self.reason}")

    def _generations(self):
        """Every generation file that survives here, or None when the directory cannot be INSPECTED.

        The two answers are different: "nothing is here" licenses creating a campaign, and "I could not
        look" must never be mistaken for it."""
        try:
            return sorted(p for p in self.dir.glob("union-gen*.jsonl") if p.is_file())
        except OSError:
            return None

    # ── loading, with everything verified ─────────────────────────────────────────────────────────
    def _load(self, *, create: bool) -> None:
        try:
            pointer = json.loads(self.path.read_text())
            if not isinstance(pointer, dict):
                raise ValueError("pointer is not an object")
        except FileNotFoundError:
            # An absent pointer is a NEW campaign only when someone asked for one AND nothing of an
            # earlier campaign survives here. A deleted pointer beside its generations is evidence loss,
            # and blessing it as new is exactly the false fixed point this guards against.
            leftovers = self._generations()
            if create and leftovers is None:
                self.status = "unusable"
                self.reason = "the campaign directory could not be inspected — refusing to create"
            elif create and not leftovers:
                self.status, self.reason = "new", "created"
            elif create:
                self.status = "unusable"
                self.reason = f"refusing to create over {len(leftovers)} existing generation(s)"
            else:
                self.status, self.reason = "unusable", "no union pointer at this path"
            return
        except (OSError, json.JSONDecodeError, ValueError) as e:
            self.status, self.reason = "unusable", f"pointer unusable: {type(e).__name__}"
            return
        name, count, digest = pointer.get("file"), pointer.get("count"), pointer.get("digest")
        gen = pointer.get("generation")
        # The GENERATION is identity, not decoration. Defaulting a malformed one to 0 let the next
        # publication write `union-gen000001.jsonl` — over the generation the pointer still names, so the
        # authoritative corpus would be destroyed BEFORE the swap that was supposed to replace it. And the
        # file must be exactly the name that generation implies, which also confines it to this directory:
        # no separators, no traversal, nothing to resolve.
        if type(gen) is not int or gen <= 0 or name != _generation_file(gen):
            self.status, self.reason = "unusable", "pointer does not identify a generation"
            return
        self.generation = gen
        if type(count) is not int or count < 0 or not isinstance(digest, str):
            self.status, self.reason = "unusable", "pointer does not describe a generation"
            return
        history = pointer.get("recoveries", [])
        if not _valid_recoveries(history, gen):
            # the campaign's own admission that evidence was lost. If we cannot READ it, we certainly
            # cannot certify the corpus it describes.
            self.status, self.reason = "unusable", "pointer's recovery history is unreadable"
            return
        self.recoveries = [dict(r) for r in history]
        try:
            raw = (self.dir / name).read_bytes()
        except OSError as e:
            self.status, self.reason = "unusable", f"generation {name!r} unreadable: {type(e).__name__}"
            return
        self._read_rows(raw)
        if self.dropped:
            self.status = "degraded"
            self.reason = f"{self.dropped} unusable union row(s)"
        elif len(self.records) != count or hashlib.sha256(raw).hexdigest() != digest:
            self.status = "degraded"
            self.reason = (f"the pointer records {count} record(s), generation {name!r} yields "
                           f"{len(self.records)}" if len(self.records) != count
                           else f"generation {name!r} changed since it was published")
        else:
            self.status, self.reason = "valid", ""

    def _read_rows(self, raw: bytes) -> None:
        for chunk in raw.splitlines():
            if not chunk.strip():
                continue
            try:
                row = json.loads(chunk.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.dropped += 1                          # one bad row costs itself, and is COUNTED
                continue
            if not isinstance(row, dict):
                self.dropped += 1
                continue
            kind, rec = row.get("kind"), row.get("record")
            if not isinstance(kind, str) or kind not in store.ENTITY_KEYS or not isinstance(rec, dict):
                self.dropped += 1                          # an unregistered kind is not an entity
                continue
            key = store.canonical_key(kind, rec)
            # the persisted id and fingerprint are CHECKED, not trusted: a row whose id does not match its
            # record, or whose fingerprint does not match its content, describes something else
            if not key or row.get("id") != key or row.get("fp") != store.fingerprint(kind, rec):
                self.dropped += 1
                continue
            self.records[(kind, key)] = rec

    # ── publishing ────────────────────────────────────────────────────────────────────────────────
    def save(self) -> None:
        """Publish the current records as the next generation. ORDINARY publication only: a union that is
        not already trustworthy may not certify itself, or a truncated one would rewrite the pointer for
        its surviving subset and reappear as a smaller, healthy campaign."""
        self.require()
        self._publish()

    def recover(self, reason: str) -> None:
        """Republish a DEGRADED or UNUSABLE union deliberately, with the loss stated.

        Separate from `save()` and impossible to reach by accident: the caller has to name what was lost,
        and the pointer records that this generation was recovered rather than accumulated."""
        if not reason or not reason.strip():
            raise ValueError("a recovery must state what was lost")
        self._publish(recovered=reason.strip())

    def _publish(self, recovered: str = "") -> None:
        """Write the generation COMPLETE, then swap the single pointer. Until the pointer lands, the
        previous generation is what the campaign reads; it is left in place, so a failed swap costs
        nothing.

        EVERYTHING is inside the settlement boundary — the directory, the serialisation, the fingerprints,
        the generation choice and both writes. A caller has already mutated `self.records` by the time this
        runs, so anything that raises in preparation would otherwise leave this object `valid` while
        holding a record no disk published."""
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            nxt = self._next_generation()
            name = _generation_file(nxt)
            lines = []
            for (kind, key), rec in sorted(self.records.items()):
                lines.append(json.dumps({"kind": kind, "id": key, "record": rec,
                                         "fp": store.fingerprint(kind, rec)}, ensure_ascii=False))
            body = "\n".join(lines) + ("\n" if lines else "")
            history = [dict(r) for r in self.recoveries]
            if recovered:
                history.append({"generation": nxt, "reason": recovered, "at": store._utc()})
            pointer = {"generation": nxt, "file": name, "count": len(self.records),
                       "digest": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                       # CARRIED FORWARD, every publication: a recovery recorded only in the pointer that
                       # made it would vanish on the next ordinary save, and the campaign would go back to
                       # looking like one that never lost anything.
                       "recoveries": history}
            store._atomic_write(self.dir / name, body)
            store._atomic_write(self.path, json.dumps(pointer, indent=2))
        except BaseException:
            # ANY interruption leaves publication UNDECIDED — the swap may have landed a moment before a
            # cancellation, or not at all. Guessing either way is how an object keeps records no disk holds
            # (or discards records the disk does hold), so the authoritative pointer is re-read and adopted.
            try:
                self._settle()
            except BaseException:
                # settling failed too: say so, and let the ORIGINAL failure be the one that propagates
                self.status = "unusable"
                self.reason = "publication failed and the pointer could not be re-read"
            raise
        self.generation = nxt
        self.recoveries = history
        self.status, self.dropped, self.reason = "valid", 0, ""

    def _next_generation(self) -> int:
        """A generation number strictly ABOVE every one that survives here — never merely `self.generation
        + 1`, which is 0-based for a malformed pointer and would publish OVER an existing generation. An
        immutable generation is only immutable if nothing ever replaces it."""
        surviving = self._generations()
        if surviving is None:
            raise OSError(f"{self.dir}: the campaign directory could not be inspected")
        highest = int(self.generation)
        for path in surviving:
            digits = path.name[len("union-gen"):-len(".jsonl")]
            if digits.isdigit():
                highest = max(highest, int(digits))
        nxt = highest + 1
        if (self.dir / _generation_file(nxt)).exists():          # belt and braces: never replace one
            raise OSError(f"{self.dir}: generation {nxt} already exists")
        return nxt

    def _settle(self) -> None:
        """Adopt whatever the pointer actually says now — the only authority on what was published."""
        self.records, self.dropped, self.reason = {}, 0, ""
        self.status, self.generation = "unusable", 0
        self._load(create=False)

    # ── absorbing a finished child ────────────────────────────────────────────────────────────────
    def absorb(self, run_dir, kinds=None) -> AbsorbResult:
        """Merge a FINISHED child's entities into the union and report what it added.

        Only a TRUSTWORTHY view is absorbed (`store.fold_run_entity`): a deleted, truncated or unreadable
        log is recorded as unusable rather than folded in as an empty corpus, because the difference
        between "this child found nothing" and "we could not read what it found" is the difference between
        a fixed point and a lie."""
        self.require()
        out = AbsorbResult()
        published = dict(self.records)            # the last PUBLISHED state, kept until this one lands
        for kind in (kinds if kinds is not None else sorted(store.ENTITY_KEYS)):
            folded = store.fold_run_entity(run_dir, kind)
            if not folded.trustworthy:
                out.unusable[kind] = f"{folded.status}: {folded.reason}"
                continue
            for key, rec in folded.records.items():
                slot = (kind, key)
                held = self.records.get(slot)
                if held is None:
                    self.records[slot] = dict(rec)
                    out.new += 1
                    out.kinds.setdefault(kind, {"new": 0, "enriched": 0})["new"] += 1
                elif store.adds_material(kind, held, rec):
                    self.records[slot] = store.merge(kind, held, rec)
                    out.enriched += 1
                    out.kinds.setdefault(kind, {"new": 0, "enriched": 0})["enriched"] += 1
        try:
            self._publish()
        except (KeyboardInterrupt, SystemExit):
            raise                                  # `_publish` already settled against the pointer
        except BaseException as e:
            # Publication failed or was interrupted, and `_publish` has re-read the pointer — so this
            # object now holds what the DISK holds, not what this absorb hoped to add. Whether that is the
            # previous generation or a swap that landed at the last moment, it is authoritative either way.
            out.unusable["__union__"] = (f"the union could not be published: {type(e).__name__}: {e}"
                                         if self.trustworthy else self.reason)
            if self.trustworthy and self.records != published:
                out.unusable["__union__"] += " (the pointer moved: this view is the published one)"
            return out
        out.absorbed = True
        return out

    # ── seeding the next child ────────────────────────────────────────────────────────────────────
    def bootstrap(self, run) -> dict:
        """Seed a child run from the union, provenance intact, WITHOUT claiming its discoveries.

        Every record keeps its `sources` and its `raw_ref`s — they point into the child that produced them,
        which is where the evidence actually is — and carries `_inherited`, so this child's own production
        stays distinguishable from what it started with. `Run.add`'s NEW-key answer is what phases count as
        discovery, and an inherited entity must never be counted that way, so the seed is written through
        the observation log directly.

        Idempotent: seeding twice adds nothing, because the merge is monotonic and the second copy is
        subsumed."""
        self.require()
        seeded: dict = {}
        for (kind, _key), rec in sorted(self.records.items()):
            record = dict(rec)
            record[INHERITED] = True
            if run.inherit(kind, record):
                seeded[kind] = seeded.get(kind, 0) + 1
        return seeded


# ── the campaign SUPERVISOR ──────────────────────────────────────────────────────────────────────────
#: why a campaign stopped. Every one of them is a NAMED outcome — a supervisor that runs out of reasons
#: and simply stops has told the operator nothing.
STOPS = ("fixed_point", "terminal", "unknown", "no_progress", "child_fault", "max_runs", "budget")
#: consecutive children with no new or enriched identity AND no reduction in the retriable remainder
NO_PROGRESS_LIMIT = 2
#: how many children one campaign may create before it stops and says so
MAX_CHILDREN = 10


@dataclass
class Decision:
    """What the supervisor concluded from one child, and whether another may run."""
    stop: str | None = None          # a name from STOPS, or None to continue
    detail: str = ""
    progressed: bool = False
    retriable: int = 0

    @property
    def success(self) -> bool:
        """Only a FIXED POINT is success. Terminal work, unknown lanes, a fault and every bound are
        outcomes a campaign must state, not quietly finish on."""
        return self.stop == "fixed_point"


def decide(summary: dict, absorbed: "AbsorbResult", *, expected_lanes=(), idle_children: int = 0,
           children: int = 0, max_children: int = MAX_CHILDREN,
           previous_retriable: int | None = None) -> Decision:
    """The stop rules, read from a child's manifest summary and what it added to the union.

    Order matters and is fixed: a broken child is not continuation, so CHILD FAULT is asked first; then a
    lane that should have reported and did not (UNKNOWN — silence is not a fixed point); then the bounds we
    chose; then progress; and only when every expected lane reported a KNOWN zero, with no terminal
    remainder outstanding and nothing new learned, is it a FIXED POINT."""
    faults = [f for f in summary.get("faults", [])
              if f.get("kind") in ("machinery", "phase_exception", "required_tool_missing")]
    if faults:
        return Decision(stop="child_fault", detail="; ".join(
            f"{f.get('kind')}: {f.get('where')}" for f in faults[:4]))

    # remainders are latest per (lane, UNIT, measure) — a lane may report several. Keeping one row per
    # lane let a valid unit hide an invalid sibling and dropped the others' counts entirely.
    by_lane: dict = {}
    for row in summary.get("remainders", []):
        if isinstance(row, dict) and isinstance(row.get("lane"), str):
            by_lane.setdefault(row["lane"], []).append(row)
    invalid = sorted(lane for lane, rows in by_lane.items()
                     if any(not _readable_remainder(r) for r in rows))
    silent = sorted(lane for lane in expected_lanes if lane not in by_lane)
    if invalid or silent:
        return Decision(stop="unknown", detail="; ".join(
            [f"{lane}: reported nothing" for lane in silent]
            + [f"{lane}: unreadable remainder" for lane in invalid])[:400])

    retriable = 0
    terminal: dict = {}
    for rows in by_lane.values():
        for row in rows:
            if row.get("model") != "project_progress":
                continue                              # repetition cannot advance it — never keeps us alive
            rt = row.get("retriable") or {}
            retriable += int(rt.get("now", 0)) + int(rt.get("cooldown", 0))
            for cause, n in (row.get("terminal") or {}).items():
                if n:
                    terminal[cause] = terminal.get(cause, 0) + int(n)

    # PROGRESS is either new material or a strict reduction in what is owed: a child that discovered no
    # identity but took half the remaining work forward is not idle, and stopping it would abandon work
    # this campaign was measurably completing.
    reduced = previous_retriable is not None and retriable < previous_retriable
    progressed = bool(absorbed.progressed) or reduced
    if absorbed.unusable:
        return Decision(stop="unknown", progressed=progressed, retriable=retriable,
                        detail="; ".join(f"{k}: {v}" for k, v in sorted(absorbed.unusable.items()))[:400])
    if children >= max_children:
        return Decision(stop="max_runs", progressed=progressed, retriable=retriable,
                        detail=f"{children} child run(s)")
    if not progressed and idle_children + 1 >= NO_PROGRESS_LIMIT and retriable:
        return Decision(stop="no_progress", progressed=False, retriable=retriable,
                        detail=f"{idle_children + 1} child(ren) added nothing and reduced nothing while "
                               f"{retriable} unit(s) stayed owed")
    if retriable:
        return Decision(progressed=progressed, retriable=retriable)     # keep going: work a child can take
    if terminal:
        return Decision(stop="terminal", progressed=progressed,
                        detail="; ".join(f"{c}: {n}" for c, n in sorted(terminal.items())))
    if progressed:
        return Decision(progressed=True)          # nothing owed, but this child still learned something
    return Decision(stop="fixed_point", detail="no retriable work and nothing new")


def _readable_remainder(row: dict) -> bool:
    """Whether one remainder row can be believed. A row the manifest already marked `invalid`, or one whose
    counts are not exact non-negative ints, is UNKNOWN — and unknown is never zero."""
    from . import remainder as _remainder
    if row.get("model") not in _remainder.MODELS or not isinstance(row.get("unit"), str):
        return False
    rt, term = row.get("retriable"), row.get("terminal")
    if not isinstance(rt, dict) or not isinstance(term, dict):
        return False
    for value in (rt.get("now"), rt.get("cooldown"), *term.values()):
        if type(value) is not int or value < 0:
            return False
    return set(term) <= set(_remainder.TERMINAL_CAUSES)


def _unreadable_child(child, index: int, states) -> str:
    """Why one loaded child cannot be believed, or `""`. Types alone are not enough: a `reserved` child
    holding a run id, or a `manifested` one without the deltas the supervisor decided on, is a CONTRADICTION
    — the record and the state disagree, and a partially written ledger looks exactly like that."""
    if not isinstance(child, dict) or child.get("index") != index or type(child["index"]) is not int:
        return "is not a readable record"
    state = child.get("state")
    if state not in states:
        return f"has an unknown state {state!r}"
    run_id = child.get("run_id")
    if state == "reserved":
        if run_id is not None:
            return "is reserved but already names a run"
    elif not isinstance(run_id, str) or not run_id.strip():
        return f"is {state} without a run id"
    if state == "manifested":
        for name in ("new_identities", "enriched", "retriable"):
            if type(child.get(name)) is not int or child[name] < 0:
                return f"is manifested without an exact {name}"
        if type(child.get("progressed")) is not bool:
            return "is manifested without a progress verdict"
        for name in ("provider_spend", "faults"):
            if not isinstance(child.get(name), list):
                return f"is manifested without its {name}"
        if not isinstance(child.get("verdict"), (str, type(None))):
            return "is manifested with an unreadable verdict"
    return ""


def _readable_stop(stop) -> bool:
    """A stop is the campaign's OUTCOME. An arbitrary object in its place is not a stop we can report."""
    if stop is None:
        return True
    return (isinstance(stop, dict) and set(stop) == {"cause", "detail", "success"}
            and isinstance(stop["cause"], str) and stop["cause"].strip()
            and isinstance(stop["detail"], str) and type(stop["success"]) is bool)


class Campaign:
    """The supervisor's LEDGER and lock. It creates no runs itself — a caller drives children — but it owns
    what makes repetition safe: one project may have only one campaign at a time, and every child is
    recorded BEFORE it starts, so a crash leaves an interrupted child rather than an orphan run directory.

        reserved    an id is allocated and nothing has been launched
        started     the child's run directory exists
        manifested  its manifest was read and its deltas computed
    """

    STATES = ("reserved", "started", "manifested")

    def __init__(self, project_dir, campaign_id: str):
        self.project_dir = Path(project_dir)
        self.campaign_id = campaign_id
        self.dir = self.project_dir / "recon" / "campaigns" / campaign_id
        self.path = self.dir / "ledger.json"
        self.children: list = []
        self.stop: dict | None = None
        self.recoveries: list = []   # CHRONOLOGICAL, carried forward by every later publication
        self.status = "new"          # new | valid | unusable — absence may create, corruption may NOT
        self.reason = ""
        self._lock = None
        self._load()

    @property
    def trustworthy(self) -> bool:
        return self.status in ("new", "valid")

    def require(self) -> None:
        """Refuse to write over a ledger nobody can read: the next `reserve()` would publish child 1 again
        and launder a campaign's whole history."""
        if not self.trustworthy:
            raise UnionUnusable(f"{self.path}: {self.status} — {self.reason}")

    def recover(self, reason: str) -> None:
        """Start recording again over an UNREADABLE ledger, deliberately and with the loss stated.

        Only from `unusable`: recovery erases every child, so on a healthy campaign it is not a repair but
        the exact laundering `require()` exists to prevent. The admission is appended to a durable history
        (never a replaceable string) — an audit record that the next publication drops never happened."""
        if not reason or not reason.strip():
            raise ValueError("a recovery must state what was lost")
        if self.trustworthy:
            raise ValueError(f"{self.path}: a {self.status} campaign has nothing to recover — recovery "
                             f"would erase {len(self.children)} child record(s)")
        history = [*self.recoveries, {"index": len(self.recoveries) + 1,
                                      "reason": reason.strip(),
                                      "cause": self.reason or "unreadable",
                                      "at": store._utc()}]
        self._commit([], stop=False, recoveries=history)

    # ── the PROJECT lock: two supervisors on one project would duplicate whole runs ────────────────
    def acquire(self):
        """Take the project-wide campaign lock. Scoped to the PROJECT, not this campaign directory: two
        supervisors that minted different ids would otherwise take different locks and both spawn children
        against the same rotation."""
        from . import budget
        self._lock = budget.state_lock(self.project_dir / "recon" / "campaigns" / ".campaign.lock")
        return self._lock

    def _load(self) -> None:
        try:
            raw = self.path.read_text()
        except FileNotFoundError:
            self.status, self.reason = "new", "no ledger yet"
            return
        except OSError as e:
            self.status, self.reason = "unusable", f"{type(e).__name__}: {e}"
            return
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as e:
            self.status, self.reason = "unusable", f"ledger is not JSON ({type(e).__name__})"
            return
        kids = doc.get("children") if isinstance(doc, dict) else None
        if isinstance(doc, dict) and _valid_campaign_recoveries(doc.get("recoveries", [])):
            # salvaged even when the rest is unreadable: the admission chain must outlive the ledger it
            # admits to losing, or a second corruption quietly erases the first recovery's confession
            self.recoveries = [dict(r) for r in doc.get("recoveries", [])]
        if not isinstance(doc, dict) or not isinstance(kids, list):
            self.status, self.reason = "unusable", "ledger does not describe a campaign"
            return
        if not _valid_campaign_recoveries(doc.get("recoveries", [])):
            self.status, self.reason = "unusable", "recovery history is unreadable"
            return
        if doc.get("campaign_id") != self.campaign_id:
            # a ledger copied from another campaign would otherwise be rewritten under THIS id, with the
            # other campaign's children counted as ours
            self.status, self.reason = "unusable", (f"ledger belongs to campaign "
                                                    f"{doc.get('campaign_id')!r}")
            return
        for index, child in enumerate(kids, start=1):
            # a ledger whose children cannot be read is a ledger that cannot account for its runs
            bad = _unreadable_child(child, index, self.STATES)
            if bad:
                self.status, self.reason = "unusable", f"child {index} {bad}"
                return
        stop = doc.get("stop")
        if not _readable_stop(stop):
            self.status, self.reason = "unusable", "stop record is unreadable"
            return
        self.children = list(kids)
        self.stop = stop
        self.status, self.reason = "valid", ""

    def _settle(self) -> None:
        """Adopt whatever the ledger on disk actually says now — the only authority on what was published.

        CONTENT comes from disk; the record OBJECTS are reused per index, so a caller still holding the
        child it reserved keeps a record this ledger recognises and can retry a transient failure. Identity
        within a campaign is the index, and rebuilding it from scratch would strand the caller."""
        previous = self.children
        self.children, self.stop, self.recoveries = [], None, []
        self.status, self.reason = "unusable", "publication was interrupted"
        self._load()
        if self.status == "valid":
            reused = []
            for index, record in enumerate(self.children, start=1):
                held = previous[index - 1] if index <= len(previous) else None
                if isinstance(held, dict):
                    held.clear()
                    held.update(record)
                    record = held
                reused.append(record)
            self.children = reused

    def _refuse_unpublishable(self, records, stop, recoveries) -> None:
        """Exactly the loader's own rules, applied to the candidate document before it can reach disk."""
        if not isinstance(records, list):
            raise ValueError("a ledger's children must be a list")
        for index, child in enumerate(records, start=1):
            bad = _unreadable_child(child, index, self.STATES)
            if bad:
                raise ValueError(f"child {index} {bad}")
        if not _valid_campaign_recoveries(recoveries):
            raise ValueError(f"a recovery history must be readable to be published: {recoveries!r}")
        if not _readable_stop(stop):
            raise ValueError(f"a stop record must be readable to be published: {stop!r}")

    def _commit(self, records: list, *, stop=None, recoveries=None, adopt=None) -> None:
        """Publish `records` and only THEN let this object believe them.

        Every writer used to mutate memory first, so a write that never landed left a trustworthy campaign
        holding a child no disk had: the failed `reserve()` stayed as child 1 in memory, and the next
        successful one published it as a phantom alongside child 2. The whole preparation and the write are
        inside the boundary, and ANY interruption re-reads the authoritative ledger — an atomic write may
        have landed a moment before a cancellation, and guessing either way is how the two diverge."""
        stop = self.stop if stop is None else (None if stop is False else stop)
        recoveries = self.recoveries if recoveries is None else recoveries
        # the WHOLE document, at the one boundary every writer passes through. Validating only the record a
        # transition touched left the rest of the snapshot unchecked, and `reserve()` hands the caller the
        # live dict: a `reserved` child given a run id by hand was published by the next `finish()` and made
        # the ledger unusable on reopen. No writer can publish what `_load()` refuses — an invariant here,
        # not a courtesy of cooperative callers.
        self._refuse_unpublishable(records, stop, recoveries)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            doc = {"campaign_id": self.campaign_id, "children": records, "stop": stop,
                   "recoveries": recoveries}
            store._atomic_write(self.path, json.dumps(doc, indent=2))
        except BaseException:
            try:
                self._settle()
            except BaseException:
                # settling failed too: say so, and let the ORIGINAL failure be the one that propagates
                self.status = "unusable"
                self.reason = "publication failed and the ledger could not be re-read"
            raise
        if adopt is not None:
            adopt()
        self.children, self.stop, self.recoveries = list(records), stop, recoveries
        self.status, self.reason = "valid", ""

    # ── child states ──────────────────────────────────────────────────────────────────────────────
    def reserve(self) -> dict:
        """Record a child BEFORE anything is launched — a crash then leaves an interrupted child in the
        ledger instead of a run directory nobody knows about."""
        self.require()
        child = {"index": len(self.children) + 1, "state": "reserved", "run_id": None}
        self._commit([*self.children, child])
        return child

    def _advance(self, child: dict, to: str) -> None:
        """Every publication is fail-closed and in ORDER. `require()` alone on `reserve()` left three doors
        open: a reopened corrupt ledger could still be laundered by calling `finish()`. Ownership is checked
        by IDENTITY — a record from another campaign is not this ledger's to advance."""
        self.require()
        index = child.get("index") if isinstance(child, dict) else None
        if (type(index) is not int or not (1 <= index <= len(self.children))
                or self.children[index - 1] is not child):
            raise ValueError("that child record does not belong to this campaign")
        state = child.get("state")
        if state not in self.STATES or self.STATES.index(to) != self.STATES.index(state) + 1:
            raise ValueError(f"child {index}: {state} -> {to} is not a transition this ledger records")

    def _transition(self, child: dict, to: str, **fields) -> None:
        """Advance one child through a CANDIDATE: the live record is never touched until the candidate has
        been validated and published. Mutating first meant a rejected manifestation left the child marked
        `manifested` and malformed in memory, where the next `finish()` published it and made the ledger
        unusable — the validation refused the write and produced exactly the record it refused."""
        self._advance(child, to)
        index = child["index"]
        candidate = {**child, **fields, "state": to}
        records = list(self.children)     # `_commit` validates the whole snapshot, candidate included
        records[index - 1] = candidate
        # the caller keeps holding the record it reserved, so identity — and every later transition —
        # survives the swap; the update lands only once the disk has agreed
        self._commit(records, adopt=lambda: (child.update(candidate), records.__setitem__(index - 1, child)))

    def started(self, child: dict, run_id: str) -> None:
        self.require()                     # trust is checked before anything else, always
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("a started child must name its run")
        self._transition(child, "started", run_id=run_id)

    def manifested(self, child: dict, *, summary: dict, absorbed: "AbsorbResult",
                   decision: "Decision") -> None:
        self._transition(child, "manifested", verdict=summary.get("verdict"),
                         new_identities=absorbed.new, enriched=absorbed.enriched,
                         retriable=decision.retriable, progressed=decision.progressed,
                         provider_spend=summary.get("provider_spend", []),
                         faults=[f.get("kind") for f in summary.get("faults", [])])

    def finish(self, decision: "Decision") -> None:
        self.require()
        self._commit(self.children, stop={"cause": decision.stop or "fixed_point",
                                          "detail": decision.detail, "success": decision.success})

    @property
    def interrupted(self) -> list:
        """Children the ledger recorded and never saw finish — an honest account of a crash."""
        return [c for c in self.children if c.get("state") != "manifested"]
