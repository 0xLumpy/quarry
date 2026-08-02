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

import hashlib
import json
from dataclasses import dataclass, field
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


def _valid_recoveries(history) -> bool:
    """A recovery entry is `{generation: int > 0, reason: non-empty str, at: str}` — anything else means
    the history cannot be read, and a history that cannot be read may not be waved through."""
    if not isinstance(history, list):
        return False
    for entry in history:
        if not isinstance(entry, dict):
            return False
        if type(entry.get("generation")) is not int or entry["generation"] <= 0:
            return False
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            return False
        if not isinstance(entry.get("at"), str):
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
        if not _valid_recoveries(history):
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
