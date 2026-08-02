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


class UnionUnusable(RuntimeError):
    """The union cannot stand in for what the campaign knows — so nothing may be built on it.

    Raised rather than returned: a supervisor that got an empty corpus back would bootstrap a smaller
    child, absorb its narrower result and call the difference a fixed point. Refusing loudly is the only
    answer that cannot be mistaken for progress."""


class Union:
    """The campaign's cumulative entity store, at `<project>/recon/campaigns/<id>/union.jsonl`.

    It carries the same trust model as a child's evidence, for the same reason: a deleted, truncated or
    tampered union would quietly hand the next child LESS than the campaign knows.

        new        deliberately created; empty and authoritative
        valid      every row loaded and verified, and the content matches what `save()` recorded
        degraded   rows were dropped, or the content no longer matches the recorded digest
        unusable   there is no union to read, or it could not be read at all
        unknown    a union exists but nothing says what it should contain (no metadata)
    """

    def __init__(self, path, *, create: bool = False):
        self.path = Path(path)
        self.meta_path = self.path.with_name(self.path.name + ".meta.json")
        self.records: dict = {}          # {(kind, key): record}
        self.status = "unusable"
        self.dropped = 0
        self.reason = ""
        self._load(create=create)

    @classmethod
    def for_campaign(cls, project_dir, campaign_id: str, *, create: bool = False) -> "Union":
        return cls(Path(project_dir) / "recon" / "campaigns" / campaign_id / "union.jsonl", create=create)

    @property
    def trustworthy(self) -> bool:
        return self.status in ("valid", "new")

    def require(self) -> None:
        """Refuse to be used when the union is not trustworthy."""
        if not self.trustworthy:
            raise UnionUnusable(f"{self.path}: {self.status} — {self.reason}")

    # ── loading, with everything verified ─────────────────────────────────────────────────────────
    def _load(self, *, create: bool) -> None:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            # an ABSENT union is a new campaign only when someone SAID so. Otherwise it is evidence that
            # went missing, and reading it as "nothing known yet" is exactly the false fixed point.
            self.status, self.reason = (("new", "created") if create
                                        else ("unusable", "no union at this path"))
            return
        except OSError as e:
            self.status, self.reason = "unusable", f"{type(e).__name__}: {e}"
            return
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
        self._reconcile(raw)

    def _reconcile(self, raw: bytes) -> None:
        """Compare what was read against what `save()` recorded. A clean line-boundary truncation drops no
        row and raises nothing — only the recorded count and digest can catch it."""
        if self.dropped:
            self.status = "degraded"
            self.reason = f"{self.dropped} unusable union row(s)"
            return
        try:
            meta = json.loads(self.meta_path.read_text())
            count, digest = meta["count"], meta["digest"]
            if type(count) is not int or not isinstance(digest, str):
                raise ValueError("malformed union metadata")
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            self.status = "unknown"
            self.reason = f"no usable union metadata ({type(e).__name__})"
            return
        actual = hashlib.sha256(raw).hexdigest()
        if len(self.records) != count or actual != digest:
            self.status = "degraded"
            self.reason = (f"the union recorded {count} record(s), this file yields {len(self.records)}"
                           if len(self.records) != count else "the union file changed since it was saved")
            return
        self.status, self.reason = "valid", ""

    def save(self) -> None:
        """Rewrite the union atomically — it is a MERGED view, not an append-only log, and a half-written
        one would hand the next child a corpus nobody produced. The sidecar records what was written, so a
        later truncation cannot pass as a smaller campaign."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for (kind, key), rec in sorted(self.records.items()):
            lines.append(json.dumps({"kind": kind, "id": key, "record": rec,
                                     "fp": store.fingerprint(kind, rec)}, ensure_ascii=False))
        body = "\n".join(lines) + ("\n" if lines else "")
        store._atomic_write(self.path, body)
        store._atomic_write(self.meta_path, json.dumps(
            {"count": len(self.records), "digest": hashlib.sha256(body.encode("utf-8")).hexdigest()}))
        self.status, self.dropped, self.reason = "valid", 0, ""

    # ── absorbing a finished child ────────────────────────────────────────────────────────────────
    def absorb(self, run_dir, kinds=None) -> AbsorbResult:
        """Merge a FINISHED child's entities into the union and report what it added.

        Only a TRUSTWORTHY view is absorbed (`store.fold_run_entity`): a deleted, truncated or unreadable
        log is recorded as unusable rather than folded in as an empty corpus, because the difference
        between "this child found nothing" and "we could not read what it found" is the difference between
        a fixed point and a lie."""
        self.require()
        out = AbsorbResult()
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
        out.absorbed = True
        self.save()
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
