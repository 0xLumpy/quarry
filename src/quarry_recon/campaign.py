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


class Union:
    """The campaign's cumulative entity store, at `<project>/recon/campaigns/<id>/union.jsonl`."""

    def __init__(self, path):
        self.path = Path(path)
        self.records: dict = {}          # {(kind, key): record}
        self._load()

    @classmethod
    def for_campaign(cls, project_dir, campaign_id: str) -> "Union":
        return cls(Path(project_dir) / "recon" / "campaigns" / campaign_id / "union.jsonl")

    def _load(self) -> None:
        try:
            raw = self.path.read_bytes()
        except OSError:
            return
        for chunk in raw.splitlines():
            if not chunk.strip():
                continue
            try:
                row = json.loads(chunk.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue                                   # one bad row costs itself, never the union
            if not isinstance(row, dict):
                continue
            kind, rec = row.get("kind"), row.get("record")
            if not isinstance(kind, str) or not isinstance(rec, dict):
                continue
            key = store.canonical_key(kind, rec)
            if not key:
                continue
            self.records[(kind, key)] = rec

    def save(self) -> None:
        """Rewrite the union atomically — it is a MERGED view, not an append-only log, and a half-written
        one would hand the next child a corpus nobody produced."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for (kind, key), rec in sorted(self.records.items()):
            lines.append(json.dumps({"kind": kind, "id": key, "record": rec,
                                     "fp": store.fingerprint(kind, rec)}, ensure_ascii=False))
        store._atomic_write(self.path, "\n".join(lines) + ("\n" if lines else ""))

    # ── absorbing a finished child ────────────────────────────────────────────────────────────────
    def absorb(self, run_dir, kinds=None) -> AbsorbResult:
        """Merge a FINISHED child's entities into the union and report what it added.

        Only a TRUSTWORTHY view is absorbed (`store.fold_run_entity`): a deleted, truncated or unreadable
        log is recorded as unusable rather than folded in as an empty corpus, because the difference
        between "this child found nothing" and "we could not read what it found" is the difference between
        a fixed point and a lie."""
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
        seeded: dict = {}
        for (kind, _key), rec in sorted(self.records.items()):
            record = dict(rec)
            record[INHERITED] = True
            if run.inherit(kind, record):
                seeded[kind] = seeded.get(kind, 0) + 1
        return seeded
