"""The campaign's cumulative store: the union of what every child run has learned.

Entities are run-scoped, so a supervisor that repeats runs needs somewhere for earlier children's
findings to live and every later child to start from (`docs/design/SETTLE-DESIGN.md` §4). It creates no
runs and decides nothing: it absorbs a finished child's trustworthy entities monotonically (the delta is
that child's progress) and bootstraps the next child from the union with provenance intact. Both are
idempotent, an inherited entity is never counted as the child's own discovery, and a child whose evidence
could not be read is never absorbed as if it were empty.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import remainder as _remainder, revision as _revision, state as _state, store
from .repository_identity import (InvalidCampaignId, InvalidRunId, valid_campaign_id,
                                  valid_run_id, valid_segment, validate_campaign_id,
                                  validate_run_id)
from .state import ContractError


#: marks an entity a child was handed rather than found. `store.RUN_SCOPED_FIELDS` excludes it from
#: material content, so an inherited copy fingerprints exactly like the record it came from.
INHERITED = "_inherited"


@dataclass
class AbsorbResult:
    """What a child added to the union, per entity kind — the campaign's progress signal."""
    new: int = 0
    enriched: int = 0
    kinds: dict = field(default_factory=dict)          # {entity: {"new": int, "enriched": int}}
    unusable: dict = field(default_factory=dict)       # {entity: reason} — evidence we could not read
    absorbed: bool = False                             # whether the union was updated at all

    @property
    def progressed(self) -> bool:
        """Progress is an identity added or enriched, and never a child whose evidence could not be read."""
        return self.absorbed and not self.unusable and bool(self.new or self.enriched)

    def as_record(self) -> dict:
        return {"new": self.new, "enriched": self.enriched, "kinds": dict(self.kinds),
                "unusable": dict(self.unusable)}

    @classmethod
    def from_record(cls, record) -> "AbsorbResult":
        """A run's absorption, replayed exactly: the deltas are the ones the union published, never a
        second merge's zeroes."""
        out = cls(new=record["new"], enriched=record["enriched"], kinds=dict(record["kinds"]),
                  unusable=dict(record["unusable"]))
        out.absorbed = True
        return out


#: exactly the keys one absorption record carries; counts are exact non-negative ints. `view` is the
#: combined view it was taken from, and is optional: a ledger written before revisions were tracked reads
#: as the base-only view.
_ABSORBED_KEYS = {"new", "enriched", "kinds", "unusable"}
_ABSORBED_OPTIONAL = {"view"}
_BASE_VIEW = [0, ""]


def _absorbed_view(record: dict) -> list:
    """The `(revision, digest)` an absorption folded, as a list; a record without one names the base run."""
    view = record.get("view")
    return list(view) if isinstance(view, list) else list(_BASE_VIEW)


def _valid_absorptions(absorbed) -> bool:
    """`{run_id: {new, enriched, kinds, unusable[, view]}}` — the ledger of which runs this union already
    holds, and of which view of each."""
    if not isinstance(absorbed, dict):
        return False
    for run_id, record in absorbed.items():
        if not valid_run_id(run_id):
            return False
        if not isinstance(record, dict) or not _ABSORBED_KEYS <= set(record):
            return False
        if set(record) - _ABSORBED_KEYS - _ABSORBED_OPTIONAL:
            return False
        for name in ("new", "enriched"):
            if type(record[name]) is not int or record[name] < 0:
                return False
        if not isinstance(record["kinds"], dict) or not isinstance(record["unusable"], dict):
            return False
        if "view" in record:
            v = record["view"]
            if (not isinstance(v, list) or len(v) != 2 or type(v[0]) is not int or v[0] < 0
                    or not isinstance(v[1], str)):
                return False
    return True


#: exactly the keys a recovery entry may carry — an unknown one makes the history unreadable.
_RECOVERY_KEYS = {"generation", "reason", "at"}


# ── acquisition: what a campaign may still obtain ────────────────────────────────────────────────────

#: whether this process may run acquisition lanes. Off by default; a campaign closes it after its first
#: child, because repeating a run repeats its provider calls (`docs/design/FLAG-AXIS-PLAN.md` §2).
_acquisition_closed = False
#: why it was closed, so a blocked lane can name what stopped it.
_acquisition_reason = ""


@contextlib.contextmanager
def acquisition_closed(reason: str = "acquisition is closed for this campaign after its first child"):
    """Close acquisition for the duration of the block; the previous setting is restored afterwards."""
    global _acquisition_closed, _acquisition_reason
    before, before_reason = _acquisition_closed, _acquisition_reason
    _acquisition_closed, _acquisition_reason = True, reason
    try:
        yield
    finally:
        _acquisition_closed, _acquisition_reason = before, before_reason


def acquisition_allowed(source_id: str) -> tuple[bool, str]:
    """`(allowed, why_not)` for one lane. Only `policy.PROVIDER_LANES` are ever refused."""
    from . import policy
    if not _acquisition_closed or source_id not in policy.PROVIDER_LANES:
        return True, ""
    return False, _acquisition_reason


def _valid_recoveries(history, pointer_generation: int) -> bool:
    """`{generation: int > 0, reason: non-empty str, at: an aware ISO-8601 timestamp}`, entries strictly
    increasing and none above `pointer_generation`."""
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
    if not isinstance(at, str) or not at.strip():
        return False
    try:
        when = datetime.fromisoformat(at)
    except ValueError:
        return False
    return when.tzinfo is not None and when.tzinfo.utcoffset(when) is not None


#: exactly the keys one campaign recovery may carry: `reason` is what the operator admits was lost,
#: `cause` is what the ledger itself said was wrong.
_CAMPAIGN_RECOVERY_KEYS = {"index", "reason", "cause", "at"}


def _valid_campaign_recoveries(history) -> bool:
    """Same rule as `_valid_recoveries`, ordered by an explicit 1-based `index` rather than a
    generation — a campaign recovery erases the children, so nothing accumulates to order them by."""
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
    """The one filename a generation may have; derived, so it stays inside the campaign directory."""
    return f"union-gen{generation:06d}.jsonl"


class UnionUnusable(RuntimeError):
    """The union cannot stand in for what the campaign knows, so nothing may be built on it. Raised
    rather than returned: an empty corpus handed back looks exactly like a campaign that found nothing."""


class Union:
    """The campaign's cumulative entity store, published as immutable generations behind one pointer
    (`docs/design/SETTLE-DESIGN.md` §4)."""

    #: new: created with no prior artifact, empty and authoritative · valid: the pointer's generation
    #: loaded and every row verified · degraded: rows dropped or the generation is not what was published
    #: · unusable: no pointer, or nothing it names can be read
    def __init__(self, path, *, create: bool = False, absent_is_damage: str = ""):
        self.path = Path(path)                       # the pointer
        self.dir = self.path.parent
        if (self.path.name != "union.json" or self.dir.parent.name != "campaigns"
                or self.dir.parent.parent.name != "recon"):
            raise ContractError(f"{self.path}: a campaign union must live at "
                                "<project>/recon/campaigns/<campaign-id>/union.json")
        validate_campaign_id(self.dir.name)
        self.project_dir = self.dir.parent.parent.parent
        #: why an absent union would be evidence loss rather than a fresh start, when it would be
        self.absent_is_damage = absent_is_damage
        self.records: dict = {}          # {(kind, key): record}
        self.status = "unusable"
        self.dropped = 0
        self.reason = ""
        self.generation = 0
        #: every recovery this campaign has made, carried forward by every later publication.
        self.recoveries: list = []
        #: {run_id: deltas} — which children this union already holds, so absorbing one twice replays its
        #: deltas instead of finding nothing new.
        self.absorbed: dict = {}
        self._load(create=create)

    @classmethod
    def for_campaign(cls, project_dir, campaign_id: str, *, create: bool = False) -> "Union":
        validate_campaign_id(campaign_id)
        # only a campaign that has manifested nothing may be handed an empty union: the ledger is what
        # says whether there was ever a corpus to lose
        settled = sum(1 for c in Campaign(project_dir, campaign_id).children
                      if c.get("state") == "manifested")
        return cls(Path(project_dir) / "recon" / "campaigns" / campaign_id / "union.json", create=create,
                   absent_is_damage=(f"the union is gone and the ledger records {settled} manifested "
                                     f"child run(s) — that corpus was lost, not never created"
                                     if settled else ""))

    @property
    def trustworthy(self) -> bool:
        return self.status in ("valid", "new")

    @property
    def was_recovered(self) -> bool:
        """Whether this campaign's corpus was ever rebuilt after a loss."""
        return bool(self.recoveries)

    def require(self) -> None:
        """Refuse to be used when the union is not trustworthy."""
        if not self.trustworthy:
            raise UnionUnusable(f"{self.path}: {self.status} — {self.reason}")

    def _generations(self):
        """Every generation file that survives here, or None when the directory could not be inspected."""
        try:
            return sorted(p for p in self.dir.glob("union-gen*.jsonl") if p.is_file())
        except OSError:
            return None

    # ── loading ───────────────────────────────────────────────────────────────────────────────────
    def _load(self, *, create: bool) -> None:
        try:
            pointer = json.loads(self.path.read_text())
            if not isinstance(pointer, dict):
                raise ValueError("pointer is not an object")
        except FileNotFoundError:
            # an absent pointer is a new campaign only when one was asked for and nothing of an earlier
            # campaign survives here: a deleted pointer beside its generations is evidence loss.
            leftovers = self._generations()
            if create and leftovers is None:
                self.status = "unusable"
                self.reason = "the campaign directory could not be inspected — refusing to create"
            elif create and self.absent_is_damage:
                # the ledger says this campaign already learned something: an absent union is that
                # corpus lost, and creating an empty one would republish the loss as authoritative
                self.status, self.reason = "unusable", self.absent_is_damage
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
        # the generation is identity: a malformed one defaulting to 0 would publish over the generation
        # the pointer still names, and the file must be exactly the name that generation implies.
        if type(gen) is not int or gen <= 0 or name != _generation_file(gen):
            self.status, self.reason = "unusable", "pointer does not identify a generation"
            return
        self.generation = gen
        if type(count) is not int or count < 0 or not isinstance(digest, str):
            self.status, self.reason = "unusable", "pointer does not describe a generation"
            return
        history = pointer.get("recoveries", [])
        if not _valid_recoveries(history, gen):
            # an audit record we cannot read may not certify the corpus it describes
            self.status, self.reason = "unusable", "pointer's recovery history is unreadable"
            return
        self.recoveries = [dict(r) for r in history]
        absorbed = pointer.get("absorbed", {})
        if not _valid_absorptions(absorbed):
            # a replay ledger we cannot read would recount a child's discoveries as zero
            self.status, self.reason = "unusable", "pointer's absorption ledger is unreadable"
            return
        self.absorbed = {run_id: dict(rec) for run_id, rec in absorbed.items()}
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
                self.dropped += 1                          # one bad row costs itself, and is counted
                continue
            if not isinstance(row, dict):
                self.dropped += 1
                continue
            kind, rec = row.get("kind"), row.get("record")
            if not isinstance(kind, str) or kind not in store.ENTITY_KEYS or not isinstance(rec, dict):
                self.dropped += 1                          # an unregistered kind is not an entity
                continue
            key = store.canonical_key(kind, rec)
            # the persisted id and fingerprint are checked, not trusted
            if not key or row.get("id") != key or row.get("fp") != store.fingerprint(kind, rec):
                self.dropped += 1
                continue
            self.records[(kind, key)] = rec

    # ── publishing ────────────────────────────────────────────────────────────────────────────────
    def save(self) -> None:
        """Publish the current records as the next generation. Ordinary publication only: a union that is
        not already trustworthy may not certify itself — see `recover`."""
        self.require()
        self._publish()

    def recover(self, reason: str) -> None:
        """Republish a degraded or unusable union deliberately, naming what was lost; the pointer then
        records that this generation was recovered rather than accumulated."""
        if not reason or not reason.strip():
            raise ValueError("a recovery must state what was lost")
        self._publish(recovered=reason.strip())

    def _publish(self, recovered: str = "") -> None:
        """Write the generation complete, then swap the single pointer — a failed swap costs nothing. The
        whole preparation and both writes are inside the settlement boundary."""
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
                       # carried forward by every publication, or the next ordinary save would drop it
                       "recoveries": history,
                       # lands in the same atomic swap as the generation it describes
                       "absorbed": {run_id: dict(rec) for run_id, rec in self.absorbed.items()}}
            store._atomic_write(self.dir / name, body)
            store._atomic_write(self.path, json.dumps(pointer, indent=2))
        except BaseException:
            # any interruption leaves publication undecided — the swap may have landed a moment before a
            # cancellation — so the authoritative pointer is re-read and adopted.
            try:
                self._settle()
            except BaseException:
                # settling failed too: say so, and let the original failure be the one that propagates
                self.status = "unusable"
                self.reason = "publication failed and the pointer could not be re-read"
            raise
        self.generation = nxt
        self.recoveries = history
        self.status, self.dropped, self.reason = "valid", 0, ""

    def _next_generation(self) -> int:
        """A generation number strictly above every one that survives here — never merely
        `self.generation + 1`, which for a malformed pointer would publish over an existing generation."""
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
        self.status, self.generation, self.absorbed = "unusable", 0, {}
        self._load(create=False)

    # ── absorbing a finished child ────────────────────────────────────────────────────────────────
    def absorb(self, run_dir, kinds=None) -> AbsorbResult:
        """Merge a finished child's entities into the union and report what it added.

        Only a trustworthy view is absorbed (`revision.combined_fold`, so a run revised after it finished
        contributes its late evidence too): a deleted, truncated or unreadable log is recorded in
        `AbsorbResult.unusable` rather than folded in as an empty corpus. Idempotent by run id AND by the
        view it was absorbed from: the same view twice replays the deltas it was published with, because a
        second merge finds nothing new and that is not the same fact, while a run whose combined view has
        changed is folded again."""
        selected = tuple(sorted(store.ENTITY_KEYS) if kinds is None else kinds)
        for kind in selected:
            store.validate_entity(kind)              # reject the complete request before reading the child view
        self.require()
        supplied = Path(run_dir)
        run_id = validate_run_id(supplied.name)
        expected = self.project_dir / "recon" / run_id
        if Path(os.path.abspath(os.fspath(supplied))) != Path(os.path.abspath(os.fspath(expected))):
            raise ContractError(f"run {run_id!r} is outside this campaign's project repository")
        store.read_run_identity(self.project_dir, run_id)       # reject symlink/non-run paths before view reads
        run_dir = expected
        view = list(_revision.view_identity(run_dir))
        held = self.absorbed.get(run_id)
        if held is not None and _absorbed_view(held) == view:
            return AbsorbResult.from_record(held)
        out = AbsorbResult()
        published = dict(self.records)            # the last published state, kept until this one lands
        for kind in selected:
            folded = _revision.combined_fold(run_dir, kind)
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
        self.absorbed[run_id] = {**out.as_record(), "view": view}
        try:
            self._publish()
        except (KeyboardInterrupt, SystemExit):
            raise                                  # `_publish` already settled against the pointer
        except BaseException as e:
            # `_publish` has re-read the pointer, so this object now holds what the disk holds — the
            # previous generation, or a swap that landed at the last moment. Authoritative either way.
            out.unusable["__union__"] = (f"the union could not be published: {type(e).__name__}: {e}"
                                         if self.trustworthy else self.reason)
            if self.trustworthy and self.records != published:
                out.unusable["__union__"] += " (the pointer moved: this view is the published one)"
            return out
        out.absorbed = True
        return out

    # ── seeding the next child ────────────────────────────────────────────────────────────────────
    def bootstrap(self, run) -> dict:
        """Seed a child run from the union, provenance intact, without claiming its discoveries.

        Every record keeps its `sources` and `raw_ref`s and carries `_inherited`. The seed is written
        through the observation log directly, so `Run.add`'s new-key answer — what phases count as
        discovery — never counts an inherited entity. Idempotent: seeding twice adds nothing."""
        self.require()
        seeded: dict = {}
        for (kind, _key), rec in sorted(self.records.items()):
            record = dict(rec)
            record[INHERITED] = True
            if run.inherit(kind, record):
                seeded[kind] = seeded.get(kind, 0) + 1
        return seeded


# ── the campaign supervisor ──────────────────────────────────────────────────────────────────────────
#: why a campaign stopped — every outcome has a name.
STOPS = ("fixed_point", "fixed_point_with_gaps", "terminal", "unknown", "no_progress", "child_fault",
         "max_runs", "budget")
#: consecutive children with no new or enriched identity and no reduction in the retriable remainder
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
    obligations: list = field(default_factory=list)   # the roster this child left behind
    terminal: dict = field(default_factory=dict)      # {cause: count} this decision counted as terminal

    @property
    def success(self) -> bool:
        """Only a fixed point is success; every other stop is an outcome the campaign must state."""
        return self.stop == "fixed_point"


#: verdicts a child may reach with its coverage intact; anything else the campaign reads as gapped.
_COVERED = ("complete", "complete_with_limits")


def _unresolved_gaps(summary: dict) -> list:
    """What the child says it did not cover, named. Its own `gaps` are authoritative; a verdict that
    claims less than covered with no gap list is unreadable, and unreadable is not clean."""
    gapped = [f"{g.get('tool') or g.get('phase')}: {g.get('status') or g.get('kind') or 'gap'}"
              for g in summary.get("gaps") or () if isinstance(g, dict)]
    if not gapped and summary.get("verdict") not in _COVERED:
        return [f"verdict {summary.get('verdict')!r} with no gap named"]
    return gapped


def _lane_activity(summary: dict) -> set:
    """Lanes with evidence they ran this child — their own coverage rollup, a gap, failure or limit
    attributed to them, or spend in their name. A lane that ran owes an answer even the first time."""
    active = set()
    for cov in summary.get("coverage") or ():
        if isinstance(cov, dict) and isinstance(cov.get("source_id"), str):
            active.add(cov["source_id"])
    for field_name in ("gaps", "failures", "coverage_limits", "provider_limits", "operator_limits"):
        for row in summary.get(field_name) or ():
            if isinstance(row, dict) and isinstance(row.get("tool"), str):
                active.add(row["tool"])
    for row in summary.get("provider_spend") or ():
        if isinstance(row, dict) and isinstance(row.get("lane"), str):
            active.add(row["lane"])
    return active


def _reported(row: dict) -> "_remainder.Obligation":
    """One remainder row as a disposition. A row that cannot be believed disposes of nothing: it is
    unknown, keyed by whatever of `(lane, unit, measure)` it did name."""
    lane = row["lane"]
    unit = row["unit"] if isinstance(row.get("unit"), str) else ""
    measure = row["measure"] if isinstance(row.get("measure"), str) else ""
    try:
        return _remainder.Obligation.of(_state.parse_remainder(row))
    except (ValueError, TypeError, KeyError):
        # flagged: the lane ran and could not measure. Otherwise: a record we cannot read.
        why = "could not measure its remainder" if row.get("invalid") else "unreadable remainder"
        return _remainder.Obligation(lane=lane, unit=unit, measure=measure, why=why)


#: what a lane's own entry says when its units disagree — the least settled of them wins.
_DISPOSITION_ORDER = ("unknown", "remainder", "terminal", "not_applicable", "known_zero")


def _lane_disposition(units) -> str:
    for disposition in _DISPOSITION_ORDER:
        if any(o.disposition == disposition for o in units):
            return disposition
    return "known_zero"


class Settlement:
    """Every obligation the campaign must dispose of, and how its last child disposed of each.

    The roster is complete before child one: every declared lane is an open obligation from the start, so
    a lane that ran and never said what it owes is caught in the first child rather than from the second
    on. Each child must leave every obligation with a disposition, per exact `(lane, unit, measure)` — a
    lane that keeps reporting one unit cannot retire another by staying quiet about it.
    """

    def __init__(self, *, expected=()):
        self.expected = set(expected)                # lanes that must report from now on
        self.roster = _remainder.roster(set(_remainder.LANE_MODEL) | self.expected)

    def adopt(self, records) -> None:
        """Take a child's persisted roster as this settlement's own, so a resumed campaign still owes
        exactly what that child left owed."""
        for record in records:
            ob = _remainder.Obligation.from_record(record)
            self.roster[ob.key] = ob
            if ob.disposition != "not_applicable":
                self.expected.add(ob.lane)

    def observe(self, summary: dict) -> list:
        """Dispose of every obligation from one child, and return the roster it leaves behind."""
        reported = {}
        for row in summary.get("remainders") or ():
            if isinstance(row, dict) and isinstance(row.get("lane"), str):
                ob = _reported(row)
                reported[ob.key] = ob
        heard = {key[0] for key in reported}
        active = self.expected | heard | (_lane_activity(summary) & set(_remainder.LANE_MODEL))
        roster: dict = {}
        for key in list(self.roster) + list(reported):
            lane, unit, measure = key
            if key in reported:
                roster[key] = reported[key]
            elif unit:
                # a unit is only ever known because the lane reported it once: dropping it is silence
                roster[key] = _remainder.Obligation(lane=lane, unit=unit, measure=measure,
                                                    why=f"stopped reporting {unit}")
            elif lane in heard:
                roster[key] = _remainder.Obligation(
                    lane=lane, disposition=_lane_disposition(
                        [o for k, o in reported.items() if k[0] == lane]))
            elif lane in active:
                roster[key] = _remainder.Obligation(lane=lane, why="reported nothing")
            else:
                roster[key] = _remainder.Obligation(lane=lane, disposition="not_applicable",
                                                    why="the lane did not run")
        self.roster, self.expected = roster, self.expected | heard
        return [roster[key] for key in sorted(roster)]


def decide(summary: dict, absorbed: "AbsorbResult", *, expected_lanes=(), idle_children: int = 0,
           children: int = 0, max_children: int = MAX_CHILDREN,
           previous_retriable: int | None = None, settlement: "Settlement | None" = None) -> Decision:
    """The stop rules, read from a child's manifest summary and what it added to the union.

    Order is fixed: child fault, then an obligation nobody disposed of (unknown), then what convergence
    MEANS — terminal work, or a fixed point — and only then the bounds on continuing. A fixed point
    requires every obligation disposed of as a known zero, with nothing terminal outstanding and nothing
    new learned; a campaign that converged on its last permitted child converged."""
    # a missing required tool is coverage we did not get, not machinery that broke: it rides the child's
    # gaps (`exit_contract.from_summary`), and stopping the campaign as a fault would report it as one
    faults = [f for f in summary.get("faults", [])
              if f.get("kind") in ("machinery", "phase_exception")]
    if faults:
        return Decision(stop="child_fault", detail="; ".join(
            f"{f.get('kind')}: {f.get('where')}" for f in faults[:4]))

    book = settlement if settlement is not None else Settlement(expected=expected_lanes)
    obligations = book.observe(summary)
    unmet = [o for o in obligations if o.disposition == "unknown"]
    if unmet:
        return Decision(stop="unknown", obligations=obligations,
                        detail="; ".join(f"{o.lane}: {o.why}" for o in unmet)[:400])

    # the lane's own entry names its disposition and carries no counts, so a lane's units are summed once
    retriable = sum(o.retriable for o in obligations)
    terminal: dict = {}
    for ob in obligations:
        # terminal work is counted whatever the model: the model answers "can another child advance
        # this?", never "does this work exist?"
        for cause, n in ob.terminal.items():
            terminal[cause] = terminal.get(cause, 0) + n

    # progress is either new material or a strict reduction in what is owed: a child that discovered no
    # identity but took half the remaining work forward is not idle
    reduced = previous_retriable is not None and retriable < previous_retriable
    progressed = bool(absorbed.progressed) or reduced
    decided = {"progressed": progressed, "retriable": retriable, "obligations": obligations,
               "terminal": terminal}
    if absorbed.unusable:
        return Decision(stop="unknown", **decided,
                        detail="; ".join(f"{k}: {v}" for k, v in sorted(absorbed.unusable.items()))[:400])
    if not retriable:                     # nothing a later child could take: this is what it means
        if terminal:
            return Decision(stop="terminal", **decided,
                            detail="; ".join(f"{c}: {n}" for c, n in sorted(terminal.items())))
        if not progressed:
            gapped = _unresolved_gaps(summary)
            if gapped:
                # the campaign has nowhere left to go, over coverage the last child never got: that is a
                # fixed point of the loop, and it is not a clean one
                return Decision(stop="fixed_point_with_gaps", **decided, detail="; ".join(gapped)[:400])
            return Decision(stop="fixed_point", **decided, detail="no retriable work and nothing new")
    if children >= max_children:
        return Decision(stop="max_runs", **decided, detail=f"{children} child run(s)")
    if not progressed and idle_children + 1 >= NO_PROGRESS_LIMIT and retriable:
        return Decision(stop="no_progress", **{**decided, "progressed": False},
                        detail=f"{idle_children + 1} child(ren) added nothing and reduced nothing while "
                               f"{retriable} unit(s) stayed owed")
    return Decision(**decided)            # keep going: owed work, or a child that still learned something


def _unreadable_child(child, index: int, states) -> str:
    """Why one loaded child cannot be believed, or `""`. State and record must agree: a `reserved` child
    may not name a run, a `manifested` one must carry the deltas and the roster the supervisor decided on,
    and an `abandoned` one must say why nobody could measure it."""
    if not isinstance(child, dict) or child.get("index") != index or type(child["index"]) is not int:
        return "is not a readable record"
    state = child.get("state")
    if state not in states:
        return f"has an unknown state {state!r}"
    run_id = child.get("run_id")
    if state == "reserved":
        if run_id is not None:
            return "is reserved but already names a run"
    elif state == "abandoned":
        # abandoned from `reserved` never launched, so it names no run; from `started` it names the one
        if run_id is not None and not valid_run_id(run_id):
            return "is abandoned with an unreadable run id"
        if not isinstance(child.get("reason"), str) or not child["reason"].strip():
            return "is abandoned without a reason"
    elif not isinstance(run_id, str) or not run_id.strip():
        return f"is {state} without a run id"
    elif not valid_run_id(run_id):
        # the id is joined to reach this child's evidence, so it may not leave the project
        return f"is {state} under a run id that is not one path segment"
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
        if not isinstance(child.get("obligations"), list):
            return "is manifested without its obligation roster"
        for record in child["obligations"]:
            try:
                _remainder.Obligation.from_record(record)
            except (ValueError, TypeError):
                return "is manifested with an unreadable obligation roster"
    # both are absent in a ledger written before a campaign charged its children; present means a value
    # someone wrote, and an explicit null is not one
    if "elapsed_s" in child:
        spent = child["elapsed_s"]
        if type(spent) not in (int, float) or spent < 0:
            return f"is {state} with an unreadable elapsed time"
    if "started_at" in child and not _aware_stamp(child["started_at"]):
        return f"is {state} with an unreadable start time"
    return ""


def _spend_field(elapsed_s) -> dict:
    """What a child cost the campaign, or nothing at all: an unmeasurable child records no spend, and a
    reader must be able to tell that from a child that cost nothing."""
    return {} if elapsed_s is None else {"elapsed_s": round(max(0.0, float(elapsed_s)), 1)}


def _readable_stop(stop) -> bool:
    """A stop is `{cause: non-empty str, detail: str, success: bool}` and, when the stop named terminal
    work, `terminal: {cause: count}`; or None while a campaign runs."""
    if stop is None:
        return True
    if not isinstance(stop, dict) or not set(stop) <= {"cause", "detail", "success", "terminal"}:
        return False
    if not {"cause", "detail", "success"} <= set(stop):
        return False
    if "terminal" in stop and not _readable_terminal(stop["terminal"]):
        return False
    return (isinstance(stop["cause"], str) and bool(stop["cause"].strip())
            and isinstance(stop["detail"], str) and type(stop["success"]) is bool)


def _readable_terminal(terminal) -> bool:
    """A terminal breakdown a reader can classify: declared causes, exact counts, and never empty — an
    absent one is how a stop says it named no terminal work."""
    if not isinstance(terminal, dict) or not terminal:
        return False
    return all(cause in _remainder.TERMINAL_CAUSES and type(n) is int and n >= 0
               for cause, n in terminal.items())


class Campaign:
    """One project's campaign ledger and its lease: every child is recorded before it launches, in one of
    `STATES` (`docs/design/SETTLE-DESIGN.md` §6). It creates no runs itself."""

    #: reserved: nothing launched · started: its run directory exists · manifested: measured and decided ·
    #: abandoned: nobody can measure it, and the campaign said so rather than counting it as anything
    STATES = ("reserved", "started", "manifested", "abandoned")
    #: the only transitions this ledger records; every other move is a defect, not an outcome.
    TRANSITIONS = {"reserved": {"started", "abandoned"}, "started": {"manifested", "abandoned"},
                   "manifested": set(), "abandoned": set()}

    def __init__(self, project_dir, campaign_id: str):
        self.project_dir = Path(project_dir)
        self.campaign_id = validate_campaign_id(campaign_id)
        self.dir = self.project_dir / "recon" / "campaigns" / campaign_id
        self.path = self.dir / "ledger.json"
        self.children: list = []
        self.stop: dict | None = None
        self.recoveries: list = []   # chronological, carried forward by every later publication
        self.status = "new"          # new | valid | unusable — absence may create, corruption may not
        self.reason = ""
        self._lock = None
        self._load()

    @property
    def trustworthy(self) -> bool:
        return self.status in ("new", "valid")

    def require(self) -> None:
        """Refuse to write over a ledger nobody can read: the next `reserve()` would republish child 1."""
        if not self.trustworthy:
            raise UnionUnusable(f"{self.path}: {self.status} — {self.reason}")

    def recover(self, reason: str) -> None:
        """Start recording again over an unusable ledger, deliberately and with the loss stated.

        Only from `unusable`, because recovery erases every child. The admission is appended to a durable
        history that every later publication carries forward."""
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

    # ── the project lock ───────────────────────────────────────────────────────────────────────────
    def acquire(self):
        """Take the campaign lock. Scoped to the project, not this campaign directory: two supervisors
        that minted different ids would otherwise take different locks."""
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
            # salvaged even when the rest is unreadable: the admission chain must outlive the ledger
            self.recoveries = [dict(r) for r in doc.get("recoveries", [])]
        if not isinstance(doc, dict) or not isinstance(kids, list):
            self.status, self.reason = "unusable", "ledger does not describe a campaign"
            return
        if not _valid_campaign_recoveries(doc.get("recoveries", [])):
            self.status, self.reason = "unusable", "recovery history is unreadable"
            return
        if doc.get("campaign_id") != self.campaign_id:
            # a ledger copied from another campaign would be rewritten under this id, with its own
            # children counted as ours
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
        """Adopt whatever the ledger on disk says now. The record objects are reused per index, so a
        caller still holding the child it reserved keeps a record this ledger recognises."""
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
        """Publish `records` and only then let this object believe them: the whole preparation and the
        write are inside the boundary, and any interruption re-reads the authoritative ledger."""
        stop = self.stop if stop is None else (None if stop is False else stop)
        recoveries = self.recoveries if recoveries is None else recoveries
        # the whole document, at the one boundary every writer passes through: no writer can publish what
        # `_load()` would refuse, including a live record a caller mutated by hand.
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
                # settling failed too: say so, and let the original failure be the one that propagates
                self.status = "unusable"
                self.reason = "publication failed and the ledger could not be re-read"
            raise
        if adopt is not None:
            adopt()
        self.children, self.stop, self.recoveries = list(records), stop, recoveries
        self.status, self.reason = "valid", ""

    # ── child states ──────────────────────────────────────────────────────────────────────────────
    def reserve(self) -> dict:
        """Record a child before anything is launched — a crash then leaves an interrupted child in the
        ledger instead of a run directory nobody knows about."""
        self.require()
        child = {"index": len(self.children) + 1, "state": "reserved", "run_id": None}
        self._commit([*self.children, child])
        return child

    def _advance(self, child: dict, to: str) -> None:
        """Refuse anything but a recorded transition, on a trustworthy ledger, for a record this ledger
        owns by identity."""
        self.require()
        index = child.get("index") if isinstance(child, dict) else None
        if (type(index) is not int or not (1 <= index <= len(self.children))
                or self.children[index - 1] is not child):
            raise ValueError("that child record does not belong to this campaign")
        state = child.get("state")
        if to not in self.TRANSITIONS.get(state, set()):
            raise ValueError(f"child {index}: {state} -> {to} is not a transition this ledger records")

    def _transition(self, child: dict, to: str, **fields) -> None:
        """Advance one child through a candidate: the live record is not touched until the candidate has
        been validated and published."""
        self._advance(child, to)
        index = child["index"]
        candidate = {**child, **fields, "state": to}
        records = list(self.children)     # `_commit` validates the whole snapshot, candidate included
        records[index - 1] = candidate
        # the caller keeps holding the record it reserved, so identity survives the swap
        self._commit(records, adopt=lambda: (child.update(candidate), records.__setitem__(index - 1, child)))

    def started(self, child: dict, run_id: str) -> None:
        self.require()                     # trust is checked before anything else
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("a started child must name its run")
        # when it started, so a child the campaign never sees finish can still be charged what it cost
        self._transition(child, "started", run_id=validate_run_id(run_id), started_at=store._utc())

    def manifested(self, child: dict, *, summary: dict, absorbed: "AbsorbResult",
                   decision: "Decision", elapsed_s: float | None = None) -> None:
        self._transition(child, "manifested", **_spend_field(elapsed_s),
                         verdict=summary.get("verdict"),
                         new_identities=absorbed.new, enriched=absorbed.enriched,
                         retriable=decision.retriable, progressed=decision.progressed,
                         provider_spend=summary.get("provider_spend", []),
                         faults=[f.get("kind") for f in summary.get("faults", [])],
                         # durable, so a resumed campaign still owes exactly what this child left owed
                         obligations=[o.as_record() for o in decision.obligations])

    def abandoned(self, child: dict, reason: str, *, elapsed_s: float | None = None) -> None:
        """Record a child nobody can measure. Its evidence stays in its own run and is never folded in as
        if it were complete, and the campaign carries that it happened — and what it cost."""
        self.require()
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("an abandoned child must state why")
        self._transition(child, "abandoned", reason=reason.strip(), **_spend_field(elapsed_s))

    def finish(self, decision: "Decision") -> None:
        self.require()
        stop = {"cause": decision.stop or "fixed_point", "detail": decision.detail,
                "success": decision.success}
        named = {c: n for c, n in decision.terminal.items() if n}
        if named:
            # the breakdown, not just the word: a reader classifies an entitlement bound and a machinery
            # terminal differently (`remainder.terminal_class`)
            stop["terminal"] = named
        self._commit(self.children, stop=stop)

    @property
    def interrupted(self) -> list:
        """Children the ledger recorded and never saw finish — an abandoned one has been accounted for."""
        return [c for c in self.children if c.get("state") not in ("manifested", "abandoned")]
