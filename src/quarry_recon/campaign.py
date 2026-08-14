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
import math
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import privfs, remainder as _remainder, revision as _revision, state as _state, store
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
MAX_CAMPAIGN_LEDGER_BYTES = 16 * 1024 * 1024
MAX_CAMPAIGN_UNION_BYTES = 4 * 1024 * 1024 * 1024


_CAMPAIGN_DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                       | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
_CAMPAIGN_FILE_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK
                        | getattr(os, "O_CLOEXEC", 0))


def _same_named_object(parent_fd: int, name: str, opened: os.stat_result) -> bool:
    """Whether an opened child is still the exact object held at its canonical parent/name."""
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino)


def _campaign_file_snapshot(observed: os.stat_result) -> tuple:
    """Every file fact whose movement would make one descriptor read cease to be a snapshot."""
    return (
        observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid,
        observed.st_nlink, observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns,
    )


def _read_campaign_document(
    path: Path,
    *,
    expected_name: str = "ledger.json",
    byte_limit: int = MAX_CAMPAIGN_LEDGER_BYTES,
    parse_json: bool = True,
):
    """One bounded snapshot below pinned, no-follow campaign-directory ancestry."""
    path = Path(path)
    if (path.name != expected_name or path.parent.parent.name != "campaigns"
            or path.parent.parent.parent.name != "recon"):
        raise ValueError("campaign document path does not name its managed repository location")
    if type(byte_limit) is not int or byte_limit <= 0:
        raise ValueError("campaign document byte bound is invalid")
    if not (getattr(os, "O_DIRECTORY", 0) and getattr(os, "O_NOFOLLOW", 0)
            and os.open in getattr(os, "supports_dir_fd", frozenset())
            and os.stat in getattr(os, "supports_dir_fd", frozenset())
            and os.stat in getattr(os, "supports_follow_symlinks", frozenset())):
        raise OSError("strict campaign-ledger descriptor traversal is unavailable")

    project = path.parents[3]
    descriptors: list[int] = []
    ancestry: list[tuple[int, int, str, os.stat_result]] = []
    try:
        project_fd = os.open(project, _CAMPAIGN_DIR_FLAGS)
        descriptors.append(project_fd)
        project_info = os.fstat(project_fd)
        try:
            project_named = project.lstat()
        except OSError as exc:
            raise OSError("campaign project authority disappeared") from exc
        if (not stat.S_ISDIR(project_info.st_mode) or stat.S_ISLNK(project_named.st_mode)
                or (project_named.st_dev, project_named.st_ino)
                != (project_info.st_dev, project_info.st_ino)):
            raise OSError("campaign project authority is unsafe")

        parent_fd = project_fd
        for component in ("recon", "campaigns", path.parent.name):
            child_fd = os.open(component, _CAMPAIGN_DIR_FLAGS, dir_fd=parent_fd)
            descriptors.append(child_fd)
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(opened.st_mode) or not _same_named_object(parent_fd, component, opened):
                raise OSError(f"campaign directory authority changed at {component!r}")
            ancestry.append((parent_fd, child_fd, component, opened))
            parent_fd = child_fd

        fd = os.open(path.name, _CAMPAIGN_FILE_FLAGS, dir_fd=parent_fd)
        descriptors.append(fd)
        info = os.fstat(fd)
        campaign_info = ancestry[-1][3]
        if (campaign_info.st_uid != os.geteuid()
                or stat.S_IMODE(campaign_info.st_mode) != privfs.DIR_MODE):
            raise ValueError("campaign directory is not one exact private authority")
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != privfs.FILE_MODE):
            raise ValueError("ledger is not one regular private artifact")
        before = _campaign_file_snapshot(info)
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, byte_limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > byte_limit:
                raise ValueError("campaign document exceeds its byte bound")
        raw = b"".join(chunks)
        if _campaign_file_snapshot(os.fstat(fd)) != before:
            raise ValueError("ledger changed while it was read")

        result = raw
        if parse_json:
            from . import run_manifest
            label = f"campaign {expected_name}"
            result = run_manifest._parse_json(raw, label)
            run_manifest._validate_json_value(result, label)

        if _campaign_file_snapshot(os.fstat(fd)) != before:
            raise ValueError("ledger changed while it was parsed")
        if not _same_named_object(parent_fd, path.name, info):
            raise OSError("campaign ledger name changed while it was read")
        for held_parent, held_fd, component, opened in ancestry:
            held_now = os.fstat(held_fd)
            if ((held_now.st_dev, held_now.st_ino, held_now.st_mode, held_now.st_uid)
                    != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid)):
                raise OSError(f"campaign directory changed at {component!r}")
            if not _same_named_object(held_parent, component, opened):
                raise OSError(f"campaign directory name changed at {component!r}")
        project_named = project.lstat()
        if ((project_named.st_dev, project_named.st_ino)
                != (project_info.st_dev, project_info.st_ino)):
            raise OSError("campaign project name changed while the ledger was read")
        return result
    finally:
        for owned in reversed(descriptors):
            try:
                os.close(owned)
            except OSError:
                pass


def _manifested_children(project_dir, campaign_id: str) -> int:
    """Count manifested children without constructing ``Campaign`` and recursing through union truth."""
    path = Path(project_dir) / "recon" / "campaigns" / campaign_id / "ledger.json"
    try:
        document = _read_campaign_document(path)
        _validate_ledger(document, campaign_id)
    except (OSError, ValueError, TypeError, KeyError, ContractError):
        return 0
    return sum(1 for child in document["children"] if child.get("state") == "manifested")


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
        settled = _manifested_children(project_dir, campaign_id)
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
            pointer = _read_campaign_document(self.path, expected_name="union.json")
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
            raw = _read_campaign_document(
                self.dir / name,
                expected_name=name,
                byte_limit=MAX_CAMPAIGN_UNION_BYTES,
                parse_json=False,
            )
        except (OSError, ValueError) as e:
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
#: current campaign documents are deliberately not read as their pre-v0.3.10 shape.  That shape did not
#: preserve coverage gaps, so accepting it as a clean terminal would recreate the very ambiguity this
#: contract closes.
LEDGER_SCHEMA_VERSION = "quarry.campaign-ledger.v1"
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
    gaps: list = field(default_factory=list)          # typed gaps this child introduced
    coverage: list = field(default_factory=list)      # explicit coverage proofs this child supplied
    resolved_gaps: list = field(default_factory=list) # earlier gaps those proofs explicitly discharged
    open_gaps: list = field(default_factory=list)     # complete unresolved history after this child

    @property
    def success(self) -> bool:
        """Only a fixed point is success; every other stop is an outcome the campaign must state."""
        return self.stop == "fixed_point"


#: verdicts a child may reach with its coverage intact; anything else the campaign reads as gapped.
_COVERED = ("complete", "complete_with_limits")

#: one normalized gap record persisted in both the child that observed it and the cumulative open set.
#: Nullable counters retain the distinction between zero and unmeasured.  Child ordinals make a repeated
#: gap auditable without using prose or timestamps as identity.
_GAP_RECORD_KEYS = {
    "source_id", "kind", "measure", "unit", "eligible", "tested", "omitted", "reason",
    "first_child", "last_child",
}
_COVERAGE_PROOF_KEYS = {
    "source_id", "measure", "eligible", "tested", "omitted", "valid", "unknown", "complete",
}


def _gap_key(record: dict) -> tuple:
    """The exact coverage identity a later proof must address.  Detail is deliberately not identity: a
    timeout explaining itself differently on child two is still the same outstanding coverage claim."""
    return (record["source_id"], record["measure"], record["unit"], record["kind"])


def _gap_sort(record: dict) -> tuple:
    source, measure, unit, kind = _gap_key(record)
    # `measure` and `unit` are optional.  Put null before strings explicitly so two legitimate claims for
    # the same source do not ask Python to order `None` against `str`.
    return (source, (measure is not None, measure or ""), (unit is not None, unit or ""), kind,
            record["first_child"], record["last_child"])


def _gap_key_sort(key: tuple) -> tuple:
    source, measure, unit, kind = key
    return (source, (measure is not None, measure or ""), (unit is not None, unit or ""), kind)


def _typed_gap(record: dict, child: int) -> dict:
    """Normalize one strict manifest gap into the campaign's closed Gap vocabulary."""
    kind = record.get("kind")
    if kind not in _state.GAP_KINDS:
        kind = "unknown"
    source_id = record.get("tool") or record.get("phase") or "run"
    if not isinstance(source_id, str) or not source_id.strip():
        source_id = "run"
    measure = record.get("measure") if isinstance(record.get("measure"), str) else None
    unit = record.get("unit") if isinstance(record.get("unit"), str) else None
    reason = record.get("why") if isinstance(record.get("why"), str) else None
    gap = _state.Gap(
        source_id=source_id,
        kind=kind,
        measure=measure,
        unit=unit,
        eligible=record.get("eligible") if type(record.get("eligible")) is int else None,
        tested=record.get("output_lines") if type(record.get("output_lines")) is int else None,
        omitted=record.get("omitted") if type(record.get("omitted")) is int else None,
        reason=reason,
    )
    return {
        "source_id": gap.source_id,
        "kind": gap.kind,
        "measure": gap.measure,
        "unit": gap.unit,
        "eligible": gap.eligible,
        "tested": gap.tested,
        "omitted": gap.omitted,
        "reason": gap.reason,
        "first_child": child,
        "last_child": child,
    }


def _gap_claims(summary: dict, child: int) -> list[dict]:
    claims = [_typed_gap(record, child) for record in summary.get("gaps") or ()
              if isinstance(record, dict)]
    if not claims and summary.get("verdict") not in _COVERED:
        # A gapped verdict with no named gap is itself an unresolved, typed unknown.  It can never be
        # cleared by a later child's silence because it is now part of the durable history.
        claims.append(_typed_gap({"phase": "run", "tool": "run", "kind": "unknown",
                                  "why": f"verdict {summary.get('verdict')!r} with no gap named"}, child))
    return sorted(claims, key=_gap_sort)


def _coverage_proofs(summary: dict) -> list[dict]:
    """Only positive, source-identified evidence may discharge an earlier gap.  The full rollup remains
    in the child manifest; this compact projection carries every fact used by the campaign fold."""
    proofs = []
    for record in summary.get("coverage") or ():
        if not isinstance(record, dict):
            continue
        source_id, measure = record.get("source_id"), record.get("measure")
        if not isinstance(source_id, str) or not source_id.strip() or not isinstance(measure, str):
            continue
        eligible, tested, omitted = (record.get(name) for name in ("eligible", "tested", "omitted"))
        if any(type(value) is not int or value < 0 for value in (eligible, tested, omitted)):
            continue
        valid = record.get("valid")
        unknown = record.get("unknown")
        if type(valid) is not bool or not isinstance(unknown, list):
            continue
        complete = valid and not unknown and omitted == 0 and tested == eligible
        proofs.append({"source_id": source_id, "measure": measure, "eligible": eligible,
                       "tested": tested, "omitted": omitted, "valid": valid,
                       "unknown": len(unknown), "complete": complete})
    return sorted(proofs, key=lambda p: (p["source_id"], p["measure"]))


def _readable_gap(record, *, child: int | None = None) -> bool:
    if not isinstance(record, dict) or set(record) != _GAP_RECORD_KEYS:
        return False
    if (not isinstance(record.get("source_id"), str) or not record["source_id"].strip()
            or record.get("kind") not in _state.GAP_KINDS):
        return False
    for name in ("measure", "unit", "reason"):
        if record.get(name) is not None and not isinstance(record[name], str):
            return False
    for name in ("eligible", "tested", "omitted"):
        if record.get(name) is not None and (type(record[name]) is not int or record[name] < 0):
            return False
    first, last = record.get("first_child"), record.get("last_child")
    if type(first) is not int or type(last) is not int or first <= 0 or last < first:
        return False
    if child is not None and (first != child or last != child):
        return False
    try:
        _state.Gap(source_id=record["source_id"], kind=record["kind"], measure=record["measure"],
                   unit=record["unit"], eligible=record["eligible"], tested=record["tested"],
                   omitted=record["omitted"], reason=record["reason"])
    except (ContractError, TypeError, ValueError):
        return False
    return True


def _readable_proof(record) -> bool:
    if not isinstance(record, dict) or set(record) != _COVERAGE_PROOF_KEYS:
        return False
    if (not isinstance(record.get("source_id"), str) or not record["source_id"].strip()
            or not isinstance(record.get("measure"), str)):
        return False
    for name in ("eligible", "tested", "omitted", "unknown"):
        if type(record.get(name)) is not int or record[name] < 0:
            return False
    if type(record.get("valid")) is not bool or type(record.get("complete")) is not bool:
        return False
    complete = (record["valid"] and record["unknown"] == 0 and record["omitted"] == 0
                and record["tested"] == record["eligible"])
    return record["complete"] == complete


def _proof_matches_gap(gap: dict, proofs: list[dict], obligations: list) -> bool:
    """A source-exact, measure-compatible positive proof is the only way an old gap closes.  An absent
    row and a `not_applicable` obligation are both silence, never evidence of completion."""
    for proof in proofs:
        if (proof["complete"] and proof["source_id"] == gap["source_id"]
                and (gap["measure"] is None or proof["measure"] == gap["measure"])):
            return True
    for obligation in obligations:
        if obligation.disposition in {"known_zero", "remainder", "terminal"} and (
                gap["source_id"] in {obligation.lane, obligation.unit}
                and (gap["measure"] is None or obligation.measure == gap["measure"])):
            return True
    return False


def _fold_gaps(open_before, claims, proofs, obligations, child: int):
    """Return `(resolved, open_after)`, deterministically.  Proofs run before this child's claims so a
    child that itself remains gapped cannot erase the same historical claim by also mentioning a source."""
    opened = {_gap_key(record): dict(record) for record in open_before}
    resolved = []
    for key in sorted(opened, key=_gap_key_sort):
        if _proof_matches_gap(opened[key], proofs, obligations):
            resolved.append(opened.pop(key))
    for claim in claims:
        key = _gap_key(claim)
        if key in opened:
            claim = {**claim, "first_child": opened[key]["first_child"], "last_child": child}
        opened[key] = claim
    return sorted(resolved, key=_gap_sort), sorted(opened.values(), key=_gap_sort)


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
        self.open_gaps: list[dict] = []

    def adopt(self, records, *, open_gaps=()) -> None:
        """Take a child's persisted roster as this settlement's own, so a resumed campaign still owes
        exactly what that child left owed.  The cumulative gap snapshot is adopted with it; restoring
        obligations alone would make every pre-restart gap disappear."""
        for record in records:
            ob = _remainder.Obligation.from_record(record)
            self.roster[ob.key] = ob
            if ob.disposition != "not_applicable":
                self.expected.add(ob.lane)
        if not isinstance(open_gaps, list) or not all(_readable_gap(record) for record in open_gaps):
            raise ValueError("a settlement can adopt only a typed open-gap snapshot")
        self.open_gaps = [dict(record) for record in open_gaps]

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
        # Lane labels are non-counting rollups.  Recompute them from the complete post-observation
        # roster, including concrete units retained as unknown after silence; deriving the label only
        # from rows reported by this child could falsely call a lane settled while an older unit remains.
        for key, label in list(roster.items()):
            lane, unit, measure = key
            if unit or measure:
                continue
            concrete = [row for row_key, row in roster.items()
                        if row_key[0] == lane and row_key != key]
            if concrete:
                roster[key] = _remainder.Obligation(
                    lane=lane,
                    disposition=_lane_disposition(concrete),
                    why=label.why,
                )
        self.roster, self.expected = roster, self.expected | heard
        return [roster[key] for key in sorted(roster)]

    def observe_gaps(self, summary: dict, obligations: list, *, child: int):
        """Fold one child's explicit positive proofs and typed gaps into the complete history."""
        claims = _gap_claims(summary, child)
        proofs = _coverage_proofs(summary)
        resolved, opened = _fold_gaps(self.open_gaps, claims, proofs, obligations, child)
        self.open_gaps = [dict(record) for record in opened]
        return claims, proofs, resolved, opened


def decide(summary: dict, absorbed: "AbsorbResult", *, expected_lanes=(), idle_children: int = 0,
           children: int = 0, max_children: int = MAX_CHILDREN,
           previous_retriable: int | None = None, settlement: "Settlement | None" = None) -> Decision:
    """The stop rules, read from a child's manifest summary and what it added to the union.

    Order is fixed: child fault, then an obligation nobody disposed of (unknown), then what convergence
    MEANS — terminal work, or a fixed point — and only then the bounds on continuing. A fixed point
    requires every obligation disposed of as a known zero, with nothing terminal outstanding and nothing
    new learned; a campaign that converged on its last permitted child converged."""
    book = settlement if settlement is not None else Settlement(expected=expected_lanes)
    obligations = book.observe(summary)
    child_index = children if type(children) is int and children > 0 else 1
    gaps, proofs, resolved, open_gaps = book.observe_gaps(summary, obligations, child=child_index)
    history = {"obligations": obligations, "gaps": gaps, "coverage": proofs,
               "resolved_gaps": resolved, "open_gaps": open_gaps}

    # These are historical facts even when the stop rule fires early.  Persisting defaults on fault or
    # unknown paths would make the child's decision contradict the obligation roster on reload.
    retriable = sum(o.retriable for o in obligations)
    terminal: dict = {}
    for ob in obligations:
        for cause, n in ob.terminal.items():
            terminal[cause] = terminal.get(cause, 0) + n
    reduced = previous_retriable is not None and retriable < previous_retriable
    progressed = bool(absorbed.progressed) or reduced
    decided = {"progressed": progressed, "retriable": retriable, "terminal": terminal, **history}

    # a missing required tool is coverage we did not get, not machinery that broke: it rides the child's
    # gaps (`exit_contract.from_summary`), and stopping the campaign as a fault would report it as one
    faults = [f for f in summary.get("faults", [])
              if f.get("kind") in ("machinery", "phase_exception", "publication")]
    if faults:
        return Decision(stop="child_fault", **decided, detail="; ".join(
            f"{f.get('kind')}: {f.get('where')}" for f in faults[:4]))

    unmet = [o for o in obligations if o.disposition == "unknown"]
    if unmet:
        return Decision(stop="unknown", **decided,
                        detail="; ".join(f"{o.lane}: {o.why}" for o in unmet)[:400])
    if absorbed.unusable:
        return Decision(stop="unknown", **decided,
                        detail="; ".join(f"{k}: {v}" for k, v in sorted(absorbed.unusable.items()))[:400])
    if not retriable:                     # nothing a later child could take: this is what it means
        if terminal:
            return Decision(stop="terminal", **decided,
                            detail="; ".join(f"{c}: {n}" for c, n in sorted(terminal.items())))
        if not progressed:
            if open_gaps:
                # the campaign has nowhere left to go, over coverage the last child never got: that is a
                # fixed point of the loop, and it is not a clean one
                detail = "; ".join(
                    f"{gap['source_id']}: {gap['kind']}"
                    + (f" ({gap['reason']})" if gap.get("reason") else "")
                    for gap in open_gaps)
                return Decision(stop="fixed_point_with_gaps", **decided, detail=detail[:400])
            return Decision(stop="fixed_point", **decided, detail="no retriable work and nothing new")
    if children >= max_children:
        return Decision(stop="max_runs", **decided, detail=f"{children} child run(s)")
    if not progressed and idle_children + 1 >= NO_PROGRESS_LIMIT and retriable:
        return Decision(stop="no_progress", **{**decided, "progressed": False},
                        detail=f"{idle_children + 1} child(ren) added nothing and reduced nothing while "
                               f"{retriable} unit(s) stayed owed")
    return Decision(**decided)            # keep going: owed work, or a child that still learned something


_CHILD_BASE_KEYS = {"index", "state", "run_id"}
_CHILD_TIME_KEYS = {"started_at", "elapsed_s"}
_MANIFESTED_KEYS = {
    "verdict", "new_identities", "enriched", "unusable", "retriable", "progressed",
    "provider_spend", "faults", "obligations", "terminal", "gaps", "coverage", "resolved_gaps",
    "open_gaps", "decision",
}
_DECISION_KEYS = {"cause", "detail", "success"}
_STOP_KEYS = {"cause", "detail", "success", "clean", "recovered"}


@dataclass(frozen=True)
class CampaignTruth:
    """The semantic fold every campaign reader consumes, never a second interpretation of ledger prose."""
    open_gaps: tuple = ()
    abandoned: int = 0
    recovered: bool = False
    clean: bool = False


def _read_obligations(records) -> list[_remainder.Obligation]:
    if not isinstance(records, list):
        raise ValueError("has no readable obligation roster")
    obligations = []
    for record in records:
        obligations.append(_remainder.Obligation.from_record(record))
    keys = [ob.key for ob in obligations]
    if len(keys) != len(set(keys)) or keys != sorted(keys):
        raise ValueError("has a duplicate or non-canonical obligation roster")
    by_lane: dict[str, list[_remainder.Obligation]] = {}
    for obligation in obligations:
        by_lane.setdefault(obligation.lane, []).append(obligation)
    for lane, lane_rows in by_lane.items():
        labels = [row for row in lane_rows if not row.unit and not row.measure]
        if len(labels) != 1:
            raise ValueError(f"{lane}: needs exactly one lane-level obligation")
        label = labels[0]
        if label.retriable or any(label.terminal.values()):
            raise ValueError(f"{lane}: lane-level obligation duplicates concrete counts")
        units = [row for row in lane_rows if row is not label]
        expected = _lane_disposition(units) if units else None
        if ((expected is None and label.disposition in {"remainder", "terminal"})
                or (expected is not None and label.disposition != expected)):
            raise ValueError(
                f"{lane}: lane-level disposition contradicts its concrete obligations",
            )
    return obligations


def _terminal_from(obligations) -> dict:
    terminal: dict = {}
    for obligation in obligations:
        for cause, count in obligation.terminal.items():
            if count:
                terminal[cause] = terminal.get(cause, 0) + count
    return terminal


def _readable_terminal(terminal) -> bool:
    """A terminal breakdown names real work: declared causes and exact positive counts."""
    return (isinstance(terminal, dict) and bool(terminal)
            and all(cause in _remainder.TERMINAL_CAUSES and type(n) is int and n > 0
                    for cause, n in terminal.items()))


def _expected_child_cause(child: dict, obligations, *, idle: int) -> set:
    blocking = {"machinery", "phase_exception", "publication"}
    if any(kind in blocking for kind in child["faults"]):
        return {"child_fault"}
    if child["unusable"] or any(ob.disposition == "unknown" for ob in obligations):
        return {"unknown"}
    if child["retriable"] == 0:
        if child["terminal"]:
            return {"terminal"}
        if child["progressed"]:
            return {None, "max_runs"}
        return {"fixed_point_with_gaps" if child["open_gaps"] else "fixed_point"}
    allowed = {None, "max_runs"}
    if not child["progressed"] and idle >= NO_PROGRESS_LIMIT:
        allowed.add("no_progress")
    return allowed


def _unreadable_child(child, index: int, states, *, open_before=(), previous_retriable=None,
                      idle: int = 0):
    """Return `(why, obligations, open_after, idle_after)` for one exact child record."""
    if not isinstance(child, dict) or child.get("index") != index or type(child.get("index")) is not int:
        return "is not a readable record", [], list(open_before), idle
    state = child.get("state")
    if state not in states:
        return f"has an unknown state {state!r}", [], list(open_before), idle
    allowed = set(_CHILD_BASE_KEYS)
    if state == "started":
        allowed |= {"started_at"}
    elif state == "abandoned":
        allowed |= {"reason", *_CHILD_TIME_KEYS}
    elif state == "manifested":
        allowed |= _CHILD_TIME_KEYS | _MANIFESTED_KEYS
    if set(child) - allowed or not _CHILD_BASE_KEYS <= set(child):
        return f"is {state} with unknown or missing members", [], list(open_before), idle

    run_id = child.get("run_id")
    if state == "reserved":
        if run_id is not None:
            return "is reserved but already names a run", [], list(open_before), idle
    elif state == "abandoned":
        if run_id is not None and not valid_run_id(run_id):
            return "is abandoned with an unreadable run id", [], list(open_before), idle
        if not isinstance(child.get("reason"), str) or not child["reason"].strip():
            return "is abandoned without a reason", [], list(open_before), idle
        if run_id is None and "started_at" in child:
            return "was never launched but carries a start time", [], list(open_before), idle
    elif not isinstance(run_id, str) or not run_id.strip():
        return f"is {state} without a run id", [], list(open_before), idle
    elif not valid_run_id(run_id):
        return (f"is {state} under a run id that is not one path segment", [],
                list(open_before), idle)

    if "elapsed_s" in child:
        spent = child["elapsed_s"]
        if type(spent) not in (int, float) or not math.isfinite(spent) or spent < 0:
            return f"is {state} with an unreadable elapsed time", [], list(open_before), idle
    if "started_at" in child and not _aware_stamp(child["started_at"]):
        return f"is {state} with an unreadable start time", [], list(open_before), idle
    if state != "manifested":
        return "", [], list(open_before), idle

    for name in ("new_identities", "enriched", "retriable"):
        if type(child.get(name)) is not int or child[name] < 0:
            return f"is manifested without an exact {name}", [], list(open_before), idle
    if type(child.get("progressed")) is not bool:
        return "is manifested without a progress verdict", [], list(open_before), idle
    if child.get("verdict") not in {"complete", "complete_with_limits", "complete_with_gaps"}:
        return "is manifested with an unreadable verdict", [], list(open_before), idle
    spend = child.get("provider_spend")
    if not isinstance(spend, list):
        return "is manifested without its provider_spend", [], list(open_before), idle
    from . import run_manifest
    try:
        for offset, record in enumerate(spend):
            run_manifest._validate_outcome(record, f"provider_spend[{offset}]", spend=True)
    except ValueError:
        return "has an unreadable provider_spend", [], list(open_before), idle
    if (not isinstance(child.get("faults"), list)
            or any(kind not in _state.FAULT_KINDS for kind in child["faults"])):
        return "is manifested without a typed fault roster", [], list(open_before), idle
    unusable = child.get("unusable")
    if (not isinstance(unusable, dict)
            or any(not isinstance(k, str) or not k or not isinstance(v, str) or not v
                   for k, v in unusable.items())):
        return "is manifested with unreadable absorption failures", [], list(open_before), idle
    try:
        obligations = _read_obligations(child.get("obligations"))
    except (ValueError, TypeError) as exc:
        return f"is manifested and {exc}", [], list(open_before), idle
    retriable = sum(ob.retriable for ob in obligations)
    if child["retriable"] != retriable:
        return "has a retriable total that contradicts its obligations", [], list(open_before), idle
    terminal = _terminal_from(obligations)
    if child.get("terminal") != terminal:
        return "has a terminal total that contradicts its obligations", [], list(open_before), idle

    claims, proofs = child.get("gaps"), child.get("coverage")
    resolved, opened = child.get("resolved_gaps"), child.get("open_gaps")
    if not isinstance(claims, list) or not all(_readable_gap(record, child=index) for record in claims):
        return "has an unreadable per-child gap roster", [], list(open_before), idle
    if claims != sorted(claims, key=_gap_sort) or len({_gap_key(g) for g in claims}) != len(claims):
        return "has a duplicate or non-canonical per-child gap roster", [], list(open_before), idle
    if not isinstance(proofs, list) or not all(_readable_proof(record) for record in proofs):
        return "has unreadable coverage proofs", [], list(open_before), idle
    proof_keys = [(proof["source_id"], proof["measure"]) for proof in proofs]
    if (proofs != sorted(proofs, key=lambda p: (p["source_id"], p["measure"]))
            or len(proof_keys) != len(set(proof_keys))):
        return "has duplicate or non-canonical coverage proofs", [], list(open_before), idle
    if not isinstance(resolved, list) or not all(_readable_gap(record) for record in resolved):
        return "has an unreadable resolved-gap roster", [], list(open_before), idle
    if not isinstance(opened, list) or not all(_readable_gap(record) for record in opened):
        return "has an unreadable open-gap roster", [], list(open_before), idle
    expected_resolved, expected_opened = _fold_gaps(open_before, claims, proofs, obligations, index)
    if resolved != expected_resolved:
        return "claims a gap resolution with no matching positive evidence", [], list(open_before), idle
    if opened != expected_opened:
        return "has an open-gap snapshot that contradicts its history", [], list(open_before), idle
    if bool(claims) != (child["verdict"] == "complete_with_gaps"):
        return "has a verdict that contradicts its per-child gaps", [], list(open_before), idle

    reduced = previous_retriable is not None and child["retriable"] < previous_retriable
    progressed = (not unusable and bool(child["new_identities"] or child["enriched"])) or reduced
    if child["progressed"] != progressed:
        return "has a progress verdict that contradicts its deltas", [], list(open_before), idle
    decision = child.get("decision")
    if not isinstance(decision, dict) or set(decision) != _DECISION_KEYS:
        return "has no exact decision record", [], list(open_before), idle
    cause = decision.get("cause")
    if cause is not None and cause not in STOPS:
        return "has an unknown decision cause", [], list(open_before), idle
    if not isinstance(decision.get("detail"), str) or type(decision.get("success")) is not bool:
        return "has an unreadable decision record", [], list(open_before), idle
    if decision["success"] != (cause == "fixed_point"):
        return "has a decision success that contradicts its cause", [], list(open_before), idle
    idle_after = 0 if progressed else idle + 1
    if cause not in _expected_child_cause(child, obligations, idle=idle_after):
        return "has a decision cause that contradicts its evidence", [], list(open_before), idle
    return "", obligations, opened, idle_after


def _spend_field(elapsed_s) -> dict:
    """What a child cost the campaign, or nothing at all: an unmeasurable child records no spend, and a
    reader must be able to tell that from a child that cost nothing."""
    return {} if elapsed_s is None else {"elapsed_s": round(max(0.0, float(elapsed_s)), 1)}


def _validate_ledger(document, campaign_id: str) -> CampaignTruth:
    """Validate and semantically replay one complete campaign document."""
    top_keys = {"schema_version", "campaign_id", "children", "stop", "recoveries", "open_gaps"}
    if not isinstance(document, dict) or set(document) != top_keys:
        raise ValueError("ledger does not carry the exact campaign schema")
    if document["schema_version"] != LEDGER_SCHEMA_VERSION:
        raise ValueError("ledger schema version is unknown")
    if document["campaign_id"] != campaign_id:
        raise ValueError(f"ledger belongs to campaign {document['campaign_id']!r}")
    recoveries = document["recoveries"]
    if not _valid_campaign_recoveries(recoveries):
        raise ValueError("recovery history is unreadable")
    children = document["children"]
    if not isinstance(children, list):
        raise ValueError("ledger does not describe a child history")

    open_gaps: list[dict] = []
    previous_retriable = None
    idle = 0
    abandoned = 0
    manifested = []
    interrupted = []
    stopped_child = None
    required_obligation_keys = set(_remainder.roster())
    for index, child in enumerate(children, start=1):
        bad, obligations, opened, idle_after = _unreadable_child(
            child, index, Campaign.STATES, open_before=open_gaps,
            previous_retriable=previous_retriable, idle=idle,
        )
        if bad:
            raise ValueError(f"child {index} {bad}")
        state = child["state"]
        if state in {"reserved", "started"}:
            interrupted.append(index)
        if interrupted and index != interrupted[0]:
            raise ValueError("an interrupted child is not the final child")
        if state == "abandoned":
            abandoned += 1
        elif state == "manifested":
            obligation_keys = {obligation.key for obligation in obligations}
            missing = required_obligation_keys - obligation_keys
            if missing:
                lane, unit, measure = sorted(missing)[0]
                identity = "/".join(part for part in (lane, unit, measure) if part) or lane
                raise ValueError(f"child {index} omits required obligation {identity!r}")
            # Once a lane has named a concrete unit, silence in a later child is an unknown disposition,
            # never permission to erase that unit from the campaign's history.
            required_obligation_keys.update(obligation_keys)
            open_gaps = [dict(record) for record in opened]
            previous_retriable = child["retriable"]
            idle = idle_after
            manifested.append(child)
            if child["decision"]["cause"] is not None:
                if stopped_child is not None:
                    raise ValueError("more than one child claims to stop the campaign")
                stopped_child = child
        if stopped_child is not None and child is not stopped_child:
            raise ValueError("a child appears after a terminal child decision")

    recorded_open = document["open_gaps"]
    if (not isinstance(recorded_open, list)
            or not all(_readable_gap(record) for record in recorded_open)
            or recorded_open != open_gaps):
        raise ValueError("ledger open gaps do not reconcile with the child history")

    stop = document["stop"]
    if stop is None:
        # Manifestation and the campaign stop are two publications.  A killed supervisor may therefore
        # leave the final child's decision durable before `finish()` records the matching top-level stop;
        # resume completes that exact decision instead of launching another child.
        return CampaignTruth(open_gaps=tuple(dict(g) for g in open_gaps), abandoned=abandoned,
                             recovered=bool(recoveries), clean=False)
    if interrupted:
        raise ValueError("a stopped campaign still has an interrupted child")
    if (not isinstance(stop, dict) or not _STOP_KEYS <= set(stop)
            or set(stop) - _STOP_KEYS - {"terminal"}):
        raise ValueError("stop record has unknown or missing members")
    cause = stop.get("cause")
    if (cause not in STOPS or not isinstance(stop.get("detail"), str)
            or type(stop.get("success")) is not bool or type(stop.get("clean")) is not bool
            or type(stop.get("recovered")) is not bool):
        raise ValueError("stop record is unreadable")
    if stop["success"] != (cause == "fixed_point"):
        raise ValueError("stop success contradicts its cause")
    if bool(recoveries) and not stop["recovered"]:
        raise ValueError("stop hides the ledger's recovery history")
    if cause == "terminal":
        if "terminal" not in stop or not _readable_terminal(stop["terminal"]):
            raise ValueError("terminal stop has no readable terminal breakdown")
    elif "terminal" in stop:
        raise ValueError("a non-terminal stop carries a terminal breakdown")

    child_causes = {"fixed_point", "fixed_point_with_gaps", "terminal", "child_fault", "no_progress"}
    if cause in child_causes:
        if stopped_child is None or stopped_child["decision"] != {
                "cause": cause, "detail": stop["detail"], "success": stop["success"]}:
            raise ValueError("stop does not reconcile with the terminal child decision")
    elif stopped_child is not None:
        # `unknown` and `max_runs` may be either child decisions or campaign-boundary decisions.  When a
        # child already made one, a different top-level story may not overwrite it.
        child_decision = stopped_child["decision"]
        if child_decision != {"cause": cause, "detail": stop["detail"],
                              "success": stop["success"]}:
            raise ValueError("stop contradicts the terminal child decision")
    if cause == "terminal" and stop["terminal"] != stopped_child["terminal"]:
        raise ValueError("terminal stop contradicts the child obligation totals")

    clean = (stop["success"] and not stop["recovered"] and not abandoned and not open_gaps)
    if stop["clean"] != clean:
        raise ValueError("stop clean verdict contradicts the complete campaign history")
    return CampaignTruth(open_gaps=tuple(dict(g) for g in open_gaps), abandoned=abandoned,
                         recovered=stop["recovered"], clean=clean)


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
        self.open_gaps: list = []
        self.recoveries: list = []   # chronological, carried forward by every later publication
        self.truth = CampaignTruth()
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
        self._commit([], stop=False, recoveries=history, open_gaps=[])

    # ── the project lock ───────────────────────────────────────────────────────────────────────────
    def acquire(self):
        """Take the campaign lock. Scoped to the project, not this campaign directory: two supervisors
        that minted different ids would otherwise take different locks."""
        from . import budget
        self._lock = budget.state_lock(self.project_dir / "recon" / "campaigns" / ".campaign.lock")
        return self._lock

    def _load(self) -> None:
        try:
            doc = _read_campaign_document(self.path)
        except FileNotFoundError:
            self.status, self.reason = "new", "no ledger yet"
            return
        except OSError as e:
            self.status, self.reason = "unusable", f"{type(e).__name__}: {e}"
            return
        except (ValueError, TypeError, ContractError) as e:
            self.status, self.reason = "unusable", f"ledger is not strict JSON ({e})"
            return
        if isinstance(doc, dict) and _valid_campaign_recoveries(doc.get("recoveries", [])):
            # salvaged even when the rest is unreadable: the admission chain must outlive the ledger
            self.recoveries = [dict(r) for r in doc.get("recoveries", [])]
        try:
            truth = _validate_ledger(doc, self.campaign_id)
            self._reconcile_union_recovery(doc)
        except (ValueError, TypeError, KeyError, ContractError, UnionUnusable) as exc:
            self.status, self.reason = "unusable", str(exc) or "ledger semantic validation failed"
            return
        self.children = list(doc["children"])
        self.stop = doc["stop"]
        self.open_gaps = [dict(record) for record in doc["open_gaps"]]
        self.recoveries = [dict(record) for record in doc["recoveries"]]
        self.truth = truth
        self.status, self.reason = "valid", ""

    def _union_recovered(self) -> bool | None:
        """The union's durable recovery debt, or ``None`` before a union pointer exists."""
        union_path = self.dir / "union.json"
        if not os.path.lexists(union_path):
            return None
        union = Union(union_path, create=False)
        union.require()
        return union.was_recovered

    def _reconcile_union_recovery(self, document: dict) -> None:
        """Refuse a terminal whose recovery/cleanliness claim contradicts its published union."""
        manifested = any(child.get("state") == "manifested"
                         for child in document.get("children", ()))
        union_recovered = self._union_recovered()
        if union_recovered is None:
            if manifested:
                raise ValueError("campaign union is unusable: the union is gone and the ledger records "
                                 "manifested child run(s)")
            return
        stop = document.get("stop")
        if stop is None:
            return
        expected = bool(document.get("recoveries")) or union_recovered
        if stop.get("recovered") is not expected:
            raise ValueError("stop recovery verdict contradicts the campaign union history")

    def _settle(self) -> None:
        """Adopt whatever the ledger on disk says now. The record objects are reused per index, so a
        caller still holding the child it reserved keeps a record this ledger recognises."""
        previous = self.children
        self.children, self.stop, self.open_gaps, self.recoveries = [], None, [], []
        self.truth = CampaignTruth()
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

    def _refuse_unpublishable(self, records, stop, recoveries, open_gaps) -> CampaignTruth:
        """Exactly the loader's own rules, applied to the candidate document before it can reach disk."""
        document = {"schema_version": LEDGER_SCHEMA_VERSION, "campaign_id": self.campaign_id,
                    "children": records, "stop": stop, "recoveries": recoveries,
                    "open_gaps": open_gaps}
        truth = _validate_ledger(document, self.campaign_id)
        self._reconcile_union_recovery(document)
        from . import run_manifest
        run_manifest._validate_json_value(document, "campaign ledger")
        return truth

    def _commit(self, records: list, *, stop=None, recoveries=None, open_gaps=None, adopt=None) -> None:
        """Publish `records` and only then let this object believe them: the whole preparation and the
        write are inside the boundary, and any interruption re-reads the authoritative ledger."""
        stop = self.stop if stop is None else (None if stop is False else stop)
        recoveries = self.recoveries if recoveries is None else recoveries
        open_gaps = self.open_gaps if open_gaps is None else open_gaps
        # the whole document, at the one boundary every writer passes through: no writer can publish what
        # `_load()` would refuse, including a live record a caller mutated by hand.
        truth = self._refuse_unpublishable(records, stop, recoveries, open_gaps)
        doc = {"schema_version": LEDGER_SCHEMA_VERSION, "campaign_id": self.campaign_id,
               "children": records, "stop": stop, "recoveries": recoveries,
               "open_gaps": open_gaps}
        body = json.dumps(doc, indent=2, allow_nan=False)
        if len(body.encode("utf-8")) > MAX_CAMPAIGN_LEDGER_BYTES:
            raise ValueError("a campaign ledger exceeds its byte bound")
        try:
            # The writer traverses the same no-follow private ancestry as the reader.  A campaign
            # directory substituted with a symlink is never a route for an authoritative publication.
            privfs.private_dir(self.dir)
            store._atomic_write(self.path, body)
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
        self.children, self.stop = list(records), stop
        self.open_gaps = [dict(record) for record in open_gaps]
        self.recoveries, self.truth = recoveries, truth
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

    def _transition(self, child: dict, to: str, *, ledger_open_gaps=None, **fields) -> None:
        """Advance one child through a candidate: the live record is not touched until the candidate has
        been validated and published."""
        self._advance(child, to)
        index = child["index"]
        candidate = {**child, **fields, "state": to}
        records = list(self.children)     # `_commit` validates the whole snapshot, candidate included
        records[index - 1] = candidate
        # the caller keeps holding the record it reserved, so identity survives the swap
        self._commit(records, open_gaps=ledger_open_gaps,
                     adopt=lambda: (child.update(candidate), records.__setitem__(index - 1, child)))

    def started(self, child: dict, run_id: str) -> None:
        self.require()                     # trust is checked before anything else
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("a started child must name its run")
        # when it started, so a child the campaign never sees finish can still be charged what it cost
        self._transition(child, "started", run_id=validate_run_id(run_id), started_at=store._utc())

    def manifested(self, child: dict, *, summary: dict, absorbed: "AbsorbResult",
                   decision: "Decision", elapsed_s: float | None = None) -> None:
        named_terminal = {cause: count for cause, count in decision.terminal.items() if count}
        self._transition(child, "manifested", ledger_open_gaps=decision.open_gaps,
                         **_spend_field(elapsed_s),
                         verdict=summary.get("verdict"),
                         new_identities=absorbed.new, enriched=absorbed.enriched,
                         unusable=dict(absorbed.unusable),
                         retriable=decision.retriable, progressed=decision.progressed,
                         provider_spend=summary.get("provider_spend", []),
                         faults=[f.get("kind") for f in summary.get("faults", [])],
                         # durable, so a resumed campaign still owes exactly what this child left owed
                         obligations=[o.as_record() for o in decision.obligations],
                         terminal=named_terminal,
                         gaps=[dict(record) for record in decision.gaps],
                         coverage=[dict(record) for record in decision.coverage],
                         resolved_gaps=[dict(record) for record in decision.resolved_gaps],
                         open_gaps=[dict(record) for record in decision.open_gaps],
                         decision={"cause": decision.stop, "detail": decision.detail,
                                   "success": decision.success})

    def abandoned(self, child: dict, reason: str, *, elapsed_s: float | None = None) -> None:
        """Record a child nobody can measure. Its evidence stays in its own run and is never folded in as
        if it were complete, and the campaign carries that it happened — and what it cost."""
        self.require()
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("an abandoned child must state why")
        self._transition(child, "abandoned", reason=reason.strip(), **_spend_field(elapsed_s))

    def finish(self, decision: "Decision", *, recovered: bool | None = None) -> None:
        self.require()
        if recovered is None:
            recovered = bool(getattr(self, "_finish_recovered", False))
        union_recovered = self._union_recovered()
        recovered = bool(recovered or self.recoveries or union_recovered)
        abandoned = any(child.get("state") == "abandoned" for child in self.children)
        clean = bool(decision.success and not recovered and not abandoned and not self.open_gaps)
        stop = {"cause": decision.stop or "fixed_point", "detail": decision.detail,
                "success": decision.success, "clean": clean, "recovered": recovered}
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
