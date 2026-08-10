"""Asset store + run manifest — structured JSONL is the source of truth (design §5).

Layout (per-project; project dir derived from the target.yaml location):
    <project>/recon/<run_id>/manifest.json
    <project>/recon/<run_id>/raw/<phase>/<tool>/...
    <project>/recon/<run_id>/normalized/<entity>.jsonl
    <project>/recon/<run_id>/exports/
    <project>/recon/<run_id>/reports/
    <project>/recon/state/current -> latest run (symlink)
    <project>/recon/state/history/<run_id>.json

Every normalized entity keeps provenance back to the raw evidence that produced it.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from pathlib import Path

# priority thresholds, never a gate: any cap/timeout with omitted>0 is already a gap. These only label it
# `major` (omitted >= 10% or >= 100 absolute, boundaries inclusive) vs `minor`, for operator triage.
COVERAGE_GAP_FRACTION = 0.10
COVERAGE_GAP_ABSOLUTE = 100


def _coverage_gates(frac: float, omitted: int) -> bool:
    """Priority label for a coverage gap: True == `major`, False == `minor`. Never decides gating."""
    return frac >= COVERAGE_GAP_FRACTION or omitted >= COVERAGE_GAP_ABSOLUTE


ENTITY_KEYS = {
    "subdomain": "host",
    "resolved": "host",
    "dns_record": "id",
    "live": "url",
    "url": "url",
    "js_url": "url",
    "endpoint": "value",
    "parameter": "value",
    "secret": "id",
    "ip": "ip",
    "certificate": "id",
    "port": "id",
    "finding": "id",
    "screenshot": "url",
    "tech": "id",
    "review": "id",
    # acquisition-ownership transitions, in their own log so a bad row damages only these
    "ownership_transition": "id",
    "wildcard_zone": "value",   # cert-derived *.X.apex brute-zones (persisted vertical -> enrich)
    "web_port": "id",           # open web port per host:ip (naabu SYN prefilter) — host->ip->port edge
    "gadget_candidate": "id",   # chain material (`gadgets.py`): never promoted to `finding`, and
                                # impact_state is always `none_proven`
    "path_observation": "id",   # path-like strings an ast-analyzer artifact contained, with provenance,
                                # shape tags and incumbent corroboration; evidence, never an endpoint
    "sink_observation": "id",   # DOM sources/sinks an ast artifact contained (postMessage, innerHTML,
                                # eval, location, storage, cookie…); evidence, never a proven flow
    "oob_interaction": "id",    # imported out-of-band callbacks (interactsh), raw in raw/oob/ and
                                # uncorrelated by default until Quarry owns the token namespace
}

# ── identity contract — canonical dedup key per entity type ───────────────────────────────────────────
# only case-insensitive components are lowered (DNS names, URL scheme+host); dedup stays stable
_HOST_KEYED = {"subdomain", "resolved"}                     # key = DNS name (case-insensitive)
_URL_KEYED = {"live", "url", "js_url", "screenshot"}        # key = URL (scheme+host insensitive, path not)
_IP_KEYED = {"ip"}                                          # key = IP literal (normalize; case-insensitive)
# every other entity is id/value-keyed, so path/param/fingerprint/composite-id case is preserved


def _canon_host(h: str) -> str:
    """DNS-name canonicalization: lower, strip trailing dot, IDNA2008/UTS-46 non-transitional (so `faß.de`
    and `xn--fa-hia.de` share one key). A host IDNA can't encode keeps the lowered/dot-stripped form.
    """
    h = h.strip().lower().rstrip(".")
    if not h:
        return h
    from . import normalize as _n
    return _n.idna_ascii(h) or h                 # shared policy; the fallback is this site's choice


def _canon_url(u: str) -> str:
    """Canonicalize a URL's scheme + hostname only (lower + IDNA + trailing-dot strip); path, query,
    fragment and userinfo are preserved exactly, so `/API` != `/api` and `Admin:SeCrEt@h` != `admin:secret@h`.
    An unparseable URL (e.g. `http://[::1`) is preserved verbatim.
    """
    from urllib.parse import urlsplit, urlunsplit
    u = u.strip()
    try:
        s = urlsplit(u)
        host = s.hostname                                  # may raise ValueError on a malformed authority
        port = s.port                                       # .port also raises ValueError (e.g. :99999, :abc)
    except ValueError:
        return u                                            # unparseable -> preserve (never crash Run.add)
    if not s.scheme and not s.netloc:
        return u                                            # not a URL shape — preserve verbatim
    canon_host = _canon_host(host or "")
    if ":" in canon_host:                                   # IPv6 literal -> re-bracket for a valid netloc
        canon_host = f"[{canon_host}]"
    netloc = canon_host
    if port is not None:
        netloc += f":{port}"
    if s.username is not None:                              # userinfo verbatim (case-sensitive creds)
        userinfo = s.username + (f":{s.password}" if s.password is not None else "")
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((s.scheme.lower(), netloc, s.path, s.query, s.fragment))


def _canon_ip(ip: str) -> str:
    import ipaddress
    ip = ip.strip()
    try:
        return str(ipaddress.ip_address(ip))                # compressed canonical form (IPv6 case-insensitive)
    except ValueError:
        return ip.lower()


def _all_refs(record: dict) -> list:
    """Every raw-evidence reference on a record — the scalar `raw_ref` folded into the `raw_refs` list."""
    refs = list(record.get("raw_refs") or [])
    rr = record.get("raw_ref")
    if rr and rr not in refs:
        refs.append(rr)
    return refs


def _subsumed(base: dict, incoming: dict) -> bool:
    """True when `incoming` carries nothing the merged `base` doesn't already hold exactly. A new list
    element, a previously-empty field now filled, or a conflicting scalar all make it False — the
    observation is novel and must be logged.
    """
    _a = base.get("_alt")                                   # alternates already logged, per field;
    alt = _a if isinstance(_a, dict) else {}                # a corrupt/crafted non-dict _alt is tolerated
    for k, v in incoming.items():
        if k in ("first_seen", "last_seen", "_alt") or v in (None, "", [], {}):
            continue
        cur = base.get(k)
        if isinstance(v, list):
            curl = cur if isinstance(cur, list) else ([cur] if cur not in (None, "") else [])
            if any(x not in curl for x in v):
                return False
        elif cur in (None, "", [], {}):
            return False                                    # fills a previously-empty field — novel
        else:
            _seen = alt.get(k)                              # a corrupt non-list entry (e.g. int) -> []
            if cur != v and v not in (_seen if isinstance(_seen, list) else []):
                return False                                # a conflict we have not logged before — novel
        # else: cur==v, or a conflict whose value is already in _alt -> nothing new
    return True


def _merge_record(base: dict, incoming: dict) -> dict:
    """Provenance merge: union list-valued evidence, fill previously-empty enrichment fields, and never
    overwrite a non-empty scalar (the conflicting value stays in the immutable observation log). `sources`,
    `raw_refs`, tags, IPs and any list field are unioned order-preserving.
    """
    merged = dict(base)
    _a = base.get("_alt")                                   # conflicting alternates already logged, per field;
    alt = dict(_a) if isinstance(_a, dict) else {}          # a corrupt/crafted non-dict _alt is tolerated
    for k, v in incoming.items():
        if k in ("raw_ref", "raw_refs", "first_seen", "last_seen", "_alt"):
            continue                                        # refs handled below; timestamps below; _alt is internal
        cur = merged.get(k)
        if isinstance(cur, list) or isinstance(v, list):    # union lists (either side), order-preserving
            out = list(cur) if isinstance(cur, list) else ([cur] if cur not in (None, "") else [])
            for x in (v if isinstance(v, list) else [v]):
                if x not in out:
                    out.append(x)
            merged[k] = out
        elif cur in (None, "", [], {}):
            merged[k] = v                                   # fill a previously-empty enrichment field
        elif cur != v:                                      # a conflict keeps the first value but remembers
            seen = alt.get(k)                               # the alternate, so a repeat is subsumed rather
            if not isinstance(seen, list):                  # than re-appended for ever
                seen = []
            if v not in seen:
                alt[k] = seen + [v]
    if alt:
        merged["_alt"] = alt                                # conflicting values, preserved in the merged view too
    refs = _all_refs(base)
    for x in _all_refs(incoming):
        if x not in refs:
            refs.append(x)
    if refs:
        merged["raw_refs"] = refs
        merged["raw_ref"] = refs[0]                         # back-compat scalar = first evidence
    # earliest first_seen and latest last_seen across observations; both are stamped on every appended
    # observation, so a reopened run recovers them from the log
    fs = [t for t in (base.get("first_seen"), incoming.get("first_seen")) if t]
    if fs:
        merged["first_seen"] = min(fs)
    ls = [t for t in (base.get("last_seen"), incoming.get("last_seen")) if t]
    if ls:
        merged["last_seen"] = max(ls)
    return merged


def canonical_key(entity: str, record: dict) -> str:
    """The dedup identity for a normalized entity, case-correct per the contract above. Empty when the
    record is not an object or the key field is absent/blank (the record is then not addable).
    """
    if not isinstance(record, dict):
        return ""                                           # a non-object JSONL row is not an entity
    raw = str(record.get(ENTITY_KEYS.get(entity, "value"), "")).strip()
    if not raw:
        return ""
    if entity in _HOST_KEYED:
        return _canon_host(raw)
    if entity in _URL_KEYED:
        return _canon_url(raw)
    if entity in _IP_KEYED:
        return _canon_ip(raw)
    return raw                                              # id/value: case-preserving (strip only)


# ── cross-run identity: what a campaign needs from a finished run ─────────────────────────────────────
#: provenance fields (where/when observed, plus `_inherited`), excluded from a fingerprint
RUN_SCOPED_FIELDS = ("first_seen", "last_seen", "raw_ref", "raw_refs", "_inherited")


def material(entity: str, record: dict) -> dict:
    """The material content of an entity — what it asserts, with run-scoped bookkeeping removed and every
    list in a stable order, so two records are comparable across runs. `sources` and `_alt` stay: a second
    independent source, and a conflicting observation, are both facts the union does not otherwise hold.
    """
    if not isinstance(record, dict):
        return {}
    return {k: _canon_value(v) for k, v in record.items() if k not in RUN_SCOPED_FIELDS}


def _canon_value(value):
    """Stable form of any JSON value at every depth — lists deduped and ordered, dicts key-sorted."""
    if isinstance(value, list):
        seen: list = []
        for x in (_canon_value(i) for i in value):
            if x not in seen:
                seen.append(x)
        return sorted(seen, key=lambda x: json.dumps(x, sort_keys=True, ensure_ascii=False))
    if isinstance(value, dict):
        return {k: _canon_value(v) for k, v in sorted(value.items())}
    return value


def fingerprint(entity: str, record: dict) -> str:
    """A stable digest of `material()` — equal iff two records assert the same thing."""
    return hashlib.sha256(json.dumps(material(entity, record), sort_keys=True,
                                     ensure_ascii=False).encode("utf-8")).hexdigest()[:32]


def merge(entity: str, base: dict, incoming: dict) -> dict:
    """The store's own monotonic merge, exposed for cross-run use: lists union, empty fields fill, a
    conflicting scalar keeps the first value and remembers the alternate. Nothing is ever removed.
    """
    return _merge_record(base, incoming)


def adds_material(entity: str, base: dict, incoming: dict) -> bool:
    """Whether merging `incoming` into `base` adds a material fact — the campaign's progress test.

    Asks the monotonic merge rather than comparing fingerprints: a DNS answer, a title or a rotating
    certificate can alternate between runs for ever, and inequality would score every swing as discovery.
    """
    return fingerprint(entity, merge(entity, base, incoming)) != fingerprint(entity, base)


@dataclass
class FoldedLog:
    """What one entity log yielded, and whether it can be trusted:

        absent    no log at all — this run never wrote this entity kind
        valid     read cleanly, every row usable
        degraded  read, but rows were dropped (bad JSON, a non-object row, no identity, bad UTF-8)
        unusable  could not be read at all — the records here are not a corpus
    """
    records: dict = field(default_factory=dict)
    status: str = "valid"
    dropped: int = 0
    reason: str = ""

    @property
    def trustworthy(self) -> bool:
        """Whether this view may stand in for the run's evidence — `degraded` is honest but incomplete and
        `unknown` means nobody could say, so neither may pass for a corpus.
        """
        return self.status in ("valid", "absent")


def fold_run_entity(run_dir, entity: str) -> FoldedLog:
    """One entity of a FINISHED run, reconciled against what its manifest says the run held — a clean parse
    of a deleted or truncated log is not an evidence claim, so the recorded count decides:

        manifest unreadable / missing            -> unknown  (nobody can say; not trustworthy)
        no count recorded + no log               -> valid    (an authoritative zero)
        a count recorded + no log                -> unusable (evidence expected, evidence gone)
        parsed count != the recorded count       -> degraded (something was lost or added since)
        parsed count == the recorded count       -> the parser's own verdict stands
    """
    run_dir = Path(run_dir)
    try:
        manifest = json.loads((run_dir / "manifest.json").read_text())
        counts = manifest.get("entity_counts") if isinstance(manifest, dict) else None
        if not isinstance(counts, dict):
            raise ValueError("no entity_counts")
    except (OSError, json.JSONDecodeError, ValueError) as e:
        return FoldedLog(status="unknown", reason=f"manifest unusable: {type(e).__name__}")
    absent_key = entity not in counts
    expected = counts.get(entity)
    if not absent_key and not (type(expected) is int and expected >= 0):
        # `True == 1` and `1.0 == 1`, so a count that is not an exact non-negative int certifies nothing
        return FoldedLog(status="unknown",
                         reason=f"manifest count for {entity!r} is not an exact non-negative int")
    folded = fold_observations(run_dir / "normalized" / f"{entity}.jsonl")
    if absent_key:
        if folded.status == "absent":
            return FoldedLog(status="valid", reason="the run recorded no entity of this kind")
        expected = 0                                   # a log with rows the manifest never counted
    if folded.status == "absent":
        return FoldedLog(status="unusable" if expected else "valid",
                         reason=(f"the run recorded {expected} but the log is gone" if expected
                                 else "the run recorded no entity of this kind"))
    if folded.status == "unusable":
        return folded
    if len(folded.records) != expected:
        return FoldedLog(records=folded.records, status="degraded", dropped=folded.dropped,
                         reason=(f"the run recorded {expected} entit(ies), the log yields "
                                 f"{len(folded.records)}"))
    return folded


def fold_observations(path) -> FoldedLog:
    """The merged view of one entity's append-only observation log, for a run nobody has open — the same
    fold `Run._records_for` does, so a finished run reads exactly as it did while it was live.
    """
    entity = Path(path).stem
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return FoldedLog(status="absent", reason="no observation log")
    except OSError as e:
        return FoldedLog(status="unusable", reason=f"{type(e).__name__}: {e}")
    merged: dict = {}
    dropped = 0
    for chunk in raw.splitlines():
        if not chunk.strip():
            continue
        try:
            # decoded per line, so one invalid byte costs that row alone and is counted
            rec = json.loads(chunk.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            dropped += 1
            continue
        if not isinstance(rec, dict):
            dropped += 1
            continue
        k = canonical_key(entity, rec)
        if not k:
            dropped += 1
            continue
        merged[k] = _merge_record(merged[k], rec) if k in merged else rec
    if dropped:
        return FoldedLog(records=merged, status="degraded", dropped=dropped,
                         reason=f"{dropped} unusable observation row(s)")
    return FoldedLog(records=merged)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


#: directories under recon/ that are not runs (one authority, so no enumerator re-lists them as runs).
RESERVED_RECON_DIRS = frozenset({"state", "campaigns"})


def _read_started(path: Path):
    """The recorded `started` timestamp from a run.json / manifest.json, or None if absent or unreadable."""
    try:
        v = json.loads(path.read_text())
        return v.get("started") if isinstance(v, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _parse_started(s) -> "datetime | None":
    """A timezone-aware datetime from an ISO `started` string, or None if it is malformed or naive."""
    if not isinstance(s, str):
        return None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def _run_identity(d: Path) -> "tuple[dict, datetime] | None":
    """`(metadata, started)` for a real run directory, or None. Requires `run_id == dir name`, a non-empty
    string `target`, and a parseable timezone-aware `started`."""
    for name in ("run.json", "manifest.json"):
        v = _read_json(d / name)
        if not isinstance(v, dict) or v.get("run_id") != d.name:
            continue
        if not (isinstance(v.get("target"), str) and v["target"].strip()):
            continue
        dt = _parse_started(v.get("started"))
        if dt is not None:
            return v, dt
    return None


def _atomic_write(path: Path, text: str) -> None:
    """Write via a same-directory temp + os.replace, so a reader never sees a half-written file and a
    crash mid-write leaves the previous version intact.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


@dataclass
class ToolRunRecord:
    phase: str
    tool: str
    status: str
    exit_code: int | None
    duration: float
    stdout_lines: int
    note: str
    cmd: str
    stderr_tail: str = ""
    cpu_s: float = 0.0                 # per-tool child CPU seconds
    peak_rss_mb: float = 0.0           # per-tool peak RSS (MB) of the process tree


class Run:
    """One reconnaissance run inside a project: owns its tree, manifest, and entity store.

    Lives at <project_dir>/recon/<run_id>/, so a run's output co-locates with the target.yaml profile
    the project dir was derived from.
    """

    def __init__(self, project_dir: Path, target: str, run_id: str | None = None, *, load_started: bool = False):
        self.project_dir = Path(project_dir)
        self.target = target
        self.run_id = run_id or self._mint_run_id()
        self.dir = self.project_dir / "recon" / self.run_id
        self.raw = self.dir / "raw"
        self.normalized = self.dir / "normalized"
        self.exports = self.dir / "exports"
        self.reports = self.dir / "reports"
        for d in (self.raw, self.normalized, self.exports, self.reports):
            d.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.dir / "manifest.json"
        self.meta_path = self.dir / "run.json"            # immutable creation record (started/run_id/target)
        self._tool_runs: list[ToolRunRecord] = []
        self._counts_cache: dict[str, int] = {}
        self._records: dict[str, dict] = {}       # entity -> {canonical_key: merged record} (instance-local)
        self._folded: dict[str, FoldedLog] = {}   # entity -> the same fold, with its trust status
        # opening an existing run reads `started` from run.json (written at create, and surviving a crash
        # that left no manifest) rather than fabricating a fresh start time
        if load_started:
            self.started = _read_started(self.meta_path) or _read_started(self.manifest_path) or _utc()
        else:
            self.started = _utc()
            if not self.meta_path.exists():
                _atomic_write(self.meta_path, json.dumps(
                    {"run_id": self.run_id, "target": target, "started": self.started}))
        self.notes: list[str] = []

    # ── C10a lifecycle ──
    @staticmethod
    def _mint_run_id() -> str:
        """Collision-resistant run id: sortable UTC timestamp + 8-hex random suffix. Second precision alone
        collides when two runs start in the same second; `Run.create` claims the directory atomically as well.
        """
        return time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex()

    @classmethod
    def create(cls, project_dir, target) -> "Run":
        """Start a NEW run — mint a unique id and claim its directory atomically (mkdir exist_ok=False),
        retrying on a clash. `started` = now.
        """
        project_dir = Path(project_dir)
        for _ in range(16):
            rid = cls._mint_run_id()
            try:
                (project_dir / "recon" / rid).mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                continue
            return cls(project_dir, target, run_id=rid)
        raise RuntimeError("could not mint a unique run id after 16 attempts")

    @classmethod
    def open(cls, project_dir, target, run_id) -> "Run":
        """Attach to an EXISTING run, reading the recorded `started` from run.json (manifest fallback).

        Raises when the directory is missing, and when neither run.json nor manifest.json is readable —
        validated before the constructor materializes any subdirectory, so a corrupt run is never given a
        fabricated start time.
        """
        d = Path(project_dir) / "recon" / run_id
        if not d.is_dir():
            raise FileNotFoundError(f"run {run_id!r} not found under {d.parent}")
        if _read_started(d / "run.json") is None and _read_started(d / "manifest.json") is None:
            raise ValueError(f"run {run_id!r} has no readable run.json/manifest — refusing to fabricate a start")
        return cls(project_dir, target, run_id=run_id, load_started=True)

    # ── raw evidence ──
    def raw_path(self, phase: str, tool: str, name: str) -> Path:
        p = self.raw / phase / tool
        p.mkdir(parents=True, exist_ok=True)
        return p / name

    # ── tool run accounting ──
    def record(self, phase: str, result) -> None:
        # the single choke point that redacts secrets out of cmd/note/stderr before they reach the manifest
        from . import secrets
        self._tool_runs.append(ToolRunRecord(
            phase=phase, tool=result.tool, status=str(result.status.value),
            exit_code=result.exit_code, duration=round(result.duration, 2),
            stdout_lines=result.stdout_lines, note=secrets.redact(result.note),
            cmd=secrets.redact(" ".join(result.cmd)), stderr_tail=secrets.redact(result.stderr_tail),
            cpu_s=getattr(result, "cpu_s", 0.0), peak_rss_mb=getattr(result, "peak_rss_mb", 0.0),
        ))

    def tool_runs(self, phase: str | None = None) -> list[ToolRunRecord]:
        if phase is None:
            return list(self._tool_runs)
        return [r for r in self._tool_runs if r.phase == phase]

    # ── normalized entities (JSONL, append, dedup on natural key) ──
    def _entity_file(self, entity: str) -> Path:
        return self.normalized / f"{entity}.jsonl"

    def add(self, entity: str, record: dict) -> bool:
        """Record an observation of a normalized entity. Returns True iff its natural key is NEW, so the
        `sum(add(...))` / `if add(...)` counting semantics across phases are unchanged.

        Identity is case-correct (`canonical_key`), and provenance is merged rather than discarded: a repeat
        observation of an existing key is unioned into the merged view, and only a value-adding observation is
        appended to the immutable log, which bounds file growth.

        `last_seen` is therefore the time of the last observation that ADDED something, not the last time the
        entity was seen at all; `first_seen` is exact.
        """
        key = canonical_key(entity, record)
        if not key:
            return False
        records = self._records_for(entity)
        # `_alt` is reserved internal merge metadata: stripping it from caller input keeps external data
        # from injecting a value that would corrupt the conflict tracking
        record = {k: v for k, v in dict(record).items() if k != "_alt"}
        now = _utc()
        record.setdefault("first_seen", now)
        record["last_seen"] = now                           # stamped on the appended observation -> durable
        if key not in records:
            records[key] = record
            self._append_obs(entity, record)
            return True
        if not _subsumed(records[key], record):             # novel: new evidence or a conflicting value
            self._append_obs(entity, record)                # keep the raw observation in the immutable log
            records[key] = _merge_record(records[key], record)   # folds max(last_seen) durably
        return False                                        # not a new entity (counting semantics preserved)

    def inherit(self, entity: str, record: dict) -> bool:
        """Record an entity this run was HANDED (a campaign seeded it from earlier children) — present for
        every downstream lane, and never counted as this run's discovery, because `add()` answers "is this key
        new?" and phases count that as production. Returns whether anything was written, so a second bootstrap
        is a no-op rather than a growing log.
        """
        key = canonical_key(entity, record)
        if not key:
            return False
        records = self._records_for(entity)
        # `_alt` is kept here, unlike in `add`: on this trusted campaign path the alternates came from this
        # store's own merge, and dropping them would hand the child less than the campaign holds
        record = dict(record)
        record.setdefault("first_seen", _utc())
        record["last_seen"] = _utc()
        if key not in records:
            records[key] = record
            self._append_obs(entity, record)
            return True
        if _subsumed(records[key], record):
            return False
        self._append_obs(entity, record)
        records[key] = _merge_record(records[key], record)
        return True

    def _append_obs(self, entity: str, record: dict) -> None:
        with self._entity_file(entity).open("a") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _records_for(self, entity: str) -> dict:
        """Lazily materialize the merged view {key: record} for an entity by folding its append-only JSONL
        log, so a reopened run recovers the same merged state. One fold, shared with `fold_observations`: the
        live and finished views cannot diverge, and a single invalid byte costs one observation here too.
        """
        if entity not in self._records:
            folded = fold_observations(self._entity_file(entity))
            self._folded[entity] = folded
            self._records[entity] = folded.records
        return self._records[entity]

    def _seen_keys(self, entity: str) -> set:
        return set(self._records_for(entity))

    def read(self, entity: str) -> list[dict]:
        """The merged entities (one per canonical key, provenance unioned) — not the raw observation lines."""
        return list(self._records_for(entity).values())

    def read_folded(self, entity: str) -> "FoldedLog":
        """The merged view WITH its trust status (`absent`/`valid`/`degraded`/`unusable`).

        `read()` throws the status away, so a caller cannot tell "no rows" from "the log could not be read".
        For an ordinary corpus that is a fair simplification; for a record that decides whether we may act —
        the acquisition-ownership transition log — it is the whole question.
        """
        if entity not in self._folded:
            self._folded[entity] = fold_observations(self._entity_file(entity))
            self._records[entity] = self._folded[entity].records
        return self._folded[entity]

    def count(self, entity: str) -> int:
        return len(self._records_for(entity))

    def values(self, entity: str) -> list[str]:
        key_field = ENTITY_KEYS.get(entity, "value")
        return [str(r.get(key_field, "")) for r in self.read(entity) if r.get(key_field)]

    # ── manifest ──
    def _run_summary(self) -> dict:
        """Per-run reliability rollup for the manifest: tool status counts, the failure list, the gaps and
        limits lists, and a run verdict.

        `tools_failed` counts only hard failures, so `gaps` carries every degraded or missing source with
        its `output_lines` (stdout lines — not proof of evidence; a -o tool preserves an artifact with
        zero stdout). `verdict` is `complete_with_gaps` whenever any source failed or degraded or a phase
        raised or a required tool was missing, `complete_with_limits` when only limits remain.

        `note`/`stderr_tail` are already redacted by record(); phase_exceptions are redacted here, so no
        free text bypasses the manifest secret choke point."""
        from . import contract, events, secrets
        _DEGRADED = ("partial", "blocked", "timed_out")
        _MISSING = ("not on path", "not installed", "not found")   # skip reason == the tool is absent
        # a required tool skipped because it is missing is a coverage gap; an optional, setup-disabled or
        # passive skip is intentional
        try:
            from .registry import load_tools
            _required = {t.bin for t in load_tools() if not t.optional}
        except Exception:
            _required = set()
        status_counts: dict[str, int] = {}
        failures = []
        gaps = []
        for r in self._tool_runs:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
            why = r.note or r.stderr_tail or f"exit {r.exit_code}"
            if r.status == "failed":
                failures.append({"phase": r.phase, "tool": r.tool, "why": why})
            elif r.status in _DEGRADED:
                gaps.append({"phase": r.phase, "tool": r.tool, "status": r.status,
                             "why": why, "output_lines": r.stdout_lines})
            elif (r.status == "skipped" and r.tool in _required
                  and any(m in why.lower() for m in _MISSING)):
                gaps.append({"phase": r.phase, "tool": r.tool, "status": "missing",
                             "why": why, "output_lines": 0})       # required tool absent -> coverage gap
        # in-process provider terminals are folded in below, so a failed or partial provider feeds the
        # verdict and every terminal — clean ones included — increments tool_status
        provider_limits: list = []                            # external limits (quota/entitlement)
        # an operator boundary is a limit too, but it is ours; a separate bucket and an `origin` field keep
        # it from reading as a provider refusing us
        operator_limits: list = []                            # our own bounds (reserve, withheld budget)
        for term in self._read_provider_terminals():
            sid = term.get("source_id", "?")
            st = term.get("status")
            status_counts[st] = status_counts.get(st, 0) + 1     # providers count toward tool_status too
            if st not in ("failed", "partial", "incomplete", "limited"):
                continue
            why = term.get("reason") or term.get("error_class") or st
            entry = {"phase": sid.split(".", 1)[0], "tool": sid, "why": why}
            ec = term.get("error_class")
            if ec:
                entry["error_class"] = ec
            # a limit is a soft outcome, never a failure or gap, and only a proven class qualifies — a bare 403
            # is `forbidden` and stays a failure
            if contract.terminal_is_limit(st, ec):
                bucket = provider_limits if ec else operator_limits
                bucket.append({**entry, "status": st, "output_lines": 0,
                               "origin": "provider" if ec else "operator"})
            elif st == "failed":
                failures.append(entry)
            else:                                                 # partial / incomplete -> a coverage gap
                gaps.append({**entry, "status": st, "output_lines": 0})
        phase_exceptions = [secrets.redact(n) for n in self.notes if "EXCEPTION" in n]
        # ── coverage counters: reconcile event-level input omissions into the verdict ──────────────
        # cap/timeout omitted>0 is a gap; sample/limit omitted>0 is a soft limit; inconsistent is unknown
        coverage = self._read_coverage()
        coverage_limits = []
        for cov in coverage:
            sid = cov["source_id"]
            base = {"phase": sid.split(".", 1)[0], "tool": sid, "measure": cov["measure"], "why": cov["reason"]}
            if not cov["valid"]:
                gaps.append({**base, "status": "coverage:unknown", "output_lines": cov["tested"],
                             "eligible": cov["eligible"], "omitted": cov["omitted"]})
                continue
            for kind, c in cov["by_kind"].items():
                if c["omitted"] <= 0:
                    continue                                          # fully covered this run — no gap/limit
                frac = round(c["omitted"] / c["eligible"], 3) if c["eligible"] else 0.0
                entry = {**base, "status": f"coverage:{kind}", "output_lines": c["tested"],
                         "eligible": c["eligible"], "omitted": c["omitted"], "omitted_fraction": frac,
                         "priority": "major" if _coverage_gates(frac, c["omitted"]) else "minor"}
                if kind in (events.COVERAGE_SAMPLE, events.COVERAGE_PROVIDER):
                    coverage_limits.append(entry)                     # operator subset / provider limit -> soft
                else:
                    gaps.append(entry)                                # cap/timeout with omitted>0 -> gap
        # ── structured child faults ────────────────────────────────────────────────────────────────
        # machinery break · optional tool failure · required tool missing, each in its own field
        faults = [{"kind": "phase_exception", "where": "run", "detail": note}
                  for note in phase_exceptions]
        _optional = set()
        try:
            from .registry import load_tools as _load
            _optional = {t.bin for t in _load() if t.optional}
        except Exception:                                          # noqa: BLE001 — a report is never a stop
            _optional = set()
        for f in failures:
            faults.append({"kind": "optional_tool_failed" if f.get("tool") in _optional else "machinery",
                           "where": f.get("tool") or f.get("phase"), "detail": f.get("why")})
        for g in gaps:
            if g.get("status") == "missing":
                faults.append({"kind": "required_tool_missing", "where": g.get("tool"),
                               "detail": g.get("why")})

        # gaps dominate: a limit only lifts an otherwise-clean run to complete_with_limits
        limits = coverage_limits + provider_limits + operator_limits
        verdict = ("complete_with_gaps" if (failures or gaps or phase_exceptions)
                   else "complete_with_limits" if limits else "complete")
        return {"verdict": verdict, "tool_status": status_counts, "tools_failed": len(failures),
                "failures": failures, "gaps": gaps, "phase_exceptions": phase_exceptions,
                "coverage": coverage, "coverage_limits": coverage_limits,
                # what each lane still owes; absent means unknown, never zero
                "remainders": self._read_remainders(),
                "faults": faults,
                "provider_spend": self._read_spend(),
                "provider_limits": provider_limits, "operator_limits": operator_limits}

    def _read_spend(self) -> list[dict]:
        """Provider spend per (lane, provider, measure), summed. Never summed ACROSS measures: pages and query
        credits are different currencies, and `pages_bought` is not equivalent to charged requests.
        """
        ev = self.dir / "events.jsonl"
        if not ev.exists():
            return []
        totals: dict = {}
        try:
            lines = ev.read_bytes().splitlines()
        except OSError:
            return []
        for chunk in lines:
            try:
                rec = json.loads(chunk.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(rec, dict) or rec.get("event") != "spend":
                continue
            lane, provider, measure = rec.get("source_id"), rec.get("provider"), rec.get("measure")
            amount = rec.get("amount")
            if not all(isinstance(x, str) and x for x in (lane, provider, measure)):
                continue
            if type(amount) is not int or amount < 0:
                # an unusable amount is not zero: the lane spent something nobody can count
                key = (lane, provider, measure)
                totals.setdefault(key, {"lane": lane, "provider": provider, "measure": measure,
                                        "amount": 0, "unknown": 0})["unknown"] += 1
                continue
            key = (lane, provider, measure)
            totals.setdefault(key, {"lane": lane, "provider": provider, "measure": measure,
                                    "amount": 0, "unknown": 0})["amount"] += amount
        return [totals[k] for k in sorted(totals)]

    def _read_remainders(self) -> list[dict]:
        """The LATEST remainder record per (lane, unit) — what each lane still owes, for a supervisor deciding
        whether repeating this run could advance anything. Latest-per-unit so a lane that finished its rotation
        clears the one before it. A lane that emitted nothing is absent here, which reads as UNKNOWN, not zero.
        """
        ev = self.dir / "events.jsonl"
        if not ev.exists():
            return []
        latest: dict = {}
        try:
            lines = ev.read_bytes().splitlines()
        except OSError:
            return []
        for chunk in lines:
            try:
                rec = json.loads(chunk.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(rec, dict) or rec.get("event") != "remainder":
                continue
            lane, unit = rec.get("source_id"), rec.get("unit")
            if not isinstance(lane, str) or not isinstance(unit, str):
                continue
            # reconstructed and validated before publication: this feeds a supervisor's arithmetic, so a
            # malformed payload arrives as unknown rather than as numbers nobody checked
            from . import remainder as _remainder
            retriable = rec.get("retriable") if isinstance(rec.get("retriable"), dict) else {}
            terminal = rec.get("terminal") if isinstance(rec.get("terminal"), dict) else {}
            try:
                built = _remainder.Remainder(
                    lane=lane, unit=unit, measure=rec.get("measure"), model=rec.get("model"),
                    now=retriable.get("now"), cooldown=retriable.get("cooldown"),
                    terminal={k: v for k, v in terminal.items() if v},
                    detail=rec.get("detail") if isinstance(rec.get("detail"), dict) else {})
                built.validate()
            except (ValueError, TypeError) as e:
                latest[(lane, unit)] = {"lane": lane, "unit": unit,
                                        "invalid": f"{type(e).__name__}: {e}"}
                continue
            latest[(lane, unit)] = built.as_record()
        return [latest[k] for k in sorted(latest)]

    def _read_coverage(self) -> list[dict]:
        """Aggregate structured coverage_partial events (those carrying eligible/tested/omitted) from
        events.jsonl into a per-(source_id, measure) rollup, rerun/resume-safe:
          1. keep only the LATEST record per (source_id, unit), so an uncapped rerun clears a prior cap
             instead of the raw appends double-counting it;
          2. aggregate the surviving units, keeping a `by_kind` breakdown so a mixed source reports each
             kind on its own terms (sample/provider stay soft limits; cap and timeout gate);
          3. a unit with a non-numeric or inconsistent triple flags the source ``valid=False`` and its
             numbers are not summed.
        Legacy per-item events without counters are ignored (already covered by degraded tool_runs), and a
        missing or garbled log yields []."""
        from . import events

        def _int(x):
            try:
                return int(x)
            except (TypeError, ValueError):
                return None

        ev = self.dir / "events.jsonl"
        if not ev.exists():
            return []
        # read in line order (append order = happened order), so a coverage_reset drops that source's
        # accumulated units and the lines after it are the new generation, with no timestamp math involved
        live: dict[str, dict] = {}                                 # source_id -> {unit: latest rec}, current gen
        try:
            for line in ev.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                et = rec.get("event")
                sid = rec.get("source_id", "?")
                if et == events.COVERAGE_RESET:
                    live.pop(sid, None)                            # new generation: prior units gone
                elif et == events.COVERAGE_PARTIAL and (rec.get("eligible") is not None
                                                        or rec.get("kind") == events.COVERAGE_UNKNOWN):
                    # COVERAGE_UNKNOWN is structured but uncounted; admitted so "ran, unmeasurable" reaches
                    # the verdict as a gap rather than reading as fully covered
                    live.setdefault(sid, {})[rec.get("unit", sid)] = rec   # latest per unit, this generation
        except Exception:
            pass
        # aggregated per (source_id, measure) so each rollup has one homogeneous denominator; by_kind and
        # the per-unit summaries keep a mixed or multi-unit rollup attributable
        agg: dict[tuple, dict] = {}
        for sid, units in live.items():
            for rec in units.values():
                measure = rec.get("measure") or "items"
                kind = rec.get("kind") or events.COVERAGE_TIMEOUT
                elig, tst, omt = _int(rec.get("eligible")), _int(rec.get("tested")), _int(rec.get("omitted"))
                a = agg.setdefault((sid, measure),
                                   {"source_id": sid, "measure": measure, "eligible": 0, "tested": 0,
                                    "omitted": 0, "reason": None, "valid": True, "by_kind": {}, "units": [],
                                    "unknown": []})
                unit_valid = (rec.get("coverage_valid") is not False and None not in (elig, tst, omt)
                              and elig >= 0 and tst >= 0 and omt >= 0 and tst + omt == elig)
                if not unit_valid:
                    a["valid"] = False                            # never sum garbage -> no += on a str
                    # its reason is kept: an inconsistent unit is the one an operator needs explained
                    a["unknown"].append({"unit": rec.get("unit", sid), "kind": kind,
                                         "reason": rec.get("reason")})
                    continue
                a["eligible"] += elig; a["tested"] += tst; a["omitted"] += omt
                a["units"].append({"unit": rec.get("unit", sid), "eligible": elig, "tested": tst,
                                   "omitted": omt, "kind": kind, "reason": rec.get("reason")})
                bk = a["by_kind"].setdefault(kind, {"eligible": 0, "tested": 0, "omitted": 0})
                bk["eligible"] += elig; bk["tested"] += tst; bk["omitted"] += omt
        for a in agg.values():                                    # aggregate reason; attribution stays in `units`
            limited = [u for u in a["units"] if u["omitted"] > 0]
            unk = a["unknown"]
            if unk:
                # unmeasurable dominates the headline, so a mixed rollup never reports only its measured
                # part and implies the rest was covered
                a["reason"] = (unk[0]["reason"] if len(unk) == 1 and not a["units"]
                               else f"{len(unk)} of {len(unk) + len(a['units'])} unit(s) unmeasurable"
                                    + (f"; {a['omitted']} {a['measure']} omitted in the rest"
                                       if a["omitted"] else ""))
            elif len(limited) == 1:
                a["reason"] = limited[0]["reason"]
            elif len(limited) > 1:
                a["reason"] = f"{len(limited)} unit(s) limited; {a['omitted']} {a['measure']} omitted"
            elif a["units"]:
                a["reason"] = a["units"][0]["reason"]             # fully covered — a representative note
        return list(agg.values())

    def _read_provider_terminals(self) -> list[dict]:
        """In-process provider terminals (run_provider, marked provider=True), which never reach _tool_runs.
        Returns every current-generation terminal — the caller counts each status and gates on failed and
        partial. A terminal marked reset_generation supersedes this source's prior terminals across all
        work units; the log is read in line order, keeping the latest per (source_id, work_unit) within the
        current generation. The `provider` flag keeps a subprocess lane from being counted twice."""
        from . import events
        ev = self.dir / "events.jsonl"
        if not ev.exists():
            return []
        latest: dict[tuple, dict] = {}
        try:
            for line in ev.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                et = rec.get("event")
                if not rec.get("provider") or et not in (events.TOOL_START, events.TOOL_FINISH):
                    continue
                sid = rec.get("source_id", "?")
                key = (sid, rec.get("work_unit"))
                if et == events.TOOL_START:
                    if rec.get("reset_generation"):              # the reset is persisted before execution
                        for k in [k for k in latest if k[0] == sid]:   # drop this source's prior units
                            del latest[k]
                    # the start is recorded as incomplete and replaced by its terminal; a start with no
                    # terminal (a crash mid-provider) stays incomplete and gates the verdict
                    latest[key] = {"source_id": sid, "work_unit": rec.get("work_unit"),
                                   "status": "incomplete", "reason": "provider started but never finished (crash?)"}
                else:                                             # TOOL_FINISH supersedes the start
                    latest[key] = rec
        except Exception:
            return []
        return list(latest.values())

    def write_manifest(self, profile_summary: dict, phases_run: list[str],
                       metrics: dict | None = None, policy: list | None = None) -> None:
        from . import secrets
        manifest = {
            "run_id": self.run_id,
            "target": self.target,
            "started": self.started,
            "finished": _utc(),
            "profile": profile_summary,
            "phases_run": phases_run,
            "tool_runs": [asdict(r) for r in self._tool_runs],
            "entity_counts": {e: self.count(e) for e in ENTITY_KEYS
                              if self._entity_file(e).exists()},
            "notes": [secrets.redact(n) for n in self.notes],
            "summary": self._run_summary(),
        }
        if metrics:                                 # pointer + headline totals for the telemetry artifact
            manifest["metrics"] = metrics
        if policy:
            # the effective coverage policy this run applied, redacted again at this sink because a sink that
            # trusts its input is how one leak becomes permanent
            manifest["policy"] = secrets.redact_deep(policy)
        # a failed event-sink write means events.jsonl is incomplete, so a coverage/verdict folded from it
        # is not clean truth
        from . import events as _events
        od = _events.observability_degraded()
        if od:
            manifest["observability_degraded"] = od
        _events.persist_degraded()                  # survives to the next resume (accumulates)
        _atomic_write(self.manifest_path, json.dumps(manifest, indent=2))
        # update state pointers (per-project, under recon/)
        state = self.project_dir / "recon" / "state"
        (state / "history").mkdir(parents=True, exist_ok=True)
        _atomic_write(state / "history" / f"{self.run_id}.json",
                      json.dumps({"run_id": self.run_id, "target": self.target,
                                  "finished": manifest["finished"],
                                  "entity_counts": manifest["entity_counts"]}, indent=2))
        # the `current` pointer is swapped atomically (temp symlink + os.replace), so a concurrent reader
        # never sees it briefly missing
        cur = state / "current"
        try:
            tmp = state / f".current.{os.getpid()}.tmp"
            if tmp.is_symlink() or tmp.exists():
                tmp.unlink()
            os.symlink(self.dir.resolve(), tmp)
            os.replace(tmp, cur)
        except OSError:
            _atomic_write(state / "current.txt", str(self.dir.resolve()))

    @staticmethod
    def list_runs(project_dir: Path) -> "list[Path]":
        """Real run directories under recon/, oldest→newest by parsed `started` (name breaks ties). Reserved
        namespaces (`state`, `campaigns`), symlinks, non-directories and invalid-identity dirs are excluded."""
        root = Path(project_dir) / "recon"
        if not root.is_dir():
            return []
        runs = []
        for d in root.iterdir():
            if d.name in RESERVED_RECON_DIRS or d.is_symlink() or not d.is_dir():
                continue
            ident = _run_identity(d)
            if ident is not None:
                runs.append((ident[1], d.name, d))
        runs.sort(key=lambda t: (t[0], t[1]))
        return [d for _, _, d in runs]

    @staticmethod
    def latest(project_dir: Path) -> "Run | None":
        candidates = Run.list_runs(project_dir)
        if not candidates:
            return None
        d = candidates[-1]
        ident = _run_identity(d)                             # the validated identity is the target authority
        return Run.open(project_dir, ident[0]["target"] if ident else "unknown", d.name)
