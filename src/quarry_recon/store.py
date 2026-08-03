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

# PRIORITY thresholds (NOT a gate): any cap/timeout with omitted>0 is already a gap — truth is not a
# fraction. These only label a gap `major` vs `minor` for operator triage: omitted >= 10% OR >= 100 absolute
# is `major` (a big-fraction small set AND a small-fraction huge set both count). Boundaries are inclusive.
COVERAGE_GAP_FRACTION = 0.10
COVERAGE_GAP_ABSOLUTE = 100


def _coverage_gates(frac: float, omitted: int) -> bool:
    """Priority label: True == `major` (material under-coverage), False == `minor`. Does NOT decide gating —
    a cap/timeout with omitted>0 is always a gap regardless of this."""
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
    "wildcard_zone": "value",   # A1: cert-derived *.X.apex brute-zones (persisted vertical→enrich for A1d)
    "web_port": "id",           # v0.3.5: open web port per host:ip (naabu SYN prefilter) — host→ip→port edge
    "gadget_candidate": "id",   # chain MATERIAL: weird primitives that are not findings and not noise
                                # (`gadgets.py`); never promoted to `finding`, impact_state always
                                # `none_proven`
    "oob_interaction": "id",    # OOB.1: imported out-of-band callbacks (interactsh); raw in raw/oob/,
                                # uncorrelated by default until Quarry owns the token namespace (Phase 2)
}

# ── C09a identity contract — canonical dedup key per entity type ──────────────────────────────────────
# The OLD key was `str(value).strip().lower()` for EVERY entity, which collapsed case-DISTINCT offensive
# surface (e.g. `/API` and `/api`, a case-sensitive endpoint/parameter/fingerprint). The contract below
# lowercases ONLY the case-INSENSITIVE components (DNS names; a URL's scheme+host) and PRESERVES everything
# case-sensitive (path, query, parameter names, composite ids, secret/cert fingerprints). Same function is
# used to WRITE and to RELOAD keys so dedup is stable across a reopened run.
_HOST_KEYED = {"subdomain", "resolved"}                     # key = DNS name (case-insensitive)
_URL_KEYED = {"live", "url", "js_url", "screenshot"}        # key = URL (scheme+host insensitive; path/query NOT)
_IP_KEYED = {"ip"}                                          # key = IP literal (normalize; case-insensitive)
# every other entity is id/value-keyed → case is PRESERVED (path/param/fingerprint/composite id carry case)


def _canon_host(h: str) -> str:
    """DNS-name canonicalization: lower, strip trailing dot, IDNA2008/UTS-46 non-transitional (so `faß.de`
    and `xn--fa-hia.de` share one key). Best-effort — a non-domain host (IP literal, wildcard, odd label)
    that IDNA can't encode falls back to the lowered/dot-stripped form rather than raising."""
    h = h.strip().lower().rstrip(".")
    if not h:
        return h
    from . import normalize as _n
    return _n.idna_ascii(h) or h                 # shared policy; best-effort fallback is THIS site's choice


def _canon_url(u: str) -> str:
    """Canonicalize a URL's scheme + HOSTNAME only (lower + IDNA + trailing-dot strip); PRESERVE path,
    query, fragment, AND userinfo (a credential-bearing lead) exactly, so `/API` != `/api` and
    `Admin:SeCrEt@h` != `admin:secret@h`. Unparseable URL (e.g. `http://[::1`) -> preserved verbatim."""
    from urllib.parse import urlsplit, urlunsplit
    u = u.strip()
    try:
        s = urlsplit(u)
        host = s.hostname                                  # may raise ValueError on a malformed authority
        port = s.port                                       # review#9: .port ALSO raises ValueError (e.g. :99999, :abc)
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
    if s.username is not None:                              # userinfo PRESERVED verbatim (case-sensitive creds)
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
    """True when `incoming` carries NOTHING the merged `base` doesn't already hold exactly — a pure
    duplicate. A new list element, a previously-empty field now filled, OR a CONFLICTING scalar (a different
    non-empty value) all make it False → the observation is novel and must be logged (never discarded)."""
    _a = base.get("_alt")                                   # review#9: alternates we've ALREADY logged per field
    alt = _a if isinstance(_a, dict) else {}                # review#8: tolerate a corrupt/crafted non-dict _alt
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
            _seen = alt.get(k)                              # review#4: a corrupt non-list entry (e.g. int) -> []
            if cur != v and v not in (_seen if isinstance(_seen, list) else []):
                return False                                # a CONFLICT we have NOT logged before — novel
        # else: cur==v (dup) OR a conflict whose value is already in the log (_alt) → nothing new
    return True


def _merge_record(base: dict, incoming: dict) -> dict:
    """C09b provenance merge: union list-valued evidence, fill previously-empty enrichment fields, and
    NEVER overwrite a non-empty scalar (a conflicting value stays in the immutable observation log). Symmetric
    provenance: `sources`, `raw_refs`, tags, IPs, and any list field are unioned order-preserving."""
    merged = dict(base)
    _a = base.get("_alt")                                   # review#9: per-field conflicting alternates already logged
    alt = dict(_a) if isinstance(_a, dict) else {}          # review#8: tolerate a corrupt/crafted non-dict _alt
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
        elif cur != v:                                      # a CONFLICT: KEEP first value (first non-empty wins),
            seen = alt.get(k)                               # but REMEMBER the alternate so a repeat is subsumed
            if not isinstance(seen, list):                  # review#4: normalize a corrupt/non-list entry
                seen = []
            if v not in seen:                               # (else an unchanged conflict re-appends forever)
                alt[k] = seen + [v]
        # else: cur==v → nothing to do
    if alt:
        merged["_alt"] = alt                                # conflicting values, preserved in the merged view too
    refs = _all_refs(base)
    for x in _all_refs(incoming):
        if x not in refs:
            refs.append(x)
    if refs:
        merged["raw_refs"] = refs
        merged["raw_ref"] = refs[0]                         # back-compat scalar = first evidence
    # keep the EARLIEST first_seen across observations
    fs = [t for t in (base.get("first_seen"), incoming.get("first_seen")) if t]
    if fs:
        merged["first_seen"] = min(fs)
    # review#8: keep the LATEST last_seen across observations — persisted (stamped on each appended obs), so a
    # reopened run recovers it from the log instead of losing an in-memory-only value.
    ls = [t for t in (base.get("last_seen"), incoming.get("last_seen")) if t]
    if ls:
        merged["last_seen"] = max(ls)
    return merged


def canonical_key(entity: str, record: dict) -> str:
    """The dedup identity for a normalized entity — case-correct per the contract above. Empty when the
    record is not an object or the key field is absent/blank (the record is then not addable)."""
    if not isinstance(record, dict):
        return ""                                           # a non-object JSONL row (null/[]/scalar) is not an entity
    raw = str(record.get(ENTITY_KEYS.get(entity, "value"), "")).strip()
    if not raw:
        return ""
    if entity in _HOST_KEYED:
        return _canon_host(raw)
    if entity in _URL_KEYED:
        return _canon_url(raw)
    if entity in _IP_KEYED:
        return _canon_ip(raw)
    return raw                                              # id/value: case-PRESERVING (strip only)


# ── cross-run identity: what a CAMPAIGN needs from a finished run (settle prerequisite A) ─────────────
#: fields that describe WHERE and WHEN an observation was made, not WHAT is true. A campaign comparing two
#: children must not see a new artifact path or a fresh timestamp as discovery — every child would then
#: look like progress and a fixed point could never be reached.
#: `_inherited` is bookkeeping about HOW a run got an entity (a campaign seeded it), never a fact about
#: the world — so an inherited copy fingerprints exactly like the record it came from.
RUN_SCOPED_FIELDS = ("first_seen", "last_seen", "raw_ref", "raw_refs", "_inherited")


def material(entity: str, record: dict) -> dict:
    """The MATERIAL content of an entity — what it asserts, with run-scoped bookkeeping removed and every
    list put in a stable order, so two records are comparable across runs.

    `sources` STAYS: a second, independent source for the same host is a fact about the world, not noise.
    `_alt` stays too — a conflicting observation is knowledge the union did not hold."""
    if not isinstance(record, dict):
        return {}
    return {k: _canon_value(v) for k, v in record.items() if k not in RUN_SCOPED_FIELDS}


def _canon_value(value):
    """Stable form of any JSON value, at EVERY depth. A shallow pass left lists nested below the first
    dict order-sensitive, so two records asserting the same thing could fingerprint differently — and a
    campaign would read that as discovery."""
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
    """The store's own MONOTONIC merge, exposed for cross-run use: lists union, empty fields fill, a
    conflicting scalar keeps the first value and remembers the alternate. Nothing is ever removed."""
    return _merge_record(base, incoming)


def adds_material(entity: str, base: dict, incoming: dict) -> bool:
    """Whether merging `incoming` into `base` ADDS a material fact — the campaign's progress test.

    Not `fingerprint(incoming) != fingerprint(base)`: a DNS answer, a title or a rotating certificate can
    alternate between runs for ever, and inequality would score every swing as discovery. This asks the
    merge, which is monotonic — the first swing records the alternate, and a return to the earlier value
    adds nothing, because the union already holds both."""
    return fingerprint(entity, merge(entity, base, incoming)) != fingerprint(entity, base)


@dataclass
class FoldedLog:
    """What one entity log actually yielded, and whether it could be trusted.

    A campaign must never read "unreadable" as "empty": bootstrapping from a lost log would drop evidence
    silently, and a fixed point declared over it would claim finished work nobody could see. So the status
    is part of the answer:

        absent    no log at all — this run never wrote this entity kind
        valid     read cleanly, every row usable
        degraded  read, but rows were dropped (bad JSON, a non-object row, no identity, bad UTF-8)
        unusable  could not be read at all — the records here are NOT a corpus
    """
    records: dict = field(default_factory=dict)
    status: str = "valid"
    dropped: int = 0
    reason: str = ""

    @property
    def trustworthy(self) -> bool:
        """Whether this view may stand in for the run's evidence. `degraded` is honest but incomplete, and
        `unknown` means nobody could say — neither may pass for a corpus."""
        return self.status in ("valid", "absent")


def fold_run_entity(run_dir, entity: str) -> FoldedLog:
    """One entity of a FINISHED run, reconciled against what its manifest says the run held.

    A parser's "I read this file cleanly" is not an evidence claim. A log can be deleted after the manifest
    was written, or truncated on a line boundary — both parse without a single dropped row, and both would
    hand a campaign a smaller corpus that looks authoritative. So the count the run itself recorded decides:

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
        # a count that is not an exact non-negative int certifies nothing. `True == 1` and `1.0 == 1` in
        # Python, so a malformed manifest would have passed a one-record log off as authoritative, and an
        # explicit `null` would have read as "the run recorded none of this kind".
        return FoldedLog(status="unknown",
                         reason=f"manifest count for {entity!r} is not an exact non-negative int")
    folded = fold_observations(run_dir / "normalized" / f"{entity}.jsonl")
    if absent_key:
        if folded.status == "absent":
            return FoldedLog(status="valid", reason="the run recorded no entity of this kind")
        expected = 0                                   # ...a log with rows the manifest never counted
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
    """The MERGED view of one entity's append-only observation log, for a run nobody has open — the same
    fold `Run._records_for` does, so a finished run reads exactly as it did while it was live."""
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
            # DECODE PER LINE: one invalid byte used to abort the whole file, losing every valid
            # observation before and after it. A bad row costs itself and is COUNTED.
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


def _read_started(path: Path):
    """The recorded `started` timestamp from a run.json / manifest.json, or None if absent/unreadable —
    so open() can recover the real start without fabricating one."""
    try:
        v = json.loads(path.read_text())
        return v.get("started") if isinstance(v, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _atomic_write(path: Path, text: str) -> None:
    """Write via a same-directory temp + os.replace so a reader never sees a half-written file and a
    crash mid-write leaves the previous version intact (C10a)."""
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
    cpu_s: float = 0.0                 # per-tool child CPU seconds (H3 telemetry)
    peak_rss_mb: float = 0.0           # per-tool peak RSS (MB) of the process tree (H3 telemetry)


class Run:
    """One reconnaissance run inside a project: owns its tree, manifest, and entity store.

    Lives at <project_dir>/recon/<run_id>/ — the project dir is derived from the target.yaml
    location, so a run's output co-locates with its profile (campaign/project model).
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
        self.meta_path = self.dir / "run.json"            # IMMUTABLE creation record (started/run_id/target)
        self._tool_runs: list[ToolRunRecord] = []
        self._counts_cache: dict[str, int] = {}
        self._records: dict[str, dict] = {}   # entity -> {canonical_key: MERGED record} (C09b; instance-local)
        # C10a/review#7: OPENING an existing run must NOT fabricate a fresh start time (a ghost). It reads
        # `started` from the IMMUTABLE run.json written at CREATE — which survives a crash even when the final
        # manifest was never written (the exact resume situation). Manifest is only a fallback; a fresh
        # CREATE stamps now and persists run.json so a later open() can never invent a start.
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
        """Collision-resistant run id: sortable UTC timestamp + 8-hex random suffix. Second-precision alone
        collided (two runs in the same second reused one directory); the 4-byte suffix (4.3B space) makes a
        same-second clash negligible, and Run.create() claims the dir atomically to eliminate even that."""
        return time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex()

    @classmethod
    def create(cls, project_dir, target) -> "Run":
        """Start a NEW run — mint a unique id and CLAIM its directory atomically (mkdir exist_ok=False),
        retrying on the astronomically-unlikely clash. `started` = now."""
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
        """Attach to an EXISTING run — must already exist (never fabricate a ghost dir / start time).
        Reads the recorded `started` from run.json (manifest fallback).

        review#5: VALIDATE the recorded start BEFORE the constructor mutates the tree (it creates raw/…
        subdirs). A run with neither a readable run.json NOR a readable manifest is corrupt — raise instead of
        silently inventing a fresh `started` (a ghost) and half-materializing a directory for it."""
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
        # Redact any secret values out of the recorded command/note/stderr before they ever
        # hit the manifest (e.g. shosubgo's `-s <shodan-key>` arg). Single choke point.
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
        """Record an observation of a normalized entity. Returns True iff its natural key is NEW (so the
        `sum(add(...))`/`if add(...)` counting semantics across phases are unchanged).

        C09a: identity is case-CORRECT (canonical_key) — `/API` != `/api`.
        C09b: provenance is MERGED, never discarded. A repeat observation of an existing key is UNIONed into
        the merged view (sources / raw_refs / tags / IPs / list evidence unioned; previously-empty
        enrichment filled; a conflicting non-empty scalar keeps the first value, and every observation is
        still appended to the immutable JSONL log, so nothing is lost). Only a VALUE-ADDING observation is
        appended (a pure duplicate that changes nothing is a no-op), which bounds file growth.

        review#3: consequently `last_seen` means the time of the last observation that ADDED something (new
        evidence / a conflicting value) — NOT the last time the entity was seen at all. A pure-duplicate
        re-sighting is deliberately not appended (growth-bounding), so it does not advance `last_seen`. This
        narrower "last value-changing observation" semantic is intentional; `first_seen` is exact."""
        key = canonical_key(entity, record)
        if not key:
            return False
        records = self._records_for(entity)
        # review#8: `_alt` is RESERVED internal merge metadata — strip it from caller/source input so external
        # data can never inject a value that later crashes or corrupts the conflict tracking.
        record = {k: v for k, v in dict(record).items() if k != "_alt"}
        now = _utc()
        record.setdefault("first_seen", now)
        record["last_seen"] = now       # review#8: on the APPENDED obs -> durable; review#3: = last VALUE-ADDING obs
        if key not in records:
            records[key] = record
            self._append_obs(entity, record)
            return True
        if not _subsumed(records[key], record):             # novel: new evidence OR a conflicting value
            self._append_obs(entity, record)                # keep the raw observation in the immutable log
            records[key] = _merge_record(records[key], record)   # folds max(last_seen) durably
        return False                                        # not a NEW entity (counting semantics preserved)

    def inherit(self, entity: str, record: dict) -> bool:
        """Record an entity this run was HANDED (a campaign seeded it from earlier children) — present for
        every downstream lane, and never counted as this run's discovery.

        `add()` answers "is this key NEW?", which is what phases count as production; an inherited entity
        must not answer yes. Returns whether anything was written (False for a pure duplicate), so a second
        bootstrap is a no-op rather than a growing log."""
        key = canonical_key(entity, record)
        if not key:
            return False
        records = self._records_for(entity)
        # `_alt` is stripped from CALLER input (`add`) because an external source could inject it. This is
        # the TRUSTED campaign path: the alternates were produced by this store's own merge, and they are
        # material knowledge — dropping them would hand the child less than the campaign holds.
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
        """Lazily materialize the MERGED view {key: record} for an entity by folding its append-only JSONL
        observation log (so a reopened run recovers the same merged state).

        ONE fold, shared with `fold_observations` — the live and finished views cannot diverge, and the
        live one inherits per-line byte decoding, so a single invalid byte costs one observation here too
        rather than raising through whatever asked for the entity."""
        if entity not in self._records:
            self._records[entity] = fold_observations(self._entity_file(entity)).records
        return self._records[entity]

    def _seen_keys(self, entity: str) -> set:
        return set(self._records_for(entity))

    def read(self, entity: str) -> list[dict]:
        """The MERGED entities (one per canonical key, provenance unioned) — not the raw observation lines."""
        return list(self._records_for(entity).values())

    def count(self, entity: str) -> int:
        return len(self._records_for(entity))

    def values(self, entity: str) -> list[str]:
        key_field = ENTITY_KEYS.get(entity, "value")
        return [str(r.get(key_field, "")) for r in self.read(entity) if r.get(key_field)]

    # ── manifest ──
    def _run_summary(self) -> dict:
        """Per-run reliability rollup for the manifest: tool status counts + the 'what failed' list + a
        run VERDICT and a GAPS list. A degraded run must NEVER read as a clean success — `tools_failed`
        only counts hard FAILED, so partial/blocked/timed_out sources were invisible in the headline.
        `gaps` names every such source with its `output_lines` (stdout line count — NOT proof of evidence;
        a -o tool preserves an artifact with zero stdout), and `verdict` is `complete_with_gaps` whenever
        any source failed OR degraded OR a phase raised OR a required tool was missing.
        `note`/`stderr_tail` were already redacted by record(); phase_exceptions are redacted here so no
        free-text bypasses the manifest secret choke point."""
        from . import contract, events, secrets
        _DEGRADED = ("partial", "blocked", "timed_out")
        _MISSING = ("not on path", "not installed", "not found")   # skip reason == the tool is absent
        # a REQUIRED (non-optional) tool skipped because it is MISSING is a coverage gap; an optional /
        # setup-disabled / passive skip is intentional and fine. (output_lines is stdout only — NOT
        # proof of evidence; a -o tool preserves an artifact with zero stdout — hence the honest name.)
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
        # review-r3#1/r4#6: in-process provider terminals (run_provider) never hit _tool_runs — fold them here
        # so a FAILED/PARTIAL provider feeds the verdict AND every provider terminal (incl. clean) increments
        # tool_status (a `tools_failed` count without a matching status count is a lie). Keyed by
        # (source_id, work_unit), latest per current generation.
        provider_limits: list = []                            # external LIMITS (quota/entitlement)
        # review-B1.4r8#2: an OPERATOR boundary is a limit, but it is OURS. Filing it under
        # `provider_limits` said the provider refused us — the exact blame-shift the taxonomy exists to
        # prevent, reintroduced by the field it was recorded in. Separate bucket, and every entry
        # carries a structured `origin` so a consumer can read either shape.
        operator_limits: list = []                            # OUR OWN bounds (reserve, withheld budget)
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
            # review-B0#3: an EXTERNAL PROVIDER LIMIT is not a Quarry defect. Exhausted credits (or a plan
            # that cannot reach the endpoint) mean the provider stopped us, not that anything went wrong —
            # so it is a soft LIMIT (complete_with_limits), never a failure or a coverage gap. It still
            # reaches the operator: coverage is genuinely incomplete and the verdict says so.
            # Limits are PROVEN classes only (quota/entitlement, from a body or balance) — a bare 403 is
            # `forbidden` and stays a failure. review-B1.4r7#1: an OPERATOR boundary is a limit too, and
            # it carries NO provider class by design, so the question is asked of the TERMINAL (status
            # AND class) rather than of the class alone.
            if contract.terminal_is_limit(st, ec):
                bucket = provider_limits if ec else operator_limits
                bucket.append({**entry, "status": st, "output_lines": 0,
                               "origin": "provider" if ec else "operator"})
            elif st == "failed":
                failures.append(entry)
            else:                                                 # partial / incomplete (crash) -> a coverage gap
                gaps.append({**entry, "status": st, "output_lines": 0})
        phase_exceptions = [secrets.redact(n) for n in self.notes if "EXCEPTION" in n]
        # ── coverage counters: reconcile event-level input omissions into the verdict ──────────────
        # A cap/timeout SITE records tool-level success yet may truncate eligible input; its coverage_partial
        # event carries eligible/tested/omitted/kind/unit. TRUTH policy (not a threshold): dropping eligible
        # methodology means the run is NOT clean —
        #   · a CAP or TIMEOUT with omitted>0 is a GAP (complete_with_gaps), regardless of fraction;
        #   · an operator-selected SAMPLE, or an external PROVIDER limit, with omitted>0 is a soft LIMIT
        #     (complete_with_limits, not a gap) — nothing failed and there is nothing to retry this run;
        #   · an INCONSISTENT triple is coverage:unknown (a gap — never fabricated completion).
        # The 10%/100 rule is retained ONLY as a `priority` label (major/minor) for triage, NOT to gate.
        # by_kind is kept so a mixed source is reported honestly (sample/provider stay soft, timeouts gate).
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
        # ── STRUCTURED child faults (settle prerequisite D) ────────────────────────────────────────
        # A campaign must decide whether repeating a child is continuation or repetition of a broken run,
        # and `failures` does not separate a machinery break from an optional tool's failure while a
        # REQUIRED missing tool arrives in `gaps` instead. So the machine-readable version says which is
        # which, in its own field, and nobody has to match prose.
        faults = [{"kind": "phase_exception", "where": "run", "detail": note}
                  for note in phase_exceptions]
        _optional = set()
        try:
            from .registry import load_tools as _load
            _optional = {t.bin for t in _load() if t.optional}
        except Exception:                                          # noqa: BLE001 - a report is never a stop
            _optional = set()
        for f in failures:
            faults.append({"kind": "optional_tool_failed" if f.get("tool") in _optional else "machinery",
                           "where": f.get("tool") or f.get("phase"), "detail": f.get("why")})
        for g in gaps:
            if g.get("status") == "missing":
                faults.append({"kind": "required_tool_missing", "where": g.get("tool"),
                               "detail": g.get("why")})

        # a LIMIT never downgrades a run that also has real gaps — gaps dominate; limits only lift a
        # otherwise-clean run to complete_with_limits so the incompleteness is still stated.
        limits = coverage_limits + provider_limits + operator_limits
        verdict = ("complete_with_gaps" if (failures or gaps or phase_exceptions)
                   else "complete_with_limits" if limits else "complete")
        return {"verdict": verdict, "tool_status": status_counts, "tools_failed": len(failures),
                "failures": failures, "gaps": gaps, "phase_exceptions": phase_exceptions,
                "coverage": coverage, "coverage_limits": coverage_limits,
                # what each lane still OWES — the supervisor's input, absent meaning UNKNOWN (settle B)
                "remainders": self._read_remainders(),
                # STRUCTURED child faults and provider spend, so a campaign never interprets prose (D)
                "faults": faults,
                "provider_spend": self._read_spend(),
                "provider_limits": provider_limits, "operator_limits": operator_limits}

    def _read_spend(self) -> list[dict]:
        """Provider spend per (lane, provider, measure), SUMMED — a child's bill, in the units it was
        charged in. Never summed ACROSS measures: pages and query credits are different currencies, and
        `pages_bought` is not equivalent to charged requests (settle prerequisite D)."""
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
        """The LATEST remainder record per (lane, unit) — what each lane still OWES, for a supervisor that
        has to decide whether repeating this run could advance anything (settle prerequisite B).

        Latest-per-unit for the same reason coverage is: a lane re-emits its remainder every run, and a run
        that finished its rotation must be able to CLEAR the one before it. A lane that emitted nothing is
        absent here — which a supervisor must read as UNKNOWN, never as zero."""
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
            # RECONSTRUCTED and validated before publication: this feeds a supervisor's arithmetic, and a
            # malformed payload must arrive as UNKNOWN rather than as numbers nobody checked.
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
        """Aggregate STRUCTURED coverage_partial events (those carrying eligible/tested/omitted) from
        events.jsonl into a per-source_id rollup, rerun/resume-safe:
          1. keep only the LATEST record per (source_id, unit) — a repeated phase re-emits the SAME unit
             every run (including with omitted=0 when it no longer caps), so latest-per-unit lets an
             uncapped rerun CLEAR a prior cap. Summing raw appends would double-count and never clear.
          2. aggregate surviving units per source_id, keeping a `by_kind` breakdown so a mixed source
             reports honestly (sample/provider stay soft limits; cap and timeout counts gate) — no relabeling.
          3. counters are coerced defensively; a unit with a non-numeric / inconsistent triple flags the
             source ``valid=False`` and its garbage numbers are NOT summed (verdict treats it as unknown,
             and manifest generation can never crash on a bad value).
        Legacy per-item events (no structured counters) are ignored — already covered by degraded tool_runs.
        Best-effort: a missing/garbled log yields []."""
        from . import events

        def _int(x):
            try:
                return int(x)
            except (TypeError, ValueError):
                return None

        ev = self.dir / "events.jsonl"
        if not ev.exists():
            return []
        # Process the log IN LINE ORDER (append order = happened order): a coverage_reset for a source DROPS
        # that source's accumulated units; the lines after it are the new generation. No timestamp math, so a
        # unit sharing the reset's millisecond can't survive, and a vanished unit is cleared by its reset.
        live: dict[str, dict] = {}                                 # source_id -> {unit: latest rec} (current gen)
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
                    # COVERAGE_UNKNOWN is structured-but-uncounted: admit it so "ran, unmeasurable" reaches the
                    # verdict as a gap. Skipping it made a first run with no stats read as fully covered.
                    live.setdefault(sid, {})[rec.get("unit", sid)] = rec   # latest per unit, this generation
        except Exception:
            pass
        # aggregate per (source_id, MEASURE) — files and params (different measures) are NEVER summed; each
        # rollup has one homogeneous denominator. by_kind is kept so a mixed source reports each kind honestly,
        # and per-unit summaries are retained so a multi-unit rollup keeps HONEST attribution (not just the
        # first unit's reason).
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
                    a["valid"] = False                            # do NOT sum garbage -> no += on a str
                    # ...but KEEP its reason: an unknown/inconsistent unit is exactly the one an operator needs
                    # explained, and dropping it left the coverage:unknown gap with `why: null`.
                    a["unknown"].append({"unit": rec.get("unit", sid), "kind": kind,
                                         "reason": rec.get("reason")})
                    continue
                a["eligible"] += elig; a["tested"] += tst; a["omitted"] += omt
                a["units"].append({"unit": rec.get("unit", sid), "eligible": elig, "tested": tst,
                                   "omitted": omt, "kind": kind, "reason": rec.get("reason")})
                bk = a["by_kind"].setdefault(kind, {"eligible": 0, "tested": 0, "omitted": 0})
                bk["eligible"] += elig; bk["tested"] += tst; bk["omitted"] += omt
        for a in agg.values():                                    # honest aggregate reason (attribution kept in `units`)
            limited = [u for u in a["units"] if u["omitted"] > 0]
            unk = a["unknown"]
            if unk:
                # UNMEASURABLE dominates the headline: a rollup that mixes measured and unmeasured units must
                # not report only the measured part, or a "5348 omitted" line would imply the rest was covered.
                a["reason"] = (unk[0]["reason"] if len(unk) == 1 and not a["units"]
                               else f"{len(unk)} of {len(unk) + len(a['units'])} unit(s) unmeasurable"
                                    + (f"; {a['omitted']} {a['measure']} omitted in the rest"
                                       if a["omitted"] else ""))
            elif len(limited) == 1:
                a["reason"] = limited[0]["reason"]
            elif len(limited) > 1:
                a["reason"] = f"{len(limited)} unit(s) limited; {a['omitted']} {a['measure']} omitted"
            elif a["units"]:
                a["reason"] = a["units"][0]["reason"]             # fully covered — carry a representative note
        return list(agg.values())

    def _read_provider_terminals(self) -> list[dict]:
        """review-r3#1/r4#6: fold IN-PROCESS provider terminals (run_provider, marked provider=True) into the
        verdict — they never hit _tool_runs, so a FAILED/PARTIAL provider would otherwise leave the run looking
        complete, and clean providers would be invisible to the status counts. Returns ALL current-generation
        terminals (the caller counts every status and gates on failed/partial). GENERATION (review-r4#3): a
        terminal marked reset_generation supersedes this source's PRIOR terminals (all work_units) — processed in
        LINE ORDER so a resume/config-change clears stale failures, keeping the LATEST per (source_id, work_unit)
        within the current generation. The `provider` flag prevents double-counting a subprocess lane."""
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
                    if rec.get("reset_generation"):               # review-r5#1: reset persisted BEFORE execution
                        for k in [k for k in latest if k[0] == sid]:   # new generation: drop this source's prior units
                            del latest[k]
                    # record the START as INCOMPLETE — replaced when the matching terminal arrives; a start with
                    # NO terminal (crash mid-provider) stays incomplete and gates the verdict.
                    latest[key] = {"source_id": sid, "work_unit": rec.get("work_unit"),
                                   "status": "incomplete", "reason": "provider started but never finished (crash?)"}
                else:                                             # TOOL_FINISH — terminal supersedes the start
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
            # the EFFECTIVE coverage policy this run applied: every registered bound, its value, who set
            # it, and what was HELD. Stored so a manifest can be read without the shell history that
            # produced it (flag-axis step 3).
            # defensively redacted a SECOND time: the rows are already non-disclosing by construction,
            # and a manifest sink that trusts its input is exactly how one leak becomes permanent.
            manifest["policy"] = secrets.redact_deep(policy)
        # C11: if any event-sink write FAILED this session, events.jsonl is incomplete — record that fact so
        # a coverage/verdict folded from it is not read as clean truth (the run itself never crashed on it).
        from . import events as _events
        od = _events.observability_degraded()
        if od:
            manifest["observability_degraded"] = od
        _events.persist_degraded()                  # review#6: survive to the next resume (accumulates)
        # C10a: atomic write (temp + os.replace) so a crash mid-write never leaves a truncated manifest.
        _atomic_write(self.manifest_path, json.dumps(manifest, indent=2))
        # update state pointers (per-project, under recon/)
        state = self.project_dir / "recon" / "state"
        (state / "history").mkdir(parents=True, exist_ok=True)
        _atomic_write(state / "history" / f"{self.run_id}.json",
                      json.dumps({"run_id": self.run_id, "target": self.target,
                                  "finished": manifest["finished"],
                                  "entity_counts": manifest["entity_counts"]}, indent=2))
        # `current` pointer: swap ATOMICALLY (temp symlink + os.replace) so a concurrent reader never sees
        # it briefly missing between unlink and re-create.
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
    def latest(project_dir: Path) -> "Run | None":
        runs_dir = Path(project_dir) / "recon"
        if not runs_dir.exists():
            return None
        candidates = sorted([d for d in runs_dir.iterdir()
                             if d.is_dir() and d.name != "state"])
        if not candidates:
            return None
        d = candidates[-1]
        # review#5: recover target from run.json when there is no manifest (a CRASHED run has run.json but no
        # final manifest) — else `latest()` mislabels a resumable run as target "unknown".
        target = "unknown"
        for meta in (d / "manifest.json", d / "run.json"):   # manifest first (richer), run.json fallback
            if meta.exists():
                try:
                    t = json.loads(meta.read_text()).get("target")
                except (OSError, json.JSONDecodeError):
                    continue
                if t:
                    target = t
                    break
        return Run.open(project_dir, target, d.name)        # C10a: OPEN (load started), never fabricate
