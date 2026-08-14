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

import errno
import fcntl
import hashlib
import json
import os
import stat
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import wraps

from pathlib import Path

from .repository_identity import (RUN_RESERVED_IDS, valid_run_id, validate_artifact_component,
                                  validate_run_id)
from .state import ContractError


class MutationScope(str, Enum):
    """The closed vocabulary for repository-owned mutation authority."""

    BASE_EVIDENCE = "base_evidence"
    FINALIZATION_METADATA = "finalization_metadata"
    REVISION = "revision"
    CONTROL = "control"


_RUN_LOCKS_GUARD = threading.Lock()
_RUN_LOCKS: dict[tuple[str, str], threading.RLock] = {}
_PROJECT_LOCKS: dict[str, threading.RLock] = {}
_ACQUISITION_ACTIVE: dict[
    tuple[str, str, str], tuple[tuple[int, int], int, object]
] = {}
_LIVE_MANAGED_ACQUISITIONS: dict[int, object] = {}
_RUN_LOCK_LOCAL = threading.local()


def _register_live_managed_acquisition(transaction) -> None:
    """Adopt one live transaction without a traced acquire/effect/exit gap."""
    with _RUN_LOCKS_GUARD: _LIVE_MANAGED_ACQUISITIONS[id(transaction)] = transaction


def _unregister_live_managed_acquisition(transaction) -> None:
    """Drop one settled transaction without a traced effect/exit gap."""
    with _RUN_LOCKS_GUARD: _LIVE_MANAGED_ACQUISITIONS.pop(id(transaction), None)


def _reset_mutation_locks_after_fork() -> None:
    """Discard process-local mutexes whose owners do not survive a fork."""
    global _RUN_LOCKS_GUARD, _RUN_LOCKS, _PROJECT_LOCKS
    global _ACQUISITION_ACTIVE, _LIVE_MANAGED_ACQUISITIONS, _RUN_LOCK_LOCAL
    inherited_acquisitions = tuple(_LIVE_MANAGED_ACQUISITIONS.values())
    for transaction in inherited_acquisitions:
        try:
            transaction._close_inherited_graph_at_fork()
        except BaseException:
            # The child must never mutate a parent's names or OFD locks.  Every
            # owned slot is independently tombstoned/closed by the transaction,
            # so one bad descriptor cannot prevent attempts on the suffix.
            pass
    _RUN_LOCKS_GUARD = threading.Lock()
    _RUN_LOCKS = {}
    _PROJECT_LOCKS = {}
    _ACQUISITION_ACTIVE = {}
    _LIVE_MANAGED_ACQUISITIONS = {}
    _RUN_LOCK_LOCAL = threading.local()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_mutation_locks_after_fork)

_BASE_ARTIFACT_DIRECTORY_ROOTS = frozenset({
    "raw", "normalized", "metrics", "envelope-fold-refused",
})
_BASE_ARTIFACT_FILE_ROOTS = frozenset({
    "events.jsonl", "events.degraded.json",
    "tool-runs.jsonl", "envelope-remainder.json", "envelope-refused.jsonl",
    "envelope-degraded.json",
})
_BASE_ARTIFACT_ROOTS = _BASE_ARTIFACT_DIRECTORY_ROOTS | _BASE_ARTIFACT_FILE_ROOTS
_CLAIM_SUFFIX = ".claim"


def _run_lock_key(project_dir: Path, run_id: str) -> tuple[str, str]:
    return str(Path(project_dir).resolve()), run_id


def _shared_run_lock(key: tuple[str, str]) -> threading.RLock:
    with _RUN_LOCKS_GUARD:
        lock = _RUN_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _RUN_LOCKS[key] = lock
        return lock


def _shared_project_lock(project_key: str) -> threading.RLock:
    with _RUN_LOCKS_GUARD:
        lock = _PROJECT_LOCKS.get(project_key)
        if lock is None:
            lock = threading.RLock()
            _PROJECT_LOCKS[project_key] = lock
        return lock


def _thread_mutation_ledgers() -> tuple[dict, dict]:
    """Return fork-safe per-thread Run/project ledgers."""
    if getattr(_RUN_LOCK_LOCAL, "pid", None) != os.getpid():
        _RUN_LOCK_LOCAL.projects = {}
        _RUN_LOCK_LOCAL.held = {}
        _RUN_LOCK_LOCAL.pid = os.getpid()
    projects = getattr(_RUN_LOCK_LOCAL, "projects", None)
    runs = getattr(_RUN_LOCK_LOCAL, "held", None)
    if projects is None:
        projects = {}
        _RUN_LOCK_LOCAL.projects = projects
    if runs is None:
        runs = {}
        _RUN_LOCK_LOCAL.held = runs
    return projects, runs


def _scoped_mutation(scope: MutationScope):
    def decorate(function):
        @wraps(function)
        def wrapped(self, *args, **kwargs):
            with self._mutation(scope):
                return function(self, *args, **kwargs)
        return wrapped
    return decorate


def _validated_artifact_components(components, *, base_only: bool = True) -> tuple[str, ...]:
    """Validate one repository-relative artifact identity before path construction."""
    if type(components) is not tuple or not components:
        raise ContractError("an artifact claim requires at least one path component")
    if len(components) > 64:
        raise ContractError("an artifact identity has too many path components")
    validated = tuple(
        validate_artifact_component(component, f"artifact component {index}")
        for index, component in enumerate(components)
    )
    if base_only and validated[0] not in _BASE_ARTIFACT_ROOTS:
        raise ContractError(f"{validated[0]!r} is not a base-artifact namespace")
    return validated


def _record_bytes(rec) -> int:
    """Serialized on-disk size of one record, the unit the byte envelope is measured in."""
    return len(json.dumps(rec, ensure_ascii=False).encode("utf-8"))


def _utf8_safe(s: str) -> bool:
    """Whether `s` is UTF-8-encodable — a lone surrogate is not, and would crash the sqlite bind."""
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


#: recent refused identities kept in RAM only to suppress redundant ledger writes; the append-only ledger,
#: not this cache, is the exact record, so resident memory stays bounded however many identities are refused.
REFUSED_DEDUP_CACHE = 256

#: the only refusal kinds a ledger line may carry; any other value is a damaged line (fail closed).
_REFUSAL_KINDS = frozenset({"key", "bytes", "corpus", "growth"})

#: a refused key longer than this is damage — a canonical key never is, and it bounds the fold's batch RAM.
_MAX_LEDGER_KEY = 8192

#: a ledger line longer than this is damage, rejected before it is materialized/parsed so a giant line
#: (e.g. a 72 MiB key) never lands in memory; comfortably fits one max key plus the JSON envelope.
_MAX_LEDGER_LINE = 16 * 1024

#: ledger fold batch size; small so batch RAM (<= batch * _MAX_LEDGER_KEY) stays well under the RSS budget.
_LEDGER_BATCH = 1000


def _iter_ledger_lines(fh, cap: int):
    """Yield each newline-delimited line as bytes (<= `cap`), or None for a line longer than `cap` — which is
    drained chunk by chunk and never materialized, so resident memory stays ~cap regardless of line size."""
    buf = b""
    draining = False                                    # inside an over-length line, discarding to its newline
    while True:
        chunk = fh.read(65536)
        if not chunk:
            break
        if draining:
            nl = chunk.find(b"\n")
            if nl < 0:
                continue                                # still inside the giant line: discard the whole chunk
            chunk = chunk[nl + 1:]                       # resume after its newline
            draining = False
            yield None                                  # the over-length line, reported once as damage
        buf += chunk
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                break
            line = buf[:nl]
            buf = buf[nl + 1:]
            yield line if len(line) <= cap else None
        if len(buf) > cap:                              # a partial line already over the cap -> drain the rest
            draining = True
            buf = b""
    if draining:
        yield None
    elif buf:
        yield buf if len(buf) <= cap else None


def _iter_descriptor_lines(fd: int):
    """Yield binary lines from an already-owned descriptor without fd handoff."""
    pending = bytearray()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        pending.extend(chunk)
        while True:
            newline = pending.find(b"\n")
            if newline < 0:
                break
            yield bytes(pending[:newline + 1])
            del pending[:newline + 1]
    if pending:
        yield bytes(pending)


class _DescriptorReader:
    """Minimal bounded-reader adapter over a descriptor owned elsewhere."""

    __slots__ = ("fd",)

    def __init__(self, fd: int) -> None:
        self.fd = fd
        os.lseek(fd, 0, os.SEEK_SET)

    def read(self, size: int) -> bytes:
        return os.read(self.fd, size)


class _BoundedKeySet:
    """A fixed-capacity LRU membership set: bounds resident memory while catching the common repeat."""
    __slots__ = ("_cap", "_d")

    def __init__(self, cap: int):
        self._cap = cap
        self._d: "OrderedDict[str, None]" = OrderedDict()

    def __contains__(self, k: str) -> bool:
        if k in self._d:
            self._d.move_to_end(k)
            return True
        return False

    def add(self, k: str) -> None:
        self._d[k] = None
        self._d.move_to_end(k)
        while len(self._d) > self._cap:
            self._d.popitem(last=False)

    def __len__(self) -> int:
        return len(self._d)

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


def validate_entity(entity: str) -> str:
    """Return a registered entity kind, or refuse before cache lookup or path construction."""
    if type(entity) is not str or entity not in ENTITY_KEYS:
        shown = repr(entity[:96]) if type(entity) is str else f"<{type(entity).__name__}>"
        raise ContractError(f"unknown entity kind {shown}")
    return entity

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
    entity = validate_entity(entity)
    if not isinstance(record, dict):
        return ""                                           # a non-object JSONL row is not an entity
    raw = str(record.get(ENTITY_KEYS[entity], "")).strip()
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
    validate_entity(entity)
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
    validate_entity(entity)
    return hashlib.sha256(json.dumps(material(entity, record), sort_keys=True,
                                     ensure_ascii=False).encode("utf-8")).hexdigest()[:32]


def merge(entity: str, base: dict, incoming: dict) -> dict:
    """The store's own monotonic merge, exposed for cross-run use: lists union, empty fields fill, a
    conflicting scalar keeps the first value and remembers the alternate. Nothing is ever removed.
    """
    validate_entity(entity)
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
    refused: int = 0                          # == len(refused_keys); distinct identities past the envelope
    refused_keys: set = field(default_factory=set)   # the distinct keys refused, for an exact remainder

    @property
    def trustworthy(self) -> bool:
        """Whether this view may stand in for the run's evidence — `degraded` is honest but incomplete and
        `unknown` means nobody could say, so neither may pass for a corpus.
        """
        return self.status in ("valid", "absent")


def fold_run_entity(run_dir, entity: str) -> FoldedLog:
    """One entity of a finished run vs its manifest: count mismatch / envelope refusal / durability gap -> degraded, unreadable manifest -> unknown; the envelope is enforced on the fold."""
    entity = validate_entity(entity)
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
    # live refusals never reach the log; the manifest's persisted state decides, unreadable fails closed
    gap_reason = _manifest_gap_reason(manifest, entity)
    from . import envelope
    folded = fold_observations(run_dir / "normalized" / f"{entity}.jsonl",
                               max_keys=envelope.MAX_KEYS_PER_ENTITY,
                               max_bytes_per_key=envelope.MAX_BYTES_PER_KEY,
                               max_corpus_bytes=envelope.MAX_CORPUS_BYTES_PER_ENTITY,
                               on_refused=lambda k, kind: None)   # bounded: refusals discarded, never held
    if absent_key and folded.status == "absent":
        result = FoldedLog(status="valid", reason="the run recorded no entity of this kind")
    elif absent_key:
        result = _reconcile_fold(folded, 0)            # a log with rows the manifest never counted
    elif folded.status == "absent":
        result = FoldedLog(status="unusable" if expected else "valid",
                           reason=(f"the run recorded {expected} but the log is gone" if expected
                                   else "the run recorded no entity of this kind"))
    elif folded.status == "unusable":
        result = folded
    else:
        result = _reconcile_fold(folded, expected)
    if gap_reason and result.trustworthy:      # a persisted refusal/durability gap is never trustworthy
        return FoldedLog(records=result.records, status="degraded", dropped=result.dropped, reason=gap_reason)
    return result


def _reconcile_fold(folded: FoldedLog, expected: int) -> FoldedLog:
    """A present log vs its recorded count: a count change or any byte/growth refusal degrades it."""
    if len(folded.records) != expected:
        return FoldedLog(records=folded.records, status="degraded", dropped=folded.dropped,
                         reason=f"the run recorded {expected} entit(ies), the log yields {len(folded.records)}")
    if folded.refused:
        return FoldedLog(records=folded.records, status="degraded", dropped=folded.dropped,
                         refused=folded.refused,
                         reason=f"{folded.refused} observation(s) refused past the corpus envelope")
    return folded


def _manifest_gap_reason(manifest: dict, entity: str) -> str:
    """Why the manifest's persisted state keeps `entity` degraded, or "" if genuinely clean; a durability gap or any remainder not cleanly parseable/attributable fails closed, never read as zero."""
    if not isinstance(manifest, dict):
        return "manifest unreadable"
    if manifest.get("envelope_degraded"):
        return "envelope durability degraded (persisted)"
    if "envelope_remainder" not in manifest:
        return ""                                       # no refusal record and no durability gap -> clean
    env_rem = manifest.get("envelope_remainder")
    if not isinstance(env_rem, dict) or not isinstance(env_rem.get("remainders"), list):
        return "malformed envelope_remainder"           # present but unreadable -> fail closed, never zero
    from . import envelope as _envelope, state as _state
    prefix = _envelope.ENVELOPE_LANE + ":"              # the record's authoritative grouping: store.envelope:<entity>
    outstanding = 0
    for record in env_rem["remainders"]:
        # parse via the contract (required fields, model/measure, int counters); an unparseable record, or one
        # whose lane/unit is not a known store.envelope:<entity>, fails closed
        if not isinstance(record, dict):
            return "malformed envelope_remainder"
        try:
            rem = _state.parse_remainder(record)
        except (KeyError, TypeError, ValueError):
            return "malformed envelope_remainder"
        if set(record) - set(rem.as_record()):          # an unknown top-level key the contract does not permit
            return "malformed envelope_remainder"
        if rem.lane != _envelope.ENVELOPE_LANE or not rem.unit.startswith(prefix):
            return "malformed envelope_remainder"
        unit_entity = rem.unit[len(prefix):]
        if unit_entity not in ENTITY_KEYS:              # an unknown entity in the unit -> not attributable
            return "malformed envelope_remainder"
        if unit_entity != entity:
            continue                                    # grouped under another entity: not this fold's concern
        # ours: retriable + all terminal causes count; a mismatched entity or unknown retriable key keeps at
        # least one unit outstanding (fail closed)
        work = rem.now + rem.cooldown + sum(rem.terminal.values())
        det = rem.detail.get("entity")
        src_retriable = record.get("retriable")
        identity_ok = (det in ENTITY_KEYS and det == unit_entity
                       and not (isinstance(src_retriable, dict) and set(src_retriable) - {"now", "cooldown"}))
        outstanding += work if identity_ok else max(work, 1)
    return f"{outstanding} unit(s) of outstanding envelope work" if outstanding else ""


def _fold_observation_stream(
    fh, entity: str, *, max_keys: int | None = None,
    max_bytes_per_key: int | None = None,
    max_corpus_bytes: int | None = None, on_refused=None,
    require_newline: bool = False,
) -> FoldedLog:
    """Fold an already-authorized binary stream without reopening its name."""
    merged: dict = {}
    dropped = 0
    corpus_bytes = 0
    refused_keys: set = set()
    refused_count = 0
    bytes_active = max_bytes_per_key is not None or max_corpus_bytes is not None

    def _refuse(k: str, kind: str) -> None:
        nonlocal refused_count
        refused_count += 1
        if on_refused is not None:
            on_refused(k, kind)                      # streamed: the caller keeps the durable, exact record
        else:
            refused_keys.add(k)

    for line in fh:                                  # one line resident at a time; the file is never held whole
        if require_newline and line and not line.endswith(b"\n"):
            dropped += 1
            continue
        if not line.strip():
            continue
        try:
            rec = json.loads(line.decode("utf-8"))   # per-line decode: one bad byte costs its row alone
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
        if k in merged:
            cand = _merge_record(merged[k], rec)
            if not bytes_active:
                merged[k] = cand
                continue
            delta = _record_bytes(cand) - _record_bytes(merged[k])
            if max_bytes_per_key is not None and _record_bytes(cand) > max_bytes_per_key:
                _refuse(k, "growth")                 # keep base; a key may not grow past the per-key ceiling
            elif max_corpus_bytes is not None and delta > 0 and corpus_bytes + delta > max_corpus_bytes:
                _refuse(k, "growth")
            else:
                merged[k] = cand
                corpus_bytes += max(0, delta)
            continue
        rb = _record_bytes(rec) if bytes_active else 0
        if max_bytes_per_key is not None and rb > max_bytes_per_key:
            _refuse(k, "bytes")                      # one record larger than the per-key ceiling
        elif max_keys is not None and len(merged) >= max_keys:
            _refuse(k, "key")                        # the distinct-key ceiling
        elif max_corpus_bytes is not None and corpus_bytes + rb > max_corpus_bytes:
            _refuse(k, "corpus")                     # the summed-bytes ceiling
        else:
            merged[k] = rec
            corpus_bytes += rb
    refused = len(refused_keys) if on_refused is None else refused_count
    if dropped:
        return FoldedLog(records=merged, status="degraded", dropped=dropped, refused=refused,
                         refused_keys=refused_keys, reason=f"{dropped} unusable observation row(s)")
    return FoldedLog(records=merged, refused=refused, refused_keys=refused_keys)


def fold_observations(path, *, max_keys: int | None = None, max_bytes_per_key: int | None = None,
                      max_corpus_bytes: int | None = None, on_refused=None,
                      require_newline: bool = False) -> FoldedLog:
    """Stream one entity's append-only log into its merged view (peak RSS = one line + the materialized set).
    Enforces the given envelope limits: a new key is refused past `max_keys`/`max_bytes_per_key`/
    `max_corpus_bytes`, and an existing key may not grow past the byte ceilings; each refusal goes to
    `on_refused(key, kind)` if given (bounded), else into `refused_keys`. All limits None -> unbounded read.
    """
    entity = Path(path).stem
    try:
        with open(path, "rb") as fh:
            return _fold_observation_stream(
                fh, entity, max_keys=max_keys,
                max_bytes_per_key=max_bytes_per_key,
                max_corpus_bytes=max_corpus_bytes, on_refused=on_refused,
                require_newline=require_newline,
            )
    except FileNotFoundError:
        return FoldedLog(status="absent", reason="no observation log")
    except OSError as e:
        return FoldedLog(status="unusable", reason=f"{type(e).__name__}: {e}")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


#: directories under recon/ that are not runs (one authority, so no enumerator re-lists them as runs).
RESERVED_RECON_DIRS = RUN_RESERVED_IDS

# Identity documents are tiny today.  Bound an untrusted repository read so a planted file cannot make
# `status`/`latest` allocate without limit before it has even established which run it is reading.
_MAX_IDENTITY_BYTES = 4 * 1024 * 1024
_DIR_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) \
                  | getattr(os, "O_CLOEXEC", 0)
_FILE_OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0))
_MALFORMED_IDENTITY = object()


class _InvalidRunIdentity(ContractError):
    """One run's identity is structurally unsafe, malformed, or contradictory."""


def _identity_stat(fd: int) -> tuple[int, int, int, int, int, int, int]:
    """The fields that must remain stable while one identity document is read."""
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


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


def _read_identity_file(run_fd: int, name: str):
    """Read one identity document relative to an already-open run directory.

    Missing and malformed regular contents are recoverable compatibility states when the other identity
    is valid.  Anything present must still be a stable regular file opened no-follow: an unsafe object is
    repository damage, not a malformed document that another file may mask.
    """
    owner = _OwnedDescriptor()
    settlement = _SettlementOwner(
        lambda: _settle_descriptor_owners((owner,), "run identity descriptor"),
    )
    try:
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                owner.open(name, _FILE_OPEN_FLAGS, dir_fd=run_fd)
                fd = owner.fd
                before = _identity_stat(fd)
                if not stat.S_ISREG(before[2]):
                    raise _InvalidRunIdentity(f"run identity {name} is not a regular file")
                chunks: list[bytes] = []
                size = 0
                while True:
                    chunk = os.read(fd, min(65536, _MAX_IDENTITY_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > _MAX_IDENTITY_BYTES:
                        if _identity_stat(fd) != before:
                            raise _InvalidRunIdentity(f"run identity {name} changed while it was being read")
                        return _MALFORMED_IDENTITY
                if _identity_stat(fd) != before:
                    raise _InvalidRunIdentity(f"run identity {name} changed while it was being read")
                try:
                    value = json.loads(b"".join(chunks).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
                    return _MALFORMED_IDENTITY
                if not isinstance(value, dict):
                    return _MALFORMED_IDENTITY
                return value
    except FileNotFoundError:
        return None
    except OSError as e:
        error = _InvalidRunIdentity if e.errno in (errno.ELOOP, errno.ENOTDIR) else ContractError
        raise error(f"run identity {name} cannot be opened safely: {type(e).__name__}: {e}") from e


def _validated_identity_record(record: dict, name: str, run_id: str) -> "tuple[dict, datetime] | None":
    recorded_id = record.get("run_id")
    target = record.get("target")
    started = _parse_started(record.get("started"))
    if not valid_run_id(recorded_id) or not isinstance(target, str) or not target.strip() or started is None:
        return None
    if recorded_id != run_id:
        raise _InvalidRunIdentity(f"run identity {name} names {recorded_id!r}, not directory {run_id!r}")
    return record, started


def _run_identity_from_fd(run_fd: int, run_id: str) -> "tuple[dict, datetime]":
    """Reconcile every present identity authority below one no-follow-opened run directory."""
    records = []
    for name in ("run.json", "manifest.json"):
        record = _read_identity_file(run_fd, name)
        if record is None or record is _MALFORMED_IDENTITY:
            continue
        validated = _validated_identity_record(record, name, run_id)
        if validated is not None:
            records.append((name, *validated))
    if not records:
        raise _InvalidRunIdentity(f"run {run_id!r} has no well-formed run.json or manifest.json identity")
    authority_name, authority, started = records[0]
    expected = (authority["run_id"], authority["target"], authority["started"])
    for name, record, _parsed in records[1:]:
        observed = (record["run_id"], record["target"], record["started"])
        if observed != expected:
            raise _InvalidRunIdentity(f"run identities {authority_name} and {name} disagree on "
                                      "run_id, target or started")
    return authority, started


def _run_creation_pending(run_fd: int) -> bool:
    """Whether current-code Run.create has not exposed its completed transaction."""
    try:
        observed = os.stat(".creation-pending", dir_fd=run_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if (not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o600):
        raise _InvalidRunIdentity("run creation-pending marker is unsafe")
    return True


def _open_run_fd_into(
    destination: "_OwnedDescriptor",
    project_dir: Path,
    run_id: str,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    """Adopt an exact Run descriptor into a caller-owned stable slot.

    The caller allocates ``destination`` and activates its settlement fences
    before entering this function.  There is consequently no raw descriptor
    return value that can be interrupted before the caller records ownership.
    This function independently fences its temporary repository-root anchor and
    also reconciles ``destination`` until its handoff has committed.
    """
    if type(destination) is not _OwnedDescriptor:
        raise TypeError("run descriptor destination must be an exact owner")
    if destination.fd >= 0 or destination.terminal:
        raise ContractError("run descriptor destination is already used")
    if (expected_identity is not None
            and destination.expected_identity not in {None, expected_identity}):
        raise ContractError("run descriptor destination expects a different identity")
    if expected_identity is not None:
        destination.expected_identity = expected_identity
    run_id = validate_run_id(run_id)                 # before the id participates in any path/open operation
    root_owner = _OwnedDescriptor()
    handed_off = False

    def settle_open() -> None:
        owners = (root_owner,) if handed_off else (destination, root_owner)
        _settle_descriptor_owners(owners, "run-open descriptors")

    settlement = _SettlementOwner(settle_open)
    key = _run_lock_key(Path(project_dir), run_id)
    _projects, held = _thread_mutation_ledgers()
    entry = held.get(key)
    root = Path(project_dir) / "recon"
    try:
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                if type(entry) is _RunMutationLedgerEntry and entry.depth > 0:
                    entry.owner.validate_live()
                    observed_identity = entry.owner.run._run_directory_identity
                    if (destination.expected_identity is not None
                            and destination.expected_identity != observed_identity):
                        raise ContractError(f"run {run_id!r} expected identity changed")
                    destination.expected_identity = observed_identity
                    destination.duplicate(entry.owner.run_anchor.fd)
                else:
                    root_owner.open(root, _DIR_OPEN_FLAGS)
                    destination.open(run_id, _DIR_OPEN_FLAGS, dir_fd=root_owner.fd)
                handed_off = True
    except FileNotFoundError as e:
        raise FileNotFoundError(f"run {run_id!r} not found under {root}") from e
    except OSError as e:
        raise ContractError(f"run {run_id!r} cannot be opened safely under {root}: "
                            f"{type(e).__name__}: {e}") from e


def _open_run_fd(
    project_dir: Path, run_id: str,
    *, expected_identity: tuple[int, int] | None = None,
) -> int:
    """Compatibility shim pending migration to ``_open_run_fd_into``."""
    owner = _OwnedDescriptor(expected_identity)
    _open_run_fd_into(
        owner, project_dir, run_id, expected_identity=expected_identity,
    )
    return owner.release()


def read_run_identity(project_dir: Path, run_id: str) -> dict:
    """Read one reconciled run identity without creating or repairing repository state."""
    run_id = validate_run_id(run_id)
    owner = _OwnedDescriptor()
    settlement = _SettlementOwner(
        lambda: _settle_descriptor_owners((owner,), "run identity anchor"),
    )
    with _SettlementFence(settlement):
        with _SettlementFence(settlement):
            _open_run_fd_into(owner, Path(project_dir), run_id)
            if _run_creation_pending(owner.fd):
                raise _InvalidRunIdentity(f"run {run_id!r} creation is incomplete")
            identity, _started = _run_identity_from_fd(owner.fd, run_id)
            return dict(identity)


def read_run_creation_target(project_dir: Path, run_id: str) -> str:
    """Read the target from a child's no-follow creation record.

    Campaign recovery deliberately does not require an interpretable ``started`` timestamp here: budget
    accounting owns that separate question and can fail closed only when a budget was requested.  The
    directory/run ID and target still reconcile with any readable manifest identity.
    """
    run_id = validate_run_id(run_id)
    owner = _OwnedDescriptor()
    settlement = _SettlementOwner(
        lambda: _settle_descriptor_owners((owner,), "run creation anchor"),
    )
    with _SettlementFence(settlement):
        with _SettlementFence(settlement):
            _open_run_fd_into(owner, Path(project_dir), run_id)
            run_fd = owner.fd
            if _run_creation_pending(run_fd):
                raise _InvalidRunIdentity(f"run {run_id!r} creation is incomplete")
            creation = _read_identity_file(run_fd, "run.json")
            if creation is None or creation is _MALFORMED_IDENTITY or not isinstance(creation, dict):
                raise _InvalidRunIdentity(f"run {run_id!r} has no readable run.json creation record")
            if creation.get("run_id") != run_id:
                raise _InvalidRunIdentity(
                    f"run.json names {creation.get('run_id')!r}, not directory {run_id!r}",
                )
            target = creation.get("target")
            if type(target) is not str or not target.strip():
                raise _InvalidRunIdentity(f"run {run_id!r} creation record names no target")
            manifest = _read_identity_file(run_fd, "manifest.json")
            if isinstance(manifest, dict):
                manifest_id, manifest_target = manifest.get("run_id"), manifest.get("target")
                if type(manifest_id) is str and manifest_id != run_id:
                    raise _InvalidRunIdentity(
                        f"manifest.json names {manifest_id!r}, not directory {run_id!r}",
                    )
                if type(manifest_target) is str and manifest_target.strip() and manifest_target != target:
                    raise _InvalidRunIdentity("run.json and manifest.json disagree on target")
            return target


def _snapshot_one_run(
    root: Path,
    name: str,
    root_owner: "_OwnedDescriptor",
):
    run_owner = _OwnedDescriptor()
    settlement = _SettlementOwner(
        lambda: _settle_descriptor_owners((run_owner,), "run enumeration descriptor"),
    )
    try:
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                run_owner.open(name, _DIR_OPEN_FLAGS, dir_fd=root_owner.fd)
                if _run_creation_pending(run_owner.fd):
                    return None
                identity, started = _run_identity_from_fd(run_owner.fd, name)
                return started, name, root / name, identity, run_owner.identity
    except _InvalidRunIdentity:
        return None
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
            return None
        raise ContractError(
            f"run {name!r} cannot be opened while enumerating {root}: "
            f"{type(exc).__name__}: {exc}",
        ) from exc


def _enumerate_run_snapshots(
    root: Path,
    root_owner: "_OwnedDescriptor",
) -> "list[tuple[datetime, str, Path, dict, tuple[int, int]]]":
    """Enumerate under already-active root descriptor settlement fences."""
    runs = []
    names = os.listdir(root_owner.fd)
    for name in names:
        if not valid_run_id(name):
            continue
        snapshot = _snapshot_one_run(root, name, root_owner)
        if snapshot is not None:
            runs.append(snapshot)
    return runs


def _run_snapshots(
    project_dir: Path,
) -> "list[tuple[datetime, str, Path, dict, tuple[int, int]]]":
    """Validated identity snapshots for selectable runs, oldest first.

    Each identity is read exactly once through a no-follow run descriptor.  Consumers carry this snapshot
    forward rather than reopening path metadata; the later repository-authority slice will pin descriptor
    lifetime across mutations as well.
    """
    root = Path(project_dir) / "recon"
    root_owner = _OwnedDescriptor()
    settlement = _SettlementOwner(
        lambda: _settle_descriptor_owners(
            (root_owner,), "run enumeration descriptors",
        ),
    )
    try:
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                root_owner.open(root, _DIR_OPEN_FLAGS)
                runs = _enumerate_run_snapshots(root, root_owner)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise ContractError(f"repository root {root} cannot be listed safely: "
                            f"{type(e).__name__}: {e}") from e
    runs.sort(key=lambda item: (item[0], item[1]))
    return runs


def validate_target(target: str) -> str:
    """Return a non-empty exact target identity, or refuse before repository side effects."""
    if type(target) is not str or not target.strip():
        raise ContractError("a run target must be a non-empty string")
    return target


def _atomic_write(path: Path, text: str) -> None:
    """Write via a same-directory temp + os.replace, so a reader never sees a half-written file and a
    crash mid-write leaves the previous version intact. Created 0600, O_NOFOLLOW: sensitive from creation,
    never chmod-after-write."""
    from . import privfs
    privfs.write_private(path, text)


def _write_all_descriptor(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("repository descriptor write made no progress")
        view = view[written:]


#: every key `Run._run_summary` emits. A committed summary carries all of them, so a partial object is
#: recognised as damage instead of being reconciled into the verdict its missing keys were to carry.
SUMMARY_KEYS = frozenset({"verdict", "tool_status", "tools_failed", "failures", "gaps",
                          "phase_exceptions", "coverage", "coverage_limits", "remainders", "faults",
                          "provider_spend", "provider_limits", "operator_limits"})


def summary_well_formed(summary) -> bool:
    """Whether a stored summary is the shape the writer emits. A dict missing required keys is damage: an
    empty one reconciles to `verdict: complete` because it carries nothing to contradict it."""
    return isinstance(summary, dict) and SUMMARY_KEYS.issubset(summary)


def manifest_committed(manifest_path) -> bool:
    """Whether a base manifest is committed — the one rule, so every reader agrees on what a commitment is.

    Readable, carrying exact non-negative entity counters and a well-formed summary. A manifest whose
    shape cannot be trusted is a damaged file: reading a commitment out of it would let a run that never
    sealed, or one whose record was mangled, report a verdict it never reached.
    """
    manifest = _read_json(manifest_path)
    if not isinstance(manifest, dict):
        return False
    counts = manifest.get("entity_counts")
    if not isinstance(counts, dict):
        return False
    # `type is int` rejects a bool counter, and a negative one is not a count of anything
    if not all(isinstance(k, str) and type(v) is int and v >= 0 for k, v in counts.items()):
        return False
    return summary_well_formed(manifest.get("summary"))


def _verdict_for(summary: dict) -> str:
    """The one verdict rule, read from a serialized summary, so the in-process fold and the manifest
    reconciliation cannot drift apart. Gaps dominate; a limit only lifts an otherwise-clean run."""
    challenged = [f for f in summary.get("faults") or [] if (f or {}).get("challenges_completeness")]
    if summary.get("failures") or summary.get("gaps") or summary.get("phase_exceptions") or challenged:
        return "complete_with_gaps"
    limits = ((summary.get("coverage_limits") or []) + (summary.get("provider_limits") or [])
              + (summary.get("operator_limits") or []))
    return "complete_with_limits" if limits else "complete"


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
    depends_on: str = ""               # registry bin this source needs; the source→tool edge the verdict reads


@dataclass(frozen=True)
class _PreparedManifest:
    """Opaque bytes computed while base evidence is still mutable.

    Publication happens only after ``begin_finalization`` has flushed and
    sealed that base.  Keeping serialized bytes here prevents a post-seal
    manifest build from lazily folding or repairing canonical evidence.
    """

    run_id: str
    target: str
    manifest_text: str
    history_text: str


def _preferred_settlement_fault(
    primary: BaseException | None,
    faults: list[BaseException],
) -> BaseException | None:
    """Prefer the operation's cancellation, then any cleanup cancellation.

    Cleanup is allowed to add diagnostic faults, but an operator's exact
    ``KeyboardInterrupt``/``SystemExit`` object is the control-flow authority.
    """
    if primary is not None and not isinstance(primary, Exception):
        return primary
    cancellation = next(
        (fault for fault in faults if not isinstance(fault, Exception)), None,
    )
    return cancellation or primary or (faults[0] if faults else None)


class _OwnedDescriptor:
    """Mutable ownership slot spanning a syscall/result-assignment boundary.

    The allocation result is assigned directly into this object on the same
    source line as the call.  A later one-shot line cancellation can therefore
    be reconciled by a second close pass instead of losing a raw integer in a
    dead frame.  ``expected_identity`` is mandatory for exposed descriptors;
    internal, never-exposed descriptors adopt their identity after allocation.
    """

    __slots__ = ("fd", "identity", "expected_identity", "terminal")

    def __init__(self, expected_identity: tuple[int, int] | None = None) -> None:
        self.fd = -1
        self.identity = None
        self.expected_identity = expected_identity
        self.terminal = False

    def _prepare_allocation(self) -> None:
        if self.fd >= 0:
            raise ContractError("repository descriptor ownership slot is already used")
        self.terminal = False

    def _finish_allocation(self) -> int:
        if self.fd < 0:
            raise ContractError("repository descriptor allocator did not adopt a descriptor")
        observed = os.fstat(self.fd)
        self.identity = (observed.st_dev, observed.st_ino)
        if (self.expected_identity is not None
                and self.identity != self.expected_identity):
            raise ContractError("repository descriptor identity changed during allocation")
        return self.fd

    def open(self, path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        """Open directly into this stable slot; no callback-return adoption gap."""
        self._prepare_allocation()
        self.fd = os.open(path, flags, mode, dir_fd=dir_fd)
        return self._finish_allocation()

    def duplicate(self, source_fd: int) -> int:
        """Duplicate directly into this stable slot."""
        self._prepare_allocation()
        self.fd = os.dup(source_fd)
        return self._finish_allocation()

    def allocate_into(self, allocate) -> int:
        """Let a strict helper adopt its result before it can return or raise.

        The callback receives this owner and must call ``adopt``.  Unlike the
        former callback-return API, a callback that adopts and then raises
        leaves the descriptor visible to the already-active settlement fence.
        """
        self._prepare_allocation()
        allocate(self)
        return self._finish_allocation()

    def adopt(self, fd: int) -> int:
        """Adopt a descriptor from inside an owner-aware allocation callback."""
        if self.fd >= 0:
            raise ContractError("repository descriptor ownership slot is already used")
        self.fd = fd
        return fd
    def close_once(self) -> BaseException | None:
        """Attempt one authenticated close and monotonically reconcile its result."""
        if self.terminal:
            return None
        if self.fd < 0:
            return None
        try:
            observed = os.fstat(self.fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                self.fd = -1
                self.terminal = True
                return None
            return exc
        except BaseException as exc:
            return exc
        identity = (observed.st_dev, observed.st_ino)
        # ``identity`` records the object this slot actually adopted.  The
        # separately declared ``expected_identity`` validates that adoption,
        # but a mismatch must still close the newly owned (wrong) descriptor.
        expected = self.identity
        if expected is not None and identity != expected:
            # The exact owned descriptor was already closed and its integer was
            # reused.  Never close the new owner's descriptor.
            self.fd = -1
            self.terminal = True
            return ContractError("repository descriptor number was reused")
        try:
            os.close(self.fd)
        except BaseException as exc:
            # A real source-line cancellation happens before ``os.close`` and a
            # second pass may safely retry.  If close committed before reporting
            # a fault, EBADF proves the owned descriptor is already terminal.
            try:
                os.fstat(self.fd)
            except OSError as observed_error:
                if observed_error.errno == errno.EBADF:
                    self.fd = -1
                    self.terminal = True
            except BaseException:
                pass
            return exc
        self.fd = -1
        self.terminal = True
        return None

    def release(self) -> int:
        """Transfer an authenticated live descriptor out of this owner."""
        if self.fd < 0 or self.terminal or self.identity is None:
            raise ContractError("repository descriptor owner has nothing to release")
        observed = os.fstat(self.fd)
        if (observed.st_dev, observed.st_ino) != self.identity:
            raise ContractError("repository descriptor identity changed before release")
        result = self.fd
        self.fd = -1
        self.terminal = True
        return result


def _open_strict_directory_into(
    destination: _OwnedDescriptor,
    anchor_fd: int,
    components: tuple[str, ...],
) -> None:
    """Walk strict directories and adopt the final descriptor before return."""
    from . import privfs
    components = privfs.validate_relative_components(components)
    walkers = [_OwnedDescriptor(), _OwnedDescriptor()]
    current_index = 0
    handed_off = False

    def settle_walk() -> None:
        owned = tuple(walkers) if handed_off else (destination, *walkers)
        _settle_descriptor_owners(owned, "strict directory walk descriptors")

    settlement = _SettlementOwner(settle_walk)
    with _SettlementFence(settlement):
        with _SettlementFence(settlement):
            walkers[current_index].duplicate(anchor_fd)
            for index, component in enumerate(components):
                final = index == len(components) - 1
                child = destination if final else walkers[1 - current_index]
                _open_strict_directory_child(
                    child, walkers[current_index].fd, component,
                    components[:index + 1],
                )
                observed = os.fstat(child.fd)
                if (not stat.S_ISDIR(observed.st_mode)
                        or observed.st_uid != os.geteuid()
                        or stat.S_IMODE(observed.st_mode) != 0o700):
                    raise ContractError("managed directory identity is unsafe")
                _settle_descriptor_owners(
                    (walkers[current_index],), "strict directory walk descriptor",
                )
                if not final:
                    current_index = 1 - current_index
            if not components:
                destination.duplicate(walkers[current_index].fd)
            handed_off = True


def _open_strict_directory_child(
    destination: _OwnedDescriptor,
    parent_fd: int,
    component: str,
    traversed: tuple[str, ...],
) -> None:
    """Map a missing strict child outside the descriptor-owning walk frame."""
    from . import privfs
    try:
        destination.open(component, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise privfs.PrivatePathMissing(
            "managed path does not exist", components=traversed,
        ) from exc


def _open_strict_file_into(
    destination: _OwnedDescriptor,
    anchor_fd: int,
    components: tuple[str, ...],
) -> None:
    """Open one strict private file directly into a stable destination."""
    from . import privfs
    components = privfs.validate_relative_components(components, allow_empty=False)
    parent = _OwnedDescriptor()
    handed_off = False

    def settle_file_open() -> None:
        owned = (parent,) if handed_off else (destination, parent)
        _settle_descriptor_owners(owned, "strict file open descriptors")

    settlement = _SettlementOwner(
        settle_file_open,
    )
    try:
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                _open_strict_directory_into(parent, anchor_fd, components[:-1])
                destination.open(components[-1], _FILE_OPEN_FLAGS, dir_fd=parent.fd)
                observed = os.fstat(destination.fd)
                if (not stat.S_ISREG(observed.st_mode)
                        or observed.st_uid != os.geteuid()
                        or observed.st_nlink != 1
                        or stat.S_IMODE(observed.st_mode) != 0o600):
                    raise ContractError("managed file identity is unsafe")
                handed_off = True
    except FileNotFoundError as exc:
        raise privfs.PrivatePathMissing(
            "managed path does not exist", components=components,
        ) from exc


def _publish_private_directory_into(
    destination: _OwnedDescriptor,
    parent_fd: int,
    name: str,
    mode: int,
) -> bool:
    """Create, pin and no-replace-publish one exact private directory."""
    from . import privfs
    state = {
        "temporary": f".quarry-dir-{os.urandom(16).hex()}.stage",
        "published": False,
        "kept": False,
    }

    def settle_stage() -> None:
        if state["kept"]:
            return
        if destination.fd >= 0 and destination.identity is not None:
            candidate = name if state["published"] else state["temporary"]
            try:
                named = os.stat(candidate, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                alternate = name if candidate == state["temporary"] else state["temporary"]
                named = os.stat(alternate, dir_fd=parent_fd, follow_symlinks=False)
                candidate = alternate
            if (named.st_dev, named.st_ino) != destination.identity:
                raise ContractError("staged private directory was substituted")
            if candidate == state["temporary"]:
                if os.listdir(destination.fd):
                    raise ContractError("staged private directory is not empty")
                os.rmdir(candidate, dir_fd=parent_fd)
                os.fsync(parent_fd)
            else:
                state["published"] = True
                state["kept"] = True
                return
        _settle_descriptor_owners(
            (destination,), "unpublished private directory descriptor",
        )

    settlement = _SettlementOwner(settle_stage)
    with _SettlementFence(settlement):
        with _SettlementFence(settlement):
            temporary = state["temporary"]
            os.mkdir(temporary, mode, dir_fd=parent_fd); destination.open(temporary, _DIR_OPEN_FLAGS, dir_fd=parent_fd)  # noqa: E702 - one traced settlement seam
            observed = os.fstat(destination.fd)
            if (not stat.S_ISDIR(observed.st_mode)
                    or observed.st_uid != os.geteuid()
                    or stat.S_IMODE(observed.st_mode) != mode):
                raise ContractError("staged private directory is unsafe")
            if not _rename_private_directory_if_absent(
                parent_fd, temporary, name,
            ):
                return False
            state["published"] = True
            os.fsync(parent_fd)
            state["kept"] = True
            return True


def _rename_private_directory_if_absent(
    parent_fd: int, temporary: str, name: str,
) -> bool:
    """Isolate the no-replace EEXIST exception-table boundary."""
    from . import privfs
    try:
        privfs._renameat2_noreplace(parent_fd, temporary, parent_fd, name)
    except FileExistsError:
        return False
    return True


def _open_or_publish_private_directory(
    destination: _OwnedDescriptor,
    parent_fd: int,
    name: str,
    mode: int,
    *, initializing: bool,
) -> bool:
    """Open an established namespace or publish one exact bootstrap inode."""
    created = False
    if initializing:
        created = _publish_private_directory_into(destination, parent_fd, name, mode)
    if destination.fd < 0:
        destination.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (named.st_dev, named.st_ino) != destination.identity:
        raise ContractError("private directory name changed during bootstrap")
    return created


def _settle_descriptor_owners(
    owners: tuple[_OwnedDescriptor, ...], what: str,
) -> None:
    """Close an exact descriptor set and refuse an indeterminate owner."""
    faults = _close_owned_descriptors_twice(owners)
    preferred = _preferred_settlement_fault(None, faults)
    if preferred is not None:
        raise preferred
    if any(owner.fd >= 0 for owner in owners):
        raise ContractError(f"{what} did not settle")


def _close_owned_descriptors_twice(
    owners: tuple[_OwnedDescriptor, ...],
) -> list[BaseException]:
    """Drain every slot twice so one line interruption cannot strand a suffix."""
    faults: list[BaseException] = []
    for _pass in range(2):
        for owner in owners:
            try:
                fault = owner.close_once()
            except BaseException as exc:
                faults.append(exc)
            else:
                if fault is not None:
                    faults.append(fault)
    return faults


class _RunMutationOwner:
    """Stable descriptor authority for one outermost Run mutation epoch."""

    __slots__ = (
        "run", "lock_directory", "state_directory", "lock_file", "lock_record",
        "project_anchor", "recon_root", "run_anchor", "creation_file",
        "claims_root", "claim_registry", "history_directory",
        "history_record", "lock_identity", "initializing",
        "lock_record_durable", "creation_record", "root_locked", "locked",
        "acquired", "terminal", "borrowed_project_anchor",
        "state_created", "locks_created", "history_created",
        "claims_root_created", "claim_registry_created",
        "claim_registry_possible", "claim_registry_stage_name",
        "authority_record_created", "authority_record_durable",
    )

    def __init__(
        self, run, *, initializing: bool = False,
        project_anchor_fd: int | None = None,
    ) -> None:
        self.run = run
        self.lock_directory = _OwnedDescriptor()
        self.state_directory = _OwnedDescriptor()
        self.lock_file = _OwnedDescriptor()
        self.lock_record = _OwnedDescriptor()
        self.project_anchor = _OwnedDescriptor(run._project_directory_identity)
        self.recon_root = _OwnedDescriptor()
        self.run_anchor = _OwnedDescriptor(run._run_directory_identity)
        self.creation_file = _OwnedDescriptor()
        self.claims_root = _OwnedDescriptor()
        self.claim_registry = _OwnedDescriptor()
        self.history_directory = _OwnedDescriptor()
        self.history_record = _OwnedDescriptor()
        self.lock_identity = None
        self.initializing = initializing
        self.lock_record_durable = False
        self.creation_record = None
        self.root_locked = False
        self.locked = False
        self.acquired = False
        self.terminal = False
        self.borrowed_project_anchor = project_anchor_fd
        self.state_created = False
        self.locks_created = False
        self.history_created = False
        self.claims_root_created = False
        self.claim_registry_created = False
        self.claim_registry_possible = False
        self.claim_registry_stage_name = None
        self.authority_record_created = False
        self.authority_record_durable = False

    @property
    def descriptor_owners(self) -> tuple[_OwnedDescriptor, ...]:
        return (
            self.creation_file, self.claim_registry, self.claims_root,
            self.history_directory,
            self.history_record,
            self.run_anchor, self.recon_root, self.project_anchor,
            self.lock_record, self.lock_file,
            self.lock_directory, self.state_directory,
        )

    @property
    def lock_record_name(self) -> str:
        return f"{self.run.run_id}.lock.identity"

    @staticmethod
    def _identity(fd: int) -> tuple[int, int]:
        observed = os.fstat(fd)
        return observed.st_dev, observed.st_ino

    def _validate_named_identities(self) -> None:
        """Both public names must still resolve to the exact pinned objects."""
        project_named = os.stat(self.run.project_dir, follow_symlinks=False)
        if ((project_named.st_dev, project_named.st_ino) != self.run._project_directory_identity
                or self._identity(self.project_anchor.fd) != self.run._project_directory_identity):
            raise ContractError("project directory identity changed")
        recon_named = os.stat(
            "recon", dir_fd=self.project_anchor.fd, follow_symlinks=False,
        )
        if (recon_named.st_dev, recon_named.st_ino) != self._identity(self.recon_root.fd):
            raise ContractError("repository root identity changed")
        state_named = os.stat(
            "state", dir_fd=self.recon_root.fd, follow_symlinks=False,
        )
        if (state_named.st_dev, state_named.st_ino) != self._identity(self.state_directory.fd):
            raise ContractError("repository state directory identity changed")
        locks_named = os.stat(
            "locks", dir_fd=self.state_directory.fd, follow_symlinks=False,
        )
        if (locks_named.st_dev, locks_named.st_ino) != self._identity(self.lock_directory.fd):
            raise ContractError("repository lock directory identity changed")
        claims_named = os.stat(
            "claims", dir_fd=self.state_directory.fd, follow_symlinks=False,
        )
        if (claims_named.st_dev, claims_named.st_ino) != self.claims_root.identity:
            raise ContractError("repository claims directory identity changed")
        registry_named = os.stat(
            self.run.run_id, dir_fd=self.claims_root.fd, follow_symlinks=False,
        )
        if (registry_named.st_dev, registry_named.st_ino) != self.claim_registry.identity:
            raise ContractError("run artifact-claim registry identity changed")
        history_named = os.stat(
            "history", dir_fd=self.state_directory.fd, follow_symlinks=False,
        )
        if (history_named.st_dev, history_named.st_ino) != self.history_directory.identity:
            raise ContractError("repository history directory identity changed")
        history_record_named = os.stat(
            "authority.identity", dir_fd=self.state_directory.fd,
            follow_symlinks=False,
        )
        if ((history_record_named.st_dev, history_record_named.st_ino)
                != self.history_record.identity):
            raise ContractError("repository history identity record changed")
        lock_named = os.stat(
            self.run._lock_path.name, dir_fd=self.lock_directory.fd,
            follow_symlinks=False,
        )
        if (lock_named.st_dev, lock_named.st_ino) != self.lock_identity:
            raise ContractError("repository lock identity changed")
        run_named = os.stat(
            self.run.run_id, dir_fd=self.recon_root.fd, follow_symlinks=False,
        )
        if (run_named.st_dev, run_named.st_ino) != self.run._run_directory_identity:
            raise ContractError(f"run {self.run.run_id!r} directory identity changed")
        if self._identity(self.run_anchor.fd) != self.run._run_directory_identity:
            raise ContractError(f"run {self.run.run_id!r} descriptor identity changed")
        creation_named = os.stat(
            "run.json", dir_fd=self.run_anchor.fd, follow_symlinks=False,
        )
        if ((creation_named.st_dev, creation_named.st_ino) != self.creation_file.identity
                or self._identity(self.creation_file.fd) != self.creation_file.identity):
            raise ContractError("run creation record identity changed")
        record_named = os.stat(
            self.lock_record_name, dir_fd=self.lock_directory.fd,
            follow_symlinks=False,
        )
        if ((record_named.st_dev, record_named.st_ino) != self.lock_record.identity
                or self._identity(self.lock_record.fd) != self.lock_record.identity):
            raise ContractError("repository lock identity record changed")
        os.lseek(self.creation_file.fd, 0, os.SEEK_SET)
        raw_creation = os.read(self.creation_file.fd, _MAX_IDENTITY_BYTES + 1)
        try:
            creation = json.loads(raw_creation.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ContractError("run creation record is unreadable") from None
        if (not isinstance(creation, dict)
                or creation.get("mutation_lock") != self._lock_witness
                or creation.get("artifact_claims") != self._claims_witness
                or creation.get("project_state") != self._project_state_witness):
            raise ContractError("run creation mutation-lock witness changed")
        os.lseek(self.lock_record.fd, 0, os.SEEK_SET)
        raw_record = os.read(self.lock_record.fd, 4097)
        try:
            lock_record = json.loads(raw_record.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ContractError("repository lock identity record is unreadable") from None
        expected_record = {
            "schema_version": 1, "run_id": self.run.run_id,
            "device": self.lock_identity[0], "inode": self.lock_identity[1],
        }
        if lock_record != expected_record:
            raise ContractError("repository lock identity record changed")
        os.lseek(self.history_record.fd, 0, os.SEEK_SET)
        raw_history_record = os.read(self.history_record.fd, 4097)
        try:
            history_record = json.loads(raw_history_record.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ContractError("repository history identity record is unreadable") from None
        expected_history_record = {
            "schema_version": 1,
            "state_device": self.state_directory.identity[0],
            "state_inode": self.state_directory.identity[1],
            "locks_device": self.lock_directory.identity[0],
            "locks_inode": self.lock_directory.identity[1],
            "claims_device": self.claims_root.identity[0],
            "claims_inode": self.claims_root.identity[1],
            "history_device": self.history_directory.identity[0],
            "history_inode": self.history_directory.identity[1],
        }
        if history_record != expected_history_record:
            raise ContractError("repository history identity record changed")

    @property
    def _shared_authority_payload(self) -> dict:
        return {
            "schema_version": 1,
            "state_device": self.state_directory.identity[0],
            "state_inode": self.state_directory.identity[1],
            "locks_device": self.lock_directory.identity[0],
            "locks_inode": self.lock_directory.identity[1],
            "claims_device": self.claims_root.identity[0],
            "claims_inode": self.claims_root.identity[1],
            "history_device": self.history_directory.identity[0],
            "history_inode": self.history_directory.identity[1],
        }

    def _bind_shared_authority(self, *, create: bool) -> None:
        """Open the bootstrap-only project-state namespace identity record."""
        from . import privfs
        flags = os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        if create:
            self.authority_record_created = True
            flags |= os.O_CREAT | os.O_EXCL
        try:
            self.history_record.open(
                "authority.identity", flags, privfs.FILE_MODE,
                dir_fd=self.state_directory.fd,
            )
        except FileNotFoundError as exc:
            raise ContractError("repository shared authority record is missing") from exc
        except FileExistsError as exc:
            raise ContractError("repository shared authority record already exists") from exc
        observed = os.fstat(self.history_record.fd)
        named = os.stat(
            "authority.identity", dir_fd=self.state_directory.fd,
            follow_symlinks=False,
        )
        if (not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE
                or (named.st_dev, named.st_ino) != self.history_record.identity
                or observed.st_size > 4096):
            raise ContractError("repository shared authority record is unsafe")
        if create:
            payload = json.dumps(
                self._shared_authority_payload, sort_keys=True,
            ).encode("utf-8")
            os.fchmod(self.history_record.fd, privfs.FILE_MODE)
            _write_all_descriptor(self.history_record.fd, payload)
            os.fsync(self.history_record.fd)
            os.fsync(self.state_directory.fd)
            self.authority_record_durable = True
        os.lseek(self.history_record.fd, 0, os.SEEK_SET)
        raw = os.read(self.history_record.fd, 4097)
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ContractError("repository shared authority record is unreadable") from None
        if record != self._shared_authority_payload:
            raise ContractError("repository shared authority identity changed")

    def _shared_authority_exists(self) -> bool:
        try:
            os.stat(
                "authority.identity", dir_fd=self.state_directory.fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        return True

    def _shared_namespace_has_run_witness(self) -> bool:
        for name in os.listdir(self.recon_root.fd):
            if name == self.run.run_id or not valid_run_id(name):
                continue
            candidate = _OwnedDescriptor()
            settlement = _SettlementOwner(
                lambda: _settle_descriptor_owners(
                    (candidate,), "shared authority witness descriptor",
                ),
            )
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    try:
                        candidate.open(name, _DIR_OPEN_FLAGS, dir_fd=self.recon_root.fd)
                    except FileNotFoundError:
                        continue
                    creation = _read_identity_file(candidate.fd, "run.json")
                    if (isinstance(creation, dict)
                            and creation.get("run_id") == name
                            and isinstance(creation.get("project_state"), dict)):
                        return True
        return False

    def _validate_shared_consensus(self) -> None:
        """Require an older Run witness before adopting established shared state."""
        witnessed = False
        for name in os.listdir(self.recon_root.fd):
            if name == self.run.run_id or not valid_run_id(name):
                continue
            candidate = _OwnedDescriptor()
            settlement = _SettlementOwner(
                lambda: _settle_descriptor_owners(
                    (candidate,), "shared authority witness descriptor",
                ),
            )
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    try:
                        candidate.open(name, _DIR_OPEN_FLAGS, dir_fd=self.recon_root.fd)
                    except FileNotFoundError:
                        continue
                    creation = _read_identity_file(candidate.fd, "run.json")
                    if not isinstance(creation, dict):
                        continue
                    if creation.get("run_id") != name:
                        continue
                    project_state = creation.get("project_state")
                    if not isinstance(project_state, dict):
                        raise ContractError(
                            "legacy repository shared authority requires explicit repair",
                        )
                    if project_state != self._project_state_witness:
                        raise ContractError("repository shared authority witness changed")
                    claims = creation.get("artifact_claims")
                    if (not isinstance(claims, dict)
                            or claims.get("root_device") != self.claims_root.identity[0]
                            or claims.get("root_inode") != self.claims_root.identity[1]):
                        raise ContractError("repository claims authority witness changed")
                    witnessed = True
        if not witnessed:
            raise ContractError(
                "repository shared authority has no creation-bound Run witness",
            )

    def _bind_durable_lock_identity(self) -> None:
        """Create-once binding from the public lock name to its exact inode.

        ``O_EXCL`` is the bootstrap arbitration.  If two different lock inodes
        are flocked during a name-substitution race, only one contender can
        create this record; the other opens the winner's record and fails the
        exact identity comparison.  An interrupted creator may leave an
        incomplete record, which safely terminalizes future acquisition rather
        than allowing another identity to replace it.
        """
        from . import privfs
        if self.initializing:
            try:
                self.lock_record.open(
                    self.lock_record_name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    privfs.FILE_MODE,
                    dir_fd=self.lock_directory.fd,
                )
            except FileExistsError as exc:
                raise ContractError("repository lock identity record already exists during creation") from exc
        else:
            try:
                self.lock_record.open(
                    self.lock_record_name, os.O_RDWR | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=self.lock_directory.fd,
                )
            except FileNotFoundError as exc:
                raise ContractError("repository lock identity record is missing") from exc
        if self.initializing:
            payload = json.dumps({
                "schema_version": 1,
                "run_id": self.run.run_id,
                "device": self.lock_identity[0],
                "inode": self.lock_identity[1],
            }, sort_keys=True).encode("utf-8")
            os.fchmod(self.lock_record.fd, privfs.FILE_MODE)
            _write_all_descriptor(self.lock_record.fd, payload)
            os.fsync(self.lock_record.fd)
            os.fsync(self.lock_directory.fd)
        observed = os.fstat(self.lock_record.fd)
        named = os.stat(
            self.lock_record_name, dir_fd=self.lock_directory.fd,
            follow_symlinks=False,
        )
        if (not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE
                or (named.st_dev, named.st_ino) != (observed.st_dev, observed.st_ino)
                or observed.st_size > 4096):
            raise ContractError("repository lock identity record is unsafe")
        os.lseek(self.lock_record.fd, 0, os.SEEK_SET)
        raw = os.read(self.lock_record.fd, 4097)
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ContractError("repository lock identity record is unreadable") from None
        expected = {
            "schema_version": 1,
            "run_id": self.run.run_id,
            "device": self.lock_identity[0],
            "inode": self.lock_identity[1],
        }
        if record != expected:
            raise ContractError("repository lock identity changed")

    @property
    def _lock_witness(self) -> dict:
        return {
            "schema_version": 1,
            "device": self.lock_identity[0],
            "inode": self.lock_identity[1],
        }

    @property
    def _claims_witness(self) -> dict:
        return {
            "schema_version": 1,
            "root_device": self.claims_root.identity[0],
            "root_inode": self.claims_root.identity[1],
            "registry_device": self.claim_registry.identity[0],
            "registry_inode": self.claim_registry.identity[1],
        }

    @property
    def _project_state_witness(self) -> dict:
        return {
            "schema_version": 1,
            "state_device": self.state_directory.identity[0],
            "state_inode": self.state_directory.identity[1],
            "locks_device": self.lock_directory.identity[0],
            "locks_inode": self.lock_directory.identity[1],
            "claims_device": self.claims_root.identity[0],
            "claims_inode": self.claims_root.identity[1],
            "history_device": self.history_directory.identity[0],
            "history_inode": self.history_directory.identity[1],
            "record_device": self.history_record.identity[0],
            "record_inode": self.history_record.identity[1],
        }

    def _bind_run_creation_witness(self) -> None:
        """Bind the lock to immutable identity inside the pinned Run itself.

        The sibling sidecar is useful for create-once arbitration, but it is not
        a trust root: an attacker could rename a lock and its self-described
        sidecar together.  ``run.json`` was claimed with the Run directory and
        is the creation-bound authority every later acquisition must reconcile.
        Legacy records without this witness fail closed rather than silently
        adopting whatever lock name happens to exist.
        """
        from . import privfs
        creation = _read_identity_file(self.run_anchor.fd, "run.json")
        if not isinstance(creation, dict):
            raise ContractError("run creation identity is unavailable for mutation locking")
        if self.initializing:
            if "mutation_lock" in creation:
                raise ContractError("run creation identity already has a mutation-lock witness")
            self.creation_record = dict(creation)
            creation = dict(creation)
            creation["mutation_lock"] = self._lock_witness
            creation["artifact_claims"] = self._claims_witness
            creation["project_state"] = self._project_state_witness
            stage = None
            try:
                stage = privfs.stage_private_bytes(
                    self.run_anchor.fd, ("run.json",),
                    json.dumps(creation).encode("utf-8"),
                )
                privfs.replace_private_stage(stage)
            except BaseException:
                if stage is not None:
                    try:
                        privfs.abort_private_stage(stage)
                    except BaseException:
                        pass
                raise
            creation = _read_identity_file(self.run_anchor.fd, "run.json")
        if (not isinstance(creation, dict)
                or creation.get("mutation_lock") != self._lock_witness
                or creation.get("artifact_claims") != self._claims_witness
                or creation.get("project_state") != self._project_state_witness):
            raise ContractError("run creation mutation-lock witness changed")
        self.creation_file.open("run.json", _FILE_OPEN_FLAGS, dir_fd=self.run_anchor.fd)
        creation_stat = os.fstat(self.creation_file.fd)
        if (not stat.S_ISREG(creation_stat.st_mode)
                or creation_stat.st_uid != os.geteuid()
                or creation_stat.st_nlink != 1):
            raise ContractError("run creation record is unsafe")
        if self.initializing:
            self.lock_record_durable = True

    def _fence_incomplete_bootstrap(self) -> None:
        """Remove only the exact incomplete names created by Run creation."""
        if not self.initializing or self.lock_record_durable:
            return
        if self.creation_record is not None and self.run_anchor.fd >= 0:
            from . import privfs
            observed_creation = _read_identity_file(self.run_anchor.fd, "run.json")
            if (isinstance(observed_creation, dict)
                    and observed_creation.get("mutation_lock") == self._lock_witness):
                stage = privfs.stage_private_bytes(
                    self.run_anchor.fd, ("run.json",),
                    json.dumps(self.creation_record).encode("utf-8"),
                )
                try:
                    privfs.replace_private_stage(stage)
                except BaseException:
                    try:
                        privfs.abort_private_stage(stage)
                    except BaseException:
                        pass
                    raise
            elif (not isinstance(observed_creation, dict)
                  or "mutation_lock" in observed_creation):
                raise ContractError("incomplete Run lock witness changed")
        if self.lock_directory.fd >= 0:
            for name, identity in (
                (self.lock_record_name, self.lock_record.identity),
                (self.run._lock_path.name, self.lock_identity or self.lock_file.identity),
            ):
                if identity is None:
                    continue
                try:
                    observed = os.stat(name, dir_fd=self.lock_directory.fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if (observed.st_dev, observed.st_ino) != identity:
                    raise ContractError("incomplete repository lock identity was substituted")
                os.unlink(name, dir_fd=self.lock_directory.fd)
            os.fsync(self.lock_directory.fd)
        if self.claim_registry_possible and self.claims_root.fd >= 0:
            registry = self.claim_registry
            public_name = self.run.run_id
            if registry.fd < 0:
                raise ContractError("incomplete claim registry lost its descriptor")
            try:
                named = os.stat(
                    public_name, dir_fd=self.claims_root.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                candidates = []
                for candidate in os.listdir(self.claims_root.fd):
                    if not (candidate.startswith(".quarry-claim-")
                            and candidate.endswith(".stage")):
                        continue
                    observed = os.stat(
                        candidate, dir_fd=self.claims_root.fd,
                        follow_symlinks=False,
                    )
                    if (observed.st_dev, observed.st_ino) == registry.identity:
                        candidates.append(candidate)
                if len(candidates) != 1:
                    raise ContractError("incomplete claim registry name is indeterminate")
                public_name = candidates[0]
                named = os.stat(
                    public_name, dir_fd=self.claims_root.fd,
                    follow_symlinks=False,
                )
            if (named.st_dev, named.st_ino) != registry.identity:
                raise ContractError("incomplete claim registry was substituted")
            if os.listdir(registry.fd):
                raise ContractError("incomplete claim registry is not empty")
            os.rmdir(public_name, dir_fd=self.claims_root.fd)
            os.fsync(self.claims_root.fd)
        if self.authority_record_created and self.history_record.identity is not None:
            named = os.stat(
                "authority.identity", dir_fd=self.state_directory.fd,
                follow_symlinks=False,
            )
            if (named.st_dev, named.st_ino) != self.history_record.identity:
                raise ContractError("incomplete shared authority record was substituted")
            os.unlink("authority.identity", dir_fd=self.state_directory.fd)
        for name, parent, descriptor, created in (
            ("history", self.state_directory, self.history_directory, self.history_created),
            ("claims", self.state_directory, self.claims_root, self.claims_root_created),
            ("locks", self.state_directory, self.lock_directory, self.locks_created),
            ("state", self.recon_root, self.state_directory, self.state_created),
        ):
            if not created or descriptor.identity is None:
                continue
            named = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != descriptor.identity:
                raise ContractError("incomplete shared authority directory was substituted")
            if os.listdir(descriptor.fd):
                raise ContractError("incomplete shared authority directory is not empty")
            os.rmdir(name, dir_fd=parent.fd)
            os.fsync(parent.fd)

    def acquire(self) -> None:
        """Pin lock and Run names, take the flock, then reconcile both names."""
        if self.acquired or self.terminal:
            raise ContractError("repository mutation owner is already used")
        from . import privfs
        if self.borrowed_project_anchor is None:
            self.project_anchor.open(self.run.project_dir, _DIR_OPEN_FLAGS)
            fcntl.flock(self.project_anchor.fd, fcntl.LOCK_EX)
            self.root_locked = True
        else:
            self.project_anchor.duplicate(self.borrowed_project_anchor)
        self.recon_root.open("recon", _DIR_OPEN_FLAGS, dir_fd=self.project_anchor.fd)
        self.run_anchor.open(self.run.run_id, _DIR_OPEN_FLAGS, dir_fd=self.recon_root.fd)
        for name, parent, destination, created_attribute in (
            ("state", self.recon_root, self.state_directory, "state_created"),
            ("locks", self.state_directory, self.lock_directory, "locks_created"),
        ):
            try:
                setattr(
                    self, created_attribute,
                    _open_or_publish_private_directory(
                        destination, parent.fd, name, privfs.DIR_MODE,
                        initializing=self.initializing,
                    ),
                )
            except FileNotFoundError as exc:
                raise ContractError(f"repository {name} directory is missing") from exc
            observed_directory = os.fstat(destination.fd)
            if (not stat.S_ISDIR(observed_directory.st_mode)
                    or observed_directory.st_uid != os.geteuid()
                    or stat.S_IMODE(observed_directory.st_mode) != privfs.DIR_MODE):
                raise ContractError(f"repository {name} directory identity is unsafe")
        try:
            self.history_created = _open_or_publish_private_directory(
                self.history_directory, self.state_directory.fd,
                "history", privfs.DIR_MODE, initializing=self.initializing,
            )
        except FileNotFoundError as exc:
            raise ContractError("repository history directory is missing") from exc
        history_stat = os.fstat(self.history_directory.fd)
        if (not stat.S_ISDIR(history_stat.st_mode)
                or history_stat.st_uid != os.geteuid()
                or stat.S_IMODE(history_stat.st_mode) != privfs.DIR_MODE):
            raise ContractError("repository history directory identity is unsafe")
        try:
            self.claims_root_created = _open_or_publish_private_directory(
                self.claims_root, self.state_directory.fd,
                "claims", privfs.DIR_MODE, initializing=self.initializing,
            )
        except FileNotFoundError as exc:
            raise ContractError("repository claims directory is missing") from exc
        claims_stat = os.fstat(self.claims_root.fd)
        if (not stat.S_ISDIR(claims_stat.st_mode)
                or claims_stat.st_uid != os.geteuid()
                or stat.S_IMODE(claims_stat.st_mode) != privfs.DIR_MODE):
            raise ContractError("repository claims directory is unsafe")

        if self.initializing:
            authority_exists = self._shared_authority_exists()
            prior_witness = self._shared_namespace_has_run_witness()
            if authority_exists:
                if not prior_witness:
                    raise ContractError(
                        "repository shared authority has no creation-bound Run witness",
                    )
                self._bind_shared_authority(create=False)
            elif prior_witness:
                raise ContractError("repository shared authority record is missing")
            else:
                # No creation-bound Run has exposed this namespace.  This is a
                # retry of a pre-witness bootstrap (possibly after a supported
                # cancellation), so finish the same project-root-serialized
                # authority record rather than permanently poisoning creation.
                if not all((
                    self.state_created, self.locks_created,
                    self.history_created, self.claims_root_created,
                )):
                    raise ContractError(
                        "repository shared namespace was planted before bootstrap",
                    )
                self._bind_shared_authority(create=True)
            if authority_exists:
                self._validate_shared_consensus()
            _claim_private_directory_into(
                self, self.claims_root.fd, self.run.run_id, privfs.DIR_MODE,
            )
            if not self.claim_registry_possible:
                if prior_witness:
                    raise ContractError(
                        "run artifact-claim registry already exists during creation",
                    ) from None
                # A pre-witness bootstrap retry may reclaim only an empty,
                # private registry.  Any planted marker or unsafe object is a
                # poisoned namespace and remains a hard refusal.
                retry_registry = _OwnedDescriptor()
                retry_settlement = _SettlementOwner(
                    lambda: _settle_descriptor_owners(
                        (retry_registry,), "claim registry retry descriptor",
                    ),
                )
                with _SettlementFence(retry_settlement):
                    with _SettlementFence(retry_settlement):
                        retry_registry.open(
                            self.run.run_id, _DIR_OPEN_FLAGS,
                            dir_fd=self.claims_root.fd,
                        )
                        retry_stat = os.fstat(retry_registry.fd)
                        if (retry_stat.st_uid != os.geteuid()
                                or stat.S_IMODE(retry_stat.st_mode) != privfs.DIR_MODE
                                or os.listdir(retry_registry.fd)):
                            raise ContractError(
                                "run artifact-claim registry already exists during creation",
                            )
            else:
                self.claim_registry_created = True
        else:
            self._bind_shared_authority(create=False)
        try:
            if self.claim_registry.fd < 0:
                self.claim_registry.open(
                    self.run.run_id, _DIR_OPEN_FLAGS, dir_fd=self.claims_root.fd,
                )
            else:
                named_registry = os.stat(
                    self.run.run_id, dir_fd=self.claims_root.fd,
                    follow_symlinks=False,
                )
                if ((named_registry.st_dev, named_registry.st_ino)
                        != self.claim_registry.identity):
                    raise ContractError("run artifact-claim registry was substituted")
        except FileNotFoundError as exc:
            raise ContractError("run artifact-claim registry is missing") from exc
        registry_stat = os.fstat(self.claim_registry.fd)
        if (not stat.S_ISDIR(registry_stat.st_mode)
                or registry_stat.st_uid != os.geteuid()
                or stat.S_IMODE(registry_stat.st_mode) != privfs.DIR_MODE):
            raise ContractError("run artifact-claim registry is unsafe")
        lock_flags = os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        if self.initializing:
            os.fsync(self.history_directory.fd)
            lock_flags |= os.O_CREAT | os.O_EXCL
        try:
            self.lock_file.open(
                self.run._lock_path.name, lock_flags,
                privfs.FILE_MODE, dir_fd=self.lock_directory.fd,
            )
        except FileNotFoundError as exc:
            raise ContractError("repository lock is missing") from exc
        except FileExistsError as exc:
            raise ContractError("repository lock already exists during creation") from exc
        observed_lock = os.fstat(self.lock_file.fd)
        if (not stat.S_ISREG(observed_lock.st_mode)
                or observed_lock.st_uid != os.geteuid()
                or observed_lock.st_nlink != 1
                or stat.S_IMODE(observed_lock.st_mode) != privfs.FILE_MODE):
            raise ContractError("repository lock identity is unsafe")
        self.lock_identity = (observed_lock.st_dev, observed_lock.st_ino)
        fcntl.flock(self.lock_file.fd, fcntl.LOCK_EX)
        self.locked = True
        self._bind_durable_lock_identity()
        self._bind_run_creation_witness()
        if self.initializing:
            os.fsync(self.claim_registry.fd)
            os.fsync(self.claims_root.fd)
            os.fsync(self.lock_directory.fd)
            os.fsync(self.state_directory.fd)
            os.fsync(self.recon_root.fd)
        self._validate_named_identities()
        self.acquired = True

    def validate_live(self) -> None:
        if (not self.acquired or self.terminal
                or (self.borrowed_project_anchor is None and not self.root_locked)
                or not self.locked
                or any(owner.fd < 0 for owner in self.descriptor_owners)):
            raise ContractError("repository mutation owner is not live")
        for descriptor in self.descriptor_owners:
            if self._identity(descriptor.fd) != descriptor.identity:
                raise ContractError("repository mutation descriptor identity changed")

    def reauthenticate(self) -> None:
        """Reconcile every public name and witness at an epoch boundary."""
        self.validate_live()
        self._validate_named_identities()

    def settle(self) -> None:
        """Idempotently release flock then every exact descriptor owner."""
        primary = None
        try:
            self._fence_incomplete_bootstrap()
            if self.locked and self.lock_file.fd >= 0:
                try:
                    fcntl.flock(self.lock_file.fd, fcntl.LOCK_UN)
                except OSError as exc:
                    if exc.errno == errno.EBADF:
                        self.locked = False
                    else:
                        raise
                else:
                    self.locked = False
        except BaseException as exc:
            primary = exc
        try:
            if self.root_locked and self.project_anchor.fd >= 0:
                try:
                    fcntl.flock(self.project_anchor.fd, fcntl.LOCK_UN)
                except OSError as exc:
                    if exc.errno == errno.EBADF:
                        self.root_locked = False
                    else:
                        raise
                else:
                    self.root_locked = False
        except BaseException as exc:
            primary = _preferred_settlement_fault(primary, [exc])
        faults = _close_owned_descriptors_twice(self.descriptor_owners)
        if self.lock_file.fd < 0:
            self.locked = False
        if self.project_anchor.fd < 0:
            self.root_locked = False
        preferred = _preferred_settlement_fault(primary, faults)
        if preferred is not None:
            raise preferred
        if (self.root_locked or self.locked
                or any(owner.fd >= 0 for owner in self.descriptor_owners)):
            raise ContractError("repository mutation authority did not settle")
        self.terminal = True


class _ProjectMutationOwner:
    """One reentrant process/thread epoch over the caller-supplied project inode."""

    __slots__ = (
        "project_dir", "expected_identity", "anchor", "locked", "acquired",
        "terminal", "pid",
    )

    def __init__(
        self, project_dir: Path,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        self.project_dir = Path(project_dir)
        self.expected_identity = expected_identity
        self.anchor = _OwnedDescriptor(expected_identity)
        self.locked = False
        self.acquired = False
        self.terminal = False
        self.pid = os.getpid()

    def acquire(self) -> None:
        if self.acquired or self.terminal:
            raise ContractError("project mutation owner is already used")
        self.anchor.open(self.project_dir, _DIR_OPEN_FLAGS)
        observed = os.fstat(self.anchor.fd)
        if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid()):
            raise ContractError("project directory identity is unsafe")
        fcntl.flock(self.anchor.fd, fcntl.LOCK_EX)
        self.locked = True
        self.reauthenticate()
        self.acquired = True

    def validate_live(self) -> None:
        if (self.pid != os.getpid() or self.terminal or not self.locked or self.anchor.fd < 0
                or self.anchor.identity is None):
            raise ContractError("project mutation owner is not live")
        observed = os.fstat(self.anchor.fd)
        if (observed.st_dev, observed.st_ino) != self.anchor.identity:
            raise ContractError("project mutation descriptor identity changed")

    def reauthenticate(self) -> None:
        if self.acquired:
            self.validate_live()
        named = os.stat(self.project_dir, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != self.anchor.identity:
            raise ContractError("project directory identity changed")

    def settle(self) -> None:
        primary = None
        try:
            if self.locked and self.anchor.fd >= 0:
                try:
                    fcntl.flock(self.anchor.fd, fcntl.LOCK_UN)
                except OSError as exc:
                    if exc.errno == errno.EBADF:
                        self.locked = False
                    else:
                        raise
                else:
                    self.locked = False
        except BaseException as exc:
            primary = exc
        faults = _close_owned_descriptors_twice((self.anchor,))
        if self.anchor.fd < 0:
            self.locked = False
        preferred = _preferred_settlement_fault(primary, faults)
        if preferred is not None:
            raise preferred
        if self.locked or self.anchor.fd >= 0:
            raise ContractError("project mutation authority did not settle")
        self.terminal = True


@dataclass
class _ProjectMutationLedgerEntry:
    owner: _ProjectMutationOwner
    depth: int = 1


class _NestedProjectMutationOwner:
    __slots__ = ("entry", "prior_depth", "armed")

    def __init__(self, entry: _ProjectMutationLedgerEntry) -> None:
        self.entry = entry
        self.prior_depth = entry.depth
        self.armed = False

    def acquire(self) -> None:
        if self.armed:
            raise ContractError("nested project mutation owner is already entered")
        self.armed = True
        self.entry.depth = self.prior_depth + 1

    def settle(self) -> None:
        if self.armed:
            if self.entry.depth not in {self.prior_depth, self.prior_depth + 1}:
                raise ContractError("project mutation depth is invalid")
            self.entry.depth = self.prior_depth
            self.armed = False
        if self.entry.depth < 1:
            raise ContractError("project mutation depth is invalid")


@contextmanager
def _project_mutation(
    project_dir: Path,
    expected_identity: tuple[int, int] | None = None,
):
    project_dir = Path(project_dir)
    project_key = str(project_dir.resolve())
    held, _runs = _thread_mutation_ledgers()
    other = next((key for key in held if key != project_key), None)
    if other is not None:
        raise ContractError("cross-project mutation nesting is unsupported")
    lock = _shared_project_lock(project_key)
    with lock:
        entry = held.get(project_key)
        if entry is not None:
            if (type(entry) is not _ProjectMutationLedgerEntry
                    or (expected_identity is not None
                        and entry.owner.anchor.identity != expected_identity)):
                raise ContractError("project mutation ledger is damaged")
            entry.owner.validate_live()
            nested = _NestedProjectMutationOwner(entry)
            settlement = _SettlementOwner(nested.settle)
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    nested.acquire()
                    yield entry.owner
            return
        owner = _ProjectMutationOwner(project_dir, expected_identity)

        def settle_epoch() -> None:
            held.pop(project_key, None)
            owner.settle()

        settlement = _SettlementOwner(settle_epoch)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                owner.acquire()
                held[project_key] = _ProjectMutationLedgerEntry(owner)
                yield owner
                owner.reauthenticate()


class _RunCreationCleanup:
    """Quarantine/remove only the exact unexposed Run generation on failure."""

    __slots__ = (
        "recon", "run_id", "run_anchor", "creation", "identity", "possible",
        "exposed", "terminal",
    )

    def __init__(
        self, recon: _OwnedDescriptor, run_id: str,
        run_anchor: _OwnedDescriptor, creation: _OwnedDescriptor,
    ) -> None:
        self.recon = recon
        self.run_id = run_id
        self.run_anchor = run_anchor
        self.creation = creation
        self.identity = None
        self.possible = False
        self.exposed = False
        self.terminal = False

    @staticmethod
    def _remove_tree(fd: int) -> None:
        for name in os.listdir(fd):
            observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(observed.st_mode):
                child = _OwnedDescriptor((observed.st_dev, observed.st_ino))
                settlement = _SettlementOwner(
                    lambda: _settle_descriptor_owners(
                        (child,), "Run creation cleanup descriptor",
                    ),
                )
                with _SettlementFence(settlement):
                    with _SettlementFence(settlement):
                        child.open(name, _DIR_OPEN_FLAGS, dir_fd=fd)
                        _RunCreationCleanup._remove_tree(child.fd)
                        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if (named.st_dev, named.st_ino) != child.identity:
                            raise ContractError("incomplete Run directory was substituted")
                        os.rmdir(name, dir_fd=fd)
            elif stat.S_ISREG(observed.st_mode):
                regular = _OwnedDescriptor((observed.st_dev, observed.st_ino))
                settlement = _SettlementOwner(
                    lambda: _settle_descriptor_owners(
                        (regular,), "Run creation cleanup file descriptor",
                    ),
                )
                with _SettlementFence(settlement):
                    with _SettlementFence(settlement):
                        regular.open(name, _FILE_OPEN_FLAGS, dir_fd=fd)
                        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if (named.st_dev, named.st_ino) != regular.identity:
                            raise ContractError("incomplete Run file was substituted")
                        os.unlink(name, dir_fd=fd)
            else:
                raise ContractError("incomplete Run contains an unsafe entry")
        os.fsync(fd)

    def settle(self) -> None:
        primary = None
        try:
            faults = _close_owned_descriptors_twice((self.creation,))
            preferred = _preferred_settlement_fault(None, faults)
            if preferred is not None:
                raise preferred
            if not self.exposed and self.possible and self.identity is None:
                # The name may have been substituted after mkdir but before a
                # descriptor could be adopted.  Never infer ownership from the
                # current public name and risk deleting someone else's inode.
                if self.run_anchor.fd < 0 or self.run_anchor.identity is None:
                    raise ContractError("incomplete Run generation lost its descriptor identity")
                self.identity = self.run_anchor.identity
            if not self.exposed and self.identity is not None:
                named = os.stat(self.run_id, dir_fd=self.recon.fd, follow_symlinks=False)
                if (named.st_dev, named.st_ino) != self.identity:
                    raise ContractError("incomplete Run generation was substituted")
                if self.run_anchor.fd < 0:
                    self.run_anchor.expected_identity = self.identity
                    self.run_anchor.open(self.run_id, _DIR_OPEN_FLAGS, dir_fd=self.recon.fd)
                creation = _read_identity_file(self.run_anchor.fd, "run.json")
                # A completed creation witness is the durable point after which
                # shared lock/claim namespaces intentionally remain coherent.
                # If cancellation occurs later, `.creation-pending` keeps the
                # generation forensic and unselectable until an operator acts;
                # if the marker is already gone, creation was already exposed.
                if (isinstance(creation, dict)
                        and isinstance(creation.get("mutation_lock"), dict)
                        and isinstance(creation.get("artifact_claims"), dict)
                        and isinstance(creation.get("project_state"), dict)):
                    self.exposed = not _run_creation_pending(self.run_anchor.fd)
                else:
                    self._remove_tree(self.run_anchor.fd)
                    faults = _close_owned_descriptors_twice((self.run_anchor,))
                    preferred = _preferred_settlement_fault(None, faults)
                    if preferred is not None:
                        raise preferred
                    os.rmdir(self.run_id, dir_fd=self.recon.fd)
                    os.fsync(self.recon.fd)
                    self.identity = None
        except FileNotFoundError:
            self.identity = None
        except BaseException as exc:
            primary = exc
        faults = _close_owned_descriptors_twice((self.creation, self.run_anchor))
        preferred = _preferred_settlement_fault(primary, faults)
        if preferred is not None:
            raise preferred
        if self.creation.fd >= 0 or self.run_anchor.fd >= 0:
            raise ContractError("Run creation cleanup descriptor did not settle")
        self.terminal = True

    def expose_if_complete(self) -> None:
        """Reconcile the marker boundary before returning a public handle."""
        if self.identity is None or self.run_anchor.fd < 0:
            raise ContractError("Run creation has no pinned generation to expose")
        named = os.stat(self.run_id, dir_fd=self.recon.fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != self.identity:
            raise ContractError("Run generation changed before exposure")
        if _run_creation_pending(self.run_anchor.fd):
            raise ContractError("Run creation remains pending")
        identity, _started = _run_identity_from_fd(self.run_anchor.fd, self.run_id)
        if (not isinstance(identity.get("mutation_lock"), dict)
                or not isinstance(identity.get("artifact_claims"), dict)
                or not isinstance(identity.get("project_state"), dict)):
            raise ContractError("Run creation authority is incomplete")
        self.exposed = True


def _bootstrap_run_tree(run_anchor: _OwnedDescriptor, identity: dict) -> None:
    """Create initial Run contents only through the exact claimed directory."""
    from . import privfs
    child = _OwnedDescriptor()
    record = _OwnedDescriptor()
    settlement = _SettlementOwner(
        lambda: _settle_descriptor_owners(
            (record, child), "Run bootstrap descriptors",
        ),
    )
    with _SettlementFence(settlement):
        with _SettlementFence(settlement):
            for name in ("raw", "normalized", "exports", "reports"):
                os.mkdir(name, privfs.DIR_MODE, dir_fd=run_anchor.fd)
                child.open(name, _DIR_OPEN_FLAGS, dir_fd=run_anchor.fd)
                os.fsync(child.fd)
                _settle_descriptor_owners((child,), "Run bootstrap directory descriptor")
            record.open(
                "run.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                privfs.FILE_MODE, dir_fd=run_anchor.fd,
            )
            _write_all_descriptor(record.fd, json.dumps(identity).encode("utf-8"))
            os.fsync(record.fd)
            _settle_descriptor_owners((record,), "Run bootstrap identity descriptor")
            os.fsync(run_anchor.fd)


def _claim_run_directory(recon_fd: int, run_id: str, mode: int) -> bool:
    """Claim one Run name; isolate the exception boundary from owner frames."""
    try:
        os.mkdir(run_id, mode, dir_fd=recon_fd)
    except FileExistsError:
        return False
    return True


def _claim_run_directory_into(
    cleanup: "_RunCreationCleanup", recon_fd: int, run_id: str, mode: int,
) -> bool:
    """Claim and pin a Run generation without a source-line adoption gap."""
    claimed = _publish_private_directory_into(
        cleanup.run_anchor, recon_fd, run_id, mode,
    )
    if not claimed:
        return False
    cleanup.identity = cleanup.run_anchor.identity
    return True


def _claim_private_directory_into(
    owner: "_RunMutationOwner", parent_fd: int, name: str, mode: int,
) -> None:
    """Claim one private name through an identity-owned temporary directory."""
    owner.claim_registry_possible = _publish_private_directory_into(
        owner.claim_registry, parent_fd, name, mode,
    )


class _ProjectStatePublisher:
    """Descriptor-owned publication of per-project history/current metadata."""

    __slots__ = ("owner", "state", "history")

    def __init__(self, owner: _RunMutationOwner) -> None:
        self.owner = owner
        self.state = _OwnedDescriptor()
        self.history = _OwnedDescriptor()

    @property
    def descriptor_owners(self) -> tuple[_OwnedDescriptor, ...]:
        return self.history, self.state

    def _validate(self) -> None:
        self.owner.validate_live()
        named = os.stat("state", dir_fd=self.owner.recon_root.fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != self.state.identity:
            raise ContractError("repository state publication directory changed")
        history_named = os.stat(
            "history", dir_fd=self.state.fd, follow_symlinks=False,
        )
        if (history_named.st_dev, history_named.st_ino) != self.history.identity:
            raise ContractError("repository history directory changed")

    def publish(self, history_name: str, history_data: bytes, run_path: str) -> None:
        from . import privfs
        self.state.duplicate(self.owner.state_directory.fd)
        self.history.expected_identity = self.owner.history_directory.identity
        self.history.duplicate(self.owner.history_directory.fd)
        observed_history = os.fstat(self.history.fd)
        if (observed_history.st_uid != os.geteuid()
                or stat.S_IMODE(observed_history.st_mode) != privfs.DIR_MODE):
            raise ContractError("repository history directory is unsafe")
        history_stage = privfs.stage_private_bytes(
            self.history.fd, (history_name,), history_data,
        )
        try:
            privfs.replace_private_stage(history_stage)
        except BaseException:
            try:
                privfs.abort_private_stage(history_stage)
            except BaseException:
                pass
            raise
        self._validate()
        pointer_stage = privfs.stage_private_bytes(
            self.state.fd, ("current.txt",), run_path.encode("utf-8"),
        )
        try:
            privfs.replace_private_stage(pointer_stage)
        except BaseException:
            try:
                privfs.abort_private_stage(pointer_stage)
            except BaseException:
                pass
            raise
        self._validate()

    def settle(self) -> None:
        _settle_descriptor_owners(
            self.descriptor_owners, "project state publication descriptors",
        )


@dataclass
class _RunMutationLedgerEntry:
    owner: _RunMutationOwner
    depth: int = 1


class _NestedMutationOwner:
    """Cancellation-safe depth accounting for one reused mutation owner."""

    __slots__ = ("entry", "prior_depth", "armed")

    def __init__(self, entry: _RunMutationLedgerEntry) -> None:
        self.entry = entry
        self.prior_depth = entry.depth
        self.armed = False

    def acquire(self) -> None:
        if self.armed:
            raise ContractError("nested mutation owner is already entered")
        self.armed = True
        self.entry.depth = self.prior_depth + 1

    def settle(self) -> None:
        if self.armed:
            if self.entry.depth not in {self.prior_depth, self.prior_depth + 1}:
                raise ContractError("repository mutation depth is invalid")
            self.entry.depth = self.prior_depth
            self.armed = False
        if self.entry.depth < 1:
            raise ContractError("repository mutation depth is invalid")


class ManagedAcquisitionRefused(ContractError):
    """A durable destination lease cannot safely authorize provider contact."""


class _ManagedAcquisitionRelocatedBusy(Exception):
    """Internal retry signal for a live marker overlap under another OFD."""


def _managed_acquisition_marker_material(
    run_id: str, components: tuple[str, ...],
) -> tuple[str, str, bytes]:
    """Return the deterministic registry name, full key and canonical body."""
    encoded = json.dumps(
        {
            "domain": "quarry-managed-http-acquisition-v1",
            "run_id": run_id,
            "components": list(components),
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    key = hashlib.sha256(encoded).hexdigest()
    body = json.dumps(
        {
            "schema_version": 1,
            "kind": "managed-http-acquisition",
            "run_id": run_id,
            "components": list(components),
            "key": key,
            "pid": os.getpid(),
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{key[:32]}{_CLAIM_SUFFIX}", key, body


class _ManagedAcquisitionMarker:
    """Exact durable destination lease spanning provider contact.

    Creation and every namespace transition happen under a short Run mutation.
    Waiting for another process happens only on the pinned marker descriptor,
    outside Run/project authority.  A still-named unlocked marker is crash
    evidence and is never silently recycled.
    """

    __slots__ = (
        "run", "components", "name", "key", "body", "directory", "marker",
        "release_owner", "created", "owned", "locked",
        "ready", "released", "abandoned", "pid",
    )

    def __init__(self, run, components: tuple[str, ...]) -> None:
        self.run = run
        self.components = components
        self.name, self.key, self.body = _managed_acquisition_marker_material(
            run.run_id, components,
        )
        self.directory = _OwnedDescriptor()
        self.marker = _OwnedDescriptor()
        self.release_owner = None
        self.created = False
        self.owned = False
        self.locked = False
        self.ready = False
        self.released = False
        self.abandoned = False
        self.pid = os.getpid()

    @property
    def local_key(self) -> tuple[str, str, str]:
        return (*self.run._authority_key, self.key)

    def require_origin_process(self) -> None:
        if os.getpid() != self.pid:
            raise ManagedAcquisitionRefused(
                "managed acquisition lease was inherited across fork",
            )

    def close_inherited_copy(self) -> None:
        """Close child copies without changing the parent's OFD flock/name."""
        faults = _close_owned_descriptors_twice((self.marker, self.directory))
        self.locked = False
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred

    def _validate_marker_stat(self, observed) -> None:
        from . import privfs
        if (not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE):
            raise ManagedAcquisitionRefused(
                "managed acquisition lease marker is unsafe",
            )

    def _validate_marker_body(self) -> bytes:
        before = os.fstat(self.marker.fd)
        self._validate_marker_stat(before)
        os.lseek(self.marker.fd, 0, os.SEEK_SET)
        raw = os.read(self.marker.fd, 64 * 1024 + 1)
        after = os.fstat(self.marker.fd)
        if len(raw) > 64 * 1024:
            raise ManagedAcquisitionRefused(
                "managed acquisition lease marker changed while inspected",
            )
        if ((before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
             before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ManagedAcquisitionRefused(
                "managed acquisition lease marker changed while inspected",
            )
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ManagedAcquisitionRefused(
                "managed acquisition lease marker is damaged or substituted",
            ) from exc
        if (not isinstance(doc, dict)
                or doc.get("schema_version") != 1
                or doc.get("kind") != "managed-http-acquisition"
                or doc.get("run_id") != self.run.run_id
                or doc.get("components") != list(self.components)
                or doc.get("key") != self.key):
            raise ManagedAcquisitionRefused(
                "managed acquisition lease marker belongs to another destination",
            )
        return raw

    def _find_relocated_marker_locked(self) -> None:
        """Refuse an exact destination marker left under a release name.

        A process may die after the reversible deterministic-to-quarantine
        rename.  Scan only when the deterministic name is absent, authenticate
        each strict 32-hex claim through a fenced descriptor, and compare the
        complete canonical body.  This keeps a crash from granting a second
        provider contact while leaving unrelated destinations concurrent.
        """
        candidate = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners(
                (candidate,), "managed acquisition relocated marker scan",
            ),
        )
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                for name in os.listdir(self.directory.fd):
                    token = (
                        name[:-len(_CLAIM_SUFFIX)]
                        if name.endswith(_CLAIM_SUFFIX) else ""
                    )
                    if name == self.name:
                        continue
                    if (len(token) != 32
                            or any(ch not in "0123456789abcdef" for ch in token)):
                        raise ManagedAcquisitionRefused(
                            "managed acquisition claim registry contains an unexplained entry",
                        )
                    listed = os.stat(
                        name, dir_fd=self.directory.fd,
                        follow_symlinks=False,
                    )
                    self._validate_marker_stat(listed)
                    candidate.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=self.directory.fd,
                    )
                    before = os.fstat(candidate.fd)
                    self._validate_marker_stat(before)
                    named = os.stat(
                        name, dir_fd=self.directory.fd,
                        follow_symlinks=False,
                    )
                    if ((named.st_dev, named.st_ino) != candidate.identity
                            or (before.st_dev, before.st_ino)
                            != candidate.identity
                            or (listed.st_dev, listed.st_ino)
                            != candidate.identity):
                        raise ManagedAcquisitionRefused(
                            "managed acquisition relocated marker changed while scanned",
                        )
                    os.lseek(candidate.fd, 0, os.SEEK_SET)
                    raw = os.read(candidate.fd, 64 * 1024 + 1)
                    after = os.fstat(candidate.fd)
                    if self._snapshot_marker_stat(before) != self._snapshot_marker_stat(after):
                        raise ManagedAcquisitionRefused(
                            "managed acquisition relocated marker changed while read",
                        )
                    try:
                        doc = json.loads(raw.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                        raise ManagedAcquisitionRefused(
                            "managed acquisition claim registry contains a damaged marker",
                        )
                    if (not isinstance(doc, dict)
                            or doc.get("schema_version") != 1
                            or doc.get("kind") != "managed-http-acquisition"
                            or doc.get("run_id") != self.run.run_id
                            or not isinstance(doc.get("components"), list)
                            or not isinstance(doc.get("key"), str)):
                        raise ManagedAcquisitionRefused(
                            "managed acquisition claim registry contains an unknown marker",
                        )
                    if (doc.get("components") == list(self.components)
                            and doc.get("key") == self.key):
                        try:
                            fcntl.flock(
                                candidate.fd,
                                fcntl.LOCK_EX | fcntl.LOCK_NB,
                            )
                        except BlockingIOError as exc:
                            raise _ManagedAcquisitionRelocatedBusy() from exc
                        raise ManagedAcquisitionRefused(
                            "managed acquisition lease is crash-stale under a release name; prior contact is unknown",
                        )
                    fault = candidate.close_once()
                    if fault is not None:
                        raise fault
                    candidate = _OwnedDescriptor()

    @staticmethod
    def _snapshot_marker_stat(observed):
        return (
            observed.st_dev, observed.st_ino, observed.st_mode,
            observed.st_nlink, observed.st_size,
            observed.st_mtime_ns, observed.st_ctime_ns,
        )

    def validate_owned_locked(self) -> None:
        """Authenticate this exact still-held lease inside a Run mutation epoch."""
        self.require_origin_process()
        if (not self.owned or not self.locked or self.released or self.abandoned
                or self.marker.fd < 0 or self.directory.fd < 0
                or self.marker.identity is None or self.directory.identity is None):
            raise ManagedAcquisitionRefused(
                "managed acquisition destination lease is not live",
            )
        self._pin_registry_locked()
        active = self.run._active_mutation_owner()
        directory_stat = os.fstat(self.directory.fd)
        if (active is None
                or (directory_stat.st_dev, directory_stat.st_ino)
                != self.directory.identity
                or self.directory.identity != active.claim_registry.identity):
            raise ManagedAcquisitionRefused(
                "managed acquisition claim registry identity changed",
            )
        named = self._named_identity()
        observed = os.fstat(self.marker.fd)
        self._validate_marker_stat(observed)
        if (named != self.marker.identity
                or (observed.st_dev, observed.st_ino) != self.marker.identity):
            raise ManagedAcquisitionRefused(
                "managed acquisition lease marker was substituted while live",
            )
        if self._validate_marker_body() != self.body:
            raise ManagedAcquisitionRefused(
                "managed acquisition lease marker body changed while owned",
            )
        # Take/refresh the nonblocking lock on the exact owner descriptor.  A
        # lost lock with no contender is safely reacquired before any artifact
        # effect; a different live OFD holding this inode makes this operation
        # fail immediately, so this exact descriptor owns the lock on return.
        try:
            fcntl.flock(self.marker.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ManagedAcquisitionRefused(
                "managed acquisition destination lease lock moved to another owner",
            ) from exc

    def _pin_registry_locked(self) -> None:
        active = self.run._active_mutation_owner()
        if active is None:
            raise ContractError("managed acquisition lease has no mutation authority")
        if self.directory.fd < 0:
            self.directory.expected_identity = active.claim_registry.identity
            self.directory.duplicate(active.claim_registry.fd)
        elif self.directory.identity != active.claim_registry.identity:
            raise ManagedAcquisitionRefused(
                "managed acquisition claim registry identity changed",
            )

    def _open_attempt_locked(self) -> bool:
        """Open/create one marker.  True means this call created and locked it."""
        from . import privfs
        self._pin_registry_locked()
        flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0))
        # Pre-arm cleanup before the allocation line.  If tracing cancellation
        # lands immediately after ``open`` adopted the new fd, settlement can
        # still prove/unlink that exact pre-contact marker.  With no adopted fd
        # this pre-arm is side-effect free and is simply disarmed below.
        self.created = True
        self.owned = True
        try:
            try:
                os.stat(
                    self.name, dir_fd=self.directory.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                self._find_relocated_marker_locked()
            self.marker.open(self.name, flags, privfs.FILE_MODE, dir_fd=self.directory.fd)
        except FileExistsError:
            self.created = False
            self.owned = False
            self.marker.open(
                self.name,
                os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=self.directory.fd,
            )
            named = os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)
            observed = os.fstat(self.marker.fd)
            self._validate_marker_stat(observed)
            if ((named.st_dev, named.st_ino) != self.marker.identity
                    or (observed.st_dev, observed.st_ino) != self.marker.identity):
                raise ManagedAcquisitionRefused(
                    "managed acquisition lease marker was substituted while opened",
                )
            self._validate_marker_body()
            return False

        os.fchmod(self.marker.fd, privfs.FILE_MODE)
        view = memoryview(self.body)
        while view:
            written = os.write(self.marker.fd, view)
            if written <= 0:
                raise OSError("managed acquisition lease write made no progress")
            view = view[written:]
        os.fsync(self.marker.fd)
        self._validate_marker_body()
        # The new inode cannot already have a cooperative owner.  Acquire its
        # lifecycle lock before the BASE mutation exposing it is released.
        fcntl.flock(self.marker.fd, fcntl.LOCK_EX | fcntl.LOCK_NB); self.locked = True  # noqa: E702 - one traced ownership seam
        os.fsync(self.directory.fd)
        self.ready = True
        return True

    def _named_identity(self) -> tuple[int, int] | None:
        try:
            named = os.stat(
                self.name, dir_fd=self.directory.fd, follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        self._validate_marker_stat(named)
        return named.st_dev, named.st_ino

    def _named_identity_while_owner_busy(self) -> tuple[int, int] | None:
        """Read the deterministic name during the exact two-link overlap."""
        try:
            named = os.stat(
                self.name, dir_fd=self.directory.fd, follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        from . import privfs
        if (not stat.S_ISREG(named.st_mode)
                or named.st_uid != os.geteuid()
                or stat.S_IMODE(named.st_mode) != privfs.FILE_MODE
                or named.st_nlink not in {1, 2}):
            raise ManagedAcquisitionRefused(
                "managed acquisition lease marker is unsafe while its owner settles",
            )
        return named.st_dev, named.st_ino

    def _check_local_owner(self) -> None:
        with _RUN_LOCKS_GUARD:
            active_local = _ACQUISITION_ACTIVE.get(self.local_key)
        if active_local is not None:
            expected, owner_thread, _owner_token = active_local
            if owner_thread == threading.get_ident():
                raise ManagedAcquisitionRefused(
                    "managed acquisition destination is already claimed by this thread",
                )
            with self.run._mutation(MutationScope.CONTROL):
                active = self.run._active_mutation_owner()
                if active is None:
                    raise ContractError(
                        "managed acquisition local lease has no mutation authority",
                    )
                try:
                    named = os.stat(
                        self.name,
                        dir_fd=active.claim_registry.fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    named_identity = None
                else:
                    from . import privfs
                    if (not stat.S_ISREG(named.st_mode)
                            or named.st_uid != os.geteuid()
                            or stat.S_IMODE(named.st_mode) != privfs.FILE_MODE
                            or named.st_nlink not in {1, 2}):
                        raise ManagedAcquisitionRefused(
                            "managed acquisition lease marker is unsafe while locally owned",
                        )
                    named_identity = named.st_dev, named.st_ino
            # A missing name may be the clean owner's unlink-before-unlock
            # interval.  A different named inode is a live substitution and
            # must refuse immediately instead of deadlocking behind its victim.
            if named_identity is not None and named_identity != expected:
                raise ManagedAcquisitionRefused(
                    "managed acquisition lease marker was substituted while live",
                )

    def _release_local(self) -> None:
        with _RUN_LOCKS_GUARD:
            active_local = _ACQUISITION_ACTIVE.get(self.local_key)
            if (active_local is not None
                    and active_local[0] == self.marker.identity
                    and active_local[2] is self):
                _ACQUISITION_ACTIVE.pop(self.local_key, None)

    def _close_attempt(self) -> None:
        faults: list[BaseException] = []
        if self.locked and self.marker.fd >= 0:
            try:
                self.locked = False; fcntl.flock(self.marker.fd, fcntl.LOCK_UN)  # noqa: E702 - tombstone before effect
            except BaseException as exc:
                faults.append(exc)
        faults.extend(_close_owned_descriptors_twice((self.marker, self.directory)))
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred
        self.marker = _OwnedDescriptor()
        self.directory = _OwnedDescriptor()
        self.created = False

    def _wait_for_existing(self) -> bool:
        """Wait outside mutation.  True requests a clean retry after unlink."""
        while True:
            try:
                fcntl.flock(self.marker.fd, fcntl.LOCK_EX | fcntl.LOCK_NB); self.locked = True  # noqa: E702 - one traced ownership seam
                break
            except BlockingIOError:
                named = self._named_identity_while_owner_busy()
                if named is not None and named != self.marker.identity:
                    raise ManagedAcquisitionRefused(
                        "managed acquisition lease marker was substituted while live",
                    )
                time.sleep(0.01)

        with self.run._mutation(MutationScope.CONTROL):
            self._pin_registry_locked()
            named = self._named_identity()
            observed = os.fstat(self.marker.fd)
            if named is None and observed.st_nlink == 0:
                self._close_attempt()
                return True
            if named != self.marker.identity:
                raise ManagedAcquisitionRefused(
                    "managed acquisition lease marker changed after its owner settled",
                )
            self._validate_marker_body()
        raise ManagedAcquisitionRefused(
            "managed acquisition lease is crash-stale; prior contact is unknown",
        )

    def acquire(self) -> None:
        self.require_origin_process()
        self._check_local_owner()
        try:
            while True:
                try:
                    with self.run._mutation(MutationScope.BASE_EVIDENCE):
                        created = self._open_attempt_locked()
                except _ManagedAcquisitionRelocatedBusy:
                    self.created = False
                    self.owned = False
                    time.sleep(0.01)
                    continue
                if created:
                    try:
                        with _RUN_LOCKS_GUARD:
                            _ACQUISITION_ACTIVE[self.local_key] = (
                                self.marker.identity, threading.get_ident(), self,
                            )
                    except BaseException:
                        # The durable marker+flock already own serialization.
                        # Settlement does not depend on the advisory map and the
                        # outer transaction will drain both exact owners.
                        raise
                    return
                if self._wait_for_existing():
                    continue
        except BaseException:
            self._release_local()
            raise

    def _settle_locked(self, pre_unlink=None) -> None:
        """Run the stable quarantine release while the marker flock is held."""
        if self.release_owner is None:
            self.release_owner = _ManagedPairRelease(
                self, pre_unlink or (lambda: None),
            )
        self.release_owner.execute()

    def settle(self, pre_unlink=None) -> None:
        """Idempotently release an owned marker; never remove a stale prior."""
        self.require_origin_process()
        if self.abandoned:
            self.abandon()
            raise ContractError(
                "managed acquisition lease was abandoned with durable crash evidence",
            )
        faults: list[BaseException] = []
        if not self.owned:
            self.released = True
        elif self.marker.fd < 0 and self.marker.identity is None and not self.ready:
            # A pre-armed create was interrupted before adopting a descriptor;
            # no marker inode can have escaped this owner.
            self.released = True
        elif self.marker.fd < 0:
            # This owner adopted a durable generation but a prior settlement
            # pass drained its descriptor without proving the name absent.
            # Never convert that unresolved generation into a false release.
            self.abandoned = True
        if self.owned and self.ready and not self.released:
            if self.release_owner is None:
                self.release_owner = _ManagedPairRelease(
                    self, pre_unlink or (lambda: None),
                )
            settlement = _SettlementOwner(self.release_owner.settle)
            try:
                with _SettlementFence(settlement):
                    with _SettlementFence(settlement):
                        self._settle_locked(pre_unlink)
            except BaseException as exc:
                faults.append(exc)
            if self.release_owner.restored and not self.released:
                self.abandoned = True
        # A quarantine-only generation must never lose its flock.  Without the
        # deterministic name, another process could otherwise acquire fresh
        # contact authority.  Persistent restoration faults are deliberately
        # fail-stop and remain in the live transaction registry.
        if (self.release_owner is not None
                and self.release_owner.needs_restoration):
            preferred = _preferred_settlement_fault(None, faults)
            if preferred is not None:
                raise preferred
            raise ManagedAcquisitionRefused(
                "managed acquisition marker quarantine could not be restored",
            )
        if self.locked and self.marker.fd >= 0:
            try:
                self.locked = False; fcntl.flock(self.marker.fd, fcntl.LOCK_UN)  # noqa: E702 - tombstone before effect
            except BaseException as exc:
                faults.append(exc)
        faults.extend(_close_owned_descriptors_twice((self.marker, self.directory)))
        self._release_local()
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred
        if self.owned and not self.released:
            raise ContractError("managed acquisition lease did not settle")

    def abandon(self) -> None:
        """Drop ephemeral ownership while retaining a durable uncertain marker.

        An unresolved body/companion CAS must keep the named claim so sealing
        and later contact fail closed.  It must not, however, strand this
        process's flock, descriptors or keyed local mutex.  Later callers can
        therefore promptly authenticate the still-named marker and classify it
        as crash-stale instead of deadlocking behind a dead Python owner.
        """
        self.require_origin_process()
        self.abandoned = True
        faults: list[BaseException] = []
        if (self.release_owner is not None
                and self.release_owner.needs_restoration):
            try:
                with self.run._mutation(MutationScope.CONTROL):
                    self.release_owner.ensure_restored()
            except BaseException as exc:
                faults.append(exc)
            if self.release_owner.needs_restoration:
                preferred = _preferred_settlement_fault(None, faults)
                if preferred is not None:
                    raise preferred
                raise ManagedAcquisitionRefused(
                    "managed acquisition marker quarantine remains live",
                )
        if self.locked and self.marker.fd >= 0:
            try:
                self.locked = False; fcntl.flock(self.marker.fd, fcntl.LOCK_UN)  # noqa: E702 - tombstone before effect
            except BaseException as exc:
                faults.append(exc)
        faults.extend(_close_owned_descriptors_twice((self.marker, self.directory)))
        self._release_local()
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred
        if (self.marker.fd >= 0 or self.directory.fd >= 0
                or self.locked):
            raise ContractError(
                "managed acquisition uncertain lease did not abandon ephemeral ownership",
            )


class _ArtifactMarkerRelease:
    """Persistent allocation and release ownership for one exact claim marker."""

    __slots__ = (
        "run", "name", "expected_identity", "directory", "marker", "released",
        "durable",
    )

    def __init__(
        self, run, name: str | None = None,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        self.run = run
        self.name = name
        self.expected_identity = expected_identity
        self.directory = _OwnedDescriptor()
        self.marker = _OwnedDescriptor(expected_identity)
        self.released = False
        self.durable = name is not None and expected_identity is not None

    def allocate(self) -> tuple[str, tuple[int, int]]:
        """Create and durably authenticate the marker into this stable owner."""
        if self.name is not None or self.expected_identity is not None:
            raise ContractError("artifact claim marker owner is already used")
        from . import privfs
        active = self.run._active_mutation_owner()
        if active is None:
            raise ContractError("artifact claim marker has no mutation authority")
        self.directory.expected_identity = active.claim_registry.identity
        self.directory.duplicate(active.claim_registry.fd)
        self.name = f"{os.urandom(16).hex()}{_CLAIM_SUFFIX}"
        self.marker.open(
            self.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            privfs.FILE_MODE,
            dir_fd=self.directory.fd,
        )
        self.expected_identity = self.marker.identity
        self.marker.expected_identity = self.expected_identity
        os.fchmod(self.marker.fd, privfs.FILE_MODE)
        body = json.dumps({
            "schema_version": 1,
            "run_id": self.run.run_id,
            "pid": os.getpid(),
        }, sort_keys=True).encode("utf-8")
        view = memoryview(body)
        while view:
            written = os.write(self.marker.fd, view)
            if written <= 0:
                raise OSError("artifact claim marker write made no progress")
            view = view[written:]
        os.fsync(self.marker.fd)
        observed = os.fstat(self.marker.fd)
        if (not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE
                or (observed.st_dev, observed.st_ino)
                != self.expected_identity):
            raise ContractError("artifact claim marker identity is unsafe")
        os.fsync(self.directory.fd)
        self.durable = True
        faults = _close_owned_descriptors_twice((self.marker, self.directory))
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred
        return self.name, self.expected_identity

    def settle(self) -> None:
        primary = None
        try:
            if not self.released:
                if self.expected_identity is None and self.marker.fd >= 0:
                    observed = os.fstat(self.marker.fd)
                    self.marker.identity = (observed.st_dev, observed.st_ino)
                    self.expected_identity = self.marker.identity
                    self.marker.expected_identity = self.expected_identity
                if self.name is None or self.expected_identity is None:
                    self.released = True
                else:
                    if self.directory.fd < 0:
                        active = self.run._active_mutation_owner()
                        if active is None:
                            raise ContractError("artifact claim release has no mutation authority")
                        self.directory.expected_identity = active.claim_registry.identity
                        self.directory.duplicate(active.claim_registry.fd)
                    try:
                        named = os.stat(
                            self.name, dir_fd=self.directory.fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        os.fsync(self.directory.fd)
                        self.released = True
                    else:
                        if (not stat.S_ISREG(named.st_mode)
                                or named.st_uid != os.geteuid()
                                or named.st_nlink != 1
                                or (named.st_dev, named.st_ino)
                                != self.expected_identity):
                            raise ContractError("artifact claim marker identity changed")
                        if self.marker.fd < 0:
                            self.marker.open(
                                self.name, _FILE_OPEN_FLAGS,
                                dir_fd=self.directory.fd,
                            )
                        observed = os.fstat(self.marker.fd)
                        if (not stat.S_ISREG(observed.st_mode)
                                or observed.st_uid != os.geteuid()
                                or observed.st_nlink != 1
                                or (observed.st_dev, observed.st_ino)
                                != self.expected_identity):
                            raise ContractError("artifact claim marker identity changed")
                        os.unlink(self.name, dir_fd=self.directory.fd)
                        os.fsync(self.directory.fd)
                        self.released = True
        except BaseException as exc:
            primary = exc
        faults = _close_owned_descriptors_twice((self.marker, self.directory))
        preferred = _preferred_settlement_fault(primary, faults)
        if preferred is not None:
            raise preferred
        if not self.released or self.marker.fd >= 0 or self.directory.fd >= 0:
            raise ContractError("artifact claim marker release did not settle")


class _ArtifactClaimRegistryRead:
    """Descriptor-owned, side-effect-free scan of one run's claim registry."""

    __slots__ = ("run", "directory", "entry")

    def __init__(self, run) -> None:
        self.run = run
        self.directory = _OwnedDescriptor()
        self.entry = _OwnedDescriptor()

    def read(self) -> int:
        active = self.run._active_mutation_owner()
        if active is None:
            raise ContractError("artifact claim registry read has no mutation authority")
        self.directory.expected_identity = active.claim_registry.identity
        self.directory.duplicate(active.claim_registry.fd)
        count = 0
        for name in os.listdir(self.directory.fd):
            token = name[:-len(_CLAIM_SUFFIX)] if name.endswith(_CLAIM_SUFFIX) else ""
            if (len(token) != 32
                    or any(char not in "0123456789abcdef" for char in token)):
                raise ContractError("artifact claim registry contains an unknown entry")
            self.entry.open(name, _FILE_OPEN_FLAGS, dir_fd=self.directory.fd)
            observed = os.fstat(self.entry.fd)
            if (not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.geteuid()
                    or observed.st_nlink != 1):
                raise ContractError("artifact claim registry contains an unsafe entry")
            faults = _close_owned_descriptors_twice((self.entry,))
            preferred = _preferred_settlement_fault(None, faults)
            if preferred is not None:
                raise preferred
            count += 1
        return count

    def settle(self) -> None:
        faults = _close_owned_descriptors_twice((self.entry, self.directory))
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred
        if self.entry.fd >= 0 or self.directory.fd >= 0:
            raise ContractError("artifact claim registry descriptors did not settle")


class _SettlementOwner:
    """Stable idempotent cleanup authority shared by two active fences."""

    __slots__ = ("operation", "faults", "primary")

    def __init__(self, operation) -> None:
        self.operation = operation
        self.faults: list[BaseException] = []
        self.primary: BaseException | None = None

    def remember(self, fault: BaseException | None) -> None:
        if fault is not None:
            self.primary = _preferred_settlement_fault(self.primary, [fault])

    def reconcile(self) -> BaseException | None:
        try:
            self.operation()
        except BaseException as exc:
            self.faults.append(exc)
        return _preferred_settlement_fault(None, self.faults)


class _SettlementFence:
    """One recovery layer over a shared mutable settlement owner.

    Two instances are entered before the first effect.  A one-shot source-line
    interruption at any entry, handler, reconciliation or return line in the
    inner ``__exit__`` therefore unwinds through the already-active outer
    instance, which repeats the idempotent operation before propagating the
    preferred exact cancellation.
    """

    __slots__ = ("owner",)

    def __init__(self, owner: _SettlementOwner) -> None:
        self.owner = owner

    def __enter__(self):
        return self

    def __exit__(self, _kind, primary, _traceback) -> bool:
        self.owner.remember(primary)
        self.owner.reconcile()
        preferred = _preferred_settlement_fault(
            self.owner.primary, self.owner.faults,
        )
        if preferred is not None and preferred is not primary:
            try:
                preferred.cleanup_errors = tuple(self.owner.faults)
            except BaseException:
                pass
            if primary is not None:
                raise preferred from primary
            raise preferred
        return False


class _ArtifactDirectoryAllocation:
    """Persistent facts for one possibly-created canonical directory."""

    __slots__ = (
        "run", "parent_components", "name", "possible", "identity", "durable",
        "anchor", "prefixes", "child",
    )

    def __init__(self, run, parent_components: tuple[str, ...], name: str) -> None:
        self.run = run
        self.parent_components = parent_components
        self.name = name
        self.possible = False
        self.identity = None
        self.durable = False
        self.anchor = _OwnedDescriptor(run._run_directory_identity)
        self.prefixes = tuple(_OwnedDescriptor() for _ in parent_components)
        self.child = _OwnedDescriptor()

    @property
    def parent(self) -> _OwnedDescriptor:
        return self.prefixes[-1]

    @property
    def descriptor_owners(self) -> tuple[_OwnedDescriptor, ...]:
        return (self.child, *reversed(self.prefixes), self.anchor)

    def _ensure_chain(self) -> None:
        from . import privfs
        if self.anchor.fd < 0:
            active = self.run._active_mutation_owner()
            if active is None:
                raise ContractError("artifact directory has no mutation authority")
            self.anchor.duplicate(active.run_anchor.fd)
        for index, owner in enumerate(self.prefixes, 1):
            if owner.fd < 0:
                prefix = self.parent_components[:index]
                _open_strict_directory_into(owner, self.anchor.fd, prefix)

    def reconcile(self) -> None:
        """Prove and durably settle a possibly-landed empty directory."""
        if not self.possible or self.durable:
            return
        self._ensure_chain()
        try:
            named = os.stat(
                self.name, dir_fd=self.parent.fd, follow_symlinks=False,
            )
        except FileNotFoundError:
            self.possible = False
            return
        self.run._validate_base_directory_stat(
            named, self.parent_components + (self.name,),
        )
        named_identity = (named.st_dev, named.st_ino)
        if self.identity is not None and named_identity != self.identity:
            raise ContractError("artifact directory identity changed during allocation")
        self.identity = named_identity
        self.child.expected_identity = named_identity
        if self.child.fd < 0:
            self.child.open(self.name, _DIR_OPEN_FLAGS, dir_fd=self.parent.fd)
        observed = os.fstat(self.child.fd)
        self.run._validate_base_directory_stat(
            observed, self.parent_components + (self.name,),
        )
        if (observed.st_dev, observed.st_ino) != named_identity:
            raise ContractError("artifact directory name changed during allocation")
        if os.listdir(self.child.fd):
            raise ContractError("new artifact directory was populated during allocation")
        # Child data first, then every name-bearing directory back to the run
        # anchor.  This also settles parents materialized immediately before the
        # allocation, rather than fsyncing only the leaf's direct parent.
        os.fsync(self.child.fd)
        for owner in reversed(self.prefixes):
            os.fsync(owner.fd)
        os.fsync(self.anchor.fd)
        self.durable = True

    def settle(self) -> None:
        primary = None
        try:
            if self.possible and not self.durable:
                self.reconcile()
        except BaseException as exc:
            primary = exc
        faults = _close_owned_descriptors_twice(self.descriptor_owners)
        preferred = _preferred_settlement_fault(primary, faults)
        if preferred is not None:
            raise preferred
        if any(owner.fd >= 0 for owner in self.descriptor_owners):
            raise ContractError("artifact directory descriptors did not settle")
        if self.possible and not self.durable:
            raise ContractError("artifact directory allocation did not settle")

    def allocate_fresh(self) -> Path:
        """Select, create and reconcile the next authenticated attempt name."""
        from . import privfs
        self._ensure_chain()
        index = 0
        while True:
            name = f"attempt-{index}"
            try:
                existing = os.stat(
                    name, dir_fd=self.parent.fd, follow_symlinks=False,
                )
            except FileNotFoundError:
                existing = None
            if existing is not None:
                self.run._validate_base_directory_stat(
                    existing, self.parent_components + (name,),
                )
                index += 1
                continue
            self.name = name
            self.possible = True
            try:
                os.mkdir(name, privfs.DIR_MODE, dir_fd=self.parent.fd)
            except FileExistsError:
                raise ContractError(
                    f"artifact attempt name {name!r} changed during allocation",
                ) from None
            self.reconcile()
            return self.run.dir.joinpath(*self.parent_components, name)

    def create_exact(self) -> Path:
        """Create and reconcile the already-declared exact directory name."""
        from . import privfs
        self._ensure_chain()
        self.possible = True
        try:
            os.mkdir(self.name, privfs.DIR_MODE, dir_fd=self.parent.fd)
        except FileExistsError:
            raise ContractError(
                "artifact directory "
                f"{'/'.join(self.parent_components + (self.name,))!r} already exists",
            ) from None
        self.reconcile()
        return self.run.dir.joinpath(*self.parent_components, self.name)


class _ArtifactClaim:
    """Opaque, single-use authority for one unpublished base artifact.

    A caller may borrow one writable descriptor, but destination naming,
    settlement, publication and fencing remain repository operations.  The
    durable marker is retained until the context exits after a terminal
    publication/fence, so finalization cannot race the owner's return path.
    """

    __slots__ = (
        "_run", "_components", "_stage",
        "_writer_fd", "_writer_owner", "_open_anchor", "_cleanup_anchor",
        "_cleanup_parent", "_discard_settled", "_marker_release",
        "_settlement_faults", "_state",
    )

    def __init__(self, run, components, marker_release):
        self._run = run
        self._components = components
        self._stage = None
        self._writer_fd = -1
        self._writer_owner = _OwnedDescriptor()
        self._open_anchor = _OwnedDescriptor(run._run_directory_identity)
        self._cleanup_anchor = _OwnedDescriptor(run._run_directory_identity)
        self._cleanup_parent = _OwnedDescriptor()
        self._discard_settled = False
        self._marker_release = marker_release
        self._settlement_faults: list[BaseException] = []
        self._state = "claimed"

    def __repr__(self) -> str:
        return f"ArtifactClaim(state={self._state!r})"

    def _require_artifact(self) -> tuple[str, ...]:
        if self._components is None:
            raise ContractError("this lifecycle claim has no artifact destination")
        if self._state not in {"claimed", "open"}:
            raise ContractError(f"artifact claim is already {self._state}")
        return self._components

    def open_writer(self) -> int:
        """Return one disposable writer duplicate for the private stage."""
        components = self._require_artifact()
        if self._stage is not None or self._writer_fd >= 0:
            raise ContractError("artifact claim already issued its writer")
        from . import privfs
        primary = None
        faults: list[BaseException] = []
        try:
            with self._run._mutation(MutationScope.BASE_EVIDENCE):
                self._run._ensure_artifact_parent(components)
                active = self._run._active_mutation_owner()
                if active is None:
                    raise ContractError("artifact claim has no mutation authority")
                self._open_anchor.duplicate(active.run_anchor.fd)
                self._stage = privfs.create_private_stage(
                    self._open_anchor.fd, components,
                )
                self._writer_owner.expected_identity = self._stage.file_identity
                self._writer_owner.duplicate(self._stage.file_fd)
                self._writer_fd = self._writer_owner.fd
        except BaseException as exc:
            primary = exc
        faults.extend(_close_owned_descriptors_twice((self._open_anchor,)))
        preferred = _preferred_settlement_fault(primary, faults)
        if preferred is not None:
            try:
                preferred.close_errors = tuple(faults)
            except BaseException:
                pass
            raise preferred
        self._state = "open"
        return self._writer_fd

    def _writer_is_live(self) -> bool:
        if self._writer_owner.terminal or self._writer_owner.fd < 0 or self._stage is None:
            return False
        try:
            observed = os.fstat(self._writer_owner.fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return False
            raise
        return (observed.st_dev, observed.st_ino) == self._stage.file_identity

    def publish(self) -> None:
        """Settle and durably publish the exact staged bytes."""
        self._require_artifact()
        if self._stage is None:
            raise ContractError("artifact claim has no opened writer")
        writer_faults = _close_owned_descriptors_twice((self._writer_owner,))
        self._writer_fd = self._writer_owner.fd
        preferred = _preferred_settlement_fault(None, writer_faults)
        if preferred is not None:
            raise preferred
        if not self._writer_owner.terminal or self._writer_is_live():
            raise ContractError("artifact writer is still live")
        from . import privfs
        with self._run._mutation(MutationScope.BASE_EVIDENCE):
            privfs.replace_private_stage(self._stage)
        self._state = "published"

    def _settle_writer(self) -> None:
        """Close the one borrowed writer before namespace publication."""
        writer_faults = _close_owned_descriptors_twice((self._writer_owner,))
        self._writer_fd = self._writer_owner.fd
        preferred = _preferred_settlement_fault(None, writer_faults)
        if preferred is not None:
            raise preferred
        if not self._writer_owner.terminal or self._writer_is_live():
            raise ContractError("artifact writer is still live")

    def publish_if_absent(self, *target_components: str) -> bool:
        """CAS the streamed stage to one same-parent canonical leaf.

        The opaque claim retains lifecycle ownership through both successful
        publication and a proven existing target.  A typed private-filesystem
        exception remains the truth for committed-with-fault or uncertain
        outcomes; the stage state is folded before that exact exception escapes.
        """
        components = self._require_artifact()
        target = (
            _validated_artifact_components(tuple(target_components))
            if target_components else components
        )
        if target[:-1] != components[:-1]:
            raise ContractError(
                "managed acquisition publication may change only its final leaf",
            )
        if self._stage is None:
            raise ContractError("artifact claim has no opened writer")
        self._settle_writer()
        from . import privfs
        try:
            with self._run._mutation(MutationScope.BASE_EVIDENCE):
                published = privfs.publish_private_stage_if_absent(
                    self._stage, target,
                )
        except BaseException:
            if self._stage.state == "committed":
                self._state = "published"
            raise
        if published:
            self._state = "published"
            return True
        self.fence()
        return False

    @staticmethod
    def _stage_graph_terminal(stage) -> bool:
        """Return true only when a private stage has no live cleanup graph."""
        if stage is None:
            return True
        if stage.state not in {"aborted", "committed", "fenced"}:
            return False
        ledger = getattr(stage, "_cleanup_ledger", None)
        if ledger is not None and ledger.pending:
            return False
        if any(
            getattr(stage, name) >= 0
            for name in ("file_fd", "parent_fd", "anchor_fd")
        ):
            return False
        target_claim = getattr(stage, "_noreplace_target_claim", None)
        return target_claim is None or getattr(target_claim, "_fd", -1) < 0

    def _terminal(self) -> bool:
        """Return true only for a nominal and physically settled claim graph."""
        discard_terminal = (
            self._stage is None
            or self._stage.state in {"committed", "fenced"}
            or self._discard_settled
        )
        return (
            self._state in {"published", "fenced"}
            and self._writer_owner.fd < 0
            and self._open_anchor.fd < 0
            and self._cleanup_parent.fd < 0
            and self._cleanup_anchor.fd < 0
            and self._stage_graph_terminal(self._stage)
            and discard_terminal
        )

    def fence(self) -> None:
        """Settle an unpublished stage without creating an authoritative final."""
        if self._terminal():
            return
        from . import privfs
        faults: list[BaseException] = []
        for _pass in range(2):
            try:
                with self._run._mutation(MutationScope.CONTROL):
                    faults.extend(_close_owned_descriptors_twice((
                        self._writer_owner, self._open_anchor,
                    )))
                    self._writer_fd = self._writer_owner.fd
                    if (self._stage is not None
                            and not self._stage_graph_terminal(self._stage)):
                        privfs.abort_private_stage(self._stage)
                    if (self._stage is not None
                            and self._stage.state == "aborted"
                            and not self._discard_settled):
                        identity = self._stage.file_identity
                        components = self._stage.components
                        if self._cleanup_anchor.fd < 0:
                            active = self._run._active_mutation_owner()
                            if active is None:
                                raise ContractError("artifact cleanup has no mutation authority")
                            self._cleanup_anchor.duplicate(active.run_anchor.fd)
                        if self._cleanup_parent.fd < 0:
                            _open_strict_directory_into(
                                self._cleanup_parent,
                                self._cleanup_anchor.fd, components[:-1],
                            )
                        for name in os.listdir(self._cleanup_parent.fd):
                            if not (name.startswith(".quarry-discard-")
                                    and name.endswith(".stage")):
                                continue
                            observed = os.stat(
                                name, dir_fd=self._cleanup_parent.fd,
                                follow_symlinks=False,
                            )
                            if (observed.st_dev, observed.st_ino) == identity:
                                os.unlink(name, dir_fd=self._cleanup_parent.fd)
                                os.fsync(self._cleanup_parent.fd)
                                break
                        self._discard_settled = True
            except BaseException as exc:
                faults.append(exc)
            faults.extend(_close_owned_descriptors_twice((
                self._cleanup_parent, self._cleanup_anchor,
            )))
            stage_terminal = self._stage_graph_terminal(self._stage)
            discard_terminal = (
                self._stage is None
                or self._stage.state in {"committed", "fenced"}
                or self._discard_settled
            )
            if (self._writer_owner.fd < 0 and stage_terminal and discard_terminal
                    and self._open_anchor.fd < 0
                    and self._cleanup_parent.fd < 0
                    and self._cleanup_anchor.fd < 0):
                if self._state != "published":
                    self._state = "fenced"
                break
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            try:
                preferred.close_errors = tuple(faults)
            except BaseException:
                pass
            raise preferred
        if not self._terminal():
            raise ContractError("artifact claim did not reach terminal fencing")

    def _settle(self) -> None:
        """Idempotently settle content ownership, then its durable marker."""
        if not self._terminal():
            self.fence()
        if self._terminal():
            with self._run._mutation(MutationScope.CONTROL):
                self._marker_release.settle()
        if not self._marker_release.released:
            raise ContractError("artifact claim marker remains live")


@dataclass(frozen=True)
class ManagedAcquisitionSnapshot:
    """Authenticated immutable facts for one named acquisition object."""

    components: tuple[str, ...]
    identity: tuple[int, int]
    signature: tuple[int, int, int, int, int, int, int]
    size: int
    digest: str
    data: bytes | None = None


@dataclass(frozen=True)
class ManagedRemoval:
    """Truthful terminal state for one requested acquisition discard."""

    state: str
    error: str = ""


@dataclass(frozen=True)
class ManagedAcquisitionCertificate:
    """Opaque terminal proof for one exact pair and optional absent sibling."""

    body: ManagedAcquisitionSnapshot
    receipt: ManagedAcquisitionSnapshot
    absent_components: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ManagedDiscardLedger:
    """Truthful per-object terminal facts for a composite discard."""

    body: ManagedRemoval
    receipt: ManagedRemoval


class _ManagedDiscardSlot:
    """Stable per-name owner across call/result-adoption cancellation gaps."""

    __slots__ = ("components", "expected", "result", "invocations")

    def __init__(self, components, expected) -> None:
        self.components = components
        self.expected = expected
        self.result = ManagedRemoval("pending")
        self.invocations = 0

    def adopt(self, result: ManagedRemoval) -> None:
        if type(result) is not ManagedRemoval:
            result = ManagedRemoval("uncertain", "discard result is invalid")
        if (result.state == "absent" and self.expected is not None
                and self.invocations > 0):
            result = ManagedRemoval("removed")
        self.result = result


class _ManagedDiscardComposite:
    """Stable two-object discard ledger installed before the first unlink."""

    __slots__ = (
        "transaction", "body", "receipt", "primary", "faults",
    )

    def __init__(
        self, transaction,
        body_components, body_expected,
        receipt_components, receipt_expected,
    ) -> None:
        self.transaction = transaction
        self.body = _ManagedDiscardSlot(body_components, body_expected)
        self.receipt = _ManagedDiscardSlot(
            receipt_components, receipt_expected,
        )
        self.primary = None
        self.faults: list[BaseException] = []

    @property
    def ledger(self) -> ManagedDiscardLedger:
        preferred = self.preferred()
        detail = (
            "discard could not be reconciled"
            if preferred is None
            else f"{type(preferred).__name__}: {preferred}"
        )
        def reported(slot):
            if slot.result.state == "pending":
                return ManagedRemoval("uncertain", detail)
            return slot.result
        return ManagedDiscardLedger(reported(self.body), reported(self.receipt))

    def remember(self, fault: BaseException | None) -> None:
        if fault is not None:
            self.primary = _preferred_settlement_fault(
                self.primary, [fault],
            )

    def _remove(self, slot: _ManagedDiscardSlot) -> None:
        if slot.result.state != "pending":
            return
        slot.invocations += 1
        try:
            result = self.transaction.remove_if_matches(
                slot.components, slot.expected,
            )
        except BaseException as exc:
            result = getattr(exc, "managed_removal", None)
            self.faults.append(exc)
            if (type(result) is ManagedRemoval
                    and result.state in {
                        "removed", "removed-with-fault", "absent", "changed",
                    }):
                slot.adopt(result)
        else:
            slot.adopt(result)

    def reconcile(self) -> None:
        for _pass in range(2):
            self._remove(self.body)
            self._remove(self.receipt)

    def preferred(self) -> BaseException | None:
        return _preferred_settlement_fault(self.primary, self.faults)

    def attach(self, fault: BaseException) -> None:
        try:
            fault.managed_discard = self.ledger
        except BaseException:
            pass


def _settle_managed_discard_escape(
    owner: _ManagedDiscardComposite, primary: BaseException,
) -> None:
    owner.remember(primary)
    try:
        owner.reconcile()
    except BaseException as exc:
        owner.faults.append(exc)
    preferred = owner.preferred() or primary
    owner.attach(preferred)
    if preferred is primary:
        raise primary
    raise preferred from primary


def _managed_discard_execute(owner: _ManagedDiscardComposite):
    owner.reconcile()
    preferred = owner.preferred()
    if preferred is not None:
        owner.attach(preferred)
        raise preferred
    return owner.ledger


def _managed_discard_middle(owner: _ManagedDiscardComposite):
    try: return _managed_discard_execute(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard boundary")


def _managed_discard_inner(owner: _ManagedDiscardComposite):
    try: return _managed_discard_middle(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard boundary")


def _managed_discard_outer(owner: _ManagedDiscardComposite):
    try: return _managed_discard_inner(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard boundary")


class _ManagedDiscardFence:
    """Repeat composite reconciliation around every public escape boundary."""

    __slots__ = ("owner",)

    def __init__(self, owner: _ManagedDiscardComposite) -> None:
        self.owner = owner

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, primary, _traceback) -> bool:
        self.owner.remember(primary)
        try:
            self.owner.reconcile()
        except BaseException as exc:
            self.owner.faults.append(exc)
        preferred = self.owner.preferred()
        if preferred is None:
            return False
        self.owner.attach(preferred)
        if preferred is primary:
            return False
        if primary is None:
            raise preferred
        raise preferred from primary


def _managed_discard_fenced(owner: _ManagedDiscardComposite):
    outer = _ManagedDiscardFence(owner)
    inner = _ManagedDiscardFence(owner)
    with outer:
        with inner:
            return _managed_discard_outer(owner)


def _managed_discard_public_middle(owner: _ManagedDiscardComposite):
    try: return _managed_discard_fenced(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard public boundary")


def _managed_discard_public_inner(owner: _ManagedDiscardComposite):
    try: return _managed_discard_public_middle(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard public boundary")


def _managed_discard_public_outer(owner: _ManagedDiscardComposite):
    try: return _managed_discard_public_inner(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard public boundary")


def _managed_discard_public_export(owner: _ManagedDiscardComposite):
    try: return _managed_discard_public_outer(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard public boundary")


def _managed_discard_public_reserved(owner: _ManagedDiscardComposite):
    try: return _managed_discard_public_export(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard public boundary")


def _managed_discard_public_final(owner: _ManagedDiscardComposite):
    try: return _managed_discard_public_reserved(owner)
    except BaseException as primary:
        _settle_managed_discard_escape(owner, primary)
    raise AssertionError("unreachable managed discard public boundary")


def _managed_discard_public(owner: _ManagedDiscardComposite):
    return _managed_discard_public_final(owner)


def _managed_discard_pair_middle(
    transaction, body_components, body_expected,
    receipt_components, receipt_expected,
):
    return transaction._discard_pair_owned(
        body_components, body_expected, receipt_components, receipt_expected,
    )


def _managed_discard_pair_inner(
    transaction, body_components, body_expected,
    receipt_components, receipt_expected,
):
    return _managed_discard_pair_middle(
        transaction, body_components, body_expected,
        receipt_components, receipt_expected,
    )


def _managed_discard_pair_export(
    transaction, body_components, body_expected,
    receipt_components, receipt_expected,
):
    # This chain is deliberately effect-free until ``_discard_pair_owned`` has
    # installed the stable composite.  A cancellation on an earlier trampoline
    # therefore truthfully means both requested names remain unattempted.
    return _managed_discard_pair_inner(
        transaction, body_components, body_expected,
        receipt_components, receipt_expected,
    )


class _ManagedPairRelease:
    """Release one durable marker while an exact second name overlaps it.

    The deterministic lease remains visible through the terminal pair
    postcheck.  A random valid ``*.claim`` hard link then remains visible while
    the deterministic name is removed.  Thus every nonterminal instant keeps
    at least one scan-recognizable name bound to the exact locked inode.
    """

    __slots__ = (
        "marker", "validate_pair", "quarantine", "started", "move_possible",
        "moved", "move_durable", "postchecked", "delete_possible",
        "terminal", "restored", "primary", "faults",
    )

    def __init__(self, marker, validate_pair) -> None:
        self.marker = marker
        self.validate_pair = validate_pair
        self.quarantine = f"{os.urandom(16).hex()}{_CLAIM_SUFFIX}"
        self.started = False
        self.move_possible = False
        self.moved = False
        self.move_durable = False
        self.postchecked = False
        self.delete_possible = False
        self.terminal = False
        self.restored = False
        self.primary = None
        self.faults: list[BaseException] = []

    def _named(self, name: str, *, allow_two_links: bool = False):
        try:
            observed = os.stat(
                name, dir_fd=self.marker.directory.fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        from . import privfs
        if (not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE
                or observed.st_nlink not in (
                    {1, 2} if allow_two_links else {1}
                )):
            raise ManagedAcquisitionRefused(
                "managed acquisition marker release name is unsafe",
            )
        identity = (observed.st_dev, observed.st_ino)
        if identity != self.marker.marker.identity:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker release name was substituted",
            )
        return identity

    def _positions_locked(self, *, allow_both: bool = False) -> tuple[bool, bool]:
        deterministic = self._named(
            self.marker.name, allow_two_links=allow_both,
        ) is not None
        quarantine = self._named(
            self.quarantine, allow_two_links=allow_both,
        ) is not None
        if deterministic and quarantine and not allow_both:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker exists under two release names",
            )
        observed = os.fstat(self.marker.marker.fd)
        expected_links = int(deterministic) + int(quarantine)
        if ((observed.st_dev, observed.st_ino) != self.marker.marker.identity
                or observed.st_nlink != expected_links):
            raise ManagedAcquisitionRefused(
                "managed acquisition marker release inode changed",
            )
        return deterministic, quarantine

    def _validate_exact_body_locked(self) -> None:
        observed = os.fstat(self.marker.marker.fd)
        self.marker._validate_marker_stat(observed)
        os.lseek(self.marker.marker.fd, 0, os.SEEK_SET)
        if os.read(self.marker.marker.fd, 64 * 1024 + 1) != self.marker.body:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker body changed during release",
            )

    def _provisional_unlink_locked(self) -> None:
        """Create and durably authenticate the exact overlapping name."""
        self.marker.validate_owned_locked()
        deterministic, quarantine = self._positions_locked(allow_both=True)
        if deterministic and quarantine:
            self.moved = True
        elif deterministic and not quarantine:
            self.move_possible = True
            os.link(
                self.marker.name, self.quarantine,
                src_dir_fd=self.marker.directory.fd,
                dst_dir_fd=self.marker.directory.fd,
                follow_symlinks=False,
            )
            deterministic, quarantine = self._positions_locked(allow_both=True)
            if not deterministic or not quarantine:
                raise ManagedAcquisitionRefused(
                    "managed acquisition marker overlap link did not commit",
                )
            self.moved = True
        else:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker changed before overlap",
            )
        os.fsync(self.marker.directory.fd)
        self.move_durable = True

    @property
    def needs_restoration(self) -> bool:
        return self.move_possible and not self.terminal and not self.restored

    def ensure_restored(self) -> None:
        """Return uncertainty to one exact deterministic marker name."""
        if self.terminal or self.restored:
            return
        self.marker.require_origin_process()
        self.marker._pin_registry_locked()
        deterministic, quarantine = self._positions_locked(allow_both=True)
        if deterministic and quarantine:
            self._unlink_exact_name_locked(self.quarantine, expected_after=1)
            os.fsync(self.marker.directory.fd)
            if self.marker._named_identity() != self.marker.marker.identity:
                raise ManagedAcquisitionRefused(
                    "managed acquisition marker deterministic name was not restored",
                )
            self._validate_exact_body_locked()
            self.restored = True
            self.marker.abandoned = True
            return
        if deterministic:
            self._validate_exact_body_locked()
            os.fsync(self.marker.directory.fd)
            self.restored = True
            self.marker.abandoned = True
            return
        if not quarantine:
            if self.delete_possible and os.fstat(self.marker.marker.fd).st_nlink == 0:
                # The final unlink committed but its result assignment/fault
                # escaped.  Only an exact terminal pair permits adopting it.
                self.validate_pair()
                os.fsync(self.marker.directory.fd)
                self.marker.released = True
                self.marker.ready = False
                self.terminal = True
                return
            raise ManagedAcquisitionRefused(
                "managed acquisition marker has no recoverable release name",
            )
        # Legacy recovery for an overlap whose deterministic unlink committed:
        # recreate that name before removing quarantine.
        os.link(
            self.quarantine, self.marker.name,
            src_dir_fd=self.marker.directory.fd,
            dst_dir_fd=self.marker.directory.fd,
            follow_symlinks=False,
        )
        os.fsync(self.marker.directory.fd)
        named = os.stat(
            self.marker.name, dir_fd=self.marker.directory.fd,
            follow_symlinks=False,
        )
        quarantined = os.stat(
            self.quarantine, dir_fd=self.marker.directory.fd,
            follow_symlinks=False,
        )
        identity = self.marker.marker.identity
        if ((named.st_dev, named.st_ino) != identity
                or (quarantined.st_dev, quarantined.st_ino) != identity
                or os.fstat(self.marker.marker.fd).st_nlink != 2):
            raise ManagedAcquisitionRefused(
                "managed acquisition marker restoration link changed",
            )
        self._unlink_exact_name_locked(self.quarantine, expected_after=1)
        os.fsync(self.marker.directory.fd)
        if self.marker._named_identity() != identity:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker deterministic name was not restored",
            )
        self._validate_exact_body_locked()
        self.restored = True
        self.marker.abandoned = True

    def _unlink_exact_name_locked(
        self, name: str, *, expected_after: int,
        validate_before=None, validate_after=None,
    ) -> None:
        """Authenticate and unlink on one traced authority line, then reconcile.

        A terminal pair validator may be coupled to the namespace effect.  The
        first unlink retains the other exact marker name while its postcheck
        runs; the last unlink follows a validator on the same traced line.
        """
        identity = self.marker.marker.identity
        named = os.stat(
            name, dir_fd=self.marker.directory.fd, follow_symlinks=False,
        )
        if ((named.st_dev, named.st_ino) != identity
                or named.st_nlink not in {1, 2}):
            raise ManagedAcquisitionRefused(
                "managed acquisition marker release name was substituted",
            )
        # Keep the final authority check and namespace effect on one physical
        # traced line.  A wrapper can run only after the effect and is handled
        # by the descriptor/name reconciliation below.
        if validate_before is None:
            named = os.stat(name, dir_fd=self.marker.directory.fd, follow_symlinks=False); os.unlink(name, dir_fd=self.marker.directory.fd)  # noqa: E702 - one traced authority boundary
        else:
            validate_before(); named = os.stat(name, dir_fd=self.marker.directory.fd, follow_symlinks=False); os.unlink(name, dir_fd=self.marker.directory.fd)  # noqa: E702 - one traced authority boundary
        if (named.st_dev, named.st_ino) != identity:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker release name changed at unlink",
            )
        observed = os.fstat(self.marker.marker.fd)
        if observed.st_nlink != expected_after:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker unlink changed the wrong inode",
            )
        if validate_after is not None:
            validate_after()

    def _delete_quarantine_locked(self) -> None:
        deterministic, quarantine = self._positions_locked(allow_both=True)
        if not deterministic or not quarantine:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker overlap is incomplete",
            )
        self.delete_possible = True
        self._unlink_exact_name_locked(
            self.marker.name, expected_after=1,
            validate_before=self.validate_pair,
            validate_after=self.validate_pair,
        )
        # The random exact name still blocks every contender while the
        # deterministic name is absent.  Remove it only after reconciling the
        # first unlink through the pinned marker descriptor.
        self._unlink_exact_name_locked(
            self.quarantine, expected_after=0,
            validate_before=self.validate_pair,
        )
        if os.fstat(self.marker.marker.fd).st_nlink != 0:
            raise ManagedAcquisitionRefused(
                "managed acquisition marker terminal unlink did not commit",
            )
        os.fsync(self.marker.directory.fd)
        self.marker.released = True
        self.marker.ready = False
        self.terminal = True

    def execute(self) -> None:
        if self.terminal:
            return
        self.started = True
        try:
            self.validate_pair()
            self._provisional_unlink_locked()
            self.validate_pair()
            self.postchecked = True
            self._delete_quarantine_locked()
        except BaseException as exc:
            self.primary = _preferred_settlement_fault(self.primary, [exc])
            raise

    def settle(self) -> None:
        if self.terminal:
            return
        faults: list[BaseException] = []
        # Before a possible rename, one retry may still complete.  Once the
        # deterministic name may have moved, only exact restoration is safe.
        if not self.move_possible:
            try:
                self.execute()
            except BaseException as exc:
                faults.append(exc)
        if not self.terminal:
            try:
                self.ensure_restored()
            except BaseException as exc:
                faults.append(exc)
            if not self.terminal:
                self.marker.released = False
                if self.restored:
                    self.marker.abandoned = True
        self.faults.extend(faults)
        preferred = _preferred_settlement_fault(self.primary, self.faults)
        if preferred is not None:
            raise preferred
        if not self.terminal:
            raise ManagedAcquisitionRefused(
                "managed acquisition terminal pair release remained uncertain",
            )


class _ManagedAcquisitionCompanion:
    """Stable adoption record for one exact companion byte generation.

    Constructing this record has no descriptor or namespace effects.  The
    transaction adopts the complete record with one attribute store before it
    opens a stage, so cancellation cannot leave an artifact owner whose frozen
    byte identity is missing.
    """

    __slots__ = ("identity", "artifact", "staged")

    def __init__(
        self, run, components: tuple[str, ...], marker,
        identity: tuple[tuple[str, ...], int, bytes],
    ) -> None:
        self.identity = identity
        self.artifact = _ArtifactClaim(run, components, marker)
        self.staged = False


class _ManagedAcquisitionTransaction:
    """Opaque descriptor-relative transaction behind one destination lease."""

    __slots__ = (
        "run", "components", "marker", "artifact", "anchor", "parent",
        "active", "settled", "companion", "contact_attempted",
        "terminal_certificate", "retain_reason", "clean_precontact",
        "discard_started",
    )

    def __init__(
        self, run, components: tuple[str, ...], marker: _ManagedAcquisitionMarker,
    ) -> None:
        self.run = run
        self.components = components
        self.marker = marker
        self.artifact = _ArtifactClaim(run, components, marker)
        self.anchor = _OwnedDescriptor(run._run_directory_identity)
        self.parent = _OwnedDescriptor()
        self.active = False
        self.settled = False
        self.companion = None
        self.contact_attempted = False
        self.terminal_certificate = None
        self.retain_reason = None
        self.clean_precontact = False
        self.discard_started = False

    def _require_origin_process(self) -> None:
        self.marker.require_origin_process()

    @staticmethod
    def _close_inherited_number(owner, name: str, identity) -> None:
        """Child-only authenticated close of one inherited numeric slot."""
        fd = getattr(owner, name, -1)
        if type(fd) is not int or fd < 0:
            return
        try:
            observed = os.fstat(fd)
        except OSError:
            observed = None
        if name == "fd":
            owner.fd = -1
            owner.terminal = True
        else:
            object.__setattr__(owner, name, -1)
        if (observed is None or type(identity) is not tuple
                or (observed.st_dev, observed.st_ino) != identity):
            return
        try:
            os.close(fd)
        except OSError:
            pass

    @classmethod
    def _close_inherited_stage(cls, stage) -> None:
        """Child-only close of every descriptor reachable from one stage."""
        if stage is None:
            return
        for name, identity in (
            ("_file_fd", getattr(stage, "file_identity", None)),
            ("_parent_fd", getattr(stage, "parent_identity", None)),
            ("_anchor_fd", getattr(stage, "anchor_identity", None)),
        ):
            cls._close_inherited_number(stage, name, identity)
        ledger = getattr(stage, "_cleanup_ledger", None)
        for claim in (() if ledger is None else ledger.claims):
            identity = getattr(claim, "_owned_identity", None)
            if identity is None:
                identity = getattr(claim, "_identity", None)
            cls._close_inherited_number(claim, "_fd", identity)
        target_claim = getattr(stage, "_noreplace_target_claim", None)
        if target_claim is not None:
            identity = getattr(target_claim, "_owned_identity", None)
            if identity is None:
                identity = getattr(target_claim, "_identity", None)
            cls._close_inherited_number(target_claim, "_fd", identity)

    def _close_inherited_graph_at_fork(self) -> None:
        """Close-only child hook; never unlink, publish, abort or LOCK_UN."""
        companion_artifact = (
            None if self.companion is None else self.companion.artifact
        )
        claims = (self.artifact,) + (
            () if companion_artifact is None
            else (companion_artifact,)
        )
        owners = tuple(
            owner
            for claim in claims
            for owner in (
                claim._writer_owner, claim._open_anchor,
                claim._cleanup_parent, claim._cleanup_anchor,
            )
        ) + (
            self.parent, self.anchor, self.marker.marker,
            self.marker.directory,
        )
        for owner in owners:
            self._close_inherited_number(owner, "fd", owner.identity)
        self._close_inherited_stage(self.artifact._stage)
        if companion_artifact is not None:
            self._close_inherited_stage(companion_artifact._stage)
        self.marker.locked = False

    @staticmethod
    def _stage_terminal(stage) -> bool:
        return _ArtifactClaim._stage_graph_terminal(stage)

    def activate(self) -> None:
        self._require_origin_process()
        with self.run._mutation(MutationScope.BASE_EVIDENCE):
            owner = self.run._active_mutation_owner()
            if owner is None:
                raise ContractError(
                    "managed acquisition transaction has no mutation authority",
                )
            self.anchor.duplicate(owner.run_anchor.fd)
            _open_strict_directory_into(
                self.parent, self.anchor.fd, self.components[:-1],
            )
        self.active = True

    def _target(self, components: tuple[str, ...]) -> tuple[str, ...]:
        components = _validated_artifact_components(components)
        if components[:-1] != self.components[:-1]:
            raise ContractError(
                "managed acquisition transaction is limited to one pinned parent",
            )
        return components

    def mark_contact_attempted(self) -> None:
        """Monotonically arm fail-closed settlement before an opener call."""
        self._require_origin_process()
        with self.run._mutation(MutationScope.BASE_EVIDENCE):
            self._reauthenticate_locked()
            self.contact_attempted = True
            self.clean_precontact = False

    def retain_uncertain(self, reason: str = "managed acquisition is uncertain") -> None:
        """Require durable stale evidence while draining ephemeral ownership."""
        self._require_origin_process()
        if type(reason) is not str or not reason:
            raise ValueError("managed acquisition uncertainty reason is invalid")
        if self.retain_reason is None:
            self.retain_reason = reason
        self.clean_precontact = False

    def settle_precontact(self) -> None:
        """Authorize clean marker release only when no contact was attempted."""
        self._require_origin_process()
        if self.contact_attempted:
            raise ContractError(
                "contacted acquisition cannot settle as a precontact refusal",
            )
        self.clean_precontact = True

    @staticmethod
    def _snapshot_matches(
        expected: ManagedAcquisitionSnapshot,
        observed: ManagedAcquisitionSnapshot | None,
    ) -> bool:
        return (
            observed is not None
            and observed.components == expected.components
            and observed.identity == expected.identity
            and observed.signature == expected.signature
            and observed.size == expected.size
            and observed.digest == expected.digest
            and (expected.data is None or observed.data == expected.data)
        )

    def certify_pair(
        self,
        body: ManagedAcquisitionSnapshot,
        receipt: ManagedAcquisitionSnapshot,
        *, absent_components: tuple[str, ...] | None = None,
    ) -> ManagedAcquisitionCertificate:
        """Certify an exact pair and mutually-exclusive absent sibling."""
        self._require_origin_process()
        if (type(body) is not ManagedAcquisitionSnapshot
                or type(receipt) is not ManagedAcquisitionSnapshot):
            raise TypeError("managed acquisition pair snapshots are invalid")
        body_components = self._target(body.components)
        receipt_components = self._target(receipt.components)
        absent_components = (
            None if absent_components is None
            else self._target(absent_components)
        )
        if (absent_components is not None
                and absent_components in {body_components, receipt_components}):
            raise ValueError(
                "managed acquisition absent sibling duplicates a certified name",
            )
        if self.retain_reason is not None:
            raise ManagedAcquisitionRefused(
                "managed acquisition was already retained as uncertain",
            )
        with self.run._mutation(MutationScope.BASE_EVIDENCE):
            self._reauthenticate_locked()
            current_body, current_receipt = self._snapshot_pair_locked(
                body_components, receipt_components,
                absent_components=absent_components,
            )
            if (not self._snapshot_matches(body, current_body)
                    or not self._snapshot_matches(receipt, current_receipt)):
                self.retain_uncertain(
                    "managed acquisition terminal pair changed during certification",
                )
                raise ManagedAcquisitionRefused(
                    "managed acquisition terminal pair is no longer current",
                )
            certificate = ManagedAcquisitionCertificate(
                current_body, current_receipt, absent_components,
            )
            if (self.terminal_certificate is not None
                    and self.terminal_certificate != certificate):
                self.retain_uncertain(
                    "managed acquisition terminal certificate changed",
                )
                raise ManagedAcquisitionRefused(
                    "managed acquisition terminal certificate changed",
                )
            self.terminal_certificate = certificate
            self.clean_precontact = False
            return certificate

    def _reauthenticate_locked(self) -> None:
        if not self.active or self.anchor.fd < 0 or self.parent.fd < 0:
            raise ContractError("managed acquisition transaction is not live")
        owner = self.run._active_mutation_owner()
        if owner is None:
            raise ContractError(
                "managed acquisition transaction has no mutation authority",
            )
        self.marker.validate_owned_locked()
        if ((os.fstat(self.anchor.fd).st_dev, os.fstat(self.anchor.fd).st_ino)
                != owner.run_anchor.identity):
            raise ManagedAcquisitionRefused(
                "managed acquisition Run identity changed during contact",
            )
        verifier = _OwnedDescriptor(self.parent.identity)
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners(
                (verifier,), "managed acquisition parent verifier",
            ),
        )
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                _open_strict_directory_into(
                    verifier, owner.run_anchor.fd, self.components[:-1],
                )
                if verifier.identity != self.parent.identity:
                    raise ManagedAcquisitionRefused(
                        "managed acquisition destination parent changed",
                    )

    @staticmethod
    def _snapshot_signature(observed) -> tuple[int, int, int, int, int, int, int]:
        return (
            observed.st_dev, observed.st_ino, observed.st_mode,
            observed.st_nlink, observed.st_size,
            observed.st_mtime_ns, observed.st_ctime_ns,
        )

    def _snapshot_pair_locked(
        self,
        body_components: tuple[str, ...],
        receipt_components: tuple[str, ...],
        *, absent_components: tuple[str, ...] | None = None,
        release_certificate: ManagedAcquisitionCertificate | None = None,
    ) -> tuple[ManagedAcquisitionSnapshot | None,
               ManagedAcquisitionSnapshot | None]:
        """Pin and authenticate both terminal names through one epoch."""
        body_owner = _OwnedDescriptor()
        receipt_owner = _OwnedDescriptor()
        owners = (body_owner, receipt_owner)
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners(
                owners, "managed acquisition pair certificate descriptors",
            ),
        )

        def opened_snapshot(owner, components, *, capture: bool):
            before = os.fstat(owner.fd)
            self.run._validate_base_file_stat(before, components)
            digest = hashlib.sha256()
            chunks: list[bytes] = []
            captured = 0
            while True:
                chunk = os.read(owner.fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                if capture:
                    if captured + len(chunk) > 1024 * 1024:
                        raise ManagedAcquisitionRefused(
                            "managed acquisition companion exceeds its read bound",
                        )
                    chunks.append(chunk)
                    captured += len(chunk)
            after = os.fstat(owner.fd)
            before_signature = self._snapshot_signature(before)
            if self._snapshot_signature(after) != before_signature:
                raise ManagedAcquisitionRefused(
                    "managed acquisition pair changed while inspected",
                )
            return before_signature, digest.hexdigest(), (
                b"".join(chunks) if capture else None
            )

        def validate_absent_sibling():
            if absent_components is None:
                return
            try:
                os.stat(
                    absent_components[-1], dir_fd=self.parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return
            raise ManagedAcquisitionRefused(
                "managed acquisition mutually exclusive sibling is present",
            )

        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                missing = []
                for owner, components in (
                    (body_owner, body_components),
                    (receipt_owner, receipt_components),
                ):
                    try:
                        owner.open(
                            components[-1], _FILE_OPEN_FLAGS,
                            dir_fd=self.parent.fd,
                        )
                    except FileNotFoundError:
                        missing.append(owner)
                if missing:
                    return None, None
                body_signature, body_digest, _body_data = opened_snapshot(
                    body_owner, body_components, capture=False,
                )
                receipt_signature, receipt_digest, receipt_data = opened_snapshot(
                    receipt_owner, receipt_components, capture=True,
                )
                named_body = os.stat(
                    body_components[-1], dir_fd=self.parent.fd,
                    follow_symlinks=False,
                )
                named_receipt = os.stat(
                    receipt_components[-1], dir_fd=self.parent.fd,
                    follow_symlinks=False,
                )
                if (self._snapshot_signature(named_body) != body_signature
                        or self._snapshot_signature(named_receipt)
                        != receipt_signature):
                    raise ManagedAcquisitionRefused(
                        "managed acquisition pair names changed while certified",
                    )
                validate_absent_sibling()
                pair = (
                    ManagedAcquisitionSnapshot(
                        body_components,
                        (body_signature[0], body_signature[1]),
                        body_signature, body_signature[4], body_digest,
                    ),
                    ManagedAcquisitionSnapshot(
                        receipt_components,
                        (receipt_signature[0], receipt_signature[1]),
                        receipt_signature, receipt_signature[4], receipt_digest,
                        receipt_data,
                    ),
                )
                if release_certificate is not None:
                    if (not self._snapshot_matches(
                            release_certificate.body, pair[0],
                        ) or not self._snapshot_matches(
                            release_certificate.receipt, pair[1],
                        )):
                        return pair
                    def validate_pinned_pair():
                        for owner, components, expected in (
                            (body_owner, body_components,
                             release_certificate.body),
                            (receipt_owner, receipt_components,
                             release_certificate.receipt),
                        ):
                            before = os.fstat(owner.fd)
                            os.lseek(owner.fd, 0, os.SEEK_SET)
                            digest = hashlib.sha256()
                            while True:
                                chunk = os.read(owner.fd, 1024 * 1024)
                                if not chunk:
                                    break
                                digest.update(chunk)
                            after = os.fstat(owner.fd)
                            named = os.stat(
                                components[-1], dir_fd=self.parent.fd,
                                follow_symlinks=False,
                            )
                            if (self._snapshot_signature(before)
                                    != expected.signature
                                    or self._snapshot_signature(after)
                                    != expected.signature
                                    or self._snapshot_signature(named)
                                    != expected.signature
                                    or digest.hexdigest() != expected.digest):
                                raise ManagedAcquisitionRefused(
                                    "managed acquisition terminal pair changed at release",
                                )
                        validate_absent_sibling()

                    # Both exact inodes remain pinned through a provisional
                    # marker unlink and its postcheck.  Any mismatch, fault or
                    # cancellation restores the deterministic durable marker
                    # before this BASE mutation can release the old flock.
                    release = self.marker.release_owner = _ManagedPairRelease(
                        self.marker, validate_pinned_pair,
                    )
                    settlement = _SettlementOwner(release.settle)
                    with _SettlementFence(settlement):
                        with _SettlementFence(settlement):
                            release.execute()
                    if release.terminal:
                        self.marker.settle()
                return pair

    def snapshot(
        self, components: tuple[str, ...], *, content_limit: int | None = None,
    ) -> ManagedAcquisitionSnapshot | None:
        """Read/hash one strict named object through the pinned parent."""
        self._require_origin_process()
        components = self._target(components)
        if content_limit is not None and (
            type(content_limit) is not int or content_limit < 0
        ):
            raise ValueError("managed acquisition content limit is invalid")
        slot = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners(
                (slot,), "managed acquisition snapshot descriptor",
            ),
        )
        with self.run._mutation(MutationScope.BASE_EVIDENCE):
            self._reauthenticate_locked()
            try:
                with _SettlementFence(settlement):
                    with _SettlementFence(settlement):
                        try:
                            slot.open(
                                components[-1], _FILE_OPEN_FLAGS,
                                dir_fd=self.parent.fd,
                            )
                        except FileNotFoundError:
                            return None
                        before = os.fstat(slot.fd)
                        self.run._validate_base_file_stat(before, components)
                        digest = hashlib.sha256()
                        chunks: list[bytes] = []
                        captured = 0
                        while True:
                            chunk = os.read(slot.fd, 1024 * 1024)
                            if not chunk:
                                break
                            digest.update(chunk)
                            if content_limit is not None:
                                if captured + len(chunk) > content_limit:
                                    raise ManagedAcquisitionRefused(
                                        "managed acquisition companion exceeds its read bound",
                                    )
                                chunks.append(chunk)
                                captured += len(chunk)
                        after = os.fstat(slot.fd)
                        named = os.stat(
                            components[-1], dir_fd=self.parent.fd,
                            follow_symlinks=False,
                        )
                        before_signature = self._snapshot_signature(before)
                        if (self._snapshot_signature(after) != before_signature
                                or self._snapshot_signature(named) != before_signature):
                            raise ManagedAcquisitionRefused(
                                "managed acquisition object changed while inspected",
                            )
                        return ManagedAcquisitionSnapshot(
                            components=components,
                            identity=(before.st_dev, before.st_ino),
                            signature=before_signature,
                            size=before.st_size,
                            digest=digest.hexdigest(),
                            data=(b"".join(chunks)
                                  if content_limit is not None else None),
                        )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.EISDIR}:
                    raise ManagedAcquisitionRefused(
                        "managed acquisition object is unsafe",
                    ) from exc
                raise

    def open_writer(self) -> int:
        self._require_origin_process()
        with self.run._mutation(MutationScope.BASE_EVIDENCE):
            self._reauthenticate_locked()
            return self.artifact.open_writer()

    def publish_body_if_absent(
        self, components: tuple[str, ...] | None = None,
    ) -> bool:
        self._require_origin_process()
        target = self.components if components is None else self._target(components)
        with self.run._mutation(MutationScope.BASE_EVIDENCE):
            self._reauthenticate_locked()
            return self.artifact.publish_if_absent(*target)

    def _companion_stage_identity_locked(
        self, companion: _ManagedAcquisitionCompanion,
    ) -> tuple[int, bytes]:
        """Authenticate the exact bytes retained after an interrupted write."""
        artifact = companion.artifact
        stage = artifact._stage
        if stage is None or stage.state != "open":
            raise ContractError(
                "managed acquisition companion stage cannot be reconciled",
            )
        artifact._settle_writer()
        reader = _OwnedDescriptor(stage.file_identity)
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners(
                (reader,), "managed acquisition companion verifier",
            ),
        )
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                reader.open(
                    stage.temporary_name, _FILE_OPEN_FLAGS,
                    dir_fd=stage.parent_fd,
                )
                before = _identity_stat(reader.fd)
                self.run._validate_base_file_stat(
                    os.fstat(reader.fd), stage.components,
                )
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(reader.fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = _identity_stat(reader.fd)
                named = os.stat(
                    stage.temporary_name, dir_fd=stage.parent_fd,
                    follow_symlinks=False,
                )
                named_signature = (
                    named.st_dev, named.st_ino, named.st_mode, named.st_nlink,
                    named.st_size, named.st_mtime_ns, named.st_ctime_ns,
                )
                if before != after or before != named_signature:
                    raise ManagedAcquisitionRefused(
                        "managed acquisition companion stage changed while reconciled",
                    )
                return before[4], digest.digest()

    @staticmethod
    def _seal_companion_exact_locked(
        companion: _ManagedAcquisitionCompanion,
    ) -> None:
        """Bind the requested generation into privfs' sealed CAS proof."""
        from . import privfs
        stage = companion.artifact._stage
        if stage is None:
            raise ContractError(
                "managed acquisition companion has no stage to authenticate",
            )
        if stage.state in {"open", "sealed"}:
            privfs.seal_private_stage(stage)
        elif stage.state != "replaced_uncertain":
            raise ContractError(
                "managed acquisition companion stage cannot replay exact bytes",
            )
        expected = (
            companion.identity[1], companion.identity[2].hex(),
        )
        if stage.sealed_digest != expected:
            raise ContractError(
                "managed acquisition companion stage does not match exact bytes",
            )

    def publish_companion_if_absent(
        self, components: tuple[str, ...], data: bytes,
    ) -> bool:
        self._require_origin_process()
        components = self._target(components)
        if type(data) is not bytes:
            raise TypeError("managed acquisition companion must be exact bytes")
        identity = (components, len(data), hashlib.sha256(data).digest())
        companion = self.companion
        if companion is not None and companion.identity != identity:
            raise ContractError(
                "managed acquisition companion publication changed on replay",
            )
        # Adopt the companion lifecycle before its first descriptor or stage
        # effect.  It deliberately shares the transaction marker, but the
        # transaction (not either ArtifactClaim) settles that marker once both
        # artifact ledgers are terminal.
        if companion is None:
            self.companion = companion = _ManagedAcquisitionCompanion(
                self.run, components, self.marker, identity,
            )
        artifact = companion.artifact
        with self.run._mutation(MutationScope.BASE_EVIDENCE):
            self._reauthenticate_locked()
            if artifact._state == "published":
                if artifact._terminal():
                    return True
                raise ContractError(
                    "managed acquisition companion commit is not terminal",
                )
            if artifact._state == "fenced":
                if artifact._terminal():
                    return False
                raise ContractError(
                    "managed acquisition companion refusal is not terminal",
                )
            if artifact._stage is None:
                writer = artifact.open_writer()
                _write_all_descriptor(writer, data)
                companion.staged = True
            elif not companion.staged:
                observed = self._companion_stage_identity_locked(companion)
                if observed != identity[1:]:
                    raise ContractError(
                        "managed acquisition companion staging is partial or changed",
                    )
                companion.staged = True
            self._seal_companion_exact_locked(companion)
            return artifact.publish_if_absent(*components)

    def _remove_if_matches_inner(
        self, components: tuple[str, ...],
        expected: ManagedAcquisitionSnapshot | None,
    ) -> ManagedRemoval:
        """Remove only the exact snapshotted inode, reconciling unlink faults."""
        self._require_origin_process()
        components = self._target(components)
        if expected is None:
            current = self.snapshot(components)
            return ManagedRemoval("absent" if current is None else "changed")
        if (type(expected) is not ManagedAcquisitionSnapshot
                or expected.components != components):
            raise TypeError("managed acquisition discard snapshot is invalid")
        # Adopt whichever strict inode currently owns the name, then compare it
        # to the prior snapshot.  A legitimate foreign replacement is a
        # truthful ``changed`` result, not a descriptor-allocation failure.
        slot = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners(
                (slot,), "managed acquisition discard descriptor",
            ),
        )
        primary = None
        result = ManagedRemoval("unremoved")
        with self.run._mutation(MutationScope.BASE_EVIDENCE):
            self._reauthenticate_locked()
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    try:
                        slot.open(
                            components[-1], _FILE_OPEN_FLAGS,
                            dir_fd=self.parent.fd,
                        )
                    except FileNotFoundError:
                        return ManagedRemoval("absent")
                    before = os.fstat(slot.fd)
                    self.run._validate_base_file_stat(before, components)
                    if self._snapshot_signature(before) != expected.signature:
                        return ManagedRemoval("changed")
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(slot.fd, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                    if digest.hexdigest() != expected.digest:
                        return ManagedRemoval("changed")
                    try:
                        os.unlink(components[-1], dir_fd=self.parent.fd)
                    except BaseException as exc:
                        primary = exc
                    try:
                        named = os.stat(
                            components[-1], dir_fd=self.parent.fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        named = None
                    retained = os.fstat(slot.fd)
                    if named is None and retained.st_nlink == 0:
                        try:
                            os.fsync(self.parent.fd)
                        except BaseException as exc:
                            if primary is None:
                                primary = exc
                        result = ManagedRemoval(
                            "removed" if primary is None else "removed-with-fault",
                            "" if primary is None else f"{type(primary).__name__}: {primary}",
                        )
                    elif named is not None and (
                        named.st_dev, named.st_ino
                    ) != expected.identity:
                        result = ManagedRemoval("changed")
                    else:
                        result = ManagedRemoval(
                            "unremoved",
                            "unlink did not commit" if primary is None
                            else f"{type(primary).__name__}: {primary}",
                        )
        if primary is not None and not isinstance(primary, Exception):
            try:
                primary.managed_removal = result
            except BaseException:
                pass
            raise primary
        return result

    def _reconcile_removal_escape(
        self, components: tuple[str, ...],
        expected: ManagedAcquisitionSnapshot | None,
        primary: BaseException,
    ) -> None:
        """Attach terminal named truth before an exact escape is re-raised."""
        self._require_origin_process()
        result = None
        reconciliation_error = None
        try:
            components = self._target(components)
            current = self.snapshot(components)
            if expected is None:
                result = ManagedRemoval(
                    "absent" if current is None else "changed",
                )
            elif current is None:
                result = ManagedRemoval("removed")
            elif (current.identity == expected.identity
                    and current.signature == expected.signature
                    and current.digest == expected.digest):
                result = ManagedRemoval("unremoved")
            else:
                result = ManagedRemoval("changed")
        except BaseException as exc:
            reconciliation_error = exc
            result = ManagedRemoval(
                "uncertain", f"{type(exc).__name__}: {exc}",
            )
        for name, value in (
            ("managed_removal", result),
            ("managed_removal_reconciliation_error", reconciliation_error),
        ):
            try:
                setattr(primary, name, value)
            except BaseException:
                pass
        raise primary

    def _remove_if_matches_public_inner(
        self, components: tuple[str, ...],
        expected: ManagedAcquisitionSnapshot | None,
    ) -> ManagedRemoval:
        try:
            return self._remove_if_matches_inner(components, expected)
        except BaseException as primary:
            self._reconcile_removal_escape(components, expected, primary)
        raise AssertionError("unreachable managed removal boundary")

    def _remove_if_matches_public_outer(
        self, components: tuple[str, ...],
        expected: ManagedAcquisitionSnapshot | None,
    ) -> ManagedRemoval:
        try:
            return self._remove_if_matches_public_inner(components, expected)
        except BaseException as primary:
            self._reconcile_removal_escape(components, expected, primary)
        raise AssertionError("unreachable managed removal boundary")

    def remove_if_matches(
        self, components: tuple[str, ...],
        expected: ManagedAcquisitionSnapshot | None,
    ) -> ManagedRemoval:
        """Cancellation-fenced public conditional-discard boundary."""
        try:
            return self._remove_if_matches_public_outer(components, expected)
        except BaseException as primary:
            self._reconcile_removal_escape(components, expected, primary)
        raise AssertionError("unreachable managed removal boundary")

    def discard_pair(
        self,
        body_components: tuple[str, ...],
        body_expected: ManagedAcquisitionSnapshot | None,
        receipt_components: tuple[str, ...],
        receipt_expected: ManagedAcquisitionSnapshot | None,
    ) -> ManagedDiscardLedger:
        """Conditionally discard body+receipt under one cancellation ledger."""
        return _managed_discard_pair_export(
            self, body_components, body_expected,
            receipt_components, receipt_expected,
        )


    def _discard_pair_owned(
        self,
        body_components: tuple[str, ...],
        body_expected: ManagedAcquisitionSnapshot | None,
        receipt_components: tuple[str, ...],
        receipt_expected: ManagedAcquisitionSnapshot | None,
    ) -> ManagedDiscardLedger:
        self._require_origin_process()
        body_components = self._target(body_components)
        receipt_components = self._target(receipt_components)
        if self.contact_attempted:
            raise ContractError(
                "contacted acquisition cannot become a discard transaction",
            )
        # This public operation is itself the explicit proof that this lease is
        # a no-provider-contact discard.  Arm that fact before the stable
        # composite owner performs its first conditional unlink.
        self.discard_started = True
        self.clean_precontact = True
        owner = _ManagedDiscardComposite(
            self, body_components, body_expected,
            receipt_components, receipt_expected,
        )
        return _managed_discard_public(owner)

    @property
    def settlement_state(self) -> str:
        """Return ``released``, ``retained-uncertain`` or ``live``."""
        ephemeral_drained = (
            self.marker.marker.fd < 0
            and self.marker.directory.fd < 0
            and not self.marker.locked
            and self.parent.fd < 0
            and self.anchor.fd < 0
        )
        if self.marker.released and ephemeral_drained:
            return "released"
        if self.marker.abandoned and ephemeral_drained:
            return "retained-uncertain"
        return "live"

    def _release_certificate_locked(self) -> bool:
        certificate = self.terminal_certificate
        if type(certificate) is not ManagedAcquisitionCertificate:
            return False
        current_body, current_receipt = self._snapshot_pair_locked(
            certificate.body.components, certificate.receipt.components,
            absent_components=certificate.absent_components,
            release_certificate=certificate,
        )
        return (
            self._snapshot_matches(certificate.body, current_body)
            and self._snapshot_matches(certificate.receipt, current_receipt)
            and self.marker.released
        )

    def settle(self) -> None:
        if os.getpid() != self.marker.pid:
            # Contextlib must run ``__exit__`` in a forked child without
            # mutating the parent's namespace or shared OFD flock.  Closing
            # the child's fd-table references is safe; every inherited public
            # operation remains refused by the PID pin.
            faults: list[BaseException] = []
            try:
                self.marker.close_inherited_copy()
            except BaseException as exc:
                faults.append(exc)
            faults.extend(_close_owned_descriptors_twice((self.parent, self.anchor)))
            preferred = _preferred_settlement_fault(None, faults)
            if preferred is not None:
                raise preferred
            raise ManagedAcquisitionRefused(
                "managed acquisition context cannot settle in a forked child",
            )
        if self.settlement_state == "released":
            _unregister_live_managed_acquisition(self)
            self.settled = True
            return
        faults: list[BaseException] = []
        try:
            if not self.artifact._terminal():
                self.artifact.fence()
        except BaseException as exc:
            faults.append(exc)
        companion = (
            None if self.companion is None else self.companion.artifact
        )
        if companion is not None and not companion._terminal():
            try:
                companion.fence()
            except BaseException as exc:
                faults.append(exc)
        content_terminal = self.artifact._terminal()
        companion_terminal = (
            companion is None
            or companion._terminal()
        )
        content_graph_terminal = content_terminal and companion_terminal
        must_retain = (
            self.marker.abandoned
            or self.retain_reason is not None
            or (
                self.active
                and
                self.terminal_certificate is None
                and not self.clean_precontact
            )
        )
        if content_graph_terminal and not must_retain:
            if self.terminal_certificate is None:
                try:
                    with self.run._mutation(MutationScope.CONTROL):
                        self.marker.settle()
                except BaseException as exc:
                    faults.append(exc)
            else:
                try:
                    with self.run._mutation(MutationScope.BASE_EVIDENCE):
                        self._reauthenticate_locked()
                        try:
                            certificate_current = self._release_certificate_locked()
                        except BaseException:
                            self.retain_uncertain(
                                "managed acquisition terminal pair could not be revalidated",
                            )
                            raise
                        if not certificate_current:
                            self.retain_uncertain(
                                "managed acquisition terminal pair changed before release",
                            )
                            raise ManagedAcquisitionRefused(
                                "managed acquisition terminal pair changed before release",
                            )
                except BaseException as exc:
                    faults.append(exc)
        if (not content_graph_terminal or self.marker.abandoned
                or self.retain_reason is not None
                or (
                    self.active
                    and
                    self.terminal_certificate is None
                    and not self.clean_precontact
                )):
            if self.retain_reason is None:
                self.retain_reason = (
                    "managed acquisition did not settle to a certified terminal pair"
                )
            try:
                self.marker.abandon()
            except BaseException as exc:
                faults.append(exc)
        faults.extend(_close_owned_descriptors_twice((self.parent, self.anchor)))
        graph_terminal = (
            content_terminal and companion_terminal
            and self.parent.fd < 0 and self.anchor.fd < 0
            and self.marker.marker.fd < 0 and self.marker.directory.fd < 0
            and not self.marker.locked
        )
        if graph_terminal:
            _unregister_live_managed_acquisition(self)
        self.settled = content_graph_terminal and self.settlement_state == "released"
        if self.settlement_state == "retained-uncertain":
            faults.append(ManagedAcquisitionRefused(
                "managed acquisition lease was abandoned with durable crash evidence",
            ))
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred


class _ArtifactAppendTransaction:
    """Copy-on-write append owner for one canonical base artifact.

    The prior inode is read through a strict descriptor into a private stage.
    Only a complete, fsynced ``prior + data`` stage can replace the canonical
    name.  Stable descriptor and marker owners let the caller install both
    settlement fences before the first allocation or namespace effect.
    """

    __slots__ = (
        "run", "components", "data", "marker", "claim", "anchor", "source",
        "verification", "source_signature", "source_missing",
    )

    def __init__(self, run, components: tuple[str, ...], data: bytes) -> None:
        self.run = run
        self.components = components
        self.data = data
        self.marker = _ArtifactMarkerRelease(run)
        self.claim = _ArtifactClaim(run, components, self.marker)
        self.anchor = _OwnedDescriptor(run._run_directory_identity)
        self.source = _OwnedDescriptor()
        self.verification = _OwnedDescriptor()
        self.source_signature = None
        self.source_missing = False

    @property
    def descriptor_owners(self) -> tuple[_OwnedDescriptor, ...]:
        return (self.verification, self.source, self.anchor)

    def _open_prior(self) -> None:
        from . import privfs
        active = self.run._active_mutation_owner()
        if active is None:
            raise ContractError("artifact append has no mutation authority")
        self.anchor.duplicate(active.run_anchor.fd)
        try:
            _open_strict_file_into(self.source, self.anchor.fd, self.components)
        except privfs.PrivatePathMissing:
            self.source_missing = True
        else:
            self.source_signature = _identity_stat(self.source.fd)

    @staticmethod
    def _write_all(fd: int, data: bytes | memoryview) -> None:
        view = memoryview(data)
        while view:
            try:
                written = os.write(fd, view)
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError("artifact append made no progress")
            view = view[written:]

    def _copy_prior(self, writer: int) -> None:
        if self.source_missing:
            return
        while True:
            try:
                chunk = os.read(self.source.fd, 1024 * 1024)
            except InterruptedError:
                continue
            if not chunk:
                return
            self._write_all(writer, chunk)

    def _verify_prior(self) -> None:
        """Bind the copied bytes to the same complete canonical generation."""
        from . import privfs
        if self.source_missing:
            try:
                _open_strict_file_into(
                    self.verification, self.anchor.fd, self.components,
                )
            except privfs.PrivatePathMissing:
                return
            raise ContractError("artifact append destination appeared during copy")
        if _identity_stat(self.source.fd) != self.source_signature:
            raise ContractError("artifact append source changed during copy")
        _open_strict_file_into(
            self.verification, self.anchor.fd, self.components,
        )
        if _identity_stat(self.verification.fd) != self.source_signature:
            raise ContractError("artifact append source name changed during copy")

    def _close_sources(self) -> None:
        faults = _close_owned_descriptors_twice(self.descriptor_owners)
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred
        if any(owner.fd >= 0 for owner in self.descriptor_owners):
            raise ContractError("artifact append source descriptors did not settle")

    def execute(self) -> None:
        self.marker.allocate()
        self._open_prior()
        writer = self.claim.open_writer()
        self._copy_prior(writer)
        self._write_all(writer, self.data)
        os.fsync(writer)
        self._verify_prior()
        self._close_sources()
        self.claim.publish()

    def settle(self) -> None:
        faults = _close_owned_descriptors_twice(self.descriptor_owners)
        try:
            self.claim._settle()
        except BaseException as exc:
            faults.append(exc)
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            raise preferred
        if (any(owner.fd >= 0 for owner in self.descriptor_owners)
                or self.claim._state not in {"published", "fenced"}
                or not self.marker.released):
            raise ContractError("artifact append transaction did not settle")


class _CanonicalLogAppendOwner:
    """Rollback-capable, descriptor-relative append of one framed JSONL row."""

    __slots__ = (
        "run", "components", "data", "parent", "file", "prior_size",
        "source_missing", "possible", "synced", "committed", "terminal",
        "reconcile_failures",
    )

    def __init__(self, run, components: tuple[str, ...], data: bytes) -> None:
        if (not isinstance(data, bytes) or not data or not data.endswith(b"\n")
                or len(data) > _MAX_IDENTITY_BYTES):
            raise ContractError("canonical append requires one bounded newline-framed row")
        self.run = run
        self.components = components
        self.data = data
        self.parent = _OwnedDescriptor()
        self.file = _OwnedDescriptor()
        self.prior_size = 0
        self.source_missing = False
        self.possible = False
        self.synced = False
        self.committed = False
        self.terminal = False
        self.reconcile_failures = 0

    @property
    def descriptor_owners(self) -> tuple[_OwnedDescriptor, ...]:
        return self.file, self.parent

    def _validate_file(self) -> None:
        from . import privfs
        observed = os.fstat(self.file.fd)
        named = os.stat(
            self.components[-1], dir_fd=self.parent.fd, follow_symlinks=False,
        )
        if (not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE
                or (observed.st_dev, observed.st_ino) != self.file.identity
                or (named.st_dev, named.st_ino) != self.file.identity):
            raise ContractError("canonical append destination identity is unsafe")

    def _reconcile(self) -> None:
        if not self.possible or self.committed:
            return
        active = self.run._active_mutation_owner()
        if active is None:
            raise ContractError("canonical append reconciliation has no mutation authority")
        active.reauthenticate()
        if self.file.fd < 0 and self.source_missing:
            try:
                self.file.open(
                    self.components[-1],
                    os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=self.parent.fd,
                )
            except FileNotFoundError:
                self.possible = False
                return
        self._validate_file()
        observed_size = os.fstat(self.file.fd).st_size
        if observed_size < self.prior_size or observed_size > self.prior_size + len(self.data):
            raise ContractError("canonical append destination changed concurrently")
        suffix = os.pread(self.file.fd, observed_size - self.prior_size, self.prior_size)
        if suffix != self.data[:len(suffix)]:
            raise ContractError("canonical append suffix changed concurrently")
        if self.synced and observed_size == self.prior_size + len(self.data):
            if suffix != self.data:
                raise ContractError("canonical append verification failed")
            self.committed = True
            return
        os.ftruncate(self.file.fd, self.prior_size)
        os.fsync(self.file.fd)
        if self.source_missing:
            named = os.stat(
                self.components[-1], dir_fd=self.parent.fd, follow_symlinks=False,
            )
            if (named.st_dev, named.st_ino) != self.file.identity:
                raise ContractError("new canonical append destination was substituted")
            os.unlink(self.components[-1], dir_fd=self.parent.fd)
        os.fsync(self.parent.fd)
        self.possible = False

    def execute(self) -> None:
        from . import privfs
        active = self.run._active_mutation_owner()
        if active is None:
            raise ContractError("canonical append has no mutation authority")
        self.run._ensure_artifact_parent(self.components)
        _open_strict_directory_into(
            self.parent, active.run_anchor.fd, self.components[:-1],
        )
        flags = (os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0))
        try:
            self.file.open(self.components[-1], flags, dir_fd=self.parent.fd)
        except FileNotFoundError:
            self.source_missing = True
            self.possible = True
            self.file.open(
                self.components[-1], flags | os.O_CREAT | os.O_EXCL,
                privfs.FILE_MODE, dir_fd=self.parent.fd,
            )
        self._validate_file()
        self.prior_size = os.fstat(self.file.fd).st_size
        if (self.prior_size
                and os.pread(self.file.fd, 1, self.prior_size - 1) != b"\n"):
            raise ContractError("canonical append destination has a torn suffix")
        self.possible = True
        view = memoryview(self.data)
        while view:
            written = os.write(self.file.fd, view)
            if written <= 0:
                raise OSError("canonical append made no progress")
            view = view[written:]
        os.fsync(self.file.fd)
        self.synced = True
        self._reconcile()
        if not self.committed:
            raise ContractError("canonical append did not commit")

    def settle(self) -> None:
        primary = None
        try:
            self._reconcile()
        except BaseException as exc:
            primary = exc
            self.reconcile_failures += 1
            # Preserve the exact descriptors for the already-active outer
            # settlement fence.  One supported interruption can then retry
            # rollback instead of closing the only authenticated generation.
            if (self.possible and not self.committed
                    and self.reconcile_failures < 2):
                raise
        faults = _close_owned_descriptors_twice(self.descriptor_owners)
        preferred = _preferred_settlement_fault(primary, faults)
        if preferred is not None:
            raise preferred
        if any(owner.fd >= 0 for owner in self.descriptor_owners):
            raise ContractError("canonical append descriptors did not settle")
        if self.possible and not self.committed:
            raise ContractError("canonical append outcome is indeterminate")
        self.terminal = True


_RUN_CONSTRUCTION_AUTHORITY = object()
_TOOL_RUNS_UNLOADED = object()


class Run:
    """One reconnaissance run inside a project: owns its tree, manifest, and entity store.

    Lives at <project_dir>/recon/<run_id>/, so a run's output co-locates with the target.yaml profile
    the project dir was derived from.
    """

    def __init__(self, project_dir: Path, target: str, run_id: str | None = None, *, load_started: bool = False,
                 _identity: dict | None = None,
                 _run_directory_identity: tuple[int, int] | None = None,
                 _authority=None):
        if _authority is not _RUN_CONSTRUCTION_AUTHORITY:
            raise ContractError("construct runs through Run.create(), Run.open() or Run.latest()")
        self.project_dir = Path(project_dir)
        observed_project = os.stat(self.project_dir, follow_symlinks=False)
        if (not stat.S_ISDIR(observed_project.st_mode)
                or observed_project.st_uid != os.geteuid()):
            raise ContractError("project directory identity is unsafe")
        self._project_directory_identity = (
            observed_project.st_dev, observed_project.st_ino,
        )
        self.target = validate_target(target)
        self.run_id = validate_run_id(run_id if run_id is not None else self._mint_run_id())
        self.dir = self.project_dir / "recon" / self.run_id
        observed_run_dir = os.stat(self.dir, follow_symlinks=False)
        if (not stat.S_ISDIR(observed_run_dir.st_mode)
                or observed_run_dir.st_uid != os.geteuid()):
            raise ContractError(f"run {self.run_id!r} directory identity is unsafe")
        self._run_directory_identity = (
            observed_run_dir.st_dev, observed_run_dir.st_ino,
        )
        if (_run_directory_identity is not None
                and self._run_directory_identity != _run_directory_identity):
            raise ContractError(f"run {self.run_id!r} directory identity changed during open")
        self.raw = self.dir / "raw"
        self.normalized = self.dir / "normalized"
        self.exports = self.dir / "exports"
        self.reports = self.dir / "reports"
        if not load_started:
            from . import privfs
            for d in (self.raw, self.normalized, self.exports, self.reports):
                privfs.private_dir(d)                        # recon/ and the run tree are 0700
        self.manifest_path = self.dir / "manifest.json"
        self.meta_path = self.dir / "run.json"            # immutable creation record (started/run_id/target)
        self.state_path = self.dir / "state.json"         # finalisation state machine + per-stage generations
        self._verdict_sealed = False                      # a fault committed after the verdict is a contract break
        self._sealed_summary: dict | None = None          # the summary the manifest carries, computed once
        self._faults: list = []                           # typed Fault records folded into the verdict
        self._gaps: list = []                             # typed Gap records folded into the verdict
        self._tool_runs: list[ToolRunRecord] = []
        self._tool_runs_path = self.dir / "tool-runs.jsonl"
        self._tool_runs_signature: tuple | None | object = _TOOL_RUNS_UNLOADED
        self._counts_cache: dict[str, int] = {}
        self._records: dict[str, dict] = {}       # entity -> {canonical_key: merged record} (instance-local)
        self._folded: dict[str, FoldedLog] = {}   # entity -> the same fold, with its trust status
        self._entity_signatures: dict[str, tuple | None] = {}
        # identities refused past the corpus envelope. Durable records, RAM bounded regardless of N:
        # live refusals append to `_refused_path`; reopen-fold refusals are rewritten per entity under
        # `_fold_refused_dir` (idempotent across reopens); the exact distinct count is folded from both by an
        # external (sqlite) dedup, never a resident set.
        self._envelope_path = self.dir / "envelope-remainder.json"       # summary marker (existence + finalised count)
        self._refused_path = self.dir / "envelope-refused.jsonl"         # append-only ledger of live refusals
        self._fold_refused_dir = self.dir / "envelope-fold-refused"      # per-entity, rewritten reopen-fold refusals
        self._degraded_path = self.dir / "envelope-degraded.json"        # durable durability-failure marker
        self._refused_cache: dict[str, _BoundedKeySet] = {}              # entity -> bounded recent-refusal cache
        self._envelope_marked = self._envelope_path.exists()            # marker already written this/a prior run
        self._envelope_durability: dict[str, str] = {}                  # cause -> surfaced durability failure
        self._marker_unwritable = False                                # the durability marker itself could not persist
        self._corpus_bytes: dict[str, int] = {}                # entity -> summed serialized bytes of the corpus
        # opening an existing run reads `started` from run.json (written at create, and surviving a crash
        # that left no manifest) rather than fabricating a fresh start time
        if load_started:
            if _identity is None:
                raise ContractError("an opened run requires a validated repository identity")
            self.started = _identity["started"]
        else:
            self.started = _utc()
            if not self.meta_path.exists():
                _atomic_write(self.meta_path, json.dumps(
                    {"run_id": self.run_id, "target": target, "started": self.started}))
        self.notes: list[str] = []
        # a durability failure recorded in a prior session (ledger unwritable / damaged) must keep this reopen
        # gapped — load it so the run never re-finalises as clean/complete
        self._load_durability_marker()

    @property
    def _authority_key(self) -> tuple[str, str]:
        return _run_lock_key(self.project_dir, self.run_id)

    @property
    def _lock_path(self) -> Path:
        return self.project_dir / "recon" / "state" / "locks" / f"{self.run_id}.lock"

    @contextmanager
    def _mutation(self, scope: MutationScope):
        """Serialize one mutation through a pinned Run and durable lock owner."""
        if type(scope) is not MutationScope:
            raise TypeError("invalid repository mutation scope")
        key = self._authority_key
        _projects, held = _thread_mutation_ledgers()
        different = next((held_key for held_key in held if held_key != key), None)
        if different is not None:
            raise ContractError("cross-Run mutation nesting is unsupported")
        lock = _shared_run_lock(key)
        with _project_mutation(
            self.project_dir, self._project_directory_identity,
        ) as project_owner:
            with lock:
                entry = held.get(key)
                if entry is not None:
                    if (type(entry) is not _RunMutationLedgerEntry
                            or entry.owner.run._run_directory_identity != self._run_directory_identity):
                        raise ContractError("repository mutation ledger is damaged")
                    entry.owner.validate_live()
                    nested = _NestedMutationOwner(entry)
                    nested_settlement = _SettlementOwner(nested.settle)
                    with _SettlementFence(nested_settlement):
                        with _SettlementFence(nested_settlement):
                            nested.acquire()
                            self._require_scope(scope, entry.owner)
                            yield
                    return
                owner = _RunMutationOwner(
                    self, project_anchor_fd=project_owner.anchor.fd,
                )
                def settle_epoch() -> None:
                    held.pop(key, None)
                    owner.settle()
                settlement = _SettlementOwner(settle_epoch)
                with _SettlementFence(settlement):
                    with _SettlementFence(settlement):
                        owner.acquire()
                        entry = _RunMutationLedgerEntry(owner)
                        held[key] = entry
                        self._require_scope(scope, owner)
                        yield
                        owner.reauthenticate()

    def _active_mutation_owner(self) -> _RunMutationOwner | None:
        _projects, held = _thread_mutation_ledgers()
        entry = held.get(self._authority_key)
        if type(entry) is _RunMutationLedgerEntry and entry.depth > 0:
            entry.owner.validate_live()
            return entry.owner
        return None

    def _replace_run_bytes_locked(self, components: tuple[str, ...], data: bytes) -> None:
        """Replace one Run object relative to the current pinned authority."""
        from . import privfs
        owner = self._active_mutation_owner()
        if owner is None:
            raise ContractError("repository replacement has no mutation authority")
        stage = privfs.stage_private_bytes(owner.run_anchor.fd, components, data)
        try:
            privfs.replace_private_stage(stage)
        except BaseException:
            try:
                privfs.abort_private_stage(stage)
            except BaseException:
                pass
            raise

    def _read_run_json_locked(self, name: str):
        owner = self._active_mutation_owner()
        if owner is None:
            return _read_json(self.dir / name)
        value = _read_identity_file(owner.run_anchor.fd, name)
        return None if value is _MALFORMED_IDENTITY else value

    def _run_name_exists_locked(self, name: str) -> bool:
        owner = self._active_mutation_owner()
        if owner is None:
            return os.path.lexists(self.dir / name)
        try:
            os.stat(name, dir_fd=owner.run_anchor.fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    def _run_file_stat_locked(self, components: tuple[str, ...]):
        """Stat one strict regular Run file through the active pinned anchor."""
        active = self._active_mutation_owner()
        if active is None:
            return os.stat(self.dir.joinpath(*components), follow_symlinks=False)
        from . import privfs
        slot = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners((slot,), "Run file stat descriptor"),
        )
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                _open_strict_file_into(slot, active.run_anchor.fd, components)
                return os.fstat(slot.fd)

    def _unlink_run_file_locked(self, components: tuple[str, ...]) -> None:
        """Capture then unlink one exact private Run file under pinned authority."""
        from . import privfs
        active = self._active_mutation_owner()
        if active is None:
            raise ContractError("Run file removal has no mutation authority")
        parent = _OwnedDescriptor()
        target = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners(
                (target, parent), "Run file removal descriptors",
            ),
        )
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                try:
                    _open_strict_directory_into(
                        parent, active.run_anchor.fd, components[:-1],
                    )
                    target.open(components[-1], _FILE_OPEN_FLAGS, dir_fd=parent.fd)
                except (FileNotFoundError, privfs.PrivatePathMissing):
                    return
                quarantine = f".quarry-unlink-{os.urandom(16).hex()}.stage"
                os.rename(
                    components[-1], quarantine,
                    src_dir_fd=parent.fd, dst_dir_fd=parent.fd,
                )
                captured = os.stat(quarantine, dir_fd=parent.fd, follow_symlinks=False)
                if (captured.st_dev, captured.st_ino) != target.identity:
                    raise ContractError("Run file removal captured a substituted name")
                os.unlink(quarantine, dir_fd=parent.fd)
                os.fsync(parent.fd)

    def _require_scope(self, scope: MutationScope, owner: _RunMutationOwner) -> None:
        owner.validate_live()
        identity, _started = _run_identity_from_fd(owner.run_anchor.fd, self.run_id)
        if identity["target"] != self.target:
            raise ContractError(f"run {self.run_id!r} identity changed")
        state = self._read_state_from_fd(owner.run_anchor.fd)["state"]
        if state == "unknown":
            raise ContractError(f"run {self.run_id} has unknown lifecycle state")
        if scope is MutationScope.BASE_EVIDENCE:
            if state not in {"created", "running"}:
                raise ContractError(
                    f"base evidence is sealed for run {self.run_id} in state {state!r}",
                )
            try:
                os.stat(
                    "manifest.json", dir_fd=owner.run_anchor.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                # Presence is the seal.  A malformed, linked or otherwise
                # unreadable manifest is damage, never permission to mutate
                # the base corpus again.
                raise ContractError(
                    f"base evidence is sealed for run {self.run_id} by its manifest",
                )
        if scope is MutationScope.FINALIZATION_METADATA and state not in {
            "finalizing", "finalization_failed", "finished",
        }:
            raise ContractError(
                f"finalization metadata is unavailable in state {state!r}",
            )

    @property
    def _artifact_claim_dir(self) -> Path:
        return self.project_dir / "recon" / "state" / "claims" / self.run_id

    def _create_artifact_claim_marker(self) -> tuple[str, tuple[int, int]]:
        """Durably register one unique live owner while the run lock is held."""
        marker = _ArtifactMarkerRelease(self)
        settlement = _SettlementOwner(
            lambda: marker.settle() if settlement.primary is not None else None,
        )
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                return marker.allocate()

    def _release_artifact_claim_marker(
        self, name: str, expected_identity: tuple[int, int],
    ) -> None:
        """Idempotently release one exact marker and settle every owned fd."""
        release = _ArtifactMarkerRelease(self, name, expected_identity)
        settlement = _SettlementOwner(release.settle)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                release.settle()
                if not release.released:
                    raise ContractError("artifact claim marker release did not settle")

    def _live_artifact_claim_count(self) -> int:
        if self._active_mutation_owner() is None:
            with self._mutation(MutationScope.CONTROL):
                return self._live_artifact_claim_count()
        registry = _ArtifactClaimRegistryRead(self)
        settlement = _SettlementOwner(registry.settle)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                return registry.read()

    def _ensure_artifact_parent(self, components: tuple[str, ...]) -> None:
        from . import privfs
        owner = self._active_mutation_owner()
        if owner is None:
            raise ContractError("artifact parent creation has no mutation authority")
        parent_fd = owner.run_anchor.fd
        owned = []
        try:
            for component in components[:-1]:
                try:
                    os.mkdir(component, privfs.DIR_MODE, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                child = _OwnedDescriptor()
                owned.append(child)
                child.open(component, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
                self._validate_base_directory_stat(
                    os.fstat(child.fd), tuple(components[:len(owned)]),
                )
                parent_fd = child.fd
        finally:
            _settle_descriptor_owners(
                tuple(reversed(owned)), "artifact parent descriptors",
            )

    def _append_base_artifact(self, components: tuple[str, ...], data: bytes) -> None:
        """Atomically append exact bytes through BASE_EVIDENCE authority."""
        components = _validated_artifact_components(components)
        if type(data) is not bytes:
            raise TypeError("artifact append data must be exact bytes")
        with self._mutation(MutationScope.BASE_EVIDENCE):
            self._ensure_artifact_parent(components)
            transaction = _ArtifactAppendTransaction(self, components, data)
            settlement = _SettlementOwner(transaction.settle)
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    transaction.execute()

    def _replace_artifact(
        self, scope: MutationScope, components: tuple[str, ...], data: bytes,
    ) -> Path:
        """Durably replace one scoped artifact through the strict stage primitive."""
        components = _validated_artifact_components(components)
        if type(data) is not bytes:
            raise TypeError("artifact replacement data must be exact bytes")
        from . import privfs
        with self._mutation(scope):
            self._ensure_artifact_parent(components)
            owner = self._active_mutation_owner()
            if owner is None:
                raise ContractError("artifact replacement has no mutation authority")
            stage = privfs.stage_private_bytes(owner.run_anchor.fd, components, data)
            try:
                privfs.replace_private_stage(stage)
            except BaseException:
                try:
                    privfs.abort_private_stage(stage)
                except BaseException:
                    pass
                raise
        return self.dir.joinpath(*components)

    @staticmethod
    def _validate_base_file_stat(observed, components: tuple[str, ...]) -> None:
        from . import privfs
        if (not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE):
            joined = "/".join(components)
            raise ContractError(f"canonical base file {joined!r} is unsafe")

    @staticmethod
    def _validate_base_directory_stat(observed, components: tuple[str, ...]) -> None:
        from . import privfs
        if (not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or stat.S_IMODE(observed.st_mode) != privfs.DIR_MODE):
            joined = "/".join(components) or "."
            raise ContractError(f"canonical base directory {joined!r} is unsafe")

    def _fsync_base_file_at(
        self, parent_fd: int, name: str, components: tuple[str, ...],
    ) -> None:
        owner = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners((owner,), "base file descriptor"),
        )
        try:
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    owner.open(name, _FILE_OPEN_FLAGS, dir_fd=parent_fd)
                    fd = owner.fd
                    before = os.fstat(fd)
                    self._validate_base_file_stat(before, components)
                    os.fsync(fd)
                    after = os.fstat(fd)
                    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    self._validate_base_file_stat(after, components)
                    self._validate_base_file_stat(named, components)
                    if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                            or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)):
                        raise ContractError(
                            f"canonical base file {'/'.join(components)!r} changed while sealing",
                        )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.EISDIR}:
                raise ContractError(
                    f"canonical base file {'/'.join(components)!r} is unsafe",
                ) from exc
            raise

    def _fsync_base_directory_at(
        self, parent_fd: int, name: str, components: tuple[str, ...],
    ) -> None:
        owner = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners((owner,), "base directory descriptor"),
        )
        try:
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    owner.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
                    fd = owner.fd
                    before = os.fstat(fd)
                    self._validate_base_directory_stat(before, components)
                    for child in sorted(os.listdir(fd)):
                        child_components = components + (child,)
                        try:
                            observed = os.stat(child, dir_fd=fd, follow_symlinks=False)
                        except FileNotFoundError:
                            raise ContractError(
                                f"canonical base entry {'/'.join(child_components)!r} changed while sealing",
                            ) from None
                        if stat.S_ISREG(observed.st_mode):
                            self._fsync_base_file_at(fd, child, child_components)
                        elif stat.S_ISDIR(observed.st_mode):
                            self._fsync_base_directory_at(fd, child, child_components)
                        else:
                            raise ContractError(
                                f"canonical base entry {'/'.join(child_components)!r} is unsafe",
                            )
                    os.fsync(fd)
                    after = os.fstat(fd)
                    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    self._validate_base_directory_stat(after, components)
                    self._validate_base_directory_stat(named, components)
                    if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                            or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)):
                        raise ContractError(
                            f"canonical base directory {'/'.join(components)!r} changed while sealing",
                        )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ContractError(
                    f"canonical base directory {'/'.join(components)!r} is unsafe",
                ) from exc
            raise

    def _flush_base_evidence(self) -> None:
        """Flush every canonical base inode and its directory chain before sealing.

        The run authority is held by the caller.  Traversal is descriptor-relative,
        refuses links and non-private objects, and deliberately excludes lifecycle,
        manifest, report, export and revision objects.
        """
        owner = self._active_mutation_owner()
        if owner is None:
            raise ContractError("base durability walk has no mutation authority")
        run_fd = owner.run_anchor.fd
        for name in ("run.json", *sorted(_BASE_ARTIFACT_ROOTS)):
            try:
                observed = os.stat(name, dir_fd=run_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if name == "run.json" or name in _BASE_ARTIFACT_FILE_ROOTS:
                if not stat.S_ISREG(observed.st_mode):
                    raise ContractError(f"canonical base file {name!r} is unsafe")
                self._fsync_base_file_at(run_fd, name, (name,))
            else:
                if not stat.S_ISDIR(observed.st_mode):
                    raise ContractError(f"canonical base directory {name!r} is unsafe")
                self._fsync_base_directory_at(run_fd, name, (name,))
        os.fsync(run_fd)

    @contextmanager
    def artifact_claim(self, *components):
        """Hold an opaque durable base-artifact authority until terminal settlement.

        The zero-component form is retained as a lifecycle-only claim for callers
        that already own a private stage through another strict subsystem.
        """
        validated = None if not components else _validated_artifact_components(tuple(components))
        marker = _ArtifactMarkerRelease(self)
        claim = _ArtifactClaim(self, validated, marker)
        settlement = _SettlementOwner(claim._settle)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                with self._mutation(MutationScope.BASE_EVIDENCE):
                    marker.allocate()
                yield claim
        claim._settlement_faults.extend(settlement.faults)
        if (not claim._terminal()
                or not claim._marker_release.released):
            raise ContractError("artifact claim did not reach terminal settlement")

    @contextmanager
    def managed_acquisition_claim(self, *components):
        """Hold one deterministic destination lease across provider contact.

        The deterministic durable marker ``flock`` spans the whole context.
        Run/project mutation authority is acquired only for
        short marker, snapshot, stage, publication, discard and release
        transitions.  Callers get an opaque transaction and never receive a
        namespace descriptor.
        """
        validated = _validated_artifact_components(tuple(components))
        marker = _ManagedAcquisitionMarker(self, validated)
        transaction = _ManagedAcquisitionTransaction(self, validated, marker)
        settlement = _SettlementOwner(transaction.settle)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                _register_live_managed_acquisition(transaction)
                marker.acquire()
                transaction.activate()
                yield transaction
        transaction.artifact._settlement_faults.extend(settlement.faults)
        if (transaction.artifact._state not in {"published", "fenced"}
                or transaction.settlement_state == "live"):
            raise ContractError(
                "managed acquisition claim did not reach terminal settlement",
            )

    @contextmanager
    def managed_acquisition_discard_claim(self, *components):
        """Hold a destination lease pre-armed for a no-contact pair discard.

        The discard lifecycle facts are installed before the first marker or
        namespace effect.  Therefore an exact cancellation after context entry
        but before the caller invokes ``discard_pair`` releases the marker as a
        proven precontact operation instead of manufacturing crash-stale state.
        """
        validated = _validated_artifact_components(tuple(components))
        marker = _ManagedAcquisitionMarker(self, validated)
        transaction = _ManagedAcquisitionTransaction(self, validated, marker)
        transaction.clean_precontact = True
        transaction.discard_started = True
        settlement = _SettlementOwner(transaction.settle)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                _register_live_managed_acquisition(transaction)
                marker.acquire()
                transaction.activate()
                yield transaction
        transaction.artifact._settlement_faults.extend(settlement.faults)
        if (transaction.artifact._state not in {"published", "fenced"}
                or transaction.settlement_state == "live"):
            raise ContractError(
                "managed acquisition discard claim did not reach terminal settlement",
            )

    def begin_finalization(
        self, *, profile_summary: dict | None = None,
        phases_run: list[str] | None = None, metrics: dict | None = None,
        policy: list | None = None, detail: str | None = None,
    ) -> _PreparedManifest | None:
        """Irreversibly seal base evidence after every artifact owner settled.

        Production passes the manifest inputs so its exact bytes are computed
        while this same authority is held, before the durability walk and state
        transition.  The zero-argument form remains the lifecycle primitive.
        """
        with self._mutation(MutationScope.CONTROL):
            state = self.state
            if state != "running":
                raise ContractError(
                    f"run {self.run_id} cannot begin finalization from {state!r}",
                )
            if self._run_name_exists_locked("manifest.json"):
                raise ContractError(
                    f"run {self.run_id} base evidence is already sealed by its manifest",
                )
            live = self._live_artifact_claim_count()
            if live:
                raise ContractError(
                    f"run {self.run_id} has {live} live artifact claim(s)",
                )
            try:
                prepared = None
                if phases_run is not None:
                    prepared = self._prepare_manifest_locked(
                        profile_summary or {}, phases_run, metrics, policy,
                        base_mutations=True,
                    )
                elif any(value is not None for value in (profile_summary, metrics, policy)):
                    raise TypeError("phases_run is required when preparing a final manifest")
                self._flush_base_evidence()
                self._write_state_locked("finalizing", detail=detail)
                return prepared
            except BaseException:
                # A failed durability walk did not cross the seal boundary. Do
                # not leave this live handle's verdict cache sealed either.
                if self.state == "running":
                    self.unseal_verdict()
                raise

    def reopen_finalization(self, *, detail: str | None = None) -> None:
        """Reopen only derived-publication metadata for a committed base.

        This transition never grants ``BASE_EVIDENCE`` authority: both eligible
        sources are already sealed states, and the destination remains sealed.
        """
        with self._mutation(MutationScope.FINALIZATION_METADATA):
            state = self.state
            if state not in {"finished", "finalization_failed"}:
                raise ContractError(
                    f"run {self.run_id} cannot reopen finalization from {state!r}",
                )
            if not self.manifest_committed():
                raise ContractError(
                    f"run {self.run_id} has no committed manifest to re-finalize",
                )
            self._write_state_locked("finalizing", detail=detail)

    # ── C10a lifecycle ──
    @staticmethod
    def _mint_run_id() -> str:
        """Collision-resistant run id: sortable UTC timestamp + 8-hex random suffix. Second precision alone
        collides when two runs start in the same second; `Run.create` claims the directory atomically as well.
        """
        return time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex()

    @classmethod
    def create(cls, project_dir, target, *, run_id: str | None = None) -> "Run":
        """Start a new run and claim its directory atomically.

        Production callers omit ``run_id`` and retry collision-resistant minted IDs.  A validated explicit
        ID is useful for imports and deterministic fixtures, but it is still a create operation: an existing
        directory raises instead of becoming an unchecked attachment. ``started`` is now.
        """
        from . import privfs
        target = validate_target(target)                        # before recon/ or a run claim can be created
        if run_id is not None:
            run_id = validate_run_id(run_id)                    # before recon/ can be created
        project_dir = Path(project_dir)
        # The caller-supplied project inode is the out-of-band parent guard.
        # Creating that project directory is deliberately outside repository
        # mutation authority; all repository effects begin only after it has
        # been pinned and flocked.
        privfs.private_dir(project_dir)
        project_observed = os.stat(project_dir, follow_symlinks=False)
        if (not stat.S_ISDIR(project_observed.st_mode)
                or project_observed.st_uid != os.geteuid()
                or stat.S_IMODE(project_observed.st_mode) != privfs.DIR_MODE):
            raise ContractError("project directory identity is unsafe")
        project_identity = project_observed.st_dev, project_observed.st_ino
        attempts = 1 if run_id is not None else 16
        with _project_mutation(project_dir, project_identity) as project_owner:
            try:
                os.mkdir("recon", privfs.DIR_MODE, dir_fd=project_owner.anchor.fd)
            except FileExistsError:
                pass
            recon = _OwnedDescriptor()
            recon_settlement = _SettlementOwner(
                lambda: _settle_descriptor_owners((recon,), "Run creation root descriptor"),
            )
            with _SettlementFence(recon_settlement):
                with _SettlementFence(recon_settlement):
                    recon.open("recon", _DIR_OPEN_FLAGS, dir_fd=project_owner.anchor.fd)
                    observed_recon = os.fstat(recon.fd)
                    if (observed_recon.st_uid == os.geteuid()
                            and stat.S_ISDIR(observed_recon.st_mode)
                            and stat.S_IMODE(observed_recon.st_mode) != privfs.DIR_MODE):
                        os.fchmod(recon.fd, privfs.DIR_MODE)
                        observed_recon = os.fstat(recon.fd)
                    if (not stat.S_ISDIR(observed_recon.st_mode)
                            or observed_recon.st_uid != os.geteuid()
                            or stat.S_IMODE(observed_recon.st_mode) != privfs.DIR_MODE):
                        raise ContractError("repository root identity is unsafe")
                    for _ in range(attempts):
                        rid = run_id if run_id is not None else cls._mint_run_id()
                        run_anchor = _OwnedDescriptor()
                        creation = _OwnedDescriptor()
                        cleanup = _RunCreationCleanup(recon, rid, run_anchor, creation)
                        outcome = [None]
                        creation_settlement = _SettlementOwner(cleanup.settle)
                        with _SettlementFence(creation_settlement):
                            with _SettlementFence(creation_settlement):
                                cleanup.possible = True
                                if not _claim_run_directory_into(
                                    cleanup, recon.fd, rid, privfs.DIR_MODE,
                                ):
                                    cleanup.possible = False
                                    if run_id is not None:
                                        raise FileExistsError(rid)
                                    continue
                                creation.open(
                                    ".creation-pending",
                                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                                    | getattr(os, "O_CLOEXEC", 0),
                                    privfs.FILE_MODE, dir_fd=run_anchor.fd,
                                )
                                os.fsync(creation.fd)
                                os.fsync(run_anchor.fd)
                                os.fsync(recon.fd)
                                _settle_descriptor_owners(
                                    (creation,), "Run creation marker descriptor",
                                )
                                identity = {
                                    "run_id": rid, "target": target, "started": _utc(),
                                }
                                _bootstrap_run_tree(run_anchor, identity)
                                run = cls(
                                    project_dir, target, run_id=rid,
                                    load_started=True, _identity=identity,
                                    _run_directory_identity=run_anchor.identity,
                                    _authority=_RUN_CONSTRUCTION_AUTHORITY,
                                )
                                run._initialize_mutation_authority(
                                    project_anchor_fd=project_owner.anchor.fd,
                                )
                                with run._mutation(MutationScope.CONTROL):
                                    run._write_state_locked("created")
                                    run._unlink_run_file_locked((".creation-pending",))
                                cleanup.exposed = True
                                _settle_descriptor_owners(
                                    (run_anchor,), "Run creation anchor descriptor",
                                )
                                outcome[0] = run
                        if outcome[0] is not None:
                            # Reconcile exposure from the durable marker/witness,
                            # not a fragile in-frame boolean assignment.
                            anchor = _OwnedDescriptor(run._run_directory_identity)
                            check = _SettlementOwner(
                                lambda: _settle_descriptor_owners(
                                    (anchor,), "Run creation exposure descriptor",
                                ),
                            )
                            with _SettlementFence(check):
                                with _SettlementFence(check):
                                    _open_run_fd_into(
                                        anchor, project_dir, run.run_id,
                                        expected_identity=run._run_directory_identity,
                                    )
                                    if _run_creation_pending(anchor.fd):
                                        raise ContractError("Run creation remains pending")
                            return outcome[0]
        raise RuntimeError("could not mint a unique run id after 16 attempts")

    def _initialize_mutation_authority(self, *, project_anchor_fd: int | None = None) -> None:
        """Create one exact lock identity while Run creation is still exclusive."""
        owner = _RunMutationOwner(
            self, initializing=True, project_anchor_fd=project_anchor_fd,
        )
        settlement = _SettlementOwner(owner.settle)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                owner.acquire()

    @classmethod
    def open(cls, project_dir, target, run_id) -> "Run":
        """Attach to an existing reconciled run without modifying any repository object.

        A crashed run may have only ``run.json`` and a legacy run may have only ``manifest.json``.  A
        malformed regular secondary document is ignored for recovery, but every well-formed identity must
        agree with the directory and each other.  Symlinked/non-regular identity objects always fail closed.
        """
        target = validate_target(target)
        run_id = validate_run_id(run_id)              # refuse before joining/opening caller-controlled input
        anchor = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners((anchor,), "Run.open identity anchor"),
        )
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                _open_run_fd_into(anchor, Path(project_dir), run_id)
                if _run_creation_pending(anchor.fd):
                    raise _InvalidRunIdentity(f"run {run_id!r} creation is incomplete")
                identity, _started = _run_identity_from_fd(anchor.fd, run_id)
                run_directory_identity = anchor.identity
        if target != identity["target"]:
            raise ContractError(f"run {run_id!r} belongs to target {identity['target']!r}, not {target!r}")
        return cls(project_dir, identity["target"], run_id=run_id, load_started=True, _identity=identity,
                   _run_directory_identity=run_directory_identity,
                   _authority=_RUN_CONSTRUCTION_AUTHORITY)

    # ── raw evidence ──
    def raw_path(self, phase: str, tool: str, name: str) -> Path:
        with self._mutation(MutationScope.BASE_EVIDENCE):
            phase = validate_artifact_component(phase, "raw phase")
            tool = validate_artifact_component(tool, "raw tool")
            name = validate_artifact_component(name, "raw filename")
            components = ("raw", phase, tool, name)
            self._ensure_artifact_parent(components)
            return self.dir.joinpath(*components)

    def fresh_artifact_dir(self, *components: str) -> Path:
        """Atomically allocate one private ``attempt-N`` base-evidence directory.

        Allocation and finalization share the Run authority, so either the
        directory is committed while base evidence is still open or the seal
        wins without a filesystem side effect.  Existing attempt names are
        authenticated rather than blindly skipped: a planted link or wrong
        object type makes the allocator fail closed.
        """
        components = _validated_artifact_components(tuple(components))
        with self._mutation(MutationScope.BASE_EVIDENCE):
            self._ensure_artifact_parent(components + ("attempt-0",))
            allocation = _ArtifactDirectoryAllocation(
                self, components, "attempt-0",
            )
            settlement = _SettlementOwner(allocation.settle)
            result = None
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    result = allocation.allocate_fresh()
            if result is None or allocation is None or not allocation.durable:
                raise ContractError("artifact attempt allocation did not settle")
            return result

    def create_artifact_dir(self, *components: str) -> Path:
        """Create one exact, previously absent private base-evidence directory.

        Unlike :meth:`fresh_artifact_dir`, the caller supplies the complete
        identity (for example a work-unit/attempt tuple).  The repository lock
        and descriptor-relative validation make creation indivisible with the
        base-seal predicate; an existing name is never adopted or reused.
        """
        components = _validated_artifact_components(tuple(components))
        if len(components) < 2:
            raise ContractError("an artifact directory requires a parent identity")
        with self._mutation(MutationScope.BASE_EVIDENCE):
            self._ensure_artifact_parent(components)
            allocation = _ArtifactDirectoryAllocation(
                self, components[:-1], components[-1],
            )
            settlement = _SettlementOwner(allocation.settle)
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    allocation.create_exact()
            if not allocation.durable:
                raise ContractError("artifact directory creation did not settle")
            return self.dir.joinpath(*components)

    # ── tool run accounting ──
    def record(self, phase: str, result, *, depends_on: str | None = None) -> None:
        # the single choke point that redacts secrets out of cmd/note/stderr before they reach the manifest
        with self._mutation(MutationScope.BASE_EVIDENCE):
            from . import secrets
            self._refresh_tool_runs()
            record = ToolRunRecord(
                phase=phase, tool=result.tool, status=str(result.status.value),
                exit_code=result.exit_code, duration=round(result.duration, 2),
                stdout_lines=result.stdout_lines, note=secrets.redact(result.note),
                cmd=secrets.redact(" ".join(result.cmd)), stderr_tail=secrets.redact(result.stderr_tail),
                cpu_s=getattr(result, "cpu_s", 0.0), peak_rss_mb=getattr(result, "peak_rss_mb", 0.0),
                depends_on=depends_on or "",
            )
            self._append_base_artifact(
                ("tool-runs.jsonl",),
                (json.dumps(asdict(record), ensure_ascii=False) + "\n").encode("utf-8"),
            )
            self._tool_runs.append(record)
            self._tool_runs_signature = self._tool_runs_disk_signature()

    def _tool_runs_disk_signature(self) -> tuple | None:
        from . import privfs
        try:
            observed = self._run_file_stat_locked(("tool-runs.jsonl",))
        except (FileNotFoundError, privfs.PrivatePathMissing):
            return None
        return (
            observed.st_dev, observed.st_ino, observed.st_size,
            observed.st_mtime_ns, observed.st_ctime_ns,
        )

    @staticmethod
    def _tool_run_from_dict(value) -> ToolRunRecord:
        if not isinstance(value, dict):
            raise ContractError("tool-run ledger contains a non-object row")
        required = (
            "phase", "tool", "status", "exit_code", "duration",
            "stdout_lines", "note", "cmd",
        )
        if any(name not in value for name in required):
            raise ContractError("tool-run ledger contains an incomplete row")
        fields = {
            "stderr_tail": "", "cpu_s": 0.0,
            "peak_rss_mb": 0.0, "depends_on": "",
        }
        fields.update({name: value[name] for name in required})
        fields.update({name: value[name] for name in fields if name in value})
        try:
            return ToolRunRecord(**fields)
        except (TypeError, ValueError) as exc:
            raise ContractError("tool-run ledger contains an invalid row") from exc

    def _refresh_tool_runs(self) -> None:
        signature = self._tool_runs_disk_signature()
        if self._tool_runs_signature is not _TOOL_RUNS_UNLOADED and signature == self._tool_runs_signature:
            return
        if signature is None:
            # Preserve same-process compatibility for an object whose tests or a
            # legacy adapter populated the historical in-memory list directly.
            if self._tool_runs_signature is _TOOL_RUNS_UNLOADED and self._tool_runs:
                self._tool_runs_signature = None
                return
            legacy = self._read_run_json_locked("manifest.json")
            rows = legacy.get("tool_runs") if isinstance(legacy, dict) else None
            self._tool_runs = (
                [self._tool_run_from_dict(row) for row in rows]
                if isinstance(rows, list) else []
            )
            self._tool_runs_signature = None
            return
        records = []
        from . import privfs
        active = self._active_mutation_owner()
        descriptor = None
        try:
            if active is None:
                iterator = self._tool_runs_path.read_bytes().splitlines(keepends=True)
            else:
                descriptor = _OwnedDescriptor()
                _open_strict_file_into(
                    descriptor, active.run_anchor.fd, ("tool-runs.jsonl",),
                )
                iterator = _iter_descriptor_lines(descriptor.fd)
            for index, encoded in enumerate(iterator, 1):
                line = encoded.decode("utf-8")
                if not line.endswith("\n"):
                    raise ContractError(f"tool-run ledger row {index} is torn")
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ContractError(f"tool-run ledger row {index} is invalid JSON") from exc
                records.append(self._tool_run_from_dict(value))
        except UnicodeError as exc:
            raise ContractError("tool-run ledger is not valid UTF-8") from exc
        finally:
            if descriptor is not None:
                _settle_descriptor_owners(
                    (descriptor,), "tool-run ledger descriptor",
                )
        self._tool_runs = records
        self._tool_runs_signature = signature

    def tool_runs(self, phase: str | None = None) -> list[ToolRunRecord]:
        self._refresh_tool_runs()
        if phase is None:
            return list(self._tool_runs)
        return [r for r in self._tool_runs if r.phase == phase]

    # ── committed faults / gaps: the verdict is computed only after these are in ──
    def _refuse_if_sealed(self, what: str) -> None:
        """A verdict this instance already computed, or one a previous process committed and closed, is
        sealed: a record arriving now would restate it and then be silently dropped, since nothing re-reads
        `_faults`/`_gaps` after the seal.

        The persisted half is what makes it hold across processes — `_verdict_sealed` is instance memory,
        and every caller reaching a finished run does so through a fresh `Run.open`. Re-finalising is still
        possible because `report` reopens the run (`finished -> finalizing`) before it republishes.
        """
        from .state import ContractError
        if self._verdict_sealed:
            raise ContractError(f"{what} committed after the verdict was sealed")
        if self.state == "finished":
            raise ContractError(f"{what} committed against finished run {self.run_id} — reopen it "
                                f"(`finalizing`) to re-finalise")

    def commit_fault(self, fault) -> None:
        """Record a typed Fault against this run. Refused once the verdict is sealed."""
        from .state import ContractError, Fault
        if not isinstance(fault, Fault):
            raise ContractError(f"commit_fault takes a Fault, got {fault!r}")
        scope = (
            MutationScope.FINALIZATION_METADATA
            if fault.kind == "publication"
            else MutationScope.BASE_EVIDENCE
        )
        with self._mutation(scope):
            self._refuse_if_sealed(f"fault {fault.kind!r}")
            if fault not in self._faults:        # the same fault committed twice is the same fact
                self._faults.append(fault)

    def commit_gap(self, gap) -> None:
        """Record a typed Gap against this run. Refused once the verdict is sealed."""
        from .state import ContractError, Gap
        if not isinstance(gap, Gap):
            raise ContractError(f"commit_gap takes a Gap, got {gap!r}")
        with self._mutation(MutationScope.BASE_EVIDENCE):
            self._refuse_if_sealed(f"gap {gap.kind!r}")
            if gap not in self._gaps:
                self._gaps.append(gap)

    def unseal_verdict(self) -> None:
        """Clear only this handle's cached summary; never grant repository mutation authority."""
        self._verdict_sealed = False
        self._sealed_summary = None

    # ── finalisation state machine ──
    def manifest_committed(self) -> bool:
        """Whether this run's base manifest is committed. `manifest_committed(path)` is the one rule."""
        owner = self._active_mutation_owner()
        if owner is not None:
            manifest = _read_identity_file(owner.run_anchor.fd, "manifest.json")
            if not isinstance(manifest, dict):
                return False
            counts = manifest.get("entity_counts")
            return (
                isinstance(counts, dict)
                and all(isinstance(k, str) and type(v) is int and v >= 0
                        for k, v in counts.items())
                and summary_well_formed(manifest.get("summary"))
            )
        return manifest_committed(self.manifest_path)

    def _read_state(self) -> dict:
        """The persisted finalisation record.

        An ABSENT file is a run written before this contract: a committed manifest means its finalisation
        finished, anything else is still `created`. A file that is PRESENT but unreadable is a different
        fact and fails closed as `unknown` — inferring `finished` from a manifest there would let a
        corrupt lifecycle record read as a completed one.
        """
        owner = self._active_mutation_owner()
        if owner is not None:
            return self._read_state_from_fd(owner.run_anchor.fd)
        from .state import RUN_STATES, STATE_UNKNOWN
        if not self.state_path.exists():
            if self.manifest_path.exists() and not self.manifest_committed():
                # a damaged manifest is not a commitment, and with no lifecycle record to read there is
                # nothing left that could say how this run ended
                return {"schema_version": 1, "run_id": self.run_id, "stages": {},
                        "state": STATE_UNKNOWN, "unreadable": True}
            return {"schema_version": 1, "run_id": self.run_id, "stages": {},
                    "state": "finished" if self.manifest_committed() else "created"}
        d = _read_json(self.state_path)
        if self._well_formed_state(d):
            return d
        return {"schema_version": 1, "run_id": self.run_id, "stages": {},
                "state": STATE_UNKNOWN, "unreadable": True}

    def _read_state_from_fd(self, run_fd: int) -> dict:
        """Read lifecycle from the exact Run descriptor held by mutation authority."""
        from .state import STATE_UNKNOWN
        state = _read_identity_file(run_fd, "state.json")
        if state is None:
            manifest = _read_identity_file(run_fd, "manifest.json")
            if manifest is not None and manifest is not _MALFORMED_IDENTITY:
                counts = manifest.get("entity_counts") if isinstance(manifest, dict) else None
                committed = (
                    isinstance(counts, dict)
                    and all(isinstance(k, str) and type(v) is int and v >= 0
                            for k, v in counts.items())
                    and summary_well_formed(manifest.get("summary"))
                )
                if not committed:
                    return {"schema_version": 1, "run_id": self.run_id, "stages": {},
                            "state": STATE_UNKNOWN, "unreadable": True}
                return {"schema_version": 1, "run_id": self.run_id, "stages": {},
                        "state": "finished"}
            return {"schema_version": 1, "run_id": self.run_id, "stages": {},
                    "state": "created"}
        if state is not _MALFORMED_IDENTITY and self._well_formed_state(state):
            return state
        return {"schema_version": 1, "run_id": self.run_id, "stages": {},
                "state": STATE_UNKNOWN, "unreadable": True}

    def _well_formed_state(self, d) -> bool:
        """Whether a persisted lifecycle record is this run's, and shaped the way this reader understands.

        A record carrying a known state word is not enough: one copied from another run, written by a
        version this reader does not know, or holding malformed stages would otherwise read as `finished`
        here and then crash the finalisation that trusted it.
        """
        from .state import RUN_STATES, SUPPORTED_SCHEMA
        if not isinstance(d, dict) or d.get("state") not in RUN_STATES:
            return False
        sv = d.get("schema_version")
        if type(sv) is not int or sv not in SUPPORTED_SCHEMA:      # `type is int` rejects a bool
            return False
        if d.get("run_id") != self.run_id:      # a record from another run answers for nothing here
            return False
        stages = d.get("stages")
        if not isinstance(stages, dict):
            return False
        return all(isinstance(name, str) and isinstance(rec, dict) for name, rec in stages.items())

    @property
    def state(self) -> str:
        return self._read_state()["state"]

    @property
    def finalization_stages(self) -> dict:
        return dict(self._read_state().get("stages") or {})

    def _write_state_locked(self, dst: str, *, detail: str | None = None) -> None:
        """Advance the finalisation state machine and persist it. Only the declared transitions are legal,
        and an unreadable record is never overwritten — it is evidence, and guessing past it is how a
        corrupt run re-finalises as a clean one."""
        from .state import ContractError, run_transition_ok
        owner = self._active_mutation_owner()
        if owner is None:
            raise ContractError("state transition has no mutation authority")
        rec = self._read_state_from_fd(owner.run_anchor.fd)
        src = rec["state"]
        if rec.get("unreadable"):
            raise ContractError(f"run {self.run_id} has an unreadable {self.state_path.name} — refusing to "
                                f"advance it to {dst!r}; inspect or remove the file deliberately")
        if src != dst and not run_transition_ok(src, dst):
            raise ContractError(f"illegal run-state transition {src!r} -> {dst!r}")
        rec.update({"schema_version": 1, "run_id": self.run_id, "state": dst,
                    "generation": self.generation(), "updated": _utc(), "detail": detail})
        self._replace_run_bytes_locked(
            ("state.json",), json.dumps(rec, indent=2).encode("utf-8"),
        )

    def write_state(self, dst: str, *, detail: str | None = None) -> None:
        """Compatibility lifecycle API routed through the authoritative seal/reopen operations."""
        if dst == "finalizing":
            source = self.state
            if source == "running":
                self.begin_finalization(detail=detail)
                return
            if source in {"finished", "finalization_failed"}:
                self.reopen_finalization(detail=detail)
                return
        with self._mutation(MutationScope.CONTROL):
            self._write_state_locked(dst, detail=detail)

    def generation(self) -> str:
        """Content address of the base evidence a derived view is generated from; a view stamped with a
        different generation is stale and regenerates.

        Every record's own fingerprint is folded in, not just how many there are: enriching a record in
        place leaves the count untouched, and a view built from the thinner record is stale all the same.
        """
        h = hashlib.sha256(self.run_id.encode("utf-8"))
        for entity in sorted(ENTITY_KEYS):
            if self._entity_signature(entity) is None:
                continue
            records = self._records_for(entity)
            h.update(f"\n{entity}:{len(records)}".encode("utf-8"))
            for key in sorted(records):
                h.update(f"\n{key}={fingerprint(entity, records[key])}".encode("utf-8"))
        return h.hexdigest()[:16]

    def stage_current(self, stage: str) -> bool:
        """Whether a derived view is already published for the current generation."""
        rec = self.finalization_stages.get(stage) or {}
        return rec.get("status") == "done" and rec.get("generation") == self.generation()

    def finalization_failed(self) -> bool:
        """Whether a derived view is recorded failed for the current generation; a stale failure from an
        older base evidence set does not gate."""
        g = self.generation()
        return any(r.get("status") == "failed" and r.get("generation") == g
                   for r in self.finalization_stages.values())

    @_scoped_mutation(MutationScope.FINALIZATION_METADATA)
    def mark_stage(self, stage: str, status: str, *, detail: str | None = None) -> None:
        from .state import ContractError
        owner = self._active_mutation_owner()
        if owner is None:
            raise ContractError("stage transition has no mutation authority")
        state = self._read_state_from_fd(owner.run_anchor.fd)
        if state["state"] != "finalizing":
            raise ContractError(
                f"run {self.run_id} must be in finalizing to record derived stage metadata",
            )
        rec = state
        if rec.get("unreadable"):
            raise ContractError(f"run {self.run_id} has an unreadable {self.state_path.name} — refusing to "
                                f"record stage {stage!r} over it")
        rec.setdefault("stages", {})[stage] = {"generation": self.generation(), "status": status,
                                               "detail": detail, "updated": _utc()}
        rec["schema_version"], rec["run_id"] = 1, self.run_id
        self._replace_run_bytes_locked(
            ("state.json",), json.dumps(rec, indent=2).encode("utf-8"),
        )

    @_scoped_mutation(MutationScope.FINALIZATION_METADATA)
    def reconcile_finalization(self) -> dict | None:
        """Bring the committed manifest's summary back in step with the finalisation stages, and return it.

        A publication fault is a claim about a derived view at one generation. A resume that republishes
        that view has answered the claim, so it must not survive in the manifest — otherwise `report`
        exits 0 while a later `status` reads the stale fault and exits 5. Only `summary.faults` and the
        verdict it implies are touched; the base evidence the manifest records is never rewritten, and a
        run with no committed manifest has nothing to reconcile.
        """
        from .state import Fault
        manifest = self._read_run_json_locked("manifest.json")
        # a damaged summary is not reconciled: filling in what it lacks would author the verdict rather
        # than bring one back in step with the stages
        if not isinstance(manifest, dict) or not summary_well_formed(manifest.get("summary")):
            return None
        owner = self._active_mutation_owner()
        if owner is None or self._read_state_from_fd(owner.run_anchor.fd)["state"] != "finalizing":
            raise ContractError(
                f"run {self.run_id} must be explicitly reopened before derived reconciliation",
            )
        summary = dict(manifest["summary"])
        stages = self.finalization_stages
        gen = self.generation()
        kept = []
        for fault in summary.get("faults") or []:
            stage = (fault or {}).get("where")
            rec = stages.get(stage) or {}
            answered = (fault.get("kind") == "publication" and rec.get("status") == "done"
                        and rec.get("generation") == gen)
            if not answered:
                kept.append(fault)
        for stage, rec in sorted(stages.items()):      # a stage failing NOW is a fault the manifest owes
            if rec.get("status") != "failed" or rec.get("generation") != gen:
                continue
            entry = Fault("publication", where=stage, detail=rec.get("detail")).to_dict()
            if entry not in kept:
                kept.append(entry)
        summary["faults"] = kept
        summary["verdict"] = _verdict_for(summary)
        manifest["summary"] = summary
        self._replace_run_bytes_locked(
            ("manifest.json",), json.dumps(manifest, indent=2).encode("utf-8"),
        )
        self._sealed_summary, self._verdict_sealed = summary, True
        return summary

    # ── normalized entities (JSONL, append, dedup on natural key) ──
    def _entity_file(self, entity: str) -> Path:
        return self.normalized / f"{validate_entity(entity)}.jsonl"

    def _entity_signature(self, entity: str) -> tuple | None:
        """Return a mutation-sensitive identity for one canonical entity log."""
        from . import privfs
        try:
            observed = self._run_file_stat_locked(
                ("normalized", f"{validate_entity(entity)}.jsonl"),
            )
        except (FileNotFoundError, privfs.PrivatePathMissing):
            return None
        except OSError:
            # Folding below reports the authoritative typed/unusable state.  A
            # distinct sentinel still invalidates any previously trusted cache.
            return ("unavailable",)
        return (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
            observed.st_ctime_ns,
        )

    def _refresh_entity_cache(self, entity: str) -> None:
        """Discard an instance cache when another run handle changed the log."""
        signature = self._entity_signature(entity)
        if (entity in self._entity_signatures
                and self._entity_signatures[entity] != signature):
            self._records.pop(entity, None)
            self._folded.pop(entity, None)
            self._corpus_bytes.pop(entity, None)
            self._counts_cache.pop(entity, None)
        self._entity_signatures[entity] = signature

    @_scoped_mutation(MutationScope.BASE_EVIDENCE)
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
            line = json.dumps(record, ensure_ascii=False)
            reason = self._envelope_admits_new(entity, records, len(line.encode("utf-8")))
            if reason:
                self._refuse_over_envelope(entity, key, reason)   # bound the corpus; record the refusal durably
                return False
            self._append_line(entity, line)
            records[key] = record
            self._corpus_bytes[entity] = self._corpus_bytes_for(entity) + len(line.encode("utf-8"))
            return True
        if not _subsumed(records[key], record):             # novel: new evidence or a conflicting value
            merged = _merge_record(records[key], record)
            delta = self._blob_len(merged) - self._blob_len(records[key])
            if self._envelope_admits_growth(entity, merged, delta):
                self._append_obs(entity, record)            # keep the raw observation in the immutable log
                records[key] = merged                       # folds max(last_seen) durably
                self._corpus_bytes[entity] = self._corpus_bytes_for(entity) + max(0, delta)
            else:
                self._refuse_over_envelope(entity, key, "growth")   # unbounded growth of a key -> owed, not held
        return False                                        # not a new entity (counting semantics preserved)

    @_scoped_mutation(MutationScope.BASE_EVIDENCE)
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
            line = json.dumps(record, ensure_ascii=False)
            reason = self._envelope_admits_new(entity, records, len(line.encode("utf-8")))
            if reason:
                self._refuse_over_envelope(entity, key, reason)   # bound the corpus; record the refusal durably
                return False
            self._append_line(entity, line)
            records[key] = record
            self._corpus_bytes[entity] = self._corpus_bytes_for(entity) + len(line.encode("utf-8"))
            return True
        if _subsumed(records[key], record):
            return False
        merged = _merge_record(records[key], record)
        delta = self._blob_len(merged) - self._blob_len(records[key])
        if not self._envelope_admits_growth(entity, merged, delta):
            self._refuse_over_envelope(entity, key, "growth")     # unbounded growth of a key -> owed, not held
            return False
        self._append_obs(entity, record)
        records[key] = merged
        self._corpus_bytes[entity] = self._corpus_bytes_for(entity) + max(0, delta)
        return True

    def _append_obs(self, entity: str, record: dict) -> None:
        self._append_line(entity, json.dumps(record, ensure_ascii=False))

    def _append_line(self, entity: str, line: str) -> None:
        append = _CanonicalLogAppendOwner(
            self, ("normalized", f"{validate_entity(entity)}.jsonl"),
            (line + "\n").encode("utf-8"),
        )
        settlement = _SettlementOwner(append.settle)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                append.execute()
        self._entity_signatures[entity] = self._entity_signature(entity)

    # ── corpus envelope: bound materialized keys and corpus bytes, refuse—never drop—the overflow ──
    @staticmethod
    def _envelope_cap() -> int:
        from . import envelope
        return envelope.MAX_KEYS_PER_ENTITY

    @staticmethod
    def _blob_len(record: dict) -> int:
        return _record_bytes(record)

    def _corpus_bytes_for(self, entity: str) -> int:
        """The summed serialized bytes of an entity's materialized corpus, computed once then maintained."""
        if entity not in self._corpus_bytes:
            self._corpus_bytes[entity] = sum(self._blob_len(r) for r in self._records_for(entity).values())
        return self._corpus_bytes[entity]

    def _envelope_admits_new(self, entity: str, records: dict, blob_len: int) -> str | None:
        """Why a new key may not be materialized (`bytes`/`key`/`corpus`), or None if it fits."""
        from . import envelope
        if blob_len > envelope.MAX_BYTES_PER_KEY:
            return "bytes"                                      # one record larger than the per-key ceiling
        if len(records) >= self._envelope_cap():
            return "key"                                        # the distinct-key ceiling
        if self._corpus_bytes_for(entity) + blob_len > envelope.MAX_CORPUS_BYTES_PER_ENTITY:
            return "corpus"                                     # the summed-bytes ceiling
        return None

    def _envelope_admits_growth(self, entity: str, merged: dict, delta: int) -> bool:
        """Whether merging may grow an existing key: refused if the merged record breaches the per-key
        ceiling or its growth breaches the corpus ceiling (so a key cannot grow without bound)."""
        from . import envelope
        if self._blob_len(merged) > envelope.MAX_BYTES_PER_KEY:
            return False
        if delta > 0 and self._corpus_bytes_for(entity) + delta > envelope.MAX_CORPUS_BYTES_PER_ENTITY:
            return False
        return True

    def _refuse_over_envelope(self, entity: str, key: str, kind: str) -> None:
        """Append one live refused identity to the durable ledger (bounded dedup cache, deduped on read); a
        write failure is surfaced, never swallowed, and the marker is written on the first refusal."""
        cache = self._refused_cache.setdefault(entity, _BoundedKeySet(REFUSED_DEDUP_CACHE))
        if key in cache:
            return                                              # recently recorded: skip the redundant write
        try:
            self._append_refused(entity, key, kind)             # durable, per refusal — no lossy sampling
        except OSError as e:
            self._mark_durability_degraded(f"ledger:{entity}",
                                           f"envelope refusal ledger unwritable for {entity!r} "
                                           f"({type(e).__name__})")
            return                                              # a lost refusal must not read as clean/complete
        cache.add(key)
        if not self._envelope_marked:
            self._envelope_marked = True
            self._write_marker_stub()                          # a durable marker exists from the first refusal

    def _mark_durability_degraded(self, cause: str, why: str) -> None:
        """Surface a refusal-durability failure (ledger unwritable / damaged) once per cause, persisting it to a
        DURABLE marker so a reopen still sees the gap. If that marker write ALSO fails, that is surfaced loudly
        too (its own exception note), never swallowed — a lost gap must not be silent."""
        if cause in self._envelope_durability:
            return
        msg = f"EXCEPTION: {why}; the refused-identity remainder may be incomplete"
        self._envelope_durability[cause] = msg
        self.notes.append(msg)
        try:
            active = self._active_mutation_owner()
            if active is not None:
                state = self._read_state_from_fd(active.run_anchor.fd)["state"]
                if state not in {"created", "running"}:
                    return
                self._replace_run_bytes_locked(
                    ("envelope-degraded.json",),
                    json.dumps(
                        {"degraded": dict(self._envelope_durability)}, indent=2,
                    ).encode("utf-8"),
                )
            elif self.state in {"created", "running"}:
                with self._mutation(MutationScope.BASE_EVIDENCE):
                    self._replace_run_bytes_locked(
                        ("envelope-degraded.json",),
                        json.dumps(
                            {"degraded": dict(self._envelope_durability)}, indent=2,
                        ).encode("utf-8"),
                    )
        except OSError as e:
            if not self._marker_unwritable:                     # surface once: the gap will not survive a crash
                self._marker_unwritable = True
                self.notes.append(f"EXCEPTION: envelope durability marker unwritable ({type(e).__name__}); "
                                  f"a refusal gap will not survive a crash")

    def _load_durability_marker(self) -> None:
        # recover durability failures from both the standalone marker and the finalized manifest, so a gap
        # survives reopen even when the separate marker itself could not be written (the manifest path could)
        for src in (self._degraded_path, self.manifest_path):
            try:
                doc = json.loads(src.read_text())
            except (OSError, json.JSONDecodeError, ValueError):
                continue
            degraded = doc.get("degraded") or doc.get("envelope_degraded") if isinstance(doc, dict) else None
            for cause, msg in (degraded or {}).items():
                if isinstance(cause, str) and isinstance(msg, str) and cause not in self._envelope_durability:
                    self._envelope_durability[cause] = msg
                    self.notes.append(msg)                      # re-surface on reopen, so the gap persists

    def _append_refused(self, entity: str, key: str, kind: str) -> None:
        append = _CanonicalLogAppendOwner(
            self, ("envelope-refused.jsonl",),
            (json.dumps({"entity": entity, "key": key, "kind": kind},
                        ensure_ascii=False) + "\n").encode(),
        )
        settlement = _SettlementOwner(append.settle)
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                append.execute()

    def _fold_refused_path(self, entity: str):
        return self._fold_refused_dir / f"{validate_entity(entity)}.jsonl"

    def _refusal_sources(self) -> list:
        """Every durable refusal file: the live append ledger plus each rewritten per-entity fold file. An
        unreadable fold dir fails closed (a durable gap), never a silent skip that reads as clean."""
        srcs = [self._refused_path]
        if self._fold_refused_dir.exists():
            try:
                srcs += sorted(self._fold_refused_dir.iterdir())
            except OSError as e:
                self._mark_durability_degraded("fold_dir",
                                               f"envelope fold-refusal dir unreadable ({type(e).__name__})")
        return srcs

    def _refusal_components_locked(self) -> list[tuple[str, ...]]:
        """Enumerate exact refusal files through the pinned Run anchor."""
        from . import privfs
        active = self._active_mutation_owner()
        if active is None:
            return [tuple(path.relative_to(self.dir).parts) for path in self._refusal_sources()
                    if path.exists()]
        components: list[tuple[str, ...]] = []
        try:
            self._run_file_stat_locked(("envelope-refused.jsonl",))
        except (FileNotFoundError, privfs.PrivatePathMissing):
            pass
        else:
            components.append(("envelope-refused.jsonl",))
        directory = _OwnedDescriptor()
        settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners((directory,), "refusal directory descriptor"),
        )
        with _SettlementFence(settlement):
            with _SettlementFence(settlement):
                try:
                    _open_strict_directory_into(
                        directory, active.run_anchor.fd,
                        ("envelope-fold-refused",),
                    )
                except privfs.PrivatePathMissing:
                    return components
                for name in sorted(os.listdir(directory.fd)):
                    validate_artifact_component(name, "fold refusal filename")
                    observed = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                    if not stat.S_ISREG(observed.st_mode):
                        raise ContractError("envelope fold-refusal entry is unsafe")
                    components.append(("envelope-fold-refused", name))
        return components

    def _ledger_distinct_by_kind(self) -> dict:
        """Exact distinct refused identities per (known entity, kind), folded from every refusal file via an
        on-disk sqlite dedup: memory is one insert batch and the group set is bounded to the entity enum, never
        a resident set of all identities. Fails CLOSED — a malformed, non-object, or out-of-vocabulary line is
        counted as damage and surfaced as a durable gap. No refusal files -> recover an old count-only marker."""
        import sqlite3
        import tempfile
        sources = self._refusal_components_locked()
        if not sources:
            return self._recover_marker_counts()
        fd, dbpath = tempfile.mkstemp(prefix="quarry-envcount-", suffix=".db")
        os.close(fd)
        damaged = 0
        out: dict[str, dict[str, int]] = {}
        try:
            con = sqlite3.connect(dbpath)
            con.execute("PRAGMA journal_mode=OFF")
            con.execute("PRAGMA synchronous=OFF")
            con.execute("CREATE TABLE r(entity TEXT, key TEXT, kind TEXT, "
                        "PRIMARY KEY(entity, key)) WITHOUT ROWID")   # PK dedups; first kind wins
            active = self._active_mutation_owner()
            for components in sources:
                batch: list = []
                source = _OwnedDescriptor()
                try:
                    if active is None:
                        source.open(self.dir.joinpath(*components), _FILE_OPEN_FLAGS)
                    else:
                        _open_strict_file_into(
                            source, active.run_anchor.fd, components,
                        )
                    reader = _DescriptorReader(source.fd)
                    for line in _iter_ledger_lines(reader, _MAX_LEDGER_LINE):
                        if line is None:            # an over-length line, rejected before materialize/parse
                            damaged += 1
                            continue
                        if not line.strip():
                            continue
                        try:
                            rec = json.loads(line.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            damaged += 1
                            continue
                        if not isinstance(rec, dict):
                            damaged += 1                    # valid JSON, wrong shape -> damage, never rec.get crash
                            continue
                        e, k, kind = rec.get("entity"), rec.get("key"), rec.get("kind")
                        # out-of-vocabulary entity/kind, an over-long key, or a key sqlite cannot encode
                        # (a lone surrogate) is damage: fails closed and bounds finalize RAM to the enum
                        # and a small batch of length-capped keys
                        if (not isinstance(e, str) or e not in ENTITY_KEYS or not isinstance(k, str)
                                or not isinstance(kind, str) or kind not in _REFUSAL_KINDS
                                or len(k) > _MAX_LEDGER_KEY or not _utf8_safe(k)):
                            damaged += 1
                            continue
                        batch.append((e, k, kind))
                        if len(batch) >= _LEDGER_BATCH:     # bounded: one small batch resident, flushed to disk
                            con.executemany("INSERT OR IGNORE INTO r VALUES(?,?,?)", batch)
                            batch.clear()
                    if batch:
                        con.executemany("INSERT OR IGNORE INTO r VALUES(?,?,?)", batch)
                except OSError:
                    damaged += 1
                finally:
                    _settle_descriptor_owners(
                        (source,), "refusal source descriptor",
                    )
            for e, kind, n in con.execute("SELECT entity, kind, COUNT(*) FROM r GROUP BY entity, kind"):
                out.setdefault(e, {})[kind] = n
            con.close()
        finally:
            for p in (dbpath, dbpath + "-journal", dbpath + "-wal", dbpath + "-shm"):
                try:
                    os.unlink(p)
                except OSError:
                    pass
        if damaged:
            self._mark_durability_degraded("ledger:damaged",
                                            f"{damaged} refusal-ledger line(s) unreadable")
        return out or self._recover_marker_counts()

    def _recover_marker_counts(self) -> dict:
        """A pre-ledger run (older code) kept only the summary marker's counts, without identities; recover them
        so its remainder is not silently lost, tallied under `key`."""
        out: dict[str, dict[str, int]] = {}
        try:
            doc = self._read_run_json_locked("envelope-remainder.json")
        except (OSError, json.JSONDecodeError, ValueError):
            return out
        for rem in (doc.get("remainders") or []) if isinstance(doc, dict) else []:
            ent = (rem.get("detail") or {}).get("entity") if isinstance(rem, dict) else None
            n = (rem.get("terminal") or {}).get("unschedulable") if isinstance(rem, dict) else None
            if isinstance(ent, str) and type(n) is int and n > 0:
                out[ent] = {"key": n}
        return out

    def _write_marker_stub(self) -> None:
        """A cheap existence marker on the first refusal, so a mid-ingest reopen sees that overflow happened
        without paying the full ledger fold; the exact count is refreshed into it at finalize."""
        try:
            from . import envelope
            self._replace_run_bytes_locked(
                ("envelope-remainder.json",),
                json.dumps({**envelope.declaration(), "overflow": True}, indent=2).encode("utf-8"),
            )
        except OSError:
            pass

    def _persist_envelope_remainder(self) -> None:
        env = self.envelope_remainder()
        if env is not None:
            self._replace_run_bytes_locked(
                ("envelope-remainder.json",), json.dumps(env, indent=2).encode("utf-8"),
            )

    def envelope_remainder(self) -> dict | None:
        """The durable record of identities this run refused past the declared corpus envelope, or None if it
        stayed within it — the exact distinct keys (folded from the refusal files, bounded) a later run on a
        raised bound still owes."""
        counts = self._ledger_distinct_by_kind()
        if not counts:
            return None
        from . import envelope
        remainders = [envelope.overflow_remainder(e, sum(by_kind.values()), by_kind=by_kind).as_record()
                      for e, by_kind in sorted(counts.items())]
        return {**envelope.declaration(), "remainders": remainders}

    def _records_for(self, entity: str) -> dict:
        """Lazily materialize ``{key: record}`` under the full envelope.

        While base evidence is live, fold refusals are rewritten per entity so
        their durable count remains exact. A sealed/report fold is read-only and
        relies on the refusal ledger committed before the seal.
        """
        entity = validate_entity(entity)
        self._refresh_entity_cache(entity)
        if entity in self._records:
            return self._records[entity]
        # A live fold may durably account for over-envelope rows. A report/reopen
        # fold is strictly read-only: the pre-seal manifest already records what
        # was refused, and derived rendering cannot author new base ledgers.
        if self.state in {"created", "running"}:
            with self._mutation(MutationScope.BASE_EVIDENCE):
                return self._fold_records_for(entity, persist_refusals=True)
        return self._fold_records_for(entity, persist_refusals=False)

    def _fold_records_for(self, entity: str, *, persist_refusals: bool) -> dict:
        if entity in self._records:
            return self._records[entity]
        from . import envelope, privfs
        active = self._active_mutation_owner()
        if persist_refusals and active is None:
            raise ContractError("persisted entity fold has no mutation authority")
        if active is None:
            folded = fold_observations(
                self._entity_file(entity), max_keys=self._envelope_cap(),
                max_bytes_per_key=envelope.MAX_BYTES_PER_KEY,
                max_corpus_bytes=envelope.MAX_CORPUS_BYTES_PER_ENTITY,
                require_newline=True,
            )
            self._folded[entity] = folded
            self._records[entity] = folded.records
            self._entity_signatures[entity] = self._entity_signature(entity)
            return self._records[entity]

        source = _OwnedDescriptor()
        source_settlement = _SettlementOwner(
            lambda: _settle_descriptor_owners((source,), "entity fold source descriptor"),
        )
        refused_any = [False]
        refusal_stage = None
        components = ("envelope-fold-refused", f"{entity}.jsonl")
        with _SettlementFence(source_settlement):
            with _SettlementFence(source_settlement):
                try:
                    _open_strict_file_into(
                        source, active.run_anchor.fd,
                        ("normalized", f"{entity}.jsonl"),
                    )
                except privfs.PrivatePathMissing:
                    folded = FoldedLog(status="absent", reason="no observation log")
                else:
                    if persist_refusals:
                        try:
                            self._ensure_artifact_parent(components)
                            refusal_stage = privfs.create_private_stage(
                                active.run_anchor.fd, components,
                            )
                        except OSError as exc:
                            self._mark_durability_degraded(
                                f"fold:{entity}",
                                f"envelope fold-refusal file unwritable for {entity!r} "
                                f"({type(exc).__name__})",
                            )

                    def _sink(k: str, kind: str) -> None:
                        refused_any[0] = True
                        if refusal_stage is not None:
                            _write_all_descriptor(
                                refusal_stage.file_fd,
                                (json.dumps({"entity": entity, "key": k, "kind": kind},
                                            ensure_ascii=False) + "\n").encode("utf-8"),
                            )

                    try:
                        folded = _fold_observation_stream(
                            _iter_descriptor_lines(source.fd), entity,
                            max_keys=self._envelope_cap(),
                            max_bytes_per_key=envelope.MAX_BYTES_PER_KEY,
                            max_corpus_bytes=envelope.MAX_CORPUS_BYTES_PER_ENTITY,
                            on_refused=_sink,
                            require_newline=True,
                        )
                        if refusal_stage is not None:
                            if refused_any[0]:
                                privfs.replace_private_stage(refusal_stage)
                            else:
                                privfs.abort_private_stage(refusal_stage)
                                self._unlink_run_file_locked(components)
                    except BaseException:
                        if (refusal_stage is not None
                                and refusal_stage.state not in {"aborted", "committed", "fenced"}):
                            try:
                                privfs.abort_private_stage(refusal_stage)
                            except BaseException:
                                pass
                        raise
        if persist_refusals:
            if refused_any[0] and not self._envelope_marked:
                self._envelope_marked = True
                self._write_marker_stub()
        self._folded[entity] = folded
        self._records[entity] = folded.records
        self._entity_signatures[entity] = self._entity_signature(entity)
        return self._records[entity]

    def _seen_keys(self, entity: str) -> set:
        return set(self._records_for(entity))

    def read(self, entity: str) -> list[dict]:
        """The merged entities (one per canonical key, provenance unioned) — not the raw observation lines."""
        return list(self._records_for(validate_entity(entity)).values())

    def read_folded(self, entity: str) -> "FoldedLog":
        """The merged view WITH its trust status (`absent`/`valid`/`degraded`/`unusable`).

        `read()` throws the status away, so a caller cannot tell "no rows" from "the log could not be read".
        For an ordinary corpus that is a fair simplification; for a record that decides whether we may act —
        the acquisition-ownership transition log — it is the whole question.
        """
        entity = validate_entity(entity)
        if entity not in self._folded:
            self._records_for(entity)          # the same capped, streaming, refused-aware fold
        return self._folded[entity]

    def count(self, entity: str) -> int:
        return len(self._records_for(validate_entity(entity)))

    def values(self, entity: str) -> list[str]:
        entity = validate_entity(entity)
        key_field = ENTITY_KEYS[entity]
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
        # fold the refusal ledger first: a damaged/unwritable ledger surfaces a durable exception into notes,
        # which phase_exceptions (below) must see so an overflow with a broken ledger never reads as clean
        env_remainder = self.envelope_remainder()
        # a degraded tool status, and the Gap kind that names why the input was lost
        _DEGRADED = {"partial": "tool_omission", "blocked": "unknown", "timed_out": "timeout"}
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
        for entity in sorted(ENTITY_KEYS):
            folded = self.read_folded(entity)
            if folded.status in {"degraded", "unusable", "unknown"}:
                gaps.append({
                    "phase": "store", "tool": f"normalized:{entity}",
                    "status": folded.status, "kind": "unknown",
                    "why": folded.reason or "canonical observation log is damaged",
                    "output_lines": len(folded.records),
                })
        tool_runs = self.tool_runs()
        for r in tool_runs:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
            why = r.note or r.stderr_tail or f"exit {r.exit_code}"
            if r.status == "failed":
                failures.append({"phase": r.phase, "tool": r.tool, "why": why})
            elif r.status in _DEGRADED:
                gaps.append({"phase": r.phase, "tool": r.tool, "status": r.status, "kind": _DEGRADED[r.status],
                             "why": why, "output_lines": r.stdout_lines})
            elif r.status == "skipped" and any(m in why.lower() for m in _MISSING) and (
                    r.tool in _required or r.depends_on in _required):
                # the absent binary, whether the source is recorded under its own name or declares the edge
                gaps.append({"phase": r.phase, "tool": r.tool, "status": "missing", "kind": "required_tool_missing",
                             "why": why, "output_lines": 0,
                             "missing_tool": r.depends_on or r.tool})   # required tool absent -> coverage gap
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
                gaps.append({**entry, "status": st, "kind": "tool_omission", "output_lines": 0})
        phase_exceptions = [secrets.redact(n) for n in self.notes if "EXCEPTION" in n]
        # ── coverage counters: reconcile event-level input omissions into the verdict ──────────────
        # cap/timeout omitted>0 is a gap; sample/limit omitted>0 is a soft limit; inconsistent is unknown
        coverage = self._read_coverage()
        coverage_limits = []
        for cov in coverage:
            sid = cov["source_id"]
            base = {"phase": sid.split(".", 1)[0], "tool": sid, "measure": cov["measure"], "why": cov["reason"]}
            if not cov["valid"]:
                gaps.append({**base, "status": "coverage:unknown", "kind": "unknown",
                             "output_lines": cov["tested"],
                             "eligible": cov["eligible"], "omitted": cov["omitted"]})
                continue
            for kind, c in cov["by_kind"].items():
                if c["omitted"] <= 0:
                    continue                                          # fully covered this run — no gap/limit
                frac = round(c["omitted"] / c["eligible"], 3) if c["eligible"] else 0.0
                entry = {**base, "status": f"coverage:{kind}", "kind": kind, "output_lines": c["tested"],
                         "eligible": c["eligible"], "omitted": c["omitted"], "omitted_fraction": frac,
                         "priority": "major" if _coverage_gates(frac, c["omitted"]) else "minor"}
                if kind in (events.COVERAGE_SAMPLE, events.COVERAGE_PROVIDER):
                    coverage_limits.append(entry)                     # operator subset / provider limit -> soft
                else:
                    gaps.append(entry)                                # cap/timeout with omitted>0 -> gap
        # ── structured child faults ────────────────────────────────────────────────────────────────
        # machinery break · optional tool failure · required tool missing, each a typed Fault carrying
        # whether it challenges completeness, so the verdict never has to re-derive that from a label
        from .state import Fault
        faults = [Fault("phase_exception", where="run", detail=note) for note in phase_exceptions]
        _optional = set()
        try:
            from .registry import load_tools as _load
            _optional = {t.bin for t in _load() if t.optional}
        except Exception:                                          # noqa: BLE001 — a report is never a stop
            _optional = set()
        for f in failures:
            faults.append(Fault("optional_tool_failed" if f.get("tool") in _optional else "machinery",
                                where=f.get("tool") or f.get("phase"), detail=f.get("why")))
        for g in gaps:
            if g.get("status") == "missing":
                faults.append(Fault("required_tool_missing", where=g.get("tool"), detail=g.get("why")))
        # faults committed against the run itself (event-sink loss, finalisation breaks) — in before the verdict
        faults += list(self._faults)

        # ── corpus-envelope overflow ──────────────────────────────────────────────────────
        # refused identities are lost coverage this run, so they gate the verdict as a gap and ride the
        # remainders a supervisor reads; without this an overflowed run finalises as clean/complete
        remainders = self._read_remainders()
        env = env_remainder
        if env is not None:
            for rec in env["remainders"]:
                remainders.append(rec)
                n = rec["terminal"].get("unschedulable", 0)
                gaps.append({"phase": "store", "tool": rec["unit"], "status": "envelope_overflow",
                             "kind": "cap",
                             "why": f"{n} identit(ies) refused past the corpus envelope", "output_lines": 0,
                             "omitted": n})

        # gaps committed against the run itself (checkpoint challenges, finalisation coverage loss)
        for g in self._gaps:
            gaps.append({"phase": (g.source_id or "run").split(".", 1)[0], "tool": g.source_id,
                         "status": f"coverage:{g.kind}", "kind": g.kind, "measure": g.measure,
                         "why": g.reason, "output_lines": g.tested or 0})

        summary = {
            "tool_status": status_counts, "tools_failed": len(failures),
            "failures": failures, "gaps": gaps, "phase_exceptions": phase_exceptions,
            "coverage": coverage, "coverage_limits": coverage_limits,
            # what each lane still owes; absent means unknown, never zero
            "remainders": remainders,
            "faults": [f.to_dict() for f in faults],
            "provider_spend": self._read_spend(),
            "provider_limits": provider_limits, "operator_limits": operator_limits}
        self._verdict_sealed = True
        self._sealed_summary = {"verdict": _verdict_for(summary), **summary}
        return self._sealed_summary

    def summary(self) -> dict:
        """The one canonical summary. Computed once per seal; a reopened run reads the committed manifest
        rather than recomputing a verdict from an empty in-process tool ledger."""
        from .state import ContractError
        if self._sealed_summary is not None:
            return self._sealed_summary
        if self.manifest_path.exists():
            # a committed manifest is the verdict; a damaged one has none, and recomputing here would
            # answer from an empty in-process ledger — a clean verdict invented for a broken record
            stored = (_read_json(self.manifest_path) or {}).get("summary")
            if not summary_well_formed(stored):
                raise ContractError(f"run {self.run_id} has a manifest whose summary is unreadable or "
                                    f"incomplete — refusing to recompute a verdict over it")
            return stored
        return self._run_summary()

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

    def _prepare_manifest_locked(
        self, profile_summary: dict, phases_run: list[str],
        metrics: dict | None = None, policy: list | None = None,
        *, base_mutations: bool,
    ) -> _PreparedManifest:
        """Build immutable manifest bytes under an already-held run authority."""
        from . import secrets
        # a failed event-sink write means events.jsonl is incomplete, so a coverage/verdict folded from it
        # is not clean truth — committed before the summary, or the verdict is computed without it
        from . import events as _events
        self.unseal_verdict()                   # this write recomputes the summary, so faults may still land
        od = _events.observability_degraded()
        if od and base_mutations:
            from .state import Fault
            self.commit_fault(Fault("machinery", where="events.jsonl",
                                    detail=f"{od['writes_failed']} event write(s) failed: {od['first_error']}"))
        manifest = {
            "run_id": self.run_id,
            "target": self.target,
            "started": self.started,
            "finished": _utc(),
            "profile": profile_summary,
            "phases_run": phases_run,
            "tool_runs": [asdict(r) for r in self.tool_runs()],
            "entity_counts": {e: self.count(e) for e in ENTITY_KEYS
                              if self._entity_file(e).exists()},
            "notes": [secrets.redact(n) for n in self.notes],
            "summary": self._run_summary(),
        }
        from . import envelope as _envelope
        manifest["envelope"] = _envelope.declaration()       # the corpus bound this run enforced
        env_remainder = self.envelope_remainder()
        if env_remainder is not None:                        # keys refused past the envelope, durably owed
            manifest["envelope_remainder"] = env_remainder
            if base_mutations:
                # refresh the standalone durable file to the exact final count before the base seal
                self._persist_envelope_remainder()
        if self._envelope_durability:                        # durability failures the reopen must re-surface even
            manifest["envelope_degraded"] = dict(self._envelope_durability)   # if the separate marker was unwritable
        if metrics:                                 # pointer + headline totals for the telemetry artifact
            manifest["metrics"] = metrics
        if policy:
            # the effective coverage policy this run applied, redacted again at this sink because a sink that
            # trusts its input is how one leak becomes permanent
            manifest["policy"] = secrets.redact_deep(policy)
        if od:
            manifest["observability_degraded"] = od
        if base_mutations:
            _events.persist_degraded()              # survives the base seal and the next process
        history = {
            "run_id": self.run_id,
            "target": self.target,
            "finished": manifest["finished"],
            "entity_counts": manifest["entity_counts"],
        }
        return _PreparedManifest(
            run_id=self.run_id,
            target=self.target,
            manifest_text=json.dumps(manifest, indent=2),
            history_text=json.dumps(history, indent=2),
        )

    def publish_manifest(self, prepared: _PreparedManifest) -> None:
        """Publish exact pre-seal manifest bytes as finalization metadata."""
        if type(prepared) is not _PreparedManifest:
            raise TypeError("publish_manifest requires a prepared manifest")
        if prepared.run_id != self.run_id or prepared.target != self.target:
            raise ContractError("prepared manifest belongs to a different run")
        with self._mutation(MutationScope.FINALIZATION_METADATA):
            current = self.state
            if current == "finalizing":
                if self._run_name_exists_locked("manifest.json"):
                    raise ContractError(
                        "the base manifest is already published; reconcile only derived-publication metadata",
                    )
            else:
                raise ContractError(
                    f"run {self.run_id} cannot publish a base manifest in state {current!r}",
                )
            self._replace_run_bytes_locked(
                ("manifest.json",), prepared.manifest_text.encode("utf-8"),
            )
            owner = self._active_mutation_owner()
            if owner is None:
                raise ContractError("manifest publication has no mutation authority")
            publisher = _ProjectStatePublisher(owner)
            settlement = _SettlementOwner(publisher.settle)
            with _SettlementFence(settlement):
                with _SettlementFence(settlement):
                    publisher.publish(
                        f"{self.run_id}.json", prepared.history_text.encode("utf-8"),
                        str(self.dir),
                    )

    def write_manifest(self, profile_summary: dict, phases_run: list[str],
                       metrics: dict | None = None, policy: list | None = None) -> None:
        """Compatibility writer; production seals precomputed bytes via ``begin_finalization``.

        Legacy/test callers may still commit an initial manifest before lifecycle
        finalization.  A finalizing caller is restricted to a read-only rebuild;
        it cannot persist a remainder or manufacture a base fault after the seal.
        """
        state_now = self.state
        if state_now == "finished":
            raise ContractError(f"run {self.run_id} is finished — reopen it (`finalizing`) before "
                                f"rewriting its manifest")
        if state_now == "finalization_failed":
            raise ContractError(
                f"run {self.run_id} is sealed — reopen derived finalization instead of rewriting its "
                "base manifest",
            )
        if state_now == "finalizing" and os.path.lexists(self.manifest_path):
            raise ContractError(
                "the base manifest is already published; reconcile only derived-publication metadata",
            )
        if state_now == "created":
            self.write_state("running")
            state_now = "running"
        if state_now == "running":
            prepared = self.begin_finalization(
                profile_summary=profile_summary,
                phases_run=phases_run,
                metrics=metrics,
                policy=policy,
            )
            if prepared is None:
                raise ContractError("manifest preparation did not complete")
            self.publish_manifest(prepared)
            return
        with self._mutation(MutationScope.FINALIZATION_METADATA):
            prepared = self._prepare_manifest_locked(
                profile_summary, phases_run, metrics, policy,
                base_mutations=False,
            )
            self.publish_manifest(prepared)

    @staticmethod
    def list_runs(project_dir: Path) -> "list[Path]":
        """Reconciled real run directories, oldest→newest, without following or modifying repository data."""
        return [path for _started, _name, path, _identity, _inode in _run_snapshots(Path(project_dir))]

    @staticmethod
    def latest(project_dir: Path, target: str | None = None) -> "Run | None":
        if target is not None:
            target = validate_target(target)
        snapshots = _run_snapshots(Path(project_dir))
        if not snapshots:
            return None
        _started, run_id, _path, identity, run_directory_identity = snapshots[-1]
        if target is not None and identity["target"] != target:
            raise ContractError(f"latest run {run_id!r} belongs to target {identity['target']!r}, "
                                f"not {target!r}")
        return Run(project_dir, identity["target"], run_id=run_id, load_started=True, _identity=identity,
                   _run_directory_identity=run_directory_identity,
                   _authority=_RUN_CONSTRUCTION_AUTHORITY)


def managed_run_for_artifact(path) -> "tuple[Run, tuple[str, ...]] | None":
    """Return the owning run and relative identity for a lexical managed path.

    This discovery is read-only.  It exists only to fail closed at compatibility
    surfaces that still receive a ``Path``; new writers should carry an explicit
    artifact claim instead.
    """
    if not isinstance(path, (str, os.PathLike)):
        return None
    try:
        candidate = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError, OSError):
        return None
    for run_dir in candidate.parents:
        if run_dir.parent.name != "recon":
            continue
        run_id = run_dir.name
        if not valid_run_id(run_id):
            continue
        try:
            relative = candidate.relative_to(run_dir)
        except ValueError:
            continue
        if not relative.parts:
            return None
        components = _validated_artifact_components(tuple(relative.parts))
        project_dir = run_dir.parent.parent
        try:
            identity = read_run_identity(project_dir, run_id)
        except FileNotFoundError:
            continue
        run = Run.open(project_dir, identity["target"], run_id)
        return run, components
    return None
