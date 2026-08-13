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
_RUN_LOCK_LOCAL = threading.local()

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


def fold_observations(path, *, max_keys: int | None = None, max_bytes_per_key: int | None = None,
                      max_corpus_bytes: int | None = None, on_refused=None) -> FoldedLog:
    """Stream one entity's append-only log into its merged view (peak RSS = one line + the materialized set).
    Enforces the given envelope limits: a new key is refused past `max_keys`/`max_bytes_per_key`/
    `max_corpus_bytes`, and an existing key may not grow past the byte ceilings; each refusal goes to
    `on_refused(key, kind)` if given (bounded), else into `refused_keys`. All limits None -> unbounded read.
    """
    entity = Path(path).stem
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

    try:
        with open(path, "rb") as fh:
            for line in fh:                          # one line resident at a time; the file is never held whole
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
                        _refuse(k, "growth")         # keep base; a key may not grow past the per-key ceiling
                    elif max_corpus_bytes is not None and delta > 0 and corpus_bytes + delta > max_corpus_bytes:
                        _refuse(k, "growth")
                    else:
                        merged[k] = cand
                        corpus_bytes += max(0, delta)
                    continue
                rb = _record_bytes(rec) if bytes_active else 0
                if max_bytes_per_key is not None and rb > max_bytes_per_key:
                    _refuse(k, "bytes")              # one record larger than the per-key ceiling
                elif max_keys is not None and len(merged) >= max_keys:
                    _refuse(k, "key")                # the distinct-key ceiling
                elif max_corpus_bytes is not None and corpus_bytes + rb > max_corpus_bytes:
                    _refuse(k, "corpus")             # the summed-bytes ceiling
                else:
                    merged[k] = rec
                    corpus_bytes += rb
    except FileNotFoundError:
        return FoldedLog(status="absent", reason="no observation log")
    except OSError as e:
        return FoldedLog(status="unusable", reason=f"{type(e).__name__}: {e}")
    refused = len(refused_keys) if on_refused is None else refused_count
    if dropped:
        return FoldedLog(records=merged, status="degraded", dropped=dropped, refused=refused,
                         refused_keys=refused_keys, reason=f"{dropped} unusable observation row(s)")
    return FoldedLog(records=merged, refused=refused, refused_keys=refused_keys)


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
    try:
        fd = os.open(name, _FILE_OPEN_FLAGS, dir_fd=run_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        error = _InvalidRunIdentity if e.errno in (errno.ELOOP, errno.ENOTDIR) else ContractError
        raise error(f"run identity {name} cannot be opened safely: {type(e).__name__}: {e}") from e
    try:
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
    finally:
        os.close(fd)


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


def _open_run_fd(project_dir: Path, run_id: str) -> int:
    """Open an existing real run directory relative to a no-follow repository root."""
    run_id = validate_run_id(run_id)                 # before the id participates in any path/open operation
    root = Path(project_dir) / "recon"
    try:
        root_fd = os.open(root, _DIR_OPEN_FLAGS)
    except FileNotFoundError as e:
        raise FileNotFoundError(f"run {run_id!r} not found under {root}") from e
    except OSError as e:
        raise ContractError(f"repository root {root} cannot be opened safely: {type(e).__name__}: {e}") from e
    try:
        try:
            return os.open(run_id, _DIR_OPEN_FLAGS, dir_fd=root_fd)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"run {run_id!r} not found under {root}") from e
        except OSError as e:
            raise ContractError(f"run {run_id!r} is not a safe real directory: "
                                f"{type(e).__name__}: {e}") from e
    finally:
        os.close(root_fd)


def read_run_identity(project_dir: Path, run_id: str) -> dict:
    """Read one reconciled run identity without creating or repairing repository state."""
    run_id = validate_run_id(run_id)
    run_fd = _open_run_fd(Path(project_dir), run_id)
    try:
        identity, _started = _run_identity_from_fd(run_fd, run_id)
        return dict(identity)
    finally:
        os.close(run_fd)


def read_run_creation_target(project_dir: Path, run_id: str) -> str:
    """Read the target from a child's no-follow creation record.

    Campaign recovery deliberately does not require an interpretable ``started`` timestamp here: budget
    accounting owns that separate question and can fail closed only when a budget was requested.  The
    directory/run ID and target still reconcile with any readable manifest identity.
    """
    run_id = validate_run_id(run_id)
    run_fd = _open_run_fd(Path(project_dir), run_id)
    try:
        creation = _read_identity_file(run_fd, "run.json")
        if creation is None or creation is _MALFORMED_IDENTITY or not isinstance(creation, dict):
            raise _InvalidRunIdentity(f"run {run_id!r} has no readable run.json creation record")
        if creation.get("run_id") != run_id:
            raise _InvalidRunIdentity(f"run.json names {creation.get('run_id')!r}, not directory {run_id!r}")
        target = creation.get("target")
        if type(target) is not str or not target.strip():
            raise _InvalidRunIdentity(f"run {run_id!r} creation record names no target")
        manifest = _read_identity_file(run_fd, "manifest.json")
        if isinstance(manifest, dict):
            manifest_id, manifest_target = manifest.get("run_id"), manifest.get("target")
            if type(manifest_id) is str and manifest_id != run_id:
                raise _InvalidRunIdentity(f"manifest.json names {manifest_id!r}, not directory {run_id!r}")
            if type(manifest_target) is str and manifest_target.strip() and manifest_target != target:
                raise _InvalidRunIdentity("run.json and manifest.json disagree on target")
        return target
    finally:
        os.close(run_fd)


def _run_snapshots(project_dir: Path) -> "list[tuple[datetime, str, Path, dict]]":
    """Validated identity snapshots for selectable runs, oldest first.

    Each identity is read exactly once through a no-follow run descriptor.  Consumers carry this snapshot
    forward rather than reopening path metadata; the later repository-authority slice will pin descriptor
    lifetime across mutations as well.
    """
    root = Path(project_dir) / "recon"
    try:
        root_fd = os.open(root, _DIR_OPEN_FLAGS)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise ContractError(f"repository root {root} cannot be listed safely: "
                            f"{type(e).__name__}: {e}") from e
    runs = []
    try:
        try:
            names = os.listdir(root_fd)
        except OSError as e:
            raise ContractError(f"repository root {root} cannot be listed: {type(e).__name__}: {e}") from e
        for name in names:
            if not valid_run_id(name):
                continue
            try:
                run_fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=root_fd)
            except OSError as e:
                if e.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                    continue                              # symlink, non-directory, or vanished entry
                raise ContractError(f"run {name!r} cannot be opened while enumerating {root}: "
                                    f"{type(e).__name__}: {e}") from e
            try:
                try:
                    identity, started = _run_identity_from_fd(run_fd, name)
                except _InvalidRunIdentity:
                    continue                              # damaged identities are not selectable as a run
            finally:
                os.close(run_fd)
            runs.append((started, name, root / name, identity))
    finally:
        os.close(root_fd)
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

    def allocate(self, allocate) -> int:
        if self.fd >= 0:
            raise ContractError("repository descriptor ownership slot is already used")
        self.terminal = False
        self.fd = allocate()
        observed = os.fstat(self.fd)
        self.identity = (observed.st_dev, observed.st_ino)
        if (self.expected_identity is not None
                and self.identity != self.expected_identity):
            raise ContractError("repository descriptor identity changed during allocation")
        return self.fd

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


def _replay_settlement(operation) -> list[BaseException]:
    """Run one idempotent settlement twice only when the first pass escaped."""
    faults: list[BaseException] = []
    try:
        operation()
    except BaseException as exc:
        faults.append(exc)
        try:
            operation()
        except BaseException as replay_exc:
            faults.append(replay_exc)
    return faults


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
        directory = privfs.private_dir(self.run._artifact_claim_dir)
        self.directory.allocate(lambda: os.open(directory, _DIR_OPEN_FLAGS))
        self.name = f"{os.urandom(16).hex()}{_CLAIM_SUFFIX}"
        self.marker.allocate(
            lambda: os.open(
                self.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                privfs.FILE_MODE,
                dir_fd=self.directory.fd,
            ),
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
                    return
                if self.directory.fd < 0:
                    self.directory.allocate(
                        lambda: os.open(
                            self.run._artifact_claim_dir, _DIR_OPEN_FLAGS,
                        ),
                    )
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
                        self.marker.allocate(
                            lambda: os.open(
                                self.name, _FILE_OPEN_FLAGS,
                                dir_fd=self.directory.fd,
                            ),
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
            self.anchor.allocate(
                lambda: _open_run_fd(self.run.project_dir, self.run.run_id),
            )
        for index, owner in enumerate(self.prefixes, 1):
            if owner.fd < 0:
                prefix = self.parent_components[:index]
                owner.allocate(
                    lambda prefix=prefix: privfs.open_strict_dir_at(
                        self.anchor.fd, prefix,
                    ),
                )

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
            self.child.allocate(
                lambda: os.open(self.name, _DIR_OPEN_FLAGS, dir_fd=self.parent.fd),
            )
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

    @classmethod
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
                self._open_anchor.allocate(
                    lambda: _open_run_fd(self._run.project_dir, self._run.run_id),
                )
                self._stage = privfs.create_private_stage(
                    self._open_anchor.fd, components,
                )
                self._writer_owner.expected_identity = self._stage.file_identity
                self._writer_owner.allocate(lambda: os.dup(self._stage.file_fd))
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

    def fence(self) -> None:
        """Settle an unpublished stage without creating an authoritative final."""
        if self._state in {"published", "fenced"}:
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
                    if self._stage is not None and self._stage.state not in {
                        "aborted", "committed", "fenced",
                    }:
                        privfs.abort_private_stage(self._stage)
                    if (self._stage is not None
                            and self._stage.state == "aborted"
                            and not self._discard_settled):
                        identity = self._stage.file_identity
                        components = self._stage.components
                        if self._cleanup_anchor.fd < 0:
                            self._cleanup_anchor.allocate(
                                lambda: _open_run_fd(
                                    self._run.project_dir, self._run.run_id,
                                ),
                            )
                        if self._cleanup_parent.fd < 0:
                            self._cleanup_parent.allocate(
                                lambda: privfs.open_strict_dir_at(
                                    self._cleanup_anchor.fd, components[:-1],
                                ),
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
            stage_terminal = (
                self._stage is None
                or self._stage.state in {"aborted", "committed", "fenced"}
            )
            discard_terminal = (
                self._stage is None
                or self._stage.state in {"committed", "fenced"}
                or self._discard_settled
            )
            if (self._writer_owner.fd < 0 and stage_terminal and discard_terminal
                    and self._open_anchor.fd < 0
                    and self._cleanup_parent.fd < 0
                    and self._cleanup_anchor.fd < 0):
                self._state = "fenced"
                break
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            try:
                preferred.close_errors = tuple(faults)
            except BaseException:
                pass
            raise preferred
        if self._state != "fenced":
            raise ContractError("artifact claim did not reach terminal fencing")

    def _settle(self) -> None:
        """Idempotently settle content ownership, then its durable marker."""
        if self._state not in {"published", "fenced"}:
            self.fence()
        if self._state in {"published", "fenced"}:
            with self._run._mutation(MutationScope.CONTROL):
                self._marker_release.settle()
        if not self._marker_release.released:
            raise ContractError("artifact claim marker remains live")


_RUN_CONSTRUCTION_AUTHORITY = object()
_TOOL_RUNS_UNLOADED = object()


class Run:
    """One reconnaissance run inside a project: owns its tree, manifest, and entity store.

    Lives at <project_dir>/recon/<run_id>/, so a run's output co-locates with the target.yaml profile
    the project dir was derived from.
    """

    def __init__(self, project_dir: Path, target: str, run_id: str | None = None, *, load_started: bool = False,
                 _identity: dict | None = None, _authority=None):
        if _authority is not _RUN_CONSTRUCTION_AUTHORITY:
            raise ContractError("construct runs through Run.create(), Run.open() or Run.latest()")
        self.project_dir = Path(project_dir)
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

    def _materialize_lock_file(self) -> int:
        """Open the sole out-of-band per-run advisory lock with private modes."""
        from . import privfs
        lock_dir = privfs.private_dir(self._lock_path.parent)
        directory_fd = os.open(
            lock_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            fd = os.open(
                self._lock_path.name,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                privfs.FILE_MODE,
                dir_fd=directory_fd,
            )
        finally:
            os.close(directory_fd)
        try:
            observed = os.fstat(fd)
            if (not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.geteuid()
                    or observed.st_nlink != 1):
                raise ContractError("repository lock identity is unsafe")
            if stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE:
                os.fchmod(fd, privfs.FILE_MODE)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextmanager
    def _mutation(self, scope: MutationScope):
        """Serialize one run mutation through the shared RLock and one flock."""
        if type(scope) is not MutationScope:
            raise TypeError("invalid repository mutation scope")
        key = self._authority_key
        lock = _shared_run_lock(key)
        with lock:
            held = getattr(_RUN_LOCK_LOCAL, "held", None)
            if held is None:
                held = {}
                _RUN_LOCK_LOCAL.held = held
            depth, fd = held.get(key, (0, -1))
            if depth == 0:
                fd = self._materialize_lock_file()
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except BaseException:
                    os.close(fd)
                    raise
            held[key] = (depth + 1, fd)
            try:
                self._require_scope(scope)
                yield
            finally:
                current_depth, current_fd = held[key]
                if current_depth == 1:
                    try:
                        fcntl.flock(current_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(current_fd)
                        del held[key]
                else:
                    held[key] = (current_depth - 1, current_fd)

    def _require_scope(self, scope: MutationScope) -> None:
        try:
            observed = os.stat(self.dir, follow_symlinks=False)
        except OSError:
            raise ContractError(f"run {self.run_id!r} directory identity is unavailable") from None
        if (not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or (observed.st_dev, observed.st_ino) != self._run_directory_identity):
            raise ContractError(f"run {self.run_id!r} directory identity changed")
        identity = read_run_identity(self.project_dir, self.run_id)
        if identity["target"] != self.target:
            raise ContractError(f"run {self.run_id!r} identity changed")
        state = self.state
        if state == "unknown":
            raise ContractError(f"run {self.run_id} has unknown lifecycle state")
        if scope is MutationScope.BASE_EVIDENCE and state not in {"created", "running"}:
            raise ContractError(
                f"base evidence is sealed for run {self.run_id} in state {state!r}",
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
        from . import privfs
        directory = privfs.private_dir(self._artifact_claim_dir)
        directory_fd = os.open(directory, _DIR_OPEN_FLAGS)
        name = f"{os.urandom(16).hex()}{_CLAIM_SUFFIX}"
        fd = -1
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                privfs.FILE_MODE,
                dir_fd=directory_fd,
            )
            os.fchmod(fd, privfs.FILE_MODE)
            body = json.dumps({
                "schema_version": 1,
                "run_id": self.run_id,
                "pid": os.getpid(),
            }, sort_keys=True).encode("utf-8")
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("artifact claim marker write made no progress")
                view = view[written:]
            os.fsync(fd)
            observed = os.fstat(fd)
            if (not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.geteuid()
                    or observed.st_nlink != 1
                    or stat.S_IMODE(observed.st_mode) != privfs.FILE_MODE):
                raise ContractError("artifact claim marker identity is unsafe")
            os.fsync(directory_fd)
            return name, (observed.st_dev, observed.st_ino)
        except BaseException:
            if fd >= 0:
                try:
                    os.unlink(name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                except OSError:
                    pass
            raise
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(directory_fd)

    def _release_artifact_claim_marker(
        self, name: str, expected_identity: tuple[int, int],
    ) -> None:
        """Idempotently release one exact marker and settle every owned fd."""
        release = _ArtifactMarkerRelease(self, name, expected_identity)
        faults = _replay_settlement(release.settle)
        preferred = _preferred_settlement_fault(None, faults)
        if preferred is not None:
            try:
                preferred.close_errors = tuple(faults)
            except BaseException:
                pass
            raise preferred
        if not release.released:
            raise ContractError("artifact claim marker release did not settle")

    def _live_artifact_claim_count(self) -> int:
        try:
            directory_fd = os.open(self._artifact_claim_dir, _DIR_OPEN_FLAGS)
        except FileNotFoundError:
            return 0
        try:
            count = 0
            for name in os.listdir(directory_fd):
                token = name[:-len(_CLAIM_SUFFIX)] if name.endswith(_CLAIM_SUFFIX) else ""
                if (len(token) != 32
                        or any(char not in "0123456789abcdef" for char in token)):
                    raise ContractError("artifact claim registry contains an unknown entry")
                fd = os.open(name, _FILE_OPEN_FLAGS, dir_fd=directory_fd)
                try:
                    observed = os.fstat(fd)
                    if (not stat.S_ISREG(observed.st_mode)
                            or observed.st_uid != os.geteuid()
                            or observed.st_nlink != 1):
                        raise ContractError("artifact claim registry contains an unsafe entry")
                finally:
                    os.close(fd)
                count += 1
            return count
        finally:
            os.close(directory_fd)

    def _ensure_artifact_parent(self, components: tuple[str, ...]) -> None:
        from . import privfs
        if len(components) > 1:
            privfs.private_dir(self.dir.joinpath(*components[:-1]))

    def _append_base_artifact(self, components: tuple[str, ...], data: bytes) -> None:
        """Durably append exact bytes through BASE_EVIDENCE authority."""
        components = _validated_artifact_components(components)
        if type(data) is not bytes:
            raise TypeError("artifact append data must be exact bytes")
        from . import privfs
        with self._mutation(MutationScope.BASE_EVIDENCE):
            self._ensure_artifact_parent(components)
            path = self.dir.joinpath(*components)
            fd = privfs.open_private(path, append=True)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("artifact append made no progress")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            parent_fd = os.open(path.parent, _DIR_OPEN_FLAGS)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)

    def _replace_artifact(
        self, scope: MutationScope, components: tuple[str, ...], data: bytes,
    ) -> Path:
        """Durably replace one scoped artifact through the strict stage primitive."""
        components = _validated_artifact_components(components)
        if type(data) is not bytes:
            raise TypeError("artifact replacement data must be exact bytes")
        from . import privfs
        stage = None
        with self._mutation(scope):
            self._ensure_artifact_parent(components)
            anchor_fd = _open_run_fd(self.project_dir, self.run_id)
            try:
                stage = privfs.stage_private_bytes(anchor_fd, components, data)
            finally:
                os.close(anchor_fd)
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
        fd = -1
        try:
            fd = os.open(name, _FILE_OPEN_FLAGS, dir_fd=parent_fd)
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
        finally:
            if fd >= 0:
                os.close(fd)

    def _fsync_base_directory_at(
        self, parent_fd: int, name: str, components: tuple[str, ...],
    ) -> None:
        fd = -1
        try:
            fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
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
        finally:
            if fd >= 0:
                os.close(fd)

    def _flush_base_evidence(self) -> None:
        """Flush every canonical base inode and its directory chain before sealing.

        The run authority is held by the caller.  Traversal is descriptor-relative,
        refuses links and non-private objects, and deliberately excludes lifecycle,
        manifest, report, export and revision objects.
        """
        run_fd = _open_run_fd(self.project_dir, self.run_id)
        try:
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
        finally:
            os.close(run_fd)

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
        if (claim._state not in {"published", "fenced"}
                or not claim._marker_release.released):
            raise ContractError("artifact claim did not reach terminal settlement")

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
        privfs.private_dir(project_dir / "recon")            # 0700 recon root before the run dir is claimed
        attempts = 1 if run_id is not None else 16
        for _ in range(attempts):
            rid = run_id if run_id is not None else cls._mint_run_id()
            try:
                os.mkdir(project_dir / "recon" / rid, privfs.DIR_MODE)   # claim atomically and 0700
            except FileExistsError:
                if run_id is not None:
                    raise
                continue
            run = cls(project_dir, target, run_id=rid, _authority=_RUN_CONSTRUCTION_AUTHORITY)
            run.write_state("created")
            return run
        raise RuntimeError("could not mint a unique run id after 16 attempts")

    @classmethod
    def open(cls, project_dir, target, run_id) -> "Run":
        """Attach to an existing reconciled run without modifying any repository object.

        A crashed run may have only ``run.json`` and a legacy run may have only ``manifest.json``.  A
        malformed regular secondary document is ignored for recovery, but every well-formed identity must
        agree with the directory and each other.  Symlinked/non-regular identity objects always fail closed.
        """
        target = validate_target(target)
        run_id = validate_run_id(run_id)              # refuse before joining/opening caller-controlled input
        identity = read_run_identity(Path(project_dir), run_id)
        if target != identity["target"]:
            raise ContractError(f"run {run_id!r} belongs to target {identity['target']!r}, not {target!r}")
        return cls(project_dir, identity["target"], run_id=run_id, load_started=True, _identity=identity,
                   _authority=_RUN_CONSTRUCTION_AUTHORITY)

    # ── raw evidence ──
    def raw_path(self, phase: str, tool: str, name: str) -> Path:
        with self._mutation(MutationScope.BASE_EVIDENCE):
            from . import privfs
            phase = validate_artifact_component(phase, "raw phase")
            tool = validate_artifact_component(tool, "raw tool")
            name = validate_artifact_component(name, "raw filename")
            p = self.raw / phase / tool
            privfs.private_dir(p)                            # raw evidence dirs are 0700
            return p / name

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
            base = self.dir.joinpath(*components)
            from . import privfs
            privfs.private_dir(base)
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
        try:
            observed = os.stat(self._tool_runs_path, follow_symlinks=False)
        except FileNotFoundError:
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
            legacy = _read_json(self.manifest_path)
            rows = legacy.get("tool_runs") if isinstance(legacy, dict) else None
            self._tool_runs = (
                [self._tool_run_from_dict(row) for row in rows]
                if isinstance(rows, list) else []
            )
            self._tool_runs_signature = None
            return
        records = []
        from . import privfs
        try:
            with os.fdopen(privfs.open_ro_private(self._tool_runs_path), "r", encoding="utf-8") as fh:
                for index, line in enumerate(fh, 1):
                    if not line.endswith("\n"):
                        raise ContractError(f"tool-run ledger row {index} is torn")
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ContractError(f"tool-run ledger row {index} is invalid JSON") from exc
                    records.append(self._tool_run_from_dict(value))
        except UnicodeError as exc:
            raise ContractError("tool-run ledger is not valid UTF-8") from exc
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
        return manifest_committed(self.manifest_path)

    def _read_state(self) -> dict:
        """The persisted finalisation record.

        An ABSENT file is a run written before this contract: a committed manifest means its finalisation
        finished, anything else is still `created`. A file that is PRESENT but unreadable is a different
        fact and fails closed as `unknown` — inferring `finished` from a manifest there would let a
        corrupt lifecycle record read as a completed one.
        """
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
        rec = self._read_state()
        src = rec["state"]
        if rec.get("unreadable"):
            raise ContractError(f"run {self.run_id} has an unreadable {self.state_path.name} — refusing to "
                                f"advance it to {dst!r}; inspect or remove the file deliberately")
        if src != dst and not run_transition_ok(src, dst):
            raise ContractError(f"illegal run-state transition {src!r} -> {dst!r}")
        rec.update({"schema_version": 1, "run_id": self.run_id, "state": dst,
                    "generation": self.generation(), "updated": _utc(), "detail": detail})
        _atomic_write(self.state_path, json.dumps(rec, indent=2))

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
            if not self._entity_file(entity).exists():
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
        if self.state != "finalizing":
            raise ContractError(
                f"run {self.run_id} must be in finalizing to record derived stage metadata",
            )
        rec = self._read_state()
        if rec.get("unreadable"):
            raise ContractError(f"run {self.run_id} has an unreadable {self.state_path.name} — refusing to "
                                f"record stage {stage!r} over it")
        rec.setdefault("stages", {})[stage] = {"generation": self.generation(), "status": status,
                                               "detail": detail, "updated": _utc()}
        rec["schema_version"], rec["run_id"] = 1, self.run_id
        _atomic_write(self.state_path, json.dumps(rec, indent=2))

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
        manifest = _read_json(self.manifest_path)
        # a damaged summary is not reconciled: filling in what it lacks would author the verdict rather
        # than bring one back in step with the stages
        if not isinstance(manifest, dict) or not summary_well_formed(manifest.get("summary")):
            return None
        if self.state != "finalizing":
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
        _atomic_write(self.manifest_path, json.dumps(manifest, indent=2))
        self._sealed_summary, self._verdict_sealed = summary, True
        return summary

    # ── normalized entities (JSONL, append, dedup on natural key) ──
    def _entity_file(self, entity: str) -> Path:
        return self.normalized / f"{validate_entity(entity)}.jsonl"

    def _entity_signature(self, entity: str) -> tuple | None:
        """Return a mutation-sensitive identity for one canonical entity log."""
        try:
            observed = os.stat(self._entity_file(entity), follow_symlinks=False)
        except FileNotFoundError:
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
            records[key] = record
            self._append_line(entity, line)
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
            records[key] = record
            self._append_line(entity, line)
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
        from . import privfs
        # 0600, O_NOFOLLOW append: the normalized log (incl. secret.jsonl) is never group/other-readable
        privfs.append_private(self._entity_file(entity), line + "\n")
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
            _atomic_write(self._degraded_path,
                          json.dumps({"degraded": dict(self._envelope_durability)}, indent=2))
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
        from . import privfs
        privfs.append_private(self._refused_path,
                              json.dumps({"entity": entity, "key": key, "kind": kind}, ensure_ascii=False) + "\n")

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

    def _ledger_distinct_by_kind(self) -> dict:
        """Exact distinct refused identities per (known entity, kind), folded from every refusal file via an
        on-disk sqlite dedup: memory is one insert batch and the group set is bounded to the entity enum, never
        a resident set of all identities. Fails CLOSED — a malformed, non-object, or out-of-vocabulary line is
        counted as damage and surfaced as a durable gap. No refusal files -> recover an old count-only marker."""
        import sqlite3
        import tempfile
        sources = [p for p in self._refusal_sources() if p.exists()]
        if not sources:
            return self._recover_marker_counts()
        fd, dbpath = tempfile.mkstemp(dir=self.dir, prefix=".envcount-", suffix=".db")
        os.close(fd)
        damaged = 0
        out: dict[str, dict[str, int]] = {}
        try:
            con = sqlite3.connect(dbpath)
            con.execute("PRAGMA journal_mode=OFF")
            con.execute("PRAGMA synchronous=OFF")
            con.execute("CREATE TABLE r(entity TEXT, key TEXT, kind TEXT, "
                        "PRIMARY KEY(entity, key)) WITHOUT ROWID")   # PK dedups; first kind wins
            for src in sources:
                batch: list = []
                try:
                    with open(src, "rb") as fh:
                        for line in _iter_ledger_lines(fh, _MAX_LEDGER_LINE):
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
            doc = json.loads(self._envelope_path.read_text())
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
            _atomic_write(self._envelope_path, json.dumps({**envelope.declaration(), "overflow": True}, indent=2))
        except OSError:
            pass

    def _persist_envelope_remainder(self) -> None:
        env = self.envelope_remainder()
        if env is not None:
            _atomic_write(self._envelope_path, json.dumps(env, indent=2))

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
        # only a log that exists on disk can fold-refuse; a live-only run never touches the fold ledger
        if not self._entity_file(entity).exists():
            self._folded[entity] = fold_observations(self._entity_file(entity))
            self._records[entity] = self._folded[entity].records
            return self._records[entity]
        fd = None
        if persist_refusals:
            privfs.private_dir(self._fold_refused_dir)
            refused_any = [False]
            try:
                fd = privfs.open_private(self._fold_refused_path(entity), append=False)   # truncate: idempotent
            except OSError as e:
                self._mark_durability_degraded(f"fold:{entity}",
                                               f"envelope fold-refusal file unwritable for {entity!r} "
                                               f"({type(e).__name__})")
                fd = None
        else:
            refused_any = [False]

        def _sink(k: str, kind: str) -> None:
            refused_any[0] = True
            if fd is None:
                return
            os.write(fd, (json.dumps({"entity": entity, "key": k, "kind": kind},
                                     ensure_ascii=False) + "\n").encode("utf-8"))

        try:
            folded = fold_observations(
                self._entity_file(entity), max_keys=self._envelope_cap(),
                max_bytes_per_key=envelope.MAX_BYTES_PER_KEY,
                max_corpus_bytes=envelope.MAX_CORPUS_BYTES_PER_ENTITY, on_refused=_sink)
        finally:
            if fd is not None:
                os.close(fd)
        if persist_refusals:
            if not refused_any[0]:                # nothing refused now: clear any stale file (e.g. a raised bound)
                try:
                    self._fold_refused_path(entity).unlink()
                except OSError:
                    pass
            elif not self._envelope_marked:
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
        state_now = self.state
        scope = (
            MutationScope.BASE_EVIDENCE
            if state_now in {"created", "running"}
            else MutationScope.FINALIZATION_METADATA
        )
        with self._mutation(scope):
            current = self.state
            if current == "finalizing":
                if os.path.lexists(self.manifest_path):
                    raise ContractError(
                        "the base manifest is already published; reconcile only derived-publication metadata",
                    )
            elif current not in {"created", "running"}:
                raise ContractError(
                    f"run {self.run_id} cannot publish a base manifest in state {current!r}",
                )
            _atomic_write(self.manifest_path, prepared.manifest_text)
            # update state pointers (per-project, under recon/)
            from . import privfs
            state = self.project_dir / "recon" / "state"
            privfs.private_dir(state / "history")                # 0700 state root
            _atomic_write(state / "history" / f"{self.run_id}.json", prepared.history_text)
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
        base_mutations = state_now in {"created", "running"}
        scope = MutationScope.BASE_EVIDENCE if base_mutations else MutationScope.FINALIZATION_METADATA
        with self._mutation(scope):
            prepared = self._prepare_manifest_locked(
                profile_summary, phases_run, metrics, policy,
                base_mutations=base_mutations,
            )
            self.publish_manifest(prepared)

    @staticmethod
    def list_runs(project_dir: Path) -> "list[Path]":
        """Reconciled real run directories, oldest→newest, without following or modifying repository data."""
        return [path for _started, _name, path, _identity in _run_snapshots(Path(project_dir))]

    @staticmethod
    def latest(project_dir: Path, target: str | None = None) -> "Run | None":
        if target is not None:
            target = validate_target(target)
        snapshots = _run_snapshots(Path(project_dir))
        if not snapshots:
            return None
        _started, run_id, _path, identity = snapshots[-1]
        if target is not None and identity["target"] != target:
            raise ContractError(f"latest run {run_id!r} belongs to target {identity['target']!r}, "
                                f"not {target!r}")
        return Run(project_dir, identity["target"], run_id=run_id, load_started=True, _identity=identity,
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
