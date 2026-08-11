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
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from pathlib import Path


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
    crash mid-write leaves the previous version intact. Created 0600, O_NOFOLLOW: sensitive from creation,
    never chmod-after-write."""
    from . import privfs
    privfs.write_private(path, text)


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
        from . import privfs
        for d in (self.raw, self.normalized, self.exports, self.reports):
            privfs.private_dir(d)                            # recon/ and the run tree are 0700
        self.manifest_path = self.dir / "manifest.json"
        self.meta_path = self.dir / "run.json"            # immutable creation record (started/run_id/target)
        self._tool_runs: list[ToolRunRecord] = []
        self._counts_cache: dict[str, int] = {}
        self._records: dict[str, dict] = {}       # entity -> {canonical_key: merged record} (instance-local)
        self._folded: dict[str, FoldedLog] = {}   # entity -> the same fold, with its trust status
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
            self.started = _read_started(self.meta_path) or _read_started(self.manifest_path) or _utc()
        else:
            self.started = _utc()
            if not self.meta_path.exists():
                _atomic_write(self.meta_path, json.dumps(
                    {"run_id": self.run_id, "target": target, "started": self.started}))
        self.notes: list[str] = []
        # a durability failure recorded in a prior session (ledger unwritable / damaged) must keep this reopen
        # gapped — load it so the run never re-finalises as clean/complete
        self._load_durability_marker()

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
        from . import privfs
        project_dir = Path(project_dir)
        privfs.private_dir(project_dir / "recon")            # 0700 recon root before the run dir is claimed
        for _ in range(16):
            rid = cls._mint_run_id()
            try:
                os.mkdir(project_dir / "recon" / rid, privfs.DIR_MODE)   # claim atomically and 0700
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
        from . import privfs
        p = self.raw / phase / tool
        privfs.private_dir(p)                                # raw evidence dirs are 0700
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
        return self._fold_refused_dir / f"{entity}.jsonl"

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
        """Lazily materialize {key: record} by folding the entity log under the full envelope. Reopen-fold
        refusals are REWRITTEN per entity (truncate-then-stream), so repeated reopens yield the same rows,
        never a growing pile, and the fold never holds the refused set resident."""
        if entity not in self._records:
            from . import envelope, privfs
            # only a log that exists on disk can fold-refuse; a live-only run never touches the fold ledger
            if not self._entity_file(entity).exists():
                self._folded[entity] = fold_observations(self._entity_file(entity))
                self._records[entity] = self._folded[entity].records
                return self._records[entity]
            privfs.private_dir(self._fold_refused_dir)
            refused_any = [False]
            try:
                fd = privfs.open_private(self._fold_refused_path(entity), append=False)   # truncate: idempotent
            except OSError as e:
                self._mark_durability_degraded(f"fold:{entity}",
                                               f"envelope fold-refusal file unwritable for {entity!r} "
                                               f"({type(e).__name__})")
                fd = None

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
            self._records_for(entity)          # the same capped, streaming, refused-aware fold
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
        # fold the refusal ledger first: a damaged/unwritable ledger surfaces a durable exception into notes,
        # which phase_exceptions (below) must see so an overflow with a broken ledger never reads as clean
        env_remainder = self.envelope_remainder()
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
                             "why": f"{n} identit(ies) refused past the corpus envelope", "output_lines": 0,
                             "omitted": n})

        # gaps dominate: a limit only lifts an otherwise-clean run to complete_with_limits
        limits = coverage_limits + provider_limits + operator_limits
        verdict = ("complete_with_gaps" if (failures or gaps or phase_exceptions)
                   else "complete_with_limits" if limits else "complete")
        return {"verdict": verdict, "tool_status": status_counts, "tools_failed": len(failures),
                "failures": failures, "gaps": gaps, "phase_exceptions": phase_exceptions,
                "coverage": coverage, "coverage_limits": coverage_limits,
                # what each lane still owes; absent means unknown, never zero
                "remainders": remainders,
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
        from . import envelope as _envelope
        manifest["envelope"] = _envelope.declaration()       # the corpus bound this run enforced
        env_remainder = self.envelope_remainder()
        if env_remainder is not None:                        # keys refused past the envelope, durably owed
            manifest["envelope_remainder"] = env_remainder
            self._persist_envelope_remainder()               # refresh the standalone durable file to the final count
        if self._envelope_durability:                        # durability failures the reopen must re-surface even
            manifest["envelope_degraded"] = dict(self._envelope_durability)   # if the separate marker was unwritable
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
        from . import privfs
        state = self.project_dir / "recon" / "state"
        privfs.private_dir(state / "history")                # 0700 state root
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
