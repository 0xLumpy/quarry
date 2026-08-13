"""Every source executes under its registry entry, and always leaves a terminal event.

    run_contract    a subprocess tool, via runner.run
    run_provider    an in-process HTTP provider
    run_providers   several provider lanes sharing one body

The registry is authoritative: an unregistered source is refused, not executed. Entity counts are not
emitted here — the phase reports what it stored, after it parses.

Provider outcome semantics: docs/design/PROVIDER-QUOTA-DESIGN.md.
"""
from __future__ import annotations

import hashlib as _hashlib
import json as _json
import os as _os
import re as _re
import shutil as _shutil
import socket as _socket
import sys as _sys
import threading as _threading
import urllib.error as _urlerr
from dataclasses import dataclass as _dataclass
from pathlib import Path as _Path

from . import events, normalize, sources
from .runner import Status, _preflight_argv, run as _run, skipped

# Non-clean terminal statuses that warrant a dedicated event before the normal tool_finish.
_PARTIAL = (Status.PARTIAL, Status.TIMED_OUT)


def _exact_counts(produced) -> dict:
    """`produced` as a validated `{entity: count}` map. Raises on anything that could lie."""
    if not isinstance(produced, dict):
        raise ValueError(f"produced must be a dict of counts, got {type(produced).__name__}")
    out: dict = {}
    for key, value in produced.items():
        if not isinstance(key, str) or not key:
            raise ValueError(f"produced key must be a non-empty entity name, got {key!r}")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"produced[{key!r}] must be an exact non-negative int, got {value!r}")
        out[key] = value
    return out


class ProviderResult(set):
    """A provider's hostname set plus how complete it is.

    `partial` means cut short, `cursor` where to continue. `produced` carries entity counts for a lane
    whose evidence is not hostnames. `limited` marks a deliberate bound and implies `partial`."""
    def __init__(self, iterable=(), *, partial=False, cursor=None, pages=None, error_class=None,
                 partial_kind=None, partial_reason=None, limited=False, produced=None):
        super().__init__(iterable)
        # `{}` produced nothing; None has no count to report
        self.produced = None if produced is None else _exact_counts(produced)
        self.partial = partial or limited
        self.cursor = cursor
        self.pages = pages
        self.error_class = error_class      # set when a LATER page failed (earlier pages preserved)
        # only "pagination" may report a pagination coverage gap
        self.partial_kind = partial_kind or ("degraded" if limited else "pagination")
        self.partial_reason = partial_reason
        self.limited = limited


# Provider outcome classes. Each implies a different operator action, so two must never collapse into
# one. 403 is `forbidden`, never `entitlement`; quota and entitlement are proven from a body or a
# balance endpoint, never from a status code. See docs/design/PROVIDER-QUOTA-DESIGN.md.
PROVIDER_AUTH = "auth"
PROVIDER_FORBIDDEN = "forbidden"
PROVIDER_ENTITLEMENT = "entitlement"
PROVIDER_RATE_LIMIT = "rate_limit"
PROVIDER_QUOTA = "quota"
PROVIDER_TRANSPORT = "transport"
PROVIDER_SERVER = "server"
PROVIDER_PARSE = "parse"
#: our read ceiling, not the provider's answer: `parse` points at their schema, `oversize` at ours
PROVIDER_OVERSIZE = "oversize"
#: our pacing refused to issue the request — a gap of ours, closable for free later
PROVIDER_PACE_BUSY = "pace_busy"
PROVIDER_HTTP = "http"
PROVIDER_ERROR = "error"

#: external limits, not defects: these feed `complete_with_limits`, never `complete_with_gaps`
PROVIDER_LIMITS = frozenset({PROVIDER_QUOTA, PROVIDER_ENTITLEMENT})
#: consumers check membership here rather than accepting any non-empty string
PROVIDER_CLASSES = frozenset({PROVIDER_AUTH, PROVIDER_FORBIDDEN, PROVIDER_ENTITLEMENT,
                              PROVIDER_RATE_LIMIT, PROVIDER_QUOTA, PROVIDER_TRANSPORT, PROVIDER_SERVER,
                              PROVIDER_PARSE, PROVIDER_OVERSIZE, PROVIDER_PACE_BUSY, PROVIDER_HTTP,
                              PROVIDER_ERROR})


def is_provider_limit(error_class) -> bool:
    """True when the class is an external provider LIMIT (quota/entitlement) rather than a failure."""
    return error_class in PROVIDER_LIMITS


_ERROR_BODY_LIMIT = 8192                                     # an error body is a sentence, not a payload


def capture_error_body(exc, *, provider: str = "", limit: int = _ERROR_BODY_LIMIT):
    """Read an HTTPError's body at the RAISE SITE and stamp the refined class on it.

    Must happen here: the body is a live socket and is gone once the exception has propagated.
    Best-effort — an unreadable body yields no signal, never an error."""
    if not isinstance(exc, _urlerr.HTTPError):
        return exc
    if getattr(exc, "body_text", None) is None:
        try:
            raw = exc.read(limit)
        except Exception:
            raw = b""
        # evidence needs the bytes: `body_text` is a lossy decode and cannot be re-encoded back
        try:
            exc.body_bytes = raw
        except Exception:
            pass
        finally:
            # a live stream: unclosed leaks a connection per failure. Stamped fields survive.
            try:
                exc.close()
            except Exception:
                pass
        # best-effort: `__slots__` rejects the stamp, and a raise-site helper must not raise
        try:
            exc.body_text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else ""
        except Exception:
            pass
    if provider and getattr(exc, "error_class", None) is None:
        try:
            exc.error_class = classify_provider_http(exc, provider=provider)
        except Exception:
            pass
    return exc


_DETAIL_CHARS = 160                                          # a terminal reason is a line, not a document


def error_detail(exc) -> "str | None":
    """A short, redacted summary of what the provider said, for the operator-visible reason.

    HTML is summarised by its <title>, where an interstitial states its business."""
    from . import secrets
    reason = error_body_reason(exc)
    text = getattr(exc, "body_text", None)
    if reason is None and isinstance(text, str) and text.strip():
        title = _re.search(r"<title[^>]*>(.*?)</title>", text, _re.I | _re.S)
        stripped = _re.sub(r"<[^>]+>", " ", title.group(1) if title else text)
        reason = _re.sub(r"\s+", " ", stripped).strip() or None
    if not reason:
        return None
    reason = secrets.redact(reason) or ""
    return (reason[:_DETAIL_CHARS] + "…") if len(reason) > _DETAIL_CHARS else reason


class IncompleteAcquisition(RuntimeError):
    """An acquired response that did not arrive whole; the partial is kept and nothing retries."""

    error_class = "incomplete"

    def __init__(self, message: str, *, bytes_written: int = 0, partial=None):
        super().__init__(message)
        self.bytes_written = bytes_written
        self.partial = partial


class AcquisitionTruncated(IncompleteAcquisition):
    """A stream stopped at our disk/byte policy — an incomplete acquisition whose cause is ours."""

    error_class = "truncated"

    def __init__(self, message: str, *, bytes_written: int = 0, partial=None, limit_kind: str = "",
                 limit_bytes: int = 0):
        super().__init__(message, bytes_written=bytes_written, partial=partial)
        self.limit_kind = limit_kind
        self.limit_bytes = limit_bytes


class AcquisitionBudgetExhausted(RuntimeError):
    """Our disk/byte governor refused to issue a request (decided before contact): nothing contacted,
    spent, or owned. Distinct from a provider limit and from pacing."""

    error_class = "disk_budget"

    def __init__(self, layer: str):
        super().__init__(f"acquisition budget exhausted at the {layer} policy")
        self.layer = layer


#: byte ceilings default off (0 = unbounded): a streamed body, paid or hostile, is kept whole and the
#: always-on host guard is the free-space reserve, not an arbitrary size cap.
_ACQUIRE_BYTES_MAX = 1 << 50                        # a sane parse ceiling for the knobs (1 PiB)
_FREE_RESERVE_DEFAULT = 1024 * 1024 * 1024          # keep at least 1 GiB free on the artifact filesystem

#: the layer that bound a truncation, so a raised bound is reproducible from the receipt
LAYER_RESPONSE, LAYER_RUN, LAYER_PROJECT, LAYER_RESERVE = (
    "response_bytes", "run_bytes", "project_bytes", "free_space_reserve")
#: which governor field holds each layer's configured bound
_LAYER_CAP_ATTR = {LAYER_RESPONSE: "response_max", LAYER_RUN: "run_max",
                   LAYER_PROJECT: "project_max", LAYER_RESERVE: "reserve_bytes"}


@_dataclass(frozen=True)
class Truncation:
    """A policy truncation as a typed remainder: which layer bound the stream and its bound in bytes."""

    kind: str
    limit: int

    def __post_init__(self):
        if self.kind not in _LAYER_CAP_ATTR:
            raise ValueError(f"unknown truncation layer {self.kind!r}")
        if isinstance(self.limit, bool) or not isinstance(self.limit, int) or self.limit < 0:
            raise ValueError(f"truncation limit must be a non-negative int, got {self.limit!r}")

    def as_receipt(self) -> dict:
        return {"kind": self.kind, "limit": self.limit}

    @classmethod
    def from_receipt(cls, doc) -> "Truncation":
        """Rebuild from a receipt's `truncation` field, rejecting any shape we did not write."""
        if not isinstance(doc, dict):
            raise ValueError(f"truncation must be an object, got {type(doc).__name__}")
        extra = set(doc) - {"kind", "limit"}
        if extra:
            raise ValueError(f"truncation carries unexpected field(s) {sorted(extra)}")
        return cls(doc.get("kind"), doc.get("limit"))


class _UnreadableProjectState(Exception):
    """The durable project counter is present but cannot be trusted; the caller must fail closed."""


def _load_project_bytes(path) -> int:
    """Best-effort durable total (missing/garbled → 0). Only for the in-memory mirror; the binding read
    is `_load_project_bytes_strict`, taken under the file lock."""
    try:
        return _load_project_bytes_strict(path)
    except _UnreadableProjectState:
        return 0


def _load_project_bytes_strict(path) -> int:
    """The durable project total. A missing file is 0 (a fresh project); a present but unreadable/garbled
    file raises so the caller refuses rather than resuming from a false zero."""
    p = _Path(path)
    try:
        raw = p.read_text()
    except FileNotFoundError:
        return 0
    except OSError as e:
        raise _UnreadableProjectState(f"project counter {p} unreadable: {e}") from e
    try:
        n = _json.loads(raw).get("bytes")
    except (ValueError, AttributeError) as e:
        raise _UnreadableProjectState(f"project counter {p} is not valid JSON: {e}") from e
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise _UnreadableProjectState(f"project counter {p} has a bad value {n!r}")
    return n


def _write_all_fd(fd, data: bytes) -> None:
    """Write every byte of `data` to `fd`; a partial `os.write` must not leave a truncated file."""
    view = memoryview(data)
    off = 0
    while off < len(view):
        n = _os.write(fd, view[off:])
        if n <= 0:
            raise OSError("short write left the counter file incomplete")
        off += n


def _store_project_bytes(path, total: int) -> None:
    p = _Path(path)
    tmp = p.with_name(p.name + ".tmp")
    # fsync the temp file then the parent dir, so a committed reservation survives a crash rather than
    # rolling back and reopening already-consumed capacity
    fd = _os.open(tmp, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
    try:
        _write_all_fd(fd, _json.dumps({"bytes": int(total)}).encode())
        _os.fsync(fd)
    finally:
        _os.close(fd)
    _os.replace(tmp, p)                             # atomic: a crash mid-write cannot tear the counter
    dfd = _os.open(p.parent, _os.O_RDONLY)
    try:
        _os.fsync(dfd)                              # make the rename itself durable
    finally:
        _os.close(dfd)


@_dataclass
class DiskGovernor:
    """Byte ceilings (response/run/project) + a free-space reserve (0 = layer off); persisted counters plus
    an `_inflight` reservation. Protocol: take → commit(persisted) → settle; project bytes lock a file."""

    response_max: int = 0
    run_max: int = 0
    project_max: int = 0
    reserve_bytes: int = _FREE_RESERVE_DEFAULT
    run_streamed: int = 0
    project_streamed: int = 0
    free_fn: object = None                          # injectable free-space probe; else shutil.disk_usage
    project_state: object = None                    # durable project-counter file (locked); None = in-memory only
    run_key: str = ""                               # identity of the run this governor scopes; a change rebuilds it

    def __post_init__(self):
        self._lock = _threading.RLock()             # serializes admit/take/commit/settle across threads
        self._inflight = 0                          # bytes granted this instant but not yet on disk
        if self.project_state is not None:
            self.project_streamed = _load_project_bytes(self.project_state)

    def _free(self, path):
        # a failed probe is unknown free space, treated as tripped by the caller (fail closed)
        if self.free_fn is not None:
            return self.free_fn(path)
        try:
            return _shutil.disk_usage(path).free
        except OSError:
            return None

    def _lockpath(self):
        s = _Path(self.project_state)
        return s.with_name(s.name + ".lock")

    def _inmem_room(self, path, written: int) -> "tuple[int | None, str | None]":
        """(room, binding layer) from the in-memory layers (response/run/reserve, and project when it has
        no durable file), charging persisted + in-flight. Caller holds `_lock`."""
        caps = []
        if self.response_max:
            caps.append((self.response_max - written, LAYER_RESPONSE))
        if self.run_max:
            caps.append((self.run_max - self.run_streamed - self._inflight, LAYER_RUN))
        if self.project_max and self.project_state is None:
            caps.append((self.project_max - self.project_streamed - self._inflight, LAYER_PROJECT))
        if self.reserve_bytes:
            free = self._free(path)
            # fail closed: uninspectable free space trips the reserve; in-flight grants are subtracted so
            # two concurrent streams cannot both spend the same free space
            caps.append((0 if free is None else free - self.reserve_bytes - self._inflight, LAYER_RESERVE))
        if not caps:
            return None, None
        room, layer = min(caps, key=lambda c: c[0])
        return max(0, room), layer

    def _reserve_project(self, want: int) -> "int | None":
        """Reserve up to `want` durable project bytes under the file lock (read-modify-write). Granted
        bytes, or None to fail closed when the counter is unreadable, the lock is held, or the write fails."""
        from . import budget
        try:
            with budget.state_lock(self._lockpath()):
                current = _load_project_bytes_strict(self.project_state)
                take = max(0, min(want, self.project_max - current))
                _store_project_bytes(self.project_state, current + take)
                self.project_streamed = current + take
                return take
        except (budget.StateBusy, _UnreadableProjectState, OSError):
            return None

    def _refund_project(self, amount: int) -> None:
        """Return `amount` over-reserved durable project bytes (a short/failed write). A refund we cannot
        persist over-counts usage — the fail-closed direction — so it is not surfaced as an error."""
        from . import budget
        try:
            with budget.state_lock(self._lockpath()):
                current = _load_project_bytes_strict(self.project_state)
                total = max(0, current - amount)
                _store_project_bytes(self.project_state, total)
                self.project_streamed = total
        except (budget.StateBusy, _UnreadableProjectState, OSError):
            pass

    def admit(self, path) -> "str | None":
        """Pre-contact gate: the binding layer name when there is NO budget to begin, else None. An
        unreadable/held durable project counter fails closed (refuses)."""
        with self._lock:
            room, layer = self._inmem_room(path, 0)
            if room is not None and room <= 0:
                return layer
            if self.project_max and self.project_state is not None:
                from . import budget
                try:
                    with budget.state_lock(self._lockpath()):
                        current = _load_project_bytes_strict(self.project_state)
                except (budget.StateBusy, _UnreadableProjectState, OSError):
                    return LAYER_PROJECT
                if self.project_max - current <= 0:
                    return LAYER_PROJECT
        return None

    def take(self, path, written: int, want: int) -> "tuple[int, str | None]":
        """Grant up to `want` bytes for a response `written` bytes in, reserving them so a concurrent
        stream sees the reservation. `commit` later charges what actually reaches disk."""
        with self._lock:
            room, layer = self._inmem_room(path, written)
            granted = want if room is None else max(0, min(want, room))
            binding = layer if (room is not None and granted < want) else None
            if self.project_max and self.project_state is not None:
                pg = self._reserve_project(granted)
                if pg is None:
                    return 0, LAYER_PROJECT          # durable project state unreadable/held: refuse
                if pg < granted:
                    granted, binding = pg, LAYER_PROJECT
            self._inflight += granted
            return granted, binding

    def commit(self, n: int) -> None:
        """`n` reserved bytes reached disk: move them from in-flight to the persisted run/project totals."""
        with self._lock:
            self._inflight -= n
            self.run_streamed += n
            if self.project_max and self.project_state is None:
                self.project_streamed += n

    def settle(self, granted_total: int, written: int) -> None:
        """Close a response: release the reserved bytes that never reached disk (a truncation stop or a
        failed write), so counters charge persisted bytes, not granted ones."""
        leftover = granted_total - written
        if leftover <= 0:
            return
        with self._lock:
            self._inflight -= leftover
        if self.project_max and self.project_state is not None:
            self._refund_project(leftover)


def _governor_ceiling(key: str, value: int, source, rejected, rejected_source) -> int:
    """Fail-closed: a value the operator set but the parser refused is rejected, never silently replaced
    by the unbounded default."""
    if rejected is not None:
        raise ValueError(f"{key}={rejected} is not a usable byte ceiling (from {rejected_source}); "
                         f"refusing to run with an unbounded default in its place")
    return value


def _current_scope() -> "tuple[str, object]":
    """(run_key, project_state_path) from the configured event sink: `<project>/recon/<run>/events.jsonl`
    → run identity is the run dir, the project counter lives at `<project>/recon/state/`. Unconfigured
    (tests, no run) yields no scope, so the governor is in-memory only."""
    from . import events
    sink = getattr(events, "_sink", None)
    if sink is None:
        return "", None
    run_dir = _Path(sink).parent
    return str(run_dir), run_dir.parent / "state" / "acquire-project-bytes.json"


def _build_governor(*, run_key: str = "", project_state=None) -> DiskGovernor:
    from . import settings
    m = _ACQUIRE_BYTES_MAX
    return DiskGovernor(
        response_max=_governor_ceiling("ACQUIRE_RESPONSE_MAX_BYTES",
            *settings.strict_int_with_source("ACQUIRE_RESPONSE_MAX_BYTES", default=0, maximum=m)),
        run_max=_governor_ceiling("ACQUIRE_RUN_MAX_BYTES",
            *settings.strict_int_with_source("ACQUIRE_RUN_MAX_BYTES", default=0, maximum=m)),
        project_max=_governor_ceiling("ACQUIRE_PROJECT_MAX_BYTES",
            *settings.strict_int_with_source("ACQUIRE_PROJECT_MAX_BYTES", default=0, maximum=m)),
        reserve_bytes=_governor_ceiling("ACQUIRE_FREE_RESERVE_BYTES",
            *settings.strict_int_with_source("ACQUIRE_FREE_RESERVE_BYTES",
                                             default=_FREE_RESERVE_DEFAULT, maximum=m)),
        run_key=run_key, project_state=project_state)


_shared_governor: "DiskGovernor | None" = None
_shared_governor_lock = _threading.Lock()           # so concurrent first callers share ONE governor


def default_governor() -> DiskGovernor:
    """The process-shared governor: run bytes reset per run (rebuilt on run change), project bytes durable
    across runs; ceilings off unless configured, reserve always on. Raises on a malformed ceiling."""
    global _shared_governor
    run_key, project_state = _current_scope()
    with _shared_governor_lock:
        if _shared_governor is None or _shared_governor.run_key != run_key:
            _shared_governor = _build_governor(run_key=run_key, project_state=project_state)
        return _shared_governor


def reset_shared_governor() -> None:
    """Drop the process-shared governor so the next acquisition rebuilds it from current settings/scope."""
    global _shared_governor
    with _shared_governor_lock:
        _shared_governor = None


def _ondisk_size(fh) -> "int | None":
    """The file's real on-disk size, or None if it cannot be stat'd."""
    try:
        return _os.fstat(fh.fileno()).st_size
    except OSError:
        return None


def _path_size(path) -> int:
    """The file's size on disk, or 0 when it is absent/unstattable."""
    try:
        return _os.stat(path).st_size
    except OSError:
        return 0


def _open_part_wb(part):
    """Open the staging `.part` write-only, no-follow so a planted `<dest>.part` symlink cannot truncate or
    publish an external target; a leftover regular file is truncated and reused."""
    fd = _os.open(part, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC | _os.O_NOFOLLOW, 0o600)
    return _os.fdopen(fd, "wb")


def _fsync_quiet(fh) -> None:
    # a sync failure must not mask the cause we are already raising
    try:
        _os.fsync(fh.fileno())
    except OSError:
        pass


def stream_to_file(r, dest, *, chunk: int = 1024 * 1024, deadline_s: float = 300.0,
                   governor: "DiskGovernor | None" = None) -> "tuple[int, str]":
    """Stream a response to `dest` atomically -> (bytes, sha256), bounded by `governor` (bytes/free-space/
    time); a policy stop raises AcquisitionTruncated, a broken transport raises IncompleteAcquisition."""
    import time as _time
    gov = governor if governor is not None else default_governor()
    dest = _Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    digest = _hashlib.sha256()
    written = 0
    granted_total = 0
    opened = False                                      # only a `.part` this call opened may be measured/charged
    end = _time.monotonic() + deadline_s if deadline_s and deadline_s > 0 else None
    try:
        with _open_part_wb(part) as fh:                 # O_NOFOLLOW: a symlinked/failed open never gets here
            opened = True
            while True:
                if end is not None and _time.monotonic() > end:
                    raise TimeoutError(f"still receiving after {deadline_s:g}s")
                buf = r.read(chunk)
                if not buf:
                    break
                # take reserves; commit charges only the bytes measured on disk. A short landing or a short
                # grant is the policy boundary
                granted, layer = gov.take(dest.parent, written, len(buf))
                granted_total += granted
                write_error = None
                if granted:
                    try:
                        fh.write(buf[:granted]); fh.flush()
                    except (KeyboardInterrupt, SystemExit):
                        raise
                    except Exception as we:
                        write_error = we             # bytes may have partly landed: charge them below, then raise
                    # charge exactly what reached disk (measured), whether the write/flush succeeded or failed,
                    # so a flush failure never refunds bytes retained on disk
                    size = _ondisk_size(fh)
                    landed = min(max(0, size - written), granted) if size is not None else 0
                    if landed:
                        digest.update(buf[:landed]); written += landed; gov.commit(landed)
                else:
                    landed = 0
                if write_error is not None:
                    _fsync_quiet(fh)
                    raise IncompleteAcquisition(
                        f"write failed after {written} byte(s) reached disk: {write_error}",
                        bytes_written=written, partial=part) from write_error
                if landed < granted:
                    # fewer bytes reached disk than we handed the sink: what is on disk is all there is
                    _fsync_quiet(fh)
                    raise IncompleteAcquisition(
                        f"short write: {landed} of {granted} granted byte(s) reached disk after {written} total",
                        bytes_written=written, partial=part)
                if granted < len(buf):
                    _fsync_quiet(fh)
                    raise AcquisitionTruncated(
                        f"acquisition stopped at the {layer} policy after {written} byte(s)",
                        bytes_written=written, partial=part, limit_kind=layer,
                        limit_bytes=getattr(gov, _LAYER_CAP_ATTR[layer], 0))
            fh.flush()
            _os.fsync(fh.fileno())
    except (KeyboardInterrupt, SystemExit):
        raise
    except IncompleteAcquisition:
        raise                                           # our own truncation/short-write already carries partial+cause
    except Exception as e:
        # the partial file stays: a request that half-arrived is evidence of what we got
        raise IncompleteAcquisition(f"response incomplete after {written} byte(s): {e}",
                                    bytes_written=written, partial=part) from e
    finally:
        # only a `.part` this call opened; post-close: charge the close-flush delta, release the rest, and
        # sync the in-flight exception's count to what was charged
        if opened:
            extra = _path_size(part) - written
            if extra > 0:
                gov.commit(extra); written += extra
            gov.settle(granted_total, written)
            exc = _sys.exc_info()[1]
            if isinstance(exc, IncompleteAcquisition):
                exc.bytes_written = written
    # publish is part of the acquisition: a failed replace leaves the body in `.part`, so raise a typed
    # incomplete carrying its path + count (probe/fetch recompute the digest) rather than a bare OSError
    try:
        _os.replace(part, dest)
    except OSError as e:
        raise IncompleteAcquisition(f"acquired {written} byte(s) but publication failed: {e}",
                                    bytes_written=written, partial=part) from e
    return written, digest.hexdigest()


class ResponseTooLarge(ValueError):
    """A response longer than the caller's read bound. Its class is OURS, never the provider's."""

    error_class = PROVIDER_OVERSIZE


def read_bounded(r, limit: int, *, provider: str = "", bound: str = "") -> bytes:
    """Read a response, raising ResponseTooLarge when it exceeds `limit`.

    Reads one byte past the limit, because reading exactly `limit` cannot tell a response that fits
    from one that was cut. The bytes read travel on the exception; `bound` names the constant."""
    raw = r.read(limit + 1)
    if len(raw) > limit:
        size = (f"{limit // (1024 * 1024)} MiB" if limit >= 1024 * 1024 else
                f"{limit // 1024} KiB" if limit >= 1024 else f"{limit} bytes")
        e = ResponseTooLarge(
            f"{provider + ': ' if provider else ''}response exceeds our {size} read cap"
            f"{f' ({bound})' if bound else ''} — the body was NOT parsed and nothing was dropped "
            f"silently")
        try:
            e.body_bytes = bytes(raw)
        except Exception:
            pass
        raise e
    return raw


def error_body_reason(exc) -> "str | None":
    """The provider's reason string from a JSON error body, or None for any other shape.

    A non-JSON body carries no signal; calling it `parse` would report a bad key as schema drift."""
    text = getattr(exc, "body_text", None)
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        doc = _json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict):
        return None
    err = doc.get("error")
    return err.strip() if isinstance(err, str) and err.strip() else None


def classify_provider_http(exc, *, provider: str) -> str:
    """Classify an HTTP error, letting the provider's own body refine the status code.

    An unrecognised reason falls back to the status class, never to a limit."""
    cls = classify_provider_error(exc)
    reason = error_body_reason(exc)
    if reason is None:
        return cls
    refined = classify_provider_reason(provider, reason)
    return refined if refined != PROVIDER_ERROR else cls


def provider_error_class(exc) -> str:
    """THE accessor for a provider error's class: one PROVEN at the raise site wins over the generic
    exception-type mapping, which cannot see a body."""
    return getattr(exc, "error_class", None) or classify_provider_error(exc)


def classify_provider_error(exc) -> str:
    """Map a provider exception to an error class.

    Never returns `quota` or `entitlement`: a limit is proven from a body or balance endpoint."""
    if isinstance(exc, _urlerr.HTTPError):
        code = getattr(exc, "code", None)
        if code == 401:
            return PROVIDER_AUTH                             # bad/missing key — do not retry
        if code == 403:
            return PROVIDER_FORBIDDEN                        # reason unknown — NOT assumed to be the plan
        if code == 429:
            return PROVIDER_RATE_LIMIT                       # too fast now — back off; credits untouched
        if code is not None and 500 <= code < 600:
            return PROVIDER_SERVER                           # upstream 5xx — transient, retryable
        return PROVIDER_HTTP                                 # other 4xx
    if isinstance(exc, (_urlerr.URLError, _socket.timeout, TimeoutError, ConnectionError, OSError)):
        return PROVIDER_TRANSPORT                            # DNS/connect/timeout — retryable
    if isinstance(exc, (_json.JSONDecodeError, ValueError)):
        return PROVIDER_PARSE                                # malformed/schema-drift body
    return PROVIDER_ERROR                                    # unclassified


class ProviderBodyError(Exception):
    """A provider reported failure inside a successful HTTP response.

    Carries the class and the provider's VERBATIM reason, so an unrecognised one reaches the operator."""

    def __init__(self, error_class: str, reason: str, provider: str = ""):
        super().__init__(f"{provider or 'provider'}: {reason}" if reason else (provider or "provider error"))
        self.error_class = error_class
        self.reason = reason
        self.provider = provider


#: Measured reasons that PROVE exhausted credits. Allow-list only, and matched EXACTLY after case and
#: whitespace normalisation — a substring test cannot tell a message from its own negation
#: ("Non-zero Account Balance"). An unrecognised reason stays a generic error.
_QUOTA_REASONS = {
    "whoxy": frozenset({"zero account balance"}),            # both measured; Shodan returns 401 for a spent balance AND for a bad key, so the body decides
    "shodan": frozenset({"insufficient query credits, please upgrade your api plan or wait for the "
                         "monthly limit to reset"}),
}


#: measured words for "I have no data", which is coverage, not failure. Exact match, as above.
_EMPTY_REASONS = {
    # without this, "not in Shodan" — the ordinary case for most IPs — reports as a lane failure
    "shodan": frozenset({"no information available for that ip."}),
}


def _norm_reason(reason: str) -> str:
    return " ".join((reason or "").split()).strip().lower()


def is_measured_empty(provider: str, reason: str) -> bool:
    """True when the provider said it has no data, in words we have measured.

    Any other body under the same status stays a failure."""
    return _norm_reason(reason) in _EMPTY_REASONS.get(provider, frozenset())


def classify_provider_reason(provider: str, reason: str) -> str:
    """Map a provider's own failure reason to a taxonomy class. Only the measured exhaustion strings become
    PROVIDER_QUOTA; everything else is PROVIDER_ERROR with the reason preserved verbatim.
    """
    if _norm_reason(reason) in _QUOTA_REASONS.get(provider, frozenset()):
        return PROVIDER_QUOTA
    return PROVIDER_ERROR


def whoxy_envelope(doc, *, provider: str = "whoxy"):
    """Validate Whoxy's status envelope, raising ProviderBodyError on a reported failure.

    `status` is the authority, not the presence of a results key, and success must be an exact int 1
    with the documented result shape."""
    if not isinstance(doc, dict):
        raise ProviderBodyError(PROVIDER_PARSE, "response was not a JSON object", provider)
    status = doc.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        raise ProviderBodyError(PROVIDER_PARSE, f"non-integer status {status!r}", provider)
    if status != 1:
        reason = doc.get("status_reason")
        reason = reason.strip() if isinstance(reason, str) and reason.strip() else f"status={status!r}"
        raise ProviderBodyError(classify_provider_reason(provider, reason), reason, provider)
    return doc


#: keeps the conversion inside CPython's int-from-string limit, so the result never depends on how the
#: interpreter is configured
_WHOXY_TOTAL_MAX_DIGITS = 15


def whoxy_total(value):
    """Whoxy's `total_results` as an exact non-negative int, or None when unusable.

    The type varies by value: `0` is an int, a non-empty total is a string. Only a canonical ASCII
    decimal is accepted, and `"0"` is not — an unmeasured shape must not take the empty path."""
    if isinstance(value, bool):
        return None                                  # bool is an int subclass; `True` is not a count
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str) or not value:
        return None
    if any(c not in "0123456789" for c in value):     # no sign, space, separator or Unicode digit
        return None
    if value[0] == "0":                               # "0" is the canonical int form; "007" is drift
        return None
    if len(value) > _WHOXY_TOTAL_MAX_DIGITS:
        return None
    return int(value)


def whoxy_reverse_rows(doc, *, provider: str = "whoxy") -> list:
    """A validated reverse-whois result list -> [domain, ...].

    Fails closed: a success body with no results key is drift, not an empty answer. Cardinality is
    checked against `total_results`, since a short page is paginated."""
    rows = doc.get("search_result")
    if rows is None and isinstance(doc.get("domainsList"), list):
        rows = [{"domain_name": d} for d in doc["domainsList"]]   # documented alternate shape
    if not isinstance(rows, list):
        raise ProviderBodyError(PROVIDER_PARSE, "success body has no search_result list", provider)
    out = []
    for row in rows:
        if not isinstance(row, dict):
            raise ProviderBodyError(PROVIDER_PARSE, f"non-object result row ({type(row).__name__})", provider)
        name = row.get("domain_name")
        # a path- or URL-shaped name would become an apex CANDIDATE, so use the strict canonicaliser
        canon = normalize.canon_host_strict(name) if isinstance(name, str) else None
        if not canon or "." not in canon:
            raise ProviderBodyError(PROVIDER_PARSE, f"result row has no usable domain_name ({name!r})",
                                    provider)
        out.append(canon)
    return out


def whoxy_reverse_page(doc, *, param: str, value: str, provider: str = "whoxy",
                       page: int = 1) -> tuple:
    """-> (rows, total_results, truncated). `truncated` means more matches than this page holds.

    `param`/`value` and `page` bind the response to the request we made, and are required: a
    zero-result body has nothing else identifying it, and an unchecked position accepts page 2 for a
    page-1 request."""
    if doc.get("api_query") != "reverse_whois":
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"not a reverse_whois answer (api_query={doc.get('api_query')!r})",
                                provider)
    if param not in ("company", "email") or not isinstance(value, str) or not value.strip():
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"a reverse-whois response cannot be bound to a request "
                                f"(param={param!r} value={value!r})", provider)
    ident = doc.get("search_identifier")
    if ident != {param: value}:
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"response identifies {ident!r}, not exactly the {param}={value!r} "
                                f"we asked", provider)
    raw_total = doc.get("total_results")
    total = whoxy_total(raw_total)
    # EXACTLY TWO empty shapes are accepted, and nothing between them: anything wider lets a body we
    # have never measured take the clean-empty path.
    if total == 0:
        sr, dl = doc.get("search_result"), doc.get("domainsList")
        cur, pages = doc.get("current_page"), doc.get("total_pages")
        # a zero count with actual rows is contradictory in EITHER supported carrier
        for name, v in (("search_result", sr), ("domainsList", dl)):
            if v is not None and (not isinstance(v, list) or v):
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"total_results is 0 but {name} carries rows", provider)
        # membership, not `.get()`: a present-but-null key is a malformed presence, not an absence
        has_carrier = "search_result" in doc or "domainsList" in doc
        has_paging = "current_page" in doc or "total_pages" in doc
        if not has_carrier and not has_paging:
            # SHAPE A — the compact empty. It carries no page identity, so it can only answer page 1;
            # accepting it later would complete a page we never received.
            if isinstance(page, bool) or not isinstance(page, int) or page != 1:
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"compact zero-result body carries no page identity and cannot "
                                        f"answer page {page!r}", provider)
            return [], 0, False
        if has_carrier and "current_page" in doc and "total_pages" in doc:
            # shape B — a strict paged empty: an empty collection plus both pagination fields, valid.
            # the carrier must be a real (empty) list — a null one is malformed, not empty.
            if not (isinstance(sr, list) or isinstance(dl, list)):
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"zero-result carrier is not a list "
                                        f"(search_result={sr!r} domainsList={dl!r})", provider)
            for label, v in (("current_page", cur), ("total_pages", pages)):
                if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                    raise ProviderBodyError(PROVIDER_PARSE, f"invalid {label} ({v!r})", provider)
            if pages > 1:
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"total_results is 0 but total_pages is {pages}", provider)
            if cur != page:
                raise ProviderBodyError(PROVIDER_PARSE,
                                        f"response is page {cur}, but page {page} was requested", provider)
            return [], 0, False
        # an unrecognised shape fails closed rather than guessing which half to trust
        raise ProviderBodyError(PROVIDER_PARSE,
                                "zero-result body is neither the compact empty shape nor a fully paged "
                                f"empty (search_result={sr!r} domainsList={dl!r} "
                                f"current_page={cur!r} total_pages={pages!r})", provider)
    rows = whoxy_reverse_rows(doc, provider=provider)
    # an absent or garbled cardinality is drift, not "no claim to check" — fail closed
    if total is None:
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"success body has no usable total_results ({raw_total!r})", provider)
    if total < len(rows):
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"total_results {total} is smaller than the {len(rows)} rows returned",
                                provider)
    # the documented schema carries the page position — both fields, always.
    cur, pages = doc.get("current_page"), doc.get("total_pages")
    for label, v in (("current_page", cur), ("total_pages", pages)):
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ProviderBodyError(PROVIDER_PARSE, f"missing/invalid {label} ({v!r})", provider)
    if cur > pages:
        raise ProviderBodyError(PROVIDER_PARSE, f"current_page {cur} exceeds total_pages {pages}", provider)
    if cur != page:
        raise ProviderBodyError(PROVIDER_PARSE,
                                f"response is page {cur}, but page {page} was requested", provider)
    truncated = total > len(rows) or pages > 1
    return rows, total, truncated


def _emit_terminal(source_id, src, res, *, work_unit, parent_id, scope_distance, discovery_context):
    """Emit the source's terminal event. Called from a finally, so a raise still terminates
    the lane (res None -> synthetic FAILED)."""
    if res is None:
        events.tool_finish(source_id, status=Status.FAILED.value, reason="execution raised before a result",
                           work_unit=work_unit, parent_id=parent_id, scope_distance=scope_distance,
                           discovery_context=discovery_context)
        return
    raw_ref = str(res.raw_path) if res.raw_path else None
    # runs in the finally that guarantees a terminal: a throw here would defeat it
    artifact_size = None
    if res.raw_path:
        try:
            artifact_size = res.raw_path.stat().st_size
        except OSError:
            artifact_size = None
    meta = res.meta or {}
    partial_ref = meta.get("partial_path")                 # retained unpublished STDOUT, owned durably here
    stderr_partial_ref = meta.get("stderr_partial_path")   # retained unpublished stderr (its own field)
    faults = meta.get("faults") or None                    # typed machinery/publication faults, persisted here
    if res.status == Status.BLOCKED:
        events.tool_blocked(source_id, reason=res.note or "blocked")
    elif res.status in _PARTIAL:
        events.coverage_partial(source_id, reason=res.note or res.status.value)
    events.tool_finish(source_id, status=res.status.value, reason=res.note or None,
                       duration=round(res.duration, 2), exit_code=res.exit_code, work_unit=work_unit,
                       rss=res.peak_rss_mb, cpu_s=res.cpu_s,
                       raw_ref=raw_ref, artifact_size=artifact_size, partial_ref=partial_ref,
                       stderr_partial_ref=stderr_partial_ref, faults=faults,
                       fallback=src.get("fallback"),
                       parent_id=parent_id, scope_distance=scope_distance,
                       discovery_context=discovery_context)


def run_provider(source_id, fn, *, work_unit=None, input_total=None):
    """Contract bracket for an in-process provider -> fn()'s result, or None on failure.

    The provider must not swallow its own errors: a failure recorded as a clean EMPTY would let resume
    treat it as done. A FAILED terminal carries an `error_class`."""
    if not _provider_start(source_id, work_unit=work_unit, input_total=input_total):
        return None
    return _provider_terminal(source_id, fn, work_unit=work_unit)


class ProviderSkip(Exception):
    """A lane that did not run and did not fail. Still needs a lifecycle, or the previous
    run's terminal stands as current."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _partial_status(error_class, limited: bool) -> str:
    """The one precedence for an incomplete provider result. Gaps dominate limits.

      1. a non-limit error_class            -> PARTIAL
      2. a proven limit or operator bound   -> LIMITED
      3. otherwise                          -> PARTIAL"""
    if error_class and not is_provider_limit(error_class):
        return Status.PARTIAL.value
    if is_provider_limit(error_class) or limited:
        return Status.LIMITED.value
    return Status.PARTIAL.value


def terminal_is_limit(status, error_class) -> bool:
    """Whether a provider terminal is a soft limit rather than a gap.

    Fail closed: the status decides and the class may only disqualify, because either signal alone can
    launder a failure into `complete_with_limits`."""
    if status != Status.LIMITED.value:
        return False
    return not error_class or is_provider_limit(error_class)


def _partial_coverage_kind(error_class, limited: bool) -> str:
    """Whose boundary truncated a paginating provider.

    Read from the class and the operator bound, never the status — that would blame every limit on the
    provider."""
    if error_class and not is_provider_limit(error_class):
        return events.COVERAGE_TIMEOUT               # a later page was LOST — the target's cost
    if is_provider_limit(error_class):
        return events.COVERAGE_PROVIDER              # a PROVEN provider limit (credits/plan)
    if limited:
        return events.COVERAGE_SAMPLE                # an OPERATOR policy — deliberately bounded
    return events.COVERAGE_CAP                       # OUR configured ceiling truncated it


def _provider_start(source_id, *, work_unit=None, input_total=None) -> bool:
    """Open a provider lane: registry check, generation reset, tool_start. False = not in the registry."""
    if sources.get(source_id) is None:
        events.tool_blocked(source_id, reason=f"unknown source_id {source_id!r} — not in registry; not executed")
        return False
    if not acquisition_open(source_id, announce=False):
        # a refused lane still needs a lifecycle: a missing lane reads as "nobody ran it"
        from . import campaign as _campaign
        why = _campaign.acquisition_allowed(source_id)[1]
        events.tool_blocked(source_id, reason=why)
        reset = events.mark_provider_generation(source_id)
        events.tool_start(source_id, input_total=input_total, work_unit=work_unit, provider=True,
                          reset_generation=reset)
        # the coverage generation moves with it, or the lane reports both "skipped" and "omitted"
        events.coverage_reset(source_id)
        events.tool_finish(source_id, status=Status.SKIPPED.value, reason=why, work_unit=work_unit,
                           provider=True)
        return False
    # stamped on the START, which persists first: a crash still supersedes the prior generation
    reset_gen = events.mark_provider_generation(source_id)   # first terminal per source per session
    events.tool_start(source_id, input_total=input_total, work_unit=work_unit,
                      provider=True, reset_generation=reset_gen)
    if reset_gen:
        # opened together, or last session's counter still stands when this run emits none
        events.coverage_reset(source_id)
    return True


def run_providers(entries, shared):
    """Bracket several provider lanes around one shared body -> {source_id: result or None}.

    Every lane starts before the body runs: the body spends, so an interruption must leave a lifecycle
    behind. A raise from `shared` fails every started lane."""
    live = [(sid, wu, fin) for sid, wu, fin in entries
            if _provider_start(sid, work_unit=wu)]
    if not live:
        # the body SPENDS: running it for no lane buys pages nobody will report
        return {}
    cancel = failed = None
    try:
        shared()
    except (KeyboardInterrupt, SystemExit) as e:
        cancel = e
    except Exception as e:
        # best-effort, as in `run_provider`: recorded, not propagated. Only cancellation escapes.
        failed = e
    results: dict = {}
    # fixed before the loop: only a SHARED failure kills every lane. One finalizer's cancellation
    # must not be replayed into the others, whose results are already computed.
    dead = cancel if cancel is not None else failed
    for sid, wu, fin in live:
        body = fin if dead is None else (lambda e=dead: (_ for _ in ()).throw(e))
        try:
            results[sid] = _provider_terminal(sid, body, work_unit=wu)
        except BaseException as e:
            # this lane's terminal is written; re-raising now would leave later lanes started
            results[sid] = None
            cancel = cancel if cancel is not None else e
    if cancel is not None:
        raise cancel
    return results


def _provider_terminal(source_id, fn, *, work_unit=None):
    """Run `fn` and emit this lane's terminal, whatever happens. The lane must already be STARTED."""
    result = None
    status = Status.FAILED.value                             # default: covers a raise BEFORE a result is computed
    reason = n = error_class = None
    is_pagination = False                                     # this result reports pagination COMPLETION (emit a counter)
    partial_limited = False                                   # the truncation was a DELIBERATE bound
    try:
        result = fn()
        n = len(result) if hasattr(result, "__len__") else None
        produced = getattr(result, "produced", None)
        if produced is not None:
            # the lane told us what it wrote. Status follows THAT, not a hostname set it never fills.
            n = sum(v for v in produced.values() if isinstance(v, int))
        if isinstance(result, ProviderResult):
            if result.partial and result.partial_kind == "pagination":
                is_pagination = True
                error_class = result.error_class
                partial_limited = bool(result.limited)
                # a proven limit stays LIMITED on whichever page it struck
                status = _partial_status(error_class, result.limited)
                reason = (f"pagination TRUNCATED at {result.pages} page(s), cursor={result.cursor!r}"
                          + (f" — {error_class} on a later page (earlier pages KEPT)" if error_class else ""))
            elif result.partial:                            # a GENERIC degraded partial, not pagination
                error_class = result.error_class
                # a partial caused by a provider LIMIT is not degradation either
                status = _partial_status(error_class, result.limited)
                reason = result.partial_reason or f"partial result ({error_class or 'degraded'}) — earlier evidence KEPT"
            else:                                            # a complete ProviderResult — a paginating provider
                is_pagination = result.pages is not None     # (only paginating providers carry a completion counter)
                status = Status.SUCCESS.value if n else Status.EMPTY.value
        else:
            status = Status.SUCCESS.value if n else Status.EMPTY.value
    except ProviderSkip as e:                                # did not run and did not fail
        status, reason, result = Status.SKIPPED.value, e.reason, None
    except Exception as e:                                   # ordinary provider error — record FAILED, don't crash phase
        # the provider's OWN words, when it gave any. A status code is what happened; the body is why.
        _detail = error_detail(e)
        reason, result = f"{type(e).__name__}: {e}" + (f" — {_detail}" if _detail else ""), None
        # a body-proven class wins: the type mapping would flatten it to `error`
        error_class = provider_error_class(e)
        # a proven limit is neither failed nor degraded: the run was clean and a third party cut it
        if is_provider_limit(error_class):
            status = Status.LIMITED.value
    finally:
        # a finally, so a terminal fires on cancellation too and no lane is left permanently started
        if is_pagination:
            # emitted every run (omitted=0 when complete), so a clean rerun clears a prior truncation
            truncated = status in (Status.PARTIAL.value, Status.LIMITED.value)
            # the kind records WHOSE boundary stopped us: provider limit, a page lost in flight, or
            # our own configured ceiling — the only one of the three that is ours

            _kind = _partial_coverage_kind(error_class, partial_limited)
            events.coverage_partial(source_id, kind=_kind, measure="pagination",
                                    unit=(work_unit or source_id), eligible=1,
                                    tested=0 if truncated else 1, omitted=1 if truncated else 0,
                                    reason=(reason if truncated else "pagination complete"))
        _produced = getattr(result, "produced", None)
        events.tool_finish(source_id, status=status, work_unit=work_unit,
                           reason=reason, error_class=error_class, provider=True,   # verdict folds provider terminals
                           produced=(dict(_produced) if _produced is not None else
                                     ({"host": n} if n is not None else None)))     # (reset is on the START now)
    return result                                            # None on failure — caller guards (best-effort)


def acquisition_open(source_id: str, *, announce: bool = True) -> bool:
    """The acquisition gate, consulted by all three provider doors.

    A closed lane records a SKIP with its cause rather than a silent absence."""
    from . import campaign
    allowed, why = campaign.acquisition_allowed(source_id)
    if allowed:
        return True
    if announce:
        events.tool_blocked(source_id, reason=why)
    return False


def registered(source_id: str) -> bool:
    """Whether this source may execute, emitting `tool_blocked` when it may not.

    A lane running several units under one lifecycle brackets itself and asks this for the same gate."""
    if sources.get(source_id) is not None:
        return True
    events.tool_blocked(source_id, reason=f"unknown source_id {source_id!r} — not in registry; not executed")
    return False


def run_contract(source_id, cmd, *, repository=None, stdout=None, stderr=None,
                 native_outputs=(),
                 input_total=None, env=None, reclassify=None, work_unit=None,
                 parent_id=None, scope_distance=None, discovery_context=None,
                 **run_kwargs):
    """Run a source under its registry contract -> the (reclassified) RunResult.

    `reclassify` runs before the terminal event, so it carries the final status. `run_kwargs` pass
    through to runner.run. Additive: the phase still records the result itself."""
    # no tool runs outside a contract: an unknown source_id never reaches runner.run
    src = sources.get(source_id)
    if src is None:
        reason = f"unknown source_id {source_id!r} — not in registry; not executed"
        events.tool_blocked(source_id, reason=reason)
        return skipped(source_id, reason)
    if not acquisition_open(source_id):        # a campaign closed acquisition: this lane does not run
        from . import campaign as _campaign
        return skipped(source_id, _campaign.acquisition_allowed(source_id)[1])
    tool = src.get("tool") or source_id.split(".", 1)[-1]

    # Event serialization must not run caller-defined container methods before runner preflight. Invalid argv
    # still receives a start/finish lifecycle, but its start carries the only safe representation: an empty argv.
    event_cmd, _argv_error = _preflight_argv(cmd)
    events.tool_start(source_id, cmd=event_cmd or [], env=env, input_total=input_total, work_unit=work_unit,
                      workers=src.get("workers"), rate=src.get("rate"),
                      timeout=run_kwargs.get("timeout", src.get("timeout")),
                      parent_id=parent_id, scope_distance=scope_distance,
                      discovery_context=discovery_context)

    res = None
    try:
        res = _run(
            tool, cmd, repository=repository, stdout=stdout, stderr=stderr,
            native_outputs=native_outputs, env=env, **run_kwargs,
        )
        if reclassify is not None:
            res = reclassify(res)                           # file-output adapter → FINAL status on the terminal event
        return res
    finally:
        _emit_terminal(source_id, src, res, work_unit=work_unit, parent_id=parent_id,
                       scope_distance=scope_distance, discovery_context=discovery_context)
