"""Durable, bounded truth for one invocation's mediated network effects.

The component brokers are deliberately allowed to keep useful local counters,
but those counters are not durable evidence.  This module owns one private
append-only JSONL inode for the whole invocation.  All network mediators share
the same :class:`NetworkTraceArtifact`, and therefore the same sequence lock.

The important ordering rule is embodied by :meth:`NetworkTraceArtifact.plan`:
the plan row and its worst-case future row capacity are durable before the
method returns.  A ``TracePlan`` is necessary but never sufficient authority:
the caller must then enter the same short-lived ``NetworkEffectFence`` around
each nonblocking syscall.  ``settle`` writes the one terminal row.  ``event``
is only for an already-planned intermediate observation (for example the
seccomp broker's ``admitted`` stage).  Effect-free policy and protocol facts
use the distinct bounded :meth:`NetworkTraceArtifact.observe` row; they never
manufacture a plan that could be mistaken for contact authorization.

The file is preallocated with Linux ``FALLOC_FL_KEEP_SIZE``.  Thus allocation
does not introduce zero-filled or otherwise non-JSON bytes into the logical
artifact, while ENOSPC is still discovered before the first plan can authorize
an effect.  Unsupported allocation is a fail-closed construction error.
"""

from __future__ import annotations

import ctypes
import contextlib
import errno
import fcntl
import functools
import hashlib
import json
import os
import re
import stat
import threading
from dataclasses import dataclass, field


ARTIFACT_NAME = "network-trace.jsonl"
ROW_SCHEMA = "quarry.network-trace-row.v1"
SETTLEMENT_SCHEMA = "quarry.network-trace-settlement.v1"

NETWORK_TRACE_MAX_ROWS = 32 * 1024
NETWORK_TRACE_MAX_BYTES = 64 * 1024 * 1024
NETWORK_TRACE_MAX_ROW_BYTES = 2048
NETWORK_TRACE_MAX_JSON_DEPTH = 8
NETWORK_TRACE_MAX_INTEGER_MAGNITUDE = (1 << 53) - 1
NETWORK_TRACE_MAX_SETTLEMENT_BYTES = 64 * 1024
NETWORK_TRACE_MAX_COMPONENTS = 32
NETWORK_TRACE_MAX_RESERVED_ROWS = 64
NETWORK_TRACE_MAX_RELPATH_BYTES = 512
NETWORK_TRACE_MIN_ALLOCATION_GRANULARITY = 512
NETWORK_TRACE_MAX_ALLOCATION_GRANULARITY = 1024 * 1024
NETWORK_TRACE_READ_CHUNK_BYTES = 64 * 1024

COMPONENT_IDS = (
    "broker.standard",
    "broker.browser",
    "broker.controller",
    "proxy",
    "cdp",
    "native.http",
    "native.dns",
)

_COMPONENT_SET = frozenset(COMPONENT_IDS)
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_PAYLOAD_KEY = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_PLAN_ID = re.compile(r"[0-9a-f]{16}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_PATH_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_FILE_FLAGS = (
    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_FALLOC_FL_KEEP_SIZE = 0x01
_EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()

_OPERATIONS = {
    "broker.standard": frozenset({
        "accept", "bind", "connect", "listen", "notification", "sendmsg",
        "sendto",
    }),
    "broker.browser": frozenset({
        "accept", "bind", "connect", "listen", "notification", "sendmsg",
        "sendto",
    }),
    "broker.controller": frozenset({
        "accept", "bind", "connect", "listen", "notification", "sendmsg",
        "sendto",
    }),
    "proxy": frozenset({"dns_query", "peer_connect", "relay", "request"}),
    "cdp": frozenset({"controller_connection", "message"}),
    "native.http": frozenset({"request"}),
    "native.dns": frozenset({"resolver_query"}),
}
_EVENT_STAGES = frozenset({
    "admitted", "authority", "message", "peer_admission", "request",
})
_OUTCOMES = frozenset({
    "allowed", "cancelled", "completed", "denied", "error", "refused",
})
_DECISIONS = frozenset({"allow", "deny"})


class NetworkTraceError(RuntimeError):
    """Base class for trace construction or verification failures."""


class NetworkTraceRefused(NetworkTraceError):
    """An operation was refused before it could authorize a network effect."""


class NetworkTraceCapacityError(NetworkTraceRefused):
    """The bounded artifact cannot reserve another complete operation."""


class NetworkTraceIntegrityError(NetworkTraceError):
    """The named artifact is not the exact canonical inode that was created."""


def _drain_after_failure(method):
    """Never let a trace failure escape before the shared effect fence drains."""

    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except BaseException as primary:
            if getattr(self, "_cancellation", None) is not None:
                self._cancellation.set()
            try:
                self._drain_effect_fence()
            except BaseException:
                raise NetworkTraceIntegrityError(
                    "network_trace_failure_drain_failed",
                ) from primary
            raise

    return wrapped


def _construction_cancel(event: threading.Event | None, callback) -> None:
    if event is not None:
        event.set()
    if callback is not None:
        callback()


def _construction_failure(primary: BaseException, *, parent_fd: int = -1,
                          descriptor: int = -1, created: bool = False,
                          event: threading.Event | None = None,
                          cancel_callback=None):
    """Best-effort cleanup that can never skip synchronous fence draining."""

    if created and parent_fd >= 0:
        try:
            os.unlink(ARTIFACT_NAME, dir_fd=parent_fd)
        except BaseException:
            pass
        try:
            os.fsync(parent_fd)
        except BaseException:
            pass
    for value in (descriptor, parent_fd):
        if value >= 0:
            try:
                os.close(value)
            except BaseException:
                pass
    try:
        _construction_cancel(event, cancel_callback)
    except BaseException as cancel_error:
        raise NetworkTraceIntegrityError(
            "network_trace_construction_cancel_failed",
        ) from primary
    raise primary.with_traceback(primary.__traceback__)


@dataclass(frozen=True)
class TracePlan:
    """Unforgeable handle for one durable plan owned by one artifact."""

    plan_id: str
    component_id: str
    operation: str
    _owner: object = field(repr=False, compare=False)


@dataclass
class _OpenPlan:
    token: TracePlan
    remaining_rows: int


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "_FileIdentity":
        return cls(int(value.st_dev), int(value.st_ino))


@dataclass(frozen=True)
class _ParentIdentity:
    device: int
    inode: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "_ParentIdentity":
        return cls(int(value.st_dev), int(value.st_ino), int(value.st_ctime_ns))


def _load_fallocate():
    try:
        library = ctypes.CDLL(None, use_errno=True)
        function = library.fallocate
    except (AttributeError, OSError) as exc:
        raise NetworkTraceRefused("network_trace_preallocation_unsupported") from exc
    function.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_longlong,
                         ctypes.c_longlong)
    function.restype = ctypes.c_int
    return function


def _fallocate(descriptor: int, flags: int, offset: int, length: int) -> None:
    function = _load_fallocate()
    while True:
        ctypes.set_errno(0)
        result = function(descriptor, flags, offset, length)
        if result == 0:
            return
        error = ctypes.get_errno() or errno.EIO
        if error == errno.EINTR:
            continue
        raise OSError(error, os.strerror(error))


def _preallocate_keep_size(descriptor: int, length: int) -> None:
    """Physically reserve ``length`` bytes without changing logical EOF."""

    _fallocate(descriptor, _FALLOC_FL_KEEP_SIZE, 0, length)


def _truncate_retry(descriptor: int, length: int) -> None:
    while True:
        try:
            os.ftruncate(descriptor, length)
            return
        except InterruptedError:
            continue


def _release_preallocation_tail(descriptor: int, *, current_eof: int,
                                future_eof: int,
                                envelope_bytes: int) -> tuple[int, int]:
    """Release the broad tail without ever changing canonical logical bytes."""

    if (type(current_eof) is not int or type(future_eof) is not int
            or type(envelope_bytes) is not int or current_eof < 0
            or current_eof > future_eof or future_eof > envelope_bytes):
        raise NetworkTraceIntegrityError(
            "network_trace_release_range_invalid",
        )
    observed = os.fstatvfs(descriptor)
    granularity = observed.f_frsize
    if (type(granularity) is not int
            or not NETWORK_TRACE_MIN_ALLOCATION_GRANULARITY
            <= granularity <= NETWORK_TRACE_MAX_ALLOCATION_GRANULARITY
            or granularity & (granularity - 1)):
        raise NetworkTraceIntegrityError(
            "network_trace_allocation_granularity_invalid",
        )
    # On the attested Linux fallocate contract, same-size ftruncate discards
    # KEEP_SIZE unwritten extents past i_size.  Unlike temporary extension, a
    # process death at either boundary preserves the exact canonical prefix.
    _truncate_retry(descriptor, current_eof)
    if future_eof > current_eof:
        _fallocate(
            descriptor, _FALLOC_FL_KEEP_SIZE, current_eof,
            future_eof - current_eof,
        )
    after = os.fstat(descriptor)
    physical_bytes = int(after.st_blocks) * 512
    physical_bound = (
        (future_eof + granularity - 1) // granularity * granularity
    )
    if (int(after.st_size) != current_eof
            or physical_bytes > physical_bound):
        raise NetworkTraceIntegrityError(
            "network_trace_preallocation_release_unproved",
        )
    return current_eof, future_eof - current_eof


def _set_cloexec(descriptor: int) -> None:
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
    fcntl.fcntl(descriptor, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)


def _check_parent(value: os.stat_result) -> None:
    if (not stat.S_ISDIR(value.st_mode)
            or int(value.st_uid) != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o700):
        raise NetworkTraceRefused("network_trace_parent_not_private_authority")


def _check_file(value: os.stat_result, *, maximum_bytes: int) -> None:
    if (not stat.S_ISREG(value.st_mode)
            or int(value.st_uid) != os.geteuid()
            or int(value.st_nlink) != 1
            or stat.S_IMODE(value.st_mode) != 0o600
            or int(value.st_size) < 0
            or int(value.st_size) > maximum_bytes):
        raise NetworkTraceIntegrityError("network_trace_file_identity_invalid")


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (int(left.st_dev), int(left.st_ino)) == (
        int(right.st_dev), int(right.st_ino),
    )


def _validate_limits(*, max_rows: int, max_bytes: int,
                     max_row_bytes: int, max_depth: int,
                     max_integer: int) -> None:
    if (type(max_rows) is not int
            or not 4 <= max_rows <= NETWORK_TRACE_MAX_ROWS
            or type(max_bytes) is not int
            or not 1024 <= max_bytes <= NETWORK_TRACE_MAX_BYTES
            or type(max_row_bytes) is not int
            or not 256 <= max_row_bytes <= NETWORK_TRACE_MAX_ROW_BYTES
            or max_row_bytes > max_bytes // 2
            or type(max_depth) is not int
            or not 2 <= max_depth <= NETWORK_TRACE_MAX_JSON_DEPTH
            or type(max_integer) is not int
            or not 1024 <= max_integer
            <= NETWORK_TRACE_MAX_INTEGER_MAGNITUDE):
        raise NetworkTraceRefused("network_trace_limits_invalid")


def _validate_identifier(value, *, field_name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise NetworkTraceRefused(f"network_trace_{field_name}_invalid")
    return value


def _validate_artifact_relpath(value) -> str:
    if type(value) is not str:
        raise NetworkTraceRefused("network_trace_relpath_invalid")
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeError as exc:
        raise NetworkTraceRefused("network_trace_relpath_invalid") from exc
    parts = value.split("/")
    if (not 2 <= len(parts) <= 16
            or len(encoded) > NETWORK_TRACE_MAX_RELPATH_BYTES
            or parts[-1] != ARTIFACT_NAME
            or any(_PATH_COMPONENT.fullmatch(part) is None for part in parts)):
        raise NetworkTraceRefused("network_trace_relpath_invalid")
    return value


def _validate_json_value(value, *, depth: int, maximum_depth: int,
                         maximum_integer: int, payload: bool = True,
                         maximum_bytes: int | None = None):
    """Return a plain bounded snapshot after validating canonical width.

    The byte budget is consumed during the walk, before ``json.dumps`` sees
    the value.  Every node and container delimiter consumes at least one byte;
    container length and string length lower bounds therefore reject hostile
    widths in O(1), while any continued walk is O(maximum_bytes).  Returning a
    snapshot also prevents caller mutation between validation and encoding.
    """

    remaining = None if maximum_bytes is None else [maximum_bytes]

    def consume(count: int) -> None:
        if remaining is None:
            return
        if count < 0 or count > remaining[0]:
            raise NetworkTraceRefused("network_trace_row_oversize")
        remaining[0] -= count

    def string_width(text: str) -> None:
        # Quotes plus at least one output byte per code point.  This rejects a
        # multi-MiB string without scanning or copying it.
        if remaining is not None and len(text) + 2 > remaining[0]:
            raise NetworkTraceRefused("network_trace_row_oversize")
        consume(2)
        for character in text:
            codepoint = ord(character)
            if codepoint in (0x22, 0x5C) or codepoint in (
                    0x08, 0x09, 0x0A, 0x0C, 0x0D):
                consume(2)
            elif codepoint < 0x20 or codepoint > 0x7F:
                consume(6 if codepoint <= 0xFFFF else 12)
            else:
                consume(1)

    def walk(item, current_depth: int):
        if current_depth > maximum_depth:
            raise NetworkTraceRefused("network_trace_json_depth_exceeded")
        if item is None:
            consume(4)
            return None
        if type(item) is bool:
            consume(4 if item else 5)
            return item
        if type(item) is int:
            if item < -maximum_integer or item > maximum_integer:
                raise NetworkTraceRefused("network_trace_json_integer_exceeded")
            consume(len(str(item)))
            return item
        if type(item) is str:
            string_width(item)
            return item
        if type(item) is list:
            consume(2)
            if item:
                consume(len(item) - 1)
                if remaining is not None and len(item) > remaining[0]:
                    raise NetworkTraceRefused("network_trace_row_oversize")
            snapshot = []
            for child in item:
                snapshot.append(walk(child, current_depth + 1))
            return snapshot
        if type(item) is dict:
            consume(2)
            if item:
                consume(len(item) - 1)
                # Each member needs at least an empty quoted key, a colon,
                # and a one-byte scalar/container value.
                if remaining is not None and len(item) * 4 > remaining[0]:
                    raise NetworkTraceRefused("network_trace_row_oversize")
            snapshot = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise NetworkTraceRefused("network_trace_json_key_invalid")
                string_width(key)
                if payload and _PAYLOAD_KEY.fullmatch(key) is None:
                    raise NetworkTraceRefused("network_trace_json_key_invalid")
                consume(1)
                snapshot[key] = walk(child, current_depth + 1)
            return snapshot
        raise NetworkTraceRefused("network_trace_json_type_invalid")

    if (maximum_bytes is not None
            and (type(maximum_bytes) is not int or maximum_bytes < 0)):
        raise NetworkTraceRefused("network_trace_row_oversize")
    return walk(value, depth)


def _canonical_line(row: dict, *, max_row_bytes: int, max_depth: int,
                    max_integer: int) -> bytes:
    safe_row = _validate_json_value(
        row, depth=0, maximum_depth=max_depth,
        maximum_integer=max_integer, payload=False,
        maximum_bytes=max_row_bytes - 1,
    )
    try:
        body = json.dumps(
            safe_row, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii") + b"\n"
    except (UnicodeError, TypeError, ValueError) as exc:
        raise NetworkTraceRefused("network_trace_json_invalid") from exc
    if len(body) > max_row_bytes:
        raise NetworkTraceRefused("network_trace_row_oversize")
    return body


def _strict_json(body: bytes, *, max_depth: int, max_integer: int) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise NetworkTraceIntegrityError(
                    "network_trace_json_member_duplicate",
                )
            value[key] = item
        return value

    def integer(text):
        value = int(text, 10)
        if abs(value) > max_integer:
            raise NetworkTraceIntegrityError(
                "network_trace_json_integer_exceeded",
            )
        return value

    def floating(_text):
        raise NetworkTraceIntegrityError("network_trace_json_float_refused")

    def nonfinite(_text):
        raise NetworkTraceIntegrityError("network_trace_json_nonfinite_refused")

    try:
        value = json.loads(
            body.decode("ascii", "strict"), object_pairs_hook=pairs,
            parse_int=integer, parse_float=floating, parse_constant=nonfinite,
        )
    except NetworkTraceIntegrityError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise NetworkTraceIntegrityError("network_trace_json_invalid") from exc
    if type(value) is not dict:
        raise NetworkTraceIntegrityError("network_trace_row_not_object")
    try:
        value = _validate_json_value(
            value, depth=0, maximum_depth=max_depth,
            maximum_integer=max_integer, payload=False,
            maximum_bytes=len(body),
        )
    except NetworkTraceRefused as exc:
        raise NetworkTraceIntegrityError(str(exc)) from exc
    canonical = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    if canonical != body:
        raise NetworkTraceIntegrityError("network_trace_json_noncanonical")
    return value


def _require_keys(row: dict, expected: frozenset[str]) -> None:
    if frozenset(row) != expected:
        raise NetworkTraceIntegrityError("network_trace_row_members_invalid")


def _read_descriptor(descriptor: int, size: int) -> bytes:
    output = bytearray()
    offset = 0
    while offset < size:
        try:
            block = os.pread(
                descriptor,
                min(NETWORK_TRACE_READ_CHUNK_BYTES, size - offset), offset,
            )
        except InterruptedError:
            continue
        if not block:
            raise NetworkTraceIntegrityError("network_trace_read_truncated")
        output.extend(block)
        offset += len(block)
    return bytes(output)


def _empty_component_state() -> dict:
    return {
        "hasher": hashlib.sha256(),
        "rows": 0,
        "plans": 0,
        "events": 0,
        "terminals": 0,
        "observations": 0,
    }


def _replay_body(body: bytes, *, invocation_id: str, artifact_relpath: str,
                 components: tuple[str, ...], max_rows: int,
                 max_bytes: int, max_row_bytes: int, max_depth: int,
                 max_integer: int) -> dict:
    if len(body) > max_bytes:
        raise NetworkTraceIntegrityError("network_trace_bytes_exceeded")
    if body and not body.endswith(b"\n"):
        raise NetworkTraceIntegrityError("network_trace_torn_suffix")
    component_set = frozenset(components)
    component_state = {name: _empty_component_state() for name in components}
    open_plans: dict[str, tuple[str, str, int]] = {}
    fatal = None
    dropped = 0
    decision = None
    reason = None
    header_seen = False
    seal_seen = False
    reserved_rows = 0
    prefix_bytes = 0
    prefix_hasher = hashlib.sha256()
    total_hasher = hashlib.sha256()
    total_hasher.update(body)
    rows = body.splitlines(keepends=True)
    if len(rows) > max_rows:
        raise NetworkTraceIntegrityError("network_trace_rows_exceeded")

    def check_prefix_capacity(processed_rows: int) -> None:
        future_control_rows = (
            int(not seal_seen) + int(fatal is None and not seal_seen)
        )
        if (processed_rows + reserved_rows + future_control_rows > max_rows
                or prefix_bytes
                + (reserved_rows + future_control_rows) * max_row_bytes
                > max_bytes):
            raise NetworkTraceIntegrityError(
                "network_trace_reservation_overcommitted",
            )

    for expected_sequence, line in enumerate(rows):
        if not line.endswith(b"\n") or line == b"\n" or len(line) > max_row_bytes:
            raise NetworkTraceIntegrityError("network_trace_row_framing_invalid")
        row = _strict_json(
            line[:-1], max_depth=max_depth, max_integer=max_integer,
        )
        if row.get("schema") != ROW_SCHEMA \
                or type(row.get("sequence")) is not int \
                or row["sequence"] != expected_sequence:
            raise NetworkTraceIntegrityError("network_trace_sequence_invalid")
        if (type(row.get("previous_sha256")) is not str
                or row["previous_sha256"] != prefix_hasher.hexdigest()):
            raise NetworkTraceIntegrityError("network_trace_chain_invalid")
        prefix_hasher.update(line)
        prefix_bytes += len(line)
        kind = row.get("kind")
        if type(kind) is not str:
            raise NetworkTraceIntegrityError("network_trace_kind_invalid")
        if kind == "header":
            _require_keys(row, frozenset({
                "schema", "sequence", "kind", "previous_sha256",
                "invocation_id", "artifact_relpath", "components", "limits",
                "preallocation",
            }))
            expected_limits = {
                "artifact_bytes": max_bytes,
                "integer_magnitude": max_integer,
                "json_depth": max_depth,
                "row_bytes": max_row_bytes,
                "row_count": max_rows,
            }
            limits = row["limits"]
            preallocation = row["preallocation"]
            if (expected_sequence != 0 or header_seen
                    or type(row["invocation_id"]) is not str
                    or row["invocation_id"] != invocation_id
                    or type(row["artifact_relpath"]) is not str
                    or row["artifact_relpath"] != artifact_relpath
                    or type(row["components"]) is not list
                    or any(type(value) is not str for value in row["components"])
                    or row["components"] != list(components)
                    or type(limits) is not dict
                    or frozenset(limits) != frozenset(expected_limits)
                    or any(type(limits[key]) is not int
                           for key in expected_limits)
                    or limits != expected_limits
                    or type(preallocation) is not dict
                    or frozenset(preallocation) != frozenset({
                        "bytes", "keep_size",
                    })
                    or type(preallocation["bytes"]) is not int
                    or preallocation["bytes"] != max_bytes
                    or type(preallocation["keep_size"]) is not bool
                    or preallocation["keep_size"] is not True):
                raise NetworkTraceIntegrityError("network_trace_header_invalid")
            header_seen = True
            check_prefix_capacity(expected_sequence + 1)
            continue
        if not header_seen:
            raise NetworkTraceIntegrityError("network_trace_header_missing")
        if seal_seen:
            raise NetworkTraceIntegrityError("network_trace_row_after_seal")
        if kind == "seal":
            _require_keys(row, frozenset({
                "schema", "sequence", "kind", "component",
                "previous_sha256", "decision", "reason",
            }))
            if (type(row["component"]) is not str
                    or row["component"] != "trace"
                    or type(row["decision"]) is not str
                    or row["decision"] not in _DECISIONS
                    or type(row["reason"]) is not str
                    or _IDENTIFIER.fullmatch(row["reason"]) is None):
                raise NetworkTraceIntegrityError("network_trace_seal_invalid")
            decision = row["decision"]
            reason = row["reason"]
            seal_seen = True
            check_prefix_capacity(expected_sequence + 1)
            continue
        if kind == "fatal":
            _require_keys(row, frozenset({
                "schema", "sequence", "kind", "component", "code", "dropped",
                "previous_sha256",
            }))
            if (fatal is not None
                    or type(row["component"]) is not str
                    or row["component"] != "trace"
                    or type(row["code"]) is not str
                    or _IDENTIFIER.fullmatch(row["code"]) is None
                    or type(row["dropped"]) is not int
                    or row["dropped"] != 1):
                raise NetworkTraceIntegrityError("network_trace_fatal_invalid")
            fatal = row["code"]
            dropped = 1
            check_prefix_capacity(expected_sequence + 1)
            continue

        if kind == "plan":
            _require_keys(row, frozenset({
                "schema", "sequence", "kind", "component", "operation",
                "plan_id", "data", "reservation", "previous_sha256",
            }))
        elif kind == "event":
            _require_keys(row, frozenset({
                "schema", "sequence", "kind", "component", "operation",
                "plan_id", "stage", "data", "previous_sha256",
            }))
        elif kind == "terminal":
            _require_keys(row, frozenset({
                "schema", "sequence", "kind", "component", "operation",
                "plan_id", "outcome", "data", "previous_sha256",
            }))
        elif kind == "observation":
            _require_keys(row, frozenset({
                "schema", "sequence", "kind", "component", "operation",
                "outcome", "data", "previous_sha256",
            }))
        else:
            raise NetworkTraceIntegrityError("network_trace_kind_invalid")

        component = row["component"]
        operation = row["operation"]
        if (type(component) is not str
                or component not in component_set
                or type(operation) is not str
                or operation not in _OPERATIONS[component]
                or type(row["data"]) is not dict):
            raise NetworkTraceIntegrityError("network_trace_row_identity_invalid")
        try:
            _validate_json_value(
                row["data"], depth=1, maximum_depth=max_depth,
                maximum_integer=max_integer,
            )
        except NetworkTraceRefused as exc:
            raise NetworkTraceIntegrityError(str(exc)) from exc

        state = component_state[component]
        state["hasher"].update(line)
        state["rows"] += 1
        if kind == "observation":
            if (fatal is not None
                    or type(row["outcome"]) is not str
                    or row["outcome"] not in _OUTCOMES):
                raise NetworkTraceIntegrityError(
                    "network_trace_observation_invalid",
                )
            state["observations"] += 1
        else:
            plan_id = row["plan_id"]
            if (type(plan_id) is not str
                    or _PLAN_ID.fullmatch(plan_id) is None):
                raise NetworkTraceIntegrityError(
                    "network_trace_row_identity_invalid",
                )
        if kind == "plan":
            if fatal is not None:
                raise NetworkTraceIntegrityError("network_trace_plan_after_fatal")
            reservation = row["reservation"]
            if (type(reservation) is not dict
                    or reservation != {
                        "row_bytes": max_row_bytes,
                        "rows": reservation.get("rows"),
                    }
                    or type(reservation.get("rows")) is not int
                    or not 1 <= reservation["rows"]
                    <= NETWORK_TRACE_MAX_RESERVED_ROWS
                    or plan_id != f"{expected_sequence:016x}"
                    or plan_id in open_plans):
                raise NetworkTraceIntegrityError("network_trace_plan_duplicate")
            open_plans[plan_id] = (
                component, operation, reservation["rows"],
            )
            reserved_rows += reservation["rows"]
            state["plans"] += 1
        elif kind == "event":
            if (type(row["stage"]) is not str
                    or row["stage"] not in _EVENT_STAGES
                    or plan_id not in open_plans
                    or open_plans[plan_id][:2] != (component, operation)
                    or open_plans[plan_id][2] <= 1):
                raise NetworkTraceIntegrityError("network_trace_event_unmatched")
            open_plans[plan_id] = (
                component, operation, open_plans[plan_id][2] - 1,
            )
            reserved_rows -= 1
            state["events"] += 1
        elif kind == "terminal":
            if (type(row["outcome"]) is not str
                    or row["outcome"] not in _OUTCOMES
                    or plan_id not in open_plans
                    or open_plans[plan_id][:2] != (component, operation)
                    or open_plans[plan_id][2] < 1):
                raise NetworkTraceIntegrityError("network_trace_terminal_unmatched")
            reserved_rows -= open_plans[plan_id][2]
            del open_plans[plan_id]
            state["terminals"] += 1
        check_prefix_capacity(expected_sequence + 1)

    if not header_seen:
        raise NetworkTraceIntegrityError("network_trace_header_missing")
    globally_clean = (
        seal_seen and decision == "allow" and fatal is None
        and dropped == 0 and not open_plans
    )
    component_summary = {}
    for component in components:
        state = component_state[component]
        component_open = sum(
            1 for value in open_plans.values() if value[0] == component
        )
        component_summary[component] = {
            "sha256": state["hasher"].hexdigest(),
            "rows": state["rows"],
            "plans": state["plans"],
            "events": state["events"],
            "terminals": state["terminals"],
            "observations": state["observations"],
            "open_plans": component_open,
            "complete": globally_clean and component_open == 0,
        }
    return {
        "artifact_relpath": artifact_relpath,
        "invocation_sha256": hashlib.sha256(invocation_id.encode("ascii")).hexdigest(),
        "sha256": total_hasher.hexdigest(),
        "bytes": len(body),
        "rows": len(rows),
        "open_plans": len(open_plans),
        "dropped_rows": dropped,
        "fatal": fatal,
        "decision": decision,
        "reason": reason,
        "components": component_summary,
        "complete": globally_clean,
    }


def _settlement(replay: dict, *, certified: bool) -> dict:
    if type(certified) is not bool:
        raise NetworkTraceIntegrityError("network_trace_certification_invalid")
    replay = json.loads(json.dumps(replay))
    if not certified:
        replay["complete"] = False
        for component in replay["components"].values():
            component["complete"] = False
    value = {
        "schema_version": SETTLEMENT_SCHEMA,
        "artifact": ARTIFACT_NAME,
        "certified": certified,
        **replay,
    }
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii") + b"\n"
    if len(encoded) > NETWORK_TRACE_MAX_SETTLEMENT_BYTES:
        raise NetworkTraceIntegrityError("network_trace_settlement_oversize")
    return value


def _strict_receipt_equal(expected, candidate) -> bool:
    """Type-strict compare bounded by the trusted candidate's fixed schema."""

    if type(expected) is not type(candidate):
        return False
    if type(candidate) is dict:
        if len(expected) != len(candidate) or expected.keys() != candidate.keys():
            return False
        return all(
            _strict_receipt_equal(expected[key], value)
            for key, value in candidate.items()
        )
    if type(candidate) is list:
        return len(expected) == len(candidate) and all(
            _strict_receipt_equal(left, right)
            for left, right in zip(expected, candidate)
        )
    return expected == candidate


class NetworkTraceArtifact:
    """One preallocated, globally sequenced invocation trace writer."""

    def __init__(self, *args, **kwargs):
        raise TypeError("use NetworkTraceArtifact.create()")

    @classmethod
    def create(cls, directory_fd: int, invocation_id: str,
               artifact_relpath: str, *,
               cancellation_event: threading.Event | None = None,
               effect_fence=None,
               max_rows: int = NETWORK_TRACE_MAX_ROWS,
               max_bytes: int = NETWORK_TRACE_MAX_BYTES,
               max_row_bytes: int = NETWORK_TRACE_MAX_ROW_BYTES,
               max_depth: int = NETWORK_TRACE_MAX_JSON_DEPTH,
               max_integer: int = NETWORK_TRACE_MAX_INTEGER_MAGNITUDE,
               components: tuple[str, ...] = COMPONENT_IDS) -> "NetworkTraceArtifact":
        # A structurally similar object cannot prove shared exclusion or
        # synchronous draining.  Import locally so network_broker can later
        # adapt this standalone writer without a module-import cycle.
        from .network_broker import NetworkEffectFence

        if type(effect_fence) is not NetworkEffectFence:
            raise NetworkTraceRefused("network_trace_effect_fence_invalid")
        fence_event = getattr(effect_fence, "event", None)
        cancel_callback = effect_fence.cancel
        if not isinstance(fence_event, threading.Event):
            _construction_failure(
                NetworkTraceRefused("network_trace_effect_fence_invalid"),
                cancel_callback=cancel_callback,
            )
        try:
            if (cancellation_event is not None
                    and cancellation_event is not fence_event):
                raise NetworkTraceRefused("network_trace_effect_fence_invalid")
            artifact_relpath = _validate_artifact_relpath(artifact_relpath)
            _validate_limits(
                max_rows=max_rows, max_bytes=max_bytes,
                max_row_bytes=max_row_bytes, max_depth=max_depth,
                max_integer=max_integer,
            )
            if (type(directory_fd) is not int or directory_fd < 0
                    or type(invocation_id) is not str
                    or _INVOCATION_ID.fullmatch(invocation_id) is None):
                raise NetworkTraceRefused(
                    "network_trace_create_arguments_invalid",
                )
            if (type(components) is not tuple or not components
                    or len(components) > NETWORK_TRACE_MAX_COMPONENTS
                    or any(type(value) is not str or value not in _COMPONENT_SET
                           for value in components)
                    or len(set(components)) != len(components)):
                raise NetworkTraceRefused("network_trace_components_invalid")
        except BaseException as exc:
            _construction_failure(
                exc, event=fence_event, cancel_callback=cancel_callback,
            )
        cancellation_event = fence_event

        parent_fd = -1
        try:
            parent_fd = os.dup(directory_fd)
            _set_cloexec(parent_fd)
            parent_before = os.fstat(parent_fd)
            _check_parent(parent_before)
            if os.listdir(parent_fd):
                raise NetworkTraceRefused(
                    "network_trace_parent_not_dedicated",
                )
        except (OSError, NetworkTraceError) as exc:
            primary = exc if isinstance(exc, NetworkTraceError) else \
                NetworkTraceRefused("network_trace_parent_open_failed")
            if primary is not exc:
                primary.__cause__ = exc
            _construction_failure(
                primary, parent_fd=parent_fd, event=cancellation_event,
                cancel_callback=cancel_callback,
            )

        descriptor = -1
        created = False
        try:
            descriptor = os.open(
                ARTIFACT_NAME, _FILE_FLAGS, 0o600, dir_fd=parent_fd,
            )
            created = True
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            _check_file(opened, maximum_bytes=max_bytes)
            if int(opened.st_size) != 0:
                raise NetworkTraceIntegrityError("network_trace_file_not_empty")
            _preallocate_keep_size(descriptor, max_bytes)
            # Allocation and the empty logical inode precede publication of a
            # usable writer.  Both file and name must survive a crash.
            os.fsync(descriptor)
            named = os.stat(
                ARTIFACT_NAME, dir_fd=parent_fd, follow_symlinks=False,
            )
            _check_file(named, maximum_bytes=max_bytes)
            if not _same_file(opened, named) or int(named.st_size) != 0:
                raise NetworkTraceIntegrityError("network_trace_file_name_changed")
            os.fsync(parent_fd)
            parent_after = os.fstat(parent_fd)
            _check_parent(parent_after)
            if not _same_file(parent_before, parent_after):
                raise NetworkTraceIntegrityError("network_trace_parent_changed")
            final_file = os.fstat(descriptor)
            final_name = os.stat(
                ARTIFACT_NAME, dir_fd=parent_fd, follow_symlinks=False,
            )
            _check_file(final_file, maximum_bytes=max_bytes)
            _check_file(final_name, maximum_bytes=max_bytes)
            if not _same_file(final_file, final_name):
                raise NetworkTraceIntegrityError("network_trace_file_name_changed")
        except BaseException as exc:
            _construction_failure(
                exc, parent_fd=parent_fd, descriptor=descriptor,
                created=created, event=cancellation_event,
                cancel_callback=cancel_callback,
            )

        self = object.__new__(cls)
        self._parent_fd = parent_fd
        self._fd = descriptor
        self._file_identity = _FileIdentity.from_stat(final_file)
        self._parent_identity = _ParentIdentity.from_stat(parent_after)
        self._invocation_id = invocation_id
        self._artifact_relpath = artifact_relpath
        self._max_rows = max_rows
        self._max_bytes = max_bytes
        self._max_row_bytes = max_row_bytes
        self._max_depth = max_depth
        self._max_integer = max_integer
        self._components = components
        self._component_set = frozenset(components)
        self._cancellation = cancellation_event or threading.Event()
        self._effect_fence = effect_fence
        self._cancel_callback = cancel_callback
        self._cancel_lock = threading.Lock()
        self._cancel_drained = False
        self._lock = threading.RLock()
        self._token_owner = object()
        self._open: dict[str, _OpenPlan] = {}
        self._reserved_rows = 0
        self._logical_bytes = 0
        self._row_count = 0
        self._digest = hashlib.sha256()
        self._fatal: str | None = None
        self._dropped = 0
        self._accepting = True
        self._poisoned: str | None = None
        self._sealed = False
        self._closed = False
        self._final_settlement: dict | None = None
        self._final_decision: str | None = None
        self._final_reason: str | None = None
        header = {
            "schema": ROW_SCHEMA,
            "sequence": 0,
            "kind": "header",
            "previous_sha256": self._digest.hexdigest(),
            "invocation_id": invocation_id,
            "artifact_relpath": artifact_relpath,
            "components": list(components),
            "limits": {
                "artifact_bytes": max_bytes,
                "integer_magnitude": max_integer,
                "json_depth": max_depth,
                "row_bytes": max_row_bytes,
                "row_count": max_rows,
            },
            "preallocation": {"bytes": max_bytes, "keep_size": True},
        }
        try:
            line = self._encode_locked(header)
            if max_rows < 3 or len(line) + 2 * max_row_bytes > max_bytes:
                raise NetworkTraceRefused("network_trace_limits_too_small")
            self._write_line_locked(line)
        except BaseException as exc:
            _construction_failure(
                exc, parent_fd=self._parent_fd, descriptor=self._fd,
                created=True, event=cancellation_event,
                cancel_callback=cancel_callback,
            )
        return self

    @property
    def cancellation_event(self) -> threading.Event:
        return self._cancellation

    @property
    def fatal(self) -> str | None:
        with self._lock:
            return self._fatal or self._poisoned

    def _drain_effect_fence(self) -> None:
        callback = self._cancel_callback
        if callback is None:
            return
        with self._cancel_lock:
            if self._cancel_drained:
                return
            try:
                callback()
            except BaseException as exc:
                raise NetworkTraceIntegrityError(
                    "network_trace_effect_fence_cancel_failed",
                ) from exc
            self._cancel_drained = True

    def _require_live_locked(self, *, accepting: bool = False) -> None:
        if self._closed or self._fd < 0:
            raise NetworkTraceRefused("network_trace_closed")
        if self._poisoned is not None:
            raise NetworkTraceIntegrityError(self._poisoned)
        if self._sealed:
            raise NetworkTraceRefused("network_trace_sealed")
        if accepting and not self._accepting:
            raise NetworkTraceRefused(self._fatal or "network_trace_not_accepting")

    def _poison_locked(self, code: str, cause: BaseException | None = None):
        self._poisoned = self._poisoned or code
        self._accepting = False
        self._cancellation.set()
        error = NetworkTraceIntegrityError(self._poisoned)
        if cause is None:
            raise error
        raise error from cause

    def _validate_identity_locked(self) -> os.stat_result:
        try:
            parent = os.fstat(self._parent_fd)
            descriptor = os.fstat(self._fd)
            named = os.stat(
                ARTIFACT_NAME, dir_fd=self._parent_fd,
                follow_symlinks=False,
            )
            _check_parent(parent)
            _check_file(descriptor, maximum_bytes=self._max_bytes)
            _check_file(named, maximum_bytes=self._max_bytes)
        except (OSError, NetworkTraceError) as exc:
            self._poison_locked("network_trace_identity_failed", exc)
        if (_ParentIdentity.from_stat(parent) != self._parent_identity
                or _FileIdentity.from_stat(descriptor) != self._file_identity
                or _FileIdentity.from_stat(named) != self._file_identity
                or int(descriptor.st_size) != self._logical_bytes
                or int(named.st_size) != self._logical_bytes):
            self._poison_locked("network_trace_identity_changed")
        return descriptor

    def _write_line_locked(self, line: bytes) -> None:
        self._validate_identity_locked()
        offset = self._logical_bytes
        written = 0
        try:
            while written < len(line):
                try:
                    count = os.pwrite(self._fd, line[written:], offset + written)
                except InterruptedError:
                    continue
                if count <= 0:
                    raise OSError(errno.EIO, "network trace write made no progress")
                written += count
            os.fsync(self._fd)
        except BaseException as exc:
            self._poison_locked("network_trace_durable_append_failed", exc)
        self._logical_bytes += len(line)
        self._row_count += 1
        self._digest.update(line)
        self._validate_identity_locked()

    def _commit_seal_locked(self, line: bytes) -> None:
        """Make the seal durable with fsync as the final fallible operation.

        Once that fsync returns successfully, the caller already holds the
        strictly replayed receipt and performs no further required I/O.  If it
        fails after bytes became visible, reopen without that returned receipt
        remains explicitly uncertified.
        """

        self._validate_identity_locked()
        offset = self._logical_bytes
        written = 0
        try:
            while written < len(line):
                try:
                    count = os.pwrite(self._fd, line[written:], offset + written)
                except InterruptedError:
                    continue
                if count <= 0:
                    raise OSError(errno.EIO, "network trace seal made no progress")
                written += count
            os.fsync(self._fd)
        except BaseException as exc:
            self._poison_locked("network_trace_seal_commit_failed", exc)
        self._logical_bytes += len(line)
        self._row_count += 1
        self._digest.update(line)

    def _encode_locked(self, row: dict) -> bytes:
        return _canonical_line(
            row, max_row_bytes=self._max_row_bytes,
            max_depth=self._max_depth, max_integer=self._max_integer,
        )

    def _fatal_locked(self, code: str) -> None:
        if self._fatal is not None:
            self._accepting = False
            self._cancellation.set()
            return
        code = _validate_identifier(code, field_name="fatal")
        row = {
            "schema": ROW_SCHEMA,
            "sequence": self._row_count,
            "kind": "fatal",
            "component": "trace",
            "previous_sha256": self._digest.hexdigest(),
            "code": code,
            "dropped": 1,
        }
        line = self._encode_locked(row)
        if (self._row_count + self._reserved_rows + 2 > self._max_rows
                or self._logical_bytes + self._reserved_rows * self._max_row_bytes
                + len(line) + self._max_row_bytes > self._max_bytes):
            self._poison_locked("network_trace_fatal_reservation_lost")
        self._write_line_locked(line)
        self._fatal = code
        self._dropped = 1
        self._accepting = False
        self._cancellation.set()

    def _validate_component(self, component_id: str) -> str:
        if type(component_id) is not str or component_id not in self._component_set:
            raise NetworkTraceRefused("network_trace_component_invalid")
        return component_id

    @_drain_after_failure
    def observe(self, component_id: str, operation: str, outcome: str,
                data: dict | None = None) -> None:
        """Durably record one effect-free policy or protocol observation.

        An observation is not contact authorization and has no terminal row.
        It is accepted only while new work is accepted and preserves the two
        control-row footprints needed for a future fatal record and seal.
        """

        with self._lock:
            self._require_live_locked(accepting=True)
            if self._cancellation.is_set():
                self._fatal_locked("network_trace_cancelled")
                raise NetworkTraceRefused("network_trace_cancelled")
            try:
                component_id = self._validate_component(component_id)
                if (type(operation) is not str
                        or operation not in _OPERATIONS[component_id]
                        or type(outcome) is not str
                        or outcome not in _OUTCOMES):
                    raise NetworkTraceRefused(
                        "network_trace_observation_invalid",
                    )
                if data is None:
                    data = {}
                if type(data) is not dict:
                    raise NetworkTraceRefused("network_trace_data_invalid")
                data = _validate_json_value(
                    data, depth=1, maximum_depth=self._max_depth,
                    maximum_integer=self._max_integer,
                    maximum_bytes=self._max_row_bytes,
                )
                row = {
                    "schema": ROW_SCHEMA,
                    "sequence": self._row_count,
                    "kind": "observation",
                    "component": component_id,
                    "previous_sha256": self._digest.hexdigest(),
                    "operation": operation,
                    "outcome": outcome,
                    "data": data,
                }
                line = self._encode_locked(row)
            except NetworkTraceRefused as exc:
                self._fatal_locked("network_trace_observation_invalid")
                raise exc

            rows_after = self._row_count + 1 + self._reserved_rows + 2
            bytes_after = (
                self._logical_bytes + len(line)
                + self._reserved_rows * self._max_row_bytes
                + 2 * self._max_row_bytes
            )
            if rows_after > self._max_rows or bytes_after > self._max_bytes:
                self._fatal_locked("network_trace_capacity_exhausted")
                raise NetworkTraceCapacityError(
                    "network_trace_capacity_exhausted",
                )
            self._write_line_locked(line)

    @_drain_after_failure
    def plan(self, component_id: str, operation: str, data: dict | None = None,
             *, reserve_rows: int = 1) -> TracePlan:
        """Durably record a plan and reserve every possible future row.

        This method does not authorize contact.  After it returns, the caller
        must separately enter the shared effect fence around each short
        nonblocking syscall; cancellation between this return and fence entry
        therefore wins.  At least one reserved row is retained for the
        terminal; additional rows may be consumed with :meth:`event`.
        """

        with self._lock:
            self._require_live_locked(accepting=True)
            if self._cancellation.is_set():
                self._fatal_locked("network_trace_cancelled")
                raise NetworkTraceRefused("network_trace_cancelled")
            try:
                component_id = self._validate_component(component_id)
                if type(operation) is not str \
                        or operation not in _OPERATIONS[component_id]:
                    raise NetworkTraceRefused("network_trace_operation_invalid")
                if data is None:
                    data = {}
                if type(data) is not dict:
                    raise NetworkTraceRefused("network_trace_data_invalid")
                data = _validate_json_value(
                    data, depth=1, maximum_depth=self._max_depth,
                    maximum_integer=self._max_integer,
                    maximum_bytes=self._max_row_bytes,
                )
                if (type(reserve_rows) is not int
                        or not 1 <= reserve_rows
                        <= NETWORK_TRACE_MAX_RESERVED_ROWS):
                    raise NetworkTraceRefused("network_trace_reservation_invalid")
                plan_id = f"{self._row_count:016x}"
                row = {
                    "schema": ROW_SCHEMA,
                    "sequence": self._row_count,
                    "kind": "plan",
                    "component": component_id,
                    "previous_sha256": self._digest.hexdigest(),
                    "operation": operation,
                    "plan_id": plan_id,
                    "data": data,
                    "reservation": {
                        "row_bytes": self._max_row_bytes,
                        "rows": reserve_rows,
                    },
                }
                line = self._encode_locked(row)
            except NetworkTraceRefused as exc:
                self._fatal_locked("network_trace_plan_invalid")
                raise exc

            # One additional row/row-footprint is always held for a durable
            # fatal record.  It is consumed only when accepting another plan
            # would exceed the bounded contract.
            rows_after = (
                self._row_count + 1 + self._reserved_rows + reserve_rows + 2
            )
            bytes_after = (
                self._logical_bytes + len(line)
                + (self._reserved_rows + reserve_rows) * self._max_row_bytes
                + 2 * self._max_row_bytes
            )
            if rows_after > self._max_rows or bytes_after > self._max_bytes:
                self._fatal_locked("network_trace_capacity_exhausted")
                raise NetworkTraceCapacityError(
                    "network_trace_capacity_exhausted",
                )

            self._write_line_locked(line)
            token = TracePlan(
                plan_id, component_id, operation, self._token_owner,
            )
            self._open[plan_id] = _OpenPlan(token, reserve_rows)
            self._reserved_rows += reserve_rows
            return token

    def _open_plan_locked(self, token: TracePlan) -> _OpenPlan:
        if (type(token) is not TracePlan or token._owner is not self._token_owner
                or _PLAN_ID.fullmatch(token.plan_id) is None):
            raise NetworkTraceRefused("network_trace_token_invalid")
        value = self._open.get(token.plan_id)
        if value is None or value.token is not token:
            raise NetworkTraceRefused("network_trace_plan_missing")
        return value

    @_drain_after_failure
    def event(self, token: TracePlan, stage: str,
              data: dict | None = None) -> None:
        """Append one durable intermediate row for an existing plan."""

        with self._lock:
            self._require_live_locked()
            try:
                value = self._open_plan_locked(token)
                stage = _validate_identifier(stage, field_name="stage")
                if stage not in _EVENT_STAGES:
                    raise NetworkTraceRefused("network_trace_stage_invalid")
                if value.remaining_rows <= 1:
                    raise NetworkTraceCapacityError(
                        "network_trace_terminal_reservation_required",
                    )
                if data is None:
                    data = {}
                if type(data) is not dict:
                    raise NetworkTraceRefused("network_trace_data_invalid")
                data = _validate_json_value(
                    data, depth=1, maximum_depth=self._max_depth,
                    maximum_integer=self._max_integer,
                    maximum_bytes=self._max_row_bytes,
                )
                row = {
                    "schema": ROW_SCHEMA,
                    "sequence": self._row_count,
                    "kind": "event",
                    "component": token.component_id,
                    "previous_sha256": self._digest.hexdigest(),
                    "operation": token.operation,
                    "plan_id": token.plan_id,
                    "stage": stage,
                    "data": data,
                }
                line = self._encode_locked(row)
            except NetworkTraceRefused as exc:
                self._fatal_locked("network_trace_event_invalid")
                raise exc
            self._write_line_locked(line)
            value.remaining_rows -= 1
            self._reserved_rows -= 1

    @_drain_after_failure
    def settle(self, token: TracePlan, outcome: str,
               data: dict | None = None) -> None:
        """Durably append the unique terminal row for ``token``."""

        with self._lock:
            self._require_live_locked()
            try:
                value = self._open_plan_locked(token)
            except NetworkTraceRefused as exc:
                self._fatal_locked("network_trace_terminal_unmatched")
                raise exc
            invalid = None
            try:
                if type(outcome) is not str or outcome not in _OUTCOMES:
                    raise NetworkTraceRefused("network_trace_outcome_invalid")
                if data is None:
                    data = {}
                if type(data) is not dict:
                    raise NetworkTraceRefused("network_trace_data_invalid")
                data = _validate_json_value(
                    data, depth=1, maximum_depth=self._max_depth,
                    maximum_integer=self._max_integer,
                    maximum_bytes=self._max_row_bytes,
                )
                row = {
                    "schema": ROW_SCHEMA,
                    "sequence": self._row_count,
                    "kind": "terminal",
                    "component": token.component_id,
                    "previous_sha256": self._digest.hexdigest(),
                    "operation": token.operation,
                    "plan_id": token.plan_id,
                    "outcome": outcome,
                    "data": data,
                }
                line = self._encode_locked(row)
            except NetworkTraceRefused as exc:
                invalid = exc
                row = {
                    "schema": ROW_SCHEMA,
                    "sequence": self._row_count,
                    "kind": "terminal",
                    "component": token.component_id,
                    "previous_sha256": self._digest.hexdigest(),
                    "operation": token.operation,
                    "plan_id": token.plan_id,
                    "outcome": "error",
                    "data": {"code": "network_trace_terminal_invalid"},
                }
                line = self._encode_locked(row)

            self._write_line_locked(line)
            del self._open[token.plan_id]
            self._reserved_rows -= value.remaining_rows
            if invalid is not None:
                self._fatal_locked("network_trace_terminal_invalid")
                raise invalid

    @_drain_after_failure
    def abort_open(self, *, code: str = "invocation_cancelled") -> None:
        """Settle every currently open plan as cancelled, in plan order."""

        code = _validate_identifier(code, field_name="abort")
        with self._lock:
            self._require_live_locked()
            tokens = tuple(
                value.token for _key, value in sorted(self._open.items())
            )
            # Invoke the undecorated body under this one lock so concurrent
            # terminal writers cannot race the snapshot.  If it fails, the
            # outer abort_open decorator drains only after this lock unwinds.
            settle_body = NetworkTraceArtifact.settle.__wrapped__
            for token in tokens:
                settle_body(self, token, "cancelled", {"code": code})

    @contextlib.contextmanager
    def effect(self, component_id: str, operation: str,
               data: dict | None = None, *, reserve_rows: int = 1):
        """Manage a token lifecycle without holding a long network epoch.

        This context does *not* itself grant contact authority.  After the plan
        is durable, callers enter the shared ``NetworkEffectFence`` separately
        around each short nonblocking syscall.  Thus cancellation between plan
        and contact makes that fence entry fail, while cancellation never waits
        behind a DNS/HTTP/relay operation lasting seconds.  Callers settle
        explicitly before leaving.  An exception gets a bounded error terminal;
        returning without a terminal is a durable fatal contract violation.
        """

        if self._effect_fence is None:
            raise NetworkTraceRefused("network_trace_effect_fence_required")
        try:
            missing_terminal = False
            token = self.plan(
                component_id, operation, data,
                reserve_rows=reserve_rows,
            )
            try:
                yield token
            except BaseException:
                with self._lock:
                    open_here = token.plan_id in self._open
                if open_here:
                    self.settle(
                        token, "error", {"code": "effect_raised"},
                    )
                raise
            else:
                with self._lock:
                    open_here = token.plan_id in self._open
                if open_here:
                    self.settle(
                        token, "error", {"code": "effect_unsettled"},
                    )
                    with self._lock:
                        self._fatal_locked(
                            "network_trace_effect_unsettled",
                        )
                    missing_terminal = True
            if missing_terminal:
                self._drain_effect_fence()
                raise NetworkTraceRefused(
                    "network_trace_effect_unsettled",
                )
        except BaseException:
            if self._cancellation.is_set():
                self._drain_effect_fence()
            raise

    @_drain_after_failure
    def finalize(self, decision: str, reason: str) -> dict:
        """Seal, reread, strictly replay, and return the compact settlement.

        Finalization first cancels and synchronously drains the shared network
        fence outside the artifact lock.  Consequently no peer-visible syscall
        epoch can outlive either an allow or deny receipt, and an effect holder
        never waits for this trace lock while cancellation waits for it.

        ``allow`` is a clean-evidence claim and is therefore accepted only
        after every plan has a terminal and no fatal/dropped truth exists.
        ``deny`` may truthfully seal an incomplete invocation; its open plans
        remain visible rather than being silently invented away.
        """

        self._cancellation.set()
        self._drain_effect_fence()
        with self._lock:
            if self._final_settlement is not None:
                if (decision, reason) != (
                        self._final_decision, self._final_reason):
                    raise NetworkTraceRefused(
                        "network_trace_finalization_conflict",
                    )
                return json.loads(json.dumps(self._final_settlement))
            self._require_live_locked()
            if (type(decision) is not str or decision not in _DECISIONS
                    or type(reason) is not str
                    or _IDENTIFIER.fullmatch(reason) is None):
                self._fatal_locked("network_trace_finalization_invalid")
                raise NetworkTraceRefused("network_trace_finalization_invalid")
            if decision == "allow" and (
                    self._open or self._fatal is not None or self._dropped):
                if self._fatal is None:
                    self._fatal_locked("network_trace_allow_incomplete")
                raise NetworkTraceRefused("network_trace_allow_incomplete")
            seal = {
                "schema": ROW_SCHEMA,
                "sequence": self._row_count,
                "kind": "seal",
                "component": "trace",
                "previous_sha256": self._digest.hexdigest(),
                "decision": decision,
                "reason": reason,
            }
            line = self._encode_locked(seal)
            if (self._row_count + self._reserved_rows + 1 > self._max_rows
                    or self._logical_bytes
                    + self._reserved_rows * self._max_row_bytes
                    + len(line) > self._max_bytes):
                self._poison_locked("network_trace_seal_reservation_lost")
            before = self._validate_identity_locked()
            body = _read_descriptor(self._fd, self._logical_bytes)
            after = self._validate_identity_locked()
            if (int(before.st_mtime_ns), int(before.st_ctime_ns), int(before.st_size)) != (
                    int(after.st_mtime_ns), int(after.st_ctime_ns), int(after.st_size)):
                self._poison_locked("network_trace_changed_during_replay")
            replay = _replay_body(
                body, invocation_id=self._invocation_id,
                artifact_relpath=self._artifact_relpath,
                components=self._components, max_rows=self._max_rows,
                max_bytes=self._max_bytes, max_row_bytes=self._max_row_bytes,
                max_depth=self._max_depth, max_integer=self._max_integer,
            )
            if (replay["sha256"] != self._digest.hexdigest()
                    or replay["bytes"] != self._logical_bytes
                    or replay["rows"] != self._row_count
                    or replay["open_plans"] != len(self._open)
                    or replay["fatal"] != self._fatal
                    or replay["dropped_rows"] != self._dropped
                    or replay["decision"] is not None
                    or replay["reason"] is not None):
                self._poison_locked("network_trace_replay_parity_failed")
            future_eof = self._logical_bytes + len(line)
            try:
                _release_preallocation_tail(
                    self._fd, current_eof=self._logical_bytes,
                    future_eof=future_eof,
                    envelope_bytes=self._max_bytes,
                )
                os.fsync(self._fd)
            except BaseException as exc:
                self._poison_locked(
                    "network_trace_precommit_release_failed", exc,
                )
            release_before = self._validate_identity_locked()
            released_body = _read_descriptor(self._fd, self._logical_bytes)
            release_after = self._validate_identity_locked()
            if (released_body != body
                    or (int(release_before.st_mtime_ns),
                        int(release_before.st_ctime_ns),
                        int(release_before.st_size))
                    != (int(release_after.st_mtime_ns),
                        int(release_after.st_ctime_ns),
                        int(release_after.st_size))):
                self._poison_locked(
                    "network_trace_release_revalidation_failed",
                )
            candidate = released_body + line
            committed_replay = _replay_body(
                candidate, invocation_id=self._invocation_id,
                artifact_relpath=self._artifact_relpath,
                components=self._components, max_rows=self._max_rows,
                max_bytes=self._max_bytes,
                max_row_bytes=self._max_row_bytes,
                max_depth=self._max_depth, max_integer=self._max_integer,
            )
            if (committed_replay["decision"] != decision
                    or committed_replay["reason"] != reason):
                self._poison_locked("network_trace_seal_replay_failed")
            value = _settlement(committed_replay, certified=True)
            # Commit point.  No required operation follows this fsync.
            self._commit_seal_locked(line)
            self._sealed = True
            self._accepting = False
            self._final_settlement = value
            self._final_decision = decision
            self._final_reason = reason
            return json.loads(json.dumps(value))

    settlement = finalize

    def close(self) -> None:
        # Closing the only durable writer is a terminal network transition.
        # Drain outside the trace lock so an in-flight short syscall epoch can
        # exit even if its owner subsequently attempts a terminal append.
        self._cancellation.set()
        drain_failure = None
        try:
            self._drain_effect_fence()
        except BaseException as exc:
            drain_failure = exc
        with self._lock:
            if self._closed:
                if drain_failure is not None:
                    raise NetworkTraceIntegrityError(
                        "network_trace_close_cancel_failed",
                    ) from drain_failure
                return
            descriptor, parent_fd = self._fd, self._parent_fd
            self._fd = -1
            self._parent_fd = -1
            self._closed = True
        failures = []
        for value in (descriptor, parent_fd):
            if value >= 0:
                try:
                    os.close(value)
                except OSError as exc:
                    failures.append(exc)
        if drain_failure is not None:
            raise NetworkTraceIntegrityError(
                "network_trace_close_cancel_failed",
            ) from drain_failure
        if failures:
            raise NetworkTraceIntegrityError("network_trace_close_failed") from failures[0]

    def __enter__(self) -> "NetworkTraceArtifact":
        return self

    def __exit__(self, _kind, _value, _traceback) -> bool:
        self.close()
        return False


def replay_network_trace(directory_fd: int, invocation_id: str,
                         artifact_relpath: str, *,
                         expected_settlement: dict | None = None,
                         max_rows: int = NETWORK_TRACE_MAX_ROWS,
                         max_bytes: int = NETWORK_TRACE_MAX_BYTES,
                         max_row_bytes: int = NETWORK_TRACE_MAX_ROW_BYTES,
                         max_depth: int = NETWORK_TRACE_MAX_JSON_DEPTH,
                         max_integer: int = NETWORK_TRACE_MAX_INTEGER_MAGNITUDE,
                         components: tuple[str, ...] = COMPONENT_IDS) -> dict:
    """Reopen the fixed artifact by descriptor and verify exact replay parity."""

    artifact_relpath = _validate_artifact_relpath(artifact_relpath)
    _validate_limits(
        max_rows=max_rows, max_bytes=max_bytes,
        max_row_bytes=max_row_bytes, max_depth=max_depth,
        max_integer=max_integer,
    )
    if (type(directory_fd) is not int or directory_fd < 0
            or type(invocation_id) is not str
            or _INVOCATION_ID.fullmatch(invocation_id) is None
            or type(components) is not tuple or not components
            or len(components) > NETWORK_TRACE_MAX_COMPONENTS
            or any(type(value) is not str or value not in _COMPONENT_SET
                   for value in components)
            or len(set(components)) != len(components)):
        raise NetworkTraceRefused("network_trace_replay_arguments_invalid")
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = os.dup(directory_fd)
        _set_cloexec(parent_fd)
        parent_before = os.fstat(parent_fd)
        _check_parent(parent_before)
        if os.listdir(parent_fd) != [ARTIFACT_NAME]:
            raise NetworkTraceIntegrityError(
                "network_trace_parent_not_dedicated",
            )
        descriptor = os.open(ARTIFACT_NAME, _READ_FLAGS, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        named_before = os.stat(
            ARTIFACT_NAME, dir_fd=parent_fd, follow_symlinks=False,
        )
        _check_file(before, maximum_bytes=max_bytes)
        _check_file(named_before, maximum_bytes=max_bytes)
        if not _same_file(before, named_before):
            raise NetworkTraceIntegrityError("network_trace_file_name_changed")
        body = _read_descriptor(descriptor, int(before.st_size))
        after = os.fstat(descriptor)
        named_after = os.stat(
            ARTIFACT_NAME, dir_fd=parent_fd, follow_symlinks=False,
        )
        parent_after = os.fstat(parent_fd)
        _check_file(after, maximum_bytes=max_bytes)
        _check_file(named_after, maximum_bytes=max_bytes)
        _check_parent(parent_after)
        if (not _same_file(before, after) or not _same_file(after, named_after)
                or _ParentIdentity.from_stat(parent_before)
                != _ParentIdentity.from_stat(parent_after)
                or (int(before.st_size), int(before.st_mtime_ns), int(before.st_ctime_ns))
                != (int(after.st_size), int(after.st_mtime_ns), int(after.st_ctime_ns))):
            raise NetworkTraceIntegrityError("network_trace_changed_during_replay")
        replay = _replay_body(
            body, invocation_id=invocation_id,
            artifact_relpath=artifact_relpath,
            components=components, max_rows=max_rows,
            max_bytes=max_bytes, max_row_bytes=max_row_bytes,
            max_depth=max_depth, max_integer=max_integer,
        )
        candidate = _settlement(replay, certified=True)
        if expected_settlement is not None:
            if type(expected_settlement) is not dict:
                raise NetworkTraceIntegrityError(
                    "network_trace_expected_settlement_invalid",
                )
            if not _strict_receipt_equal(expected_settlement, candidate):
                raise NetworkTraceIntegrityError(
                    "network_trace_settlement_parity_failed",
                )
            return candidate
        return _settlement(replay, certified=False)
    except NetworkTraceError:
        raise
    except OSError as exc:
        raise NetworkTraceIntegrityError("network_trace_replay_open_failed") from exc
    finally:
        for value in (descriptor, parent_fd):
            if value >= 0:
                try:
                    os.close(value)
                except OSError:
                    pass


__all__ = (
    "ARTIFACT_NAME", "COMPONENT_IDS", "NETWORK_TRACE_MAX_BYTES",
    "NETWORK_TRACE_MAX_COMPONENTS", "NETWORK_TRACE_MAX_INTEGER_MAGNITUDE",
    "NETWORK_TRACE_MAX_JSON_DEPTH", "NETWORK_TRACE_MAX_RELPATH_BYTES",
    "NETWORK_TRACE_MAX_ALLOCATION_GRANULARITY",
    "NETWORK_TRACE_MAX_RESERVED_ROWS", "NETWORK_TRACE_MAX_ROWS",
    "NETWORK_TRACE_MAX_ROW_BYTES", "NETWORK_TRACE_MAX_SETTLEMENT_BYTES",
    "NETWORK_TRACE_MIN_ALLOCATION_GRANULARITY",
    "NETWORK_TRACE_READ_CHUNK_BYTES", "NetworkTraceArtifact",
    "NetworkTraceCapacityError", "NetworkTraceError",
    "NetworkTraceIntegrityError", "NetworkTraceRefused", "ROW_SCHEMA",
    "SETTLEMENT_SCHEMA", "TracePlan",
    "replay_network_trace",
)
