"""Strict, bounded records for Quarry's killable execution boundary.

This module is deliberately pure: it does not inspect PATH, open a file, read the
ambient environment, create a process, or publish an artifact.  The runner facade
normalizes an invocation here before it crosses any of those side-effect boundaries;
the future worker and parent exchange only the versioned JSON frames defined here.

Canonical target evidence is not redacted by this protocol.  Conversely, request
arguments and environments may contain Quarry credentials, so record reprs and
validation errors never include their values.  Frames are private control traffic and
must never be copied into events or reports.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import (Path, PosixPath, PurePath, PurePosixPath,
                     PureWindowsPath, WindowsPath)

# Version 1 has not yet had a production caller or persisted transcript.  The
# PREPARED launch handshake was added while this protocol was still preparatory,
# before compatibility with an external peer or stored frame existed.
PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 1 << 20
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 16_384
MAX_JSON_INTEGER_DIGITS = 16
MAX_ARGV_ITEMS = 16_384
MAX_ENV_ITEMS = 16_384
MAX_ARGV_BYTES = 384 * 1024
MAX_ENV_BYTES = 384 * 1024
MAX_STDIN_DATA_BYTES = MAX_FRAME_BYTES * 16
MAX_TEXT_BYTES = 256 * 1024
MAX_PATH_BYTES = 4096
MAX_DIAGNOSTIC_BYTES = 64
MAX_DETAIL_BYTES = MAX_DIAGNOSTIC_BYTES
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_EXIT_CODES = 256
MIN_EXIT_CODE = -(1 << 31)
MAX_EXIT_CODE = (1 << 31) - 1
MAX_PID = (1 << 31) - 1

_HEX = frozenset("0123456789abcdef")
_DIGEST_EMPTY = hashlib.sha256(b"").hexdigest()
_VALIDATION_AUTHORITY = object()
_PATH_TYPES = frozenset({
    Path, PurePath, PosixPath, PurePosixPath, PureWindowsPath, WindowsPath,
})


class ProtocolError(ValueError):
    """A request, settlement, or control frame violates the protocol.

    ``code`` and ``field`` are safe for telemetry.  The human message is assembled
    exclusively from those fixed labels and never embeds a rejected value.
    """

    def __init__(self, code: str, field_name: str | None = None) -> None:
        self.code = code
        self.field_name = field_name
        message = code if field_name is None else f"{code}: {field_name}"
        super().__init__(message)


class StdinMode(str, Enum):
    NULL = "null"
    DATA = "data"
    FILE = "file"


class StreamRole(str, Enum):
    STDIN = "stdin"
    STDOUT = "stdout"
    STDERR = "stderr"


class StreamTerminal(str, Enum):
    NOT_STARTED = "not_started"
    COMPLETE = "complete"
    EOF = "eof"
    PEER_CLOSED = "peer_closed"
    CANCELLED = "cancelled"
    DEADLINE = "deadline"
    SOURCE_ERROR = "source_error"
    SINK_ERROR = "sink_error"
    CAPPED = "capped"
    WORKER_CRASH = "worker_crash"


class ExecutionTerminal(str, Enum):
    COMPLETE = "complete"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    LAUNCH_FAILED = "launch_failed"
    WORKER_FAILED = "worker_failed"


class ContainmentKind(str, Enum):
    PGID = "pgid"
    CGROUP_V2 = "cgroup_v2"


def new_request_id(random_bytes: bytes) -> str:
    """Turn exactly 16 caller-supplied random bytes into a request correlation id."""
    if type(random_bytes) is not bytes or len(random_bytes) != 16:
        raise ProtocolError("invalid request id entropy", "request_id")
    return random_bytes.hex()


def _exact_string(value, field_name: str, *, allow_empty: bool = False,
                  max_bytes: int = MAX_TEXT_BYTES) -> str:
    if type(value) is not str:
        raise ProtocolError("invalid string", field_name)
    if not allow_empty and not value:
        raise ProtocolError("empty string", field_name)
    if "\x00" in value:
        raise ProtocolError("NUL is forbidden", field_name)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ProtocolError("invalid unicode", field_name) from None
    if size > max_bytes:
        raise ProtocolError("text exceeds limit", field_name)
    return value


def _bounded_int(value, field_name: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ProtocolError("invalid bounded integer", field_name)
    return value


def _nonnegative_int(value, field_name: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER:
        raise ProtocolError("invalid non-negative integer", field_name)
    return value


def _positive_int(value, field_name: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_PID:
        raise ProtocolError("invalid positive integer", field_name)
    return value


def _optional_digest(value, field_name: str) -> str | None:
    if value is None:
        return None
    if (type(value) is not str or len(value) != 64
            or any(ch not in _HEX for ch in value)):
        raise ProtocolError("invalid sha256 digest", field_name)
    return value


def _request_id(value) -> str:
    value = _exact_string(value, "request_id")
    if len(value) != 32 or any(ch not in _HEX for ch in value):
        raise ProtocolError("invalid request id", "request_id")
    return value


def _claim_id(value, field_name: str = "claim_id") -> str:
    value = _exact_string(value, field_name)
    if len(value) != 32 or any(ch not in _HEX for ch in value):
        raise ProtocolError("invalid claim id", field_name)
    return value


def _derived_claim_id(request_id: str, role: StreamRole) -> str:
    material = b"quarry-runner-claim-v1\0" + bytes.fromhex(request_id) + role.value.encode()
    return hashlib.sha256(material).hexdigest()[:32]


def _timeout(value) -> int | float:
    if type(value) not in (int, float):
        raise ProtocolError("invalid timeout", "timeout")
    if type(value) is int:
        if value < 0 or value > MAX_SAFE_INTEGER:
            raise ProtocolError("invalid timeout", "timeout")
        return value
    if (value < 0 or value > MAX_SAFE_INTEGER or not math.isfinite(value)
            or (value == 0.0 and math.copysign(1.0, value) < 0)):
        raise ProtocolError("invalid timeout", "timeout")
    return int(value) if value.is_integer() else value


def _path_text(value, field_name: str) -> str:
    if type(value) is str:
        text = value
    elif type(value) in _PATH_TYPES:
        text = str(value)
    else:
        raise ProtocolError("invalid path", field_name)
    _exact_string(text, field_name, max_bytes=MAX_PATH_BYTES)
    # Pure lexical anchoring: this neither resolves symlinks nor touches the filesystem.
    try:
        return os.path.abspath(os.path.normpath(text))
    except (OSError, ValueError):
        raise ProtocolError("path cannot be normalized", field_name) from None


def _optional_path(value, field_name: str) -> str | None:
    return None if value is None else _path_text(value, field_name)


def _enum(enum_type, value, field_name: str):
    if type(value) is not str:
        raise ProtocolError("invalid enum", field_name)
    try:
        return enum_type(value)
    except ValueError:
        raise ProtocolError("unknown enum", field_name) from None


def _exact_keys(doc: dict, expected: frozenset[str], field_name: str) -> None:
    if type(doc) is not dict:
        raise ProtocolError("expected object", field_name)
    if any(type(key) is not str for key in doc):
        raise ProtocolError("invalid object key", field_name)
    keys = frozenset(doc)
    if keys != expected:
        raise ProtocolError("object keys do not match schema", field_name)


def _json_string_size(value: str) -> int:
    """Exact UTF-8 size of one ``ensure_ascii=False`` JSON string.

    Values have already passed the per-string bound.  This does not construct a
    combined argv/environment serialization, so aggregate refusal occurs before a
    potentially enormous temporary allocation.
    """
    raw_size = len(value.encode("utf-8"))
    extra = 0
    for char in value:
        if char in ('"', "\\") or char in "\b\f\n\r\t":
            extra += 1
        elif ord(char) < 0x20:
            extra += 5
    return raw_size + extra + 2


def _add_json_string_size(total: int, value: str, limit: int,
                          field_name: str, *, separator: int = 0) -> int:
    total += separator + _json_string_size(value)
    if total > limit:
        raise ProtocolError("value exceeds aggregate limit", field_name)
    return total


def _diagnostic_code(value) -> str | None:
    if value is None:
        return None
    value = _exact_string(value, "diagnostic_code", max_bytes=MAX_DIAGNOSTIC_BYTES)
    if any(not (ch.isascii() and (ch.islower() or ch.isdigit() or ch in "._-"))
           for ch in value):
        raise ProtocolError("invalid diagnostic code", "diagnostic_code")
    return value


def _containment_id(value) -> str:
    value = _exact_string(value, "containment_id", max_bytes=512)
    if (value.startswith("/") or value.endswith("/") or "//" in value
            or any(part in ("", ".", "..") for part in value.split("/"))
            or any(not (ch.isascii() and (ch.isalnum() or ch in "._-/"))
                   for ch in value)):
        raise ProtocolError("invalid containment id", "containment_id")
    return value


_ROLE_ORDER = {role: index for index, role in enumerate(StreamRole)}


@dataclass(frozen=True)
class DescriptorClaim:
    """Logical role for one descriptor transferred out of band.

    The identifier correlates request, stream, and parent-local proof records. It is
    deliberately not a filesystem path or an authority token.
    """

    role: StreamRole
    claim_id: str

    def __post_init__(self) -> None:
        if type(self.role) is not StreamRole:
            raise ProtocolError("invalid stream enum", "claim.role")
        _claim_id(self.claim_id, "claim.claim_id")

    def to_dict(self) -> dict:
        return {"role": self.role.value, "claim_id": self.claim_id}

    @classmethod
    def from_dict(cls, doc: dict) -> "DescriptorClaim":
        _exact_keys(doc, frozenset({"role", "claim_id"}), "claim")
        return cls(role=_enum(StreamRole, doc["role"], "claim.role"),
                   claim_id=doc["claim_id"])


@dataclass(frozen=True, repr=False)
class WorkerRequest:
    """The bounded control-plane portion of one normalized invocation.

    Stdin bytes and input/output descriptors travel out of band. ``environment`` is
    the effective launch environment captured by the parent at invocation time, not a
    worker-global snapshot.  It is serialized only onto private IPC.
    """

    request_id: str
    tool: str
    argv: tuple[str, ...] = field(repr=False)
    timeout: int | float
    ok_empty: bool
    ok_codes: tuple[int, ...]
    environment: tuple[tuple[str, str], ...] = field(repr=False)
    cwd: str | None = field(repr=False)
    stdin_mode: StdinMode
    stdin_bytes: int | None
    stdin_sha256: str | None = field(repr=False)
    descriptor_claims: tuple[DescriptorClaim, ...]
    max_output_bytes: int | None

    def __post_init__(self) -> None:
        _request_id(self.request_id)
        _exact_string(self.tool, "tool")
        if type(self.argv) is not tuple or not self.argv or len(self.argv) > MAX_ARGV_ITEMS:
            raise ProtocolError("invalid argv", "argv")
        argv_size = 2
        for index, arg in enumerate(self.argv):
            _exact_string(arg, "argv.item", allow_empty=True)
            argv_size = _add_json_string_size(
                argv_size, arg, MAX_ARGV_BYTES, "argv", separator=int(index > 0))
        if not self.argv[0]:
            raise ProtocolError("empty executable", "argv[0]")
        object.__setattr__(self, "timeout", _timeout(self.timeout))
        if type(self.ok_empty) is not bool:
            raise ProtocolError("invalid boolean", "ok_empty")
        if (type(self.ok_codes) is not tuple or not self.ok_codes
                or len(self.ok_codes) > MAX_EXIT_CODES):
            raise ProtocolError("invalid exit-code set", "ok_codes")
        for code in self.ok_codes:
            _bounded_int(code, "ok_codes.item", minimum=MIN_EXIT_CODE,
                         maximum=MAX_EXIT_CODE)
        if len(set(self.ok_codes)) != len(self.ok_codes):
            raise ProtocolError("duplicate exit code", "ok_codes")
        if type(self.environment) is not tuple or len(self.environment) > MAX_ENV_ITEMS:
            raise ProtocolError("invalid environment", "environment")
        prior = None
        environment_size = 2
        for index, pair in enumerate(self.environment):
            if type(pair) is not tuple or len(pair) != 2:
                raise ProtocolError("invalid environment entry", "environment.item")
            key = _exact_string(pair[0], "environment.key")
            value = _exact_string(pair[1], "environment.value", allow_empty=True)
            if "=" in key:
                raise ProtocolError("invalid environment key", "environment.key")
            if prior is not None and key <= prior:
                raise ProtocolError("environment is not unique and sorted", "environment")
            prior = key
            environment_size = _add_json_string_size(
                environment_size, key, MAX_ENV_BYTES, "environment",
                separator=int(index > 0))
            environment_size += 1  # colon
            environment_size = _add_json_string_size(
                environment_size, value, MAX_ENV_BYTES, "environment")
        if self.cwd is not None:
            if self.cwd != _path_text(self.cwd, "cwd"):
                raise ProtocolError("path is not normalized", "cwd")
        if type(self.stdin_mode) is not StdinMode:
            raise ProtocolError("invalid enum", "stdin_mode")
        if (type(self.descriptor_claims) is not tuple
                or len(self.descriptor_claims) > len(StreamRole)):
            raise ProtocolError("invalid descriptor claims", "claims")
        if any(type(claim) is not DescriptorClaim for claim in self.descriptor_claims):
            raise ProtocolError("invalid descriptor claim", "claims")
        roles = tuple(claim.role for claim in self.descriptor_claims)
        if len(set(roles)) != len(roles):
            raise ProtocolError("duplicate descriptor role", "claims")
        if tuple(sorted(roles, key=_ROLE_ORDER.__getitem__)) != roles:
            raise ProtocolError("descriptor claims are not canonical", "claims")
        if (StreamRole.STDIN in roles) != (self.stdin_mode is StdinMode.FILE):
            raise ProtocolError("stdin descriptor claim mismatch", "claims")
        for claim in self.descriptor_claims:
            if claim.claim_id != _derived_claim_id(self.request_id, claim.role):
                raise ProtocolError("descriptor claim does not bind request", "claim_id")
        if self.max_output_bytes is not None:
            _nonnegative_int(self.max_output_bytes, "max_output_bytes")
            if not self.stdout_requested:
                raise ProtocolError("output cap requires stdout", "max_output_bytes")
        digest = _optional_digest(self.stdin_sha256, "stdin_sha256")
        if self.stdin_mode is StdinMode.DATA:
            if self.stdin_bytes is None:
                raise ProtocolError("data stdin needs a size", "stdin_bytes")
            _nonnegative_int(self.stdin_bytes, "stdin_bytes")
            if self.stdin_bytes > MAX_STDIN_DATA_BYTES:
                raise ProtocolError("data stdin exceeds limit", "stdin_bytes")
            if digest is None:
                raise ProtocolError("data stdin needs a digest", "stdin_sha256")
        elif self.stdin_bytes is not None or digest is not None:
            raise ProtocolError("non-data stdin has data metadata", "stdin_mode")

    @property
    def stdout_requested(self) -> bool:
        return self.claim_for(StreamRole.STDOUT) is not None

    @property
    def stderr_requested(self) -> bool:
        return self.claim_for(StreamRole.STDERR) is not None

    def claim_for(self, role: StreamRole) -> DescriptorClaim | None:
        return next((claim for claim in self.descriptor_claims if claim.role is role), None)

    def __repr__(self) -> str:
        return (f"WorkerRequest(request_id={self.request_id!r}, tool={self.tool!r}, "
                f"argv_items={len(self.argv)}, environment_items={len(self.environment)}, "
                f"stdin_mode={self.stdin_mode.value!r})")

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "tool": self.tool,
            "argv": list(self.argv),
            "timeout": self.timeout,
            "ok_empty": self.ok_empty,
            "ok_codes": list(self.ok_codes),
            "environment": {key: value for key, value in self.environment},
            "cwd": self.cwd,
            "stdin_mode": self.stdin_mode.value,
            "stdin_bytes": self.stdin_bytes,
            "stdin_sha256": self.stdin_sha256,
            "descriptor_claims": [claim.to_dict() for claim in self.descriptor_claims],
            "max_output_bytes": self.max_output_bytes,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "WorkerRequest":
        expected = frozenset({
            "request_id", "tool", "argv", "timeout", "ok_empty", "ok_codes",
            "environment", "cwd", "stdin_mode", "stdin_bytes", "stdin_sha256",
            "descriptor_claims", "max_output_bytes",
        })
        _exact_keys(doc, expected, "request")
        if (type(doc["argv"]) is not list or type(doc["ok_codes"]) is not list
                or type(doc["descriptor_claims"]) is not list):
            raise ProtocolError("expected array", "request")
        if (not doc["argv"] or len(doc["argv"]) > MAX_ARGV_ITEMS
                or not doc["ok_codes"] or len(doc["ok_codes"]) > MAX_EXIT_CODES
                or len(doc["descriptor_claims"]) > len(StreamRole)):
            raise ProtocolError("request collection exceeds limit", "request")
        environment = doc["environment"]
        if type(environment) is not dict:
            raise ProtocolError("expected object", "environment")
        if len(environment) > MAX_ENV_ITEMS:
            raise ProtocolError("environment exceeds limit", "environment")
        normalized_environment = []
        environment_size = 2
        for index, (key, value) in enumerate(environment.items()):
            _exact_string(key, "environment.key")
            _exact_string(value, "environment.value", allow_empty=True)
            environment_size = _add_json_string_size(
                environment_size, key, MAX_ENV_BYTES, "environment",
                separator=int(index > 0))
            environment_size += 1
            environment_size = _add_json_string_size(
                environment_size, value, MAX_ENV_BYTES, "environment")
            normalized_environment.append((key, value))
        return cls(
            request_id=doc["request_id"], tool=doc["tool"], argv=tuple(doc["argv"]),
            timeout=doc["timeout"], ok_empty=doc["ok_empty"],
            ok_codes=tuple(doc["ok_codes"]),
            environment=tuple(sorted(normalized_environment)), cwd=doc["cwd"],
            stdin_mode=_enum(StdinMode, doc["stdin_mode"], "stdin_mode"),
            stdin_bytes=doc["stdin_bytes"], stdin_sha256=doc["stdin_sha256"],
            descriptor_claims=tuple(
                DescriptorClaim.from_dict(claim) for claim in doc["descriptor_claims"]),
            max_output_bytes=doc["max_output_bytes"],
        )


@dataclass(frozen=True, repr=False)
class NormalizedInvocation:
    """Parent-local request plus out-of-band payload/path claims."""

    worker: WorkerRequest
    stdin_data: bytes | None = field(default=None, repr=False)
    input_file: str | None = field(default=None, repr=False)
    raw_path: str | None = field(default=None, repr=False)
    stderr_path: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.worker) is not WorkerRequest:
            raise ProtocolError("invalid worker request", "worker")
        if self.worker.stdin_mode is StdinMode.DATA:
            if type(self.stdin_data) is not bytes:
                raise ProtocolError("missing stdin payload", "stdin_data")
            if len(self.stdin_data) != self.worker.stdin_bytes:
                raise ProtocolError("stdin payload size mismatch", "stdin_data")
            if hashlib.sha256(self.stdin_data).hexdigest() != self.worker.stdin_sha256:
                raise ProtocolError("stdin payload digest mismatch", "stdin_data")
        elif self.stdin_data is not None:
            raise ProtocolError("unexpected stdin payload", "stdin_data")
        if self.worker.stdin_mode is StdinMode.FILE:
            if self.input_file is None:
                raise ProtocolError("missing stdin file", "input_file")
        elif self.input_file is not None:
            raise ProtocolError("unexpected stdin file", "input_file")
        for name in ("input_file", "raw_path", "stderr_path"):
            value = getattr(self, name)
            if value is not None and value != _path_text(value, name):
                raise ProtocolError("path is not normalized", name)
        if self.worker.stdout_requested != (self.raw_path is not None):
            raise ProtocolError("stdout claim mismatch", "raw_path")
        if self.worker.stderr_requested != (self.stderr_path is not None):
            raise ProtocolError("stderr claim mismatch", "stderr_path")
        paths = [p for p in (self.input_file, self.raw_path, self.stderr_path) if p is not None]
        if len(paths) != len(set(paths)):
            raise ProtocolError("path claims alias", "paths")

    def __repr__(self) -> str:
        return f"NormalizedInvocation(worker={self.worker!r})"


def normalize_invocation(*, request_id, tool, cmd, timeout=1800, stdin_data=None,
                         input_file=None, ok_empty=True, ok_codes=(0,), env=None,
                         base_environment=None, cwd=None, raw_path=None, stderr_path=None,
                         max_output_bytes=None) -> NormalizedInvocation:
    """Validate and normalize the current runner facade without side effects."""
    rid = _request_id(request_id)
    tool = _exact_string(tool, "tool")
    if type(cmd) not in (list, tuple) or not cmd or len(cmd) > MAX_ARGV_ITEMS:
        raise ProtocolError("invalid argv", "cmd")
    argv_items = []
    argv_size = 2
    for index, arg in enumerate(cmd):
        arg = _exact_string(arg, "cmd.item", allow_empty=True)
        argv_size = _add_json_string_size(
            argv_size, arg, MAX_ARGV_BYTES, "cmd", separator=int(index > 0))
        argv_items.append(arg)
    argv = tuple(argv_items)
    if not argv[0]:
        raise ProtocolError("empty executable", "cmd[0]")
    timeout = _timeout(timeout)
    if type(ok_empty) is not bool:
        raise ProtocolError("invalid boolean", "ok_empty")
    if type(ok_codes) not in (list, tuple) or not ok_codes:
        raise ProtocolError("invalid exit-code set", "ok_codes")
    codes = tuple(ok_codes)
    if len(codes) > MAX_EXIT_CODES:
        raise ProtocolError("invalid exit-code set", "ok_codes")
    for code in codes:
        _bounded_int(code, "ok_codes.item", minimum=MIN_EXIT_CODE,
                     maximum=MAX_EXIT_CODE)
    if len(set(codes)) != len(codes):
        raise ProtocolError("duplicate exit code", "ok_codes")
    if env is not None and type(env) is not dict:
        raise ProtocolError("invalid environment", "env")
    if type(base_environment) is not dict:
        raise ProtocolError("invalid environment", "base_environment")
    merged: dict[str, str] = {}
    for label, source in (("base_environment", base_environment), ("env", env or {})):
        if len(source) > MAX_ENV_ITEMS:
            raise ProtocolError("environment exceeds limit", label)
        source_size = 2
        for index, (key, value) in enumerate(source.items()):
            key = _exact_string(key, f"{label}.key")
            value = _exact_string(value, f"{label}.value", allow_empty=True)
            if "=" in key:
                raise ProtocolError("invalid environment key", f"{label}.key")
            source_size = _add_json_string_size(
                source_size, key, MAX_ENV_BYTES, label, separator=int(index > 0))
            source_size += 1
            source_size = _add_json_string_size(
                source_size, value, MAX_ENV_BYTES, label)
            merged[key] = value
    if len(merged) > MAX_ENV_ITEMS:
        raise ProtocolError("environment exceeds limit", "environment")
    if stdin_data is not None and input_file is not None:
        raise ProtocolError("multiple stdin sources", "stdin")
    payload = None
    input_path = _optional_path(input_file, "input_file")
    if stdin_data is not None:
        if type(stdin_data) is not str:
            raise ProtocolError("invalid string", "stdin_data")
        try:
            payload = stdin_data.encode("utf-8")
        except UnicodeEncodeError:
            raise ProtocolError("invalid unicode", "stdin_data") from None
        if len(payload) > MAX_STDIN_DATA_BYTES:
            raise ProtocolError("text exceeds limit", "stdin_data")
        stdin_mode = StdinMode.DATA
        stdin_bytes = len(payload)
        stdin_sha256 = hashlib.sha256(payload).hexdigest()
    elif input_path is not None:
        stdin_mode, stdin_bytes, stdin_sha256 = StdinMode.FILE, None, None
    else:
        stdin_mode, stdin_bytes, stdin_sha256 = StdinMode.NULL, None, None
    raw = _optional_path(raw_path, "raw_path")
    stderr = _optional_path(stderr_path, "stderr_path")
    cwd_text = _optional_path(cwd, "cwd")
    if max_output_bytes is not None:
        _nonnegative_int(max_output_bytes, "max_output_bytes")
        if raw is None:
            raise ProtocolError("output cap requires stdout", "max_output_bytes")
    claimed_roles = []
    if input_path is not None:
        claimed_roles.append(StreamRole.STDIN)
    if raw is not None:
        claimed_roles.append(StreamRole.STDOUT)
    if stderr is not None:
        claimed_roles.append(StreamRole.STDERR)
    claims = tuple(DescriptorClaim(role, _derived_claim_id(rid, role))
                   for role in claimed_roles)
    worker = WorkerRequest(
        request_id=rid, tool=tool, argv=argv, timeout=timeout,
        ok_empty=ok_empty, ok_codes=codes,
        environment=tuple(sorted(merged.items())), cwd=cwd_text,
        stdin_mode=stdin_mode, stdin_bytes=stdin_bytes, stdin_sha256=stdin_sha256,
        descriptor_claims=claims,
        max_output_bytes=max_output_bytes,
    )
    # A normalized invocation must be frameable; callers may not discover a
    # control-plane size failure after staging descriptors or launching a worker.
    encode_request(worker)
    return NormalizedInvocation(worker=worker, stdin_data=payload, input_file=input_path,
                                raw_path=raw, stderr_path=stderr)


@dataclass(frozen=True, repr=False)
class StreamSettlement:
    role: StreamRole
    terminal: StreamTerminal
    observed_bytes: int
    retained_bytes: int
    observed_sha256: str | None = field(repr=False)
    retained_sha256: str | None = field(repr=False)
    claim_id: str | None = None
    lines: int = 0
    detail: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.role) is not StreamRole or type(self.terminal) is not StreamTerminal:
            raise ProtocolError("invalid stream enum", "stream")
        _nonnegative_int(self.observed_bytes, "observed_bytes")
        _nonnegative_int(self.retained_bytes, "retained_bytes")
        _nonnegative_int(self.lines, "lines")
        observed_digest = _optional_digest(self.observed_sha256, "observed_sha256")
        retained_digest = _optional_digest(self.retained_sha256, "retained_sha256")
        if self.claim_id is not None:
            _claim_id(self.claim_id)
        _diagnostic_code(self.detail)
        if self.terminal is StreamTerminal.NOT_STARTED:
            if (self.observed_bytes != 0 or self.retained_bytes != 0
                    or observed_digest is not None or retained_digest is not None
                    or self.claim_id is not None or self.lines != 0):
                raise ProtocolError("unstarted stream has activity", "stream")
            return
        if (self.terminal in (StreamTerminal.COMPLETE, StreamTerminal.EOF,
                              StreamTerminal.CAPPED)
                and observed_digest is None):
            raise ProtocolError("complete stream needs observed digest", "observed_sha256")
        if self.role is StreamRole.STDIN:
            if (self.retained_bytes != 0 or retained_digest is not None
                    or self.claim_id is not None or self.lines != 0):
                raise ProtocolError("stdin cannot retain an artifact", "stdin")
            if self.terminal in (StreamTerminal.EOF, StreamTerminal.SINK_ERROR,
                                 StreamTerminal.CAPPED):
                raise ProtocolError("invalid stdin terminal", "stdin.terminal")
        else:
            if self.terminal in (StreamTerminal.COMPLETE, StreamTerminal.PEER_CLOSED,
                                 StreamTerminal.SOURCE_ERROR):
                raise ProtocolError("invalid output terminal", "stream.terminal")
            if self.retained_bytes > self.observed_bytes:
                raise ProtocolError("retained bytes exceed observed bytes", "retained_bytes")
            if self.lines > self.observed_bytes:
                raise ProtocolError("line count exceeds observed bytes", "lines")
            if self.claim_id is None:
                if self.retained_bytes != 0 or retained_digest is not None:
                    raise ProtocolError("unclaimed output retains an artifact", "claim_id")
            elif retained_digest is None:
                raise ProtocolError("retained stream needs a digest", "retained_sha256")
            if self.terminal is StreamTerminal.CAPPED:
                if self.role is not StreamRole.STDOUT or retained_digest is None:
                    raise ProtocolError("invalid capped stream", "stream.terminal")
                if self.retained_bytes >= self.observed_bytes:
                    raise ProtocolError("cap did not truncate stream", "retained_bytes")
        if self.retained_bytes == self.observed_bytes and retained_digest is not None:
            if retained_digest != observed_digest:
                raise ProtocolError("equal stream lengths have different digests", "stream")
        if retained_digest is not None and self.retained_bytes == 0 and retained_digest != _DIGEST_EMPTY:
            raise ProtocolError("empty artifact digest mismatch", "retained_sha256")
        if observed_digest is not None and self.observed_bytes == 0 and observed_digest != _DIGEST_EMPTY:
            raise ProtocolError("empty stream digest mismatch", "observed_sha256")

    def __repr__(self) -> str:
        return (f"StreamSettlement(role={self.role.value!r}, terminal={self.terminal.value!r}, "
                f"observed_bytes={self.observed_bytes}, retained_bytes={self.retained_bytes})")

    def to_dict(self) -> dict:
        return {
            "role": self.role.value, "terminal": self.terminal.value,
            "observed_bytes": self.observed_bytes, "retained_bytes": self.retained_bytes,
            "observed_sha256": self.observed_sha256,
            "retained_sha256": self.retained_sha256,
            "claim_id": self.claim_id, "lines": self.lines, "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "StreamSettlement":
        expected = frozenset({"role", "terminal", "observed_bytes", "retained_bytes",
                              "observed_sha256", "retained_sha256", "claim_id", "lines",
                              "detail"})
        _exact_keys(doc, expected, "stream")
        return cls(
            role=_enum(StreamRole, doc["role"], "role"),
            terminal=_enum(StreamTerminal, doc["terminal"], "terminal"),
            observed_bytes=doc["observed_bytes"], retained_bytes=doc["retained_bytes"],
            observed_sha256=doc["observed_sha256"],
            retained_sha256=doc["retained_sha256"], claim_id=doc["claim_id"],
            lines=doc["lines"], detail=doc["detail"],
        )


@dataclass(frozen=True)
class ReadyFrame:
    request_id: str
    worker_pid: int

    def __post_init__(self) -> None:
        _request_id(self.request_id)
        _positive_int(self.worker_pid, "worker_pid")

    def to_dict(self) -> dict:
        return {"request_id": self.request_id, "worker_pid": self.worker_pid}

    @classmethod
    def from_dict(cls, doc: dict) -> "ReadyFrame":
        _exact_keys(doc, frozenset({"request_id", "worker_pid"}), "ready")
        return cls(request_id=doc["request_id"], worker_pid=doc["worker_pid"])


@dataclass(frozen=True, repr=False)
class PreparedFrame:
    """Worker testimony that a pre-exec launcher is parked.

    This record declares the identity and containment intent that the parent must
    independently bind before sending GO.  It is not evidence that the process was
    bound, that GO was sent, that exec succeeded, or that containment is effective.
    """

    request_id: str
    worker_pid: int
    launcher_pid: int
    launcher_pgid: int
    containment_kind: ContainmentKind
    containment_id: str

    def __post_init__(self) -> None:
        _request_id(self.request_id)
        _positive_int(self.worker_pid, "worker_pid")
        _positive_int(self.launcher_pid, "launcher_pid")
        _positive_int(self.launcher_pgid, "launcher_pgid")
        if self.launcher_pgid != self.launcher_pid:
            raise ProtocolError("launcher group leader mismatch", "launcher_pgid")
        if self.worker_pid == self.launcher_pid:
            raise ProtocolError("worker must differ from launcher", "worker_pid")
        if type(self.containment_kind) is not ContainmentKind:
            raise ProtocolError("invalid enum", "containment_kind")
        _containment_id(self.containment_id)

    def __repr__(self) -> str:
        return (f"PreparedFrame(request_id={self.request_id!r}, "
                f"worker_pid={self.worker_pid}, launcher_pid={self.launcher_pid}, "
                f"containment_kind={self.containment_kind.value!r})")

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id, "worker_pid": self.worker_pid,
            "launcher_pid": self.launcher_pid, "launcher_pgid": self.launcher_pgid,
            "containment_kind": self.containment_kind.value,
            "containment_id": self.containment_id,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "PreparedFrame":
        expected = frozenset({"request_id", "worker_pid", "launcher_pid",
                              "launcher_pgid", "containment_kind", "containment_id"})
        _exact_keys(doc, expected, "prepared")
        return cls(
            request_id=doc["request_id"], worker_pid=doc["worker_pid"],
            launcher_pid=doc["launcher_pid"], launcher_pgid=doc["launcher_pgid"],
            containment_kind=_enum(ContainmentKind, doc["containment_kind"],
                                   "containment_kind"),
            containment_id=doc["containment_id"],
        )


@dataclass(frozen=True, repr=False)
class StartedFrame:
    request_id: str
    worker_pid: int
    tool_pid: int
    tool_pgid: int
    containment_kind: ContainmentKind
    containment_id: str

    def __post_init__(self) -> None:
        _request_id(self.request_id)
        _positive_int(self.worker_pid, "worker_pid")
        _positive_int(self.tool_pid, "tool_pid")
        _positive_int(self.tool_pgid, "tool_pgid")
        if self.tool_pgid != self.tool_pid:
            raise ProtocolError("tool group leader mismatch", "tool_pgid")
        if self.worker_pid in (self.tool_pid, self.tool_pgid):
            raise ProtocolError("worker must remain outside tool group", "worker_pid")
        if type(self.containment_kind) is not ContainmentKind:
            raise ProtocolError("invalid enum", "containment_kind")
        _containment_id(self.containment_id)

    def __repr__(self) -> str:
        return (f"StartedFrame(request_id={self.request_id!r}, "
                f"worker_pid={self.worker_pid}, tool_pid={self.tool_pid}, "
                f"containment_kind={self.containment_kind.value!r})")

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id, "worker_pid": self.worker_pid,
            "tool_pid": self.tool_pid, "tool_pgid": self.tool_pgid,
            "containment_kind": self.containment_kind.value,
            "containment_id": self.containment_id,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "StartedFrame":
        expected = frozenset({"request_id", "worker_pid", "tool_pid", "tool_pgid",
                              "containment_kind", "containment_id"})
        _exact_keys(doc, expected, "started")
        return cls(
            request_id=doc["request_id"], worker_pid=doc["worker_pid"],
            tool_pid=doc["tool_pid"], tool_pgid=doc["tool_pgid"],
            containment_kind=_enum(ContainmentKind, doc["containment_kind"],
                                   "containment_kind"),
            containment_id=doc["containment_id"],
        )


@dataclass(frozen=True, repr=False)
class WorkerSettlement:
    """Worker testimony. It never authorizes publication by itself."""

    request_id: str
    terminal: ExecutionTerminal
    launched: bool
    exit_code: int | None
    process_group_settled: bool
    process_tree_settled: bool
    streams: tuple[StreamSettlement, ...]
    worker_pid: int
    tool_pid: int | None
    detail: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _request_id(self.request_id)
        if type(self.terminal) is not ExecutionTerminal:
            raise ProtocolError("invalid enum", "terminal")
        if type(self.launched) is not bool:
            raise ProtocolError("invalid boolean", "launched")
        if self.exit_code is not None:
            _bounded_int(self.exit_code, "exit_code", minimum=MIN_EXIT_CODE,
                         maximum=MAX_EXIT_CODE)
        if (type(self.process_group_settled) is not bool
                or type(self.process_tree_settled) is not bool):
            raise ProtocolError("invalid boolean", "process settlement")
        _positive_int(self.worker_pid, "worker_pid")
        if self.tool_pid is not None:
            _positive_int(self.tool_pid, "tool_pid")
        _diagnostic_code(self.detail)
        if type(self.streams) is not tuple or len(self.streams) != 3:
            raise ProtocolError("settlement needs three streams", "streams")
        if any(type(stream) is not StreamSettlement for stream in self.streams):
            raise ProtocolError("invalid stream record", "streams")
        if tuple(stream.role for stream in self.streams) != tuple(StreamRole):
            raise ProtocolError("stream roles are not in canonical order", "streams")
        if self.launched != (self.tool_pid is not None):
            raise ProtocolError("tool launch identity mismatch", "tool_pid")
        if not self.launched:
            if self.exit_code is not None:
                raise ProtocolError("unlaunched tool has an exit code", "exit_code")
            if self.terminal not in (ExecutionTerminal.LAUNCH_FAILED,
                                     ExecutionTerminal.WORKER_FAILED,
                                     ExecutionTerminal.CANCELLED):
                raise ProtocolError("invalid unlaunched terminal", "terminal")
            for stream in self.streams:
                if (stream.observed_bytes or stream.retained_bytes
                        or stream.claim_id is not None):
                    raise ProtocolError("unlaunched tool has stream activity", "streams")
        elif self.terminal is ExecutionTerminal.LAUNCH_FAILED:
            raise ProtocolError("launched tool cannot be launch-failed", "terminal")
        if self.terminal is ExecutionTerminal.COMPLETE and self.exit_code is None:
            raise ProtocolError("completed execution needs exit code", "exit_code")

    def __repr__(self) -> str:
        return (f"WorkerSettlement(request_id={self.request_id!r}, "
                f"terminal={self.terminal.value!r}, launched={self.launched})")

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id, "terminal": self.terminal.value,
            "launched": self.launched, "exit_code": self.exit_code,
            "process_group_settled": self.process_group_settled,
            "process_tree_settled": self.process_tree_settled,
            "streams": [stream.to_dict() for stream in self.streams],
            "worker_pid": self.worker_pid, "tool_pid": self.tool_pid,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "WorkerSettlement":
        expected = frozenset({"request_id", "terminal", "launched", "exit_code",
                              "process_group_settled", "process_tree_settled", "streams",
                              "worker_pid", "tool_pid", "detail"})
        _exact_keys(doc, expected, "settlement")
        if type(doc["streams"]) is not list or len(doc["streams"]) != len(StreamRole):
            raise ProtocolError("expected array", "streams")
        return cls(
            request_id=doc["request_id"],
            terminal=_enum(ExecutionTerminal, doc["terminal"], "terminal"),
            launched=doc["launched"], exit_code=doc["exit_code"],
            process_group_settled=doc["process_group_settled"],
            process_tree_settled=doc["process_tree_settled"],
            streams=tuple(StreamSettlement.from_dict(stream) for stream in doc["streams"]),
            worker_pid=doc["worker_pid"], tool_pid=doc["tool_pid"], detail=doc["detail"],
        )


@dataclass(frozen=True, repr=False)
class ControlTranscript:
    ready: ReadyFrame
    prepared: PreparedFrame | None
    started: StartedFrame | None
    settlement: WorkerSettlement

    def __repr__(self) -> str:
        return (f"ControlTranscript(request_id={self.ready.request_id!r}, "
                f"prepared={self.prepared is not None}, "
                f"launched={self.started is not None})")


def validate_control_sequence(frames: tuple) -> ControlTranscript:
    if type(frames) is not tuple or len(frames) not in (2, 3, 4):
        raise ProtocolError("invalid control sequence", "control")
    if type(frames[0]) is not ReadyFrame or type(frames[-1]) is not WorkerSettlement:
        raise ProtocolError("invalid control sequence", "control")
    ready = frames[0]
    settlement = frames[-1]
    prepared = None
    started = None
    if len(frames) == 3:
        if type(frames[1]) is not PreparedFrame:
            raise ProtocolError("invalid control sequence", "control")
        prepared = frames[1]
    elif len(frames) == 4:
        if type(frames[1]) is not PreparedFrame or type(frames[2]) is not StartedFrame:
            raise ProtocolError("invalid control sequence", "control")
        prepared, started = frames[1:3]
    if settlement.launched != (started is not None):
        raise ProtocolError("control launch state mismatch", "control")
    records = tuple(record for record in (ready, prepared, started, settlement)
                    if record is not None)
    if any(record.request_id != ready.request_id for record in records):
        raise ProtocolError("control request mismatch", "control")
    if any(record.worker_pid != ready.worker_pid for record in records):
        raise ProtocolError("control worker mismatch", "control")
    if started is not None:
        if (started.tool_pid != prepared.launcher_pid
                or started.tool_pgid != prepared.launcher_pgid):
            raise ProtocolError("control launcher mismatch", "control")
        if (started.containment_kind is not prepared.containment_kind
                or started.containment_id != prepared.containment_id):
            raise ProtocolError("control containment mismatch", "control")
        if settlement.tool_pid != started.tool_pid:
            raise ProtocolError("control tool mismatch", "control")
    return ControlTranscript(ready=ready, prepared=prepared, started=started,
                             settlement=settlement)


@dataclass(frozen=True)
class DescriptorProof:
    """Parent-computed authentication of one closed descriptor claim.

    ``size``, ``sha256`` and output ``lines`` are recomputed from the exact retained
    artifact. They are never copied from worker testimony.
    """

    role: StreamRole
    claim_id: str
    size: int
    sha256: str = field(repr=False)
    lines: int | None = None

    def __post_init__(self) -> None:
        if type(self.role) is not StreamRole:
            raise ProtocolError("invalid stream enum", "proof.role")
        _claim_id(self.claim_id, "proof.claim_id")
        _nonnegative_int(self.size, "proof.size")
        if _optional_digest(self.sha256, "proof.sha256") is None:
            raise ProtocolError("proof needs a digest", "proof.sha256")
        if self.role is StreamRole.STDIN:
            if self.lines is not None:
                raise ProtocolError("stdin proof cannot count lines", "proof.lines")
        else:
            if self.lines is None:
                raise ProtocolError("output proof needs line count", "proof.lines")
            _nonnegative_int(self.lines, "proof.lines")
            if self.lines > self.size:
                raise ProtocolError("proof lines exceed size", "proof.lines")


@dataclass(frozen=True, repr=False)
class ParentSettlementContext:
    """Parent-owned facts used to validate worker testimony.

    ``prepared_identity_verified`` means the parent independently matched the
    PREPARED launcher PID/PGID to the parked process it created; PREPARED itself is
    only worker testimony. ``tool_identity_verified`` means the parent matched the
    STARTED PID/PGID to the process it allowed to exec. ``containment_verified``
    means the named containment is parent-owned and has the required controls.
    ``containment_bound`` means the parent independently observed that exact tool
    inside it. ``containment_empty`` is the final recursive membership result.
    None of these booleans is received from the worker.
    """

    request: WorkerRequest = field(repr=False)
    ready: ReadyFrame
    prepared: PreparedFrame | None
    started: StartedFrame | None
    settlement: WorkerSettlement
    descriptor_proofs: tuple[DescriptorProof, ...] = field(repr=False)
    expected_worker_pid: int
    expected_launcher_pid: int | None
    expected_launcher_pgid: int | None
    expected_containment_kind: ContainmentKind
    expected_containment_id: str
    worker_returncode: int
    worker_reaped: bool
    control_eof: bool
    trailing_control_bytes: int
    prepared_identity_verified: bool
    tool_identity_verified: bool
    containment_verified: bool
    containment_bound: bool
    containment_empty: bool
    stages_closed: bool

    def __post_init__(self) -> None:
        if type(self.request) is not WorkerRequest:
            raise ProtocolError("invalid worker request", "request")
        if type(self.ready) is not ReadyFrame or type(self.settlement) is not WorkerSettlement:
            raise ProtocolError("invalid control record", "control")
        if self.prepared is not None and type(self.prepared) is not PreparedFrame:
            raise ProtocolError("invalid control record", "prepared")
        if self.started is not None and type(self.started) is not StartedFrame:
            raise ProtocolError("invalid control record", "started")
        if type(self.descriptor_proofs) is not tuple:
            raise ProtocolError("invalid descriptor proofs", "descriptor_proofs")
        if any(type(proof) is not DescriptorProof for proof in self.descriptor_proofs):
            raise ProtocolError("invalid descriptor proof", "descriptor_proofs")
        roles = tuple(proof.role for proof in self.descriptor_proofs)
        if tuple(sorted(roles, key=_ROLE_ORDER.__getitem__)) != roles:
            raise ProtocolError("descriptor proofs are not in canonical order", "descriptor_proofs")
        if len(set(roles)) != len(roles):
            raise ProtocolError("duplicate descriptor proof", "descriptor_proofs")
        _positive_int(self.expected_worker_pid, "expected_worker_pid")
        if self.prepared is None:
            if self.expected_launcher_pid is not None or self.expected_launcher_pgid is not None:
                raise ProtocolError("unexpected launcher identity", "expected_launcher_pid")
            if self.prepared_identity_verified is not False:
                raise ProtocolError("unprepared launcher cannot be verified",
                                    "prepared_identity_verified")
        else:
            _positive_int(self.expected_launcher_pid, "expected_launcher_pid")
            _positive_int(self.expected_launcher_pgid, "expected_launcher_pgid")
        if type(self.expected_containment_kind) is not ContainmentKind:
            raise ProtocolError("invalid enum", "expected_containment_kind")
        _containment_id(self.expected_containment_id)
        _bounded_int(self.worker_returncode, "worker_returncode", minimum=MIN_EXIT_CODE,
                     maximum=MAX_EXIT_CODE)
        _nonnegative_int(self.trailing_control_bytes, "trailing_control_bytes")
        for name in ("worker_reaped", "control_eof", "prepared_identity_verified",
                     "tool_identity_verified",
                     "containment_verified", "containment_bound",
                     "containment_empty", "stages_closed"):
            if type(getattr(self, name)) is not bool:
                raise ProtocolError("invalid boolean", name)

    def __repr__(self) -> str:
        return (f"ParentSettlementContext(request_id={self.request.request_id!r}, "
                f"worker_pid={self.expected_worker_pid}, "
                f"proofs={len(self.descriptor_proofs)})")


@dataclass(frozen=True)
class ValidatedSettlement:
    """Mechanical/capture proof, deliberately not semantic result classification."""

    worker: WorkerSettlement = field(repr=False)
    mechanically_settled: bool
    tree_proven: bool
    capture_complete: bool
    _authority: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority is not _VALIDATION_AUTHORITY:
            raise ProtocolError("validated settlement requires parent authority", "authority")
        for name in ("mechanically_settled", "tree_proven", "capture_complete"):
            if type(getattr(self, name)) is not bool:
                raise ProtocolError("invalid boolean", name)
        if self.capture_complete and not (self.mechanically_settled and self.tree_proven):
            raise ProtocolError("complete capture lacks settlement proof", "capture_complete")


def _stream_map(settlement: WorkerSettlement) -> dict[StreamRole, StreamSettlement]:
    return {stream.role: stream for stream in settlement.streams}


def validate_parent_settlement(context: ParentSettlementContext) -> ValidatedSettlement:
    if type(context) is not ParentSettlementContext:
        raise ProtocolError("invalid parent settlement context", "context")
    transcript_records = [context.ready]
    if context.prepared is not None:
        transcript_records.append(context.prepared)
    if context.started is not None:
        transcript_records.append(context.started)
    transcript_records.append(context.settlement)
    transcript_frames = tuple(transcript_records)
    transcript = validate_control_sequence(transcript_frames)
    request = context.request
    settlement = transcript.settlement
    if request.request_id != settlement.request_id:
        raise ProtocolError("request and settlement mismatch", "request_id")
    if context.ready.worker_pid != context.expected_worker_pid:
        raise ProtocolError("worker identity mismatch", "worker_pid")

    if transcript.prepared is not None:
        if (transcript.prepared.launcher_pid != context.expected_launcher_pid
                or transcript.prepared.launcher_pgid != context.expected_launcher_pgid):
            raise ProtocolError("prepared identity mismatch", "launcher_pid")
    prepared_bound = (
        transcript.prepared is not None
        and context.prepared_identity_verified
        and transcript.prepared.containment_kind is context.expected_containment_kind
        and transcript.prepared.containment_id == context.expected_containment_id
    )
    binding_ok = (
        prepared_bound
        and transcript.started is not None
        and transcript.started.containment_kind is context.expected_containment_kind
        and transcript.started.containment_id == context.expected_containment_id
    )

    expected_roles = tuple(claim.role for claim in request.descriptor_claims)
    proof_roles = tuple(proof.role for proof in context.descriptor_proofs)
    proof_by_role = {proof.role: proof for proof in context.descriptor_proofs}
    claim_by_role = {claim.role: claim for claim in request.descriptor_claims}
    evidence_bound = expected_roles == proof_roles
    streams = _stream_map(settlement)

    for role in StreamRole:
        stream = streams[role]
        claim = claim_by_role.get(role)
        proof = proof_by_role.get(role)
        if role is StreamRole.STDIN:
            if stream.claim_id is not None:
                evidence_bound = False
            if request.stdin_mode is StdinMode.NULL:
                evidence_bound &= (claim is None and proof is None
                                   and stream.observed_bytes == 0
                                   and stream.observed_sha256 == _DIGEST_EMPTY
                                   and stream.terminal is StreamTerminal.COMPLETE)
            elif request.stdin_mode is StdinMode.DATA:
                evidence_bound &= (claim is None and proof is None
                                   and stream.observed_bytes == request.stdin_bytes
                                   and stream.observed_sha256 == request.stdin_sha256
                                   and stream.terminal is StreamTerminal.COMPLETE)
            else:
                evidence_bound &= (claim is not None and proof is not None
                                   and proof.claim_id == claim.claim_id
                                   and stream.observed_bytes == proof.size
                                   and stream.observed_sha256 == proof.sha256
                                   and stream.terminal is StreamTerminal.COMPLETE)
            continue

        if claim is None:
            evidence_bound &= (proof is None and stream.claim_id is None
                               and stream.retained_bytes == 0
                               and stream.retained_sha256 is None)
            continue
        evidence_bound &= (proof is not None and stream.claim_id == claim.claim_id
                           and proof.claim_id == claim.claim_id
                           and proof.size == stream.retained_bytes
                           and proof.sha256 == stream.retained_sha256
                           and proof.lines == stream.lines)
        if role is StreamRole.STDOUT and request.max_output_bytes is not None:
            evidence_bound &= stream.retained_bytes <= request.max_output_bytes
        if stream.terminal is StreamTerminal.EOF:
            evidence_bound &= (stream.retained_bytes == stream.observed_bytes
                               and stream.retained_sha256 == stream.observed_sha256)
        elif stream.terminal is StreamTerminal.CAPPED:
            evidence_bound &= (role is StreamRole.STDOUT
                               and request.max_output_bytes is not None
                               and stream.retained_bytes == request.max_output_bytes
                               and stream.observed_bytes > stream.retained_bytes)

    authority_settled = (
        context.worker_reaped
        and context.worker_returncode == 0
        and context.control_eof
        and context.trailing_control_bytes == 0
        and context.prepared_identity_verified
        and context.tool_identity_verified
        and context.containment_verified
        and context.containment_bound
        and context.containment_empty
        and context.stages_closed
        and binding_ok
    )
    streams_settled = all(stream.terminal not in (
        StreamTerminal.NOT_STARTED, StreamTerminal.WORKER_CRASH,
    ) for stream in settlement.streams)
    mechanically_settled = (
        authority_settled and settlement.process_group_settled and streams_settled
    )
    tree_proven = (
        mechanically_settled
        and context.expected_containment_kind is ContainmentKind.CGROUP_V2
        and context.containment_verified
        and context.containment_empty
    )
    stdout = streams[StreamRole.STDOUT]
    stderr = streams[StreamRole.STDERR]
    stdin = streams[StreamRole.STDIN]
    capture_complete = (
        mechanically_settled and tree_proven and evidence_bound
        and settlement.terminal is ExecutionTerminal.COMPLETE
        and stdin.terminal is StreamTerminal.COMPLETE
        and stdout.terminal is StreamTerminal.EOF
        and stderr.terminal is StreamTerminal.EOF
    )
    return ValidatedSettlement(
        worker=settlement, mechanically_settled=mechanically_settled,
        tree_proven=tree_proven, capture_complete=capture_complete,
        _authority=_VALIDATION_AUTHORITY,
    )


def _reject_constant(_value):
    raise ProtocolError("non-finite JSON number", "frame")


def _parse_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if not digits or len(digits) > MAX_JSON_INTEGER_DIGITS or value == "-0":
        raise ProtocolError("JSON integer exceeds limit", "frame")
    try:
        parsed = int(value)
    except (ValueError, OverflowError):
        raise ProtocolError("invalid JSON integer", "frame") from None
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise ProtocolError("JSON integer exceeds limit", "frame")
    return parsed


def _parse_float(value: str) -> float:
    if len(value) > 64:
        raise ProtocolError("JSON float exceeds limit", "frame")
    try:
        parsed = float(value)
    except (ValueError, OverflowError):
        raise ProtocolError("invalid JSON float", "frame") from None
    if not math.isfinite(parsed) or abs(parsed) > MAX_SAFE_INTEGER:
        raise ProtocolError("JSON float exceeds limit", "frame")
    mantissa = value.lower().split("e", 1)[0]
    lexical_nonzero = any(ch in "123456789" for ch in mantissa)
    if parsed == 0.0 and (lexical_nonzero or value.startswith("-")):
        raise ProtocolError("JSON float underflow or negative zero", "frame")
    return parsed


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ProtocolError("duplicate JSON key", "frame")
        out[key] = value
    return out


def _check_tree(root) -> None:
    stack = [(root, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ProtocolError("JSON node limit exceeded", "frame")
        if depth > MAX_JSON_DEPTH:
            raise ProtocolError("JSON depth limit exceeded", "frame")
        if type(value) is dict:
            stack.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            stack.extend((item, depth + 1) for item in value)
        elif value is not None and type(value) not in (str, int, float, bool):
            raise ProtocolError("unsupported JSON value", "frame")
        elif type(value) is int and abs(value) > MAX_SAFE_INTEGER:
            raise ProtocolError("JSON integer exceeds limit", "frame")
        elif type(value) is float and not math.isfinite(value):
            raise ProtocolError("non-finite JSON number", "frame")


def _encode(kind: str, body: dict) -> bytes:
    envelope = {"version": PROTOCOL_VERSION, "kind": kind, "body": body}
    _check_tree(envelope)
    try:
        payload = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        raise ProtocolError("record cannot be encoded", "frame") from None
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("frame exceeds limit", "frame")
    return struct.pack(">I", len(payload)) + payload


def _decode(frame: bytes, expected_kind: str) -> dict:
    if type(frame) is not bytes or len(frame) < 4:
        raise ProtocolError("truncated frame", "frame")
    declared = struct.unpack(">I", frame[:4])[0]
    if declared == 0 or declared > MAX_FRAME_BYTES:
        raise ProtocolError("invalid frame length", "frame")
    if len(frame) != declared + 4:
        raise ProtocolError("frame length mismatch", "frame")
    try:
        doc = json.loads(frame[4:].decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=_reject_constant, parse_int=_parse_int,
                         parse_float=_parse_float)
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ProtocolError("invalid JSON frame", "frame") from None
    _check_tree(doc)
    _exact_keys(doc, frozenset({"version", "kind", "body"}), "frame")
    if type(doc["version"]) is not int or doc["version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version", "version")
    if type(doc["kind"]) is not str or doc["kind"] != expected_kind:
        raise ProtocolError("unexpected frame kind", "kind")
    if type(doc["body"]) is not dict:
        raise ProtocolError("expected object", "body")
    return doc["body"]


def encode_request(request: WorkerRequest) -> bytes:
    if type(request) is not WorkerRequest:
        raise ProtocolError("invalid worker request", "request")
    return _encode("request", request.to_dict())


def decode_request(frame: bytes) -> WorkerRequest:
    return WorkerRequest.from_dict(_decode(frame, "request"))


def encode_ready(ready: ReadyFrame) -> bytes:
    if type(ready) is not ReadyFrame:
        raise ProtocolError("invalid ready frame", "ready")
    return _encode("ready", ready.to_dict())


def decode_ready(frame: bytes) -> ReadyFrame:
    return ReadyFrame.from_dict(_decode(frame, "ready"))


def encode_prepared(prepared: PreparedFrame) -> bytes:
    if type(prepared) is not PreparedFrame:
        raise ProtocolError("invalid prepared frame", "prepared")
    return _encode("prepared", prepared.to_dict())


def decode_prepared(frame: bytes) -> PreparedFrame:
    return PreparedFrame.from_dict(_decode(frame, "prepared"))


def encode_started(started: StartedFrame) -> bytes:
    if type(started) is not StartedFrame:
        raise ProtocolError("invalid started frame", "started")
    return _encode("started", started.to_dict())


def decode_started(frame: bytes) -> StartedFrame:
    return StartedFrame.from_dict(_decode(frame, "started"))


def encode_settlement(settlement: WorkerSettlement) -> bytes:
    if type(settlement) is not WorkerSettlement:
        raise ProtocolError("invalid worker settlement", "settlement")
    return _encode("settlement", settlement.to_dict())


def decode_settlement(frame: bytes) -> WorkerSettlement:
    return WorkerSettlement.from_dict(_decode(frame, "settlement"))
