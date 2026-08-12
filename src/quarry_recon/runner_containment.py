"""Parent-owned process containment for the killable runner boundary.

This module deliberately does not participate in :mod:`quarry_recon.runner` yet.
It prepares one Linux cgroup-v2 backend whose assurance is *cooperative*: ordinary
forks, ``setsid()``, double-forks and concurrent forks remain in the acquired
subtree, but a deliberately hostile same-UID program may be able to migrate to a
different writable cgroup.  This is an execution-correctness boundary, not a
security sandbox.

A read-only probe reports only whether the current cgroup looks like a delegation
candidate.  Authority is established only when Quarry successfully creates a
unique child and opens the exact control files it needs.  The supervisor remains
outside that child.  It launches a child in a parked state, binds that exact
PID/start-time identity through its parent-only ``cgroup.procs`` descriptor,
verifies membership independently, and only then lets the child execute.  A future
native ``clone3(CLONE_INTO_CGROUP)`` launcher can strengthen that launch seam
without changing the parent-owned handle.
"""
from __future__ import annotations

import ctypes
import errno
import math
import os
import stat
import sys
import time
from dataclasses import dataclass
from enum import Enum

from .runner_protocol import ContainmentAssurance, ContainmentKind

_CGROUP2_SUPER_MAGIC = 0x63677270
_MAX_PROC_TEXT = 1 << 20
_MAX_EVENTS_TEXT = 64 * 1024
_MAX_CGROUP_COMPONENTS = 128
_MAX_CGROUP_PATH_BYTES = 4096
_MAX_SAFE_DEADLINE = (1 << 53) - 1
_MAX_DESCENDANT_DEPTH = 64
_MAX_DESCENDANT_CGROUPS = 4096
_MAX_DESCENDANT_ENTRIES = 65_536
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIR_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
_WRITE_FLAGS = os.O_WRONLY | _O_NOFOLLOW | _O_CLOEXEC
_PROC_ROOT = "/proc"
_MOUNTINFO = "/proc/self/mountinfo"
_SELF_CGROUP = "/proc/self/cgroup"


class ContainmentReason(str, Enum):
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    SETTLED = "settled"
    NOT_LINUX = "not_linux"
    DESCRIPTOR_API_MISSING = "descriptor_api_missing"
    CGROUP_V2_MOUNT_MISSING = "cgroup_v2_mount_missing"
    CGROUP_V2_MOUNT_READ_ONLY = "cgroup_v2_mount_read_only"
    CGROUP_V2_MAGIC_MISMATCH = "cgroup_v2_magic_mismatch"
    CURRENT_CGROUP_MISSING = "current_cgroup_missing"
    CURRENT_CGROUP_UNSAFE = "current_cgroup_unsafe"
    CURRENT_CGROUP_MOVED = "current_cgroup_moved"
    DELEGATION_CONTROLS_MISSING = "delegation_controls_missing"
    DELEGATION_REFUSED = "delegation_refused"
    REQUEST_ID_INVALID = "request_id_invalid"
    LEAF_COLLISION = "leaf_collision"
    LEAF_CREATE_FAILED = "leaf_create_failed"
    LEAF_CONTROL_UNUSABLE = "leaf_control_unusable"
    LEAF_DOMAIN_UNUSABLE = "leaf_domain_unusable"
    CGROUP_KILL_UNAVAILABLE = "cgroup_kill_unavailable"
    LEAF_ROLLBACK_FAILED = "leaf_rollback_failed"
    HANDLE_CLOSED = "handle_closed"
    BINDING_WRITE_FAILED = "binding_write_failed"
    BINDING_ALREADY_USED = "binding_already_used"
    PROCESS_GONE = "process_gone"
    PROCESS_IDENTITY_INVALID = "process_identity_invalid"
    PROCESS_IDENTITY_CHANGED = "process_identity_changed"
    PROCESS_NOT_PARKED = "process_not_parked"
    PROCESS_CGROUP_MALFORMED = "process_cgroup_malformed"
    PROCESS_CGROUP_MISMATCH = "process_cgroup_mismatch"
    LEAF_MEMBERSHIP_MISSING = "leaf_membership_missing"
    EVENTS_MALFORMED = "events_malformed"
    DEADLINE_INVALID = "deadline_invalid"
    DEADLINE_EXPIRED = "deadline_expired"
    KILL_FAILED = "kill_failed"
    LEAF_NOT_EMPTY = "leaf_not_empty"
    LEAF_IDENTITY_CHANGED = "leaf_identity_changed"
    DESCENDANT_UNSAFE = "descendant_unsafe"
    DESCENDANT_LIMIT = "descendant_limit"
    REMOVE_FAILED = "remove_failed"


class ContainmentError(RuntimeError):
    """Fixed, credential-safe containment failure plus an optional OS errno."""

    def __init__(self, reason: ContainmentReason, os_errno: int | None = None) -> None:
        if type(reason) is not ContainmentReason:
            raise TypeError("reason must be ContainmentReason")
        if os_errno is not None and type(os_errno) is not int:
            raise TypeError("os_errno must be an exact integer or None")
        self.reason = reason
        self.os_errno = os_errno
        suffix = "" if os_errno is None else f":errno={os_errno}"
        super().__init__(f"{self.__class__.__name__}:{reason.value}{suffix}")


class ContainmentUnsupported(ContainmentError):
    """The host lacks a kernel/filesystem primitive required by this backend."""


class ContainmentRefused(ContainmentError):
    """The host has cgroup v2, but Quarry does not own the requested authority."""


class ContainmentFailure(ContainmentError):
    """An acquired authority failed during a bounded operation."""


@dataclass(frozen=True)
class ContainmentProbe:
    """Side-effect-free candidacy, never proof that a usable leaf can be acquired."""

    candidate: bool
    reason: ContainmentReason
    kind: ContainmentKind = ContainmentKind.CGROUP_V2
    cooperative_only: bool = True
    cooperative_settlement_capable: bool = False
    tree_proof_capable: bool = False

    def __post_init__(self) -> None:
        if type(self.candidate) is not bool or type(self.reason) is not ContainmentReason:
            raise TypeError("invalid containment probe")
        if self.candidate != (self.reason is ContainmentReason.CANDIDATE):
            raise ValueError("probe candidacy and reason disagree")
        if self.kind is not ContainmentKind.CGROUP_V2:
            raise ValueError("direct probe must describe cgroup v2")
        if (not self.cooperative_only or self.cooperative_settlement_capable
                or self.tree_proof_capable):
            raise ValueError("a probe cannot claim acquired tree authority")


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_time_ticks: int

    def __post_init__(self) -> None:
        _positive_pid(self.pid)
        if type(self.start_time_ticks) is not int or self.start_time_ticks < 0:
            raise ContainmentRefused(ContainmentReason.PROCESS_IDENTITY_INVALID)


@dataclass(frozen=True)
class MembershipVerification:
    verified: bool
    reason: ContainmentReason

    def __post_init__(self) -> None:
        if type(self.verified) is not bool or type(self.reason) is not ContainmentReason:
            raise TypeError("invalid membership verification")
        if self.verified and self.reason is not ContainmentReason.VERIFIED:
            raise ValueError("verified membership needs the fixed success reason")


@dataclass(frozen=True)
class ContainmentSettlement:
    killed: bool
    empty: bool
    removed: bool
    reason: ContainmentReason
    os_errno: int | None = None
    containment_assurance: ContainmentAssurance = (
        ContainmentAssurance.COOPERATIVE_SCOPE)

    def __post_init__(self) -> None:
        for value in (self.killed, self.empty, self.removed):
            if type(value) is not bool:
                raise TypeError("settlement flags must be booleans")
        if type(self.reason) is not ContainmentReason:
            raise TypeError("invalid settlement reason")
        if self.os_errno is not None and type(self.os_errno) is not int:
            raise TypeError("invalid settlement errno")
        if self.containment_assurance is not ContainmentAssurance.COOPERATIVE_SCOPE:
            raise ValueError("direct settlement has cooperative-scope assurance")
        if self.removed and not (self.killed and self.empty):
            raise ValueError("removed containment must be killed and empty")
        if self.removed != (self.reason is ContainmentReason.SETTLED):
            raise ValueError("settled reason and removal disagree")

    @property
    def cooperative_settled(self) -> bool:
        """The acquired subtree was killed, observed empty and removed."""
        return self.killed and self.empty and self.removed

    @property
    def tree_settled(self) -> bool:
        """Never claim escape-protected proof for cooperative containment.

        The parent protocol separately decides whether the request's declared policy
        permits a recursively settled cooperative scope to be classified as clean.
        """
        return False

    @property
    def escape_protected(self) -> bool:
        return False


@dataclass(frozen=True)
class PgidFallback:
    """Explicitly degraded identity: a process group can never prove a tree empty."""

    pgid: int
    kind: ContainmentKind = ContainmentKind.PGID
    containment_assurance: ContainmentAssurance = ContainmentAssurance.PROCESS_GROUP
    cooperative_settlement_capable: bool = False
    tree_proof_capable: bool = False
    escape_protected: bool = False

    def __post_init__(self) -> None:
        _positive_pid(self.pgid)
        if (self.kind is not ContainmentKind.PGID
                or self.containment_assurance is not ContainmentAssurance.PROCESS_GROUP
                or self.cooperative_settlement_capable
                or self.tree_proof_capable or self.escape_protected):
            raise ValueError("invalid PGID fallback assurance")


def _positive_pid(value) -> int:
    if type(value) is not int or value <= 0 or value > (1 << 31) - 1:
        raise ContainmentRefused(ContainmentReason.PROCESS_IDENTITY_INVALID)
    return value


def _os_errno(exc: BaseException) -> int | None:
    value = getattr(exc, "errno", None)
    return value if type(value) is int else None


def _validate_request_id(value) -> str:
    if (type(value) is not str or len(value) != 32
            or any(ch not in "0123456789abcdef" for ch in value)):
        raise ContainmentRefused(ContainmentReason.REQUEST_ID_INVALID)
    return value


def _validate_deadline(value) -> int | float:
    """Validate without coercing an arbitrarily large Python integer to float."""
    if type(value) is int:
        if value < 0 or value > _MAX_SAFE_DEADLINE:
            raise ContainmentRefused(ContainmentReason.DEADLINE_INVALID)
        return value
    if type(value) is float:
        if value < 0 or value > _MAX_SAFE_DEADLINE or not math.isfinite(value):
            raise ContainmentRefused(ContainmentReason.DEADLINE_INVALID)
        return value
    raise ContainmentRefused(ContainmentReason.DEADLINE_INVALID)


def _require_features() -> None:
    required = (
        sys.platform.startswith("linux"),
        _O_DIRECTORY != 0,
        _O_NOFOLLOW != 0,
        os.open in getattr(os, "supports_dir_fd", ()),
        os.mkdir in getattr(os, "supports_dir_fd", ()),
        os.rmdir in getattr(os, "supports_dir_fd", ()),
        os.stat in getattr(os, "supports_dir_fd", ()),
        os.stat in getattr(os, "supports_follow_symlinks", ()),
        hasattr(os, "pread"),
    )
    if not required[0]:
        raise ContainmentUnsupported(ContainmentReason.NOT_LINUX)
    if not all(required[1:]):
        raise ContainmentUnsupported(ContainmentReason.DESCRIPTOR_API_MISSING)


def _fstatfs_type(fd: int) -> int:
    """Return Linux ``statfs.f_type`` without depending on a glibc Python wrapper."""
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "fstatfs", None)
    if function is None:
        raise ContainmentUnsupported(ContainmentReason.DESCRIPTOR_API_MISSING)
    buffer = ctypes.create_string_buffer(256)
    function.argtypes = (ctypes.c_int, ctypes.c_void_p)
    function.restype = ctypes.c_int
    if function(fd, ctypes.byref(buffer)) != 0:
        number = ctypes.get_errno()
        raise ContainmentUnsupported(ContainmentReason.CGROUP_V2_MAGIC_MISMATCH, number)
    return ctypes.c_ulong.from_buffer(buffer).value


def _read_fd(fd: int, limit: int, *,
             reason: ContainmentReason = ContainmentReason.EVENTS_MALFORMED) -> bytes:
    chunks: list[bytes] = []
    total = 0
    offset = 0
    while True:
        try:
            chunk = os.pread(fd, min(64 * 1024, limit + 1 - total), offset)
        except InterruptedError:
            continue
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        offset += len(chunk)
        if total > limit:
            raise ContainmentFailure(reason)
    return b"".join(chunks)


def _open_control(dir_fd: int, name: str, flags: int, *,
                  reason: ContainmentReason = ContainmentReason.DELEGATION_CONTROLS_MISSING,
                  failure: bool = False) -> int:
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        error_type = ContainmentFailure if failure else ContainmentRefused
        raise error_type(reason, _os_errno(exc)) from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            error_type = ContainmentFailure if failure else ContainmentRefused
            raise error_type(reason)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_leaf_kill(dir_fd: int) -> int:
    try:
        return _open_control(
            dir_fd, "cgroup.kill", _WRITE_FLAGS,
            reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
        )
    except ContainmentRefused as exc:
        if exc.os_errno in (errno.ENOENT, errno.ENODEV, errno.ENOSYS,
                            errno.EOPNOTSUPP):
            raise ContainmentUnsupported(
                ContainmentReason.CGROUP_KILL_UNAVAILABLE, exc.os_errno) from None
        raise ContainmentRefused(ContainmentReason.LEAF_CONTROL_UNUSABLE,
                                 exc.os_errno) from None


def _read_control(dir_fd: int, name: str, limit: int = _MAX_EVENTS_TEXT, *,
                  reason: ContainmentReason = ContainmentReason.DELEGATION_CONTROLS_MISSING,
                  failure: bool = False) -> bytes:
    fd = _open_control(dir_fd, name, _READ_FLAGS, reason=reason, failure=failure)
    try:
        return _read_fd(fd, limit, reason=reason)
    finally:
        os.close(fd)


def _parse_pid_lines(raw: bytes) -> frozenset[int]:
    try:
        lines = raw.decode("ascii").splitlines()
        parsed = tuple(int(line) for line in lines if line)
    except (UnicodeDecodeError, ValueError):
        raise ContainmentFailure(ContainmentReason.PROCESS_CGROUP_MALFORMED) from None
    # A cgroup read may expose PID 0 for a task hidden by the reader's PID
    # namespace.  (On write, PID 0 separately means the writing process.)  It is
    # never a verifiable read-side identity, so discard it here.
    if any(value < 0 or value > (1 << 31) - 1 for value in parsed):
        raise ContainmentFailure(ContainmentReason.PROCESS_CGROUP_MALFORMED)
    return frozenset(value for value in parsed if value != 0)


def _decode_mount_field(value: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            out.append(value[index])
            index += 1
            continue
        digits = value[index + 1:index + 4]
        if len(digits) != 3 or any(ch not in "01234567" for ch in digits):
            raise ContainmentRefused(ContainmentReason.CURRENT_CGROUP_UNSAFE)
        decoded = chr(int(digits, 8))
        if decoded == "\x00":
            raise ContainmentRefused(ContainmentReason.CURRENT_CGROUP_UNSAFE)
        out.append(decoded)
        index += 4
    return "".join(out)


def _read_bounded_path(path: str, limit: int = _MAX_PROC_TEXT) -> str:
    try:
        fd = os.open(path, _READ_FLAGS)
        try:
            raw = _read_fd(fd, limit, reason=ContainmentReason.CURRENT_CGROUP_UNSAFE)
        finally:
            os.close(fd)
        return raw.decode("utf-8")
    except ContainmentError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise ContainmentUnsupported(ContainmentReason.CURRENT_CGROUP_MISSING,
                                     _os_errno(exc)) from None


def _unified_membership(text: str) -> str:
    matches = [line[3:] for line in text.splitlines() if line.startswith("0::")]
    if len(matches) != 1:
        raise ContainmentUnsupported(ContainmentReason.CURRENT_CGROUP_MISSING)
    value = matches[0]
    if (not value.startswith("/") or "\x00" in value
            or len(value.encode("utf-8")) > _MAX_CGROUP_PATH_BYTES
            or any(part in (".", "..") for part in value.split("/") if part)):
        raise ContainmentRefused(ContainmentReason.CURRENT_CGROUP_UNSAFE)
    return value.rstrip("/") or "/"


@dataclass(frozen=True)
class _Mount:
    root: str
    point: str
    writable: bool


def _cgroup2_mounts(text: str) -> tuple[_Mount, ...]:
    mounts: list[_Mount] = []
    for line in text.splitlines():
        fields = line.split()
        try:
            split = fields.index("-")
        except ValueError:
            continue
        if split < 6 or split + 1 >= len(fields) or fields[split + 1] != "cgroup2":
            continue
        options = frozenset(fields[5].split(","))
        mounts.append(_Mount(_decode_mount_field(fields[3]),
                             _decode_mount_field(fields[4]), "rw" in options))
    return tuple(mounts)


def _components(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or "\x00" in path:
        raise ContainmentRefused(ContainmentReason.CURRENT_CGROUP_UNSAFE)
    components = tuple(part for part in path.split("/") if part)
    if (len(components) > _MAX_CGROUP_COMPONENTS
            or any(part in (".", "..") or len(part.encode("utf-8")) > 255
                   for part in components)):
        raise ContainmentRefused(ContainmentReason.CURRENT_CGROUP_UNSAFE)
    return components


def _open_absolute_dir(path: str) -> int:
    components = _components(path)
    fd = os.open("/", _DIR_FLAGS)
    try:
        for component in components:
            next_fd = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _walk_dir(parent_fd: int, components: tuple[str, ...]) -> int:
    fd = os.dup(parent_fd)
    try:
        for component in components:
            next_fd = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _relative_candidates(mount_root: str, membership: str) -> tuple[tuple[str, ...], ...]:
    candidates: list[tuple[str, ...]] = []
    if mount_root == "/":
        candidates.append(_components(membership))
    elif membership == "/":
        candidates.append(())
    elif membership == mount_root or membership.startswith(mount_root.rstrip("/") + "/"):
        suffix = membership[len(mount_root.rstrip("/")):] or "/"
        candidates.append(_components(suffix))
    # A cgroup namespace reports paths relative to its namespace root while
    # mountinfo may retain the host-side mount root. Membership verification
    # below decides whether this second interpretation is the current cgroup.
    direct = _components(membership)
    if direct not in candidates:
        candidates.append(direct)
    return tuple(candidates)


@dataclass
class _DiscoveredParent:
    fd: int
    membership: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def _check_parent_candidate(fd: int) -> None:
    if _fstatfs_type(fd) != _CGROUP2_SUPER_MAGIC:
        raise ContainmentUnsupported(ContainmentReason.CGROUP_V2_MAGIC_MISMATCH)
    try:
        if not os.access(".", os.W_OK | os.X_OK, dir_fd=fd,
                         effective_ids=True, follow_symlinks=False):
            raise ContainmentRefused(ContainmentReason.DELEGATION_REFUSED)
    except (NotImplementedError, TypeError):
        raise ContainmentUnsupported(ContainmentReason.DESCRIPTOR_API_MISSING) from None
    for name in ("cgroup.procs", "cgroup.threads", "cgroup.subtree_control"):
        control = _open_control(fd, name, _WRITE_FLAGS)
        os.close(control)


def _discover_parent() -> _DiscoveredParent:
    _require_features()
    membership = _unified_membership(_read_bounded_path(_SELF_CGROUP))
    mounts = _cgroup2_mounts(_read_bounded_path(_MOUNTINFO))
    if not mounts:
        raise ContainmentUnsupported(ContainmentReason.CGROUP_V2_MOUNT_MISSING)
    saw_read_only = False
    last_error: ContainmentError | None = None
    for mount in mounts:
        if not mount.writable:
            saw_read_only = True
            continue
        mount_fd = None
        try:
            mount_fd = _open_absolute_dir(mount.point)
            if _fstatfs_type(mount_fd) != _CGROUP2_SUPER_MAGIC:
                raise ContainmentUnsupported(ContainmentReason.CGROUP_V2_MAGIC_MISMATCH)
            for components in _relative_candidates(mount.root, membership):
                parent_fd = None
                try:
                    parent_fd = _walk_dir(mount_fd, components)
                    pids = _parse_pid_lines(_read_control(parent_fd, "cgroup.procs"))
                    if os.getpid() not in pids:
                        os.close(parent_fd)
                        parent_fd = None
                        continue
                    _check_parent_candidate(parent_fd)
                    return _DiscoveredParent(parent_fd, membership)
                except ContainmentError as exc:
                    last_error = exc
                    if parent_fd is not None:
                        os.close(parent_fd)
                except OSError as exc:
                    last_error = ContainmentRefused(
                        ContainmentReason.CURRENT_CGROUP_UNSAFE, _os_errno(exc))
                    if parent_fd is not None:
                        os.close(parent_fd)
        except ContainmentError as exc:
            last_error = exc
        except OSError as exc:
            last_error = ContainmentRefused(
                ContainmentReason.CURRENT_CGROUP_UNSAFE, _os_errno(exc))
        finally:
            if mount_fd is not None:
                os.close(mount_fd)
    if last_error is not None:
        raise last_error
    if saw_read_only:
        raise ContainmentUnsupported(ContainmentReason.CGROUP_V2_MOUNT_READ_ONLY)
    raise ContainmentUnsupported(ContainmentReason.CURRENT_CGROUP_MISSING)


def probe_direct_cgroup_v2() -> ContainmentProbe:
    """Inspect the current hierarchy without creating or modifying a cgroup."""
    try:
        discovered = _discover_parent()
    except ContainmentError as exc:
        return ContainmentProbe(False, exc.reason)
    else:
        discovered.close()
        return ContainmentProbe(True, ContainmentReason.CANDIDATE)


def _mkdir_leaf(name: str, parent_fd: int) -> None:
    os.mkdir(name, 0o700, dir_fd=parent_fd)


def _rmdir_cgroup(name: str, parent_fd: int) -> None:
    os.rmdir(name, dir_fd=parent_fd)


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _leaf_membership(parent_membership: str, leaf_name: str) -> str:
    return "/" + leaf_name if parent_membership == "/" else parent_membership + "/" + leaf_name


def _open_proc_pid(pid: int) -> int:
    _positive_pid(pid)
    root_fd = _open_absolute_dir(_PROC_ROOT)
    try:
        return os.open(str(pid), _DIR_FLAGS, dir_fd=root_fd)
    except FileNotFoundError:
        raise ContainmentFailure(ContainmentReason.PROCESS_GONE) from None
    except OSError as exc:
        raise ContainmentFailure(ContainmentReason.PROCESS_IDENTITY_INVALID,
                                 _os_errno(exc)) from None
    finally:
        os.close(root_fd)


def _proc_state_and_start_time(proc_fd: int) -> tuple[str, int]:
    raw = _read_control(
        proc_fd, "stat", _MAX_PROC_TEXT,
        reason=ContainmentReason.PROCESS_GONE, failure=True,
    )
    try:
        text = raw.decode("ascii")
        close = text.rindex(")")
        fields = text[close + 1:].split()
        state = fields[0]
        value = int(fields[19])
    except (UnicodeDecodeError, ValueError, IndexError):
        raise ContainmentFailure(ContainmentReason.PROCESS_IDENTITY_INVALID) from None
    if len(state) != 1 or value < 0:
        raise ContainmentFailure(ContainmentReason.PROCESS_IDENTITY_INVALID)
    return state, value


def _proc_start_time(proc_fd: int) -> int:
    return _proc_state_and_start_time(proc_fd)[1]


def capture_process_identity(pid: int) -> ProcessIdentity:
    """Capture a non-reaped child identity for later membership verification."""
    proc_fd = _open_proc_pid(pid)
    try:
        return ProcessIdentity(pid, _proc_start_time(proc_fd))
    finally:
        os.close(proc_fd)


def _proc_cgroup(proc_fd: int) -> str:
    raw = _read_control(
        proc_fd, "cgroup", _MAX_PROC_TEXT,
        reason=ContainmentReason.PROCESS_GONE, failure=True,
    )
    try:
        return _unified_membership(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise ContainmentFailure(ContainmentReason.PROCESS_CGROUP_MALFORMED) from None
    except ContainmentError:
        raise ContainmentFailure(ContainmentReason.PROCESS_CGROUP_MALFORMED) from None


def _parse_populated(raw: bytes) -> bool:
    try:
        lines = raw.decode("ascii").splitlines()
        pairs = [line.split() for line in lines]
    except UnicodeDecodeError:
        raise ContainmentFailure(ContainmentReason.EVENTS_MALFORMED) from None
    values = [parts[1] for parts in pairs if len(parts) == 2 and parts[0] == "populated"]
    if len(values) != 1 or values[0] not in ("0", "1"):
        raise ContainmentFailure(ContainmentReason.EVENTS_MALFORMED)
    return values[0] == "1"


@dataclass
class _WalkFrame:
    fd: int
    iterator: object | None
    depth: int
    parent_fd: int | None = None
    name: str | None = None
    identity: tuple[int, int] | None = None

    def close(self, *, strict: bool) -> None:
        """Release both resources once; strict cleanup maps the first close fault."""
        failure: OSError | None = None
        iterator, self.iterator = self.iterator, None
        if iterator is not None:
            try:
                iterator.close()
            except OSError as exc:
                failure = exc
        fd, self.fd = self.fd, -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError as exc:
                if failure is None:
                    failure = exc
        if strict and failure is not None:
            raise ContainmentFailure(ContainmentReason.REMOVE_FAILED,
                                     _os_errno(failure)) from None


def _append_walk_frame(stack: list[_WalkFrame], frame: _WalkFrame) -> None:
    """Tiny ownership-transfer seam used by cancellation fault tests."""
    stack.append(frame)


class DirectCgroupV2:
    """Exclusive parent handle for one acquired cooperative cgroup-v2 leaf."""

    kind = ContainmentKind.CGROUP_V2
    containment_assurance = ContainmentAssurance.COOPERATIVE_SCOPE
    cooperative_settlement_capable = True
    tree_proof_capable = False
    escape_protected = False

    def __init__(self, *, parent_fd: int, leaf_fd: int, procs_read_fd: int,
                 procs_write_fd: int, events_fd: int, kill_fd: int,
                 leaf_name: str, membership: str) -> None:
        self._parent_fd = parent_fd
        self._leaf_fd = leaf_fd
        self._procs_read_fd = procs_read_fd
        self._procs_write_fd = procs_write_fd
        self._events_fd = events_fd
        self._kill_fd = kill_fd
        self._leaf_name = leaf_name
        self._membership = membership
        st = os.fstat(leaf_fd)
        self._leaf_identity = (st.st_dev, st.st_ino)
        self._kill_sent = False
        self._binding_attempted = False
        self._closed = False
        self._removed = False

    @property
    def containment_id(self) -> str:
        return f"direct/{self._leaf_name}"

    @property
    def membership(self) -> str:
        return self._membership

    def _require_open(self) -> None:
        if self._closed or self._removed:
            raise ContainmentRefused(ContainmentReason.HANDLE_CLOSED)

    def _verify_open_proc(self, identity: ProcessIdentity,
                          proc_fd: int) -> MembershipVerification:
        if _proc_start_time(proc_fd) != identity.start_time_ticks:
            return MembershipVerification(False, ContainmentReason.PROCESS_IDENTITY_CHANGED)
        if _proc_cgroup(proc_fd) != self._membership:
            return MembershipVerification(False, ContainmentReason.PROCESS_CGROUP_MISMATCH)
        pids = _parse_pid_lines(_read_fd(
            self._procs_read_fd, _MAX_PROC_TEXT,
            reason=ContainmentReason.PROCESS_CGROUP_MALFORMED,
        ))
        if identity.pid not in pids:
            return MembershipVerification(False, ContainmentReason.LEAF_MEMBERSHIP_MISSING)
        if _proc_start_time(proc_fd) != identity.start_time_ticks:
            return MembershipVerification(False, ContainmentReason.PROCESS_IDENTITY_CHANGED)
        return MembershipVerification(True, ContainmentReason.VERIFIED)

    def bind_pid(self, identity: ProcessIdentity) -> MembershipVerification:
        """Bind and verify one exact PID while its child is stopped before exec.

        This is parent-only authority: the target receives no cgroup descriptor.
        The caller must first park the child with a kernel-observed ``T``/``t``
        state and must not resume it unless this method returns ``verified=True``.
        One acquired containment permits exactly one binding attempt.
        """
        self._require_open()
        if type(identity) is not ProcessIdentity:
            raise ContainmentRefused(ContainmentReason.PROCESS_IDENTITY_INVALID)
        if self._binding_attempted:
            raise ContainmentRefused(ContainmentReason.BINDING_ALREADY_USED)
        proc_fd = _open_proc_pid(identity.pid)
        try:
            state, start_time = _proc_state_and_start_time(proc_fd)
            if start_time != identity.start_time_ticks:
                return MembershipVerification(
                    False, ContainmentReason.PROCESS_IDENTITY_CHANGED)
            if state not in ("T", "t"):
                return MembershipVerification(False, ContainmentReason.PROCESS_NOT_PARKED)
            self._binding_attempted = True
            payload = f"{identity.pid}\n".encode("ascii")
            try:
                written = os.write(self._procs_write_fd, payload)
            except OSError as exc:
                raise ContainmentFailure(ContainmentReason.BINDING_WRITE_FAILED,
                                         _os_errno(exc)) from None
            if written != len(payload):
                raise ContainmentFailure(ContainmentReason.BINDING_WRITE_FAILED)
            return self._verify_open_proc(identity, proc_fd)
        except ContainmentFailure:
            raise
        finally:
            os.close(proc_fd)

    def verify_pid(self, identity: ProcessIdentity) -> MembershipVerification:
        """Independently bind PID, start time, proc membership and leaf membership."""
        self._require_open()
        if type(identity) is not ProcessIdentity:
            raise ContainmentRefused(ContainmentReason.PROCESS_IDENTITY_INVALID)
        try:
            proc_fd = _open_proc_pid(identity.pid)
        except ContainmentFailure as exc:
            return MembershipVerification(False, exc.reason)
        try:
            return self._verify_open_proc(identity, proc_fd)
        except ContainmentFailure as exc:
            return MembershipVerification(False, exc.reason)
        finally:
            os.close(proc_fd)

    def populated(self) -> bool:
        self._require_open()
        return _parse_populated(_read_fd(
            self._events_fd, _MAX_EVENTS_TEXT,
            reason=ContainmentReason.EVENTS_MALFORMED,
        ))

    def _leaf_identity_current(self) -> bool:
        try:
            open_st = os.fstat(self._leaf_fd)
            named_st = os.stat(self._leaf_name, dir_fd=self._parent_fd,
                               follow_symlinks=False)
        except OSError:
            return False
        return (stat.S_ISDIR(open_st.st_mode) and stat.S_ISDIR(named_st.st_mode)
                and (open_st.st_dev, open_st.st_ino) == self._leaf_identity
                and (named_st.st_dev, named_st.st_ino) == self._leaf_identity)

    def _remove_descendants(self, directory_fd: int, deadline: float) -> None:
        """Bounded iterative post-order removal; ``directory_fd`` itself remains."""
        stack: list[_WalkFrame] = []
        entries_seen = 0
        cgroups_seen = 0
        root_fd = -1
        root_iterator = None
        root_frame: _WalkFrame | None = None
        try:
            root_fd = os.dup(directory_fd)
            root_iterator = os.scandir(root_fd)
            root_frame = _WalkFrame(root_fd, root_iterator, 0)
            _append_walk_frame(stack, root_frame)
        except BaseException as exc:
            if root_frame is not None:
                root_frame.close(strict=False)
            else:
                if root_iterator is not None:
                    try:
                        root_iterator.close()
                    except OSError:
                        pass
                if root_fd >= 0:
                    _close_quietly(root_fd)
            if isinstance(exc, OSError):
                raise ContainmentFailure(ContainmentReason.REMOVE_FAILED,
                                         _os_errno(exc)) from None
            raise
        try:
            while stack:
                if time.monotonic() >= deadline:
                    raise ContainmentFailure(ContainmentReason.DEADLINE_EXPIRED)
                frame = stack[-1]
                if frame.iterator is None:
                    raise ContainmentFailure(ContainmentReason.REMOVE_FAILED)
                try:
                    entry = next(frame.iterator)
                except StopIteration:
                    if frame.parent_fd is not None:
                        if time.monotonic() >= deadline:
                            raise ContainmentFailure(ContainmentReason.DEADLINE_EXPIRED)
                        try:
                            current = os.stat(
                                frame.name, dir_fd=frame.parent_fd,
                                follow_symlinks=False,
                            )
                        except OSError as exc:
                            raise ContainmentFailure(
                                ContainmentReason.REMOVE_FAILED,
                                _os_errno(exc),
                            ) from None
                        if (not stat.S_ISDIR(current.st_mode)
                                or (current.st_dev, current.st_ino) != frame.identity):
                            raise ContainmentRefused(
                                ContainmentReason.DESCENDANT_UNSAFE)
                        frame.close(strict=True)
                        try:
                            _rmdir_cgroup(frame.name, frame.parent_fd)
                        except OSError as exc:
                            raise ContainmentFailure(
                                ContainmentReason.REMOVE_FAILED,
                                _os_errno(exc),
                            ) from None
                    else:
                        frame.close(strict=True)
                    stack.pop()
                    continue
                except OSError as exc:
                    raise ContainmentFailure(ContainmentReason.REMOVE_FAILED,
                                             _os_errno(exc)) from None

                entries_seen += 1
                if entries_seen > _MAX_DESCENDANT_ENTRIES:
                    raise ContainmentFailure(ContainmentReason.DESCENDANT_LIMIT)
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise ContainmentFailure(ContainmentReason.REMOVE_FAILED,
                                             _os_errno(exc)) from None
                if stat.S_ISREG(info.st_mode):
                    continue                     # kernel-generated cgroup control file
                if not stat.S_ISDIR(info.st_mode):
                    raise ContainmentRefused(ContainmentReason.DESCENDANT_UNSAFE)
                child_depth = frame.depth + 1
                cgroups_seen += 1
                if (child_depth > _MAX_DESCENDANT_DEPTH
                        or cgroups_seen > _MAX_DESCENDANT_CGROUPS):
                    raise ContainmentFailure(ContainmentReason.DESCENDANT_LIMIT)
                child_fd = -1
                child_iterator = None
                child_frame: _WalkFrame | None = None
                try:
                    child_fd = os.open(entry.name, _DIR_FLAGS, dir_fd=frame.fd)
                    child_st = os.fstat(child_fd)
                    if ((child_st.st_dev, child_st.st_ino) != (info.st_dev, info.st_ino)
                            or _fstatfs_type(child_fd) != _CGROUP2_SUPER_MAGIC):
                        raise ContainmentRefused(ContainmentReason.DESCENDANT_UNSAFE)
                    child_iterator = os.scandir(child_fd)
                    child_frame = _WalkFrame(
                        child_fd, child_iterator, child_depth,
                        parent_fd=frame.fd, name=entry.name,
                        identity=(info.st_dev, info.st_ino),
                    )
                    _append_walk_frame(stack, child_frame)
                except BaseException as exc:
                    if child_frame is not None:
                        child_frame.close(strict=False)
                    else:
                        if child_iterator is not None:
                            try:
                                child_iterator.close()
                            except OSError:
                                pass
                        if child_fd >= 0:
                            _close_quietly(child_fd)
                    if isinstance(exc, OSError):
                        raise ContainmentFailure(
                            ContainmentReason.REMOVE_FAILED,
                            _os_errno(exc),
                        ) from None
                    raise
        finally:
            for frame in reversed(stack):
                frame.close(strict=False)

    def kill_settle_remove(self, deadline: float) -> ContainmentSettlement:
        """Kill, await recursive emptiness and remove under one absolute deadline."""
        self._require_open()
        deadline = _validate_deadline(deadline)
        if time.monotonic() >= deadline:
            return ContainmentSettlement(False, False, False,
                                         ContainmentReason.DEADLINE_EXPIRED)
        if not self._leaf_identity_current():
            return ContainmentSettlement(False, False, False,
                                         ContainmentReason.LEAF_IDENTITY_CHANGED)
        if not self._kill_sent:
            try:
                written = os.write(self._kill_fd, b"1\n")
                if written != 2:
                    return ContainmentSettlement(False, False, False,
                                                 ContainmentReason.KILL_FAILED)
                self._kill_sent = True
            except OSError as exc:
                return ContainmentSettlement(False, False, False,
                                             ContainmentReason.KILL_FAILED,
                                             _os_errno(exc))
        while True:
            try:
                occupied = self.populated()
            except ContainmentFailure as exc:
                return ContainmentSettlement(True, False, False, exc.reason, exc.os_errno)
            if not occupied:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ContainmentSettlement(True, False, False,
                                             ContainmentReason.DEADLINE_EXPIRED)
            time.sleep(min(0.02, remaining))
        try:
            self._remove_descendants(self._leaf_fd, deadline)
            if self.populated():
                return ContainmentSettlement(True, False, False,
                                             ContainmentReason.LEAF_NOT_EMPTY)
            if time.monotonic() >= deadline:
                return ContainmentSettlement(True, True, False,
                                             ContainmentReason.DEADLINE_EXPIRED)
            if not self._leaf_identity_current():
                return ContainmentSettlement(True, True, False,
                                             ContainmentReason.LEAF_IDENTITY_CHANGED)
            _rmdir_cgroup(self._leaf_name, self._parent_fd)
        except ContainmentError as exc:
            return ContainmentSettlement(True, False, False, exc.reason, exc.os_errno)
        except OSError as exc:
            return ContainmentSettlement(True, True, False,
                                         ContainmentReason.REMOVE_FAILED,
                                         _os_errno(exc))
        self._removed = True
        self.close()
        return ContainmentSettlement(True, True, True, ContainmentReason.SETTLED)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for name in ("_kill_fd", "_events_fd", "_procs_write_fd",
                     "_procs_read_fd", "_leaf_fd", "_parent_fd"):
            fd = getattr(self, name)
            if fd >= 0:
                _close_quietly(fd)
                setattr(self, name, -1)


def _cleanup_failed_acquisition(*, fds: list[int], created: bool,
                                leaf_name: str, parent_fd: int,
                                preserve: BaseException) -> None:
    """Best-effort cleanup which never replaces cancellation or ``SystemExit``."""
    for fd in reversed(fds):
        _close_quietly(fd)
    if not created:
        return
    try:
        _rmdir_cgroup(leaf_name, parent_fd)
    except OSError as rollback:
        if isinstance(preserve, Exception):
            raise ContainmentFailure(ContainmentReason.LEAF_ROLLBACK_FAILED,
                                     _os_errno(rollback)) from preserve


def _acquire_from_parent(request_id: str, discovered: _DiscoveredParent) -> DirectCgroupV2:
    request_id = _validate_request_id(request_id)
    leaf_name = f"quarry-{request_id}"
    created = False
    fds: list[int] = []
    try:
        try:
            _mkdir_leaf(leaf_name, discovered.fd)
            created = True
        except FileExistsError:
            raise ContainmentRefused(ContainmentReason.LEAF_COLLISION, errno.EEXIST) from None
        except OSError as exc:
            reason = (ContainmentReason.DELEGATION_REFUSED
                      if _os_errno(exc) in (errno.EACCES, errno.EPERM, errno.EROFS)
                      else ContainmentReason.LEAF_CREATE_FAILED)
            exception = ContainmentRefused if reason is ContainmentReason.DELEGATION_REFUSED else ContainmentFailure
            raise exception(reason, _os_errno(exc)) from None
        leaf_fd = os.open(leaf_name, _DIR_FLAGS, dir_fd=discovered.fd)
        fds.append(leaf_fd)
        leaf_st = os.fstat(leaf_fd)
        named_st = os.stat(leaf_name, dir_fd=discovered.fd, follow_symlinks=False)
        if (not stat.S_ISDIR(leaf_st.st_mode)
                or (leaf_st.st_dev, leaf_st.st_ino) != (named_st.st_dev, named_st.st_ino)
                or _fstatfs_type(leaf_fd) != _CGROUP2_SUPER_MAGIC):
            raise ContainmentRefused(ContainmentReason.LEAF_CONTROL_UNUSABLE)
        if _read_control(
                leaf_fd, "cgroup.type",
                reason=ContainmentReason.LEAF_CONTROL_UNUSABLE).strip() != b"domain":
            raise ContainmentUnsupported(ContainmentReason.LEAF_DOMAIN_UNUSABLE)
        if _parse_populated(_read_control(
                leaf_fd, "cgroup.events",
                reason=ContainmentReason.LEAF_CONTROL_UNUSABLE)):
            raise ContainmentRefused(ContainmentReason.LEAF_CONTROL_UNUSABLE)
        procs_read = _open_control(
            leaf_fd, "cgroup.procs", _READ_FLAGS,
            reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
        )
        fds.append(procs_read)
        procs_write = _open_control(
            leaf_fd, "cgroup.procs", _WRITE_FLAGS,
            reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
        )
        fds.append(procs_write)
        events = _open_control(
            leaf_fd, "cgroup.events", _READ_FLAGS,
            reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
        )
        fds.append(events)
        kill = _open_leaf_kill(leaf_fd)
        fds.append(kill)
        if _parse_pid_lines(_read_fd(
                procs_read, _MAX_PROC_TEXT,
                reason=ContainmentReason.LEAF_CONTROL_UNUSABLE)):
            raise ContainmentRefused(ContainmentReason.LEAF_CONTROL_UNUSABLE)
        handle = DirectCgroupV2(
            parent_fd=discovered.fd, leaf_fd=leaf_fd,
            procs_read_fd=procs_read, procs_write_fd=procs_write,
            events_fd=events, kill_fd=kill, leaf_name=leaf_name,
            membership=_leaf_membership(discovered.membership, leaf_name),
        )
        discovered.fd = -1
        fds.clear()
        return handle
    except BaseException as original:
        _cleanup_failed_acquisition(
            fds=fds, created=created, leaf_name=leaf_name,
            parent_fd=discovered.fd, preserve=original,
        )
        if isinstance(original, OSError):
            raise ContainmentFailure(ContainmentReason.LEAF_CONTROL_UNUSABLE,
                                     _os_errno(original)) from None
        raise


def acquire_direct_cgroup_v2(request_id: str) -> DirectCgroupV2:
    """Create and prove one usable child under the current delegated cgroup."""
    _validate_request_id(request_id)       # refuse before filesystem discovery
    discovered = _discover_parent()
    try:
        return _acquire_from_parent(request_id, discovered)
    finally:
        discovered.close()
