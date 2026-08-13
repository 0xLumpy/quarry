"""Parent-owned process containment for the killable runner boundary.

This module deliberately does not participate in :mod:`quarry_recon.runner` yet.
It prepares one Linux cgroup-v2 backend whose assurance is *cooperative*: ordinary
forks, ``setsid()``, double-forks and concurrent forks remain in the acquired
subtree, but a deliberately hostile same-UID program may be able to migrate to a
different writable cgroup.  This is an execution-correctness boundary, not a
security sandbox.

The handle is single-owner authority and assumes cooperative, exclusive mutation
of its generated leaf name.  Linux has no directory-FD form of ``rmdir``: the
backend pins and rechecks the acquired inode so a concurrent name replacement
cannot be reported as a successful settlement, but it cannot prevent a hostile
renamer from changing which name-based directory the kernel removes.

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
import fcntl
import math
import os
import stat
import sys
import time
from dataclasses import dataclass, field
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
_PARKED_IDENTITY_AUTHORITY = object()


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
    DESCRIPTOR_CLOSE_FAILED = "descriptor_close_failed"
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
    KILL_AMBIGUOUS = "kill_ambiguous"
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


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ParkedProcessIdentity:
    """Parent-authenticated identity of one stopped session/group leader."""

    process: ProcessIdentity
    parent: ProcessIdentity
    state: str

    def __init__(
        self,
        *,
        process: ProcessIdentity,
        parent: ProcessIdentity,
        state: str,
        _authority: object,
    ) -> None:
        if (_authority is not _PARKED_IDENTITY_AUTHORITY
                or type(process) is not ProcessIdentity
                or type(parent) is not ProcessIdentity
                or state not in ("T", "t")
                or process.pid == parent.pid):
            raise ContainmentRefused(
                ContainmentReason.PROCESS_IDENTITY_INVALID,
            )
        object.__setattr__(self, "process", process)
        object.__setattr__(self, "parent", parent)
        object.__setattr__(self, "state", state)

    def __repr__(self) -> str:
        return "ParkedProcessIdentity(verified=True)"


@dataclass(frozen=True)
class _ProcStatIdentity:
    """One bounded observation from an already-open ``/proc/<pid>``."""

    pid: int
    state: str
    parent_pid: int
    process_group: int
    session: int
    start_time_ticks: int


@dataclass(repr=False)
class _DescriptorCloseClaim:
    """Durable close authority for one numeric descriptor.

    ``fd`` is retained only for bounded reconciliation.  Once a close invocation
    is committed, the corresponding handle attribute is tombstoned before the
    syscall so no later operation can accidentally reuse the numeric authority.
    """

    attribute: str
    fd: int
    identity: tuple[int, ...]
    owned_identity: tuple[int, ...] = ()
    allocation_verified: bool = True
    attempts: int = 0
    disposition: str = "pending"
    os_errno: int | None = None
    faulted: bool = False
    fresh_owned: bool = False

    def __repr__(self) -> str:
        return (
            "DescriptorCloseClaim("
            f"attribute={self.attribute!r}, disposition={self.disposition!r})"
        )


@dataclass
class _PopulationSample:
    """Durable result for one transaction's mandatory population read."""

    state: str = "not_started"
    occupied: bool | None = None
    error: ContainmentFailure | None = None


@dataclass
class _RemoveAttempt:
    """One authenticated, non-replayable removal action."""

    state: str = "not_started"
    os_errno: int | None = None


@dataclass
class _AcquisitionCleanupState:
    """Caller-visible ownership fact for failed-acquisition reconciliation."""

    entered: bool = False
    remove_attempt: _RemoveAttempt = field(default_factory=_RemoveAttempt)


@dataclass
class _UnpublishedRollbackState:
    """Durable facts while revoking a handle that never reached its caller."""

    entered: bool = False
    probe_complete: bool = False
    removable: bool = False
    remove_attempt: _RemoveAttempt = field(default_factory=_RemoveAttempt)


_CLOSE_TERMINAL = frozenset({
    "closed_clean", "closed_after_fault", "gone", "foreign",
    "inspect_failed", "close_failed", "close_ambiguous", "unallocated",
})


@dataclass(frozen=True)
class MembershipVerification:
    verified: bool
    reason: ContainmentReason

    def __post_init__(self) -> None:
        if type(self.verified) is not bool or type(self.reason) is not ContainmentReason:
            raise TypeError("invalid membership verification")
        if self.verified != (self.reason is ContainmentReason.VERIFIED):
            raise ValueError("membership truth and reason disagree")


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
        if self.empty and not self.killed:
            raise ValueError("empty containment requires a completed kill write")
        if self.removed and not self.empty:
            raise ValueError("removed containment must be killed and empty")
        if self.removed != (self.reason is ContainmentReason.SETTLED):
            raise ValueError("settled reason and removal disagree")
        if (self.reason in (ContainmentReason.KILL_FAILED,
                            ContainmentReason.KILL_AMBIGUOUS)
                and self.killed):
            raise ValueError("failed or ambiguous kill cannot claim completion")
        if self.reason is ContainmentReason.SETTLED and self.os_errno is not None:
            raise ValueError("settled containment cannot retain an errno")

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


def _fd_fingerprint(fd: int) -> tuple[int, ...]:
    """Capture stable identity and descriptor flags without rendering them."""
    observed = os.fstat(fd)
    descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    status_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    return (
        observed.st_dev,
        observed.st_ino,
        observed.st_mode,
        observed.st_uid,
        observed.st_gid,
        observed.st_rdev,
        descriptor_flags,
        status_flags,
    )


def _new_close_claim(
    attribute: str, fd: int, *, fresh_owned: bool = False,
) -> _DescriptorCloseClaim:
    if type(attribute) is not str or type(fd) is not int or fd < 0:
        raise ContainmentFailure(ContainmentReason.DESCRIPTOR_CLOSE_FAILED)
    try:
        identity = _fd_fingerprint(fd)
    except OSError as exc:
        raise ContainmentFailure(
            ContainmentReason.DESCRIPTOR_CLOSE_FAILED, _os_errno(exc),
        ) from None
    return _DescriptorCloseClaim(
        attribute, fd, identity, owned_identity=identity,
        fresh_owned=fresh_owned,
    )


def _new_allocation_claim(attribute: str) -> _DescriptorCloseClaim:
    """Pre-register an empty slot before an OS call can return a new FD."""
    return _DescriptorCloseClaim(
        attribute, -1, (), disposition="allocating", fresh_owned=True,
        allocation_verified=False,
    )


def _populate_allocation_claim(
    claim: _DescriptorCloseClaim, allocate,
) -> int:
    if claim.fd != -1 or claim.disposition != "allocating":
        raise ContainmentFailure(ContainmentReason.DESCRIPTOR_CLOSE_FAILED)
    claim.fd = allocate()
    claim.disposition = "fresh_owned"
    try:
        observed = os.fstat(claim.fd)
        claim.owned_identity = (
            observed.st_dev, observed.st_ino, observed.st_mode,
            observed.st_uid, observed.st_gid, observed.st_rdev,
        )
        claim.allocation_verified = True
    except OSError:
        claim.allocation_verified = False
        # The numeric slot is still durably owned.  Full descriptor validation
        # may fail later, but cleanup can adopt the actual identity before its
        # first ambiguous close invocation.
        pass
    except BaseException:
        raise
    return claim.fd


def _remember_cancellation(
    current: BaseException | None, candidate: BaseException | None,
) -> BaseException | None:
    return current if current is not None else candidate


def _tombstone_close_claim(owner, claim: _DescriptorCloseClaim) -> None:
    if owner is not None and getattr(owner, claim.attribute, -1) == claim.fd:
        setattr(owner, claim.attribute, -1)


def _inspect_close_claim(
    claim: _DescriptorCloseClaim, owner,
) -> tuple[str, BaseException | None]:
    if claim.fd < 0:
        claim.disposition = (
            "unallocated" if claim.disposition == "allocating" else "gone"
        )
        return "terminal", None
    if claim.fresh_owned and not claim.identity:
        try:
            observed_stat = os.fstat(claim.fd)
        except OSError as exc:
            claim.faulted = True
            claim.os_errno = _os_errno(exc)
            if exc.errno == errno.EBADF:
                claim.fd = -1
                claim.disposition = "gone"
            else:
                claim.disposition = "inspect_failed"
            _tombstone_close_claim(owner, claim)
            return "terminal", None
        except BaseException as exc:
            if isinstance(exc, Exception):
                claim.faulted = True
                claim.disposition = "inspect_failed"
                _tombstone_close_claim(owner, claim)
                return "terminal", None
            claim.faulted = True
            claim.disposition = "inspect_interrupted"
            return "cancelled", exc
        actual = (
            observed_stat.st_dev, observed_stat.st_ino,
            observed_stat.st_mode, observed_stat.st_uid,
            observed_stat.st_gid, observed_stat.st_rdev,
        )
        if claim.owned_identity and actual != claim.owned_identity:
            claim.faulted = True
            claim.fd = -1
            claim.disposition = "foreign"
            _tombstone_close_claim(owner, claim)
            return "terminal", None
        claim.owned_identity = actual
        if not claim.allocation_verified and claim.attempts == 0:
            # A full descriptor fingerprint may be unavailable, but this is a
            # freshly allocated, unexposed descriptor whose inode identity was
            # captured immediately after allocation and just reauthenticated.
            # One first close invocation is safe; only an ambiguous retry needs
            # the stronger full fingerprint below.
            return "fresh_exact", None
        # Adopt current descriptor flags only after authenticating the inode.
        try:
            claim.identity = _fd_fingerprint(claim.fd)
        except OSError as exc:
            claim.faulted = True
            claim.os_errno = _os_errno(exc)
            claim.disposition = "inspect_failed"
            _tombstone_close_claim(owner, claim)
            return "terminal", None
        except BaseException as exc:
            if not isinstance(exc, Exception):
                claim.faulted = True
                claim.disposition = "inspect_interrupted"
                return "cancelled", exc
            claim.identity = ()
        if not claim.identity:
            # Fresh allocation authority is sufficient for its first close.  A
            # cancellation will reauthenticate the retained inode before retry.
            return "exact", None
    try:
        observed = _fd_fingerprint(claim.fd)
    except OSError as exc:
        claim.faulted = True
        claim.os_errno = _os_errno(exc)
        _tombstone_close_claim(owner, claim)
        if exc.errno == errno.EBADF:
            claim.fd = -1
            claim.disposition = "gone"
        else:
            claim.disposition = "inspect_failed"
        return "terminal", None
    except BaseException as exc:
        if isinstance(exc, Exception):
            claim.faulted = True
            claim.disposition = "inspect_failed"
            _tombstone_close_claim(owner, claim)
            return "terminal", None
        claim.faulted = True
        claim.disposition = "inspect_interrupted"
        return "cancelled", exc
    if observed != claim.identity:
        claim.faulted = True
        claim.fd = -1
        claim.disposition = "foreign"
        _tombstone_close_claim(owner, claim)
        return "terminal", None
    return "exact", None


def _invoke_close_claim(
    claim: _DescriptorCloseClaim, owner,
) -> BaseException | None:
    # Commit ownership consumption before the ambiguous syscall.  The retained
    # claim, not the public handle attribute, remains the recovery authority.
    # Tombstoning may enter Python (for a property or injected trace), so it is
    # deliberately completed before the close-attempt fact is committed.  If it
    # is interrupted, the claim still proves that no raw close was invoked.
    _tombstone_close_claim(owner, claim)
    try:
        # Only local fact writes and the raw syscall share this supported source
        # line.  Cancellation before the line leaves attempts==0; after syscall
        # entry leaves attempts==1 and the numeric slot is never targeted again.
        claim.attempts += 1; claim.disposition = "close_started"; os.close(claim.fd)
    except OSError as exc:
        claim.faulted = True
        claim.os_errno = _os_errno(exc)
        claim.disposition = "close_failed"
        return None
    except BaseException as exc:
        claim.faulted = True
        if isinstance(exc, Exception):
            claim.os_errno = _os_errno(exc)
            claim.disposition = "close_failed"
            return None
        claim.disposition = (
            "close_interrupted" if claim.attempts > 0 else "pending"
        )
        return exc
    claim.fd = -1
    claim.disposition = (
        "closed_after_fault" if claim.faulted or claim.attempts > 1
        else "closed_clean"
    )
    return None


def _drain_close_claims(
    claims: tuple[_DescriptorCloseClaim, ...], *, owner=None,
) -> tuple[BaseException | None, int | None, bool]:
    """Drain every claim and recover one cooperative close cancellation.

    Ordinary faults and inconclusive/foreign numeric descriptors are never
    retried.  Nor is a close syscall retried after cancellation: userspace
    fingerprints cannot distinguish the same open file description from a
    replacement opened on the same inode with the same flags.  Untouched suffix
    claims are still drained before the original cancellation is reraised.
    """
    cancellation: BaseException | None = None

    def drain_one(claim: _DescriptorCloseClaim) -> BaseException | None:
        if claim.disposition in _CLOSE_TERMINAL:
            return None
        if claim.attempts > 0:
            # A raw close syscall is irreversible and its delivery is
            # ambiguous under cancellation.  Never target its numeric slot a
            # second time, even if an inode fingerprint still matches.
            claim.faulted = True
            claim.disposition = "close_ambiguous"
            _tombstone_close_claim(owner, claim)
            return None
        status, interrupted = _inspect_close_claim(claim, owner)
        if interrupted is not None or status not in ("exact", "fresh_exact"):
            return interrupted
        interrupted = _invoke_close_claim(claim, owner)
        if interrupted is not None and claim.attempts > 0:
            claim.disposition = "close_ambiguous"
            _tombstone_close_claim(owner, claim)
        return interrupted

    # Two complete passes form one cooperative-cancellation fence.  Every helper
    # boundary is caught here, so a line interruption before or after the close
    # syscall cannot strand the suffix or leave the owner half-transitioned.
    for pass_number in range(2):
        for claim in claims:
            if claim.disposition in _CLOSE_TERMINAL:
                continue
            try:
                interrupted = drain_one(claim)
            except BaseException as exc:
                claim.faulted = True
                if isinstance(exc, Exception):
                    claim.os_errno = _os_errno(exc)
                    claim.disposition = "inspect_failed"
                    _tombstone_close_claim(owner, claim)
                else:
                    cancellation = _remember_cancellation(cancellation, exc)
                continue
            if interrupted is not None:
                claim.faulted = True
                cancellation = _remember_cancellation(
                    cancellation, interrupted,
                )
        if cancellation is None:
            break

    for claim in claims:
        if claim.disposition not in _CLOSE_TERMINAL:
            claim.faulted = True
            claim.disposition = "close_ambiguous"
            _tombstone_close_claim(owner, claim)

    failure_errno = next(
        (claim.os_errno for claim in claims if claim.os_errno is not None),
        None,
    )
    clean = all(
        claim.disposition in ("closed_clean", "unallocated")
        for claim in claims
    )
    return cancellation, failure_errno, clean


def _close_claims_fenced(
    claims: tuple[_DescriptorCloseClaim, ...], *, owner=None,
) -> tuple[BaseException | None, int | None, bool]:
    """Run descriptor reconciliation behind one outer line-cancellation fence."""
    cancellation: BaseException | None = None
    close_errno: int | None = None
    clean = False
    try:
        cancellation, close_errno, clean = _drain_close_claims(
            claims, owner=owner,
        )
    except BaseException as exc:
        for claim in claims:
            if claim.disposition not in _CLOSE_TERMINAL:
                claim.faulted = True
        if not isinstance(exc, Exception):
            cancellation = exc
        else:
            close_errno = _os_errno(exc)
        retry_cancellation, retry_errno, _retry_clean = _drain_close_claims(
            claims, owner=owner,
        )
        cancellation = _remember_cancellation(
            cancellation, retry_cancellation,
        )
        if close_errno is None:
            close_errno = retry_errno
        clean = False
    return cancellation, close_errno, clean


def _close_claims_guarded(
    claims: tuple[_DescriptorCloseClaim, ...], *, owner=None,
) -> tuple[BaseException | None, int | None, bool]:
    """Re-enter the close fence once if its call boundary is interrupted.

    The lower fence owns interruptions after it starts.  Ownership roots also
    need to cover the Python line on which that fence is invoked: a cooperative
    cancellation can otherwise arrive before the callee executes.  This helper
    is deliberately idempotent and never retries a committed raw close.
    """
    boundary: BaseException | None = None
    close_errno: int | None = None
    clean = False
    try:
        cancellation, close_errno, clean = _close_claims_fenced(
            claims, owner=owner,
        )
    except BaseException as exc:
        boundary = exc
        for claim in claims:
            if claim.disposition not in _CLOSE_TERMINAL:
                claim.faulted = True
        try:
            cancellation, retry_errno, _retry_clean = _close_claims_fenced(
                claims, owner=owner,
            )
        except BaseException as retry_exc:
            cancellation = (
                retry_exc if not isinstance(retry_exc, Exception) else None
            )
            retry_errno = _os_errno(retry_exc)
        if close_errno is None:
            close_errno = retry_errno
        clean = False
    if boundary is not None and not isinstance(boundary, Exception):
        cancellation = _remember_cancellation(boundary, cancellation)
    elif boundary is not None and close_errno is None:
        close_errno = _os_errno(boundary)
    return cancellation, close_errno, clean


def _close_claims_or_raise(
    claims: tuple[_DescriptorCloseClaim, ...], *, owner=None,
) -> None:
    cancellation, close_errno, clean = _close_claims_guarded(
        claims, owner=owner,
    )
    if cancellation is not None:
        raise cancellation
    if not clean:
        raise ContainmentFailure(
            ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
        ) from None


def _recover_claims_and_raise(
    primary: BaseException,
    claims: tuple[_DescriptorCloseClaim, ...],
    *,
    owner=None,
) -> None:
    """Drain an ownership root, then apply cancellation-safe precedence."""
    cancellation, close_errno, clean = _close_claims_guarded(
        claims, owner=owner,
    )
    if not isinstance(primary, Exception):
        raise primary
    if cancellation is not None:
        raise cancellation
    if not clean:
        raise ContainmentFailure(
            ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
        ) from None
    raise primary


def _recover_claims_at_boundary(
    primary: BaseException,
    claims: tuple[_DescriptorCloseClaim, ...],
    *,
    owner=None,
) -> None:
    """Own the source-line boundary into descriptor recovery.

    ``_recover_claims_and_raise`` owns every descriptor once its frame begins.
    This wrapper additionally catches the one supported cooperative cancellation
    that can arrive on the caller's invocation line before that frame executes.
    It then performs the same idempotent reconciliation and gives the earliest
    non-``Exception`` priority over an ordinary primary.
    """
    try:
        boundary: BaseException | None = None
        _recover_claims_and_raise(primary, claims, owner=owner)
    except BaseException as exc:
        boundary = exc
    chosen = (
        primary if not isinstance(primary, Exception)
        else boundary if boundary is not None else primary
    )
    _recover_claims_and_raise(chosen, claims, owner=owner)


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
                  failure: bool = False,
                  _claim: _DescriptorCloseClaim | None = None) -> int:
    claim = _new_allocation_claim("control_fd") if _claim is None else _claim
    try:
        fd = _populate_allocation_claim(
            claim, lambda: os.open(name, flags, dir_fd=dir_fd),
        )
    except OSError as exc:
        error_type = ContainmentFailure if failure else ContainmentRefused
        raise error_type(reason, _os_errno(exc)) from None
    except BaseException:
        _close_claims_fenced((claim,))
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            error_type = ContainmentFailure if failure else ContainmentRefused
            raise error_type(reason)
        return fd
    except BaseException as primary:
        cancellation, close_errno, clean = _close_claims_fenced((claim,))
        if not isinstance(primary, Exception):
            raise primary
        if cancellation is not None:
            raise cancellation
        if not clean:
            raise ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
            ) from primary
        raise


def _open_leaf_kill(
    dir_fd: int, *, _claim: _DescriptorCloseClaim | None = None,
) -> int:
    try:
        return _open_control(
            dir_fd, "cgroup.kill", _WRITE_FLAGS,
            reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
            _claim=_claim,
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
    claim = _new_allocation_claim("control_fd")
    fd = -1
    primary: BaseException | None = None
    result: bytes | None = None
    try:
        try:
            fd = _open_control(
                dir_fd, name, _READ_FLAGS, reason=reason, failure=failure,
                _claim=claim,
            )
            result = _read_fd(fd, limit, reason=reason)
        except BaseException as exc:
            primary = exc
        _close_claims_or_raise((claim,))
        if primary is not None:
            raise primary
        if result is None:
            raise ContainmentFailure(reason)
        return result
    except BaseException as boundary:
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, (claim,))


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
    claim = _new_allocation_claim("fd")
    fd = -1
    primary: BaseException | None = None
    try:
        try:
            try:
                fd = _populate_allocation_claim(
                    claim, lambda: os.open(path, _READ_FLAGS),
                )
                raw = _read_fd(
                    fd, limit,
                    reason=ContainmentReason.CURRENT_CGROUP_UNSAFE,
                )
                result = raw.decode("utf-8")
            except ContainmentError:
                raise
            except (OSError, UnicodeDecodeError) as exc:
                raise ContainmentUnsupported(
                    ContainmentReason.CURRENT_CGROUP_MISSING,
                    _os_errno(exc),
                ) from None
            _close_claims_or_raise((claim,))
            return result
        except BaseException as exc:
            primary = exc
        _recover_claims_at_boundary(primary, (claim,))
    except BaseException as boundary:
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, (claim,))


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
    current = _new_allocation_claim("current_fd")
    claims = [current]
    boundary: BaseException | None = None
    try:
        try:
            _populate_allocation_claim(current, lambda: os.open("/", _DIR_FLAGS))
            for component in components:
                following = _new_allocation_claim("following_fd")
                claims.append(following)
                _populate_allocation_claim(
                    following,
                    lambda component=component: os.open(
                        component, _DIR_FLAGS, dir_fd=current.fd,
                    ),
                )
                _close_claims_or_raise((current,))
                current = following
            return current.fd
        except BaseException as primary:
            boundary = primary
        _recover_claims_at_boundary(boundary, tuple(claims))
    except BaseException as cleanup_boundary:
        chosen = (
            boundary if boundary is not None
            and not isinstance(boundary, Exception) else cleanup_boundary
        )
        _recover_claims_at_boundary(chosen, tuple(claims))


def _walk_dir(parent_fd: int, components: tuple[str, ...]) -> int:
    current = _new_allocation_claim("current_fd")
    claims = [current]
    boundary: BaseException | None = None
    try:
        try:
            _populate_allocation_claim(current, lambda: os.dup(parent_fd))
            for component in components:
                following = _new_allocation_claim("following_fd")
                claims.append(following)
                _populate_allocation_claim(
                    following,
                    lambda component=component: os.open(
                        component, _DIR_FLAGS, dir_fd=current.fd,
                    ),
                )
                _close_claims_or_raise((current,))
                current = following
            return current.fd
        except BaseException as primary:
            boundary = primary
        _recover_claims_at_boundary(boundary, tuple(claims))
    except BaseException as cleanup_boundary:
        chosen = (
            boundary if boundary is not None
            and not isinstance(boundary, Exception) else cleanup_boundary
        )
        _recover_claims_at_boundary(chosen, tuple(claims))


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
    _close_claim: _DescriptorCloseClaim | None = field(
        default=None, repr=False, compare=False,
    )

    def __post_init__(self) -> None:
        if self._close_claim is None:
            self._close_claim = _new_close_claim(
                "fd", self.fd, fresh_owned=True,
            )
        elif self._close_claim.fd != self.fd:
            raise ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
            )

    @classmethod
    def _adopt(
        cls, claim: _DescriptorCloseClaim, membership: str,
    ) -> _DiscoveredParent:
        return cls(claim.fd, membership, claim)

    def close(self) -> None:
        if self.fd < 0 or self._close_claim is None:
            return
        primary: BaseException | None = None
        try:
            try:
                _close_claims_or_raise((self._close_claim,), owner=self)
                return
            except BaseException as exc:
                primary = exc
            # A private discovery owner is best-effort/idempotent after its one
            # raw close invocation.  Preserve this call's cancellation, but a
            # replay must never target a potentially reused numeric descriptor.
            if self.fd >= 0 and primary is not None:
                _recover_claims_at_boundary(
                    primary, (self._close_claim,), owner=self,
                )
            raise primary
        except BaseException as boundary:
            chosen = (
                primary if primary is not None
                and not isinstance(primary, Exception) else boundary
            )
            if self.fd >= 0:
                try:
                    _recover_claims_at_boundary(
                        chosen, (self._close_claim,), owner=self,
                    )
                except BaseException:
                    raise
            raise chosen


def _check_parent_candidate(fd: int) -> None:
    if _fstatfs_type(fd) != _CGROUP2_SUPER_MAGIC:
        raise ContainmentUnsupported(ContainmentReason.CGROUP_V2_MAGIC_MISMATCH)
    try:
        if not os.access(".", os.W_OK | os.X_OK, dir_fd=fd,
                         effective_ids=True, follow_symlinks=False):
            raise ContainmentRefused(ContainmentReason.DELEGATION_REFUSED)
    except (NotImplementedError, TypeError):
        raise ContainmentUnsupported(ContainmentReason.DESCRIPTOR_API_MISSING) from None
    claims: list[_DescriptorCloseClaim] = []
    primary: BaseException | None = None
    try:
        try:
            for name in ("cgroup.procs", "cgroup.threads", "cgroup.subtree_control"):
                control_claim = _new_allocation_claim("control")
                claims.append(control_claim)
                control = _open_control(
                    fd, name, _WRITE_FLAGS, _claim=control_claim,
                )
                _close_claims_or_raise((control_claim,))
            return
        except BaseException as exc:
            primary = exc
        _recover_claims_at_boundary(primary, tuple(reversed(claims)))
    except BaseException as boundary:
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, tuple(reversed(claims)))


def _discover_parent() -> _DiscoveredParent:
    claims: list[_DescriptorCloseClaim] = []
    mount_fd = None
    parent_fd = None
    discovered: _DiscoveredParent | None = None
    primary: BaseException | None = None
    try:
        try:
            _require_features()
            membership = _unified_membership(_read_bounded_path(_SELF_CGROUP))
            mounts = _cgroup2_mounts(_read_bounded_path(_MOUNTINFO))
            if not mounts:
                raise ContainmentUnsupported(
                    ContainmentReason.CGROUP_V2_MOUNT_MISSING,
                )
            saw_read_only = False
            last_error: ContainmentError | None = None
            for mount in mounts:
                if not mount.writable:
                    saw_read_only = True
                    continue
                mount_claim = _new_allocation_claim("mount_fd")
                claims.append(mount_claim)
                mount_fd = None
                try:
                    mount_fd = _populate_allocation_claim(
                        mount_claim, lambda: _open_absolute_dir(mount.point),
                    )
                    if _fstatfs_type(mount_fd) != _CGROUP2_SUPER_MAGIC:
                        raise ContainmentUnsupported(
                            ContainmentReason.CGROUP_V2_MAGIC_MISMATCH,
                        )
                    for components in _relative_candidates(mount.root, membership):
                        parent_claim = _new_allocation_claim("parent_fd")
                        claims.append(parent_claim)
                        parent_fd = None
                        try:
                            parent_fd = _populate_allocation_claim(
                                parent_claim,
                                lambda components=components: _walk_dir(
                                    mount_fd, components,
                                ),
                            )
                            pids = _parse_pid_lines(_read_control(
                                parent_fd, "cgroup.procs",
                            ))
                            if os.getpid() not in pids:
                                _close_claims_or_raise((parent_claim,))
                                parent_fd = None
                                continue
                            _check_parent_candidate(parent_fd)
                            parent_claim.attribute = "fd"
                            discovered = _DiscoveredParent._adopt(
                                parent_claim, membership,
                            )
                            _close_claims_or_raise((mount_claim,))
                            return discovered
                        except ContainmentError as exc:
                            last_error = exc
                            _close_claims_or_raise((parent_claim,))
                            parent_fd = None
                        except OSError as exc:
                            last_error = ContainmentRefused(
                                ContainmentReason.CURRENT_CGROUP_UNSAFE,
                                _os_errno(exc),
                            )
                            _close_claims_or_raise((parent_claim,))
                            parent_fd = None
                except ContainmentError as exc:
                    last_error = exc
                except OSError as exc:
                    last_error = ContainmentRefused(
                        ContainmentReason.CURRENT_CGROUP_UNSAFE,
                        _os_errno(exc),
                    )
                _close_claims_or_raise((mount_claim,))
                mount_fd = None
            if last_error is not None:
                raise last_error
            if saw_read_only:
                raise ContainmentUnsupported(
                    ContainmentReason.CGROUP_V2_MOUNT_READ_ONLY,
                )
            raise ContainmentUnsupported(ContainmentReason.CURRENT_CGROUP_MISSING)
        except BaseException as exc:
            primary = exc
        _recover_claims_at_boundary(
            primary, tuple(reversed(claims)), owner=discovered,
        )
    except BaseException as boundary:
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(
            chosen, tuple(reversed(claims)), owner=discovered,
        )


def probe_direct_cgroup_v2() -> ContainmentProbe:
    """Inspect the current hierarchy without creating or modifying a cgroup."""
    discovered: _DiscoveredParent | None = None
    primary: BaseException | None = None
    cleanup: BaseException | None = None
    try:
        try:
            discovered = _discover_parent()
            discovered.close()
            return ContainmentProbe(True, ContainmentReason.CANDIDATE)
        except BaseException as exc:
            primary = exc
        if discovered is not None:
            try:
                discovered.close()
            except BaseException as exc:
                cleanup = exc
            if (cleanup is not None and not isinstance(cleanup, Exception)
                    and discovered.fd >= 0):
                try:
                    discovered.close()
                except BaseException as exc:
                    if isinstance(cleanup, Exception):
                        cleanup = exc
    except BaseException as boundary:
        if cleanup is None or isinstance(cleanup, Exception):
            cleanup = boundary
        if discovered is not None and discovered.fd >= 0:
            try:
                discovered.close()
            except BaseException as exc:
                if cleanup is None or isinstance(cleanup, Exception):
                    cleanup = exc
    if primary is None:
        primary = cleanup or ContainmentFailure(
            ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
        )
    if not isinstance(primary, Exception):
        raise primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        raise cleanup
    error = cleanup if isinstance(cleanup, ContainmentError) else primary
    if isinstance(error, ContainmentError):
        return ContainmentProbe(False, error.reason)
    raise primary


def _mkdir_leaf(name: str, parent_fd: int) -> None:
    os.mkdir(name, 0o700, dir_fd=parent_fd)


def _rmdir_cgroup(name: str, parent_fd: int) -> None:
    os.rmdir(name, dir_fd=parent_fd)


def _remove_authenticated_once(
    attempt: _RemoveAttempt,
    *,
    name: str,
    parent_fd: int,
    identity: tuple[int, int],
    anchor: _DescriptorCloseClaim,
    reason: ContainmentReason = ContainmentReason.LEAF_ROLLBACK_FAILED,
) -> None:
    """Remove a cooperative name while pinning and verifying its acquired inode.

    The post-action link check prevents a stale name lookup from being laundered
    into ``removed`` truth.  It is detection, not atomic name-to-FD removal; the
    module-level cooperative namespace assumption remains required.
    """
    if attempt.state == "removed":
        return
    if attempt.state != "not_started":
        raise ContainmentFailure(
            reason, attempt.os_errno,
        )
    if (type(anchor) is not _DescriptorCloseClaim or anchor.fd < 0
            or anchor.attempts != 0
            or anchor.disposition in _CLOSE_TERMINAL):
        attempt.state = "refused"
        raise ContainmentFailure(reason)
    try:
        held = os.fstat(anchor.fd)
    except OSError as exc:
        attempt.state = "failed"
        attempt.os_errno = _os_errno(exc)
        raise ContainmentFailure(reason, attempt.os_errno) from None
    if (not stat.S_ISDIR(held.st_mode)
            or (held.st_dev, held.st_ino) != identity):
        attempt.state = "refused"
        raise ContainmentFailure(reason)
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        attempt.state = "failed"
        attempt.os_errno = _os_errno(exc)
        raise ContainmentFailure(
            reason, attempt.os_errno,
        ) from None
    if (not stat.S_ISDIR(named.st_mode)
            or (named.st_dev, named.st_ino) != identity):
        attempt.state = "refused"
        raise ContainmentFailure(
            reason,
        )
    try:
        # A trace before this line leaves the action not_started and eligible
        # for one authenticated recovery.  Any exception from inside the helper
        # is ambiguous and permanently consumes the removal authority.
        attempt.state = "attempting"; _rmdir_cgroup(name, parent_fd)
        unlinked = os.fstat(anchor.fd)
        if ((unlinked.st_dev, unlinked.st_ino) != identity
                or unlinked.st_nlink != 0):
            attempt.state = "ambiguous"
            raise ContainmentFailure(reason)
        attempt.state = "removed"
    except OSError as exc:
        attempt.state = "failed"
        attempt.os_errno = _os_errno(exc)
        raise ContainmentFailure(
            reason, attempt.os_errno,
        ) from None
    except BaseException:
        if attempt.state == "attempting":
            attempt.state = "ambiguous"
        raise


def _remove_authenticated_fenced(
    attempt: _RemoveAttempt,
    *,
    name: str,
    parent_fd: int,
    identity: tuple[int, int],
    anchor: _DescriptorCloseClaim,
    reason: ContainmentReason = ContainmentReason.LEAF_ROLLBACK_FAILED,
) -> None:
    """Recover only a conclusively uninvoked removal, then preserve cancellation."""
    try:
        _remove_authenticated_once(
            attempt, name=name, parent_fd=parent_fd, identity=identity,
            anchor=anchor, reason=reason,
        )
        return
    except BaseException as primary:
        if not isinstance(primary, Exception) and attempt.state == "not_started":
            try:
                _remove_authenticated_once(
                    attempt, name=name, parent_fd=parent_fd,
                    identity=identity, anchor=anchor, reason=reason,
                )
            except BaseException:
                pass
        raise primary


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _leaf_membership(parent_membership: str, leaf_name: str) -> str:
    return "/" + leaf_name if parent_membership == "/" else parent_membership + "/" + leaf_name


def _open_proc_pid(pid: int) -> int:
    """Open one proc directory behind an outer allocation-ownership fence."""
    return _open_proc_pid_owner(pid)


def _open_proc_pid_owner(pid: int) -> int:
    root = _new_allocation_claim("proc_root_fd")
    child = _new_allocation_claim("proc_pid_fd")
    primary: BaseException | None = None
    result = -1
    try:
        try:
            result = _open_proc_pid_transaction(pid, root=root, child=child)
            # The inner transaction consumes the root before transferring the
            # child.  This outer owner still retains both claims until RET.
            if root.fd >= 0:
                raise ContainmentFailure(
                    ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
                )
            return result
        except BaseException as exc:
            primary = exc
        if primary is not None:
            _recover_claims_at_boundary(primary, (root, child))
        raise ContainmentFailure(ContainmentReason.PROCESS_IDENTITY_INVALID)
    except BaseException as boundary:
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, (root, child))


def _open_proc_pid_transaction(
    pid: int, *, root: _DescriptorCloseClaim, child: _DescriptorCloseClaim,
) -> int:
    _positive_pid(pid)
    primary: BaseException | None = None
    try:
        try:
            _populate_allocation_claim(
                root, lambda: _open_absolute_dir(_PROC_ROOT),
            )
            _populate_allocation_claim(
                child, lambda: os.open(str(pid), _DIR_FLAGS, dir_fd=root.fd),
            )
        except FileNotFoundError:
            primary = ContainmentFailure(ContainmentReason.PROCESS_GONE)
        except OSError as exc:
            primary = ContainmentFailure(
                ContainmentReason.PROCESS_IDENTITY_INVALID, _os_errno(exc),
            )
        except BaseException as exc:
            primary = exc
        if primary is not None:
            raise primary
        _close_claims_or_raise((root,))
        return child.fd
    except BaseException as boundary:
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, (root, child))


def _proc_stat_identity(proc_fd: int) -> _ProcStatIdentity:
    """Parse the identity-bearing fields from one proc stat snapshot."""
    raw = _read_control(
        proc_fd, "stat", _MAX_PROC_TEXT,
        reason=ContainmentReason.PROCESS_GONE, failure=True,
    )
    try:
        text = raw.decode("ascii")
        close = text.rindex(")")
        pid = int(text[:text.index(" (")])
        fields = text[close + 1:].split()
        state = fields[0]
        parent_pid = int(fields[1])
        process_group = int(fields[2])
        session = int(fields[3])
        start_time_ticks = int(fields[19])
    except (UnicodeDecodeError, ValueError, IndexError):
        raise ContainmentFailure(ContainmentReason.PROCESS_IDENTITY_INVALID) from None
    if (len(state) != 1 or pid <= 0 or parent_pid < 0
            or process_group < 0 or session < 0 or start_time_ticks < 0):
        raise ContainmentFailure(ContainmentReason.PROCESS_IDENTITY_INVALID)
    return _ProcStatIdentity(
        pid=pid,
        state=state,
        parent_pid=parent_pid,
        process_group=process_group,
        session=session,
        start_time_ticks=start_time_ticks,
    )


def _proc_state_and_start_time(proc_fd: int) -> tuple[str, int]:
    observed = _proc_stat_identity(proc_fd)
    return observed.state, observed.start_time_ticks


def _proc_start_time(proc_fd: int) -> int:
    return _proc_state_and_start_time(proc_fd)[1]


def capture_process_identity(pid: int) -> ProcessIdentity:
    """Capture a non-reaped child identity for later membership verification."""
    claim: _DescriptorCloseClaim | None = None
    primary: BaseException | None = None
    identity: ProcessIdentity | None = None
    try:
        try:
            claim = _open_proc_close_claim(pid, "proc_fd")
            identity = ProcessIdentity(pid, _proc_start_time(claim.fd))
        except BaseException as exc:
            primary = exc
        claims = () if claim is None else (claim,)
        _close_claims_or_raise(claims)
        if primary is not None:
            raise primary
        if identity is None:
            raise ContainmentFailure(
                ContainmentReason.PROCESS_IDENTITY_INVALID,
            )
        return identity
    except BaseException as boundary:
        claims = () if claim is None else (claim,)
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, claims)


def _open_proc_close_claim(pid: int, attribute: str) -> _DescriptorCloseClaim:
    claim = _new_allocation_claim(attribute)
    primary: BaseException | None = None
    try:
        try:
            _populate_allocation_claim(claim, lambda: _open_proc_pid(pid))
            claim.identity = _fd_fingerprint(claim.fd)
            claim.allocation_verified = True
            claim.disposition = "pending"
            return claim
        except BaseException as exc:
            primary = exc
            if (isinstance(exc, OSError) and claim.owned_identity
                    and not claim.identity):
                claim.allocation_verified = False
        if primary is not None:
            if isinstance(primary, OSError):
                mapped: BaseException = ContainmentFailure(
                    ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
                    _os_errno(primary),
                )
                _recover_claims_at_boundary(mapped, (claim,))
            _recover_claims_at_boundary(primary, (claim,))
        raise ContainmentFailure(ContainmentReason.PROCESS_IDENTITY_INVALID)
    except BaseException as boundary:
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, (claim,))


def _finish_proc_claim(
    claim: _DescriptorCloseClaim | None,
    *,
    primary: BaseException | None,
    result,
):
    claims: tuple[_DescriptorCloseClaim, ...] = ()
    try:
        claims = () if claim is None else (claim,)
        _close_claims_or_raise(claims)
        if primary is not None:
            raise primary
        return result
    except BaseException as boundary:
        if not claims and claim is not None:
            claims = (claim,)
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, claims)


def capture_parked_process_identity(
    pid: int,
    expected_parent: ProcessIdentity,
) -> ParkedProcessIdentity:
    """Prove a stable stopped child and its exact, still-live parent.

    Both proc directories remain open across all four observations.  This binds
    parentage to start-time identities instead of trusting reusable integer PIDs.
    """
    _positive_pid(pid)
    if type(expected_parent) is not ProcessIdentity or pid == expected_parent.pid:
        raise ContainmentRefused(ContainmentReason.PROCESS_IDENTITY_INVALID)
    parent_claim: _DescriptorCloseClaim | None = None
    child_claim: _DescriptorCloseClaim | None = None
    primary: BaseException | None = None
    proof: ParkedProcessIdentity | None = None
    try:
        try:
            parent_claim = _open_proc_close_claim(
                expected_parent.pid, "parent_proc_fd",
            )
            child_claim = _open_proc_close_claim(pid, "child_proc_fd")
            parent_before = _proc_stat_identity(parent_claim.fd)
            child_before = _proc_stat_identity(child_claim.fd)
            child_after = _proc_stat_identity(child_claim.fd)
            parent_after = _proc_stat_identity(parent_claim.fd)

            if (parent_before.state in ("Z", "X", "x")
                    or parent_after.state in ("Z", "X", "x")):
                raise ContainmentFailure(ContainmentReason.PROCESS_GONE)
            if (parent_before.pid != expected_parent.pid
                    or parent_after.pid != expected_parent.pid):
                raise ContainmentRefused(
                    ContainmentReason.PROCESS_IDENTITY_INVALID,
                )
            if (parent_before.start_time_ticks != expected_parent.start_time_ticks
                    or parent_after.start_time_ticks
                    != expected_parent.start_time_ticks):
                raise ContainmentRefused(
                    ContainmentReason.PROCESS_IDENTITY_CHANGED,
                )
            if (child_before.state in ("Z", "X", "x")
                    or child_after.state in ("Z", "X", "x")):
                raise ContainmentFailure(ContainmentReason.PROCESS_GONE)
            if (child_before.state not in ("T", "t")
                    or child_after.state not in ("T", "t")):
                raise ContainmentRefused(
                    ContainmentReason.PROCESS_NOT_PARKED,
                )
            if (child_before.pid != pid
                    or child_before.parent_pid != expected_parent.pid
                    or child_before.process_group != pid
                    or child_before.session != pid):
                raise ContainmentRefused(
                    ContainmentReason.PROCESS_IDENTITY_INVALID,
                )
            if child_before != child_after:
                raise ContainmentRefused(
                    ContainmentReason.PROCESS_IDENTITY_CHANGED,
                )
            proof = ParkedProcessIdentity(
                process=ProcessIdentity(pid, child_before.start_time_ticks),
                parent=expected_parent,
                state=child_before.state,
                _authority=_PARKED_IDENTITY_AUTHORITY,
            )
        except BaseException as exc:
            primary = exc
        claims = tuple(
            claim for claim in (child_claim, parent_claim)
            if claim is not None
        )
        _close_claims_or_raise(claims)
        if primary is not None:
            raise primary
        if proof is None:
            raise ContainmentFailure(
                ContainmentReason.PROCESS_IDENTITY_INVALID,
            )
        return proof
    except BaseException as boundary:
        claims = tuple(
            claim for claim in (child_claim, parent_claim)
            if claim is not None
        )
        chosen = (
            primary if primary is not None
            and not isinstance(primary, Exception) else boundary
        )
        _recover_claims_at_boundary(chosen, claims)


def _parked_observation_matches(
    proof: ParkedProcessIdentity,
    parent: _ProcStatIdentity,
    child: _ProcStatIdentity,
) -> bool:
    """Match one held parent/child observation to an opaque parked proof."""
    return (
        parent.pid == proof.parent.pid
        and parent.start_time_ticks == proof.parent.start_time_ticks
        and parent.state not in ("Z", "X", "x")
        and child.pid == proof.process.pid
        and child.start_time_ticks == proof.process.start_time_ticks
        and child.state == proof.state
        and child.parent_pid == proof.parent.pid
        and child.process_group == proof.process.pid
        and child.session == proof.process.pid
    )


def _proc_cgroup(proc_fd: int) -> str:
    raw = _read_control(
        proc_fd, "cgroup", _MAX_PROC_TEXT,
        reason=ContainmentReason.PROCESS_GONE, failure=True,
    )
    try:
        return _unified_membership(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise ContainmentFailure(ContainmentReason.PROCESS_CGROUP_MALFORMED) from None
    except ContainmentError as exc:
        if exc.reason is ContainmentReason.DESCRIPTOR_CLOSE_FAILED:
            raise
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
    close_claim: _DescriptorCloseClaim | None = None
    remove_attempt: _RemoveAttempt = field(default_factory=_RemoveAttempt)
    ready_to_remove: bool = False
    close_faulted: bool = False

    def __post_init__(self) -> None:
        if self.fd >= 0:
            self.close_claim = _new_close_claim(
                "fd", self.fd, fresh_owned=True,
            )

    def close(self, *, strict: bool, retain_fd: bool = False) -> None:
        """Release both resources once; strict cleanup maps the first close fault."""
        try:
            failure_errno: int | None = None
            cancellation: BaseException | None = None
            iterator = self.iterator
            iterator_attempted = False
            boundary: BaseException | None = None
            if iterator is not None:
                try:
                    iterator_attempted = True; iterator.close()
                except OSError as exc:
                    failure_errno = _os_errno(exc)
                    self.close_faulted = True
                except BaseException as exc:
                    self.close_faulted = True
                    if not isinstance(exc, Exception):
                        cancellation = exc
                        # Directory iterators are stable Python object authority.
                        # One cooperative cancellation receives one safe retry;
                        # an ordinary close fault is never retried.
                        try:
                            iterator.close()
                        except BaseException:
                            pass
                self.iterator = None
            if not retain_fd and self.close_claim is not None:
                interrupted, close_errno, clean = _close_claims_guarded(
                    (self.close_claim,), owner=self,
                )
                cancellation = _remember_cancellation(
                    cancellation, interrupted,
                )
                if not clean:
                    self.close_faulted = True
                    if failure_errno is None:
                        failure_errno = close_errno
        except BaseException as exc:
            boundary = exc
        if boundary is not None:
            failure_errno = locals().get("failure_errno")
            cancellation = locals().get("cancellation")
            iterator = locals().get("iterator", self.iterator)
            iterator_attempted = locals().get("iterator_attempted", False)
            if not isinstance(boundary, Exception):
                cancellation = _remember_cancellation(cancellation, boundary)
            else:
                self.close_faulted = True
                if failure_errno is None:
                    failure_errno = _os_errno(boundary)
            # Never retry an iterator after an ordinary close fault.  If the
            # boundary fired before its invocation, the stable object remains
            # conclusively unattempted and receives its one safe attempt.
            if iterator is not None:
                if not iterator_attempted:
                    try:
                        iterator.close()
                    except BaseException as exc:
                        self.close_faulted = True
                        if not isinstance(exc, Exception):
                            cancellation = _remember_cancellation(
                                cancellation, exc,
                            )
                        elif failure_errno is None:
                            failure_errno = _os_errno(exc)
                self.iterator = None
            if not retain_fd and self.close_claim is not None:
                interrupted, close_errno, clean = _close_claims_guarded(
                    (self.close_claim,), owner=self,
                )
                cancellation = _remember_cancellation(
                    cancellation, interrupted,
                )
                if not clean:
                    self.close_faulted = True
                    if failure_errno is None:
                        failure_errno = close_errno
        if cancellation is not None:
            raise cancellation
        if strict and self.close_faulted:
            raise ContainmentFailure(
                ContainmentReason.REMOVE_FAILED, failure_errno,
            )


def _append_walk_frame(stack: list[_WalkFrame], frame: _WalkFrame) -> None:
    """Tiny ownership-transfer seam used by cancellation fault tests."""
    stack.append(frame)


def _close_walk_frame_owned(frame: _WalkFrame) -> BaseException | None:
    """Consume one frame before its ancestor authority can be released."""
    primary: BaseException | None = None
    cancellation: BaseException | None = None
    try:
        if (frame.ready_to_remove
                and frame.remove_attempt.state == "not_started"
                and frame.parent_fd is not None
                and frame.name is not None
                and frame.identity is not None
                and frame.close_claim is not None):
            _remove_authenticated_fenced(
                frame.remove_attempt,
                name=frame.name,
                parent_fd=frame.parent_fd,
                identity=frame.identity,
                anchor=frame.close_claim,
                reason=ContainmentReason.REMOVE_FAILED,
            )
        frame.close(strict=False)
        return None
    except BaseException as exc:
        primary = exc

    frame.close_faulted = True
    if primary is not None and not isinstance(primary, Exception):
        cancellation = primary
    # If the boundary was conclusively before the name action, consume it now
    # while the next (ancestor) frame still owns the required parent FD.
    if (frame.ready_to_remove
            and frame.remove_attempt.state == "not_started"
            and frame.parent_fd is not None
            and frame.name is not None
            and frame.identity is not None
            and frame.close_claim is not None):
        try:
            _remove_authenticated_fenced(
                frame.remove_attempt,
                name=frame.name,
                parent_fd=frame.parent_fd,
                identity=frame.identity,
                anchor=frame.close_claim,
                reason=ContainmentReason.REMOVE_FAILED,
            )
        except BaseException as exc:
            frame.close_faulted = True
            if not isinstance(exc, Exception):
                cancellation = _remember_cancellation(cancellation, exc)
                if frame.remove_attempt.state == "not_started":
                    try:
                        _remove_authenticated_fenced(
                            frame.remove_attempt,
                            name=frame.name,
                            parent_fd=frame.parent_fd,
                            identity=frame.identity,
                            anchor=frame.close_claim,
                            reason=ContainmentReason.REMOVE_FAILED,
                        )
                    except BaseException as retry_exc:
                        frame.close_faulted = True
                        if not isinstance(retry_exc, Exception):
                            cancellation = _remember_cancellation(
                                cancellation, retry_exc,
                            )
    try:
        frame.close(strict=False)
    except BaseException as exc:
        frame.close_faulted = True
        if not isinstance(exc, Exception):
            cancellation = _remember_cancellation(cancellation, exc)
            claim = frame.close_claim
            if (claim is not None and claim.attempts == 0
                    and claim.disposition not in _CLOSE_TERMINAL):
                try:
                    frame.close(strict=False)
                except BaseException as retry_exc:
                    frame.close_faulted = True
                    if not isinstance(retry_exc, Exception):
                        cancellation = _remember_cancellation(
                            cancellation, retry_exc,
                        )
    return cancellation


def _close_walk_frames_owner(
    frames: tuple[_WalkFrame, ...],
) -> BaseException | None:
    """Drive and replay one stable child-first frame ledger."""
    cancellation: BaseException | None = None
    boundary: BaseException | None = None
    try:
        for frame in frames:
            cancellation = _remember_cancellation(
                cancellation, _close_walk_frame_owned(frame),
            )
    except BaseException as exc:
        boundary = exc
    if boundary is None:
        return cancellation
    if not isinstance(boundary, Exception):
        cancellation = _remember_cancellation(cancellation, boundary)
    # A helper exception can occur on its own ``try:`` header before that frame
    # owns it.  With the sole interruption retained, replay the full ledger in
    # the same child-first order; terminal frame facts are inert.
    for frame in frames:
        cancellation = _remember_cancellation(
            cancellation, _close_walk_frame_owned(frame),
        )
    return cancellation


def _close_walk_frames_guarded(
    frames: tuple[_WalkFrame, ...],
) -> BaseException | None:
    """Fence every internal owner/handler line, then drain child-first."""
    try:
        return _close_walk_frames_owner(frames)
    except BaseException as boundary:
        cancellation = (
            boundary if not isinstance(boundary, Exception) else None
        )
        # The owner catches ordinary action faults itself.  An escape here is a
        # line-boundary interruption somewhere in that owner (including its
        # handler/replay lines); with the sole interruption consumed, reconcile
        # every stable frame before returning it to the caller.
        for frame in frames:
            cancellation = _remember_cancellation(
                cancellation, _close_walk_frame_owned(frame),
            )
        return cancellation


class _WalkLedgerFence:
    """One context layer over a shared traversal authority ledger.

    Two instances are installed before allocation.  If cancellation interrupts
    the inner instance's ordinary-failure cleanup, the already-active outer
    instance drains the same ledger after that sole interruption is consumed.
    """

    def __init__(self, frames: list[_WalkFrame]) -> None:
        self._frames = frames

    def __enter__(self) -> _WalkLedgerFence:
        return self

    def __exit__(self, _kind, primary, _traceback) -> bool:
        cleanup = _close_walk_frames_guarded(
            tuple(reversed(self._frames)),
        )
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        if cleanup is not None:
            raise cleanup
        return False


class DirectCgroupV2:
    """Exclusive parent handle for one acquired cooperative cgroup-v2 leaf."""

    kind = ContainmentKind.CGROUP_V2
    containment_assurance = ContainmentAssurance.COOPERATIVE_SCOPE
    cooperative_settlement_capable = True
    tree_proof_capable = False
    escape_protected = False

    def __init__(self, *, parent_fd: int, leaf_fd: int, procs_read_fd: int,
                 procs_write_fd: int, events_fd: int, kill_fd: int,
                 leaf_name: str, membership: str,
                 _claims: tuple[_DescriptorCloseClaim, ...] | None = None) -> None:
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
        self._kill_state = "not_requested"
        self._kill_errno = None
        self._binding_attempted = False
        self._closed = False
        self._closing = False
        self._removed = False
        self._settlement_teardown_started = False
        self._settlement_cache: ContainmentSettlement | None = None
        self._settlement_failure: ContainmentFailure | None = None
        close_names = (
            "_kill_fd", "_events_fd", "_procs_write_fd",
            "_procs_read_fd", "_leaf_fd", "_parent_fd",
        )
        if _claims is None:
            self._close_claims = tuple(
                _new_close_claim(name, getattr(self, name))
                for name in close_names
            )
        else:
            if (type(_claims) is not tuple or len(_claims) != len(close_names)
                    or any(type(claim) is not _DescriptorCloseClaim
                           for claim in _claims)
                    or any(claim.fd != getattr(self, name)
                           for claim, name in zip(_claims, close_names))):
                raise ContainmentFailure(
                    ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
                )
            self._close_claims = _claims
        self._close_failure_errno = None
        self._close_clean: bool | None = None

    @property
    def containment_id(self) -> str:
        return f"direct/{self._leaf_name}"

    @property
    def membership(self) -> str:
        return self._membership

    def _require_open(self) -> None:
        if self._closed or self._closing or self._removed:
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
        claim: _DescriptorCloseClaim | None = None
        primary: BaseException | None = None
        result: MembershipVerification | None = None
        try:
            try:
                claim = _open_proc_close_claim(identity.pid, "bind_proc_fd")
                state, start_time = _proc_state_and_start_time(claim.fd)
                if start_time != identity.start_time_ticks:
                    result = MembershipVerification(
                        False, ContainmentReason.PROCESS_IDENTITY_CHANGED)
                elif state not in ("T", "t"):
                    result = MembershipVerification(
                        False, ContainmentReason.PROCESS_NOT_PARKED)
                else:
                    payload = f"{identity.pid}\n".encode("ascii")
                    self._binding_attempted = True
                    try:
                        written = os.write(self._procs_write_fd, payload)
                    except Exception as exc:
                        raise ContainmentFailure(
                            ContainmentReason.BINDING_WRITE_FAILED,
                            _os_errno(exc),
                        ) from None
                    if written != len(payload):
                        raise ContainmentFailure(
                            ContainmentReason.BINDING_WRITE_FAILED,
                        )
                    result = self._verify_open_proc(identity, claim.fd)
            except BaseException as exc:
                primary = exc
            return _finish_proc_claim(
                claim, primary=primary, result=result,
            )
        except BaseException as boundary:
            claims = () if claim is None else (claim,)
            chosen = (
                primary if primary is not None
                and not isinstance(primary, Exception) else boundary
            )
            _recover_claims_at_boundary(chosen, claims)

    def bind_parked_process(
        self, proof: ParkedProcessIdentity,
    ) -> MembershipVerification:
        """Revalidate and bind one opaque, parent-authenticated parked child."""
        self._require_open()
        if type(proof) is not ParkedProcessIdentity:
            raise ContainmentRefused(ContainmentReason.PROCESS_IDENTITY_INVALID)
        if self._binding_attempted:
            raise ContainmentRefused(ContainmentReason.BINDING_ALREADY_USED)
        parent_claim: _DescriptorCloseClaim | None = None
        child_claim: _DescriptorCloseClaim | None = None
        primary: BaseException | None = None
        result: MembershipVerification | None = None
        try:
            try:
                parent_claim = _open_proc_close_claim(
                proof.parent.pid, "parked_parent_proc_fd",
                )
                child_claim = _open_proc_close_claim(
                proof.process.pid, "parked_child_proc_fd",
                )
                parent_before = _proc_stat_identity(parent_claim.fd)
                child_before = _proc_stat_identity(child_claim.fd)
                if not _parked_observation_matches(
                    proof, parent_before, child_before,
                ):
                    raise ContainmentRefused(
                        ContainmentReason.PROCESS_IDENTITY_CHANGED,
                    )
                if not self._leaf_identity_current():
                    result = MembershipVerification(
                        False, ContainmentReason.LEAF_IDENTITY_CHANGED,
                    )
                else:
                    payload = f"{proof.process.pid}\n".encode("ascii")
                    self._binding_attempted = True
                    try:
                        written = os.write(self._procs_write_fd, payload)
                    except Exception as exc:
                        raise ContainmentFailure(
                            ContainmentReason.BINDING_WRITE_FAILED,
                            _os_errno(exc),
                        ) from None
                    if written != len(payload):
                        raise ContainmentFailure(
                            ContainmentReason.BINDING_WRITE_FAILED,
                        )
                    parent_after = _proc_stat_identity(parent_claim.fd)
                    child_after = _proc_stat_identity(child_claim.fd)
                    if not _parked_observation_matches(
                        proof, parent_after, child_after,
                    ):
                        result = MembershipVerification(
                            False, ContainmentReason.PROCESS_IDENTITY_CHANGED,
                        )
                    else:
                        result = self._verify_open_proc(
                            proof.process, child_claim.fd,
                        )
                        if not self._leaf_identity_current():
                            result = MembershipVerification(
                                False, ContainmentReason.LEAF_IDENTITY_CHANGED,
                            )
            except BaseException as exc:
                primary = exc
            claims = tuple(
                claim for claim in (child_claim, parent_claim)
                if claim is not None
            )
            _close_claims_or_raise(claims)
            if primary is not None:
                raise primary
            if result is None:
                raise ContainmentFailure(
                    ContainmentReason.PROCESS_IDENTITY_INVALID,
                )
            return result
        except BaseException as boundary:
            claims = tuple(
                claim for claim in (child_claim, parent_claim)
                if claim is not None
            )
            chosen = (
                primary if primary is not None
                and not isinstance(primary, Exception) else boundary
            )
            _recover_claims_at_boundary(chosen, claims)

    def verify_pid(self, identity: ProcessIdentity) -> MembershipVerification:
        """Independently bind PID, start time, proc membership and leaf membership."""
        self._require_open()
        if type(identity) is not ProcessIdentity:
            raise ContainmentRefused(ContainmentReason.PROCESS_IDENTITY_INVALID)
        claim: _DescriptorCloseClaim | None = None
        primary: BaseException | None = None
        result: MembershipVerification | None = None
        try:
            try:
                claim = _open_proc_close_claim(identity.pid, "verify_proc_fd")
                result = self._verify_open_proc(identity, claim.fd)
            except ContainmentFailure as exc:
                if exc.reason is ContainmentReason.DESCRIPTOR_CLOSE_FAILED:
                    primary = exc
                else:
                    result = MembershipVerification(False, exc.reason)
            except BaseException as exc:
                primary = exc
            return _finish_proc_claim(
                claim, primary=primary, result=result,
            )
        except BaseException as boundary:
            claims = () if claim is None else (claim,)
            chosen = (
                primary if primary is not None
                and not isinstance(primary, Exception) else boundary
            )
            _recover_claims_at_boundary(chosen, claims)

    def populated(self) -> bool:
        self._require_open()
        try:
            return _parse_populated(_read_fd(
                self._events_fd, _MAX_EVENTS_TEXT,
                reason=ContainmentReason.EVENTS_MALFORMED,
            ))
        except ContainmentError:
            raise
        except Exception as exc:
            raise ContainmentFailure(
                ContainmentReason.EVENTS_MALFORMED, _os_errno(exc),
            ) from None

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

    def _remove_descendants(
        self, directory_fd: int, deadline: float,
    ) -> None:
        """Install two shared-ledger fences before traversal authority exists."""
        owned_frames: list[_WalkFrame] = []
        with _WalkLedgerFence(owned_frames):
            with _WalkLedgerFence(owned_frames):
                self._remove_descendants_owned(
                    directory_fd, deadline, owned_frames,
                )

    def _remove_descendants_owned(
        self, directory_fd: int, deadline: float,
        owned_frames: list[_WalkFrame],
    ) -> None:
        """Bounded iterative post-order removal under a caller-owned ledger."""
        stack: list[_WalkFrame] = []
        entries_seen = 0
        cgroups_seen = 0
        root_fd = -1
        root_iterator = None
        root_frame: _WalkFrame | None = None
        primary: BaseException | None = None
        cleanup_cancellation: BaseException | None = None
        cleanup_complete = False
        try:
            try:
                root_frame = _WalkFrame(-1, None, 0)
                root_frame.close_claim = _new_allocation_claim("fd")
                owned_frames.append(root_frame)
                root_fd = _populate_allocation_claim(
                    root_frame.close_claim, lambda: os.dup(directory_fd),
                ); root_frame.fd = root_fd
                root_iterator = os.scandir(root_fd); root_frame.iterator = root_iterator
                _append_walk_frame(stack, root_frame)
            except BaseException as exc:
                if isinstance(exc, OSError):
                    primary = ContainmentFailure(
                        ContainmentReason.REMOVE_FAILED,
                        _os_errno(exc),
                    )
                else:
                    primary = exc
            if primary is not None:
                interrupted_frames: list[_WalkFrame] = []
                cleanup_cancellation = _close_walk_frames_guarded(
                    tuple(reversed(owned_frames)),
                )
                cleanup_complete = True
        except BaseException as boundary:
            if (primary is None or isinstance(primary, Exception)):
                primary = boundary
            if not cleanup_complete:
                retry = _close_walk_frames_guarded(
                    tuple(reversed(owned_frames)),
                )
                cleanup_cancellation = _remember_cancellation(
                    cleanup_cancellation, retry,
                )
                cleanup_complete = True
        if primary is not None:
            if not isinstance(primary, Exception):
                raise primary
            if cleanup_cancellation is not None:
                raise cleanup_cancellation
            raise primary from None
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
                        if frame.close_claim is None or frame.identity is None:
                            raise ContainmentFailure(
                                ContainmentReason.REMOVE_FAILED,
                            )
                        # The iterator must release its directory stream before
                        # removal, but the directory FD remains an identity anchor
                        # until the name-based action is durably consumed.
                        frame.close(strict=True, retain_fd=True); frame.ready_to_remove = True
                        _remove_authenticated_fenced(
                            frame.remove_attempt,
                            name=frame.name,
                            parent_fd=frame.parent_fd,
                            identity=frame.identity,
                            anchor=frame.close_claim,
                            reason=ContainmentReason.REMOVE_FAILED,
                        )
                        frame.close(strict=True)
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
                    child_frame = _WalkFrame(
                        -1, None, child_depth,
                        parent_fd=frame.fd, name=entry.name,
                        identity=(info.st_dev, info.st_ino),
                    )
                    child_frame.close_claim = _new_allocation_claim("fd")
                    owned_frames.append(child_frame)
                    child_fd = _populate_allocation_claim(
                        child_frame.close_claim,
                        lambda: os.open(
                            entry.name, _DIR_FLAGS, dir_fd=frame.fd,
                        ),
                    ); child_frame.fd = child_fd
                    child_st = os.fstat(child_fd)
                    if ((child_st.st_dev, child_st.st_ino) != (info.st_dev, info.st_ino)
                            or _fstatfs_type(child_fd) != _CGROUP2_SUPER_MAGIC):
                        raise ContainmentRefused(ContainmentReason.DESCENDANT_UNSAFE)
                    child_iterator = os.scandir(child_fd); child_frame.iterator = child_iterator
                    _append_walk_frame(stack, child_frame)
                except BaseException as exc:
                    if isinstance(exc, OSError):
                        raise ContainmentFailure(
                            ContainmentReason.REMOVE_FAILED,
                            _os_errno(exc),
                        ) from None
                    raise
        finally:
            try:
                cleanup_cancellation: BaseException | None = None
                interrupted_frames: list[_WalkFrame] = []
                cleanup_cancellation = _close_walk_frames_guarded(
                    tuple(reversed(owned_frames)),
                )
            except BaseException as cleanup_boundary:
                cleanup_cancellation = (
                    cleanup_boundary
                    if not isinstance(cleanup_boundary, Exception) else None
                )
                retry = _close_walk_frames_guarded(
                    tuple(reversed(owned_frames)),
                )
                cleanup_cancellation = _remember_cancellation(
                    cleanup_cancellation, retry,
                )
            if cleanup_cancellation is not None:
                raise cleanup_cancellation

    def _request_kill_once(self) -> BaseException | None:
        """Invoke ``cgroup.kill`` at most once and retain conservative truth."""
        if self._kill_state != "not_requested":
            return None
        try:
            self._kill_state = "attempting"
            written = os.write(self._kill_fd, b"1\n")
        except OSError as exc:
            self._kill_state = "write_failed"
            self._kill_errno = _os_errno(exc)
            return None
        except Exception as exc:
            self._kill_state = "write_failed"
            self._kill_errno = _os_errno(exc)
            return None
        except BaseException as exc:
            self._kill_state = "ambiguous"
            return exc
        if written != 2:
            self._kill_state = "write_failed"
            self._kill_errno = None
            return None
        self._kill_state = "write_complete"; self._kill_sent = True
        return None

    def _request_kill_and_sample_once(
        self, sample: _PopulationSample | None = None,
    ) -> tuple[BaseException | None, bool | None, ContainmentFailure | None]:
        """Commit the one-shot kill action and one per-call population sample."""
        if sample is None:
            sample = _PopulationSample()
        cancellation: BaseException | None = None
        try:
            cancellation = self._request_kill_once()
        except BaseException as exc:
            if self._kill_state in ("attempting", "write_complete"):
                self._kill_state = "ambiguous"
                self._kill_sent = False
            if not isinstance(exc, Exception):
                cancellation = exc
            else:
                self._kill_state = "write_failed"
                self._kill_errno = _os_errno(exc)
        if self._kill_state == "attempting":
            self._kill_state = "ambiguous"
            self._kill_sent = False
        if sample.state == "not_started":
            try:
                # Keep the read and its durable fact commit on one supported
                # source-line boundary.  Recovery can then distinguish an
                # interruption before the read from one after it completed.
                occupied = self.populated(); sample.occupied = occupied; sample.state = "complete"
            except ContainmentFailure as exc:
                sample.error = exc
                sample.state = "complete"
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    cancellation = _remember_cancellation(cancellation, exc)
                if sample.state == "not_started":
                    # The line was interrupted before the read began.  One
                    # cooperative retry takes the mandatory nonblocking sample.
                    try:
                        occupied = self.populated(); sample.occupied = occupied; sample.state = "complete"
                    except ContainmentFailure as retry_exc:
                        sample.error = retry_exc
                        sample.state = "complete"
                    except BaseException as retry_exc:
                        if not isinstance(retry_exc, Exception):
                            cancellation = _remember_cancellation(
                                cancellation, retry_exc,
                            )
                        sample.state = "interrupted"
                else:
                    sample.state = "interrupted"
        return cancellation, sample.occupied, sample.error

    def _finish_settlement_teardown(self, primary: BaseException) -> None:
        """Terminalize post-settlement authority, then preserve error priority."""
        close_error: BaseException | None = None
        if not self._closed:
            try:
                self.close()
            except BaseException as exc:
                close_error = exc
        if not self._closed:
            try:
                self.close()
            except BaseException as exc:
                if close_error is None or isinstance(close_error, Exception):
                    close_error = exc
        if self._removed and self._close_clean is True:
            self._settlement_cache = ContainmentSettlement(
                True, True, True, ContainmentReason.SETTLED,
            )
        elif self._settlement_failure is None:
            self._settlement_failure = ContainmentFailure(
                (ContainmentReason.DESCRIPTOR_CLOSE_FAILED
                 if self._removed else ContainmentReason.REMOVE_FAILED),
                (self._close_failure_errno if self._removed else None),
            )
        if not isinstance(primary, Exception):
            raise primary
        if close_error is not None and not isinstance(close_error, Exception):
            raise close_error
        raise primary

    def kill_settle_remove(self, deadline: float) -> ContainmentSettlement:
        deadline = _validate_deadline(deadline)
        primary: BaseException | None = None
        try:
            try:
                return self._kill_settle_remove_transaction(deadline)
            except BaseException as exc:
                primary = exc
                if not self._settlement_teardown_started:
                    raise
                # The helper is idempotent, but its caller line is still a
                # cancellation boundary.  The outer owner below catches that
                # sole interruption and enters it once more to finish the drain.
                self._finish_settlement_teardown(primary)
        except BaseException as boundary:
            if not self._settlement_teardown_started:
                raise
            chosen = (
                primary if primary is not None
                and not isinstance(primary, Exception) else boundary
            )
            self._finish_settlement_teardown(chosen)
            raise chosen

    def _kill_settle_remove_transaction(
        self, deadline: float,
    ) -> ContainmentSettlement:
        """Request kill once, then settle/remove within one absolute deadline.

        ``ContainmentSettlement.killed`` means the exact ``cgroup.kill`` write
        returned its full byte count.  Cancellation around that syscall remains
        ambiguous, is never retried, and can therefore never set ``killed``.
        """
        if self._settlement_failure is not None:
            raise ContainmentFailure(
                self._settlement_failure.reason,
                self._settlement_failure.os_errno,
            ) from None
        if self._settlement_cache is not None:
            return self._settlement_cache
        self._require_open()
        deadline = _validate_deadline(deadline)
        if not self._leaf_identity_current():
            return ContainmentSettlement(False, False, False,
                                         ContainmentReason.LEAF_IDENTITY_CHANGED)
        sample_state = _PopulationSample()
        boundary_cancellation: BaseException | None = None
        try:
            sample = self._request_kill_and_sample_once(sample_state)
        except BaseException as exc:
            if isinstance(exc, Exception):
                raise
            boundary_cancellation = exc
            # The one-shot write state prevents replay.  A second helper entry
            # exists solely to take the mandatory nonblocking population sample.
            sample = self._request_kill_and_sample_once(sample_state)
        cancellation, occupied, population_error = sample
        if boundary_cancellation is not None:
            raise boundary_cancellation
        if cancellation is not None:
            raise cancellation
        if self._kill_state == "ambiguous":
            return ContainmentSettlement(
                False, False, False, ContainmentReason.KILL_AMBIGUOUS,
            )
        if self._kill_state == "write_failed":
            return ContainmentSettlement(
                False, False, False, ContainmentReason.KILL_FAILED,
                self._kill_errno,
            )
        if population_error is not None:
            return ContainmentSettlement(
                True, False, False,
                population_error.reason, population_error.os_errno,
            )
        if occupied is None:
            return ContainmentSettlement(
                True, False, False, ContainmentReason.EVENTS_MALFORMED,
            )
        if occupied and time.monotonic() >= deadline:
            return ContainmentSettlement(
                True, False, False, ContainmentReason.DEADLINE_EXPIRED,
            )
        while True:
            if not occupied:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ContainmentSettlement(True, False, False,
                                             ContainmentReason.DEADLINE_EXPIRED)
            time.sleep(min(0.02, remaining))
            try:
                occupied = self.populated()
            except ContainmentFailure as exc:
                return ContainmentSettlement(
                    True, False, False, exc.reason, exc.os_errno,
                )
        if time.monotonic() >= deadline:
            return ContainmentSettlement(
                True, True, False, ContainmentReason.DEADLINE_EXPIRED,
            )
        self._settlement_teardown_started = True
        remove_attempt = _RemoveAttempt()
        leaf_claim = self._close_claims[-2]
        settlement = ContainmentSettlement(
            True, True, True, ContainmentReason.SETTLED,
        )
        descendants_complete = False
        operation_error: BaseException | None = None
        handler_boundary: BaseException | None = None
        try:
            try:
                self._remove_descendants(self._leaf_fd, deadline); descendants_complete = True
                if self.populated():
                    return ContainmentSettlement(
                        True, False, False,
                        ContainmentReason.LEAF_NOT_EMPTY,
                    )
                if time.monotonic() >= deadline:
                    return ContainmentSettlement(
                        True, True, False,
                        ContainmentReason.DEADLINE_EXPIRED,
                    )
                if not self._leaf_identity_current():
                    return ContainmentSettlement(
                        True, True, False,
                        ContainmentReason.LEAF_IDENTITY_CHANGED,
                    )
                _remove_authenticated_fenced(
                    remove_attempt, name=self._leaf_name,
                    parent_fd=self._parent_fd,
                    identity=self._leaf_identity, anchor=leaf_claim,
                    reason=ContainmentReason.REMOVE_FAILED,
                ); self._removed = remove_attempt.state == "removed"
                self.close()
                self._settlement_cache = settlement
                return settlement
            except ContainmentError as exc:
                self._removed = remove_attempt.state == "removed"
                if not self._removed and remove_attempt.state == "not_started":
                    return ContainmentSettlement(
                        True, False, False, exc.reason, exc.os_errno,
                    )
                # Once the name-based action was attempted, failed, refused,
                # or became ambiguous, no safe replay exists.  Terminalize the
                # handle and retain a fixed failure rather than later
                # contradicting the already-completed kill fact.
                operation_error = exc
            except OSError as exc:
                return ContainmentSettlement(
                    True, True, False,
                    ContainmentReason.REMOVE_FAILED, _os_errno(exc),
                )
            except BaseException as exc:
                operation_error = exc
        except BaseException as boundary:
            handler_boundary = boundary

        chosen = operation_error
        if (chosen is None or isinstance(chosen, Exception)):
            if handler_boundary is not None:
                chosen = handler_boundary

        cleanup_cancellation: BaseException | None = None
        cleanup_error: ContainmentError | None = None
        if (chosen is not None and not isinstance(chosen, Exception)
                and descendants_complete
                and remove_attempt.state == "not_started"):
            try:
                if (time.monotonic() < deadline and not self.populated()
                        and self._leaf_identity_current()):
                    _remove_authenticated_fenced(
                        remove_attempt, name=self._leaf_name,
                        parent_fd=self._parent_fd,
                        identity=self._leaf_identity, anchor=leaf_claim,
                        reason=ContainmentReason.REMOVE_FAILED,
                    )
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    cleanup_cancellation = exc
                elif isinstance(exc, ContainmentError):
                    cleanup_error = exc
                else:
                    cleanup_error = ContainmentFailure(
                        ContainmentReason.REMOVE_FAILED, _os_errno(exc),
                    )
        self._removed = remove_attempt.state == "removed"

        close_boundary: BaseException | None = None
        try:
            self.close()
        except BaseException as exc:
            close_boundary = exc
        if not self._closed:
            try:
                self.close()
            except BaseException as retry_exc:
                if (close_boundary is None
                        or isinstance(close_boundary, Exception)):
                    close_boundary = retry_exc

        for candidate in (close_boundary, cleanup_cancellation):
            if candidate is not None and not isinstance(candidate, Exception):
                cleanup_cancellation = _remember_cancellation(
                    cleanup_cancellation, candidate,
                )

        if self._removed and self._close_clean is True:
            self._settlement_cache = settlement
        elif cleanup_error is not None:
            self._settlement_failure = ContainmentFailure(
                cleanup_error.reason, cleanup_error.os_errno,
            )
        elif isinstance(close_boundary, ContainmentFailure):
            self._settlement_failure = ContainmentFailure(
                close_boundary.reason, close_boundary.os_errno,
            )
        else:
            self._settlement_failure = ContainmentFailure(
                (ContainmentReason.DESCRIPTOR_CLOSE_FAILED
                 if self._removed else ContainmentReason.REMOVE_FAILED),
                (self._close_failure_errno if self._removed
                 else remove_attempt.os_errno),
            )

        if chosen is not None and not isinstance(chosen, Exception):
            raise chosen
        if cleanup_cancellation is not None:
            raise cleanup_cancellation
        if chosen is not None:
            raise chosen
        if self._settlement_failure is not None:
            raise ContainmentFailure(
                self._settlement_failure.reason,
                self._settlement_failure.os_errno,
            ) from None
        return self._settlement_cache or settlement

    def close(self) -> None:
        try:
            primary: BaseException | None = None
            recovery: BaseException | None = None
            try:
                self._close_owned_transaction()
                return
            except BaseException as exc:
                primary = exc
            if not self._closed:
                for claim in self._close_claims:
                    if claim.disposition not in _CLOSE_TERMINAL:
                        claim.faulted = True
                try:
                    self._close_owned_transaction()
                except BaseException as exc:
                    recovery = exc
        except BaseException as boundary:
            primary = locals().get("primary")
            recovery = boundary

        # A cancellation may land on either transaction-call boundary before
        # its callee starts.  With that sole cancellation now retained, one last
        # idempotent reconciliation drains every still-owned claim and commits
        # the authoritative terminal state.
        if not self._closed:
            try:
                self._close_owned_transaction()
            except BaseException as exc:
                if recovery is None or isinstance(recovery, Exception):
                    recovery = exc

        cancellation: BaseException | None = None
        for candidate in (primary, recovery):
            if candidate is not None and not isinstance(candidate, Exception):
                cancellation = _remember_cancellation(cancellation, candidate)
        if cancellation is not None:
            if self._closed:
                self._close_clean = False; self._closing = False
            raise cancellation
        if primary is not None:
            if isinstance(primary, ContainmentError):
                raise primary
            raise ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
                _os_errno(primary),
            ) from None
        if recovery is not None:
            if isinstance(recovery, ContainmentError):
                raise recovery
            raise ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
                _os_errno(recovery),
            ) from None

    def _close_owned_transaction(self) -> None:
        if self._closed:
            if self._close_clean is not True:
                raise ContainmentFailure(
                    ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
                    self._close_failure_errno,
                )
            return
        cancellation: BaseException | None = None
        close_errno: int | None = None
        clean = False
        try:
            self._closing = True
            cancellation, close_errno, clean = _close_claims_fenced(
                self._close_claims, owner=self,
            )
        except BaseException as exc:
            if not isinstance(exc, Exception):
                cancellation = exc
            else:
                close_errno = _os_errno(exc)
            for claim in self._close_claims:
                if claim.disposition not in _CLOSE_TERMINAL:
                    claim.faulted = True
            retry_cancellation, retry_errno, _retry_clean = (
                _close_claims_fenced(self._close_claims, owner=self)
            )
            cancellation = _remember_cancellation(
                cancellation, retry_cancellation,
            )
            if close_errno is None:
                close_errno = retry_errno
            clean = False
        self._close_failure_errno = close_errno
        self._close_clean = clean
        self._closed = True
        self._closing = False
        if cancellation is not None:
            raise cancellation
        if not clean:
            raise ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
            )


def _cleanup_failed_acquisition(*, claims: tuple[_DescriptorCloseClaim, ...], created: bool,
                                leaf_name: str, parent_fd: int,
                                preserve: BaseException,
                                leaf_identity: tuple[int, int] | None = None,
                                leaf_claim: _DescriptorCloseClaim | None = None,
                                _state: _AcquisitionCleanupState | None = None) -> None:
    """Drain controls, remove against a pinned leaf, then release that anchor."""
    state = _AcquisitionCleanupState() if _state is None else _state
    state.entered = True
    cleanup_cancellation: BaseException | None = None
    close_errno: int | None = None
    rollback_error: ContainmentFailure | None = None
    remove_attempt = state.remove_attempt

    if leaf_claim is None:
        for candidate in claims:
            identity = candidate.owned_identity or candidate.identity
            if (len(identity) >= 3 and stat.S_ISDIR(identity[2])
                    and (leaf_identity is None
                         or (identity[0], identity[1]) == leaf_identity)):
                leaf_claim = candidate
                break
    if leaf_identity is None and leaf_claim is not None:
        identity = leaf_claim.owned_identity or leaf_claim.identity
        if len(identity) >= 3 and stat.S_ISDIR(identity[2]):
            leaf_identity = (identity[0], identity[1])

    control_claims = tuple(
        claim for claim in reversed(claims) if claim is not leaf_claim
    )
    control_clean = False
    anchor_clean = leaf_claim is None
    anchor_errno: int | None = None
    try:
        interrupted, close_errno, control_clean = _close_claims_guarded(
            control_claims,
        )
        cleanup_cancellation = _remember_cancellation(
            cleanup_cancellation, interrupted,
        )
    except BaseException as boundary:
        if not isinstance(boundary, Exception):
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, boundary,
            )
        elif close_errno is None:
            close_errno = _os_errno(boundary)
        try:
            interrupted, retry_errno, _retry_clean = _close_claims_guarded(
                control_claims,
            )
        except BaseException as retry:
            interrupted = retry if not isinstance(retry, Exception) else None
            retry_errno = _os_errno(retry)
        cleanup_cancellation = _remember_cancellation(
            cleanup_cancellation, interrupted,
        )
        if close_errno is None:
            close_errno = retry_errno
        control_clean = False

    try:
        if created:
            if leaf_identity is None or leaf_claim is None:
                raise ContainmentFailure(
                    ContainmentReason.LEAF_ROLLBACK_FAILED,
                )
            _remove_authenticated_fenced(
                remove_attempt, name=leaf_name, parent_fd=parent_fd,
                identity=leaf_identity, anchor=leaf_claim,
            )
        if leaf_claim is not None:
            interrupted, anchor_errno, anchor_clean = _close_claims_guarded(
                (leaf_claim,),
            )
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, interrupted,
            )
    except BaseException as boundary:
        if not isinstance(boundary, Exception):
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, boundary,
            )
        elif rollback_error is None:
            rollback_error = (
                boundary if isinstance(boundary, ContainmentFailure)
                else ContainmentFailure(
                    ContainmentReason.LEAF_ROLLBACK_FAILED,
                    _os_errno(boundary),
                )
            )
        if (created and leaf_identity is not None and leaf_claim is not None
                and remove_attempt.state == "not_started"):
            try:
                _remove_authenticated_fenced(
                    remove_attempt, name=leaf_name, parent_fd=parent_fd,
                    identity=leaf_identity, anchor=leaf_claim,
                )
            except BaseException as recovery:
                if not isinstance(recovery, Exception):
                    cleanup_cancellation = _remember_cancellation(
                        cleanup_cancellation, recovery,
                    )
                elif rollback_error is None:
                    rollback_error = (
                        recovery if isinstance(recovery, ContainmentFailure)
                        else ContainmentFailure(
                            ContainmentReason.LEAF_ROLLBACK_FAILED,
                            _os_errno(recovery),
                        )
                    )
    if (leaf_claim is not None
            and leaf_claim.disposition not in _CLOSE_TERMINAL):
        try:
            interrupted, anchor_errno, anchor_clean = _close_claims_guarded(
                (leaf_claim,),
            )
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, interrupted,
            )
        except BaseException as boundary:
            if not isinstance(boundary, Exception):
                cleanup_cancellation = _remember_cancellation(
                    cleanup_cancellation, boundary,
                )
            anchor_errno = _os_errno(boundary)
            try:
                interrupted, retry_errno, _retry_clean = _close_claims_guarded(
                    (leaf_claim,),
                )
            except BaseException as retry:
                interrupted = retry if not isinstance(retry, Exception) else None
                retry_errno = _os_errno(retry)
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, interrupted,
            )
            if anchor_errno is None:
                anchor_errno = retry_errno
            anchor_clean = False
    if close_errno is None:
        close_errno = anchor_errno
    clean = control_clean and anchor_clean
    if not isinstance(preserve, Exception):
        raise preserve
    if cleanup_cancellation is not None:
        raise cleanup_cancellation
    if not clean:
        raise ContainmentFailure(
            ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
        ) from None
    if rollback_error is not None:
        raise rollback_error from None


def _finish_unpublished_rollback(
    handle: DirectCgroupV2,
    state: _UnpublishedRollbackState,
) -> tuple[BaseException | None, ContainmentError | None]:
    """Idempotently reconcile a rollback after its one boundary interruption."""
    cancellation: BaseException | None = None
    error: ContainmentError | None = None
    if not state.probe_complete:
        try:
            removable = handle._leaf_identity_current() and not handle.populated(); state.removable = removable; state.probe_complete = True
        except BaseException as exc:
            state.probe_complete = True
            if not isinstance(exc, Exception):
                cancellation = exc
            elif isinstance(exc, ContainmentError):
                error = exc
            else:
                error = ContainmentFailure(
                    ContainmentReason.LEAF_ROLLBACK_FAILED, _os_errno(exc),
                )
    controls = handle._close_claims[:-2]
    leaf_claim = handle._close_claims[-2]
    try:
        interrupted, close_errno, clean = _close_claims_guarded(
            controls, owner=handle,
        )
        cancellation = _remember_cancellation(cancellation, interrupted)
        if not clean:
            error = error or ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
            )
    except BaseException as exc:
        if not isinstance(exc, Exception):
            cancellation = _remember_cancellation(cancellation, exc)
        else:
            error = error or ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED, _os_errno(exc),
            )
    if state.removable and state.remove_attempt.state == "not_started":
        try:
            _remove_authenticated_fenced(
                state.remove_attempt, name=handle._leaf_name,
                parent_fd=handle._parent_fd,
                identity=handle._leaf_identity, anchor=leaf_claim,
            )
        except BaseException as exc:
            if not isinstance(exc, Exception):
                cancellation = _remember_cancellation(cancellation, exc)
            else:
                error = error or ContainmentFailure(
                    ContainmentReason.LEAF_ROLLBACK_FAILED, _os_errno(exc),
                )
    if state.remove_attempt.state == "removed":
        handle._removed = True
    try:
        interrupted, close_errno, clean = _close_claims_guarded(
            (leaf_claim,), owner=handle,
        )
        cancellation = _remember_cancellation(cancellation, interrupted)
        if not clean:
            error = error or ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
            )
    except BaseException as exc:
        if not isinstance(exc, Exception):
            cancellation = _remember_cancellation(cancellation, exc)
        else:
            error = error or ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED, _os_errno(exc),
            )
    try:
        handle.close()
    except BaseException as exc:
        if not isinstance(exc, Exception):
            cancellation = _remember_cancellation(cancellation, exc)
        elif isinstance(exc, ContainmentError):
            error = error or exc
        else:
            error = error or ContainmentFailure(
                ContainmentReason.DESCRIPTOR_CLOSE_FAILED, _os_errno(exc),
            )
    if not handle._closed:
        try:
            handle.close()
        except BaseException as exc:
            if not isinstance(exc, Exception):
                cancellation = _remember_cancellation(cancellation, exc)
            elif isinstance(exc, ContainmentError):
                error = error or exc
    return cancellation, error


def _rollback_unpublished_handle(
    handle: DirectCgroupV2, preserve: BaseException,
    *, _state: _UnpublishedRollbackState | None = None,
) -> None:
    """Revoke a fully acquired handle that never crossed the public return."""
    state = _UnpublishedRollbackState() if _state is None else _state
    boundary: BaseException | None = None
    cleanup_cancellation: BaseException | None = None
    cleanup_error: ContainmentError | None = None
    try:
        try:
            state.entered = True
            removable = state.removable
            remove_attempt = state.remove_attempt
            child_claims = handle._close_claims[:-2]
            leaf_claim = handle._close_claims[-2]
            if not state.probe_complete:
                removable = handle._leaf_identity_current() and not handle.populated(); state.removable = removable; state.probe_complete = True
            interrupted, close_errno, clean = _close_claims_guarded(
                child_claims, owner=handle,
            )
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, interrupted,
            )
            if not clean:
                cleanup_error = ContainmentFailure(
                    ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
                )
            if removable:
                _remove_authenticated_fenced(
                    remove_attempt, name=handle._leaf_name,
                    parent_fd=handle._parent_fd,
                    identity=handle._leaf_identity, anchor=leaf_claim,
                )
                handle._removed = remove_attempt.state == "removed"
            interrupted, close_errno, clean = _close_claims_guarded(
                (leaf_claim,), owner=handle,
            )
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, interrupted,
            )
            if not clean:
                cleanup_error = cleanup_error or ContainmentFailure(
                    ContainmentReason.DESCRIPTOR_CLOSE_FAILED, close_errno,
                )
            handle.close()
        except BaseException as exc:
            boundary = exc
        if boundary is not None:
            if not isinstance(boundary, Exception):
                cleanup_cancellation = _remember_cancellation(
                    cleanup_cancellation, boundary,
                )
            elif isinstance(boundary, ContainmentError):
                cleanup_error = cleanup_error or boundary
            else:
                cleanup_error = cleanup_error or ContainmentFailure(
                    ContainmentReason.LEAF_ROLLBACK_FAILED,
                    _os_errno(boundary),
                )
            retry_cancellation, retry_error = _finish_unpublished_rollback(
                handle, state,
            )
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, retry_cancellation,
            )
            cleanup_error = cleanup_error or retry_error
    except BaseException as recovery_boundary:
        if not isinstance(recovery_boundary, Exception):
            cleanup_cancellation = _remember_cancellation(
                cleanup_cancellation, recovery_boundary,
            )
        elif isinstance(recovery_boundary, ContainmentError):
            cleanup_error = cleanup_error or recovery_boundary
        else:
            cleanup_error = cleanup_error or ContainmentFailure(
                ContainmentReason.LEAF_ROLLBACK_FAILED,
                _os_errno(recovery_boundary),
            )
        retry_cancellation, retry_error = _finish_unpublished_rollback(
            handle, state,
        )
        cleanup_cancellation = _remember_cancellation(
            cleanup_cancellation, retry_cancellation,
        )
        cleanup_error = cleanup_error or retry_error
    if not isinstance(preserve, Exception):
        raise preserve
    if cleanup_cancellation is not None:
        raise cleanup_cancellation
    if cleanup_error is not None:
        raise cleanup_error from None
    raise preserve


def _acquire_from_parent(request_id: str, discovered: _DiscoveredParent) -> DirectCgroupV2:
    request_id = _validate_request_id(request_id)
    leaf_name = f"quarry-{request_id}"
    created = False
    leaf_identity: tuple[int, int] | None = None
    leaf_claim = _new_allocation_claim("_leaf_fd")
    procs_read_claim = _new_allocation_claim("_procs_read_fd")
    procs_write_claim = _new_allocation_claim("_procs_write_fd")
    events_claim = _new_allocation_claim("_events_fd")
    kill_claim = _new_allocation_claim("_kill_fd")
    cleanup_state = _AcquisitionCleanupState()
    claims = (
        leaf_claim, procs_read_claim, procs_write_claim,
        events_claim, kill_claim,
    )
    original: BaseException | None = None
    try:
        try:
            try:
                _mkdir_leaf(leaf_name, discovered.fd); created = True
            except FileExistsError:
                raise ContainmentRefused(
                    ContainmentReason.LEAF_COLLISION, errno.EEXIST,
                ) from None
            except OSError as exc:
                reason = (
                    ContainmentReason.DELEGATION_REFUSED
                    if _os_errno(exc) in (
                        errno.EACCES, errno.EPERM, errno.EROFS,
                    ) else ContainmentReason.LEAF_CREATE_FAILED
                )
                exception = (
                    ContainmentRefused
                    if reason is ContainmentReason.DELEGATION_REFUSED
                    else ContainmentFailure
                )
                raise exception(reason, _os_errno(exc)) from None
            leaf_fd = _populate_allocation_claim(
                leaf_claim,
                lambda: os.open(
                    leaf_name, _DIR_FLAGS, dir_fd=discovered.fd,
                ),
            )
            leaf_st = os.fstat(leaf_fd)
            leaf_identity = (leaf_st.st_dev, leaf_st.st_ino)
            named_st = os.stat(
                leaf_name, dir_fd=discovered.fd, follow_symlinks=False,
            )
            if (not stat.S_ISDIR(leaf_st.st_mode)
                    or (leaf_st.st_dev, leaf_st.st_ino) != (
                        named_st.st_dev, named_st.st_ino,
                    )
                    or _fstatfs_type(leaf_fd) != _CGROUP2_SUPER_MAGIC):
                raise ContainmentRefused(
                    ContainmentReason.LEAF_CONTROL_UNUSABLE,
                )
            if _read_control(
                    leaf_fd, "cgroup.type",
                    reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
                    ).strip() != b"domain":
                raise ContainmentUnsupported(
                    ContainmentReason.LEAF_DOMAIN_UNUSABLE,
                )
            if _parse_populated(_read_control(
                    leaf_fd, "cgroup.events",
                    reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
                    )):
                raise ContainmentRefused(
                    ContainmentReason.LEAF_CONTROL_UNUSABLE,
                )
            procs_read = _open_control(
                leaf_fd, "cgroup.procs", _READ_FLAGS,
                reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
                _claim=procs_read_claim,
            )
            procs_write = _open_control(
                leaf_fd, "cgroup.procs", _WRITE_FLAGS,
                reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
                _claim=procs_write_claim,
            )
            events = _open_control(
                leaf_fd, "cgroup.events", _READ_FLAGS,
                reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
                _claim=events_claim,
            )
            kill = _open_leaf_kill(
                leaf_fd, _claim=kill_claim,
            )
            if _parse_pid_lines(_read_fd(
                    procs_read, _MAX_PROC_TEXT,
                    reason=ContainmentReason.LEAF_CONTROL_UNUSABLE,
                    )):
                raise ContainmentRefused(
                    ContainmentReason.LEAF_CONTROL_UNUSABLE,
                )
            parent_claim = discovered._close_claim
            if parent_claim is None or parent_claim.fd != discovered.fd:
                raise ContainmentFailure(
                    ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
                )
            close_claims = (
                kill_claim, events_claim, procs_write_claim,
                procs_read_claim, leaf_claim, parent_claim,
            )
            handle = DirectCgroupV2(
                parent_fd=discovered.fd, leaf_fd=leaf_fd,
                procs_read_fd=procs_read, procs_write_fd=procs_write,
                events_fd=events, kill_fd=kill, leaf_name=leaf_name,
                membership=_leaf_membership(
                    discovered.membership, leaf_name,
                ),
                _claims=close_claims,
            )
            # Keep the acquisition claims live until the return boundary.  They
            # are the rollback authority if cancellation lands on a preceding
            # line; on success the returned handle owns the same descriptors.
            parent_claim.attribute = "_parent_fd"; discovered.fd = -1; return handle
        except BaseException as exc:
            original = exc
        _cleanup_failed_acquisition(
            claims=claims, created=created, leaf_name=leaf_name,
            parent_fd=discovered.fd, preserve=original,
            leaf_identity=leaf_identity, leaf_claim=leaf_claim,
            _state=cleanup_state,
        )
        if isinstance(original, OSError):
            raise ContainmentFailure(
                ContainmentReason.LEAF_CONTROL_UNUSABLE,
                _os_errno(original),
            ) from None
        raise original
    except BaseException as boundary:
        chosen = (
            original if original is not None
            and not isinstance(original, Exception) else boundary
        )
        _cleanup_failed_acquisition(
            claims=claims, created=created, leaf_name=leaf_name,
            parent_fd=discovered.fd, preserve=chosen,
            leaf_identity=leaf_identity, leaf_claim=leaf_claim,
            _state=cleanup_state,
        )
        if isinstance(chosen, OSError):
            raise ContainmentFailure(
                ContainmentReason.LEAF_CONTROL_UNUSABLE,
                _os_errno(chosen),
            ) from None
        raise chosen


def acquire_direct_cgroup_v2(request_id: str) -> DirectCgroupV2:
    """Create and prove one usable child under the current delegated cgroup."""
    _validate_request_id(request_id)       # refuse before filesystem discovery
    discovered: _DiscoveredParent | None = None
    handle: DirectCgroupV2 | None = None
    rollback_state = _UnpublishedRollbackState()
    primary: BaseException | None = None
    cleanup: BaseException | None = None
    try:
        try:
            discovered = _discover_parent()
            handle = _acquire_from_parent(request_id, discovered)
            return handle
        except BaseException as exc:
            primary = exc
        if handle is not None:
            try:
                _rollback_unpublished_handle(
                    handle, primary, _state=rollback_state,
                )
            except BaseException as rollback_boundary:
                if not rollback_state.entered:
                    chosen = (
                        primary if not isinstance(primary, Exception)
                        else rollback_boundary
                    )
                    _rollback_unpublished_handle(
                        handle, chosen, _state=rollback_state,
                    )
                raise
        if discovered is not None:
            try:
                discovered.close()
            except BaseException as exc:
                cleanup = exc
            if (cleanup is not None and not isinstance(cleanup, Exception)
                    and discovered.fd >= 0):
                try:
                    discovered.close()
                except BaseException as exc:
                    if isinstance(cleanup, Exception):
                        cleanup = exc
    except BaseException as boundary:
        if cleanup is None or isinstance(cleanup, Exception):
            cleanup = boundary
        if handle is not None and not handle._closed:
            try:
                _rollback_unpublished_handle(
                    handle, cleanup, _state=rollback_state,
                )
            except BaseException as exc:
                if cleanup is None or isinstance(cleanup, Exception):
                    cleanup = exc
        elif discovered is not None and discovered.fd >= 0:
            try:
                discovered.close()
            except BaseException as exc:
                if cleanup is None or isinstance(cleanup, Exception):
                    cleanup = exc
    if primary is None:
        primary = cleanup or ContainmentFailure(
            ContainmentReason.DESCRIPTOR_CLOSE_FAILED,
        )
    if not isinstance(primary, Exception):
        raise primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        raise cleanup
    if cleanup is not None:
        raise cleanup from None
    raise primary
