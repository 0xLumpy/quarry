"""Internal, policy-neutral ownership claims for private file descriptors.

This module is deliberately a dependency leaf.  Filesystem policy, exception
types, descriptor allocation and operating-system seams are supplied by its
caller so higher layers retain their fault-injection and lifecycle boundaries.
"""
from __future__ import annotations

import errno
import threading
from collections.abc import Callable


TERMINAL_DISPOSITIONS = frozenset({
    "closed_clean", "closed_after_fault", "close_ambiguous", "gone",
    "identity_rejected", "unallocated",
})
MAX_CLAIM_ERRORS = 2
MAX_DROPPED_ERRORS = (1 << 63) - 1

_DESCRIPTOR_CLAIM_CONSTRUCTOR = object()


class DescriptorClaim:
    """One exact, privately retained descriptor with monotonic close progress."""

    __slots__ = (
        "_fd", "_identity", "_owned_identity", "_fresh_owned", "_kind",
        "_components", "_disposition",
        "_close_attempts", "_errors", "_dropped_error_count", "_metadata_fault",
        "_lock",
    )

    def __init__(
        self,
        *,
        fd: int,
        identity: tuple[int, int],
        kind: str,
        components: tuple[str, ...],
        _constructor_token: object,
    ) -> None:
        if (_constructor_token is not _DESCRIPTOR_CLAIM_CONSTRUCTOR
                or type(fd) is not int or fd < -1
                or type(identity) is not tuple or len(identity) != 2
                or any(type(value) is not int or value < 0 for value in identity)
                or type(kind) is not str
                or type(components) is not tuple):
            raise ValueError("invalid private descriptor claim")
        object.__setattr__(self, "_fd", fd)
        object.__setattr__(self, "_identity", identity)
        object.__setattr__(self, "_owned_identity", None)
        object.__setattr__(self, "_fresh_owned", fd == -1)
        object.__setattr__(self, "_kind", kind)
        object.__setattr__(self, "_components", components)
        object.__setattr__(
            self, "_disposition", "allocating" if fd == -1 else "pending",
        )
        object.__setattr__(self, "_close_attempts", 0)
        object.__setattr__(self, "_errors", ())
        object.__setattr__(self, "_dropped_error_count", 0)
        object.__setattr__(self, "_metadata_fault", False)
        object.__setattr__(self, "_lock", threading.RLock())

    def __setattr__(self, name, value) -> None:
        raise AttributeError("private descriptor claims are read-only")

    def __delattr__(self, name) -> None:
        raise AttributeError("private descriptor claims are read-only")

    @property
    def fd(self) -> int:
        with self._lock:
            return self._fd

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def disposition(self) -> str:
        with self._lock:
            return self._disposition

    @property
    def errors(self) -> tuple[BaseException, ...]:
        with self._lock:
            return self._errors

    def __repr__(self) -> str:
        return (
            "PrivateDescriptorClaim("
            f"kind={self._kind!r}, disposition={self._disposition!r})"
        )


def new_claim(
    fd: int,
    identity: tuple[int, int],
    kind: str,
    components: tuple[str, ...],
    *,
    allowed_kinds: frozenset[str],
    invalid_error: Callable[[], BaseException],
) -> DescriptorClaim:
    """Build a claim while translating malformed input at the policy boundary."""
    if type(kind) is not str or kind not in allowed_kinds:
        raise invalid_error()
    try:
        return DescriptorClaim(
            fd=fd,
            identity=identity,
            kind=kind,
            components=components,
            _constructor_token=_DESCRIPTOR_CLAIM_CONSTRUCTOR,
        )
    except ValueError:
        raise invalid_error() from None


def record_error(
    claim: DescriptorClaim,
    error: BaseException,
    *,
    max_errors: int = MAX_CLAIM_ERRORS,
    max_dropped: int = MAX_DROPPED_ERRORS,
) -> None:
    """Append one fault to a bounded journal, saturating its dropped counter."""
    with claim._lock:
        if len(claim._errors) < max_errors:
            object.__setattr__(claim, "_errors", claim._errors + (error,))
        else:
            object.__setattr__(
                claim,
                "_dropped_error_count",
                min(claim._dropped_error_count + 1, max_dropped),
            )


def populate_allocation_slot(
    claim: DescriptorClaim,
    allocate_fd: Callable[[], int],
    *,
    invalid_error: Callable[[], BaseException],
) -> int:
    """Assign an allocation result directly into a pre-registered claim slot."""
    if (type(claim) is not DescriptorClaim
            or claim._fd != -1 or claim._disposition != "allocating"):
        raise invalid_error()
    # Keep allocation and retained-slot assignment on one source line.  A
    # cooperative line interruption can therefore never observe the returned
    # descriptor outside its already-reachable ownership claim.  Error-state
    # translation belongs to the caller because allocation boundaries differ.
    object.__setattr__(claim, "_fd", allocate_fd())
    object.__setattr__(claim, "_disposition", "pending")
    return claim._fd


def populate_claim(
    claim: DescriptorClaim,
    allocate_fd: Callable[[], int],
    *,
    allow_unlinked: bool,
    fstat: Callable[[int], object],
    identity_of: Callable[[object], tuple[int, int]],
    validate_metadata: Callable[[DescriptorClaim, object, bool], None],
    make_identity_error: Callable[[tuple[str, ...]], BaseException],
    record_claim_error: Callable[[DescriptorClaim, BaseException], None],
    invalid_error: Callable[[], BaseException],
) -> DescriptorClaim:
    """Allocate, adopt and validate one already-registered descriptor claim."""
    if (type(claim) is not DescriptorClaim
            or claim._fd != -1 or claim._disposition != "allocating"):
        raise invalid_error()
    try:
        populate_allocation_slot(
            claim, allocate_fd, invalid_error=invalid_error,
        )
        observed = fstat(claim._fd)
        object.__setattr__(claim, "_owned_identity", identity_of(observed))
        if identity_of(observed) != claim._identity:
            raise make_identity_error(claim._components)
        validate_metadata(claim, observed, allow_unlinked)
        return claim
    except BaseException as primary:
        if claim._fd < 0:
            object.__setattr__(claim, "_disposition", "unallocated")
        else:
            record_claim_error(claim, primary)
        raise


def inspect_claim(
    claim: DescriptorClaim,
    *,
    allow_unlinked: bool,
    fstat: Callable[[int], object],
    identity_of: Callable[[object], tuple[int, int]],
    validate_metadata: Callable[[DescriptorClaim, object, bool], None],
    is_metadata_error: Callable[[BaseException], bool],
    make_identity_error: Callable[[tuple[str, ...]], BaseException],
    record_claim_error: Callable[[DescriptorClaim, BaseException], None],
):
    """Authenticate a claim, terminalizing only proved gone or foreign FDs."""
    try:
        observed = fstat(claim._fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        record_claim_error(claim, exc)
        object.__setattr__(claim, "_fd", -1)
        object.__setattr__(claim, "_disposition", "gone")
        return None
    if claim._fresh_owned and claim._owned_identity is None:
        # A directly allocated, unexposed claim can safely adopt its actual inode
        # after interruption, solely so cleanup retains authentic close authority.
        object.__setattr__(claim, "_owned_identity", identity_of(observed))
    cleanup_identity = (
        claim._identity
        if claim._owned_identity is None
        else claim._owned_identity
    )
    if identity_of(observed) != cleanup_identity:
        error = make_identity_error(claim._components)
        record_claim_error(claim, error)
        object.__setattr__(claim, "_fd", -1)
        object.__setattr__(claim, "_disposition", "identity_rejected")
        return None
    try:
        validate_metadata(claim, observed, allow_unlinked)
    except BaseException as exc:
        if not is_metadata_error(exc):
            raise
        record_claim_error(claim, exc)
        object.__setattr__(claim, "_metadata_fault", True)
    return observed


def drain_claim(
    claim: DescriptorClaim,
    *,
    allow_unlinked: bool,
    inspect: Callable[..., object | None],
    close_owned: Callable[[int], BaseException | None],
    fstat: Callable[[int], object],
    identity_of: Callable[[object], tuple[int, int]],
    make_close_identity_error: Callable[[tuple[str, ...]], BaseException],
    record_claim_error: Callable[[DescriptorClaim, BaseException], None],
) -> tuple[BaseException, ...]:
    """Settle one descriptor with bounded, identity-checked close recovery."""
    with claim._lock:
        if claim._disposition in TERMINAL_DISPOSITIONS:
            return ()
        before_errors = len(claim._errors)
        observed = inspect(claim, allow_unlinked=allow_unlinked)
        if observed is None:
            return claim._errors[before_errors:]

        while claim._close_attempts < 2:
            object.__setattr__(claim, "_disposition", "close_started")
            object.__setattr__(claim, "_close_attempts", claim._close_attempts + 1)
            close_fault: BaseException | None = None
            try:
                close_fault = close_owned(claim._fd)
            except BaseException as exc:
                close_fault = exc
            if close_fault is None:
                object.__setattr__(claim, "_fd", -1)
                object.__setattr__(
                    claim,
                    "_disposition",
                    "closed_clean" if not claim._errors else "closed_after_fault",
                )
                return claim._errors[before_errors:]

            record_claim_error(claim, close_fault)
            try:
                current = fstat(claim._fd)
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    object.__setattr__(claim, "_fd", -1)
                    object.__setattr__(claim, "_disposition", "close_ambiguous")
                    return claim._errors[before_errors:]
                record_claim_error(claim, exc)
                object.__setattr__(claim, "_disposition", "close_started")
                return claim._errors[before_errors:]
            except BaseException as exc:
                record_claim_error(claim, exc)
                object.__setattr__(claim, "_disposition", "close_started")
                return claim._errors[before_errors:]
            cleanup_identity = (
                claim._identity
                if claim._owned_identity is None
                else claim._owned_identity
            )
            if identity_of(current) != cleanup_identity:
                error = make_close_identity_error(claim._components)
                record_claim_error(claim, error)
                object.__setattr__(claim, "_fd", -1)
                object.__setattr__(claim, "_disposition", "identity_rejected")
                return claim._errors[before_errors:]

        # An exact descriptor still live after its lifetime close budget remains
        # pending for process-level recovery; replay never resets the budget.
        object.__setattr__(claim, "_disposition", "close_started")
        return claim._errors[before_errors:]


def drain_claims(
    get_claims: Callable[[], tuple[DescriptorClaim, ...]],
    lock: threading.RLock,
    *,
    kinds: frozenset[str] | None,
    drain: Callable[..., tuple[BaseException, ...]],
    record_claim_error: Callable[[DescriptorClaim, BaseException], None],
) -> tuple[BaseException, ...]:
    """Drain selected claims twice so one control fault cannot strand a suffix."""
    errors: list[BaseException] = []

    def drain_pass() -> None:
        for claim in get_claims():
            if (kinds is not None and claim._kind not in kinds) or (
                claim._disposition in TERMINAL_DISPOSITIONS
            ):
                continue
            try:
                errors.extend(drain(claim))
            except BaseException as exc:
                record_claim_error(claim, exc)
                errors.append(exc)

    with lock:
        try:
            drain_pass()
        except BaseException as exc:
            errors.append(exc)
        finally:
            try:
                drain_pass()
            except BaseException as exc:
                errors.append(exc)
    return tuple(errors)
