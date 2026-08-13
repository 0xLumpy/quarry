"""Parent-owned bootstrap supervisor for Quarry's killable worker boundary.

The supervisor proves a fixed worker plus its parked, non-executing launcher.
It authenticates READY and PREPARED, then issues an exact prepared-frame-bound
abort.  It never releases the launcher, transfers a stage, or authorizes
publication.
"""
from __future__ import annotations

import hashlib
import math
import os
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum

from . import runner_ipc
from .privfs import (
    PrivateStageArtifactProof,
    PrivateStageHandoffBatch,
    PrivateStageHandoffError,
    _bind_private_stage_transfer_authority,
    _prepare_private_stage_transfer_authority,
    _spawn_with_private_stage_handoff,
    abort_unspawned_private_stage_handoff,
    fence_private_stage_handoff,
    open_ro_private,
    settle_private_stage_handoff,
    transfer_private_stage_handoff,
)
from .runner_containment import (
    ContainmentRefused,
    ContainmentSettlement,
    ContainmentUnsupported,
    MembershipVerification,
    acquire_direct_cgroup_v2,
    capture_parked_process_identity,
    capture_process_identity,
)
from .runner_protocol import (
    MAX_FRAME_BYTES,
    ControlTranscript,
    DescriptorProof,
    ExecutionTerminal,
    NormalizedInvocation,
    ParentSettlementContext,
    PreparedFrame,
    ProtocolError,
    ReadyFrame,
    StartedFrame,
    StdinMode,
    StreamRole,
    StreamTerminal,
    ValidatedSettlement,
    WorkerCommand,
    WorkerCommandKind,
    WorkerRequest,
    WorkerSettlement,
    decode_control_frame,
    encode_command,
    encode_request,
    prepared_digest,
    request_digest,
    validate_parent_settlement,
    validate_control_sequence,
)
from .runner_worker import (
    EXECUTION_ENV,
    EXPECTED_PARENT_PID_ENV,
    PREPARED_ABORT_ENV,
    STDERR_FD_ENV,
    STDIN_FD_ENV,
    STDOUT_FD_ENV,
)


_BOOTSTRAP_OUTCOME_AUTHORITY = object()
_EXECUTION_OUTCOME_AUTHORITY = object()
_REAL_MONOTONIC = time.monotonic
_READ_CHUNK_BYTES = 64 * 1024
_REAP_RESERVE_SECONDS = 0.10
_REAL_CLOCK_SAMPLE_ATTEMPTS = 2
_CONTROL_SELECT_SLICE_SECONDS = 60.0
_CHILD_WAIT_SLICE_SECONDS = 60.0
_MAX_SAFE_DEADLINE = (1 << 53) - 1
_MAX_TRAILING_BYTES = (1 << 53) - 1


class BootstrapReason(str, Enum):
    ABORTED = "aborted"
    UNSUPPORTED = "unsupported"
    SPAWN_FAILED = "spawn_failed"
    IDENTITY_FAILED = "identity_failed"
    REQUEST_FAILED = "request_failed"
    READY_FAILED = "ready_failed"
    COMMAND_FAILED = "command_failed"
    CONTROL_FAILED = "control_failed"
    CONTAINMENT_FAILED = "containment_failed"
    WORKER_FAILED = "worker_failed"
    DEADLINE = "deadline"
    REAP_FAILED = "reap_failed"


@dataclass(frozen=True, slots=True, repr=False, init=False)
class BootstrapOutcome:
    """Parent-authenticated result of one deliberately non-launching bootstrap.

    ``observed_trailing_control_bytes`` is a bounded lower bound: failure paths
    stop consuming untrusted control traffic once invalidity is established.
    ``kill_requested`` records that ``Popen.kill`` was invoked.  An exception
    can make delivery ambiguous, so the reaped status and return code, not that
    flag, prove the eventual child outcome.
    """

    reason: BootstrapReason
    request_id: str = field(repr=False)
    worker_pid: int | None = field(repr=False)
    worker_start_time_ticks: int | None = field(repr=False)
    ready: ReadyFrame | None = field(repr=False)
    settlement: WorkerSettlement | None = field(repr=False)
    worker_returncode: int | None
    worker_spawned: bool
    worker_reaped: bool
    control_eof: bool
    observed_trailing_control_bytes: int
    abort_command_sent: bool
    parent_pipes_closed: bool
    kill_requested: bool

    def __init__(
        self,
        *,
        reason: BootstrapReason,
        request_id: str,
        worker_pid: int | None,
        worker_start_time_ticks: int | None,
        ready: ReadyFrame | None,
        settlement: WorkerSettlement | None,
        worker_returncode: int | None,
        worker_spawned: bool,
        worker_reaped: bool,
        control_eof: bool,
        observed_trailing_control_bytes: int,
        abort_command_sent: bool,
        parent_pipes_closed: bool,
        kill_requested: bool,
        _expected_request_sha256: str | None,
        _authority: object,
        _containment_bound: bool = False,
        _containment_settled: bool = False,
    ) -> None:
        if _authority is not _BOOTSTRAP_OUTCOME_AUTHORITY:
            raise TypeError("bootstrap outcomes require supervisor authority")
        if type(reason) is not BootstrapReason or type(request_id) is not str:
            raise TypeError("invalid bootstrap outcome")
        if worker_pid is not None and (type(worker_pid) is not int or worker_pid <= 0):
            raise TypeError("invalid bootstrap outcome")
        if worker_start_time_ticks is not None and (
                type(worker_start_time_ticks) is not int
                or worker_start_time_ticks < 0):
            raise TypeError("invalid bootstrap outcome")
        if ready is not None and type(ready) is not ReadyFrame:
            raise TypeError("invalid bootstrap outcome")
        if settlement is not None and type(settlement) is not WorkerSettlement:
            raise TypeError("invalid bootstrap outcome")
        if worker_returncode is not None and type(worker_returncode) is not int:
            raise TypeError("invalid bootstrap outcome")
        if (type(worker_spawned) is not bool or type(worker_reaped) is not bool
                or type(control_eof) is not bool
                or type(abort_command_sent) is not bool
                or type(parent_pipes_closed) is not bool
                or type(kill_requested) is not bool
                or type(_containment_bound) is not bool
                or type(_containment_settled) is not bool
                or type(observed_trailing_control_bytes) is not int
                or not 0 <= observed_trailing_control_bytes <= _MAX_TRAILING_BYTES):
            raise TypeError("invalid bootstrap outcome")
        if worker_reaped != (worker_returncode is not None):
            raise ValueError("inconsistent worker reap outcome")
        if not worker_spawned and (
                worker_pid is not None
                or worker_start_time_ticks is not None
                or ready is not None or settlement is not None
                or worker_returncode is not None or worker_reaped
                or control_eof or observed_trailing_control_bytes != 0
                or abort_command_sent or not parent_pipes_closed
                or kill_requested
                or reason is BootstrapReason.REAP_FAILED):
            raise ValueError("inconsistent worker spawn outcome")
        if worker_spawned and (
                (reason is BootstrapReason.REAP_FAILED) != (not worker_reaped)):
            raise ValueError("inconsistent worker reap outcome")
        if worker_spawned and worker_pid is None:
            raise ValueError("inconsistent worker spawn outcome")
        complete = reason is BootstrapReason.ABORTED
        if complete:
            if (not worker_spawned
                    or worker_pid is None or worker_start_time_ticks is None
                    or ready is None or settlement is None
                    or worker_returncode != 0 or not worker_reaped
                    or not control_eof
                    or observed_trailing_control_bytes != 0
                    or not abort_command_sent or not parent_pipes_closed
                    or kill_requested or not _containment_bound
                    or not _containment_settled):
                raise ValueError("incomplete successful bootstrap outcome")
            if (ready.request_id != request_id or ready.worker_pid != worker_pid
                    or settlement.request_id != request_id
                    or settlement.worker_pid != worker_pid):
                raise ValueError("mismatched successful bootstrap outcome")
            if (_expected_request_sha256 is None
                    or ready.request_sha256 != _expected_request_sha256):
                raise ValueError("mismatched successful bootstrap outcome")
            if (settlement.terminal is not ExecutionTerminal.CANCELLED
                    or settlement.launched
                    or not settlement.process_group_settled
                    or settlement.process_tree_settled
                    or settlement.detail != "parent_abort"
                    or any(stream.terminal is not StreamTerminal.NOT_STARTED
                           for stream in settlement.streams)):
                raise ValueError("invalid successful bootstrap settlement")
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "worker_pid", worker_pid)
        object.__setattr__(self, "worker_start_time_ticks", worker_start_time_ticks)
        object.__setattr__(self, "ready", ready)
        object.__setattr__(self, "settlement", settlement)
        object.__setattr__(self, "worker_returncode", worker_returncode)
        object.__setattr__(self, "worker_spawned", worker_spawned)
        object.__setattr__(self, "worker_reaped", worker_reaped)
        object.__setattr__(self, "control_eof", control_eof)
        object.__setattr__(
            self, "observed_trailing_control_bytes",
            observed_trailing_control_bytes,
        )
        object.__setattr__(self, "abort_command_sent", abort_command_sent)
        object.__setattr__(self, "parent_pipes_closed", parent_pipes_closed)
        object.__setattr__(self, "kill_requested", kill_requested)

    @property
    def transaction_complete(self) -> bool:
        return self.reason is BootstrapReason.ABORTED

    def __repr__(self) -> str:
        return (
            "BootstrapOutcome("
            f"reason={self.reason.value!r}, "
            f"transaction_complete={self.transaction_complete}, "
            f"worker_spawned={self.worker_spawned}, "
            f"worker_reaped={self.worker_reaped}, control_eof={self.control_eof}, "
            "observed_trailing_control_bytes="
            f"{self.observed_trailing_control_bytes})"
        )


@dataclass(slots=True, repr=False)
class _BootstrapOwner:
    """Mutable, private authority for one selector and one exact child.

    The object is allocated before either authority exists.  Every post-spawn
    cleanup helper mutates these durable facts before taking an ambiguous action,
    so an outer recovery pass cannot accidentally close or signal twice merely
    because cancellation interrupted a caller between a helper return and a
    local assignment.
    """

    selector: object | None = None
    selector_close_attempted: bool = False
    containment: object | None = None
    containment_bound: bool = False
    containment_settle_attempts: int = 0
    containment_settle_retry_allowed: bool = False
    containment_settlement: ContainmentSettlement | None = None
    containment_close_attempts: int = 0
    containment_close_retry_allowed: bool = False
    containment_terminal: bool = False
    containment_cleanup_failed: bool = False
    child: object | None = None
    worker_spawned: bool = False
    worker_pid: int | None = None
    worker_start_time_ticks: int | None = None
    worker_identity: object | None = None
    input_pipe: object | None = None
    output_pipe: object | None = None
    input_close_attempted: bool = False
    output_close_attempted: bool = False
    input_close_attempts: int = 0
    output_close_attempts: int = 0
    input_close_retry_allowed: bool = False
    output_close_retry_allowed: bool = False
    input_closed_clean: bool = False
    output_closed_clean: bool = False
    input_registered: bool = False
    output_registered: bool = False
    input_fd: int = -1
    output_fd: int = -1
    pending_cancellation: BaseException | None = None
    failure: BootstrapReason | None = None
    ready: ReadyFrame | None = None
    prepared: PreparedFrame | None = None
    settlement: WorkerSettlement | None = None
    control_eof: bool = False
    observed_trailing_control_bytes: int = 0
    abort_command_sent: bool = False
    kill_requested: bool = False
    forced_termination_fault: bool = False
    child_status_fault: bool = False
    worker_reaped: bool = False
    worker_returncode: int | None = None
    poll_cancellations: int = 0
    wait_attempts: int = 0

    def remember(self, exc: BaseException) -> None:
        if not isinstance(exc, Exception):
            self.pending_cancellation = _remember_cancellation(
                self.pending_cancellation, exc,
            )


def _validate_deadline(deadline, clock) -> tuple[float, float]:
    if type(deadline) not in (int, float) or type(deadline) is bool:
        raise TypeError("deadline must be a finite absolute monotonic instant")
    if type(deadline) is int:
        if deadline < 0 or deadline > _MAX_SAFE_DEADLINE:
            raise ValueError("deadline must be a finite absolute monotonic instant")
        deadline_value = float(deadline)
    else:
        deadline_value = deadline
    if (not math.isfinite(deadline_value) or deadline_value < 0
            or deadline_value > _MAX_SAFE_DEADLINE):
        raise ValueError("deadline must be a finite absolute monotonic instant")
    now = clock()
    if type(now) not in (int, float) or type(now) is bool:
        raise TypeError("clock must return a finite monotonic instant")
    if type(now) is int:
        if now < 0 or now > _MAX_SAFE_DEADLINE:
            raise TypeError("clock must return a finite monotonic instant")
        now_value = float(now)
    else:
        now_value = now
    if (not math.isfinite(now_value) or now_value < 0
            or now_value > _MAX_SAFE_DEADLINE):
        raise TypeError("clock must return a finite monotonic instant")
    return deadline_value, now_value


def _remaining(deadline: float, clock, real_deadline: float) -> float:
    """Return a real-time-capped budget; invalid clocks expire fail-closed."""
    real_remaining, cancellation = _real_remaining(real_deadline)
    if cancellation is not None:
        raise cancellation
    try:
        now = clock()
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return real_remaining
    if type(now) not in (int, float) or type(now) is bool:
        return real_remaining
    if type(now) is int:
        if now < 0 or now > _MAX_SAFE_DEADLINE:
            return real_remaining
        now_value = float(now)
    else:
        now_value = now
    if (not math.isfinite(now_value) or now_value < 0
            or now_value > _MAX_SAFE_DEADLINE):
        return real_remaining
    return min(real_remaining, max(0.0, deadline - now_value))


def _select_control(selector, remaining: float):
    """Wait without handing a platform selector an unrepresentable timeout.

    The boolean result says that an empty wait consumed the caller's complete
    remaining budget.  A semantic no-ceiling execution therefore polls in
    finite OS-safe slices without being misclassified as expired.
    """
    wait = min(remaining, _CONTROL_SELECT_SLICE_SECONDS)
    return selector.select(wait), wait >= remaining


def _real_remaining(
    real_deadline: float,
) -> tuple[float, BaseException | None]:
    """Sample trusted time without losing one asynchronous cancellation.

    A second cancellation is outside the cooperative boundary.  It is still
    preserved, but the remaining budget becomes zero so teardown cannot spin
    forever without a usable clock.
    """
    cancellation = None
    for _attempt in range(_REAL_CLOCK_SAMPLE_ATTEMPTS):
        try:
            now = _REAL_MONOTONIC()
        except BaseException as exc:
            if isinstance(exc, Exception):
                return 0.0, cancellation
            cancellation = _remember_cancellation(cancellation, exc)
            continue
        return max(0.0, real_deadline - now), cancellation
    return 0.0, cancellation


def _outcome(
    request: WorkerRequest,
    *,
    reason: BootstrapReason,
    worker_pid: int | None = None,
    worker_start_time_ticks: int | None = None,
    ready: ReadyFrame | None = None,
    settlement: WorkerSettlement | None = None,
    worker_returncode: int | None = None,
    worker_spawned: bool = False,
    worker_reaped: bool = False,
    control_eof: bool = False,
    observed_trailing_control_bytes: int = 0,
    abort_command_sent: bool = False,
    parent_pipes_closed: bool = True,
    kill_requested: bool = False,
    _containment_bound: bool = False,
    _containment_settled: bool = False,
) -> BootstrapOutcome:
    expected_digest = request_digest(request) if reason is BootstrapReason.ABORTED else None
    return BootstrapOutcome(
        reason=reason,
        request_id=request.request_id,
        worker_pid=worker_pid,
        worker_start_time_ticks=worker_start_time_ticks,
        ready=ready,
        settlement=settlement,
        worker_returncode=worker_returncode,
        worker_spawned=worker_spawned,
        worker_reaped=worker_reaped,
        control_eof=control_eof,
        observed_trailing_control_bytes=observed_trailing_control_bytes,
        abort_command_sent=abort_command_sent,
        parent_pipes_closed=parent_pipes_closed,
        kill_requested=kill_requested,
        _expected_request_sha256=expected_digest,
        _authority=_BOOTSTRAP_OUTCOME_AUTHORITY,
        _containment_bound=_containment_bound,
        _containment_settled=_containment_settled,
    )


def _record_reaped(owner: _BootstrapOwner, returncode: int) -> None:
    owner.worker_returncode = returncode
    owner.worker_reaped = True


def _poll_child(owner: _BootstrapOwner) -> str:
    """Poll once, retaining cancellation and never hiding ownership faults."""
    try:
        returncode = owner.child.poll()
    except BaseException as exc:
        if isinstance(exc, Exception):
            owner.child_status_fault = True
            return "fault"
        owner.remember(exc)
        owner.poll_cancellations += 1
        if owner.poll_cancellations >= _REAL_CLOCK_SAMPLE_ATTEMPTS:
            owner.child_status_fault = True
        return "cancelled"
    if returncode is None:
        return "live"
    _record_reaped(owner, returncode)
    return "reaped"


def _wait_child(
    owner: _BootstrapOwner, deadline: float, clock, real_deadline: float,
) -> None:
    """Give a clean transcript one bounded graceful reap opportunity."""
    status = _poll_child(owner)
    if status != "live" or owner.child_status_fault:
        return
    try:
        remaining = _remaining(deadline, clock, real_deadline)
    except BaseException as exc:
        owner.remember(exc)
        remaining, fallback_cancellation = _real_remaining(real_deadline)
        if fallback_cancellation is not None:
            owner.remember(fallback_cancellation)
    if remaining <= 0 or owner.wait_attempts >= _REAL_CLOCK_SAMPLE_ATTEMPTS:
        return
    owner.wait_attempts += 1
    try:
        returncode = owner.child.wait(
            timeout=min(remaining, _CHILD_WAIT_SLICE_SECONDS),
        )
    except subprocess.TimeoutExpired:
        return
    except BaseException as exc:
        if isinstance(exc, Exception):
            owner.child_status_fault = True
        else:
            owner.remember(exc)
        return
    _record_reaped(owner, returncode)


def _graceful_reap_deadlines(
    deadline: float, clock, real_deadline: float,
) -> tuple[float, float]:
    """Reserve part of the one absolute budget for forced kill/reap recovery."""
    remaining = _remaining(deadline, clock, real_deadline)
    reserve = min(_REAP_RESERVE_SECONDS, remaining / 2.0)
    return deadline - reserve, real_deadline - reserve


def _request_kill_bounded(
    owner: _BootstrapOwner, real_deadline: float,
) -> None:
    """Request exact-child termination after a conclusive liveness poll.

    A poll fault never falls through to a PID-based kill because exact child
    ownership could already have been lost to an external reaper.  Cancellation
    during a liveness poll may be retried while the trusted real-time budget
    remains.  The kill invocation itself is attempted at most once: an exception
    makes signal delivery ambiguous, so blindly retrying could target a reused
    numeric PID after an unobserved child exit.
    """
    if (owner.child is None or not owner.worker_spawned or owner.worker_reaped
            or owner.child_status_fault or owner.kill_requested):
        return
    _remaining_budget, sample_cancellation = _real_remaining(real_deadline)
    if sample_cancellation is not None:
        owner.remember(sample_cancellation)

    # A reachable child gets one nonblocking observation even if Popen consumed
    # the absolute deadline.  One cancellation may be retried; repeated
    # cancellation is bounded independently of wall time.
    for _attempt in range(_REAL_CLOCK_SAMPLE_ATTEMPTS):
        status = _poll_child(owner)
        if status == "cancelled" and not owner.child_status_fault:
            continue
        if status != "live":
            return
        # Commit the ambiguous action before invoking it.  Keeping both operations
        # on one source line closes the supported line-cancellation seam.
        try:
            owner.kill_requested = True; owner.child.kill()
        except BaseException as exc:
            owner.forced_termination_fault = True
            owner.remember(exc)
        return


def _final_reap_bounded(
    owner: _BootstrapOwner, real_deadline: float,
) -> None:
    """Conclude exact-child reap under trusted time despite one-shot cancellation."""
    if (owner.child is None or not owner.worker_spawned or owner.worker_reaped
            or owner.child_status_fault):
        return
    for _attempt in range(_REAL_CLOCK_SAMPLE_ATTEMPTS):
        remaining, sample_cancellation = _real_remaining(real_deadline)
        if sample_cancellation is not None:
            owner.remember(sample_cancellation)
        status = _poll_child(owner)
        if status == "cancelled" and not owner.child_status_fault:
            continue
        if status != "live":
            return
        if remaining <= 0 or owner.wait_attempts >= _REAL_CLOCK_SAMPLE_ATTEMPTS:
            return
        owner.wait_attempts += 1
        try:
            returncode = owner.child.wait(
                timeout=min(remaining, _CHILD_WAIT_SLICE_SECONDS),
            )
        except subprocess.TimeoutExpired:
            continue
        except BaseException as exc:
            if isinstance(exc, Exception):
                owner.child_status_fault = True
                return
            owner.remember(exc)
            continue
        _record_reaped(owner, returncode)
        return


def _close_pipe_once(pipe) -> tuple[bool, BaseException | None]:
    """Make one close attempt; never retry an ambiguous numeric authority."""
    if pipe is None:
        return True, None
    try:
        pipe.close()
        return True, None
    except BaseException as exc:
        cancellation = exc if not isinstance(exc, Exception) else None
        return False, cancellation


def _remember_cancellation(
    current: BaseException | None, candidate: BaseException | None,
) -> BaseException | None:
    return current if current is not None else candidate


def _adopt_child_authority(owner: _BootstrapOwner) -> None:
    """Recover every observable Popen authority into the durable owner."""
    child = owner.child
    if child is None:
        return
    try:
        observed_pid = getattr(child, "pid", None)
    except BaseException as exc:
        owner.remember(exc)
        if owner.failure is None:
            owner.failure = BootstrapReason.SPAWN_FAILED
    else:
        if type(observed_pid) is int and observed_pid > 0:
            owner.worker_pid = observed_pid
            owner.worker_spawned = True
    for role in ("input", "output"):
        attribute = "stdin" if role == "input" else "stdout"
        if getattr(owner, f"{role}_pipe") is not None:
            continue
        try:
            pipe = getattr(child, attribute, None)
        except BaseException as exc:
            owner.remember(exc)
            if owner.failure is None:
                owner.failure = BootstrapReason.SPAWN_FAILED
            continue
        if pipe is not None:
            setattr(owner, f"{role}_pipe", pipe)


def _owner_unregister(owner: _BootstrapOwner, role: str) -> None:
    registered_name = f"{role}_registered"
    if owner.selector is None or not getattr(owner, registered_name):
        return
    setattr(owner, registered_name, False)
    fd = owner.input_fd if role == "input" else owner.output_fd
    try:
        owner.selector.unregister(fd)
    except BaseException as exc:
        owner.remember(exc)
        if owner.failure is None:
            owner.failure = BootstrapReason.CONTROL_FAILED


def _owner_close_selector(owner: _BootstrapOwner) -> None:
    if owner.selector is None or owner.selector_close_attempted:
        return
    _owner_unregister(owner, "input")
    _owner_unregister(owner, "output")
    try:
        owner.selector_close_attempted = True; owner.selector.close()
    except BaseException as exc:
        owner.remember(exc)
        if owner.failure is None:
            owner.failure = BootstrapReason.CONTROL_FAILED


def _pipe_closed_state(
    owner: _BootstrapOwner, pipe,
) -> bool | None:
    """Return a conclusive stable-object close state, or ``None`` on a fault."""
    try:
        return getattr(pipe, "closed", False) is True
    except BaseException as exc:
        owner.remember(exc)
        return None


def _owner_close_pipe(owner: _BootstrapOwner, role: str) -> bool:
    pipe = owner.input_pipe if role == "input" else owner.output_pipe
    attempted_name = f"{role}_close_attempted"
    attempts_name = f"{role}_close_attempts"
    retry_name = f"{role}_close_retry_allowed"
    clean_name = f"{role}_closed_clean"
    if pipe is None:
        setattr(owner, clean_name, True)
        return True
    if getattr(owner, clean_name):
        return True
    state = _pipe_closed_state(owner, pipe)
    if state is None:
        return False
    if state and not getattr(owner, attempted_name):
        setattr(owner, clean_name, True)
        return True
    # A prior invocation that completed physically but raised is not clean and is
    # never retried.  If it was interrupted before close, however, the stable
    # Python file object can safely receive one bounded cooperative retry.
    attempts = getattr(owner, attempts_name)
    if (state or attempts >= _REAL_CLOCK_SAMPLE_ATTEMPTS
            or (attempts and not getattr(owner, retry_name))):
        return False
    while getattr(owner, attempts_name) < _REAL_CLOCK_SAMPLE_ATTEMPTS:
        if getattr(owner, attempts_name):
            if not getattr(owner, retry_name):
                return False
        # Commit the attempt and invoke close on one source line, closing the
        # supported line-cancellation seams between permission consumption,
        # accounting, and the stable-object action.
        setattr(owner, retry_name, False); setattr(owner, attempted_name, True); setattr(owner, attempts_name, getattr(owner, attempts_name) + 1); closed, cancellation = _close_pipe_once(pipe)
        if closed:
            setattr(owner, clean_name, True)
            return True
        if cancellation is None:
            return False
        owner.remember(cancellation)
        state = _pipe_closed_state(owner, pipe)
        if state is not False:
            return False
        if getattr(owner, attempts_name) < _REAL_CLOCK_SAMPLE_ATTEMPTS:
            setattr(owner, retry_name, True)
    return False


def _settle_owned_containment(
    owner: _BootstrapOwner, real_deadline: float,
) -> None:
    """Settle one acquired cgroup, then terminalize any residual FD authority."""
    handle = owner.containment
    if handle is None or owner.containment_terminal:
        return

    while (owner.containment_settlement is None
           and owner.containment_settle_attempts < _REAL_CLOCK_SAMPLE_ATTEMPTS
           and (owner.containment_settle_attempts == 0
                or owner.containment_settle_retry_allowed)):
        owner.containment_settle_retry_allowed = False
        try:
            owner.containment_settle_attempts += 1; owner.containment_settlement = handle.kill_settle_remove(real_deadline)
        except BaseException as exc:
            owner.remember(exc)
            if (not isinstance(exc, Exception)
                    and owner.containment_settle_attempts
                    < _REAL_CLOCK_SAMPLE_ATTEMPTS):
                # The public containment transaction stores monotone kill/remove
                # facts and explicitly supports one same-owner reconciliation
                # entry after cooperative cancellation.  Ordinary faults and
                # concrete non-settled results are never replayed.
                owner.containment_settle_retry_allowed = True
                continue
            break

    settlement = owner.containment_settlement
    if (type(settlement) is ContainmentSettlement
            and settlement.cooperative_settled):
        owner.containment_terminal = True
        return

    owner.containment_cleanup_failed = True
    owner.failure = BootstrapReason.CONTAINMENT_FAILED
    while (not owner.containment_terminal
           and owner.containment_close_attempts < _REAL_CLOCK_SAMPLE_ATTEMPTS
           and (owner.containment_close_attempts == 0
                or owner.containment_close_retry_allowed)):
        owner.containment_close_retry_allowed = False
        try:
            owner.containment_close_attempts += 1; handle.close(); owner.containment_terminal = True
        except BaseException as exc:
            owner.remember(exc)
            if (not isinstance(exc, Exception)
                    and owner.containment_close_attempts
                    < _REAL_CLOCK_SAMPLE_ATTEMPTS):
                # The stable DirectCgroupV2 owner reconciles its own monotone
                # descriptor claims.  A second entry is safe after the one
                # cooperative cancellation, including a cancellation at the
                # callee's first line before its fence became active.
                owner.containment_close_retry_allowed = True
                continue
            break
        else:
            break


def _settle_owned_child(
    owner: _BootstrapOwner, deadline: float, clock, real_deadline: float,
) -> None:
    """Settle both parent-owned authorities from their durable facts."""
    _adopt_child_authority(owner)
    _owner_close_selector(owner)
    input_clean = _owner_close_pipe(owner, "input")
    output_clean = _owner_close_pipe(owner, "output")
    parent_pipes_closed = input_clean and output_clean
    if not parent_pipes_closed and owner.failure is None:
        owner.failure = BootstrapReason.CONTROL_FAILED

    # Closing the command channel first makes the fixed worker fail closed.
    # Consume exact child-status authority before cgroup settlement: the latter
    # may legitimately wait until the absolute deadline, but must never thereby
    # strand an unreaped supervisor child.  Cgroup kill remains the final
    # fallback for the already-bound launcher and any cooperative descendants.
    if owner.worker_spawned:
        if owner.failure is None:
            try:
                graceful_deadline, graceful_real_deadline = (
                    _graceful_reap_deadlines(deadline, clock, real_deadline)
                )
            except BaseException as exc:
                owner.remember(exc)
                owner.failure = BootstrapReason.DEADLINE
            else:
                _wait_child(
                    owner, graceful_deadline, clock, graceful_real_deadline,
                )

        if not owner.worker_reaped and not owner.child_status_fault:
            _request_kill_bounded(owner, real_deadline)
        if not owner.worker_reaped and not owner.child_status_fault:
            _final_reap_bounded(owner, real_deadline)

    _settle_owned_containment(owner, real_deadline)

    if not owner.worker_spawned:
        return

    if not owner.worker_reaped:
        owner.failure = BootstrapReason.REAP_FAILED
        owner.worker_returncode = None
    elif owner.containment_cleanup_failed:
        owner.failure = BootstrapReason.CONTAINMENT_FAILED
    elif owner.failure is None and (
            owner.worker_returncode != 0 or owner.kill_requested
            or owner.forced_termination_fault):
        owner.failure = BootstrapReason.WORKER_FAILED
    if owner.failure is None:
        if (owner.containment_bound
                and type(owner.containment_settlement) is ContainmentSettlement
                and owner.containment_settlement.cooperative_settled
                and owner.containment_terminal):
            owner.failure = BootstrapReason.ABORTED
        else:
            owner.failure = BootstrapReason.CONTAINMENT_FAILED


def _drive_abort_protocol(
    owner: _BootstrapOwner,
    request: WorkerRequest,
    request_wire: bytes,
    digest: str,
    decoder: runner_ipc.IncrementalFrameDecoder,
    deadline: float,
    clock,
    real_deadline: float,
) -> None:
    """Drive REQUEST -> READY -> PREPARED -> ABORT -> CANCELLED."""
    input_pipe = owner.input_pipe
    output_pipe = owner.output_pipe
    selector = owner.selector
    owner.input_fd = input_pipe.fileno()
    owner.output_fd = output_pipe.fileno()
    os.set_blocking(owner.input_fd, False)
    os.set_blocking(owner.output_fd, False)
    selector.register(owner.input_fd, selectors.EVENT_WRITE, "write")
    owner.input_registered = True
    selector.register(owner.output_fd, selectors.EVENT_READ, "read")
    owner.output_registered = True

    initial_remaining = _remaining(deadline, clock, real_deadline)
    reserve = min(_REAP_RESERVE_SECONDS, initial_remaining / 4.0)
    io_deadline = deadline - reserve
    io_real_deadline = real_deadline - reserve
    write_wire = request_wire
    write_offset = 0
    write_phase = "request"
    frames: list[object] = []

    while owner.failure is None and not owner.control_eof:
        remaining = _remaining(io_deadline, clock, io_real_deadline)
        if remaining <= 0:
            owner.failure = BootstrapReason.DEADLINE
            break
        try:
            events, budget_consumed = _select_control(selector, remaining)
        except BaseException as exc:
            owner.remember(exc)
            owner.failure = BootstrapReason.CONTROL_FAILED
            break
        if not events and not budget_consumed:
            continue
        if not events:
            owner.failure = BootstrapReason.DEADLINE
            break
        for key, mask in events:
            if key.data == "write" and mask & selectors.EVENT_WRITE:
                try:
                    count = os.write(
                        owner.input_fd, write_wire[write_offset:],
                    )
                except BlockingIOError:
                    continue
                except BaseException as exc:
                    owner.remember(exc)
                    owner.failure = (
                        BootstrapReason.REQUEST_FAILED
                        if write_phase == "request"
                        else BootstrapReason.COMMAND_FAILED
                    )
                    break
                if count <= 0:
                    owner.failure = (
                        BootstrapReason.REQUEST_FAILED
                        if write_phase == "request"
                        else BootstrapReason.COMMAND_FAILED
                    )
                    break
                write_offset += count
                if write_offset == len(write_wire):
                    _owner_unregister(owner, "input")
                    if owner.failure is not None:
                        break
                    if write_phase == "command":
                        if not _owner_close_pipe(owner, "input"):
                            owner.failure = BootstrapReason.COMMAND_FAILED
                            break
                        owner.input_fd = -1
                        owner.abort_command_sent = True
                    write_wire = b""
                    write_offset = 0

            if key.data == "read" and mask & selectors.EVENT_READ:
                try:
                    chunk = os.read(owner.output_fd, _READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                except BaseException as exc:
                    owner.remember(exc)
                    owner.failure = BootstrapReason.CONTROL_FAILED
                    break
                if not chunk:
                    owner.control_eof = True
                    _owner_unregister(owner, "output")
                    try:
                        decoder.finish()
                    except runner_ipc.IpcError:
                        owner.observed_trailing_control_bytes = min(
                            decoder.pending_size, _MAX_TRAILING_BYTES,
                        )
                        owner.failure = BootstrapReason.CONTROL_FAILED
                    break
                try:
                    wire_frames = decoder.feed(chunk)
                except runner_ipc.IpcError:
                    owner.observed_trailing_control_bytes = min(
                        decoder.pending_size, _MAX_TRAILING_BYTES,
                    )
                    owner.failure = BootstrapReason.CONTROL_FAILED
                    break
                for wire_frame in wire_frames:
                    if len(frames) >= 3:
                        owner.observed_trailing_control_bytes = min(
                            owner.observed_trailing_control_bytes
                            + len(wire_frame),
                            _MAX_TRAILING_BYTES,
                        )
                        owner.failure = BootstrapReason.CONTROL_FAILED
                        break
                    try:
                        record = decode_control_frame(wire_frame)
                    except ProtocolError:
                        owner.failure = BootstrapReason.CONTROL_FAILED
                        break
                    if not frames:
                        if type(record) is not ReadyFrame:
                            owner.failure = BootstrapReason.READY_FAILED
                            break
                        if (record.request_id != request.request_id
                                or record.worker_pid != owner.worker_pid
                                or record.request_sha256 != digest):
                            owner.failure = BootstrapReason.READY_FAILED
                            break
                        owner.ready = record
                    elif len(frames) == 1:
                        if type(record) is not PreparedFrame:
                            owner.failure = BootstrapReason.CONTROL_FAILED
                            break
                        if (record.request_id != request.request_id
                                or record.worker_pid != owner.worker_pid
                                or record.launcher_pid != record.launcher_pgid
                                or owner.containment is None
                                or record.containment_kind
                                is not owner.containment.kind
                                or record.containment_id
                                != owner.containment.containment_id
                                or owner.worker_identity is None):
                            owner.failure = BootstrapReason.CONTROL_FAILED
                            break
                        try:
                            proof = capture_parked_process_identity(
                                record.launcher_pid, owner.worker_identity,
                            )
                        except BaseException as exc:
                            owner.remember(exc)
                            owner.failure = BootstrapReason.IDENTITY_FAILED
                            break
                        if (proof.process.pid != record.launcher_pid
                                or proof.parent != owner.worker_identity
                                or proof.state not in ("T", "t")):
                            owner.failure = BootstrapReason.IDENTITY_FAILED
                            break
                        try:
                            verification = owner.containment.bind_parked_process(
                                proof,
                            )
                        except BaseException as exc:
                            owner.remember(exc)
                            owner.failure = BootstrapReason.CONTAINMENT_FAILED
                            break
                        if (type(verification) is not MembershipVerification
                                or not verification.verified):
                            owner.failure = BootstrapReason.CONTAINMENT_FAILED
                            break
                        owner.containment_bound = True
                        owner.prepared = record
                        write_wire = encode_command(WorkerCommand(
                            request_id=request.request_id,
                            request_sha256=digest,
                            worker_pid=owner.worker_pid,
                            command=WorkerCommandKind.ABORT,
                            prepared_sha256=prepared_digest(record),
                        ))
                        write_offset = 0
                        write_phase = "command"
                        try:
                            selector.register(
                                owner.input_fd, selectors.EVENT_WRITE, "write",
                            )
                            owner.input_registered = True
                        except BaseException as exc:
                            owner.remember(exc)
                            owner.failure = BootstrapReason.COMMAND_FAILED
                            break
                    elif type(record) is not WorkerSettlement:
                        owner.failure = BootstrapReason.CONTROL_FAILED
                        break
                    else:
                        if not owner.abort_command_sent:
                            owner.failure = BootstrapReason.CONTROL_FAILED
                            break
                        owner.settlement = record
                    frames.append(record)
                if owner.failure is not None:
                    break

    if owner.failure is not None:
        return
    if (not owner.control_eof or owner.ready is None or owner.prepared is None
            or owner.settlement is None or not owner.abort_command_sent):
        owner.failure = BootstrapReason.CONTROL_FAILED
        return
    try:
        transcript: ControlTranscript = validate_control_sequence(
            (owner.ready, owner.prepared, owner.settlement),
        )
    except ProtocolError:
        owner.failure = BootstrapReason.CONTROL_FAILED
        return
    settled = transcript.settlement
    if (settled.request_id != request.request_id
            or settled.worker_pid != owner.worker_pid
            or settled.terminal is not ExecutionTerminal.CANCELLED
            or settled.launched or not settled.process_group_settled
            or settled.process_tree_settled
            or settled.detail != "parent_abort"
            or any(stream.terminal is not StreamTerminal.NOT_STARTED
                   for stream in settled.streams)):
        owner.failure = BootstrapReason.CONTROL_FAILED


def bootstrap_worker(
    request: WorkerRequest,
    *,
    deadline,
    clock=time.monotonic,
    popen_factory=subprocess.Popen,
) -> BootstrapOutcome:
    """Prove the parked worker boundary by completing a pre-launch abort.

    This process must retain exclusive child-status ownership for the call:
    ``SIGCHLD`` must use its default disposition and no independent reaper may
    consume this exact child.  The supervisor refuses a non-default disposition;
    the caller is responsible for keeping that process-global contract stable.
    """
    if type(request) is not WorkerRequest:
        raise ProtocolError("invalid worker request", "request")
    if not callable(clock) or not callable(popen_factory):
        raise TypeError("bootstrap dependencies must be callable")
    deadline, now = _validate_deadline(deadline, clock)
    real_now = _REAL_MONOTONIC()
    real_deadline = real_now + (deadline - now)
    if not math.isfinite(real_deadline):
        raise ValueError("deadline must be a finite absolute monotonic instant")
    if sys.platform != "linux":
        return _outcome(request, reason=BootstrapReason.UNSUPPORTED)
    if now >= deadline:
        return _outcome(request, reason=BootstrapReason.DEADLINE)
    try:
        sigchld_handler = signal.getsignal(signal.SIGCHLD)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return _outcome(request, reason=BootstrapReason.UNSUPPORTED)
    if sigchld_handler is not signal.SIG_DFL:
        return _outcome(request, reason=BootstrapReason.UNSUPPORTED)

    argv = [sys.executable, "-I", "-m", "quarry_recon.runner_worker"]
    bootstrap_env = {
        EXPECTED_PARENT_PID_ENV: str(os.getpid()),
        PREPARED_ABORT_ENV: "1",
    }
    try:
        decoder = runner_ipc.IncrementalFrameDecoder(MAX_FRAME_BYTES)
        request_wire = encode_request(request)
        digest = request_digest(request)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return _outcome(request, reason=BootstrapReason.REQUEST_FAILED)
    if _remaining(deadline, clock, real_deadline) <= 0:
        return _outcome(request, reason=BootstrapReason.DEADLINE)

    owner = _BootstrapOwner()
    try:
        try:
            owner.containment = acquire_direct_cgroup_v2(request.request_id)
        except (ContainmentUnsupported, ContainmentRefused):
            owner.failure = BootstrapReason.UNSUPPORTED
        except BaseException as exc:
            owner.remember(exc)
            owner.failure = BootstrapReason.CONTAINMENT_FAILED
        if owner.failure is None and _remaining(
                deadline, clock, real_deadline,
        ) <= 0:
            owner.failure = BootstrapReason.DEADLINE
        if owner.failure is None:
            try:
                owner.selector = selectors.DefaultSelector()
            except BaseException as exc:
                owner.remember(exc)
                owner.failure = BootstrapReason.CONTROL_FAILED
        if owner.failure is None:
            spawn_kwargs = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.DEVNULL,
                "close_fds": True,
                "start_new_session": True,
                "shell": False,
                "env": bootstrap_env,
                "cwd": "/",
                "bufsize": 0,
                "text": False,
            }
            if popen_factory is subprocess.Popen:
                # Publish the exact Popen object before its initializer can fork.
                # If construction is interrupted after PID creation, the outer
                # owner can still recover its pipes and exact wait authority.
                owner.child = subprocess.Popen.__new__(subprocess.Popen)
                subprocess.Popen.__init__(owner.child, argv, **spawn_kwargs)
            else:
                # Test-only seam: a custom factory must honor Popen's postcondition
                # that raising means it did not create a child authority.
                owner.child = popen_factory(argv, **spawn_kwargs)
            _adopt_child_authority(owner)
            if (not owner.worker_spawned or owner.input_pipe is None
                    or owner.output_pipe is None):
                owner.failure = BootstrapReason.SPAWN_FAILED
            else:
                try:
                    identity = capture_process_identity(owner.worker_pid)
                    if identity.pid != owner.worker_pid:
                        raise RuntimeError("worker identity mismatch")
                    owner.worker_start_time_ticks = identity.start_time_ticks
                    owner.worker_identity = identity
                except BaseException as exc:
                    owner.remember(exc)
                    owner.failure = BootstrapReason.IDENTITY_FAILED
            if owner.failure is None:
                _drive_abort_protocol(
                    owner, request, request_wire, digest, decoder,
                    deadline, clock, real_deadline,
                )
    except BaseException as exc:
        owner.remember(exc)
        _adopt_child_authority(owner)
        if owner.failure is None:
            owner.failure = (
                BootstrapReason.REQUEST_FAILED
                if owner.selector is None
                else BootstrapReason.SPAWN_FAILED
                if not owner.worker_spawned
                else BootstrapReason.CONTROL_FAILED
            )
    finally:
        try:
            _settle_owned_child(owner, deadline, clock, real_deadline)
        except BaseException as exc:
            # One cooperative cancellation anywhere inside the first cleanup
            # pass cannot strand the durable owner.  A second pass resumes from
            # its monotone close/kill/reap facts without replaying an ambiguous
            # action.  Repeated arbitrary injection remains outside the boundary.
            owner.remember(exc)
            if owner.failure is None:
                owner.failure = BootstrapReason.CONTROL_FAILED
            try:
                _settle_owned_child(owner, deadline, clock, real_deadline)
            except BaseException as retry_exc:
                owner.remember(retry_exc)
                if owner.worker_spawned and not owner.worker_reaped:
                    owner.failure = BootstrapReason.REAP_FAILED

    if owner.pending_cancellation is not None:
        raise owner.pending_cancellation
    if not owner.worker_spawned:
        return _outcome(request, reason=owner.failure or BootstrapReason.SPAWN_FAILED)
    return _outcome(
        request,
        reason=owner.failure or BootstrapReason.REAP_FAILED,
        worker_pid=owner.worker_pid,
        worker_start_time_ticks=owner.worker_start_time_ticks,
        ready=owner.ready,
        settlement=owner.settlement,
        worker_returncode=owner.worker_returncode,
        worker_spawned=True,
        worker_reaped=owner.worker_reaped,
        control_eof=owner.control_eof,
        observed_trailing_control_bytes=owner.observed_trailing_control_bytes,
        abort_command_sent=owner.abort_command_sent,
        parent_pipes_closed=(
            owner.input_closed_clean and owner.output_closed_clean
        ),
        kill_requested=owner.kill_requested,
        _containment_bound=owner.containment_bound,
        _containment_settled=(
            type(owner.containment_settlement) is ContainmentSettlement
            and owner.containment_settlement.cooperative_settled
            and owner.containment_terminal
        ),
    )


class ExecutionReason(str, Enum):
    """Parent-side disposition of one execution transaction."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNSUPPORTED = "unsupported"
    SPAWN_FAILED = "spawn_failed"
    IDENTITY_FAILED = "identity_failed"
    INPUT_FAILED = "input_failed"
    REQUEST_FAILED = "request_failed"
    COMMAND_FAILED = "command_failed"
    CONTROL_FAILED = "control_failed"
    CONTAINMENT_FAILED = "containment_failed"
    STAGE_FAILED = "stage_failed"
    WORKER_FAILED = "worker_failed"
    DEADLINE = "deadline"
    REAP_FAILED = "reap_failed"


@dataclass(frozen=True, slots=True, repr=False)
class ExecutionOutcome:
    """Immutable parent-authenticated facts for one supervised execution.

    A complete outcome includes a ``ValidatedSettlement`` created by the
    protocol's private parent-validation authority and, when output was
    requested, exact immutable private-stage proofs.  Non-complete outcomes are
    intentionally useful for fault reporting without granting publication
    authority.
    """

    reason: ExecutionReason
    request_id: str = field(repr=False)
    worker_pid: int | None = field(default=None, repr=False)
    worker_start_time_ticks: int | None = field(default=None, repr=False)
    ready: ReadyFrame | None = field(default=None, repr=False)
    prepared: PreparedFrame | None = field(default=None, repr=False)
    started: StartedFrame | None = field(default=None, repr=False)
    settlement: WorkerSettlement | None = field(default=None, repr=False)
    validated: ValidatedSettlement | None = field(default=None, repr=False)
    artifact_proofs: tuple[PrivateStageArtifactProof, ...] = field(
        default=(), repr=False,
    )
    worker_returncode: int | None = None
    worker_spawned: bool = False
    worker_reaped: bool = False
    control_eof: bool = False
    observed_trailing_control_bytes: int = 0
    go_command_sent: bool = False
    parent_pipes_closed: bool = True
    kill_requested: bool = False
    containment_settled: bool = False
    stages_settled: bool = False
    _authority: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority is not _EXECUTION_OUTCOME_AUTHORITY:
            raise TypeError("execution outcomes require supervisor authority")
        if type(self.reason) is not ExecutionReason:
            raise TypeError("invalid execution outcome")
        if (type(self.request_id) is not str or len(self.request_id) != 32
                or any(char not in "0123456789abcdef"
                       for char in self.request_id)):
            raise TypeError("invalid execution outcome")
        if self.worker_pid is not None and (
                type(self.worker_pid) is not int or self.worker_pid <= 0):
            raise TypeError("invalid execution outcome")
        if self.worker_start_time_ticks is not None and (
                type(self.worker_start_time_ticks) is not int
                or self.worker_start_time_ticks < 0):
            raise TypeError("invalid execution outcome")
        for value, expected in (
            (self.ready, ReadyFrame),
            (self.prepared, PreparedFrame),
            (self.started, StartedFrame),
            (self.settlement, WorkerSettlement),
            (self.validated, ValidatedSettlement),
        ):
            if value is not None and type(value) is not expected:
                raise TypeError("invalid execution outcome")
        if self.worker_returncode is not None and (
                type(self.worker_returncode) is not int):
            raise TypeError("invalid execution outcome")
        if (type(self.observed_trailing_control_bytes) is not int
                or not 0 <= self.observed_trailing_control_bytes
                <= _MAX_TRAILING_BYTES):
            raise TypeError("invalid execution outcome")
        if type(self.artifact_proofs) is not tuple or any(
                type(proof) is not PrivateStageArtifactProof
                for proof in self.artifact_proofs):
            raise TypeError("invalid execution outcome")
        for name in (
            "worker_spawned", "worker_reaped", "control_eof",
            "go_command_sent", "parent_pipes_closed", "kill_requested",
            "containment_settled", "stages_settled",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError("invalid execution outcome")
        if self.worker_reaped != (self.worker_returncode is not None):
            raise ValueError("inconsistent execution reap outcome")
        if self.reason is ExecutionReason.COMPLETE:
            if (type(self.validated) is not ValidatedSettlement
                    or not self.validated.capture_complete
                    or type(self.settlement) is not WorkerSettlement
                    or not self.worker_reaped or self.worker_returncode != 0
                    or not self.control_eof
                    or self.observed_trailing_control_bytes != 0
                    or not self.go_command_sent or not self.parent_pipes_closed
                    or not self.containment_settled or not self.stages_settled):
                raise ValueError("incomplete successful execution outcome")

    @property
    def transaction_complete(self) -> bool:
        return self.reason is ExecutionReason.COMPLETE

    def __repr__(self) -> str:
        return (
            "ExecutionOutcome("
            f"reason={self.reason.value!r}, "
            f"transaction_complete={self.transaction_complete}, "
            f"worker_spawned={self.worker_spawned}, "
            f"worker_reaped={self.worker_reaped}, "
            f"control_eof={self.control_eof}, "
            f"artifact_proofs={len(self.artifact_proofs)})"
        )


@dataclass(slots=True, repr=False)
class _ExecutionOwner(_BootstrapOwner):
    """Durable mutable authority for an execution-only transaction."""

    started: StartedFrame | None = None
    validated: ValidatedSettlement | None = None
    stage_batch: PrivateStageHandoffBatch | None = None
    stage_authority: object | None = None
    stage_receipt: object | None = None
    artifact_proofs: tuple[PrivateStageArtifactProof, ...] = ()
    input_file_fd: int = -1
    input_file_close_attempted: bool = False
    input_file_closed_clean: bool = True
    go_command_sent: bool = False
    prepared_identity: object | None = None
    prepared_identity_verified: bool = False
    tool_identity_verified: bool = False
    containment_verified: bool = False
    stages_settled: bool = False


class _ExecutionProtocolFailure(Exception):
    """Credential-safe internal classification for one protocol step."""

    def __init__(self, reason: ExecutionReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def _execution_reason(value, default: ExecutionReason) -> ExecutionReason:
    if type(value) is ExecutionReason:
        return value
    if type(value) is BootstrapReason:
        try:
            return ExecutionReason(value.value)
        except ValueError:
            return default
    return default


def _set_execution_failure(
    owner: _ExecutionOwner, reason: ExecutionReason,
) -> None:
    if owner.failure is None:
        owner.failure = reason


def _execution_outcome(
    invocation: NormalizedInvocation,
    owner: _ExecutionOwner,
    *,
    reason: ExecutionReason | None = None,
) -> ExecutionOutcome:
    resolved = reason or _execution_reason(
        owner.failure, ExecutionReason.REAP_FAILED,
    )
    return ExecutionOutcome(
        reason=resolved,
        request_id=invocation.worker.request_id,
        worker_pid=owner.worker_pid,
        worker_start_time_ticks=owner.worker_start_time_ticks,
        ready=owner.ready,
        prepared=owner.prepared,
        started=owner.started,
        settlement=owner.settlement,
        validated=owner.validated,
        artifact_proofs=owner.artifact_proofs,
        worker_returncode=owner.worker_returncode,
        worker_spawned=owner.worker_spawned,
        worker_reaped=owner.worker_reaped,
        control_eof=owner.control_eof,
        observed_trailing_control_bytes=owner.observed_trailing_control_bytes,
        go_command_sent=owner.go_command_sent,
        parent_pipes_closed=(
            (
                not owner.worker_spawned
                and owner.input_pipe is None
                and owner.output_pipe is None
            )
            or (owner.input_closed_clean and owner.output_closed_clean)
        ),
        kill_requested=owner.kill_requested,
        containment_settled=(
            type(owner.containment_settlement) is ContainmentSettlement
            and owner.containment_settlement.cooperative_settled
            and owner.containment_terminal
        ),
        stages_settled=owner.stages_settled,
        _authority=_EXECUTION_OUTCOME_AUTHORITY,
    )


def _execution_output_claims(
    request: WorkerRequest,
) -> tuple[tuple[StreamRole, str], ...]:
    return tuple(
        (claim.role, claim.claim_id)
        for claim in request.descriptor_claims
        if claim.role in (StreamRole.STDOUT, StreamRole.STDERR)
    )


def _execution_spawn_env(
    writer_fds: tuple[int, ...],
    output_claims: tuple[tuple[StreamRole, str], ...],
    input_file_fd: int,
) -> tuple[dict[str, str], tuple[int, ...]]:
    if len(writer_fds) != len(output_claims):
        raise PrivateStageHandoffError("borrow_spawn")
    env = {
        EXPECTED_PARENT_PID_ENV: str(os.getpid()),
        EXECUTION_ENV: "1",
    }
    role_names = {
        StreamRole.STDOUT: STDOUT_FD_ENV,
        StreamRole.STDERR: STDERR_FD_ENV,
    }
    for writer_fd, (role, _claim_id) in zip(writer_fds, output_claims):
        if type(writer_fd) is not int or writer_fd < 0:
            raise PrivateStageHandoffError("borrow_spawn")
        env[role_names[role]] = str(writer_fd)
    pass_fds = writer_fds
    if input_file_fd >= 0:
        env[STDIN_FD_ENV] = str(input_file_fd)
        pass_fds += (input_file_fd,)
    if len(set(pass_fds)) != len(pass_fds):
        raise PrivateStageHandoffError("borrow_spawn")
    return env, pass_fds


def _spawn_execution_child(
    owner: _ExecutionOwner,
    writer_fds: tuple[int, ...],
    output_claims: tuple[tuple[StreamRole, str], ...],
    popen_factory,
):
    env, pass_fds = _execution_spawn_env(
        writer_fds, output_claims, owner.input_file_fd,
    )
    argv = [sys.executable, "-I", "-m", "quarry_recon.runner_worker"]
    spawn_kwargs = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "start_new_session": True,
        "shell": False,
        "env": env,
        "cwd": "/",
        "bufsize": 0,
        "text": False,
        "pass_fds": pass_fds,
    }
    if popen_factory is subprocess.Popen:
        owner.child = subprocess.Popen.__new__(subprocess.Popen)
        subprocess.Popen.__init__(owner.child, argv, **spawn_kwargs)
    else:
        owner.child = popen_factory(argv, **spawn_kwargs)
    return owner.child


def _authenticate_execution_ready(
    owner: _ExecutionOwner,
    request: WorkerRequest,
    digest: str,
    ready: ReadyFrame,
) -> None:
    if (ready.request_id != request.request_id
            or ready.worker_pid != owner.worker_pid
            or ready.request_sha256 != digest):
        raise ProtocolError("ready authentication failed", "ready")
    if owner.stage_batch is not None:
        try:
            owner.stage_authority = _bind_private_stage_transfer_authority(
                owner.stage_batch,
                owner.stage_authority,
                worker_pid=owner.worker_pid,
            )
        except Exception:
            raise _ExecutionProtocolFailure(
                ExecutionReason.STAGE_FAILED,
            ) from None
    owner.ready = ready


def _authenticate_execution_prepared(
    owner: _ExecutionOwner,
    request: WorkerRequest,
    prepared: PreparedFrame,
) -> None:
    if (prepared.request_id != request.request_id
            or prepared.worker_pid != owner.worker_pid
            or prepared.launcher_pid != prepared.launcher_pgid
            or owner.containment is None
            or prepared.containment_kind is not owner.containment.kind
            or prepared.containment_id != owner.containment.containment_id
            or owner.worker_identity is None):
        raise ProtocolError("prepared authentication failed", "prepared")
    try:
        proof = capture_parked_process_identity(
            prepared.launcher_pid, owner.worker_identity,
        )
    except Exception:
        raise _ExecutionProtocolFailure(
            ExecutionReason.IDENTITY_FAILED,
        ) from None
    if (proof.process.pid != prepared.launcher_pid
            or proof.parent != owner.worker_identity
            or proof.state not in ("T", "t")):
        raise _ExecutionProtocolFailure(ExecutionReason.IDENTITY_FAILED)
    try:
        verification = owner.containment.bind_parked_process(proof)
    except Exception:
        raise _ExecutionProtocolFailure(
            ExecutionReason.CONTAINMENT_FAILED,
        ) from None
    if (type(verification) is not MembershipVerification
            or not verification.verified):
        raise _ExecutionProtocolFailure(ExecutionReason.CONTAINMENT_FAILED)
    owner.containment_bound = True
    owner.prepared_identity = proof.process
    owner.prepared_identity_verified = True
    owner.prepared = prepared
    if owner.stage_batch is not None:
        try:
            owner.stage_receipt = transfer_private_stage_handoff(
                owner.stage_batch, owner.stage_authority,
            )
        except Exception:
            raise _ExecutionProtocolFailure(
                ExecutionReason.STAGE_FAILED,
            ) from None


def _authenticate_execution_started(
    owner: _ExecutionOwner,
    request: WorkerRequest,
    started: StartedFrame,
) -> None:
    prepared = owner.prepared
    if (not owner.go_command_sent or prepared is None
            or started.request_id != request.request_id
            or started.worker_pid != owner.worker_pid
            or started.tool_pid != prepared.launcher_pid
            or started.tool_pgid != prepared.launcher_pgid
            or started.containment_kind is not prepared.containment_kind
            or started.containment_id != prepared.containment_id):
        raise ProtocolError("started authentication failed", "started")
    try:
        identity = capture_process_identity(started.tool_pid)
    except Exception:
        raise _ExecutionProtocolFailure(
            ExecutionReason.IDENTITY_FAILED,
        ) from None
    if (identity.pid != started.tool_pid
            or identity != owner.prepared_identity):
        raise _ExecutionProtocolFailure(ExecutionReason.IDENTITY_FAILED)
    try:
        verification = owner.containment.verify_pid(identity)
    except Exception:
        raise _ExecutionProtocolFailure(
            ExecutionReason.CONTAINMENT_FAILED,
        ) from None
    if (type(verification) is not MembershipVerification
            or not verification.verified):
        raise _ExecutionProtocolFailure(ExecutionReason.CONTAINMENT_FAILED)
    owner.tool_identity_verified = True
    owner.started = started


def _drive_execution_protocol(
    owner: _ExecutionOwner,
    request: WorkerRequest,
    request_wire: bytes,
    digest: str,
    decoder: runner_ipc.IncrementalFrameDecoder,
    deadline: float,
    clock,
    real_deadline: float,
) -> None:
    """Drive REQUEST(+DATA) -> READY -> PREPARED -> GO -> STARTED -> SETTLEMENT."""
    owner.input_fd = owner.input_pipe.fileno()
    owner.output_fd = owner.output_pipe.fileno()
    os.set_blocking(owner.input_fd, False)
    os.set_blocking(owner.output_fd, False)
    owner.selector.register(owner.input_fd, selectors.EVENT_WRITE, "write")
    owner.input_registered = True
    owner.selector.register(owner.output_fd, selectors.EVENT_READ, "read")
    owner.output_registered = True

    initial_remaining = _remaining(deadline, clock, real_deadline)
    reserve = min(_REAP_RESERVE_SECONDS, initial_remaining / 4.0)
    io_deadline = deadline - reserve
    io_real_deadline = real_deadline - reserve
    write_wire = request_wire
    write_offset = 0
    write_phase = "request"
    frames: list[object] = []

    while owner.failure is None and not owner.control_eof:
        remaining = _remaining(io_deadline, clock, io_real_deadline)
        if remaining <= 0:
            _set_execution_failure(owner, ExecutionReason.DEADLINE)
            break
        try:
            events, budget_consumed = _select_control(
                owner.selector, remaining,
            )
        except BaseException as exc:
            owner.remember(exc)
            _set_execution_failure(owner, ExecutionReason.CONTROL_FAILED)
            break
        if not events and not budget_consumed:
            continue
        if not events:
            _set_execution_failure(owner, ExecutionReason.DEADLINE)
            break
        for key, mask in events:
            if key.data == "write" and mask & selectors.EVENT_WRITE:
                try:
                    count = os.write(
                        owner.input_fd, write_wire[write_offset:],
                    )
                except BlockingIOError:
                    continue
                except BaseException as exc:
                    owner.remember(exc)
                    _set_execution_failure(
                        owner,
                        ExecutionReason.REQUEST_FAILED
                        if write_phase == "request"
                        else ExecutionReason.COMMAND_FAILED,
                    )
                    break
                if count <= 0:
                    _set_execution_failure(
                        owner,
                        ExecutionReason.REQUEST_FAILED
                        if write_phase == "request"
                        else ExecutionReason.COMMAND_FAILED,
                    )
                    break
                write_offset += count
                if write_offset == len(write_wire):
                    _owner_unregister(owner, "input")
                    if owner.failure is not None:
                        break
                    if write_phase == "command":
                        if not _owner_close_pipe(owner, "input"):
                            _set_execution_failure(
                                owner, ExecutionReason.COMMAND_FAILED,
                            )
                            break
                        owner.input_fd = -1
                        owner.go_command_sent = True
                    write_wire = b""
                    write_offset = 0

            if key.data == "read" and mask & selectors.EVENT_READ:
                try:
                    chunk = os.read(owner.output_fd, _READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                except BaseException as exc:
                    owner.remember(exc)
                    _set_execution_failure(
                        owner, ExecutionReason.CONTROL_FAILED,
                    )
                    break
                if not chunk:
                    owner.control_eof = True
                    _owner_unregister(owner, "output")
                    try:
                        decoder.finish()
                    except runner_ipc.IpcError:
                        owner.observed_trailing_control_bytes = min(
                            decoder.pending_size, _MAX_TRAILING_BYTES,
                        )
                        _set_execution_failure(
                            owner, ExecutionReason.CONTROL_FAILED,
                        )
                    break
                try:
                    wire_frames = decoder.feed(chunk)
                except runner_ipc.IpcError:
                    owner.observed_trailing_control_bytes = min(
                        decoder.pending_size, _MAX_TRAILING_BYTES,
                    )
                    _set_execution_failure(
                        owner, ExecutionReason.CONTROL_FAILED,
                    )
                    break
                for wire_frame in wire_frames:
                    if len(frames) >= 4:
                        owner.observed_trailing_control_bytes = min(
                            owner.observed_trailing_control_bytes
                            + len(wire_frame),
                            _MAX_TRAILING_BYTES,
                        )
                        _set_execution_failure(
                            owner, ExecutionReason.CONTROL_FAILED,
                        )
                        break
                    try:
                        record = decode_control_frame(wire_frame)
                        if len(frames) == 0:
                            if type(record) is not ReadyFrame:
                                raise ProtocolError(
                                    "expected READY", "control",
                                )
                            _authenticate_execution_ready(
                                owner, request, digest, record,
                            )
                        elif len(frames) == 1:
                            if type(record) is not PreparedFrame:
                                raise ProtocolError(
                                    "expected PREPARED", "control",
                                )
                            _authenticate_execution_prepared(
                                owner, request, record,
                            )
                            write_wire = encode_command(WorkerCommand(
                                request_id=request.request_id,
                                request_sha256=digest,
                                worker_pid=owner.worker_pid,
                                command=WorkerCommandKind.GO,
                                prepared_sha256=prepared_digest(record),
                            ))
                            write_offset = 0
                            write_phase = "command"
                            owner.selector.register(
                                owner.input_fd,
                                selectors.EVENT_WRITE,
                                "write",
                            )
                            owner.input_registered = True
                        elif len(frames) == 2:
                            if type(record) is not StartedFrame:
                                raise ProtocolError(
                                    "expected STARTED", "control",
                                )
                            _authenticate_execution_started(
                                owner, request, record,
                            )
                        else:
                            if type(record) is not WorkerSettlement:
                                raise ProtocolError(
                                    "expected SETTLEMENT", "control",
                                )
                            if not owner.go_command_sent or owner.started is None:
                                raise ProtocolError(
                                    "settlement preceded GO", "control",
                                )
                            owner.settlement = record
                    except BaseException as exc:
                        owner.remember(exc)
                        _set_execution_failure(
                            owner,
                            exc.reason
                            if type(exc) is _ExecutionProtocolFailure
                            else ExecutionReason.CONTROL_FAILED,
                        )
                        break
                    frames.append(record)
                if owner.failure is not None:
                    break

    if owner.failure is not None:
        return
    if (not owner.control_eof or owner.ready is None
            or owner.prepared is None or owner.started is None
            or owner.settlement is None or not owner.go_command_sent):
        _set_execution_failure(owner, ExecutionReason.CONTROL_FAILED)
        return
    try:
        validate_control_sequence((
            owner.ready, owner.prepared, owner.started, owner.settlement,
        ))
    except ProtocolError:
        _set_execution_failure(owner, ExecutionReason.CONTROL_FAILED)


def _close_execution_input_file(owner: _ExecutionOwner) -> None:
    if owner.input_file_fd < 0 or owner.input_file_close_attempted:
        return
    owner.input_file_close_attempted = True
    try:
        os.close(owner.input_file_fd)
    except BaseException as exc:
        owner.remember(exc)
        owner.input_file_closed_clean = False
        _set_execution_failure(owner, ExecutionReason.INPUT_FAILED)
    else:
        owner.input_file_closed_clean = True
    finally:
        owner.input_file_fd = -1


def _input_descriptor_proof(
    owner: _ExecutionOwner,
    request: WorkerRequest,
    deadline: float,
    clock,
    real_deadline: float,
) -> DescriptorProof | None:
    if request.stdin_mode is not StdinMode.FILE:
        return None
    claim = request.claim_for(StreamRole.STDIN)
    if claim is None or owner.input_file_fd < 0:
        raise ProtocolError("missing input descriptor", "stdin")
    digest = hashlib.sha256()
    size = 0
    offset = 0
    while True:
        if _remaining(deadline, clock, real_deadline) <= 0:
            raise TimeoutError("input authentication deadline")
        chunk = os.pread(owner.input_file_fd, _READ_CHUNK_BYTES, offset)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
        offset += len(chunk)
        if size > _MAX_SAFE_DEADLINE:
            raise ProtocolError("input exceeds proof limit", "stdin")
    return DescriptorProof(
        role=StreamRole.STDIN,
        claim_id=claim.claim_id,
        size=size,
        sha256=digest.hexdigest(),
        lines=None,
    )


def _execution_descriptor_proofs(
    request: WorkerRequest,
    input_proof: DescriptorProof | None,
    artifact_proofs: tuple[PrivateStageArtifactProof, ...],
) -> tuple[DescriptorProof, ...]:
    by_role: dict[StreamRole, DescriptorProof] = {}
    if input_proof is not None:
        by_role[StreamRole.STDIN] = input_proof
    for artifact in artifact_proofs:
        role = StreamRole(artifact.role)
        by_role[role] = DescriptorProof(
            role=role,
            claim_id=artifact.claim_id,
            size=artifact.size,
            sha256=artifact.sha256,
            lines=artifact.lines,
        )
    return tuple(
        by_role[claim.role]
        for claim in request.descriptor_claims
        if claim.role in by_role
    )


def _fence_execution_stages(owner: _ExecutionOwner) -> None:
    batch = owner.stage_batch
    if batch is None or batch.state in {"fenced", "aborted", "committed"}:
        return
    try:
        if batch.state == "prepared":
            abort_unspawned_private_stage_handoff(batch)
        else:
            fence_private_stage_handoff(batch)
    except BaseException as exc:
        owner.remember(exc)
        _set_execution_failure(owner, ExecutionReason.STAGE_FAILED)


def _settle_execution_authorities(
    owner: _ExecutionOwner,
    request: WorkerRequest,
    output_claims: tuple[tuple[StreamRole, str], ...],
    deadline: float,
    clock,
    real_deadline: float,
) -> None:
    """Close, reap, settle containment, then authenticate or fence stages."""
    _adopt_child_authority(owner)
    _owner_close_selector(owner)
    input_clean = _owner_close_pipe(owner, "input")
    output_clean = _owner_close_pipe(owner, "output")
    if not input_clean or not output_clean:
        _set_execution_failure(owner, ExecutionReason.CONTROL_FAILED)

    if owner.worker_spawned:
        if owner.failure is None:
            try:
                graceful_deadline, graceful_real_deadline = (
                    _graceful_reap_deadlines(deadline, clock, real_deadline)
                )
                _wait_child(
                    owner, graceful_deadline, clock, graceful_real_deadline,
                )
            except BaseException as exc:
                owner.remember(exc)
                _set_execution_failure(owner, ExecutionReason.DEADLINE)
        if owner.failure is not None and not owner.worker_reaped:
            _request_kill_bounded(owner, real_deadline)
        if not owner.worker_reaped:
            # A nominal transcript whose worker did not exit in its reserved reap
            # window is no longer nominal and receives the same exact-child fence.
            _set_execution_failure(owner, ExecutionReason.REAP_FAILED)
            _request_kill_bounded(owner, real_deadline)
        if not owner.worker_reaped:
            _final_reap_bounded(owner, real_deadline)

    _settle_owned_containment(owner, real_deadline)
    containment_settled = (
        type(owner.containment_settlement) is ContainmentSettlement
        and owner.containment_settlement.cooperative_settled
        and owner.containment_terminal
    )
    if owner.worker_spawned and not owner.worker_reaped:
        owner.failure = ExecutionReason.REAP_FAILED
        owner.worker_returncode = None
    elif owner.worker_reaped and owner.worker_returncode != 0:
        _set_execution_failure(owner, ExecutionReason.WORKER_FAILED)
    if owner.containment is not None and not containment_settled:
        owner.failure = ExecutionReason.CONTAINMENT_FAILED

    input_proof = None
    if owner.failure is None:
        try:
            input_proof = _input_descriptor_proof(
                owner, request, deadline, clock, real_deadline,
            )
        except BaseException as exc:
            owner.remember(exc)
            _set_execution_failure(
                owner,
                ExecutionReason.DEADLINE
                if isinstance(exc, TimeoutError)
                else ExecutionReason.INPUT_FAILED,
            )
    _close_execution_input_file(owner)

    if owner.stage_batch is not None and owner.failure is None:
        try:
            owner.artifact_proofs = settle_private_stage_handoff(
                owner.stage_batch,
                owner.stage_receipt,
                worker_reaped=owner.worker_reaped,
                claims=tuple(
                    (claim_id, role.value)
                    for role, claim_id in output_claims
                ),
            )
            owner.stages_settled = True
        except BaseException as exc:
            owner.remember(exc)
            _set_execution_failure(owner, ExecutionReason.STAGE_FAILED)
    elif owner.stage_batch is None:
        owner.stages_settled = True

    if owner.failure is None:
        try:
            descriptor_proofs = _execution_descriptor_proofs(
                request, input_proof, owner.artifact_proofs,
            )
            containment = owner.containment
            owner.validated = validate_parent_settlement(
                ParentSettlementContext(
                    request=request,
                    ready=owner.ready,
                    prepared=owner.prepared,
                    started=owner.started,
                    settlement=owner.settlement,
                    descriptor_proofs=descriptor_proofs,
                    expected_worker_pid=owner.worker_pid,
                    expected_launcher_pid=owner.prepared.launcher_pid,
                    expected_launcher_pgid=owner.prepared.launcher_pgid,
                    expected_containment_kind=containment.kind,
                    expected_containment_id=containment.containment_id,
                    containment_assurance=containment.containment_assurance,
                    worker_returncode=owner.worker_returncode,
                    worker_reaped=owner.worker_reaped,
                    control_eof=owner.control_eof,
                    trailing_control_bytes=owner.observed_trailing_control_bytes,
                    prepared_identity_verified=owner.prepared_identity_verified,
                    tool_identity_verified=owner.tool_identity_verified,
                    containment_verified=owner.containment_verified,
                    containment_bound=owner.containment_bound,
                    containment_empty=owner.containment_settlement.empty,
                    stages_closed=(
                        owner.stages_settled
                        and owner.input_file_closed_clean
                    ),
                )
            )
            owner.failure = (
                ExecutionReason.COMPLETE
                if owner.validated.capture_complete
                else ExecutionReason.INCOMPLETE
            )
        except BaseException as exc:
            owner.remember(exc)
            _set_execution_failure(owner, ExecutionReason.CONTROL_FAILED)

    # A protocol-valid non-clean settlement (timeout, cap, source/sink fault)
    # still owns useful, stable partial bytes.  Preserve its settled proof tuple
    # for the later partial-evidence transaction.  Authentication/authority
    # failures never retain that authority and are fenced here.
    if owner.failure not in {
            ExecutionReason.COMPLETE, ExecutionReason.INCOMPLETE,
    }:
        _fence_execution_stages(owner)


def supervise_execution(
    invocation,
    *,
    stage_batch=None,
    deadline,
    clock=time.monotonic,
    popen_factory=subprocess.Popen,
) -> ExecutionOutcome:
    """Run one authenticated worker transaction without publishing its stages.

    The parent acquires containment before spawn, passes only private descriptors
    to the fixed worker command line, authenticates and binds its parked launcher,
    transfers its writer ownership, and only then releases the request-bound GO.
    Stable artifact proofs are produced after the worker is reaped and containment
    is empty.  Publication remains a separate repository transaction.
    """
    if type(invocation) is not NormalizedInvocation:
        raise ProtocolError("invalid normalized invocation", "invocation")
    if stage_batch is not None and type(stage_batch) is not PrivateStageHandoffBatch:
        raise TypeError("stage_batch must be a private stage handoff or None")
    if not callable(clock) or not callable(popen_factory):
        raise TypeError("execution dependencies must be callable")
    request = invocation.worker
    output_claims = _execution_output_claims(request)
    if (stage_batch is None) != (len(output_claims) == 0):
        raise ProtocolError("output stage claims mismatch", "stage_batch")

    deadline, now = _validate_deadline(deadline, clock)
    real_now = _REAL_MONOTONIC()
    real_deadline = real_now + (deadline - now)
    if not math.isfinite(real_deadline):
        raise ValueError("deadline must be a finite absolute monotonic instant")
    owner = _ExecutionOwner(stage_batch=stage_batch)
    if sys.platform != "linux":
        return _execution_outcome(
            invocation, owner, reason=ExecutionReason.UNSUPPORTED,
        )
    if now >= deadline:
        return _execution_outcome(
            invocation, owner, reason=ExecutionReason.DEADLINE,
        )
    try:
        sigchld_handler = signal.getsignal(signal.SIGCHLD)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return _execution_outcome(
            invocation, owner, reason=ExecutionReason.UNSUPPORTED,
        )
    if sigchld_handler is not signal.SIG_DFL:
        return _execution_outcome(
            invocation, owner, reason=ExecutionReason.UNSUPPORTED,
        )

    try:
        decoder = runner_ipc.IncrementalFrameDecoder(MAX_FRAME_BYTES)
        request_wire = encode_request(request)
        if request.stdin_mode is StdinMode.DATA:
            request_wire += invocation.stdin_data
        digest = request_digest(request)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return _execution_outcome(
            invocation, owner, reason=ExecutionReason.REQUEST_FAILED,
        )

    try:
        if request.stdin_mode is StdinMode.FILE:
            owner.input_file_closed_clean = False
            try:
                owner.input_file_fd = open_ro_private(invocation.input_file)
            except BaseException as exc:
                owner.remember(exc)
                _set_execution_failure(owner, ExecutionReason.INPUT_FAILED)
        try:
            if owner.failure is None:
                owner.containment = acquire_direct_cgroup_v2(request.request_id)
                owner.containment_verified = (
                    owner.containment.kind.value == "cgroup_v2"
                    and owner.containment.containment_id
                    == f"direct/quarry-{request.request_id}"
                )
                if not owner.containment_verified:
                    raise RuntimeError("unexpected containment identity")
        except (ContainmentUnsupported, ContainmentRefused):
            _set_execution_failure(owner, ExecutionReason.UNSUPPORTED)
        except BaseException as exc:
            owner.remember(exc)
            _set_execution_failure(owner, ExecutionReason.CONTAINMENT_FAILED)
        if owner.failure is None and _remaining(
                deadline, clock, real_deadline,
        ) <= 0:
            _set_execution_failure(owner, ExecutionReason.DEADLINE)
        if owner.failure is None:
            try:
                owner.selector = selectors.DefaultSelector()
            except BaseException as exc:
                owner.remember(exc)
                _set_execution_failure(owner, ExecutionReason.CONTROL_FAILED)
        if owner.failure is None and owner.stage_batch is not None:
            try:
                owner.stage_authority = _prepare_private_stage_transfer_authority(
                    owner.stage_batch, request_id=request.request_id,
                )
            except BaseException as exc:
                owner.remember(exc)
                _set_execution_failure(owner, ExecutionReason.STAGE_FAILED)
        if owner.failure is None:
            try:
                if owner.stage_batch is None:
                    _spawn_execution_child(
                        owner, (), output_claims, popen_factory,
                    )
                else:
                    owner.child, owner.stage_authority = (
                        _spawn_with_private_stage_handoff(
                            owner.stage_batch,
                            owner.stage_authority,
                            lambda writer_fds: _spawn_execution_child(
                                owner, writer_fds, output_claims,
                                popen_factory,
                            ),
                        )
                    )
                _adopt_child_authority(owner)
                if (not owner.worker_spawned or owner.input_pipe is None
                        or owner.output_pipe is None):
                    _set_execution_failure(
                        owner, ExecutionReason.SPAWN_FAILED,
                    )
                else:
                    identity = capture_process_identity(owner.worker_pid)
                    if identity.pid != owner.worker_pid:
                        raise RuntimeError("worker identity mismatch")
                    owner.worker_start_time_ticks = identity.start_time_ticks
                    owner.worker_identity = identity
            except BaseException as exc:
                owner.remember(exc)
                _adopt_child_authority(owner)
                _set_execution_failure(
                    owner,
                    ExecutionReason.IDENTITY_FAILED
                    if owner.worker_spawned
                    else ExecutionReason.SPAWN_FAILED,
                )
        if owner.failure is None:
            _drive_execution_protocol(
                owner, request, request_wire, digest, decoder,
                deadline, clock, real_deadline,
            )
    except BaseException as exc:
        owner.remember(exc)
        _adopt_child_authority(owner)
        _set_execution_failure(
            owner,
            ExecutionReason.CONTROL_FAILED
            if owner.worker_spawned
            else ExecutionReason.SPAWN_FAILED,
        )
    finally:
        try:
            _settle_execution_authorities(
                owner, request, output_claims,
                deadline, clock, real_deadline,
            )
        except BaseException as exc:
            owner.remember(exc)
            _set_execution_failure(owner, ExecutionReason.CONTROL_FAILED)
            try:
                _settle_execution_authorities(
                    owner, request, output_claims,
                    deadline, clock, real_deadline,
                )
            except BaseException as retry_exc:
                owner.remember(retry_exc)
                if owner.worker_spawned and not owner.worker_reaped:
                    owner.failure = ExecutionReason.REAP_FAILED
                _close_execution_input_file(owner)
                _fence_execution_stages(owner)

    if owner.pending_cancellation is not None:
        raise owner.pending_cancellation
    return _execution_outcome(invocation, owner)
