"""Parent-owned bootstrap supervisor for Quarry's killable worker boundary.

This preparatory supervisor proves only the fixed worker transport.  It always
issues a request-bound pre-launch abort and therefore never launches a tool,
transfers a stage, claims containment, or authorizes publication.
"""
from __future__ import annotations

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
from .runner_containment import capture_process_identity
from .runner_protocol import (
    MAX_FRAME_BYTES,
    ControlTranscript,
    ExecutionTerminal,
    ProtocolError,
    ReadyFrame,
    StreamTerminal,
    WorkerCommand,
    WorkerCommandKind,
    WorkerRequest,
    WorkerSettlement,
    decode_control_frame,
    encode_command,
    encode_request,
    request_digest,
    validate_control_sequence,
)
from .runner_worker import EXPECTED_PARENT_PID_ENV


_BOOTSTRAP_OUTCOME_AUTHORITY = object()
_REAL_MONOTONIC = time.monotonic
_READ_CHUNK_BYTES = 64 * 1024
_REAP_RESERVE_SECONDS = 0.10
_REAL_CLOCK_SAMPLE_ATTEMPTS = 2
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
                    or kill_requested):
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
                    or settlement.process_group_settled
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
    child: object | None = None
    worker_spawned: bool = False
    worker_pid: int | None = None
    worker_start_time_ticks: int | None = None
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
        returncode = owner.child.wait(timeout=remaining)
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
            returncode = owner.child.wait(timeout=remaining)
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


def _settle_owned_child(
    owner: _BootstrapOwner, deadline: float, clock, real_deadline: float,
) -> None:
    """Close parent channels and settle the exact child from durable facts."""
    _adopt_child_authority(owner)
    _owner_close_selector(owner)
    input_clean = _owner_close_pipe(owner, "input")
    output_clean = _owner_close_pipe(owner, "output")
    parent_pipes_closed = input_clean and output_clean
    if not parent_pipes_closed and owner.failure is None:
        owner.failure = BootstrapReason.CONTROL_FAILED

    if not owner.worker_spawned:
        return

    if owner.failure is None:
        try:
            graceful_deadline, graceful_real_deadline = _graceful_reap_deadlines(
                deadline, clock, real_deadline,
            )
        except BaseException as exc:
            owner.remember(exc)
            owner.failure = BootstrapReason.DEADLINE
        else:
            _wait_child(owner, graceful_deadline, clock, graceful_real_deadline)

    if not owner.worker_reaped and not owner.child_status_fault:
        _request_kill_bounded(owner, real_deadline)
    if not owner.worker_reaped and not owner.child_status_fault:
        _final_reap_bounded(owner, real_deadline)

    if not owner.worker_reaped:
        owner.failure = BootstrapReason.REAP_FAILED
        owner.worker_returncode = None
    elif owner.failure is None and (
            owner.worker_returncode != 0 or owner.kill_requested
            or owner.forced_termination_fault):
        owner.failure = BootstrapReason.WORKER_FAILED
    if owner.failure is None:
        owner.failure = BootstrapReason.ABORTED


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
    """Drive REQUEST -> READY -> ABORT -> CANCELLED over owned channels."""
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
            events = selector.select(remaining)
        except BaseException as exc:
            owner.remember(exc)
            owner.failure = BootstrapReason.CONTROL_FAILED
            break
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
                    if len(frames) >= 2:
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
                        write_wire = encode_command(WorkerCommand(
                            request_id=request.request_id,
                            request_sha256=digest,
                            worker_pid=owner.worker_pid,
                            command=WorkerCommandKind.ABORT,
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
    if (not owner.control_eof or owner.ready is None
            or owner.settlement is None or not owner.abort_command_sent):
        owner.failure = BootstrapReason.CONTROL_FAILED
        return
    try:
        transcript: ControlTranscript = validate_control_sequence(
            (owner.ready, owner.settlement),
        )
    except ProtocolError:
        owner.failure = BootstrapReason.CONTROL_FAILED
        return
    settled = transcript.settlement
    if (settled.request_id != request.request_id
            or settled.worker_pid != owner.worker_pid
            or settled.terminal is not ExecutionTerminal.CANCELLED
            or settled.launched or settled.process_group_settled
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
    """Prove the fixed worker transport by completing a pre-launch abort.

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
    bootstrap_env = {EXPECTED_PARENT_PID_ENV: str(os.getpid())}
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
        owner.selector = selectors.DefaultSelector()
        if _remaining(deadline, clock, real_deadline) <= 0:
            owner.failure = BootstrapReason.DEADLINE
        else:
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
    )
