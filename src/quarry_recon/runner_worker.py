"""Fixed non-launching bootstrap for Quarry's future execution worker.

The module is intentionally executable only through ``python -m`` with a private
request/command channel on stdin and a worker-control channel on stdout.  This
first slice never launches a tool, receives stage descriptors, touches
containment, or authorizes publication.  Its only successful transaction is a
request-bound parent abort.
"""
from __future__ import annotations

import ctypes
import os
import signal
import sys

from . import runner_ipc
from .runner_protocol import (
    MAX_FRAME_BYTES,
    ExecutionTerminal,
    ReadyFrame,
    StreamRole,
    StreamSettlement,
    StreamTerminal,
    WorkerCommandKind,
    WorkerSettlement,
    decode_command,
    decode_request,
    encode_ready,
    encode_settlement,
    request_digest,
)


EXPECTED_PARENT_PID_ENV = "QUARRY_RUNNER_EXPECTED_PARENT_PID"
_PR_SET_PDEATHSIG = 1
_EXIT_BOOTSTRAP_INVALID = 64
_EXIT_CONTROL_FAILED = 65


def _expected_parent_pid() -> int:
    raw = os.environ.get(EXPECTED_PARENT_PID_ENV)
    if raw is None or not raw.isascii() or not raw.isdecimal():
        raise RuntimeError("worker_parent_invalid")
    value = int(raw)
    if not 1 <= value <= (1 << 31) - 1:
        raise RuntimeError("worker_parent_invalid")
    return value


def _arm_parent_death(expected_parent_pid: int) -> None:
    """Arm Linux parent-death SIGKILL and close the install race."""
    if sys.platform != "linux":
        raise RuntimeError("worker_platform_unsupported")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = getattr(libc, "prctl", None)
    if prctl is None:
        raise RuntimeError("worker_pdeathsig_unavailable")
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise RuntimeError("worker_pdeathsig_failed")
    if os.getppid() != expected_parent_pid:
        raise RuntimeError("worker_parent_changed")


def _not_started_streams() -> tuple[StreamSettlement, ...]:
    return tuple(
        StreamSettlement(
            role=role,
            terminal=StreamTerminal.NOT_STARTED,
            observed_bytes=0,
            retained_bytes=0,
            observed_sha256=None,
            retained_sha256=None,
            claim_id=None,
            lines=0,
            detail=None,
        )
        for role in StreamRole
    )


def _negative_settlement(
    *, request_id: str, worker_pid: int, terminal: ExecutionTerminal, detail: str,
) -> WorkerSettlement:
    return WorkerSettlement(
        request_id=request_id,
        terminal=terminal,
        launched=False,
        exit_code=None,
        process_group_settled=False,
        process_tree_settled=False,
        streams=_not_started_streams(),
        worker_pid=worker_pid,
        tool_pid=None,
        detail=detail,
    )


def _write_settlement(control_fd: int, settlement: WorkerSettlement) -> None:
    runner_ipc.write_all(control_fd, encode_settlement(settlement))


def _run_worker(request_fd: int, control_fd: int, expected_parent_pid: int) -> int:
    """Run one bootstrap transaction over already-open blocking descriptors."""
    _arm_parent_death(expected_parent_pid)
    worker_pid = os.getpid()
    try:
        request = decode_request(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
    except BaseException:
        return _EXIT_BOOTSTRAP_INVALID

    digest = request_digest(request)
    try:
        runner_ipc.write_all(control_fd, encode_ready(ReadyFrame(
            request_id=request.request_id,
            worker_pid=worker_pid,
            request_sha256=digest,
        )))
    except BaseException:
        return _EXIT_CONTROL_FAILED

    try:
        command = decode_command(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
        runner_ipc.require_eof(request_fd)
    except BaseException:
        try:
            _write_settlement(control_fd, _negative_settlement(
                request_id=request.request_id,
                worker_pid=worker_pid,
                terminal=ExecutionTerminal.WORKER_FAILED,
                detail="command_invalid",
            ))
        except BaseException:
            return _EXIT_CONTROL_FAILED
        return _EXIT_CONTROL_FAILED

    correlation_ok = (
        command.request_id == request.request_id
        and command.request_sha256 == digest
        and command.worker_pid == worker_pid
    )
    if not correlation_ok:
        settlement = _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=ExecutionTerminal.WORKER_FAILED,
            detail="command_mismatch",
        )
    elif command.command is WorkerCommandKind.GO:
        settlement = _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=ExecutionTerminal.WORKER_FAILED,
            detail="go_before_prepared",
        )
    else:
        settlement = _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=ExecutionTerminal.CANCELLED,
            detail="parent_abort",
        )
    try:
        _write_settlement(control_fd, settlement)
    except BaseException:
        return _EXIT_CONTROL_FAILED
    return 0


def main() -> int:
    """Process entry point; never render private failures to stderr."""
    try:
        expected_parent_pid = _expected_parent_pid()
        # The bootstrap environment contains only fixed numeric metadata.  Remove
        # even that value before accepting the target-effective request over IPC.
        os.environ.clear()
        return _run_worker(0, 1, expected_parent_pid)
    except BaseException:
        return _EXIT_BOOTSTRAP_INVALID
    finally:
        try:
            os.close(1)
        except OSError:
            pass


if __name__ == "__main__":  # pragma: no cover - exercised by integration tests
    raise SystemExit(main())
