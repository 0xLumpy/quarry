"""Fixed bootstrap and parked pre-exec launcher owner.

The module is intentionally executable only through ``python -m`` with a private
request/command channel on stdin and a worker-control channel on stdout.  The
legacy path creates no child.  The additive parked path forks a fixed launcher
before decoding target material, proves it stopped as a session/group leader, and
accepts only a PREPARED-digest-bound abort.  This slice never releases or executes
the target.
"""
from __future__ import annotations

import ctypes
import os
import signal
import sys

from . import runner_ipc
from .runner_protocol import (
    MAX_FRAME_BYTES,
    MAX_PID,
    ContainmentKind,
    ExecutionTerminal,
    PreparedFrame,
    ReadyFrame,
    StdinMode,
    StreamRole,
    StreamSettlement,
    StreamTerminal,
    WorkerCommandKind,
    WorkerSettlement,
    decode_command,
    decode_request,
    encode_prepared,
    encode_ready,
    encode_settlement,
    prepared_digest,
    request_digest,
)
from .runner_containment import (
    capture_parked_process_identity,
    capture_process_identity,
)


EXPECTED_PARENT_PID_ENV = "QUARRY_RUNNER_EXPECTED_PARENT_PID"
PREPARED_ABORT_ENV = "QUARRY_RUNNER_PREPARED_ABORT"
STDOUT_FD_ENV = "QUARRY_RUNNER_STDOUT_FD"
STDERR_FD_ENV = "QUARRY_RUNNER_STDERR_FD"
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


def _metadata_failure() -> RuntimeError:
    return RuntimeError("worker_metadata_invalid")


def _parse_output_fd(raw: str | None) -> int | None:
    if raw is None:
        return None
    if (type(raw) is not str or not raw or not raw.isascii()
            or not raw.isdecimal() or (len(raw) > 1 and raw[0] == "0")):
        raise _metadata_failure()
    value = int(raw)
    if not 3 <= value <= MAX_PID:
        raise _metadata_failure()
    return value


def _pop_output_fd_metadata() -> tuple[int | None, int | None]:
    """Remove both private keys even when either value is malformed."""
    stdout_raw = os.environ.pop(STDOUT_FD_ENV, None)
    stderr_raw = os.environ.pop(STDERR_FD_ENV, None)
    return _parse_output_fd(stdout_raw), _parse_output_fd(stderr_raw)


def _pop_prepared_abort_mode() -> bool:
    raw = os.environ.pop(PREPARED_ABORT_ENV, None)
    if raw is None:
        return False
    if raw != "1":
        raise _metadata_failure()
    return True


def _validate_output_fds(
    request,
    stdout_fd: int | None,
    stderr_fd: int | None,
    *,
    request_fd: int,
    control_fd: int,
) -> tuple[int | None, int | None]:
    expected_stdout = request.claim_for(StreamRole.STDOUT) is not None
    expected_stderr = request.claim_for(StreamRole.STDERR) is not None
    if (request.stdin_mode is StdinMode.FILE
            or expected_stdout != (stdout_fd is not None)
            or expected_stderr != (stderr_fd is not None)):
        raise _metadata_failure()
    values = tuple(fd for fd in (stdout_fd, stderr_fd) if fd is not None)
    if (any(type(fd) is not int or not 3 <= fd <= MAX_PID for fd in values)
            or len(values) != len(set(values))
            or any(fd in (request_fd, control_fd, 0, 1, 2) for fd in values)):
        raise _metadata_failure()
    return stdout_fd, stderr_fd


def _fd_identity(fd: int) -> tuple[int, int]:
    observed = os.fstat(fd)
    return observed.st_dev, observed.st_ino


def _validate_spawn_fds(
    stdout_fd: int | None,
    stderr_fd: int | None,
    inherited_fds: tuple[int, ...],
) -> None:
    """Authenticate all numeric inputs before pipe allocation can reuse a hole."""
    if (type(inherited_fds) is not tuple or len(inherited_fds) != 2
            or any(type(fd) is not int or fd < 0 for fd in inherited_fds)):
        raise RuntimeError("launcher_metadata_invalid")
    outputs = tuple(fd for fd in (stdout_fd, stderr_fd) if fd is not None)
    values = outputs + inherited_fds
    if (any(type(fd) is not int or fd < 0 for fd in outputs)
            or len(values) != len(set(values))):
        raise RuntimeError("launcher_metadata_invalid")
    try:
        identities = tuple(_fd_identity(fd) for fd in values)
    except OSError:
        raise RuntimeError("launcher_metadata_invalid") from None
    if len(identities) != len(set(identities)):
        raise RuntimeError("launcher_metadata_invalid")


def _consume_output_fd_metadata(
    request,
    *,
    request_fd: int,
    control_fd: int,
) -> tuple[int | None, int | None]:
    """Consume numeric environment metadata and bind it to request claims."""
    stdout_fd, stderr_fd = _pop_output_fd_metadata()
    return _validate_output_fds(
        request, stdout_fd, stderr_fd,
        request_fd=request_fd, control_fd=control_fd,
    )


def _close_quietly(fd: int) -> None:
    if type(fd) is not int or fd < 0:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _close_child_fds_except(keep: set[int]) -> None:
    """Close the fork snapshot, including aliases unknown to the worker owner."""
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        # Linux procfs is part of this launcher's identity-proof prerequisite.  A
        # missing view is a setup failure rather than permission to retain ambient
        # descriptors.
        raise RuntimeError("launcher_proc_unavailable") from None
    for name in names:
        if not name.isascii() or not name.isdecimal():
            continue
        fd = int(name)
        if fd not in keep:
            _close_quietly(fd)


def _launcher_child(
    *,
    worker_pid: int,
    release_read: int,
    release_write: int,
    stdout_fd: int | None,
    stderr_fd: int | None,
    inherited_fds: tuple[int, ...],
) -> None:
    """Become a release-gated child without ever decoding or executing a target."""
    try:
        _close_quietly(release_write)
        _arm_parent_death(worker_pid)
        os.setsid()
        if os.getpid() != os.getpgrp() or os.getpid() != os.getsid(0):
            raise RuntimeError("launcher_identity_invalid")

        if stdout_fd is None:
            _close_quietly(1)
        elif stdout_fd != 1:
            os.dup2(stdout_fd, 1, inheritable=False)
        if stderr_fd is None:
            _close_quietly(2)
        elif stderr_fd != 2:
            os.dup2(stderr_fd, 2, inheritable=False)

        keep = {
            release_read,
            1 if stdout_fd is not None else -1,
            2 if stderr_fd is not None else -1,
        }
        _close_child_fds_except(keep)

        os.kill(os.getpid(), signal.SIGSTOP)
        # SIGCONT is merely scheduling.  No release token is ever written in this
        # slice; EOF or a stray byte both terminate without exec.
        while True:
            try:
                os.read(release_read, 1)
                break
            except InterruptedError:
                continue
        _close_quietly(release_read)
    except BaseException:
        pass
    os._exit(0)


class _ParkedLauncher:
    """Exclusive status/release authority for one exact forked child."""

    def __init__(self, pid: int, release_write: int) -> None:
        self.pid = pid
        self.pgid = pid
        self.start_time_ticks: int | None = None
        self.returncode: int | None = None
        self._release_write = release_write
        self._release_close_attempted = False
        self._reaped = False
        self._stop_wait_state = "not_started"
        self._stop_wait_result: tuple[int, int] | None = None
        self._wait_state = "not_started"
        self._wait_result: tuple[int, int] | None = None

    def close_inherited_before_stop(self) -> None:
        """Compatibility seam; real child setup closes inherited descriptors."""

    def prove_stopped(self) -> bool:
        if self._reaped:
            return False
        if self._stop_wait_state == "complete":
            if self._stop_wait_result is None:
                raise RuntimeError("launcher_wait_invalid")
            waited_pid, status = self._stop_wait_result
            return self._finish_stop_observation(waited_pid, status)
        if self._stop_wait_state == "ambiguous":
            # The prior wait may have consumed the stop notification.  A fresh
            # parent/start/session/group/stopped proof is stronger than replaying
            # that notification and cannot reap the child.
            try:
                worker = capture_process_identity(os.getpid())
                proof = capture_parked_process_identity(self.pid, worker)
            except Exception:
                self._stop_wait_state = "not_started"
            else:
                self.start_time_ticks = proof.process.start_time_ticks
                self._stop_wait_state = "proved_after_ambiguity"
                return True
        while True:
            try:
                self._stop_wait_state = "attempting"; self._stop_wait_result = os.waitpid(self.pid, os.WUNTRACED); self._stop_wait_state = "complete"
                break
            except InterruptedError:
                self._stop_wait_state = "not_started"
                continue
            except BaseException:
                self._stop_wait_state = "ambiguous"
                raise
        if self._stop_wait_result is None:
            raise RuntimeError("launcher_wait_invalid")
        waited_pid, status = self._stop_wait_result
        return self._finish_stop_observation(waited_pid, status)

    def _finish_stop_observation(self, waited_pid: int, status: int) -> bool:
        if waited_pid != self.pid:
            raise RuntimeError("launcher_wait_invalid")
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            self.returncode = os.waitstatus_to_exitcode(status)
            self._reaped = True
            self._wait_state = "terminal"
            return False
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            return False
        worker = capture_process_identity(os.getpid())
        proof = capture_parked_process_identity(self.pid, worker)
        if (proof.process.pid != self.pid or proof.parent.pid != os.getpid()
                or proof.state not in ("T", "t")):
            raise RuntimeError("launcher_identity_invalid")
        self.start_time_ticks = proof.process.start_time_ticks
        return True

    def _finish_wait_result(self, waited_pid: int, status: int) -> int:
        if waited_pid != self.pid:
            raise RuntimeError("launcher_wait_invalid")
        self.returncode = os.waitstatus_to_exitcode(status)
        self._reaped = True
        self._wait_state = "terminal"
        return self.returncode

    def _reconcile_ambiguous_wait(self) -> int | None:
        try:
            waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            # This object is the exclusive reaper for the direct child.  ECHILD
            # after an ambiguous wait means that invocation consumed the status.
            self._reaped = True
            self._wait_state = "terminal"
            return self.returncode
        if waited_pid == 0:
            self._wait_state = "not_started"
            return None
        return self._finish_wait_result(waited_pid, status)

    def abort_and_reap(self) -> int:
        if self._reaped:
            return 0 if self.returncode is None else self.returncode
        if self._wait_state == "complete":
            if self._wait_result is None:
                raise RuntimeError("launcher_wait_invalid")
            return self._finish_wait_result(*self._wait_result)
        if self._wait_state == "ambiguous":
            reconciled = self._reconcile_ambiguous_wait()
            if self._reaped:
                return 0 if reconciled is None else reconciled
        if self._stop_wait_state == "complete":
            if self._stop_wait_result is None:
                raise RuntimeError("launcher_wait_invalid")
            waited_pid, status = self._stop_wait_result
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                return self._finish_wait_result(waited_pid, status)

        if self._stop_wait_state == "ambiguous":
            # A failed stop wait may have reaped an early-exiting child.  Reconcile
            # child status before any numeric signal can target a reused identity.
            reconciled = self._reconcile_ambiguous_wait()
            if self._reaped:
                return 0 if reconciled is None else reconciled

        if self._release_write >= 0 and not self._release_close_attempted:
            release_write = self._release_write
            try:
                os.close(release_write)
            except OSError:
                self._release_close_attempted = True
                self._release_write = -1
            except BaseException:
                # The raw close may or may not have completed.  Never retry a
                # numeric FD that could now be reused; process exit closes any
                # surviving private writer after child reconciliation.
                self._release_close_attempted = True
                self._release_write = -1
                raise
            else:
                self._release_close_attempted = True
                self._release_write = -1
        # Retrying SIGKILL before wait is safe: the exact direct child remains
        # unreaped, so its PID/PGID cannot have been reused.
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except ProcessLookupError:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while True:
            try:
                self._wait_state = "attempting"; self._wait_result = os.waitpid(self.pid, 0); self._wait_state = "complete"
                break
            except InterruptedError:
                self._wait_state = "not_started"
                continue
            except BaseException:
                self._wait_state = "ambiguous"
                raise
        if self._wait_result is None:
            raise RuntimeError("launcher_wait_invalid")
        return self._finish_wait_result(*self._wait_result)


class _PreparedAbortOwner:
    """Stable cleanup root spanning allocation, fork and transaction return."""

    def __init__(self) -> None:
        self.release_read = -1
        self.release_write = -1
        self.pid = -1
        self.launcher = None


class _PreparedAbortFence:
    """One active cleanup layer over a shared launcher authority.

    Two layers are installed before the fork.  If the sole cooperative
    cancellation lands in the inner layer's handler or settlement call, the
    outer layer observes the same durable PID/launcher facts and finishes the
    reap before preserving that cancellation.
    """

    def __init__(self, owner: _PreparedAbortOwner) -> None:
        self._owner = owner

    def __enter__(self) -> _PreparedAbortFence:
        return self

    def __exit__(self, _kind, primary, _traceback) -> bool:
        owner = self._owner
        if owner.launcher is None and owner.pid > 0:
            owner.launcher = _ParkedLauncher(owner.pid, owner.release_write)
        launcher = owner.launcher
        if launcher is not None and not _launcher_terminal(launcher):
            try:
                _settle_launcher(launcher)
            except BaseException as cleanup:
                if primary is not None and not isinstance(primary, Exception):
                    raise primary
                raise cleanup
        if primary is not None and not isinstance(primary, Exception):
            raise primary
        return False


def _spawn_parked_launcher(
    *,
    stdout_fd: int | None,
    stderr_fd: int | None,
    inherited_fds: tuple[int, ...],
    _owner: _PreparedAbortOwner | None = None,
) -> _ParkedLauncher:
    """Fork a metadata-only launcher before target request decoding."""
    _validate_spawn_fds(stdout_fd, stderr_fd, inherited_fds)
    owner = _PreparedAbortOwner() if _owner is None else _owner
    if (type(owner) is not _PreparedAbortOwner or owner.pid != -1
            or owner.release_read != -1 or owner.release_write != -1
            or owner.launcher is not None):
        raise RuntimeError("launcher_owner_invalid")
    try:
        owner.release_read, owner.release_write = os.pipe()
        worker_pid = os.getpid()
        owner.pid = os.fork()
        if owner.pid == 0:  # pragma: no cover - covered by Linux integration tests
            _launcher_child(
                worker_pid=worker_pid,
                release_read=owner.release_read,
                release_write=owner.release_write,
                stdout_fd=stdout_fd,
                stderr_fd=stderr_fd,
                inherited_fds=inherited_fds,
            )
        owner.launcher = _ParkedLauncher(owner.pid, owner.release_write)
        _close_quietly(owner.release_read)
        owner.release_read = -1
        for fd in {fd for fd in (stdout_fd, stderr_fd) if fd is not None}:
            _close_quietly(fd)
        return owner.launcher
    except BaseException as primary:
        if owner.pid == 0:
            os._exit(_EXIT_BOOTSTRAP_INVALID)
        _close_quietly(owner.release_read)
        owner.release_read = -1
        if owner.pid > 0:
            if owner.launcher is None:
                owner.launcher = _ParkedLauncher(
                    owner.pid, owner.release_write,
                )
            _settle_launcher(owner.launcher)
        else:
            _close_quietly(owner.release_write)
            owner.release_write = -1
        for fd in {fd for fd in (stdout_fd, stderr_fd) if fd is not None}:
            _close_quietly(fd)
        raise primary


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
    process_group_settled: bool = False,
) -> WorkerSettlement:
    return WorkerSettlement(
        request_id=request_id,
        terminal=terminal,
        launched=False,
        exit_code=None,
        process_group_settled=process_group_settled,
        process_tree_settled=False,
        streams=_not_started_streams(),
        worker_pid=worker_pid,
        tool_pid=None,
        detail=detail,
    )


def _write_settlement(control_fd: int, settlement: WorkerSettlement) -> None:
    runner_ipc.write_all(control_fd, encode_settlement(settlement))


def _launcher_terminal(launcher) -> bool:
    return (
        getattr(launcher, "_reaped", False) is True
        or getattr(launcher, "returncode", None) is not None
    )


def _settle_launcher(launcher) -> bool:
    """Kill/reap once; retry only after a failed cooperative cleanup boundary."""
    first: BaseException | None = None
    try:
        launcher.abort_and_reap()
        return True
    except BaseException as exc:
        first = exc
    if _launcher_terminal(launcher):
        if first is not None and not isinstance(first, Exception):
            raise first
        return True
    try:
        launcher.abort_and_reap()
        settled = True
    except BaseException as retry:
        if first is not None and not isinstance(first, Exception):
            raise first
        if not isinstance(retry, Exception):
            raise retry
        settled = False
    if first is not None and not isinstance(first, Exception):
        raise first
    return settled


def _settle_after_boundary(launcher, primary: BaseException) -> bool:
    """Reconcile child authority, then preserve cooperative cancellation."""
    try:
        settled = _settle_launcher(launcher)
    except BaseException as cleanup:
        if not isinstance(primary, Exception):
            raise primary
        raise cleanup
    if not isinstance(primary, Exception):
        raise primary
    return settled


def _command_matches_prepared(command, request, prepared: PreparedFrame) -> bool:
    return (
        command.request_id == request.request_id
        and command.request_sha256 == request_digest(request)
        and command.worker_pid == prepared.worker_pid
        and command.prepared_sha256 == prepared_digest(prepared)
    )


def _write_parked_failure(
    control_fd: int,
    *,
    request_id: str,
    worker_pid: int,
    detail: str,
    settled: bool,
) -> bool:
    try:
        _write_settlement(control_fd, _negative_settlement(
            request_id=request_id,
            worker_pid=worker_pid,
            terminal=ExecutionTerminal.WORKER_FAILED,
            detail=detail,
            process_group_settled=settled,
        ))
        return True
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return False


def _run_prepared_abort_transaction(
    request_fd: int,
    control_fd: int,
    worker_pid: int,
    owner: _PreparedAbortOwner,
    *,
    stdout_fd: int | None,
    stderr_fd: int | None,
) -> int:
    launcher = None
    request = None
    try:
        # No target request has been read or decoded at this boundary.  The forked
        # child receives only fixed descriptor metadata.
        launcher = _spawn_parked_launcher(
            stdout_fd=stdout_fd,
            stderr_fd=stderr_fd,
            inherited_fds=(request_fd, control_fd),
            _owner=owner,
        )
        launcher.close_inherited_before_stop()
    except BaseException as primary:
        if launcher is not None:
            _settle_after_boundary(launcher, primary)
        if not isinstance(primary, Exception):
            raise
        return _EXIT_BOOTSTRAP_INVALID

    try:
        request = decode_request(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
        # The fixed supervisor uses explicit stage-free PREPARED mode only to
        # prove and abort the launcher, so request claims need no dummy writer.
        # Once any private writer is supplied, however, its roles must match the
        # request exactly before the transaction can testify PREPARED.
        if stdout_fd is not None or stderr_fd is not None:
            _validate_output_fds(
                request, stdout_fd, stderr_fd,
                request_fd=request_fd, control_fd=control_fd,
            )
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_BOOTSTRAP_INVALID

    digest = request_digest(request)
    try:
        runner_ipc.write_all(control_fd, encode_ready(ReadyFrame(
            request_id=request.request_id,
            worker_pid=worker_pid,
            request_sha256=digest,
        )))
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_CONTROL_FAILED

    proof_error: BaseException | None = None
    try:
        stopped = launcher.prove_stopped()
    except BaseException as primary:
        proof_error = primary
        stopped = False
    if not stopped:
        settled = (
            _settle_after_boundary(launcher, proof_error)
            if proof_error is not None else _settle_launcher(launcher)
        )
        _write_parked_failure(
            control_fd,
            request_id=request.request_id,
            worker_pid=worker_pid,
            detail="launcher_not_parked",
            settled=settled,
        )
        return _EXIT_CONTROL_FAILED

    prepared = PreparedFrame(
        request_id=request.request_id,
        worker_pid=worker_pid,
        launcher_pid=launcher.pid,
        launcher_pgid=launcher.pgid,
        containment_kind=ContainmentKind.CGROUP_V2,
        containment_id=f"direct/quarry-{request.request_id}",
    )
    try:
        runner_ipc.write_all(control_fd, encode_prepared(prepared))
    except BaseException as primary:
        _settle_after_boundary(launcher, primary)
        return _EXIT_CONTROL_FAILED

    command_error: BaseException | None = None
    try:
        command = decode_command(runner_ipc.read_frame(
            request_fd, max_frame_bytes=MAX_FRAME_BYTES,
        ))
        runner_ipc.require_eof(request_fd)
        command_valid = _command_matches_prepared(command, request, prepared)
    except BaseException as primary:
        command_error = primary
        command = None
        command_valid = False
        command_invalid = True
    else:
        command_invalid = False

    settled = (
        _settle_after_boundary(launcher, command_error)
        if command_error is not None else _settle_launcher(launcher)
    )
    if not settled:
        detail = "launcher_settlement_failed"
        terminal = ExecutionTerminal.WORKER_FAILED
        returncode = _EXIT_CONTROL_FAILED
    elif command_invalid:
        detail = "command_invalid"
        terminal = ExecutionTerminal.WORKER_FAILED
        returncode = _EXIT_CONTROL_FAILED
    elif not command_valid:
        detail = "command_mismatch"
        terminal = ExecutionTerminal.WORKER_FAILED
        returncode = 0
    elif command.command is WorkerCommandKind.GO:
        detail = "go_refused"
        terminal = ExecutionTerminal.WORKER_FAILED
        returncode = 0
    else:
        detail = "parent_abort"
        terminal = ExecutionTerminal.CANCELLED
        returncode = 0
    try:
        _write_settlement(control_fd, _negative_settlement(
            request_id=request.request_id,
            worker_pid=worker_pid,
            terminal=terminal,
            detail=detail,
            process_group_settled=settled,
        ))
    except BaseException as exc:
        if not isinstance(exc, Exception):
            raise
        return _EXIT_CONTROL_FAILED
    return returncode


def _run_prepared_abort_worker(
    request_fd: int,
    control_fd: int,
    worker_pid: int,
    *,
    stdout_fd: int | None,
    stderr_fd: int | None,
) -> int:
    owner = _PreparedAbortOwner()
    with _PreparedAbortFence(owner):
        with _PreparedAbortFence(owner):
            return _run_prepared_abort_transaction(
                request_fd, control_fd, worker_pid, owner,
                stdout_fd=stdout_fd, stderr_fd=stderr_fd,
            )


def _run_worker(
    request_fd: int,
    control_fd: int,
    expected_parent_pid: int,
    *,
    stdout_fd: int | None = None,
    stderr_fd: int | None = None,
    prepared_abort: bool = False,
) -> int:
    """Run one legacy or parked transaction over blocking descriptors."""
    _arm_parent_death(expected_parent_pid)
    worker_pid = os.getpid()
    if (type(prepared_abort) is not bool):
        raise _metadata_failure()
    if prepared_abort or stdout_fd is not None or stderr_fd is not None:
        return _run_prepared_abort_worker(
            request_fd, control_fd, worker_pid,
            stdout_fd=stdout_fd, stderr_fd=stderr_fd,
        )
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
        and command.prepared_sha256 is None
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
        prepared_abort = _pop_prepared_abort_mode()
        stdout_fd, stderr_fd = _pop_output_fd_metadata()
        # The bootstrap environment contains only fixed numeric metadata.  Remove
        # even that value before accepting the target-effective request over IPC.
        os.environ.clear()
        return _run_worker(
            0, 1, expected_parent_pid,
            stdout_fd=stdout_fd, stderr_fd=stderr_fd,
            prepared_abort=prepared_abort,
        )
    except BaseException:
        return _EXIT_BOOTSTRAP_INVALID
    finally:
        try:
            os.close(1)
        except OSError:
            pass


if __name__ == "__main__":  # pragma: no cover - exercised by integration tests
    raise SystemExit(main())
