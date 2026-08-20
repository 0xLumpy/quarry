"""Worker-local binary stream settlement for one release-gated tool.

This module owns only the launcher's three tool pipe descriptors.  Output stage
descriptors and a FILE-mode input descriptor are borrowed from the worker's
private handoff and remain caller-owned.  A returned settlement therefore means
that the direct launcher has been reaped and every owned pipe has been closed;
it does not claim that the parent has authenticated or published the stages.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import selectors
import stat
import time
from dataclasses import dataclass, field

from .runner_protocol import (
    ExecutionTerminal,
    StdinMode,
    StreamRole,
    StreamSettlement,
    StreamTerminal,
    WorkerRequest,
    WorkerSettlement,
)


_CHUNK_BYTES = 64 * 1024
_SELECT_SLICE = 0.05
_SETTLEMENT_GRACE_SECONDS = 5.0
_PRIVATE_REDACTIONS_ENV = "QUARRY_RUNNER_PRIVATE_REDACTIONS"


def _request_redactions(request: WorkerRequest) -> tuple[bytes, ...]:
    raw = dict(request.environment).get(_PRIVATE_REDACTIONS_ENV)
    if raw is None:
        return ()
    try:
        values = json.loads(raw)
    except (TypeError, ValueError):
        raise RuntimeError("stream_redactions_invalid") from None
    if (not isinstance(values, list) or not values
            or not all(isinstance(value, str) and len(value) >= 6 for value in values)
            or len(values) != len(set(values))):
        raise RuntimeError("stream_redactions_invalid")
    try:
        encoded = tuple(value.encode("utf-8", "strict") for value in values)
    except UnicodeError:
        raise RuntimeError("stream_redactions_invalid") from None
    return tuple(sorted(encoded, key=lambda value: (-len(value), value)))


def _valid_deadline(value, name: str, *, optional: bool) -> float | None:
    if value is None and optional:
        return None
    if (type(value) not in (int, float) or not math.isfinite(value)
            or value < 0):
        raise RuntimeError(f"{name}_invalid")
    return float(value)


def _close_fd(fd: int) -> None:
    """Close an owned descriptor once, accepting only an already-closed fd."""
    try:
        os.close(fd)
    except OSError as exc:
        # EBADF proves there is no longer an open descriptor at this number.  Any
        # other close failure is ambiguous, so a terminal settlement is unsafe.
        if exc.errno != 9:
            raise


def _detach_launcher_fd(launcher, attribute: str) -> int:
    fd = getattr(launcher, attribute, None)
    if type(fd) is not int or fd < 0:
        raise RuntimeError("launcher_pipe_invalid")
    setattr(launcher, attribute, -1)
    return fd


def _abort_and_reap(launcher) -> int:
    exit_code = launcher.abort_and_reap()
    if type(exit_code) is not int:
        raise RuntimeError("launcher_wait_invalid")
    return exit_code


def _claim_id(request: WorkerRequest, role: StreamRole) -> str | None:
    claim = request.claim_for(role)
    return None if claim is None else claim.claim_id


@dataclass
class _OutputState:
    role: StreamRole
    pipe_fd: int
    stage_fd: int | None
    claim_id: str | None
    cap: int | None
    observed_hash: object = field(default_factory=hashlib.sha256)
    retained_hash: object = field(default_factory=hashlib.sha256)
    observed_bytes: int = 0
    retained_bytes: int = 0
    lines: int = 0
    terminal: StreamTerminal | None = None
    detail: str | None = None
    redactions: tuple[bytes, ...] = ()
    redaction_carry: bytes = b""

    @property
    def open(self) -> bool:
        return self.pipe_fd >= 0

    def close_pipe(self, selector: selectors.BaseSelector) -> None:
        if self.pipe_fd < 0:
            return
        fd = self.pipe_fd
        self.pipe_fd = -1
        try:
            selector.unregister(fd)
        except (KeyError, ValueError):
            pass
        _close_fd(fd)

    def _retain(self, data: bytes) -> None:
        if self.stage_fd is None or not data or self.terminal is StreamTerminal.SINK_ERROR:
            return
        view = memoryview(data)
        while view:
            try:
                written = os.write(self.stage_fd, view)
            except OSError:
                self.terminal = StreamTerminal.SINK_ERROR
                self.detail = "stage_write"
                return
            if type(written) is not int or written <= 0:
                self.terminal = StreamTerminal.SINK_ERROR
                self.detail = "stage_write"
                return
            committed = bytes(view[:written])
            self.retained_hash.update(committed)
            self.retained_bytes += written
            self.lines += committed.count(b"\n")
            view = view[written:]

    def _sanitize(self, data: bytes, *, final: bool) -> bytes:
        if not self.redactions:
            return data
        combined = self.redaction_carry + data
        if final:
            emit_at = len(combined)
        else:
            emit_at = max(0, len(combined) - max(len(value) for value in self.redactions) + 1)
            # Do not split a complete match: keeping the whole raw value lets the next chunk replace every
            # byte, rather than leaking a prefix/suffix around an arbitrary read boundary.
            for value in self.redactions:
                start = combined.find(value)
                while start >= 0:
                    end = start + len(value)
                    if start < emit_at < end:
                        emit_at = start
                    start = combined.find(value, start + 1)
        sanitized = combined
        for value in self.redactions:
            sanitized = sanitized.replace(value, b"*" * len(value))
        emitted = sanitized[:emit_at]
        self.redaction_carry = b"" if final else combined[emit_at:]
        return emitted

    def _consume_bytes(self, chunk: bytes) -> None:
        chunk = self._sanitize(chunk, final=False)
        if not chunk:
            return
        self.observed_hash.update(chunk)
        self.observed_bytes += len(chunk)
        if self.stage_fd is None:
            return
        if self.cap is None:
            retained = chunk
        else:
            remaining = max(0, self.cap - self.retained_bytes)
            retained = chunk[:remaining]
        self._retain(retained)

    def flush_redaction(self) -> None:
        chunk = self._sanitize(b"", final=True)
        if not chunk:
            return
        self.observed_hash.update(chunk)
        self.observed_bytes += len(chunk)
        if self.stage_fd is None:
            return
        retained = chunk if self.cap is None else chunk[:max(0, self.cap - self.retained_bytes)]
        self._retain(retained)

    def consume_ready(self, selector: selectors.BaseSelector) -> None:
        while self.pipe_fd >= 0:
            try:
                chunk = os.read(self.pipe_fd, _CHUNK_BYTES)
            except BlockingIOError:
                return
            except OSError:
                self.terminal = StreamTerminal.WORKER_CRASH
                self.detail = "pipe_read"
                self.close_pipe(selector)
                return
            if not chunk:
                self.flush_redaction()
                self.close_pipe(selector)
                return
            self._consume_bytes(chunk)

    def fsync_stage(self) -> None:
        if self.stage_fd is None:
            return
        try:
            os.fsync(self.stage_fd)
        except OSError:
            if self.terminal is not StreamTerminal.SINK_ERROR:
                self.detail = "stage_fsync"
            self.terminal = StreamTerminal.SINK_ERROR

    def finish(self, *, forced_deadline: bool) -> StreamSettlement:
        terminal = self.terminal
        if terminal is None:
            if forced_deadline:
                terminal = StreamTerminal.DEADLINE
            elif self.cap is not None and self.observed_bytes > self.retained_bytes:
                terminal = StreamTerminal.CAPPED
            else:
                terminal = StreamTerminal.EOF
        retained_digest = (
            self.retained_hash.hexdigest() if self.claim_id is not None else None
        )
        return StreamSettlement(
            role=self.role,
            terminal=terminal,
            observed_bytes=self.observed_bytes,
            retained_bytes=self.retained_bytes,
            observed_sha256=self.observed_hash.hexdigest(),
            retained_sha256=retained_digest,
            claim_id=self.claim_id,
            lines=self.lines,
            detail=self.detail,
        )


@dataclass
class _InputState:
    pipe_fd: int
    mode: StdinMode
    data: bytes | None
    file_fd: int | None
    observed_hash: object = field(default_factory=hashlib.sha256)
    observed_bytes: int = 0
    data_offset: int = 0
    file_offset: int = 0
    pending: bytes = b""
    pending_offset: int = 0
    source_eof: bool = False
    terminal: StreamTerminal | None = None
    detail: str | None = None

    @property
    def open(self) -> bool:
        return self.pipe_fd >= 0

    def close_pipe(self, selector: selectors.BaseSelector) -> None:
        if self.pipe_fd < 0:
            return
        fd = self.pipe_fd
        self.pipe_fd = -1
        try:
            selector.unregister(fd)
        except (KeyError, ValueError):
            pass
        _close_fd(fd)

    def _fill(self) -> None:
        if self.pending_offset < len(self.pending) or self.source_eof:
            return
        self.pending = b""
        self.pending_offset = 0
        if self.mode is StdinMode.DATA:
            assert self.data is not None
            if self.data_offset >= len(self.data):
                self.source_eof = True
                return
            end = min(len(self.data), self.data_offset + _CHUNK_BYTES)
            self.pending = self.data[self.data_offset:end]
            self.data_offset = end
            return
        if self.mode is StdinMode.FILE:
            assert self.file_fd is not None
            try:
                block = os.pread(self.file_fd, _CHUNK_BYTES, self.file_offset)
            except OSError:
                self.terminal = StreamTerminal.SOURCE_ERROR
                self.detail = "stdin_read"
                self.source_eof = True
                return
            if not block:
                self.source_eof = True
                return
            self.file_offset += len(block)
            self.pending = block
            return
        self.source_eof = True

    def prime(self, selector: selectors.BaseSelector) -> None:
        if self.mode is StdinMode.NULL:
            self.source_eof = True
            self.terminal = StreamTerminal.COMPLETE
            self.close_pipe(selector)
            return
        self._fill()
        if self.terminal is StreamTerminal.SOURCE_ERROR:
            self.close_pipe(selector)
        elif self.source_eof:
            self.terminal = StreamTerminal.COMPLETE
            self.close_pipe(selector)

    def consume_ready(self, selector: selectors.BaseSelector) -> None:
        while self.pipe_fd >= 0:
            self._fill()
            if self.terminal is StreamTerminal.SOURCE_ERROR:
                self.close_pipe(selector)
                return
            if self.source_eof and self.pending_offset >= len(self.pending):
                self.terminal = StreamTerminal.COMPLETE
                self.close_pipe(selector)
                return
            view = memoryview(self.pending)[self.pending_offset:]
            try:
                written = os.write(self.pipe_fd, view)
            except BlockingIOError:
                return
            except (BrokenPipeError, OSError):
                self.terminal = StreamTerminal.PEER_CLOSED
                self.close_pipe(selector)
                return
            if type(written) is not int or written <= 0:
                self.terminal = StreamTerminal.PEER_CLOSED
                self.close_pipe(selector)
                return
            committed = bytes(view[:written])
            self.observed_hash.update(committed)
            self.observed_bytes += written
            self.pending_offset += written

    def stop(self, selector: selectors.BaseSelector, terminal: StreamTerminal) -> None:
        if self.terminal is None:
            self.terminal = terminal
        self.close_pipe(selector)

    def finish(self) -> StreamSettlement:
        return StreamSettlement(
            role=StreamRole.STDIN,
            terminal=self.terminal or StreamTerminal.WORKER_CRASH,
            observed_bytes=self.observed_bytes,
            retained_bytes=0,
            observed_sha256=self.observed_hash.hexdigest(),
            retained_sha256=None,
            claim_id=None,
            lines=0,
            detail=self.detail,
        )


def _leader_exited(pid: int, launcher) -> bool:
    """Observe direct-child exit without consuming the launcher's wait status."""
    if getattr(launcher, "returncode", None) is not None:
        return True
    while True:
        try:
            observed = os.waitid(
                os.P_PID,
                pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except InterruptedError:
            continue
        except ChildProcessError:
            return getattr(launcher, "returncode", None) is not None
        return observed is not None and observed.si_pid == pid


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


def _validate_inputs(
    request: WorkerRequest,
    launcher,
    *,
    stdin_data: bytes | None,
    stdin_file_fd: int | None,
    stdout_stage_fd: int | None,
    stderr_stage_fd: int | None,
) -> None:
    if type(request) is not WorkerRequest:
        raise RuntimeError("stream_request_invalid")
    if (type(getattr(launcher, "pid", None)) is not int
            or type(getattr(launcher, "pgid", None)) is not int
            or launcher.pid <= 0
            or launcher.pgid != launcher.pid
            or not callable(getattr(launcher, "release_for_exec", None))
            or not callable(getattr(launcher, "abort_and_reap", None))
            or not callable(getattr(launcher, "send_deadline_sigint", None))):
        raise RuntimeError("stream_launcher_invalid")

    launcher_fds = tuple(
        getattr(launcher, name, None)
        for name in ("stdin_write_fd", "stdout_read_fd", "stderr_read_fd")
    )
    if (any(type(fd) is not int or fd < 0 for fd in launcher_fds)
            or len(set(launcher_fds)) != len(launcher_fds)):
        raise RuntimeError("launcher_pipe_invalid")
    try:
        launcher_stats = tuple(os.fstat(fd) for fd in launcher_fds)
        launcher_flags = tuple(
            fcntl.fcntl(fd, fcntl.F_GETFL) for fd in launcher_fds
        )
    except OSError:
        raise RuntimeError("launcher_pipe_invalid") from None
    if (any(not stat.S_ISFIFO(item.st_mode) for item in launcher_stats)
            or len({(item.st_dev, item.st_ino) for item in launcher_stats})
            != len(launcher_stats)
            or launcher_flags[0] & os.O_ACCMODE == os.O_RDONLY
            or any(flags & os.O_ACCMODE == os.O_WRONLY
                   for flags in launcher_flags[1:])):
        raise RuntimeError("launcher_pipe_invalid")

    if request.stdin_mode is StdinMode.NULL:
        valid_input = stdin_data is None and stdin_file_fd is None
    elif request.stdin_mode is StdinMode.DATA:
        valid_input = (
            type(stdin_data) is bytes
            and stdin_file_fd is None
            and len(stdin_data) == request.stdin_bytes
            and hashlib.sha256(stdin_data).hexdigest() == request.stdin_sha256
        )
    else:
        valid_input = (
            stdin_data is None
            and type(stdin_file_fd) is int
            and stdin_file_fd >= 0
        )
    if not valid_input:
        raise RuntimeError("stream_input_invalid")

    for role, fd in (
        (StreamRole.STDOUT, stdout_stage_fd),
        (StreamRole.STDERR, stderr_stage_fd),
    ):
        claimed = request.claim_for(role) is not None
        if claimed != (type(fd) is int and fd >= 0):
            raise RuntimeError("stream_stage_invalid")
    borrowed_fds = tuple(
        fd for fd in (stdin_file_fd, stdout_stage_fd, stderr_stage_fd)
        if fd is not None
    )
    if (len(borrowed_fds) != len(set(borrowed_fds))
            or set(borrowed_fds).intersection(launcher_fds)):
        raise RuntimeError("stream_stage_invalid")

    borrowed_identities: list[tuple[int, int]] = []

    if stdin_file_fd is not None:
        try:
            metadata = os.fstat(stdin_file_fd)
            flags = fcntl.fcntl(stdin_file_fd, fcntl.F_GETFL)
        except OSError:
            raise RuntimeError("stream_input_invalid") from None
        if (not stat.S_ISREG(metadata.st_mode)
                or flags & os.O_ACCMODE == os.O_WRONLY):
            raise RuntimeError("stream_input_invalid")
        borrowed_identities.append((metadata.st_dev, metadata.st_ino))

    for fd in (stdout_stage_fd, stderr_stage_fd):
        if fd is None:
            continue
        try:
            metadata = os.fstat(fd)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        except OSError:
            raise RuntimeError("stream_stage_invalid") from None
        if (not stat.S_ISREG(metadata.st_mode)
                or flags & os.O_ACCMODE == os.O_RDONLY
                or flags & os.O_APPEND
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != 0):
            raise RuntimeError("stream_stage_invalid")
        try:
            position = os.lseek(fd, 0, os.SEEK_CUR)
        except OSError:
            raise RuntimeError("stream_stage_invalid") from None
        if position != 0:
            raise RuntimeError("stream_stage_invalid")
        borrowed_identities.append((metadata.st_dev, metadata.st_ino))
    if len(borrowed_identities) != len(set(borrowed_identities)):
        raise RuntimeError("stream_stage_invalid")


def _run_stream_engine(
    request: WorkerRequest,
    launcher,
    *,
    stdin_data: bytes | None = None,
    stdin_file_fd: int | None = None,
    stdout_stage_fd: int | None = None,
    stderr_stage_fd: int | None = None,
    execution_deadline,
    settlement_deadline,
    clock=time.monotonic,
    on_started=None,
) -> WorkerSettlement:
    """Execute, settle, and testify about one already-contained launcher.

    ``execution_deadline`` and ``settlement_deadline`` are absolute readings from
    ``clock``.  A pair of ``None`` values means no execution cutoff (the
    normalized timeout-zero contract).  Release remains bounded, and a bounded
    settlement grace starts only after the exact leader exits.  A finite
    execution always has a finite outer settlement deadline.
    """
    if not callable(clock):
        raise RuntimeError("stream_clock_invalid")
    if on_started is not None and not callable(on_started):
        raise RuntimeError("stream_started_callback_invalid")
    execution_deadline = _valid_deadline(
        execution_deadline, "execution_deadline", optional=True,
    )
    settlement_deadline = _valid_deadline(
        settlement_deadline, "settlement_deadline", optional=True,
    )
    if (execution_deadline is not None
            and (settlement_deadline is None
                 or execution_deadline > settlement_deadline)):
        raise RuntimeError("stream_deadline_invalid")
    _validate_inputs(
        request,
        launcher,
        stdin_data=stdin_data,
        stdin_file_fd=stdin_file_fd,
        stdout_stage_fd=stdout_stage_fd,
        stderr_stage_fd=stderr_stage_fd,
    )
    redactions = _request_redactions(request)

    now = float(clock())
    if execution_deadline is None:
        release_deadline = now + _SETTLEMENT_GRACE_SECONDS
    else:
        assert settlement_deadline is not None
        release_deadline = min(settlement_deadline, execution_deadline)
    if now >= release_deadline:
        _abort_and_reap(launcher)
        return WorkerSettlement(
            request_id=request.request_id,
            terminal=ExecutionTerminal.LAUNCH_FAILED,
            launched=False,
            exit_code=None,
            process_group_settled=True,
            process_tree_settled=False,
            streams=_not_started_streams(),
            worker_pid=os.getpid(),
            tool_pid=None,
            detail="release_deadline",
        )

    released = launcher.release_for_exec(
        request,
        deadline=release_deadline,
        clock=clock,
    )
    if not released:
        _abort_and_reap(launcher)
        return WorkerSettlement(
            request_id=request.request_id,
            terminal=ExecutionTerminal.LAUNCH_FAILED,
            launched=False,
            exit_code=None,
            process_group_settled=True,
            process_tree_settled=False,
            streams=_not_started_streams(),
            worker_pid=os.getpid(),
            tool_pid=None,
            detail="exec_release",
        )

    if on_started is not None:
        try:
            on_started()
        except BaseException:
            _abort_and_reap(launcher)
            raise

    selector = selectors.DefaultSelector()
    owned_fds: set[int] = set()
    reaped = False
    exit_code: int | None = None
    execution_cutoff = False
    settlement_cutoff = False
    deadline_sigint_sent = False
    stdin_state: _InputState | None = None
    outputs: tuple[_OutputState, ...] = ()
    drain_deadline: float | None = None
    try:
        stdin_pipe = _detach_launcher_fd(launcher, "stdin_write_fd")
        owned_fds.add(stdin_pipe)
        stdout_pipe = _detach_launcher_fd(launcher, "stdout_read_fd")
        owned_fds.add(stdout_pipe)
        stderr_pipe = _detach_launcher_fd(launcher, "stderr_read_fd")
        owned_fds.add(stderr_pipe)
        for fd in owned_fds:
            os.set_blocking(fd, False)

        stdin_state = _InputState(
            pipe_fd=stdin_pipe,
            mode=request.stdin_mode,
            data=stdin_data,
            file_fd=stdin_file_fd,
        )
        outputs = (
            _OutputState(
                role=StreamRole.STDOUT,
                pipe_fd=stdout_pipe,
                stage_fd=stdout_stage_fd,
                claim_id=_claim_id(request, StreamRole.STDOUT),
                cap=request.max_output_bytes,
                redactions=redactions,
            ),
            _OutputState(
                role=StreamRole.STDERR,
                pipe_fd=stderr_pipe,
                stage_fd=stderr_stage_fd,
                claim_id=_claim_id(request, StreamRole.STDERR),
                cap=None,
                redactions=redactions,
            ),
        )
        # From this point every detached descriptor has a stable stream owner.
        # Keep ``owned_fds`` only as the allocation-failure backstop.
        owned_fds.clear()
        selector.register(stdout_pipe, selectors.EVENT_READ, outputs[0])
        selector.register(stderr_pipe, selectors.EVENT_READ, outputs[1])
        selector.register(stdin_pipe, selectors.EVENT_WRITE, stdin_state)
        stdin_state.prime(selector)

        while not reaped:
            now = float(clock())
            if _leader_exited(launcher.pid, launcher):
                exit_code = _abort_and_reap(launcher)
                reaped = True
                drain_deadline = now + _SETTLEMENT_GRACE_SECONDS
                if settlement_deadline is not None:
                    drain_deadline = min(drain_deadline, settlement_deadline)
                if stdin_state.open:
                    stdin_state.stop(selector, StreamTerminal.PEER_CLOSED)
                break
            if execution_deadline is not None and now >= execution_deadline:
                if request.deadline_sigint and not deadline_sigint_sent:
                    # This request-bound posture leaves the pipe readers alive
                    # for the fixed settlement window.  The hard-kill/reap
                    # branch below remains the fallback for every survivor.
                    launcher.send_deadline_sigint()
                    deadline_sigint_sent = True
                    if stdin_state.open:
                        stdin_state.stop(selector, StreamTerminal.DEADLINE)
                elif not deadline_sigint_sent:
                    execution_cutoff = True
                    _abort_and_reap(launcher)
                    reaped = True
                    assert settlement_deadline is not None
                    drain_deadline = settlement_deadline
                    if stdin_state.open:
                        stdin_state.stop(selector, StreamTerminal.DEADLINE)
                    break
            if (settlement_deadline is not None
                    and now >= settlement_deadline):
                settlement_cutoff = True
                exit_code = _abort_and_reap(launcher)
                reaped = True
                drain_deadline = settlement_deadline
                if stdin_state.open:
                    stdin_state.stop(selector, StreamTerminal.DEADLINE)
                break

            nearest = None if deadline_sigint_sent else execution_deadline
            if settlement_deadline is not None:
                nearest = (
                    settlement_deadline if nearest is None
                    else min(nearest, settlement_deadline)
                )
            timeout = _SELECT_SLICE
            if nearest is not None:
                timeout = min(timeout, max(0.0, nearest - now))
            for key, _events in selector.select(timeout):
                state = key.data
                state.consume_ready(selector)

        if drain_deadline is None:
            raise RuntimeError("stream_drain_deadline_invalid")
        while any(output.open for output in outputs):
            now = float(clock())
            if now >= drain_deadline:
                settlement_cutoff = True
                break
            timeout = min(_SELECT_SLICE, max(0.0, drain_deadline - now))
            for key, _events in selector.select(timeout):
                state = key.data
                # stdin has already been closed before the reaped state.
                if isinstance(state, _OutputState):
                    state.consume_ready(selector)

        for output in outputs:
            if output.open:
                output.close_pipe(selector)
        for output in outputs:
            output.flush_redaction()
            output.fsync_stage()

        forced_output_deadline = execution_cutoff or settlement_cutoff
        stdin_stream = stdin_state.finish()
        output_streams = tuple(
            output.finish(forced_deadline=forced_output_deadline)
            for output in outputs
        )
        streams = (stdin_stream, *output_streams)
        streams_failed = any(
            stream.terminal in (
                StreamTerminal.SOURCE_ERROR,
                StreamTerminal.SINK_ERROR,
                StreamTerminal.WORKER_CRASH,
            )
            for stream in streams
        )
        if execution_cutoff:
            terminal = ExecutionTerminal.TIMED_OUT
            detail = "execution_deadline"
            reported_exit_code = None
        elif settlement_cutoff:
            terminal = ExecutionTerminal.WORKER_FAILED
            detail = "settlement_deadline"
            reported_exit_code = exit_code
        elif streams_failed:
            terminal = ExecutionTerminal.WORKER_FAILED
            detail = "stream_failed"
            reported_exit_code = exit_code
        else:
            terminal = ExecutionTerminal.COMPLETE
            detail = "sigint_deadline_exit" if deadline_sigint_sent else None
            reported_exit_code = exit_code
        return WorkerSettlement(
            request_id=request.request_id,
            terminal=terminal,
            launched=True,
            exit_code=reported_exit_code,
            process_group_settled=True,
            process_tree_settled=False,
            streams=streams,
            worker_pid=os.getpid(),
            tool_pid=launcher.pid,
            detail=detail,
        )
    finally:
        # A terminal return is reachable only after the exact direct child was
        # reaped.  On an exceptional path, settle before relinquishing pipe
        # ownership; the outer worker can then report a typed machinery failure.
        if not reaped:
            _abort_and_reap(launcher)
        if stdin_state is not None and stdin_state.pipe_fd >= 0:
            fd = stdin_state.pipe_fd
            stdin_state.pipe_fd = -1
            _close_fd(fd)
        for output in outputs:
            if output.pipe_fd >= 0:
                fd = output.pipe_fd
                output.pipe_fd = -1
                _close_fd(fd)
        # Covers allocation failures between detaching a descriptor and attaching
        # all three to their stable stream states.
        for fd in owned_fds:
            try:
                _close_fd(fd)
            except OSError:
                pass
        selector.close()


__all__ = ()
