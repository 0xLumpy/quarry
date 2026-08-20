"""Red contract for the PREPARED -> GO worker execution transaction."""
from __future__ import annotations

import hashlib
import inspect
import os
import threading
from dataclasses import replace

import pytest

from quarry_recon import runner_ipc
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_worker


pytestmark = pytest.mark.offline

RID = "e1" * 16
WORKER_PID = 45001
LAUNCHER_PID = 45002
EXECUTION_ENV = "QUARRY_RUNNER_EXECUTION"
DATA = b"private input\x00with binary bytes\n"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _invocation(*, timeout=30):
    return protocol.normalize_invocation(
        request_id=RID,
        tool="fixture",
        cmd=["tool-secret", "target-secret"],
        timeout=timeout,
        stdin_data=DATA.decode("utf-8"),
        raw_path="/tmp/quarry-execution.stdout",
        stderr_path="/tmp/quarry-execution.stderr",
        env={"TOKEN": "environment-secret"},
        base_environment={"PATH": "/usr/bin"},
    )


def _prepared(request):
    return protocol.PreparedFrame(
        request_id=request.request_id,
        worker_pid=WORKER_PID,
        launcher_pid=LAUNCHER_PID,
        launcher_pgid=LAUNCHER_PID,
        containment_kind=protocol.ContainmentKind.CGROUP_V2,
        containment_id=f"direct/quarry-{request.request_id}",
    )


def _command(request, kind=protocol.WorkerCommandKind.GO, **overrides):
    values = {
        "request_id": request.request_id,
        "request_sha256": protocol.request_digest(request),
        "prepared_sha256": protocol.prepared_digest(_prepared(request)),
        "worker_pid": WORKER_PID,
        "command": kind,
    }
    values.update(overrides)
    return protocol.WorkerCommand(**values)


def _frame_records(control_read: int):
    decoder = runner_ipc.IncrementalFrameDecoder(protocol.MAX_FRAME_BYTES)
    records = []
    while True:
        chunk = os.read(control_read, 65536)
        if not chunk:
            break
        records.extend(
            protocol.decode_control_frame(frame)
            for frame in decoder.feed(chunk)
        )
    decoder.finish()
    return tuple(records)


class _FakeExecutionLauncher:
    def __init__(self, *, release_result=True, stopped=True, events=None):
        self.pid = LAUNCHER_PID
        self.pgid = LAUNCHER_PID
        self.stdin_write_fd = 91
        self.stdout_read_fd = 92
        self.stderr_read_fd = 93
        self.release_result = release_result
        self.stopped = stopped
        self.events = [] if events is None else events
        self.release_calls = []
        self.reap_calls = 0
        self.returncode = None

    def close_inherited_before_stop(self):
        self.events.append("launcher_fds_closed")

    def prove_stopped(self):
        self.events.append("stop_proved")
        return self.stopped

    def release_for_exec(self, request, *, deadline=None, clock=None):
        self.events.append("release")
        self.release_calls.append((request, deadline, clock))
        return self.release_result

    def abort_and_reap(self):
        self.events.append("reaped")
        self.reap_calls += 1
        if self.returncode is None:
            self.returncode = -9
        return self.returncode


def _complete_settlement(request, launcher):
    stdin_digest = hashlib.sha256(DATA).hexdigest()
    streams = (
        protocol.StreamSettlement(
            role=protocol.StreamRole.STDIN,
            terminal=protocol.StreamTerminal.COMPLETE,
            observed_bytes=len(DATA),
            retained_bytes=0,
            observed_sha256=stdin_digest,
            retained_sha256=None,
        ),
        *(
            protocol.StreamSettlement(
                role=role,
                terminal=protocol.StreamTerminal.EOF,
                observed_bytes=0,
                retained_bytes=0,
                observed_sha256=EMPTY_SHA256,
                retained_sha256=EMPTY_SHA256,
                claim_id=request.claim_for(role).claim_id,
            )
            for role in (protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR)
        ),
    )
    return protocol.WorkerSettlement(
        request_id=request.request_id,
        terminal=protocol.ExecutionTerminal.COMPLETE,
        launched=True,
        exit_code=0,
        process_group_settled=True,
        process_tree_settled=False,
        streams=streams,
        worker_pid=WORKER_PID,
        tool_pid=launcher.pid,
    )


def _install_execution_fakes(
    monkeypatch,
    launcher,
    *,
    events,
    stream_behavior="complete",
    stream_calls=None,
):
    real_decode_request = runner_worker.decode_request
    real_decode_command = runner_worker.decode_command
    real_write_all = runner_worker.runner_ipc.write_all

    def decode_request(frame):
        events.append("request_decoded")
        return real_decode_request(frame)

    def decode_command(frame):
        events.append("command_decoded")
        return real_decode_command(frame)

    def write_control(fd, data):
        try:
            record = protocol.decode_control_frame(data)
        except protocol.ProtocolError:
            record = None
        if record is not None:
            events.append(type(record).__name__)
        return real_write_all(fd, data)

    def spawn(*args, **kwargs):
        events.append("launcher_spawned")
        assert args == ()
        assert set(kwargs) == {"inherited_fds", "_owner"}
        assert len(kwargs["inherited_fds"]) == 2
        rendered = repr((args, kwargs))
        assert not any(
            secret in rendered
            for secret in (
                "tool-secret", "target-secret", "environment-secret", "TOKEN",
            )
        )
        return launcher

    def stream_engine(request, observed_launcher, **kwargs):
        events.append("stream_engine")
        assert observed_launcher is launcher
        if stream_calls is not None:
            stream_calls.append((request, observed_launcher, kwargs))
        if stream_behavior == "invalid_input":
            raise RuntimeError("stream_input_invalid")
        if stream_behavior == "keyboard_interrupt_after_terminal":
            launcher.returncode = 0
            raise KeyboardInterrupt("stream cancellation")
        released = launcher.release_for_exec(
            request,
            deadline=kwargs["execution_deadline"],
            clock=kwargs["clock"],
        )
        if not released:
            launcher.abort_and_reap()
            return runner_worker._negative_settlement(
                request_id=request.request_id,
                worker_pid=WORKER_PID,
                terminal=protocol.ExecutionTerminal.LAUNCH_FAILED,
                detail="exec_release",
                process_group_settled=True,
            )
        try:
            kwargs["on_started"]()
        except BaseException:
            launcher.abort_and_reap()
            raise
        events.append("stream_settled")
        return _complete_settlement(request, launcher)

    monkeypatch.setattr(runner_worker, "decode_request", decode_request)
    monkeypatch.setattr(runner_worker, "decode_command", decode_command)
    monkeypatch.setattr(runner_worker.runner_ipc, "write_all", write_control)
    monkeypatch.setattr(
        runner_worker, "_spawn_execution_launcher", spawn,
    )
    monkeypatch.setattr(
        runner_worker, "_run_stream_engine", stream_engine, raising=False,
    )


def _exchange(
    monkeypatch,
    *,
    command_factory=_command,
    stdin_data=DATA,
    wire_stdin_data=None,
    launcher=None,
    stream_behavior="complete",
    timeout=30,
    trailing=b"",
):
    invocation = _invocation(timeout=timeout)
    request = invocation.worker
    events = []
    launcher = (
        _FakeExecutionLauncher(events=events)
        if launcher is None else launcher
    )
    launcher.events = events
    stream_calls = []
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    try:
        command = (
            command_factory(request)
            if callable(command_factory) else command_factory
        )
        wire = protocol.encode_request(request)
        if wire_stdin_data is not None:
            wire += wire_stdin_data
        if command is not None:
            wire += protocol.encode_command(command)
        wire += trailing
        runner_ipc.write_all(request_write, wire)
        os.close(request_write)
        request_write = -1

        monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
        monkeypatch.setattr(runner_worker.os, "getpid", lambda: WORKER_PID)
        _install_execution_fakes(
            monkeypatch,
            launcher,
            events=events,
            stream_behavior=stream_behavior,
            stream_calls=stream_calls,
        )
        returncode = runner_worker._run_worker(
            request_read,
            control_write,
            expected_parent_pid=8001,
            stdout_fd=81,
            stderr_fd=82,
            execution=True,
            stdin_data=stdin_data,
            stdin_file_fd=None,
        )
        os.close(control_write)
        control_write = -1
        records = _frame_records(control_read)
        return request, returncode, records, launcher, stream_calls, events
    finally:
        os.close(request_read)
        os.close(control_read)
        if request_write >= 0:
            os.close(request_write)
        if control_write >= 0:
            os.close(control_write)


def test_execution_reads_exact_data_payload_before_command(monkeypatch):
    request, returncode, records, _launcher, stream_calls, events = _exchange(
        monkeypatch,
        stdin_data=None,
        wire_stdin_data=DATA,
    )

    assert returncode == 0
    assert tuple(type(record) for record in records) == (
        protocol.ReadyFrame,
        protocol.PreparedFrame,
        protocol.StartedFrame,
        protocol.WorkerSettlement,
    )
    assert stream_calls[0][2]["stdin_data"] == DATA
    assert events.index("request_decoded") < events.index("ReadyFrame")
    assert events.index("ReadyFrame") < events.index("command_decoded")


def test_execution_rejects_truncated_data_payload_before_ready(monkeypatch):
    request, returncode, records, launcher, stream_calls, events = _exchange(
        monkeypatch,
        command_factory=None,
        stdin_data=None,
        wire_stdin_data=DATA[:-1],
    )

    assert request.stdin_bytes == len(DATA)
    assert returncode == runner_worker._EXIT_BOOTSTRAP_INVALID
    assert records == ()
    assert stream_calls == []
    assert "ReadyFrame" not in events
    assert launcher.reap_calls == 1


def test_execution_go_is_exactly_ordered_and_streams_own_stage_descriptors(
        monkeypatch):
    request, returncode, records, launcher, stream_calls, events = _exchange(
        monkeypatch,
    )
    assert returncode == 0
    assert tuple(type(record) for record in records) == (
        protocol.ReadyFrame,
        protocol.PreparedFrame,
        protocol.StartedFrame,
        protocol.WorkerSettlement,
    )
    transcript = protocol.validate_control_sequence(records)
    assert transcript.ready == protocol.ReadyFrame(
        request.request_id, WORKER_PID, protocol.request_digest(request),
    )
    assert transcript.prepared == _prepared(request)
    assert transcript.started == protocol.StartedFrame(
        request_id=request.request_id,
        worker_pid=WORKER_PID,
        tool_pid=launcher.pid,
        tool_pgid=launcher.pgid,
        containment_kind=protocol.ContainmentKind.CGROUP_V2,
        containment_id=f"direct/quarry-{request.request_id}",
    )
    assert transcript.settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert transcript.settlement.exit_code == 0

    assert events.index("launcher_spawned") < events.index("request_decoded")
    assert events.index("stop_proved") < events.index("PreparedFrame")
    assert events.index("command_decoded") < events.index("release")
    assert events.index("release") < events.index("StartedFrame")
    assert events.index("StartedFrame") < events.index("stream_settled")
    assert events.index("stream_settled") < events.index("WorkerSettlement")

    assert launcher.release_calls[0][0] == request
    assert launcher.reap_calls == 0
    assert len(stream_calls) == 1
    stream_request, stream_launcher, kwargs = stream_calls[0]
    assert stream_request is launcher.release_calls[0][0]
    assert stream_request == request and stream_launcher is launcher
    assert kwargs["stdin_data"] == DATA
    assert kwargs["stdin_file_fd"] is None
    assert kwargs["stdout_stage_fd"] == 81
    assert kwargs["stderr_stage_fd"] == 82
    assert callable(kwargs["on_started"])


def test_execution_keeps_fast_child_unreaped_until_parent_started_eof(
        monkeypatch):
    invocation = _invocation()
    request = invocation.worker
    events = []
    launcher = _FakeExecutionLauncher(events=events)
    stream_calls = []
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    result = {}
    try:
        runner_ipc.write_all(
            request_write,
            protocol.encode_request(request)
            + protocol.encode_command(_command(request)),
        )
        monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
        monkeypatch.setattr(runner_worker.os, "getpid", lambda: WORKER_PID)
        _install_execution_fakes(
            monkeypatch,
            launcher,
            events=events,
            stream_calls=stream_calls,
        )

        def run_worker():
            result["returncode"] = runner_worker._run_worker(
                request_read,
                control_write,
                expected_parent_pid=8001,
                stdout_fd=81,
                stderr_fd=82,
                execution=True,
                stdin_data=DATA,
                stdin_file_fd=None,
            )

        thread = threading.Thread(target=run_worker, daemon=True)
        thread.start()
        decoder = runner_ipc.IncrementalFrameDecoder(protocol.MAX_FRAME_BYTES)
        records = []
        while len(records) < 3:
            records.extend(
                protocol.decode_control_frame(frame)
                for frame in decoder.feed(os.read(control_read, 65536))
            )
        assert tuple(type(record) for record in records) == (
            protocol.ReadyFrame,
            protocol.PreparedFrame,
            protocol.StartedFrame,
        )
        assert thread.is_alive()
        assert launcher.reap_calls == 0
        assert "stream_settled" not in events

        os.close(request_write)
        request_write = -1
        thread.join(1)
        assert not thread.is_alive()
        assert result == {"returncode": 0}
        assert "stream_settled" in events
    finally:
        for fd in (request_read, request_write, control_read, control_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def test_execution_rejects_trailing_bytes_after_go_at_started_barrier(
        monkeypatch):
    request = _invocation().worker

    def command_with_trailing_bytes(observed):
        return _command(observed)

    events = []
    launcher = _FakeExecutionLauncher(events=events)
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    try:
        runner_ipc.write_all(
            request_write,
            protocol.encode_request(request)
            + protocol.encode_command(command_with_trailing_bytes(request))
            + b"trailing-control-byte",
        )
        os.close(request_write)
        request_write = -1
        monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
        monkeypatch.setattr(runner_worker.os, "getpid", lambda: WORKER_PID)
        _install_execution_fakes(monkeypatch, launcher, events=events)
        returncode = runner_worker._run_worker(
            request_read,
            control_write,
            expected_parent_pid=8001,
            stdout_fd=81,
            stderr_fd=82,
            execution=True,
            stdin_data=DATA,
            stdin_file_fd=None,
        )
        os.close(control_write)
        control_write = -1
        records = _frame_records(control_read)

        assert returncode == runner_worker._EXIT_CONTROL_FAILED
        assert tuple(type(record) for record in records) == (
            protocol.ReadyFrame,
            protocol.PreparedFrame,
            protocol.StartedFrame,
        )
        assert launcher.reap_calls == 1
        assert "stream_settled" not in events
    finally:
        for fd in (request_read, request_write, control_read, control_write):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def test_timeout_zero_defers_settlement_deadline_until_natural_exit(monkeypatch):
    request, returncode, records, _launcher, stream_calls, _events = _exchange(
        monkeypatch, timeout=0,
    )

    assert returncode == 0
    assert records[-1].terminal is protocol.ExecutionTerminal.COMPLETE
    assert request.timeout == 0
    kwargs = stream_calls[0][2]
    assert kwargs["execution_deadline"] is None
    assert kwargs["settlement_deadline"] is None


def test_network_cleanup_fault_does_not_replace_stream_cancellation(monkeypatch):
    def cleanup_fault(*_args, **_kwargs):
        raise RuntimeError("network cleanup failed")

    monkeypatch.setattr(runner_worker, "_settle_network_broker", cleanup_fault)
    with pytest.raises(KeyboardInterrupt, match="stream cancellation"):
        _exchange(
            monkeypatch,
            stream_behavior="keyboard_interrupt_after_terminal",
        )


@pytest.mark.parametrize(
    ("command_factory", "terminal", "detail"),
    [
        (
            lambda request: _command(
                request, protocol.WorkerCommandKind.ABORT,
            ),
            protocol.ExecutionTerminal.CANCELLED,
            "parent_abort",
        ),
        (
            lambda request: replace(
                _command(request), prepared_sha256="b3" * 32,
            ),
            protocol.ExecutionTerminal.WORKER_FAILED,
            "command_mismatch",
        ),
        (
            lambda request: replace(
                _command(request), request_sha256="b4" * 32,
            ),
            protocol.ExecutionTerminal.WORKER_FAILED,
            "command_mismatch",
        ),
        (
            None,
            protocol.ExecutionTerminal.WORKER_FAILED,
            "command_invalid",
        ),
    ],
    ids=["abort", "prepared-digest", "request-digest", "no-command"],
)
def test_abort_mismatch_and_missing_go_never_release_or_start(
        monkeypatch, command_factory, terminal, detail):
    _request_record, returncode, records, launcher, stream_calls, _events = _exchange(
        monkeypatch, command_factory=command_factory,
    )
    assert returncode in (0, runner_worker._EXIT_CONTROL_FAILED)
    assert tuple(type(record) for record in records) == (
        protocol.ReadyFrame,
        protocol.PreparedFrame,
        protocol.WorkerSettlement,
    )
    assert records[-1].terminal is terminal
    assert records[-1].detail == detail
    assert records[-1].launched is False
    assert launcher.release_calls == []
    assert launcher.reap_calls == 1
    assert stream_calls == []


@pytest.mark.parametrize("kind", [
    protocol.WorkerCommandKind.ABORT,
    protocol.WorkerCommandKind.GO,
])
def test_negative_or_mismatched_command_rejects_trailing_bytes_before_launch(
        monkeypatch, kind):
    def command(request):
        observed = _command(request, kind)
        if kind is protocol.WorkerCommandKind.GO:
            observed = replace(observed, request_sha256="c7" * 32)
        return observed

    _request, returncode, records, launcher, streams, _events = _exchange(
        monkeypatch,
        command_factory=command,
        trailing=b"unexpected-trailing-command",
    )

    assert returncode == runner_worker._EXIT_CONTROL_FAILED
    assert records[-1].terminal is protocol.ExecutionTerminal.WORKER_FAILED
    assert records[-1].detail == "command_invalid"
    assert records[-1].launched is False
    assert launcher.release_calls == []
    assert launcher.reap_calls == 1
    assert streams == []


def test_exec_failure_emits_no_started_and_returns_typed_launch_failure(monkeypatch):
    launcher = _FakeExecutionLauncher(release_result=False)
    _request_record, returncode, records, launcher, stream_calls, events = _exchange(
        monkeypatch, launcher=launcher,
    )
    assert returncode == 0
    assert tuple(type(record) for record in records) == (
        protocol.ReadyFrame,
        protocol.PreparedFrame,
        protocol.WorkerSettlement,
    )
    settlement = records[-1]
    assert settlement.terminal is protocol.ExecutionTerminal.LAUNCH_FAILED
    assert settlement.launched is False and settlement.tool_pid is None
    assert settlement.detail == "exec_release"
    assert launcher.release_calls and launcher.reap_calls == 1
    assert len(stream_calls) == 1
    assert "StartedFrame" not in events


@pytest.mark.parametrize("wrong", [DATA[:-1], b"X" + DATA[1:]], ids=["size", "digest"])
def test_data_payload_mismatch_is_rejected_before_readiness(monkeypatch, wrong):
    _request_record, returncode, records, launcher, calls, events = _exchange(
        monkeypatch,
        stdin_data=wrong,
    )
    assert returncode == runner_worker._EXIT_BOOTSTRAP_INVALID
    assert records == ()
    assert launcher.release_calls == []
    assert launcher.reap_calls == 1
    assert calls == []
    assert not any(
        name in events
        for name in ("ReadyFrame", "PreparedFrame", "StartedFrame")
    )


def test_execution_mode_is_explicit_canonical_and_one_shot(monkeypatch):
    assert runner_worker.EXECUTION_ENV == EXECUTION_ENV
    monkeypatch.delenv(EXECUTION_ENV, raising=False)
    assert runner_worker._pop_execution_mode() is False
    assert EXECUTION_ENV not in os.environ

    monkeypatch.setenv(EXECUTION_ENV, "1")
    assert runner_worker._pop_execution_mode() is True
    assert EXECUTION_ENV not in os.environ


@pytest.mark.parametrize(
    "value",
    ["", "0", "01", "+1", " 1", "1 ", "true", "target-secret"],
)
def test_execution_mode_rejects_noncanonical_values_without_reflection(
        monkeypatch, value):
    monkeypatch.setenv(EXECUTION_ENV, value)
    with pytest.raises(RuntimeError, match="^worker_metadata_invalid$") as error:
        runner_worker._pop_execution_mode()
    if value:
        assert value not in str(error.value)
    assert EXECUTION_ENV not in os.environ


def test_execution_dispatch_is_additive_and_passes_private_stream_ownership(
        monkeypatch):
    calls = []
    monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
    monkeypatch.setattr(runner_worker.os, "getpid", lambda: WORKER_PID)
    monkeypatch.setattr(
        runner_worker,
        "_run_execution_worker",
        lambda *args, **kwargs: calls.append((args, kwargs)) or 73,
        raising=False,
    )
    monkeypatch.setattr(
        runner_worker,
        "_run_prepared_abort_worker",
        lambda *_args, **_kwargs: pytest.fail("execution dispatched abort worker"),
    )
    assert runner_worker._run_worker(
        10,
        11,
        expected_parent_pid=8001,
        stdout_fd=81,
        stderr_fd=82,
        execution=True,
        stdin_data=DATA,
        stdin_file_fd=None,
    ) == 73
    assert calls == [(
        (10, 11, WORKER_PID),
        {
            "stdout_fd": 81,
            "stderr_fd": 82,
            "stdin_data": DATA,
            "stdin_file_fd": None,
        },
    )]


def test_execution_and_abort_modes_are_mutually_exclusive(monkeypatch):
    monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
    with pytest.raises(RuntimeError, match="^worker_metadata_invalid$"):
        runner_worker._run_worker(
            10,
            11,
            expected_parent_pid=8001,
            prepared_abort=True,
            execution=True,
        )


def test_execution_arguments_extend_the_existing_worker_call_shape():
    signature = inspect.signature(runner_worker._run_worker)
    assert tuple(signature.parameters)[:3] == (
        "request_fd", "control_fd", "expected_parent_pid",
    )
    for name, default in (
        ("execution", False),
        ("stdin_data", None),
        ("stdin_file_fd", None),
    ):
        parameter = signature.parameters[name]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is default
