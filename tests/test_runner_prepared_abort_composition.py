"""Red contract for the parked PREPARED -> ABORT worker composition slice."""
from __future__ import annotations

import hashlib
import inspect
import os
import signal
import sys
import time
from dataclasses import replace

import pytest

from quarry_recon import runner_ipc
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_worker


pytestmark = pytest.mark.offline

RID = "a1" * 16
WORKER_PID = 44001
LAUNCHER_PID = 44002
PREPARED_ABORT_ENV = "QUARRY_RUNNER_PREPARED_ABORT"
STDOUT_FD_ENV = "QUARRY_RUNNER_STDOUT_FD"
STDERR_FD_ENV = "QUARRY_RUNNER_STDERR_FD"


def _request():
    return protocol.normalize_invocation(
        request_id=RID,
        tool="fixture",
        cmd=["tool-must-never-exec", "target-secret"],
        timeout=30,
        env={"TOKEN": "environment-secret"},
        base_environment={"PATH": "/usr/bin"},
        raw_path="/tmp/quarry-prepared-abort.stdout",
        stderr_path="/tmp/quarry-prepared-abort.stderr",
    ).worker


def _prepared(**overrides):
    values = {
        "request_id": RID,
        "worker_pid": WORKER_PID,
        "launcher_pid": LAUNCHER_PID,
        "launcher_pgid": LAUNCHER_PID,
        "containment_kind": protocol.ContainmentKind.CGROUP_V2,
        "containment_id": f"direct/quarry-{RID}",
    }
    values.update(overrides)
    return protocol.PreparedFrame(**values)


def _command(kind=protocol.WorkerCommandKind.ABORT, **overrides):
    prepared = _prepared()
    values = {
        "request_id": RID,
        "request_sha256": protocol.request_digest(_request()),
        "prepared_sha256": protocol.prepared_digest(prepared),
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


def _assert_not_started_abort(records, *, launcher_pid: int):
    ready, prepared, settlement = records
    assert type(ready) is protocol.ReadyFrame
    assert type(prepared) is protocol.PreparedFrame
    assert prepared.launcher_pid == launcher_pid
    assert settlement.terminal is protocol.ExecutionTerminal.CANCELLED
    assert settlement.detail == "parent_abort"
    assert settlement.launched is False and settlement.tool_pid is None
    assert settlement.exit_code is None
    assert settlement.process_group_settled is True
    assert settlement.process_tree_settled is False
    assert tuple(stream.role for stream in settlement.streams) == tuple(
        protocol.StreamRole
    )
    assert all(
        stream.terminal is protocol.StreamTerminal.NOT_STARTED
        and stream.observed_bytes == stream.retained_bytes == 0
        and stream.observed_sha256 is None
        and stream.retained_sha256 is None
        and stream.claim_id is None
        for stream in settlement.streams
    )


def test_prepared_digest_is_canonical_and_domain_bound():
    prepared = _prepared()
    digest = protocol.prepared_digest(prepared)
    assert digest == hashlib.sha256(
        b"quarry-runner-prepared-v1\0" + protocol.encode_prepared(prepared)
    ).hexdigest()
    assert digest == protocol.prepared_digest(
        protocol.decode_prepared(protocol.encode_prepared(prepared))
    )
    assert digest != hashlib.sha256(protocol.encode_prepared(prepared)).hexdigest()
    for field, value in (
        ("request_id", "a2" * 16),
        ("worker_pid", WORKER_PID + 10),
        ("launcher_pid", LAUNCHER_PID + 10),
        ("containment_id", "other-containment"),
    ):
        changes = {field: value}
        if field == "launcher_pid":
            changes["launcher_pgid"] = value
        assert protocol.prepared_digest(replace(prepared, **changes)) != digest


def test_worker_command_prepared_binding_is_required_only_after_prepared():
    ready_abort = protocol.WorkerCommand(
        request_id=RID,
        request_sha256=protocol.request_digest(_request()),
        prepared_sha256=None,
        worker_pid=WORKER_PID,
        command=protocol.WorkerCommandKind.ABORT,
    )
    assert ready_abort.prepared_sha256 is None
    assert protocol.decode_command(protocol.encode_command(ready_abort)) == ready_abort

    prepared = _prepared()
    command = _command()
    assert command.prepared_sha256 == protocol.prepared_digest(prepared)
    assert protocol.decode_command(protocol.encode_command(command)) == command
    for missing in (None, "b2" * 32):
        changed = replace(command, prepared_sha256=missing)
        assert changed.prepared_sha256 != protocol.prepared_digest(prepared)
        assert protocol.decode_command(protocol.encode_command(changed)) == changed


class _FakeLauncher:
    def __init__(self, *, pid=LAUNCHER_PID, stopped=True):
        self.pid = pid
        self.pgid = pid
        self.stopped = stopped
        self.stage_fds_closed = False
        self.control_fds_closed = False
        self.release_read_closed = False
        self.release_write_closed = False
        self.resumed = 0
        self.executed = 0
        self.reap_calls = 0
        self.returncode = None

    def close_inherited_before_stop(self):
        self.stage_fds_closed = True
        self.control_fds_closed = True

    def prove_stopped(self):
        assert self.stage_fds_closed and self.control_fds_closed
        return self.stopped

    def resume(self):
        self.resumed += 1
        self.executed += 1

    def stray_sigcont(self):
        self.resumed += 1
        # Scheduling state is not release authority.  No pipe token means no
        # exec, regardless of an unrelated SIGCONT.

    def abort_and_reap(self):
        self.reap_calls += 1
        self.release_write_closed = True
        self.release_read_closed = True
        self.returncode = -signal.SIGKILL
        return self.returncode


def _parked_exchange(monkeypatch, *, command_factory=_command, trailing=b"",
                     launcher=None, spawn_observer=None):
    request = _request()
    launcher = _FakeLauncher() if launcher is None else launcher
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    try:
        command = command_factory() if callable(command_factory) else command_factory
        wire = protocol.encode_request(request)
        if command is not None:
            wire += protocol.encode_command(command)
        wire += trailing
        runner_ipc.write_all(request_write, wire)
        os.close(request_write)
        request_write = -1
        monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
        monkeypatch.setattr(runner_worker.os, "getpid", lambda: WORKER_PID)

        def fake_spawn(*args, **kwargs):
            launcher.spawn_arguments = (args, kwargs)
            if spawn_observer is not None:
                spawn_observer(args, kwargs)
            launcher.close_inherited_before_stop()
            return launcher

        monkeypatch.setattr(
            runner_worker, "_spawn_parked_launcher", fake_spawn,
        )
        returncode = runner_worker._run_worker(
            request_read, control_write, expected_parent_pid=8001,
            stdout_fd=81, stderr_fd=82,
        )
        os.close(control_write)
        control_write = -1
        return returncode, _frame_records(control_read), launcher
    finally:
        os.close(request_read)
        os.close(control_read)
        if request_write >= 0:
            os.close(request_write)
        if control_write >= 0:
            os.close(control_write)


def test_worker_testifies_prepared_only_after_launcher_stop_proof(monkeypatch):
    events = []
    launcher = _FakeLauncher()
    real_proof = launcher.prove_stopped

    def prove_stopped():
        events.append("sigstop_proved")
        return real_proof()

    launcher.prove_stopped = prove_stopped
    original_write = runner_worker.runner_ipc.write_all

    def record_control(fd, data):
        try:
            record = protocol.decode_control_frame(data)
        except protocol.ProtocolError:
            record = None
        if type(record) is protocol.PreparedFrame:
            events.append("prepared_written")
        original_write(fd, data)

    monkeypatch.setattr(runner_worker.runner_ipc, "write_all", record_control)
    returncode, records, launcher = _parked_exchange(
        monkeypatch, launcher=launcher,
    )
    assert returncode == 0
    assert events == ["sigstop_proved", "prepared_written"]
    assert launcher.stage_fds_closed and launcher.control_fds_closed
    _assert_not_started_abort(records, launcher_pid=launcher.pid)


def test_launcher_spawn_precedes_request_decode_and_receives_no_target_data(
        monkeypatch):
    events = []
    real_decode = runner_worker.decode_request

    def observe_spawn(args, kwargs):
        events.append("spawn")
        assert args == ()
        assert set(kwargs) == {
            "stdout_fd", "stderr_fd", "inherited_fds", "_owner",
        }
        assert kwargs["stdout_fd"] == 81
        assert kwargs["stderr_fd"] == 82
        inherited_fds = kwargs["inherited_fds"]
        assert (type(inherited_fds) is tuple and len(inherited_fds) == 2
                and all(type(fd) is int for fd in inherited_fds)
                and len(set(inherited_fds)) == 2)
        rendered = repr((args, kwargs))
        assert not any(
            secret in rendered
            for secret in (
                "tool-must-never-exec", "target-secret",
                "environment-secret", "TOKEN",
            )
        )
        assert not any(
            type(value) is protocol.WorkerRequest
            for value in args
        )
        assert not any(
            type(value) is protocol.WorkerRequest
            for value in kwargs.values()
        )

    def observe_decode(frame):
        events.append("decode_request")
        return real_decode(frame)

    monkeypatch.setattr(runner_worker, "decode_request", observe_decode)
    returncode, records, launcher = _parked_exchange(
        monkeypatch, spawn_observer=observe_spawn,
    )
    assert returncode == 0
    assert events[:2] == ["spawn", "decode_request"]
    assert launcher.reap_calls == 1 and launcher.executed == 0
    _assert_not_started_abort(records, launcher_pid=launcher.pid)


def test_prepared_abort_is_digest_bound_unlaunched_and_reaps_exact_launcher(
        monkeypatch):
    returncode, records, launcher = _parked_exchange(monkeypatch)
    assert returncode == 0
    _assert_not_started_abort(records, launcher_pid=launcher.pid)
    assert launcher.resumed == launcher.executed == 0
    assert launcher.reap_calls == 1
    assert launcher.returncode == -signal.SIGKILL
    assert launcher.release_read_closed and launcher.release_write_closed
    launcher.stray_sigcont()
    assert launcher.resumed == 1 and launcher.executed == 0


def test_failed_sigstop_proof_never_emits_prepared_or_accepts_command(monkeypatch):
    launcher = _FakeLauncher(stopped=False)
    returncode, records, launcher = _parked_exchange(
        monkeypatch, launcher=launcher,
    )
    assert returncode == runner_worker._EXIT_CONTROL_FAILED
    assert len(records) == 2
    assert type(records[0]) is protocol.ReadyFrame
    assert type(records[1]) is protocol.WorkerSettlement
    assert records[1].terminal is protocol.ExecutionTerminal.WORKER_FAILED
    assert records[1].launched is False
    assert launcher.resumed == launcher.executed == 0
    assert launcher.reap_calls == 1


@pytest.mark.parametrize("command_factory", [
    lambda: _command(protocol.WorkerCommandKind.GO),
    lambda: replace(_command(), request_id="a2" * 16),
    lambda: replace(_command(), request_sha256="b4" * 32),
    lambda: replace(_command(), worker_pid=WORKER_PID + 1),
    lambda: replace(_command(), prepared_sha256="b3" * 32),
])
def test_go_and_prepared_command_mismatches_never_resume_or_exec(
        monkeypatch, command_factory):
    returncode, records, launcher = _parked_exchange(
        monkeypatch, command_factory=command_factory,
    )
    assert returncode in (0, runner_worker._EXIT_CONTROL_FAILED)
    assert type(records[0]) is protocol.ReadyFrame
    assert type(records[1]) is protocol.PreparedFrame
    assert records[-1].terminal is protocol.ExecutionTerminal.WORKER_FAILED
    assert records[-1].launched is False
    if command_factory().command is protocol.WorkerCommandKind.GO:
        assert records[-1].detail == "go_refused"
    assert launcher.resumed == launcher.executed == 0
    assert launcher.reap_calls == 1


@pytest.mark.parametrize("mode", ["missing", "duplicate", "trailing", "malformed"])
def test_invalid_post_prepared_channels_never_resume_or_exec(monkeypatch, mode):
    command = _command()
    if mode == "missing":
        command_factory, trailing = None, b""
    elif mode == "duplicate":
        command_factory, trailing = command, protocol.encode_command(command)
    elif mode == "trailing":
        command_factory, trailing = command, b"x"
    else:
        command_factory, trailing = None, b"\x00\x00\x00\x01x"
    returncode, records, launcher = _parked_exchange(
        monkeypatch, command_factory=command_factory, trailing=trailing,
    )
    assert returncode == runner_worker._EXIT_CONTROL_FAILED
    assert type(records[0]) is protocol.ReadyFrame
    assert type(records[1]) is protocol.PreparedFrame
    assert records[-1].terminal is protocol.ExecutionTerminal.WORKER_FAILED
    assert records[-1].launched is False
    assert launcher.resumed == launcher.executed == 0
    assert launcher.reap_calls == 1


def test_out_of_order_command_reaps_predecoded_launcher_without_exec(monkeypatch):
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    spawn_calls = []
    launcher = _FakeLauncher()
    try:
        runner_ipc.write_all(request_write, protocol.encode_command(_command()))
        os.close(request_write)
        request_write = -1
        monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)

        def fake_spawn(*args, **kwargs):
            spawn_calls.append((args, kwargs))
            launcher.close_inherited_before_stop()
            return launcher

        monkeypatch.setattr(
            runner_worker, "_spawn_parked_launcher",
            fake_spawn,
        )
        assert runner_worker._run_worker(
            request_read, control_write, expected_parent_pid=8001,
            stdout_fd=81, stderr_fd=82,
        ) == runner_worker._EXIT_BOOTSTRAP_INVALID
        os.close(control_write)
        control_write = -1
        assert os.read(control_read, 1) == b""
        assert len(spawn_calls) == 1
        assert launcher.reap_calls == 1
        assert launcher.resumed == launcher.executed == 0
    finally:
        os.close(request_read)
        os.close(control_read)
        if request_write >= 0:
            os.close(request_write)
        if control_write >= 0:
            os.close(control_write)


@pytest.mark.parametrize("name", [STDOUT_FD_ENV, STDERR_FD_ENV])
@pytest.mark.parametrize("value", [
    None, "", "-1", "+12", " 12", "x", "01", str(protocol.MAX_PID + 1),
])
def test_output_fd_metadata_is_numeric_canonical_and_value_safe(
        monkeypatch, name, value):
    other = STDERR_FD_ENV if name == STDOUT_FD_ENV else STDOUT_FD_ENV
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)
    monkeypatch.setenv(other, "82" if other == STDERR_FD_ENV else "81")
    with pytest.raises(RuntimeError, match="worker_metadata_invalid") as error:
        runner_worker._consume_output_fd_metadata(
            _request(), request_fd=0, control_fd=1,
        )
    if value:
        assert value not in str(error.value)
    assert STDOUT_FD_ENV not in os.environ
    assert STDERR_FD_ENV not in os.environ


def test_output_fd_metadata_is_consumed_and_cleared(monkeypatch):
    monkeypatch.setenv(STDERR_FD_ENV, "82")
    monkeypatch.setenv(STDOUT_FD_ENV, "81")
    assert runner_worker._consume_output_fd_metadata(
        _request(), request_fd=0, control_fd=1,
    ) == (81, 82)
    assert STDOUT_FD_ENV not in os.environ
    assert STDERR_FD_ENV not in os.environ


def test_prepared_abort_mode_is_explicit_canonical_and_one_shot(monkeypatch):
    assert runner_worker.PREPARED_ABORT_ENV == PREPARED_ABORT_ENV
    monkeypatch.delenv(PREPARED_ABORT_ENV, raising=False)
    assert runner_worker._pop_prepared_abort_mode() is False
    assert PREPARED_ABORT_ENV not in os.environ

    monkeypatch.setenv(PREPARED_ABORT_ENV, "1")
    assert runner_worker._pop_prepared_abort_mode() is True
    assert PREPARED_ABORT_ENV not in os.environ


@pytest.mark.parametrize("value", [
    "", "0", "01", "+1", " 1", "1 ", "true", "environment-secret",
])
def test_prepared_abort_mode_rejects_noncanonical_values_without_reflection(
        monkeypatch, value):
    monkeypatch.setenv(PREPARED_ABORT_ENV, value)
    with pytest.raises(RuntimeError) as error:
        runner_worker._pop_prepared_abort_mode()
    assert str(error.value) == "worker_metadata_invalid"
    if value:
        assert value not in str(error.value)
    assert PREPARED_ABORT_ENV not in os.environ


def test_explicit_prepared_mode_dispatches_stage_free_request_to_parked_path(
        monkeypatch):
    calls = []
    monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
    monkeypatch.setattr(runner_worker.os, "getpid", lambda: WORKER_PID)

    def parked(*args, **kwargs):
        calls.append((args, kwargs))
        return 73

    monkeypatch.setattr(runner_worker, "_run_prepared_abort_worker", parked)
    assert runner_worker._run_worker(
        10, 11, expected_parent_pid=8001,
        stdout_fd=None, stderr_fd=None, prepared_abort=True,
    ) == 73
    assert calls == [(
        (10, 11, WORKER_PID),
        {"stdout_fd": None, "stderr_fd": None},
    )]


def test_explicit_false_preserves_stage_free_legacy_decode_path(monkeypatch):
    monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
    monkeypatch.setattr(runner_worker.os, "getpid", lambda: WORKER_PID)
    monkeypatch.setattr(
        runner_worker,
        "_run_prepared_abort_worker",
        lambda *_args, **_kwargs: pytest.fail("legacy path dispatched parked worker"),
    )
    # Invalid descriptors terminate at the legacy request decoder.  Reaching that
    # typed result proves explicit False did not select the parked transaction.
    assert runner_worker._run_worker(
        -1, -1, expected_parent_pid=8001,
        stdout_fd=None, stderr_fd=None, prepared_abort=False,
    ) == runner_worker._EXIT_BOOTSTRAP_INVALID


@pytest.mark.parametrize("value", [None, 0, 1, "1"])
def test_non_boolean_private_mode_is_rejected_before_dispatch(monkeypatch, value):
    monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
    monkeypatch.setattr(runner_worker.os, "getpid", lambda: WORKER_PID)
    monkeypatch.setattr(
        runner_worker,
        "_run_prepared_abort_worker",
        lambda *_args, **_kwargs: pytest.fail("invalid mode reached parked worker"),
    )
    with pytest.raises(RuntimeError, match="^worker_metadata_invalid$"):
        runner_worker._run_worker(
            10, 11, expected_parent_pid=8001, prepared_abort=value,
        )


def _request_with_outputs(*, stdout: bool, stderr: bool, stdin_file: bool = False):
    return protocol.normalize_invocation(
        request_id=RID,
        tool="fixture",
        cmd=["tool-must-never-exec"],
        timeout=30,
        input_file=("/tmp/quarry-prepared-abort.stdin" if stdin_file else None),
        raw_path=("/tmp/quarry-prepared-abort.stdout" if stdout else None),
        stderr_path=("/tmp/quarry-prepared-abort.stderr" if stderr else None),
        env={},
        base_environment={"PATH": "/usr/bin"},
    ).worker


def test_absent_output_metadata_preserves_legacy_no_output_request(monkeypatch):
    monkeypatch.delenv(STDOUT_FD_ENV, raising=False)
    monkeypatch.delenv(STDERR_FD_ENV, raising=False)
    assert runner_worker._consume_output_fd_metadata(
        _request_with_outputs(stdout=False, stderr=False),
        request_fd=0, control_fd=1,
    ) == (None, None)


@pytest.mark.parametrize(
    ("stdout", "stderr", "metadata", "expected"),
    [
        (True, False, {STDOUT_FD_ENV: "81"}, (81, None)),
        (False, True, {STDERR_FD_ENV: "82"}, (None, 82)),
        (True, True, {STDERR_FD_ENV: "82", STDOUT_FD_ENV: "81"}, (81, 82)),
    ],
)
def test_output_fd_metadata_follows_exact_claims_in_canonical_role_order(
        monkeypatch, stdout, stderr, metadata, expected):
    monkeypatch.delenv(STDOUT_FD_ENV, raising=False)
    monkeypatch.delenv(STDERR_FD_ENV, raising=False)
    for name, value in metadata.items():
        monkeypatch.setenv(name, value)
    assert runner_worker._consume_output_fd_metadata(
        _request_with_outputs(stdout=stdout, stderr=stderr),
        request_fd=0, control_fd=1,
    ) == expected
    assert STDOUT_FD_ENV not in os.environ
    assert STDERR_FD_ENV not in os.environ


@pytest.mark.parametrize(
    ("worker_request", "metadata"),
    [
        (_request_with_outputs(stdout=True, stderr=True),
         {STDOUT_FD_ENV: "81"}),
        (_request_with_outputs(stdout=True, stderr=True), {}),
        (_request_with_outputs(stdout=True, stderr=False),
         {STDOUT_FD_ENV: "81", STDERR_FD_ENV: "82"}),
        (_request_with_outputs(stdout=False, stderr=False),
         {STDOUT_FD_ENV: "81"}),
        (_request_with_outputs(stdout=True, stderr=True),
         {STDOUT_FD_ENV: "81", STDERR_FD_ENV: "81"}),
        (_request_with_outputs(stdout=True, stderr=True),
         {STDOUT_FD_ENV: "0", STDERR_FD_ENV: "82"}),
        (_request_with_outputs(stdout=True, stderr=True),
         {STDOUT_FD_ENV: "1", STDERR_FD_ENV: "82"}),
        (_request_with_outputs(stdout=True, stderr=True),
         {STDOUT_FD_ENV: "2", STDERR_FD_ENV: "82"}),
        (_request_with_outputs(stdout=True, stderr=True, stdin_file=True),
         {STDOUT_FD_ENV: "81", STDERR_FD_ENV: "82"}),
    ],
    ids=[
        "partial", "absent-required", "unexpected-stderr", "unexpected-output",
        "collision", "request-fd", "control-fd", "reserved-stderr",
        "stdin-file-refused",
    ],
)
def test_output_fd_metadata_rejects_claim_mismatch_and_aliases(
        monkeypatch, worker_request, metadata):
    monkeypatch.delenv(STDOUT_FD_ENV, raising=False)
    monkeypatch.delenv(STDERR_FD_ENV, raising=False)
    for name, value in metadata.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match="worker_metadata_invalid"):
        runner_worker._consume_output_fd_metadata(
            worker_request, request_fd=0, control_fd=1,
        )
    assert STDOUT_FD_ENV not in os.environ
    assert STDERR_FD_ENV not in os.environ


def test_existing_run_worker_call_shape_remains_accepted():
    signature = inspect.signature(runner_worker._run_worker)
    assert tuple(signature.parameters)[:3] == (
        "request_fd", "control_fd", "expected_parent_pid",
    )
    assert signature.parameters["stdout_fd"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["stderr_fd"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["prepared_abort"].kind \
        is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["prepared_abort"].default is False


def _proc_launcher_facts(pid: int):
    with open(f"/proc/{pid}/stat", "rb") as source:
        raw = source.read().decode("ascii")
    tail = raw[raw.rfind(")") + 2:].split()
    return {
        "state": tail[0],
        "ppid": int(tail[1]),
        "pgrp": int(tail[2]),
        "session": int(tail[3]),
        "start_time_ticks": int(tail[19]),
    }


def _proc_has_identity(pid: int, identity: tuple[int, int]) -> bool:
    for entry in os.listdir(f"/proc/{pid}/fd"):
        try:
            observed = os.stat(f"/proc/{pid}/fd/{entry}")
        except (FileNotFoundError, PermissionError):
            continue
        if (observed.st_dev, observed.st_ino) == identity:
            return True
    return False


@pytest.mark.integration
def test_real_linux_launcher_is_stopped_isolated_release_gated_and_exactly_reaped(
        monkeypatch, tmp_path):
    if sys.platform != "linux" or not os.path.isdir("/proc/self/fd"):
        pytest.skip("parked launcher authority requires Linux procfs")

    marker = tmp_path / "launcher-exec-marker"
    request = protocol.normalize_invocation(
        request_id="a3" * 16,
        tool="fixture",
        cmd=[
            sys.executable, "-c",
            ("from pathlib import Path; "
             f"Path({str(marker)!r}).write_bytes(b'executed')"),
        ],
        timeout=30,
        env={},
        base_environment={"PATH": "/usr/bin"},
    ).worker
    assert str(marker) in request.argv[-1]
    stage_read, stage_write = os.pipe()
    control_read, control_write = os.pipe()
    inherited = (stage_write, control_write)
    inherited_identities = tuple(
        (observed.st_dev, observed.st_ino)
        for observed in map(os.fstat, inherited)
    )
    real_waitpid = os.waitpid
    waits = []
    launcher = None

    def recording_waitpid(pid: int, flags: int):
        result = real_waitpid(pid, flags)
        waits.append((pid, flags, result))
        return result

    monkeypatch.setattr(runner_worker.os, "waitpid", recording_waitpid)
    try:
        launcher = runner_worker._spawn_parked_launcher(
            stdout_fd=None,
            stderr_fd=None,
            inherited_fds=inherited,
        )
        assert launcher.prove_stopped() is True
        pid = launcher.pid
        assert type(pid) is int and pid > 0
        facts = _proc_launcher_facts(pid)
        assert facts["state"] in ("T", "t")
        assert facts["ppid"] == os.getpid()
        assert facts["pgrp"] == facts["session"] == pid
        assert launcher.pgid == pid
        assert os.getpgid(pid) == os.getsid(pid) == pid
        assert launcher.start_time_ticks == facts["start_time_ticks"]
        assert any(
            waited_pid == pid
            and flags & os.WUNTRACED
            and result_pid == pid
            and os.WIFSTOPPED(status)
            for waited_pid, flags, (result_pid, status) in waits
        )
        assert all(
            not _proc_has_identity(pid, identity)
            for identity in inherited_identities
        )
        executable = os.stat(f"/proc/{pid}/exe")
        executable_identity = (executable.st_dev, executable.st_ino)

        # SIGCONT alone cannot authorize exec; the private release pipe still has
        # no token.  The launcher may become sleeping, but the marker must not exist.
        os.kill(pid, signal.SIGCONT)
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            if marker.exists():
                break
            facts = _proc_launcher_facts(pid)
            if facts["state"] not in ("T", "t"):
                time.sleep(0.05)
                break
            time.sleep(0.01)
        assert os.path.isdir(f"/proc/{pid}")
        assert not marker.exists()
        executable = os.stat(f"/proc/{pid}/exe")
        assert (executable.st_dev, executable.st_ino) == executable_identity

        assert launcher.abort_and_reap() == -signal.SIGKILL
        assert launcher.returncode == -signal.SIGKILL
        assert not os.path.exists(f"/proc/{pid}")
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        with pytest.raises(ProcessLookupError):
            os.killpg(pid, 0)
    finally:
        if launcher is not None and getattr(launcher, "returncode", None) is None:
            pid = launcher.pid
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                real_waitpid(pid, 0)
            except ChildProcessError:
                pass
        for fd in (stage_read, stage_write, control_read, control_write):
            try:
                os.close(fd)
            except OSError:
                pass
