"""Hermetic checks for the fixed, deliberately non-launching worker."""
from __future__ import annotations

import os

import pytest

from quarry_recon import runner_ipc
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_worker


pytestmark = pytest.mark.offline

RID = "71" * 16


def _request():
    return protocol.normalize_invocation(
        request_id=RID,
        tool="fixture",
        cmd=["tool-secret", "target-secret"],
        timeout=30,
        env={"TOKEN": "environment-secret"},
        base_environment={"PATH": "/usr/bin"},
    ).worker


def _exchange(monkeypatch, command, *, trailing=b""):
    request = _request()
    worker_pid = os.getpid()
    if callable(command):
        command = command(request)
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    try:
        payload = protocol.encode_request(request)
        if command is not None:
            payload += protocol.encode_command(command)
        payload += trailing
        runner_ipc.write_all(request_write, payload)
        os.close(request_write)
        request_write = -1

        armed = []
        monkeypatch.setattr(
            runner_worker,
            "_arm_parent_death",
            lambda expected: armed.append(expected),
        )
        returncode = runner_worker._run_worker(
            request_read, control_write, expected_parent_pid=8001,
        )
        os.close(control_write)
        control_write = -1

        decoder = runner_ipc.IncrementalFrameDecoder(protocol.MAX_FRAME_BYTES)
        frames = []
        while True:
            chunk = os.read(control_read, 65536)
            if not chunk:
                break
            frames.extend(decoder.feed(chunk))
        decoder.finish()
        return request, returncode, tuple(
            protocol.decode_control_frame(frame) for frame in frames
        ), armed
    finally:
        os.close(request_read)
        os.close(control_read)
        if request_write >= 0:
            os.close(request_write)
        if control_write >= 0:
            os.close(control_write)


def _command(kind):
    def construct(request):
        return protocol.WorkerCommand(
            request_id=request.request_id,
            request_sha256=protocol.request_digest(request),
            worker_pid=os.getpid(),
            command=kind,
        )
    return construct


def test_abort_completes_ready_negative_settlement_and_eof(monkeypatch):
    request, returncode, frames, armed = _exchange(
        monkeypatch, _command(protocol.WorkerCommandKind.ABORT),
    )
    assert armed == [8001]
    assert returncode == 0
    assert len(frames) == 2
    ready, settlement = frames
    assert ready == protocol.ReadyFrame(
        request.request_id, os.getpid(), protocol.request_digest(request),
    )
    assert settlement.terminal is protocol.ExecutionTerminal.CANCELLED
    assert settlement.launched is False and settlement.tool_pid is None
    assert settlement.detail == "parent_abort"
    assert settlement.process_group_settled is False
    assert settlement.process_tree_settled is False
    assert all(
        stream.terminal is protocol.StreamTerminal.NOT_STARTED
        for stream in settlement.streams
    )


def test_go_before_prepared_is_a_terminal_worker_failure(monkeypatch):
    _request_record, returncode, frames, _armed = _exchange(
        monkeypatch, _command(protocol.WorkerCommandKind.GO),
    )
    assert returncode == 0
    assert len(frames) == 2
    assert frames[1].terminal is protocol.ExecutionTerminal.WORKER_FAILED
    assert frames[1].detail == "go_before_prepared"
    assert frames[1].launched is False


@pytest.mark.parametrize("field,value", [
    ("request_id", "72" * 16),
    ("request_sha256", "b6" * 32),
    ("worker_pid", os.getpid() + 1),
])
def test_command_correlation_mismatch_is_terminal_and_nonlaunching(
    monkeypatch, field, value,
):
    def mismatched(request):
        command = _command(protocol.WorkerCommandKind.ABORT)(request)
        from dataclasses import replace
        return replace(command, **{field: value})

    _request_record, returncode, frames, _armed = _exchange(
        monkeypatch, mismatched,
    )
    assert returncode == 0
    assert frames[1].terminal is protocol.ExecutionTerminal.WORKER_FAILED
    assert frames[1].detail == "command_mismatch"
    assert frames[1].launched is False


def test_duplicate_command_is_rejected_as_trailing_channel_data(monkeypatch):
    request = _request()
    command = protocol.WorkerCommand(
        request_id=request.request_id,
        request_sha256=protocol.request_digest(request),
        worker_pid=os.getpid(),
        command=protocol.WorkerCommandKind.ABORT,
    )
    _request_record, returncode, frames, _armed = _exchange(
        monkeypatch, command, trailing=protocol.encode_command(command),
    )
    assert returncode == runner_worker._EXIT_CONTROL_FAILED
    assert frames[1].terminal is protocol.ExecutionTerminal.WORKER_FAILED
    assert frames[1].detail == "command_invalid"


def test_malformed_initial_request_emits_no_ready_or_settlement(monkeypatch):
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    try:
        runner_ipc.write_all(request_write, b"\x00\x00\x00\x01x")
        os.close(request_write)
        request_write = -1
        monkeypatch.setattr(runner_worker, "_arm_parent_death", lambda _pid: None)
        assert runner_worker._run_worker(
            request_read, control_write, expected_parent_pid=8001,
        ) == runner_worker._EXIT_BOOTSTRAP_INVALID
        os.close(control_write)
        control_write = -1
        assert os.read(control_read, 1) == b""
    finally:
        os.close(request_read)
        os.close(control_read)
        if request_write >= 0:
            os.close(request_write)
        if control_write >= 0:
            os.close(control_write)


class _FakePrctl:
    def __init__(self, result=0):
        self.argtypes = None
        self.restype = None
        self.result = result
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.result


def test_parent_death_signal_is_armed_before_parent_identity_recheck(monkeypatch):
    prctl = _FakePrctl()
    monkeypatch.setattr(runner_worker.sys, "platform", "linux")
    monkeypatch.setattr(runner_worker.ctypes, "CDLL", lambda *a, **kw: type(
        "Libc", (), {"prctl": prctl},
    )())
    monkeypatch.setattr(runner_worker.os, "getppid", lambda: 8123)
    runner_worker._arm_parent_death(8123)
    assert prctl.calls == [(
        runner_worker._PR_SET_PDEATHSIG,
        runner_worker.signal.SIGKILL,
        0, 0, 0,
    )]


def test_parent_change_after_pdeathsig_install_fails_closed(monkeypatch):
    prctl = _FakePrctl()
    monkeypatch.setattr(runner_worker.sys, "platform", "linux")
    monkeypatch.setattr(runner_worker.ctypes, "CDLL", lambda *a, **kw: type(
        "Libc", (), {"prctl": prctl},
    )())
    monkeypatch.setattr(runner_worker.os, "getppid", lambda: 9002)
    with pytest.raises(RuntimeError, match="worker_parent_changed"):
        runner_worker._arm_parent_death(9001)
    assert len(prctl.calls) == 1


@pytest.mark.parametrize("value", [None, "", "-1", "+12", " 12", "x", str(1 << 31)])
def test_expected_parent_pid_accepts_only_bounded_decimal_metadata(monkeypatch, value):
    if value is None:
        monkeypatch.delenv(runner_worker.EXPECTED_PARENT_PID_ENV, raising=False)
    else:
        monkeypatch.setenv(runner_worker.EXPECTED_PARENT_PID_ENV, value)
    with pytest.raises(RuntimeError, match="worker_parent_invalid") as error:
        runner_worker._expected_parent_pid()
    if value:
        assert value not in str(error.value)


def test_expected_parent_pid_accepts_pid_one(monkeypatch):
    monkeypatch.setenv(runner_worker.EXPECTED_PARENT_PID_ENV, "1")
    assert runner_worker._expected_parent_pid() == 1
