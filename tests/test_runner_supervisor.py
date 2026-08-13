"""Hermetic parent-side checks for the fixed worker bootstrap."""
from __future__ import annotations

import inspect
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import FrozenInstanceError, fields, replace
from types import SimpleNamespace

import pytest

from quarry_recon import runner_ipc
from quarry_recon import runner_containment as containment
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_supervisor as supervisor


pytestmark = pytest.mark.offline

RID = "81" * 16
FAKE_PID = 42001
FAKE_LAUNCHER_PID = 42002
PREPARED_ABORT_ENV = "QUARRY_RUNNER_PREPARED_ABORT"
SECRET_VALUES = ("secret-tool", "secret-target", "environment-secret")


@pytest.fixture(autouse=True)
def _acquire_fake_direct_containment(fake_direct_containment):
    """Keep parent-side protocol tests independent of host cgroup delegation."""
    return fake_direct_containment


@pytest.fixture(autouse=True)
def _authenticate_fake_parked_launcher(monkeypatch):
    """Give hermetic peers an independently authenticated parked identity."""
    monkeypatch.setattr(
        supervisor,
        "capture_parked_process_identity",
        lambda pid, parent: SimpleNamespace(
            process=SimpleNamespace(pid=pid),
            parent=parent,
            state="T",
        ),
        raising=False,
    )


def _request():
    return protocol.normalize_invocation(
        request_id=RID,
        tool="fixture",
        cmd=[SECRET_VALUES[0], SECRET_VALUES[1]],
        timeout=30,
        env={"TOKEN": SECRET_VALUES[2]},
        base_environment={"PATH": "/private/tool/path"},
    ).worker


def _staged_request():
    return protocol.normalize_invocation(
        request_id="83" * 16,
        tool="fixture",
        cmd=[SECRET_VALUES[0], SECRET_VALUES[1]],
        timeout=30,
        input_file="/private/stage/stdin",
        raw_path="/private/stage/stdout",
        stderr_path="/private/stage/stderr",
        env={"TOKEN": SECRET_VALUES[2]},
        base_environment={"PATH": "/private/tool/path"},
    ).worker


def _streams():
    return tuple(
        protocol.StreamSettlement(
            role=role,
            terminal=protocol.StreamTerminal.NOT_STARTED,
            observed_bytes=0,
            retained_bytes=0,
            observed_sha256=None,
            retained_sha256=None,
        )
        for role in protocol.StreamRole
    )


def _settlement(request, *, detail="parent_abort", terminal=None, **overrides):
    values = {
        "request_id": request.request_id,
        "terminal": terminal or protocol.ExecutionTerminal.CANCELLED,
        "launched": False,
        "exit_code": None,
        "process_group_settled": True,
        "process_tree_settled": False,
        "streams": _streams(),
        "worker_pid": FAKE_PID,
        "tool_pid": None,
        "detail": detail,
    }
    values.update(overrides)
    return protocol.WorkerSettlement(**values)


class _PipeChild:
    """Small Popen-shaped peer backed by real pipes and one fixture thread."""

    def __init__(self, handler, *, kill_hook=None):
        command_read, parent_write = os.pipe()
        parent_read, control_write = os.pipe()
        self.stdin = os.fdopen(parent_write, "wb", buffering=0)
        self.stdout = os.fdopen(parent_read, "rb", buffering=0)
        self.pid = FAKE_PID
        self.returncode = None
        self._handler_result = None
        self._forced_returncode = None
        self.killed = False
        self.kill_calls = 0
        self.wait_timeouts = []
        self._kill_hook = kill_hook
        self._command_read = command_read
        self._control_write = control_write

        def target():
            try:
                self._handler_result = handler(command_read, control_write)
            except BaseException:
                self._handler_result = 91
            finally:
                for fd in (command_read, control_write):
                    try:
                        os.close(fd)
                    except OSError:
                        pass

        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise subprocess.TimeoutExpired("fixed-worker", timeout)
        if self.returncode is None:
            self.returncode = (
                self._forced_returncode
                if self._forced_returncode is not None
                else self._handler_result
            )
        return self.returncode

    def kill(self):
        self.kill_calls += 1
        self.killed = True
        if self._kill_hook is not None:
            self._kill_hook()
        for fd in (self._command_read, self._control_write):
            try:
                os.close(fd)
            except OSError:
                pass
        if self.returncode is None:
            self._forced_returncode = -9


class _FailingFileno:
    def __init__(self, pipe):
        self._pipe = pipe

    @property
    def closed(self):
        return self._pipe.closed

    def fileno(self):
        raise OSError("injected fileno failure")

    def close(self):
        self._pipe.close()


class _CloseFaultPipe:
    def __init__(self, pipe):
        self._pipe = pipe
        self.close_calls = 0

    @property
    def closed(self):
        return self._pipe.closed

    def fileno(self):
        return self._pipe.fileno()

    def close(self):
        self.close_calls += 1
        # Release the real descriptor while reporting a close failure.  This lets
        # the fake worker reach a terminal state without letting the supervisor
        # claim that its parent-side close completed cleanly.
        self._pipe.close()
        raise OSError("injected parent pipe close failure")


class _CountingClosePipe:
    def __init__(self, pipe):
        self._pipe = pipe
        self.close_calls = 0

    @property
    def closed(self):
        return self._pipe.closed

    def fileno(self):
        return self._pipe.fileno()

    def close(self):
        self.close_calls += 1
        self._pipe.close()


class _CancellingClosePipe:
    def __init__(self, pipe, cancellation, mode):
        self._pipe = pipe
        self._cancellation = cancellation
        self._mode = mode
        self.close_calls = 0

    @property
    def closed(self):
        return self._pipe.closed

    def fileno(self):
        return self._pipe.fileno()

    def close(self):
        self.close_calls += 1
        if self._mode == "before_once" and self.close_calls == 1:
            raise self._cancellation
        if self._mode == "after_once" and self.close_calls == 1:
            self._pipe.close()
            raise self._cancellation
        if self._mode == "persistent":
            raise self._cancellation
        self._pipe.close()

    def force_close(self):
        self._pipe.close()


class _SelectorProxy:
    def __init__(self, inner, fault):
        self._inner = inner
        self._fault = fault

    def register(self, *args, **kwargs):
        if self._fault == "register":
            raise OSError("injected register failure")
        return self._inner.register(*args, **kwargs)

    def unregister(self, *args, **kwargs):
        if self._fault == "unregister":
            raise OSError("injected unregister failure")
        return self._inner.unregister(*args, **kwargs)

    def select(self, *args, **kwargs):
        if self._fault == "select":
            raise OSError("injected select failure")
        return self._inner.select(*args, **kwargs)

    def close(self):
        self._inner.close()
        if self._fault == "close":
            raise OSError("injected selector close failure")


def _ready(request):
    return protocol.ReadyFrame(
        request_id=request.request_id,
        worker_pid=FAKE_PID,
        request_sha256=protocol.request_digest(request),
    )


def _prepared(request, **overrides):
    values = {
        "request_id": request.request_id,
        "worker_pid": FAKE_PID,
        "launcher_pid": FAKE_LAUNCHER_PID,
        "launcher_pgid": FAKE_LAUNCHER_PID,
        "containment_kind": protocol.ContainmentKind.CGROUP_V2,
        "containment_id": f"direct/quarry-{request.request_id}",
    }
    values.update(overrides)
    return protocol.PreparedFrame(**values)


def _read_prepared_abort(command_fd, request, prepared):
    command = protocol.decode_command(runner_ipc.read_frame(
        command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
    ))
    runner_ipc.require_eof(command_fd)
    assert command == protocol.WorkerCommand(
        request_id=request.request_id,
        request_sha256=protocol.request_digest(request),
        worker_pid=FAKE_PID,
        command=protocol.WorkerCommandKind.ABORT,
        prepared_sha256=protocol.prepared_digest(prepared),
    )
    return command


def _honest_abort_peer(command_fd, control_fd):
    request = protocol.decode_request(runner_ipc.read_frame(
        command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
    ))
    prepared = _prepared(request)
    # Coalescing is a normal pipe behavior.  The parent must consume both exact
    # frames before it decides whether a prepared-bound command is authorized.
    runner_ipc.write_all(
        control_fd,
        protocol.encode_ready(_ready(request))
        + protocol.encode_prepared(prepared),
    )
    _read_prepared_abort(command_fd, request, prepared)
    runner_ipc.write_all(
        control_fd, protocol.encode_settlement(_settlement(request)),
    )
    return 0


def _factory(monkeypatch, handler, calls):
    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=123456),
    )

    def make(argv, **kwargs):
        calls.append((argv, kwargs))
        return _PipeChild(handler)

    return make


def _run_unauthorized_peer(monkeypatch, control_wire_factory):
    """Run a peer that closes control and proves the parent wrote no command."""
    observed = []
    command_read_finished = threading.Event()
    child_box = []

    def peer(command_fd, control_fd):
        request = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        runner_ipc.write_all(control_fd, control_wire_factory(request))
        os.close(control_fd)
        try:
            observed.append(os.read(command_fd, 1))
        except OSError:
            observed.append(None)
        finally:
            command_read_finished.set()
        return 0

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=123456),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(
            peer, kill_hook=lambda: command_read_finished.wait(1),
        )
        child_box.append(child)
        return child

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2, popen_factory=factory,
    )
    assert command_read_finished.wait(1)
    assert observed == [b""]
    assert not outcome.abort_command_sent
    assert not outcome.transaction_complete
    assert outcome.worker_reaped
    return outcome


def test_bootstrap_public_signature_and_outcome_shape_remain_stable():
    signature = inspect.signature(supervisor.bootstrap_worker)
    assert tuple(signature.parameters) == (
        "request", "deadline", "clock", "popen_factory",
    )
    assert signature.parameters["request"].kind \
        is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert all(
        signature.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        for name in ("deadline", "clock", "popen_factory")
    )
    assert tuple(item.name for item in fields(supervisor.BootstrapOutcome)) == (
        "reason", "request_id", "worker_pid", "worker_start_time_ticks",
        "ready", "settlement", "worker_returncode", "worker_spawned",
        "worker_reaped", "control_eof", "observed_trailing_control_bytes",
        "abort_command_sent", "parent_pipes_closed", "kill_requested",
    )
    assert supervisor.BootstrapReason.CONTAINMENT_FAILED.value \
        == "containment_failed"


def test_supervisor_uses_only_the_fixed_isolated_spawn_shape(monkeypatch):
    request = _request()
    calls = []
    outcome = supervisor.bootstrap_worker(
        request,
        deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, _honest_abort_peer, calls),
    )
    assert outcome.reason is supervisor.BootstrapReason.ABORTED
    assert outcome.transaction_complete is True
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == [
        supervisor.sys.executable, "-I", "-m", "quarry_recon.runner_worker",
    ]
    assert kwargs == {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "start_new_session": True,
        "shell": False,
        "env": {
            supervisor.EXPECTED_PARENT_PID_ENV: str(os.getpid()),
            supervisor.PREPARED_ABORT_ENV: "1",
        },
        "bufsize": 0,
        "text": False,
        "cwd": "/",
    }
    assert supervisor.PREPARED_ABORT_ENV == PREPARED_ABORT_ENV
    rendered = repr(calls) + repr(outcome)
    assert "pass_fds" not in kwargs
    for secret in SECRET_VALUES:
        assert secret not in rendered


def test_prelaunch_abort_of_staged_request_transfers_no_stage_authority(
    monkeypatch,
):
    """Claims describe a future launch; ABORT must not require or transfer FDs."""
    calls = []
    request = _staged_request()
    outcome = supervisor.bootstrap_worker(
        request, deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, _honest_abort_peer, calls),
    )
    assert outcome.reason is supervisor.BootstrapReason.ABORTED
    assert outcome.settlement.launched is False
    assert all(
        stream.terminal is protocol.StreamTerminal.NOT_STARTED
        for stream in outcome.settlement.streams
    )
    argv, kwargs = calls[0]
    assert argv == [
        supervisor.sys.executable, "-I", "-m", "quarry_recon.runner_worker",
    ]
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["close_fds"] is True
    assert "pass_fds" not in kwargs
    assert set(kwargs["env"]) == {
        supervisor.EXPECTED_PARENT_PID_ENV,
        supervisor.PREPARED_ABORT_ENV,
    }
    rendered = repr(calls) + repr(outcome)
    assert "/private/stage/stdin" not in rendered
    assert "/private/stage/stdout" not in rendered
    assert "/private/stage/stderr" not in rendered
    for secret in SECRET_VALUES:
        assert secret not in rendered


def test_parent_acquires_binds_then_commands_exact_direct_containment(
    monkeypatch, fake_direct_containment,
):
    request = _request()
    fake_direct_containment.containment_id = "direct/parent-owned-leaf"
    proof_box = []

    def authenticate(pid, parent):
        proof = SimpleNamespace(
            process=SimpleNamespace(pid=pid), parent=parent, state="T",
        )
        proof_box.append(proof)
        return proof

    def peer(command_fd, control_fd):
        decoded = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        prepared = _prepared(
            decoded,
            containment_kind=fake_direct_containment.kind,
            containment_id=fake_direct_containment.containment_id,
        )
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(decoded))
            + protocol.encode_prepared(prepared),
        )
        _read_prepared_abort(command_fd, decoded, prepared)
        fake_direct_containment.events.append(("command_observed", None))
        runner_ipc.write_all(
            control_fd, protocol.encode_settlement(_settlement(decoded)),
        )
        return 0

    monkeypatch.setattr(
        supervisor, "capture_parked_process_identity", authenticate,
    )

    def factory(_argv, **_kwargs):
        fake_direct_containment.events.append(("spawn", None))
        return _PipeChild(peer)

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=123456),
    )
    outcome = supervisor.bootstrap_worker(
        request, deadline=time.monotonic() + 2, popen_factory=factory,
    )

    handle = fake_direct_containment.handle
    assert outcome.reason is supervisor.BootstrapReason.ABORTED
    assert fake_direct_containment.acquire_calls == [request.request_id]
    assert [
        event for event, _value in fake_direct_containment.events
        if event != "close"
    ] == [
        "acquire", "spawn", "bind", "command_observed", "settle",
    ]
    assert len(proof_box) == 1
    assert handle.bind_proofs == [proof_box[0]]
    assert handle.kind is protocol.ContainmentKind.CGROUP_V2
    assert handle.containment_id == "direct/parent-owned-leaf"
    assert len(handle.settlement_deadlines) == 1
    assert handle.terminal is True


@pytest.mark.parametrize(
    "acquire_exception",
    [
        containment.ContainmentUnsupported(
            containment.ContainmentReason.CGROUP_V2_MOUNT_MISSING,
        ),
        containment.ContainmentRefused(
            containment.ContainmentReason.DELEGATION_REFUSED,
        ),
    ],
    ids=("unsupported", "refused"),
)
def test_direct_containment_acquisition_refusal_is_unsupported_without_spawn(
    fake_direct_containment, acquire_exception,
):
    fake_direct_containment.acquire_exception = acquire_exception
    spawn_calls = []
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 1,
        popen_factory=lambda *args, **kwargs: spawn_calls.append((args, kwargs)),
    )

    assert fake_direct_containment.acquire_calls == [RID]
    assert fake_direct_containment.handles == []
    assert spawn_calls == []
    assert outcome.reason is supervisor.BootstrapReason.UNSUPPORTED
    assert not outcome.worker_spawned
    assert not outcome.transaction_complete


@pytest.mark.parametrize(
    "acquire_exception",
    [
        containment.ContainmentFailure(
            containment.ContainmentReason.LEAF_CREATE_FAILED,
        ),
        OSError("injected acquisition machinery failure"),
    ],
    ids=("typed", "os-error"),
)
def test_direct_containment_acquisition_machinery_failure_is_typed_without_spawn(
    fake_direct_containment, acquire_exception,
):
    fake_direct_containment.acquire_exception = acquire_exception
    spawn_calls = []

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 1,
        popen_factory=lambda *args, **kwargs: spawn_calls.append((args, kwargs)),
    )

    assert fake_direct_containment.acquire_calls == [RID]
    assert fake_direct_containment.handles == []
    assert spawn_calls == []
    assert outcome.reason is supervisor.BootstrapReason.CONTAINMENT_FAILED
    assert not outcome.worker_spawned
    assert not outcome.transaction_complete


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_direct_containment_acquisition_cancellation_is_exact_without_spawn(
    fake_direct_containment, cancellation_type,
):
    cancellation = cancellation_type("cancel containment acquisition")
    fake_direct_containment.acquire_exception = cancellation
    spawn_calls = []

    with pytest.raises(cancellation_type) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=time.monotonic() + 1,
            popen_factory=lambda *args, **kwargs: spawn_calls.append(
                (args, kwargs)
            ),
        )

    assert caught.value is cancellation
    assert fake_direct_containment.acquire_calls == [RID]
    assert fake_direct_containment.handles == []
    assert spawn_calls == []


@pytest.mark.parametrize("mode", ["unverified", "error"])
def test_parent_never_commands_when_exact_parked_binding_fails(
    monkeypatch, fake_direct_containment, mode,
):
    if mode == "unverified":
        fake_direct_containment.bind_result = containment.MembershipVerification(
            False, containment.ContainmentReason.PROCESS_CGROUP_MISMATCH,
        )
    else:
        fake_direct_containment.bind_exception = containment.ContainmentFailure(
            containment.ContainmentReason.BINDING_WRITE_FAILED,
        )

    outcome = _run_unauthorized_peer(
        monkeypatch,
        lambda request: (
            protocol.encode_ready(_ready(request))
            + protocol.encode_prepared(_prepared(request))
        ),
    )

    handle = fake_direct_containment.handle
    assert len(handle.bind_proofs) == 1
    assert not outcome.transaction_complete
    assert outcome.reason is supervisor.BootstrapReason.CONTAINMENT_FAILED
    assert outcome.abort_command_sent is False
    assert len(handle.settlement_deadlines) == 1
    assert handle.terminal is True


def test_binding_cancellation_sends_no_command_and_settles_containment(
    monkeypatch, fake_direct_containment,
):
    cancellation = KeyboardInterrupt("cancel exact parked binding")
    fake_direct_containment.bind_exception = cancellation
    observed = []
    command_read_finished = threading.Event()

    def peer(command_fd, control_fd):
        request = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(request))
            + protocol.encode_prepared(_prepared(request)),
        )
        os.close(control_fd)
        try:
            observed.append(os.read(command_fd, 1))
        except OSError:
            observed.append(None)
        finally:
            command_read_finished.set()
        return 0

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=123456),
    )

    def factory(_argv, **_kwargs):
        return _PipeChild(
            peer, kill_hook=lambda: command_read_finished.wait(1),
        )

    with pytest.raises(KeyboardInterrupt) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=time.monotonic() + 2, popen_factory=factory,
        )

    handle = fake_direct_containment.handle
    assert caught.value is cancellation
    assert command_read_finished.wait(1)
    assert observed == [b""]
    assert len(handle.bind_proofs) == 1
    assert len(handle.settlement_deadlines) == 1
    assert handle.terminal is True


@pytest.mark.parametrize("mode", ["unsettled", "error"])
def test_containment_settlement_must_be_exact_before_aborted_outcome(
    monkeypatch, fake_direct_containment, mode,
):
    if mode == "unsettled":
        fake_direct_containment.settlement_result = containment.ContainmentSettlement(
            True, False, False, containment.ContainmentReason.DEADLINE_EXPIRED,
        )
    else:
        fake_direct_containment.settlement_exception = (
            containment.ContainmentFailure(
                containment.ContainmentReason.KILL_FAILED,
            )
        )

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, _honest_abort_peer, []),
    )

    handle = fake_direct_containment.handle
    assert outcome.abort_command_sent is True
    assert outcome.worker_reaped
    assert outcome.reason is supervisor.BootstrapReason.CONTAINMENT_FAILED
    assert not outcome.transaction_complete
    assert len(handle.settlement_deadlines) == 1
    assert handle.close_calls == 1
    assert handle.terminal is True
    assert [event for event, _value in fake_direct_containment.events[-2:]] == [
        "settle", "close",
    ]


def test_containment_settlement_uses_trusted_real_monotonic_deadline(
    monkeypatch, fake_direct_containment,
):
    monkeypatch.setattr(supervisor, "_REAL_MONOTONIC", lambda: 1000.0)
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=150.0, clock=lambda: 100.0,
        popen_factory=_factory(monkeypatch, _honest_abort_peer, []),
    )

    assert outcome.reason is supervisor.BootstrapReason.ABORTED
    assert fake_direct_containment.handle.settlement_deadlines == [1050.0]
    assert fake_direct_containment.handle.terminal is True


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_containment_settlement_cancellation_reconciles_then_reraises_after_reap(
    monkeypatch, fake_direct_containment, cancellation_type,
):
    cancellation = cancellation_type("cancel first containment settlement entry")
    child_box = []
    acquire = supervisor.acquire_direct_cgroup_v2

    def acquire_with_one_shot_cancellation(request_id):
        handle = acquire(request_id)

        def settle(deadline):
            handle.settlement_deadlines.append(deadline)
            fake_direct_containment.events.append(("settle", deadline))
            if len(handle.settlement_deadlines) == 1:
                raise cancellation
            result = containment.ContainmentSettlement(
                True, True, True, containment.ContainmentReason.SETTLED,
            )
            handle.terminal = True
            return result

        handle.kill_settle_remove = settle
        return handle

    monkeypatch.setattr(
        supervisor, "acquire_direct_cgroup_v2",
        acquire_with_one_shot_cancellation,
    )
    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=123456),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(_honest_abort_peer)
        child_box.append(child)
        return child

    with pytest.raises(cancellation_type) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=time.monotonic() + 2,
            popen_factory=factory,
        )

    handle = fake_direct_containment.handle
    child = child_box[0]
    assert caught.value is cancellation
    assert len(handle.settlement_deadlines) == 2
    assert handle.close_calls == 0
    assert handle.terminal is True
    assert not child._thread.is_alive()
    assert child.returncode == 0


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_containment_fallback_close_cancellation_retries_then_reraises_after_reap(
    monkeypatch, fake_direct_containment, cancellation_type,
):
    cancellation = cancellation_type("cancel first containment close entry")
    child_box = []
    fake_direct_containment.settlement_result = containment.ContainmentSettlement(
        True, False, False, containment.ContainmentReason.DEADLINE_EXPIRED,
    )
    acquire = supervisor.acquire_direct_cgroup_v2

    def acquire_with_one_shot_close_cancellation(request_id):
        handle = acquire(request_id)

        def close():
            handle.close_calls += 1
            fake_direct_containment.events.append(("close", None))
            if handle.close_calls == 1:
                raise cancellation
            handle.terminal = True

        handle.close = close
        return handle

    monkeypatch.setattr(
        supervisor, "acquire_direct_cgroup_v2",
        acquire_with_one_shot_close_cancellation,
    )
    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=123456),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(_honest_abort_peer)
        child_box.append(child)
        return child

    with pytest.raises(cancellation_type) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=time.monotonic() + 2,
            popen_factory=factory,
        )

    handle = fake_direct_containment.handle
    child = child_box[0]
    assert caught.value is cancellation
    assert len(handle.settlement_deadlines) == 1
    assert handle.close_calls == 2
    assert handle.terminal is True
    assert not child._thread.is_alive()
    assert child.returncode == 0


def test_expired_cleanup_reaps_exact_worker_before_containment_settlement():
    events = []
    settled = containment.ContainmentSettlement(
        True, True, True, containment.ContainmentReason.SETTLED,
    )

    class Child:
        pid = FAKE_PID
        stdin = None
        stdout = None

        def __init__(self):
            self.returncode = None
            self.wait_calls = 0

        def poll(self):
            events.append(("poll", self.returncode))
            return self.returncode

        def kill(self):
            events.append(("kill", None))
            self.returncode = -signal.SIGKILL

        def wait(self, timeout=None):
            self.wait_calls += 1
            pytest.fail("an expired cleanup budget must not enter blocking wait")

    class Handle:
        def kill_settle_remove(self, deadline):
            events.append(("settle", deadline))
            assert owner.worker_reaped is True
            assert owner.worker_returncode == -signal.SIGKILL
            return settled

        def close(self):
            pytest.fail("a settled containment must not use fallback close")

    child = Child()
    owner = supervisor._BootstrapOwner(
        containment=Handle(), child=child, worker_spawned=True,
        worker_pid=FAKE_PID, failure=supervisor.BootstrapReason.DEADLINE,
    )
    real_deadline = supervisor._REAL_MONOTONIC() - 1

    supervisor._settle_owned_child(
        owner, deadline=10.0, clock=lambda: 11.0,
        real_deadline=real_deadline,
    )

    assert child.wait_calls == 0
    assert owner.worker_reaped is True
    assert owner.worker_returncode == -signal.SIGKILL
    assert owner.containment_terminal is True
    assert [event for event, _value in events] == ["poll", "kill", "poll", "settle"]


def test_ready_without_prepared_never_authorizes_parent_command(monkeypatch):
    outcome = _run_unauthorized_peer(
        monkeypatch,
        lambda request: protocol.encode_ready(_ready(request)),
    )
    assert outcome.reason is supervisor.BootstrapReason.CONTROL_FAILED
    assert outcome.ready == _ready(_request())


@pytest.mark.parametrize(
    "change",
    [
        {"request_id": "82" * 16},
        {"worker_pid": FAKE_PID + 7},
        {"containment_kind": protocol.ContainmentKind.PGID},
        {"containment_id": f"direct/quarry-{'82' * 16}"},
    ],
    ids=(
        "request", "worker", "containment-kind", "containment-id",
    ),
)
def test_untrusted_prepared_intent_never_authorizes_parent_command(
    monkeypatch, fake_direct_containment, change,
):
    monkeypatch.setattr(
        supervisor,
        "capture_parked_process_identity",
        lambda *_args: pytest.fail(
            "invalid PREPARED intent reached process authentication"
        ),
    )
    outcome = _run_unauthorized_peer(
        monkeypatch,
        lambda request: (
            protocol.encode_ready(_ready(request))
            + protocol.encode_prepared(_prepared(request, **change))
        ),
    )
    assert outcome.reason is supervisor.BootstrapReason.CONTROL_FAILED
    assert fake_direct_containment.handle.bind_proofs == []


@pytest.mark.parametrize("proof_change", [
    {"process_pid": FAKE_LAUNCHER_PID + 1},
    {"parent_pid": FAKE_PID + 1},
    {"state": "S"},
], ids=("launcher", "parent", "not-stopped"))
def test_untrusted_parked_identity_never_authorizes_parent_command(
    monkeypatch, proof_change,
):
    def forged_proof(pid, parent):
        parent_proof = parent
        if "parent_pid" in proof_change:
            parent_proof = SimpleNamespace(
                pid=proof_change["parent_pid"],
                start_time_ticks=parent.start_time_ticks,
            )
        return SimpleNamespace(
            process=SimpleNamespace(
                pid=proof_change.get("process_pid", pid),
            ),
            parent=parent_proof,
            state=proof_change.get("state", "T"),
        )

    monkeypatch.setattr(
        supervisor, "capture_parked_process_identity", forged_proof,
    )
    outcome = _run_unauthorized_peer(
        monkeypatch,
        lambda request: (
            protocol.encode_ready(_ready(request))
            + protocol.encode_prepared(_prepared(request))
        ),
    )
    assert outcome.reason is supervisor.BootstrapReason.IDENTITY_FAILED


def test_prepared_authentication_uses_exact_launcher_and_worker_identity(
    monkeypatch,
):
    calls = []

    def authenticate(pid, parent):
        calls.append((pid, parent))
        return SimpleNamespace(
            process=SimpleNamespace(pid=pid), parent=parent, state="T",
        )

    monkeypatch.setattr(
        supervisor, "capture_parked_process_identity", authenticate,
    )
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, _honest_abort_peer, []),
    )
    assert outcome.reason is supervisor.BootstrapReason.ABORTED
    assert len(calls) == 1
    launcher_pid, worker_identity = calls[0]
    assert launcher_pid == FAKE_LAUNCHER_PID
    assert worker_identity.pid == FAKE_PID
    assert worker_identity.start_time_ticks == 123456


@pytest.mark.parametrize("sequence", [
    lambda request: protocol.encode_prepared(_prepared(request)),
    lambda request: (
        protocol.encode_ready(_ready(request))
        + protocol.encode_ready(_ready(request))
    ),
    lambda request: (
        protocol.encode_ready(_ready(request))
        + protocol.encode_settlement(_settlement(request))
    ),
    lambda request: (
        protocol.encode_ready(_ready(request))
        + protocol.encode_prepared(_prepared(request))
        + protocol.encode_prepared(_prepared(request))
    ),
    lambda request: protocol.encode_ready(_ready(request)) + b"\x00\x00\x00\x01x",
], ids=(
    "prepared-before-ready", "duplicate-ready", "settlement-before-prepared",
    "duplicate-prepared", "malformed-after-ready",
))
def test_invalid_prepared_order_and_duplicates_never_authorize_command(
    monkeypatch, sequence,
):
    outcome = _run_unauthorized_peer(monkeypatch, sequence)
    assert outcome.reason in {
        supervisor.BootstrapReason.READY_FAILED,
        supervisor.BootstrapReason.CONTROL_FAILED,
    }


@pytest.mark.parametrize("mode", [
    "group-unsettled", "tree-settled", "launched", "wrong-terminal",
    "wrong-detail", "stream-started", "wrong-request", "wrong-worker",
])
def test_post_abort_settlement_requires_exact_negative_parked_truth(
    monkeypatch, mode,
):
    def peer(command_fd, control_fd):
        request = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        prepared = _prepared(request)
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(request))
            + protocol.encode_prepared(prepared),
        )
        _read_prepared_abort(command_fd, request, prepared)
        changes = {
            "group-unsettled": {"process_group_settled": False},
            "tree-settled": {"process_tree_settled": True},
            "launched": {"launched": True, "tool_pid": FAKE_LAUNCHER_PID},
            "wrong-terminal": {
                "terminal": protocol.ExecutionTerminal.WORKER_FAILED,
            },
            "wrong-detail": {"detail": "command_mismatch"},
            "stream-started": {
                "streams": (
                    replace(
                        _streams()[0],
                        terminal=protocol.StreamTerminal.CANCELLED,
                    ),
                    *_streams()[1:],
                ),
            },
            "wrong-request": {"request_id": "82" * 16},
            "wrong-worker": {"worker_pid": FAKE_PID + 1},
        }[mode]
        runner_ipc.write_all(
            control_fd,
            protocol.encode_settlement(_settlement(request, **changes)),
        )
        return 0

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, peer, []),
    )
    assert outcome.abort_command_sent
    assert outcome.reason is supervisor.BootstrapReason.CONTROL_FAILED
    assert not outcome.transaction_complete
    assert outcome.worker_reaped


def test_successful_outcome_proves_exact_negative_transaction(monkeypatch):
    request = _request()
    child = _PipeChild(_honest_abort_peer)
    calls = []

    def factory(argv, **kwargs):
        calls.append((argv, kwargs))
        return child

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=777),
    )
    outcome = supervisor.bootstrap_worker(
        request, deadline=time.monotonic() + 2, popen_factory=factory,
    )
    assert outcome.transaction_complete
    assert outcome.worker_pid == FAKE_PID
    assert outcome.worker_start_time_ticks == 777
    assert outcome.worker_returncode == 0 and outcome.worker_reaped
    assert outcome.control_eof and outcome.observed_trailing_control_bytes == 0
    assert outcome.kill_requested is False
    assert outcome.parent_pipes_closed is True
    assert outcome.abort_command_sent is True
    assert outcome.ready == _ready(request)
    assert outcome.settlement == _settlement(request)
    assert outcome.settlement.process_group_settled is True
    # PREPARED is private transaction state; the established public outcome shape
    # remains unchanged.
    assert not hasattr(outcome, "prepared")


def test_bootstrap_outcome_is_frozen_nonforgeable_and_credential_safe(monkeypatch):
    request = _request()
    calls = []
    outcome = supervisor.bootstrap_worker(
        request,
        deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, _honest_abort_peer, calls),
    )
    with pytest.raises(FrozenInstanceError):
        outcome.reason = supervisor.BootstrapReason.CONTROL_FAILED
    values = {
        "reason": supervisor.BootstrapReason.ABORTED,
        "request_id": request.request_id,
        "worker_pid": FAKE_PID,
        "worker_start_time_ticks": 1,
        "ready": outcome.ready,
        "settlement": outcome.settlement,
        "worker_returncode": 0,
        "worker_spawned": True,
        "worker_reaped": True,
        "control_eof": True,
        "observed_trailing_control_bytes": 0,
        "kill_requested": False,
        "parent_pipes_closed": True,
        "abort_command_sent": True,
        "_expected_request_sha256": protocol.request_digest(request),
    }
    with pytest.raises(TypeError, match="authority"):
        supervisor.BootstrapOutcome(**values, _authority=object())
    rendered = repr(outcome)
    assert request.request_id not in rendered
    assert str(FAKE_PID) not in rendered
    for secret in SECRET_VALUES:
        assert secret not in rendered


def test_private_outcome_requires_reap_failed_exactly_for_spawned_unreaped():
    request = _request()

    valid = supervisor._outcome(
        request,
        reason=supervisor.BootstrapReason.REAP_FAILED,
        worker_pid=FAKE_PID,
        worker_spawned=True,
        worker_reaped=False,
    )
    assert valid.reason is supervisor.BootstrapReason.REAP_FAILED
    assert valid.worker_spawned and not valid.worker_reaped

    invalid = (
        {
            "reason": supervisor.BootstrapReason.CONTROL_FAILED,
            "worker_pid": FAKE_PID,
            "worker_spawned": True,
            "worker_reaped": False,
        },
        {
            "reason": supervisor.BootstrapReason.REAP_FAILED,
            "worker_pid": None,
            "worker_spawned": False,
            "worker_reaped": False,
        },
        {
            "reason": supervisor.BootstrapReason.REAP_FAILED,
            "worker_pid": FAKE_PID,
            "worker_returncode": 0,
            "worker_spawned": True,
            "worker_reaped": True,
        },
    )
    for values in invalid:
        with pytest.raises(ValueError, match="worker (?:spawn|reap) outcome"):
            supervisor._outcome(request, **values)


@pytest.mark.parametrize("fact", [
    "worker_pid",
    "worker_start_time_ticks",
    "ready",
    "settlement",
    "worker_returncode",
    "worker_reaped",
    "control_eof",
    "observed_trailing_control_bytes",
    "abort_command_sent",
    "parent_pipes_closed",
    "kill_requested",
])
def test_private_unspawned_outcome_rejects_every_child_transport_fact(fact):
    request = _request()
    non_vacuous = {
        "worker_pid": FAKE_PID,
        "worker_start_time_ticks": 1,
        "ready": _ready(request),
        "settlement": _settlement(request),
        "worker_returncode": 0,
        "worker_reaped": True,
        "control_eof": True,
        "observed_trailing_control_bytes": 1,
        "abort_command_sent": True,
        "parent_pipes_closed": False,
        "kill_requested": True,
    }

    with pytest.raises(ValueError, match="worker (?:spawn|reap) outcome"):
        supervisor._outcome(
            request,
            reason=supervisor.BootstrapReason.CONTROL_FAILED,
            worker_spawned=False,
            **{fact: non_vacuous[fact]},
        )


def test_private_outcome_rejects_aborted_without_spawned_worker():
    request = _request()
    with pytest.raises(ValueError, match="spawn outcome"):
        supervisor._outcome(
            request,
            reason=supervisor.BootstrapReason.ABORTED,
            worker_pid=FAKE_PID,
            worker_start_time_ticks=1,
            ready=_ready(request),
            settlement=_settlement(request),
            worker_returncode=None,
            worker_spawned=False,
            worker_reaped=False,
            control_eof=True,
            observed_trailing_control_bytes=0,
            abort_command_sent=True,
            parent_pipes_closed=True,
            kill_requested=False,
        )


@pytest.mark.parametrize(
    "missing_witness", ["_containment_bound", "_containment_settled"],
    ids=("binding", "settlement"),
)
def test_private_outcome_requires_hidden_containment_witnesses_for_aborted(
    missing_witness,
):
    request = _request()
    values = {
        "reason": supervisor.BootstrapReason.ABORTED,
        "worker_pid": FAKE_PID,
        "worker_start_time_ticks": 1,
        "ready": _ready(request),
        "settlement": _settlement(request),
        "worker_returncode": 0,
        "worker_spawned": True,
        "worker_reaped": True,
        "control_eof": True,
        "observed_trailing_control_bytes": 0,
        "abort_command_sent": True,
        "parent_pipes_closed": True,
        "kill_requested": False,
        "_containment_bound": True,
        "_containment_settled": True,
    }
    values[missing_witness] = False

    with pytest.raises(ValueError, match="incomplete successful bootstrap"):
        supervisor._outcome(request, **values)

    values[missing_witness] = True
    outcome = supervisor._outcome(request, **values)
    assert outcome.reason is supervisor.BootstrapReason.ABORTED
    assert outcome.transaction_complete is True


def test_private_authority_rejects_aborted_outcome_with_wrong_ready_digest(
    monkeypatch,
):
    request = _request()
    calls = []
    valid = supervisor.bootstrap_worker(
        request,
        deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, _honest_abort_peer, calls),
    )
    assert valid.transaction_complete
    wrong_ready = replace(valid.ready, request_sha256="f0" * 32)
    with pytest.raises(ValueError, match="successful bootstrap"):
        supervisor._outcome(
            request,
            reason=supervisor.BootstrapReason.ABORTED,
            worker_pid=valid.worker_pid,
            worker_start_time_ticks=valid.worker_start_time_ticks,
            ready=wrong_ready,
            settlement=valid.settlement,
            worker_returncode=0,
            worker_spawned=True,
            worker_reaped=True,
            control_eof=True,
            observed_trailing_control_bytes=0,
            kill_requested=False,
            parent_pipes_closed=True,
            abort_command_sent=True,
        )


def test_expired_deadline_has_no_spawn_side_effect():
    calls = []
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=10, clock=lambda: 10,
        popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    assert outcome.reason is supervisor.BootstrapReason.DEADLINE
    assert outcome.transaction_complete is False
    assert calls == []


def test_non_linux_is_typed_unsupported_without_spawn(monkeypatch):
    monkeypatch.setattr(supervisor.sys, "platform", "darwin")
    calls = []
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 1,
        popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    assert outcome.reason is supervisor.BootstrapReason.UNSUPPORTED
    assert not outcome.transaction_complete
    assert calls == []


def test_nondefault_sigchld_disposition_refuses_before_spawn(monkeypatch):
    monkeypatch.setattr(signal, "getsignal", lambda _signum: signal.SIG_IGN)
    calls = []
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 1,
        popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    assert outcome.reason is supervisor.BootstrapReason.UNSUPPORTED
    assert not outcome.transaction_complete
    assert calls == []


def test_expiry_during_pre_spawn_preparation_has_no_popen_side_effect():
    instants = iter((10.0, 20.0))
    calls = []
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=15.0, clock=lambda: next(instants, 20.0),
        popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    assert outcome.reason is supervisor.BootstrapReason.DEADLINE
    assert not outcome.transaction_complete
    assert calls == []


def test_cancellation_after_selector_allocation_closes_once_without_spawn(
    monkeypatch, fake_direct_containment,
):
    original_selector = supervisor.selectors.DefaultSelector
    selector_box = []
    spawn_calls = []
    cancellation = KeyboardInterrupt("interrupt after selector allocation")
    injected = []

    class CountingSelector:
        def __init__(self):
            self.inner = original_selector()
            self.close_calls = 0

        def close(self):
            self.close_calls += 1
            self.inner.close()

    def allocate_selector():
        selector = CountingSelector()
        selector_box.append(selector)
        return selector

    def trace_selector_gap(frame, event, _arg):
        owner = frame.f_locals.get("owner")
        if (event == "line" and frame.f_code is supervisor.bootstrap_worker.__code__
                and selector_box and owner is not None
                and owner.selector is selector_box[0]
                and owner.child is None
                and not spawn_calls and not injected):
            injected.append(frame.f_lineno)
            sys.settrace(None)
            raise cancellation
        return trace_selector_gap

    monkeypatch.setattr(
        supervisor.selectors, "DefaultSelector", allocate_selector,
    )
    previous_trace = sys.gettrace()
    try:
        sys.settrace(trace_selector_gap)
        with pytest.raises(KeyboardInterrupt) as caught:
            supervisor.bootstrap_worker(
                _request(), deadline=time.monotonic() + 1,
                popen_factory=lambda *args, **kwargs: spawn_calls.append(
                    (args, kwargs)
                ),
            )
        assert caught.value is cancellation
        assert len(injected) == 1
        assert selector_box[0].close_calls == 1
        assert spawn_calls == []
        assert len(fake_direct_containment.handle.settlement_deadlines) == 1
        assert fake_direct_containment.handle.terminal is True
    finally:
        sys.settrace(previous_trace)
        if selector_box and selector_box[0].close_calls == 0:
            selector_box[0].inner.close()


def test_spawn_failure_is_typed_and_settles_direct_containment(
    fake_direct_containment,
):
    def refuse(*args, **kwargs):
        raise OSError("environment-secret")

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 1, popen_factory=refuse,
    )
    assert outcome.reason is supervisor.BootstrapReason.SPAWN_FAILED
    assert not outcome.transaction_complete
    assert len(fake_direct_containment.handle.settlement_deadlines) == 1
    assert fake_direct_containment.handle.terminal is True
    for secret in SECRET_VALUES:
        assert secret not in repr(outcome)


def test_natural_exit_between_graceful_timeout_and_kill_remains_complete(
    monkeypatch,
):
    """A timeout observation must not turn an already-exited rc0 child into failure."""
    child_box = []

    class ExitAtKillBoundaryChild(_PipeChild):
        def __init__(self, handler):
            super().__init__(handler)
            self.poll_calls = 0
            self.wait_calls = 0

        def poll(self):
            self.poll_calls += 1
            if self.poll_calls == 1:
                return None
            return 0

        def wait(self, timeout=None):
            self.wait_timeouts.append(timeout)
            self.wait_calls += 1
            if self.wait_calls == 1:
                # The graceful observation times out; immediately afterward the
                # exact child becomes observably reaped with rc0 before any kill.
                self._thread.join(1)
                raise subprocess.TimeoutExpired("fixed-worker", timeout)
            return 0

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=456),
    )

    def factory(_argv, **_kwargs):
        child = ExitAtKillBoundaryChild(_honest_abort_peer)
        child_box.append(child)
        return child

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 1, popen_factory=factory,
    )
    child = child_box[0]
    assert outcome.reason is supervisor.BootstrapReason.ABORTED
    assert outcome.transaction_complete
    assert child.kill_calls == 0 and not outcome.kill_requested
    assert outcome.worker_reaped and outcome.worker_returncode == 0


def test_graceful_poll_fault_never_authorizes_a_later_kill(monkeypatch):
    child_box = []

    class AmbiguousPollChild(_PipeChild):
        def __init__(self, handler):
            super().__init__(handler)
            self.poll_calls = 0

        def poll(self):
            self.poll_calls += 1
            if self.poll_calls == 1:
                raise OSError("ambiguous graceful poll failure")
            return super().poll()

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=459),
    )

    def factory(_argv, **_kwargs):
        child = AmbiguousPollChild(_honest_abort_peer)
        child_box.append(child)
        return child

    try:
        outcome = supervisor.bootstrap_worker(
            _request(), deadline=time.monotonic() + 1, popen_factory=factory,
        )
        child = child_box[0]
        assert not outcome.transaction_complete
        assert outcome.reason in {
            supervisor.BootstrapReason.WORKER_FAILED,
            supervisor.BootstrapReason.REAP_FAILED,
        }
        assert child.kill_calls == 0
        assert outcome.kill_requested is False
        assert child.stdin.closed and child.stdout.closed
        if outcome.worker_reaped:
            assert outcome.worker_returncode == 0
        else:
            assert outcome.reason is supervisor.BootstrapReason.REAP_FAILED
    finally:
        if child_box:
            child = child_box[0]
            child._thread.join(1)
            if child.returncode is None and not child._thread.is_alive():
                child.wait(timeout=0)


@pytest.mark.parametrize("mode", ["wrong_ready", "duplicate", "trailing", "crash"])
def test_malformed_duplicate_trailing_and_crash_never_complete(monkeypatch, mode):
    def peer(command_fd, control_fd):
        request = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        if mode == "crash":
            return 17
        ready = _ready(request)
        if mode == "wrong_ready":
            ready = protocol.ReadyFrame(
                request.request_id, FAKE_PID + 1, protocol.request_digest(request),
            )
        runner_ipc.write_all(control_fd, protocol.encode_ready(ready))
        if mode == "wrong_ready":
            return 0
        prepared = _prepared(request)
        runner_ipc.write_all(control_fd, protocol.encode_prepared(prepared))
        _read_prepared_abort(command_fd, request, prepared)
        wire = protocol.encode_settlement(_settlement(request))
        if mode == "duplicate":
            wire += protocol.encode_settlement(_settlement(request))
        elif mode == "trailing":
            wire += b"x"
        runner_ipc.write_all(control_fd, wire)
        return 0

    calls = []
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, peer, calls),
    )
    assert outcome.reason is not supervisor.BootstrapReason.ABORTED
    assert not outcome.transaction_complete
    assert outcome.worker_reaped


def test_settlement_before_parent_abort_delivery_never_completes(monkeypatch):
    """Cross-channel testimony cannot replace the parent's command/EOF proof."""
    def premature(command_fd, control_fd):
        request = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        os.close(command_fd)
        prepared = _prepared(request)
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(request))
            + protocol.encode_prepared(prepared)
            + protocol.encode_settlement(_settlement(request)),
        )
        return 0

    calls = []
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2,
        popen_factory=_factory(monkeypatch, premature, calls),
    )
    assert outcome.reason is not supervisor.BootstrapReason.ABORTED
    assert not outcome.transaction_complete


def test_early_settlement_cannot_be_laundered_by_later_abort_delivery(
    monkeypatch,
):
    """The worker must not testify to ABORT before the parent delivered it + EOF."""
    settlement_seen = threading.Event()
    ambiguous_command_write = threading.Event()
    command_drained = threading.Event()
    child_box = []
    original_write = supervisor.os.write
    original_decode = supervisor.decode_control_frame

    def early_peer(command_fd, control_fd):
        request = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        prepared = _prepared(request)
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(request))
            + protocol.encode_prepared(prepared),
        )
        assert ambiguous_command_write.wait(1)
        runner_ipc.write_all(
            control_fd, protocol.encode_settlement(_settlement(request)),
        )
        # Keep the request channel open and eventually drain the authentic command.
        # This proves that later delivery cannot repair an impossible transcript.
        _read_prepared_abort(command_fd, request, prepared)
        command_drained.set()
        return 0

    def defer_parent_command(fd, data):
        child = child_box[0]
        if (threading.current_thread() is threading.main_thread()
                and fd == child.stdin.fileno()
                and b'"kind":"launch_command"' in bytes(data)
                and not settlement_seen.is_set()):
            # Model an ambiguous transport fault: the complete frame reached the
            # pipe, but the parent never received a successful write result and
            # therefore cannot claim delivery.  The peer later drains these bytes
            # plus EOF; that observation still cannot repair the causal ordering.
            if not ambiguous_command_write.is_set():
                original_write(fd, data)
                ambiguous_command_write.set()
            raise BlockingIOError
        return original_write(fd, data)

    def observe_settlement(frame):
        record = original_decode(frame)
        if type(record) is protocol.WorkerSettlement:
            settlement_seen.set()
        return record

    monkeypatch.setattr(supervisor.os, "write", defer_parent_command)
    monkeypatch.setattr(supervisor, "decode_control_frame", observe_settlement)
    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=321),
    )

    def factory(_argv, **_kwargs):
        # Teardown closes the parent command endpoint before requesting kill.
        # Let the peer observe that EOF before the fake kill closes its copy of
        # the descriptor, avoiding a fixture-only scheduling race.
        child = _PipeChild(
            early_peer, kill_hook=lambda: command_drained.wait(1),
        )
        child_box.append(child)
        return child

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2, popen_factory=factory,
    )
    assert settlement_seen.is_set()
    assert ambiguous_command_write.is_set()
    assert command_drained.is_set()
    assert outcome.reason is not supervisor.BootstrapReason.ABORTED
    assert not outcome.transaction_complete
    assert child_box[0].kill_calls == 1
    assert outcome.worker_reaped


def test_clock_fault_during_final_wait_is_bounded_and_reaped(monkeypatch):
    child_box = []
    final_poll_seen = threading.Event()
    clock_faulted = threading.Event()

    class FinalWaitChild(_PipeChild):
        def poll(self):
            if self.returncode is None:
                final_poll_seen.set()
            return super().poll()

    def fault_once_in_final_wait():
        if final_poll_seen.is_set() and not clock_faulted.is_set():
            clock_faulted.set()
            raise RuntimeError("injected final-wait clock failure")
        return time.monotonic()

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=654),
    )

    def factory(_argv, **_kwargs):
        child = FinalWaitChild(_honest_abort_peer)
        child_box.append(child)
        return child

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2,
        clock=fault_once_in_final_wait, popen_factory=factory,
    )
    child = child_box[0]
    assert clock_faulted.is_set()
    assert outcome.worker_reaped
    assert outcome.worker_returncode in (0, -9)
    assert outcome.kill_requested is (child.kill_calls == 1)
    assert all(timeout is None or 0 <= timeout <= 2 for timeout in child.wait_timeouts)


def test_persistent_clock_cancellation_after_spawn_cleans_up_then_reraises(
    monkeypatch,
):
    spawned = threading.Event()
    child_box = []
    cancellation = KeyboardInterrupt("persistent post-spawn clock cancellation")

    def clock():
        if spawned.is_set():
            raise cancellation
        return time.monotonic()

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=655),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(_honest_abort_peer)
        child_box.append(child)
        spawned.set()
        return child

    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=started + 1, clock=clock,
            popen_factory=factory,
        )
    elapsed = time.monotonic() - started

    child = child_box[0]
    assert caught.value is cancellation
    assert child.kill_calls == 1
    assert child.stdin.closed and child.stdout.closed
    assert child.wait_timeouts
    assert all(timeout is None or 0 <= timeout <= 1 for timeout in child.wait_timeouts)
    assert not child._thread.is_alive()
    assert child.returncode == -9
    assert elapsed < 1


def test_graceful_wait_timeout_preserves_one_shot_clock_cancellation(
    monkeypatch,
):
    graceful_poll_seen = threading.Event()
    cancellation_raised = threading.Event()
    child_box = []
    cancellation = KeyboardInterrupt("one-shot graceful-wait cancellation")

    class GracefulTimeoutChild(_PipeChild):
        def __init__(self, handler):
            super().__init__(handler)
            self.wait_calls = 0

        def poll(self):
            graceful_poll_seen.set()
            return super().poll()

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls == 1:
                self.wait_timeouts.append(timeout)
                raise subprocess.TimeoutExpired("fixed-worker", timeout)
            return super().wait(timeout=timeout)

    def clock():
        if graceful_poll_seen.is_set() and not cancellation_raised.is_set():
            cancellation_raised.set()
            raise cancellation
        return time.monotonic()

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=656),
    )

    def factory(_argv, **_kwargs):
        child = GracefulTimeoutChild(_honest_abort_peer)
        child_box.append(child)
        return child

    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=started + 1, clock=clock,
            popen_factory=factory,
        )
    elapsed = time.monotonic() - started

    child = child_box[0]
    assert cancellation_raised.is_set()
    assert caught.value is cancellation
    assert child.wait_calls == 2
    assert child.kill_calls == 1
    assert child.stdin.closed and child.stdout.closed
    assert all(timeout is None or 0 <= timeout <= 1 for timeout in child.wait_timeouts)
    assert not child._thread.is_alive()
    assert child.returncode == -9
    assert elapsed < 1


@pytest.mark.parametrize(
    "cancellation_seam",
    ["kill_poll", "final_poll", "final_wait"],
)
def test_one_shot_teardown_cancellation_retries_kill_and_exact_reap(
    monkeypatch, cancellation_seam,
):
    child_box = []
    cancellation = KeyboardInterrupt(
        f"one-shot teardown cancellation at {cancellation_seam}",
    )

    class TeardownCancellationChild(_PipeChild):
        def __init__(self, handler):
            super().__init__(handler)
            self.poll_calls = 0
            self.wait_calls = 0
            self.cancellation_calls = 0

        def poll(self):
            self.poll_calls += 1
            should_interrupt = (
                cancellation_seam == "kill_poll" and self.poll_calls == 1
            ) or (
                cancellation_seam == "final_poll"
                and self.killed
                and self.cancellation_calls == 0
            )
            if should_interrupt:
                self.cancellation_calls += 1
                raise cancellation
            return super().poll()

        def wait(self, timeout=None):
            self.wait_calls += 1
            if (cancellation_seam == "final_wait"
                    and self.killed and self.cancellation_calls == 0):
                self.cancellation_calls += 1
                self.wait_timeouts.append(timeout)
                raise cancellation
            return super().wait(timeout=timeout)

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda _pid: (_ for _ in ()).throw(OSError("force teardown")),
    )

    def factory(_argv, **_kwargs):
        child = TeardownCancellationChild(_honest_abort_peer)
        child_box.append(child)
        return child

    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=started + 1, popen_factory=factory,
        )
    elapsed = time.monotonic() - started

    child = child_box[0]
    assert caught.value is cancellation
    assert child.cancellation_calls == 1
    assert child.kill_calls == 1
    assert child.poll_calls >= 3
    assert child.wait_calls == (2 if cancellation_seam == "final_wait" else 1)
    assert child.stdin.closed and child.stdout.closed
    assert all(timeout is None or 0 <= timeout <= 1 for timeout in child.wait_timeouts)
    assert not child._thread.is_alive()
    assert child.returncode == -9
    assert elapsed < 1


@pytest.mark.parametrize("cancellation_kind", ["keyboard", "system_exit"])
def test_ambiguous_kill_cancellation_is_not_retried_and_is_reaped_before_reraise(
    monkeypatch, cancellation_kind,
):
    child_box = []
    cancellation = (
        KeyboardInterrupt("kill invocation interrupted")
        if cancellation_kind == "keyboard"
        else SystemExit("kill invocation interrupted")
    )

    class AmbiguousKillChild(_PipeChild):
        def kill(self):
            # Model signal delivery completing before cancellation interrupts the
            # caller.  Retrying this ambiguous numeric authority is forbidden.
            super().kill()
            raise cancellation

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda _pid: (_ for _ in ()).throw(OSError("force teardown")),
    )

    def factory(_argv, **_kwargs):
        child = AmbiguousKillChild(_honest_abort_peer)
        child_box.append(child)
        return child

    started = time.monotonic()
    with pytest.raises(type(cancellation)) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=started + 1, popen_factory=factory,
        )
    elapsed = time.monotonic() - started

    child = child_box[0]
    assert caught.value is cancellation
    assert child.kill_calls == 1
    assert child.stdin.closed and child.stdout.closed
    assert child.wait_timeouts
    assert all(timeout is None or 0 <= timeout <= 1 for timeout in child.wait_timeouts)
    assert not child._thread.is_alive()
    assert child.returncode == -9
    assert elapsed < 1


def test_cancellation_after_committed_kill_helper_does_not_signal_twice(
    monkeypatch,
):
    release = threading.Event()
    child_box = []
    helper_calls = []
    cancellation = KeyboardInterrupt("cancel after committed kill helper")
    original_kill_helper = supervisor._request_kill_bounded

    def hangs(_command_fd, _control_fd):
        release.wait(5)
        return 0

    def interrupt_after_committed_kill(owner, real_deadline):
        original_kill_helper(owner, real_deadline)
        helper_calls.append(owner)
        assert owner.kill_requested
        assert child_box[0].kill_calls == 1
        if len(helper_calls) == 1:
            raise cancellation

    monkeypatch.setattr(
        supervisor, "_request_kill_bounded", interrupt_after_committed_kill,
    )
    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda _pid: (_ for _ in ()).throw(OSError("force teardown")),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(hangs, kill_hook=release.set)
        child_box.append(child)
        return child

    started = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            supervisor.bootstrap_worker(
                _request(), deadline=started + 1, popen_factory=factory,
            )
        child = child_box[0]
        assert caught.value is cancellation
        assert len(helper_calls) == 2
        assert helper_calls[0] is helper_calls[1]
        assert child.kill_calls == 1
        assert child.stdin.closed and child.stdout.closed
        assert len(child.wait_timeouts) == 1
        assert not child._thread.is_alive()
        assert child.returncode == -9
        assert time.monotonic() - started < 1
    finally:
        release.set()
        if child_box:
            for pipe in (child_box[0].stdin, child_box[0].stdout):
                if not pipe.closed:
                    pipe.close()
            child_box[0]._thread.join(1)


def test_slow_popen_exhausting_budget_still_gets_one_kill_attempt(monkeypatch):
    release = threading.Event()
    child_box = []

    def hangs(_command_fd, _control_fd):
        release.wait(5)
        return 0

    class ObservedChild(_PipeChild):
        def __init__(self, handler, **kwargs):
            super().__init__(handler, **kwargs)
            self.poll_calls = 0

        def poll(self):
            self.poll_calls += 1
            return super().poll()

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=657),
    )

    def factory(_argv, **_kwargs):
        child = ObservedChild(hangs, kill_hook=release.set)
        child_box.append(child)
        # Popen is allowed to return after the caller's absolute budget.  Once it
        # does, the returned child is still an owned authority that must receive
        # one safe nonblocking observation and at most one kill invocation.
        time.sleep(0.05)
        return child

    started = time.monotonic()
    try:
        outcome = supervisor.bootstrap_worker(
            _request(), deadline=started + 0.02, popen_factory=factory,
        )
        child = child_box[0]
        child._thread.join(0.5)
        assert outcome.reason is supervisor.BootstrapReason.REAP_FAILED
        assert outcome.worker_spawned and not outcome.worker_reaped
        assert outcome.kill_requested is True
        assert child.poll_calls >= 1
        assert child.kill_calls == 1
        assert child.stdin.closed and child.stdout.closed
        assert not child._thread.is_alive()
        assert time.monotonic() - started < 0.5
    finally:
        release.set()
        if child_box:
            for pipe in (child_box[0].stdin, child_box[0].stdout):
                if not pipe.closed:
                    pipe.close()
            child_box[0]._thread.join(1)


@pytest.mark.parametrize("cancellation_seam", ["poll", "wait"])
def test_persistent_teardown_cancellation_has_bounded_attempt_count(
    monkeypatch, cancellation_seam,
):
    release = threading.Event()
    child_box = []
    cancellation = KeyboardInterrupt(
        f"persistent teardown cancellation at {cancellation_seam}",
    )

    def hangs(_command_fd, _control_fd):
        release.wait(5)
        return 0

    class PersistentCancellationChild(_PipeChild):
        def __init__(self, handler, **kwargs):
            super().__init__(handler, **kwargs)
            self.poll_calls = 0
            self.wait_calls = 0

        def poll(self):
            self.poll_calls += 1
            if cancellation_seam == "poll":
                raise cancellation
            return super().poll()

        def wait(self, timeout=None):
            self.wait_calls += 1
            if cancellation_seam == "wait":
                raise cancellation
            return super().wait(timeout=timeout)

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda _pid: (_ for _ in ()).throw(OSError("force teardown")),
    )

    def factory(_argv, **_kwargs):
        child = PersistentCancellationChild(hangs, kill_hook=release.set)
        child_box.append(child)
        return child

    started = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            supervisor.bootstrap_worker(
                _request(), deadline=started + 0.10, popen_factory=factory,
            )
        child = child_box[0]
        assert caught.value is cancellation
        # Each teardown helper gets at most two cooperative cancellation samples;
        # persistent cancellation must not busy-spin for the entire deadline.
        assert child.poll_calls <= 4
        assert child.wait_calls <= 2
        assert child.kill_calls <= 1
        assert child.stdin.closed and child.stdout.closed
        assert time.monotonic() - started < 0.5
    finally:
        release.set()
        if child_box:
            for pipe in (child_box[0].stdin, child_box[0].stdout):
                if not pipe.closed:
                    pipe.close()
            child_box[0]._thread.join(1)


def test_input_close_commit_and_invocation_have_no_line_visible_gap(
    monkeypatch,
):
    child_box = []
    input_wrapper_box = []
    observed_gap = []

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=658),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(_honest_abort_peer)
        wrapper = _CountingClosePipe(child.stdin)
        child.stdin = wrapper
        child_box.append(child)
        input_wrapper_box.append(wrapper)
        return child

    def trace_close_gap(frame, event, _arg):
        owner = frame.f_locals.get("owner")
        if (event == "line" and frame.f_code is supervisor._owner_close_pipe.__code__
                and child_box and owner is not None
                and frame.f_locals.get("role") == "input"
                and owner.input_pipe is child_box[0].stdin
                and owner.input_close_attempted is True
                and owner.input_closed_clean is False
                and owner.abort_command_sent is False
                and not child_box[0].stdin.closed
                and input_wrapper_box[0].close_calls == 0):
            observed_gap.append(frame.f_lineno)
        return trace_close_gap

    previous_trace = sys.gettrace()
    try:
        sys.settrace(trace_close_gap)
        outcome = supervisor.bootstrap_worker(
            _request(), deadline=time.monotonic() + 1,
            popen_factory=factory,
        )
        child = child_box[0]
        child._thread.join(0.5)
        assert observed_gap == []
        assert outcome.transaction_complete
        assert input_wrapper_box[0].close_calls == 1
        assert child.stdin.closed and child.stdout.closed
        assert child.kill_calls == 0
        assert child.wait_timeouts
        assert not child._thread.is_alive()
        assert child.returncode == 0
    finally:
        sys.settrace(previous_trace)
        if child_box:
            for pipe in (child_box[0].stdin, child_box[0].stdout):
                if not pipe.closed:
                    pipe.close()
            child_box[0]._thread.join(1)


@pytest.mark.parametrize(
    "injection_seam", ["after_popen", "before_reap"],
)
def test_line_cancellation_after_popen_remains_owned_through_exact_reap(
    monkeypatch, injection_seam,
):
    release = threading.Event()
    child_box = []
    wrappers_box = []
    cancellation = KeyboardInterrupt(f"line cancellation at {injection_seam}")
    injected = []

    def hangs(_command_fd, _control_fd):
        release.wait(5)
        return 0

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda _pid: (_ for _ in ()).throw(OSError("force teardown")),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(hangs, kill_hook=release.set)
        input_wrapper = _CountingClosePipe(child.stdin)
        output_wrapper = _CountingClosePipe(child.stdout)
        child.stdin = input_wrapper
        child.stdout = output_wrapper
        child_box.append(child)
        wrappers_box.append((input_wrapper, output_wrapper))
        return child

    def trace_ownership_gap(frame, event, _arg):
        owner = frame.f_locals.get("owner")
        if event != "line" or not child_box or owner is None or injected:
            return trace_ownership_gap
        if injection_seam == "after_popen":
            at_gap = (
                frame.f_code is supervisor.bootstrap_worker.__code__
                and owner.child is child_box[0]
                and not owner.worker_spawned
                and owner.input_pipe is None and owner.output_pipe is None
            )
        else:
            at_gap = (
                frame.f_code is supervisor._settle_owned_child.__code__
                and owner.child is child_box[0]
                and owner.worker_spawned and not owner.worker_reaped
                and not owner.kill_requested
                and wrappers_box
                and all(wrapper.closed for wrapper in wrappers_box[0])
            )
        if at_gap:
            injected.append(frame.f_lineno)
            sys.settrace(None)
            raise cancellation
        return trace_ownership_gap

    previous_trace = sys.gettrace()
    try:
        sys.settrace(trace_ownership_gap)
        with pytest.raises(KeyboardInterrupt) as caught:
            supervisor.bootstrap_worker(
                _request(), deadline=time.monotonic() + 1,
                popen_factory=factory,
            )
        child = child_box[0]
        child._thread.join(0.5)
        assert len(injected) == 1
        assert caught.value is cancellation
        assert tuple(wrapper.close_calls for wrapper in wrappers_box[0]) == (1, 1)
        assert child.stdin.closed and child.stdout.closed
        assert child.kill_calls == 1
        assert child.wait_timeouts
        assert not child._thread.is_alive()
        assert child.returncode == -9
    finally:
        sys.settrace(previous_trace)
        release.set()
        if child_box:
            for pipe in (child_box[0].stdin, child_box[0].stdout):
                if not pipe.closed:
                    pipe.close()
            child_box[0]._thread.join(1)


@pytest.mark.parametrize("sampling_seam", ["kill_budget", "final_reap"])
@pytest.mark.parametrize("cancellation_kind", ["keyboard", "system_exit"])
def test_one_shot_trusted_time_cancellation_is_reaped_then_reraised(
    monkeypatch, sampling_seam, cancellation_kind,
):
    child_box = []
    cancellation = (
        KeyboardInterrupt("trusted time sampling interrupted")
        if cancellation_kind == "keyboard"
        else SystemExit("trusted time sampling interrupted")
    )
    active_sampling = {"seam": None}
    injected = []
    real_monotonic = supervisor._REAL_MONOTONIC
    original_kill = supervisor._request_kill_bounded
    original_final_reap = supervisor._final_reap_bounded

    def sampled_monotonic():
        if active_sampling["seam"] == sampling_seam and not injected:
            injected.append(active_sampling["seam"])
            raise cancellation
        return real_monotonic()

    def instrumented_kill(*args, **kwargs):
        active_sampling["seam"] = "kill_budget"
        try:
            return original_kill(*args, **kwargs)
        finally:
            active_sampling["seam"] = None

    def instrumented_final_reap(*args, **kwargs):
        active_sampling["seam"] = "final_reap"
        try:
            return original_final_reap(*args, **kwargs)
        finally:
            active_sampling["seam"] = None

    monkeypatch.setattr(supervisor, "_REAL_MONOTONIC", sampled_monotonic)
    monkeypatch.setattr(supervisor, "_request_kill_bounded", instrumented_kill)
    monkeypatch.setattr(supervisor, "_final_reap_bounded", instrumented_final_reap)
    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda _pid: (_ for _ in ()).throw(OSError("force teardown")),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(_honest_abort_peer)
        child_box.append(child)
        return child

    started = time.monotonic()
    with pytest.raises(type(cancellation)) as caught:
        supervisor.bootstrap_worker(
            _request(), deadline=started + 1, popen_factory=factory,
        )
    elapsed = time.monotonic() - started

    child = child_box[0]
    assert injected == [sampling_seam]
    assert caught.value is cancellation
    assert child.kill_calls == 1
    assert child.stdin.closed and child.stdout.closed
    assert child.wait_timeouts
    assert all(timeout is None or 0 <= timeout <= 1 for timeout in child.wait_timeouts)
    assert not child._thread.is_alive()
    assert child.returncode == -9
    assert elapsed < 1


@pytest.mark.parametrize("fault_seam", ["identity", "select", "read", "write"])
def test_keyboard_interrupt_propagates_only_after_child_cleanup(
    monkeypatch, fault_seam,
):
    child_box = []
    original_selector = supervisor.selectors.DefaultSelector
    original_read = supervisor.os.read
    original_write = supervisor.os.write

    if fault_seam == "identity":
        monkeypatch.setattr(
            supervisor,
            "capture_process_identity",
            lambda _pid: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
    else:
        monkeypatch.setattr(
            supervisor,
            "capture_process_identity",
            lambda pid: SimpleNamespace(pid=pid, start_time_ticks=808),
        )

    if fault_seam == "select":
        class InterruptingSelector:
            def __init__(self):
                self.inner = original_selector()

            def register(self, *args, **kwargs):
                return self.inner.register(*args, **kwargs)

            def unregister(self, *args, **kwargs):
                return self.inner.unregister(*args, **kwargs)

            def select(self, _timeout=None):
                raise KeyboardInterrupt

            def close(self):
                self.inner.close()

        monkeypatch.setattr(
            supervisor.selectors, "DefaultSelector", InterruptingSelector,
        )

    if fault_seam == "read":
        def interrupt_control_read(fd, size):
            child = child_box[0] if child_box else None
            if (child is not None
                    and threading.current_thread() is threading.main_thread()
                    and fd == child.stdout.fileno()):
                raise KeyboardInterrupt
            return original_read(fd, size)

        monkeypatch.setattr(supervisor.os, "read", interrupt_control_read)

    if fault_seam == "write":
        def interrupt_command_write(fd, data):
            child = child_box[0]
            if (threading.current_thread() is threading.main_thread()
                    and fd == child.stdin.fileno()):
                raise KeyboardInterrupt
            return original_write(fd, data)

        monkeypatch.setattr(supervisor.os, "write", interrupt_command_write)

    def factory(_argv, **_kwargs):
        child = _PipeChild(_honest_abort_peer)
        child_box.append(child)
        return child

    with pytest.raises(KeyboardInterrupt):
        supervisor.bootstrap_worker(
            _request(), deadline=time.monotonic() + 2, popen_factory=factory,
        )

    child = child_box[0]
    assert child.kill_calls == 1
    assert child.stdin.closed and child.stdout.closed
    assert child.wait_timeouts
    assert not child._thread.is_alive()
    assert child.returncode == -9


@pytest.mark.parametrize("fault", [
    "input_fileno",
    "output_fileno",
    "set_blocking",
    "register",
    "select",
    "unregister",
    "close",
    "decode",
    "output_read",
])
def test_every_post_spawn_setup_and_control_fault_is_owned_killed_and_reaped(
    monkeypatch, fault,
):
    request = _request()
    child_box = []
    original_selector = supervisor.selectors.DefaultSelector
    original_read = supervisor.os.read

    if fault in {"register", "select", "unregister", "close"}:
        monkeypatch.setattr(
            supervisor.selectors,
            "DefaultSelector",
            lambda: _SelectorProxy(original_selector(), fault),
        )
    if fault == "set_blocking":
        monkeypatch.setattr(
            supervisor.os,
            "set_blocking",
            lambda *_args: (_ for _ in ()).throw(
                OSError("injected set_blocking failure")
            ),
        )
    if fault == "decode":
        monkeypatch.setattr(
            supervisor,
            "decode_control_frame",
            lambda _wire: (_ for _ in ()).throw(
                ValueError("injected decode failure")
            ),
        )
    if fault == "output_read":
        def fail_parent_control_read(fd, size):
            child = child_box[0]
            if (threading.current_thread() is threading.main_thread()
                    and fd == child.stdout.fileno()):
                raise OSError("injected output read failure")
            return original_read(fd, size)

        monkeypatch.setattr(supervisor.os, "read", fail_parent_control_read)

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=999),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(_honest_abort_peer)
        if fault == "input_fileno":
            child.stdin = _FailingFileno(child.stdin)
        elif fault == "output_fileno":
            child.stdout = _FailingFileno(child.stdout)
        child_box.append(child)
        return child

    outcome = supervisor.bootstrap_worker(
        request, deadline=time.monotonic() + 2, popen_factory=factory,
    )
    child = child_box[0]
    assert outcome.reason is not supervisor.BootstrapReason.ABORTED
    assert not outcome.transaction_complete
    assert child.kill_calls == 1
    assert outcome.kill_requested is True
    assert child.stdin.closed and child.stdout.closed
    assert child.wait_timeouts and len(child.wait_timeouts) == 1
    assert 0 <= child.wait_timeouts[0] <= 2
    assert outcome.worker_reaped is True
    assert outcome.worker_returncode == -9


@pytest.mark.parametrize("pipe_name", ["stdin", "stdout"])
def test_parent_pipe_close_fault_is_attempted_once_and_never_complete(
    monkeypatch, pipe_name,
):
    child_box = []
    wrapper_box = []
    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=111),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(_honest_abort_peer)
        wrapper = _CloseFaultPipe(getattr(child, pipe_name))
        setattr(child, pipe_name, wrapper)
        child_box.append(child)
        wrapper_box.append(wrapper)
        return child

    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 2, popen_factory=factory,
    )
    assert wrapper_box[0].close_calls == 1
    assert wrapper_box[0].closed
    assert outcome.parent_pipes_closed is False
    assert not outcome.transaction_complete
    assert outcome.reason is not supervisor.BootstrapReason.ABORTED
    assert outcome.worker_reaped


@pytest.mark.parametrize("pipe_role", ["input", "output"])
def test_ordinary_preclose_fault_is_not_retried_by_later_owner_cleanup(
    pipe_role,
):
    read_fd, write_fd = os.pipe()
    pipe = os.fdopen(write_fd, "wb", buffering=0)
    fault = OSError(f"{pipe_role} close failed before physical close")
    wrapper = _CancellingClosePipe(pipe, fault, "before_once")
    owner = supervisor._BootstrapOwner()
    setattr(owner, f"{pipe_role}_pipe", wrapper)
    deadline = time.monotonic() + 1

    try:
        supervisor._settle_owned_child(
            owner, deadline, time.monotonic, deadline,
        )
        assert wrapper.close_calls == 1
        assert not wrapper.closed
        assert getattr(owner, f"{pipe_role}_close_attempts") == 1
        assert not getattr(owner, f"{pipe_role}_closed_clean")
        assert not (owner.input_closed_clean and owner.output_closed_clean)

        supervisor._settle_owned_child(
            owner, deadline, time.monotonic, deadline,
        )
        assert wrapper.close_calls == 1
        assert not wrapper.closed
        assert getattr(owner, f"{pipe_role}_close_attempts") == 1
        assert not getattr(owner, f"{pipe_role}_closed_clean")
        assert not (owner.input_closed_clean and owner.output_closed_clean)
    finally:
        if not wrapper.closed:
            wrapper.force_close()
        os.close(read_fd)


@pytest.mark.parametrize("pipe_name", ["stdin", "stdout"])
@pytest.mark.parametrize("cancellation_kind", ["keyboard", "system_exit"])
@pytest.mark.parametrize(
    ("close_mode", "expected_calls", "expected_closed"),
    [
        ("before_once", 2, True),
        ("after_once", 1, True),
        ("persistent", 2, False),
    ],
)
def test_parent_pipe_close_cancellation_has_bounded_retry_and_exact_cleanup(
    monkeypatch, pipe_name, cancellation_kind, close_mode, expected_calls,
    expected_closed,
):
    release = threading.Event()
    child_box = []
    wrapper_box = []
    cancellation = (
        KeyboardInterrupt(f"{pipe_name} close interrupted")
        if cancellation_kind == "keyboard"
        else SystemExit(f"{pipe_name} close interrupted")
    )

    def hangs(_command_fd, _control_fd):
        release.wait(5)
        return 0

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda _pid: (_ for _ in ()).throw(OSError("force teardown")),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(hangs, kill_hook=release.set)
        wrapper = _CancellingClosePipe(
            getattr(child, pipe_name), cancellation, close_mode,
        )
        setattr(child, pipe_name, wrapper)
        child_box.append(child)
        wrapper_box.append(wrapper)
        return child

    started = time.monotonic()
    try:
        with pytest.raises(type(cancellation)) as caught:
            supervisor.bootstrap_worker(
                _request(), deadline=started + 1, popen_factory=factory,
            )
        elapsed = time.monotonic() - started
        child = child_box[0]
        wrapper = wrapper_box[0]

        assert caught.value is cancellation
        assert wrapper.close_calls == expected_calls
        assert wrapper.closed is expected_closed
        other_pipe = child.stdout if pipe_name == "stdin" else child.stdin
        assert other_pipe.closed
        assert child.kill_calls == 1
        assert len(child.wait_timeouts) == 1
        assert not child._thread.is_alive()
        assert child.returncode == -9
        assert elapsed < 0.5
    finally:
        release.set()
        if wrapper_box and not wrapper_box[0].closed:
            wrapper_box[0].force_close()
        if child_box:
            other_pipe = (
                child_box[0].stdout
                if pipe_name == "stdin"
                else child_box[0].stdin
            )
            if not other_pipe.closed:
                other_pipe.close()
            child_box[0]._thread.join(1)


def test_pathologically_huge_deadline_is_a_typed_pre_spawn_refusal():
    calls = []
    with pytest.raises(ValueError, match="deadline"):
        supervisor.bootstrap_worker(
            _request(), deadline=10 ** 10_000,
            popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
    assert calls == []


@pytest.mark.parametrize("fault_seam", ["encode_request", "request_digest"])
def test_pre_spawn_request_fault_precedes_selector_allocation_without_fd_delta(
    monkeypatch, fault_seam,
):
    if not os.path.isdir("/proc/self/fd"):
        pytest.skip("exact descriptor accounting requires procfs")

    original_selector = supervisor.selectors.DefaultSelector
    trackers = []
    spawn_calls = []

    class TrackingSelector:
        def __init__(self):
            self.inner = original_selector()
            self.closed = False

        def close(self):
            self.closed = True
            self.inner.close()

    def allocate_selector():
        tracker = TrackingSelector()
        trackers.append(tracker)
        return tracker

    monkeypatch.setattr(
        supervisor.selectors, "DefaultSelector", allocate_selector,
    )
    monkeypatch.setattr(
        supervisor,
        fault_seam,
        lambda _request: (_ for _ in ()).throw(
            RuntimeError("injected private request failure")
        ),
    )

    before = len(os.listdir("/proc/self/fd"))
    outcome = supervisor.bootstrap_worker(
        _request(), deadline=time.monotonic() + 1,
        popen_factory=lambda *args, **kwargs: spawn_calls.append((args, kwargs)),
    )
    after = len(os.listdir("/proc/self/fd"))
    for tracker in trackers:
        if not tracker.closed:
            tracker.inner.close()

    assert outcome.reason is supervisor.BootstrapReason.REQUEST_FAILED
    assert not outcome.transaction_complete
    assert spawn_calls == []
    assert trackers == []
    assert after == before


def test_valid_transcript_eof_with_live_worker_is_killed_then_reaped_in_budget(
    monkeypatch,
):
    release = threading.Event()
    child_box = []

    def hangs_after_eof(command_fd, control_fd):
        request = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        prepared = _prepared(request)
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(request))
            + protocol.encode_prepared(prepared),
        )
        _read_prepared_abort(command_fd, request, prepared)
        runner_ipc.write_all(
            control_fd, protocol.encode_settlement(_settlement(request)),
        )
        os.close(control_fd)
        release.wait(5)
        return 0

    monkeypatch.setattr(
        supervisor,
        "capture_process_identity",
        lambda pid: SimpleNamespace(pid=pid, start_time_ticks=123),
    )

    def factory(_argv, **_kwargs):
        child = _PipeChild(hangs_after_eof, kill_hook=release.set)
        child_box.append(child)
        return child

    started = time.monotonic()
    try:
        outcome = supervisor.bootstrap_worker(
            _request(), deadline=started + 0.5, popen_factory=factory,
        )
    finally:
        release.set()
    elapsed = time.monotonic() - started
    child = child_box[0]
    assert elapsed < 0.8
    assert outcome.reason is supervisor.BootstrapReason.WORKER_FAILED
    assert not outcome.transaction_complete
    assert child.kill_calls == 1 and outcome.kill_requested
    assert len(child.wait_timeouts) == 2
    assert all(0 <= timeout <= 0.5 for timeout in child.wait_timeouts)
    assert outcome.worker_reaped
    assert outcome.worker_returncode == -9


@pytest.mark.parametrize("clock_value", [True, float("inf"), object()])
def test_bad_clock_result_is_a_typed_pre_spawn_refusal(clock_value):
    calls = []
    with pytest.raises(TypeError, match="clock") as error:
        supervisor.bootstrap_worker(
            _request(), deadline=10,
            clock=lambda: clock_value,
            popen_factory=lambda *args, **kwargs: calls.append((args, kwargs)),
        )
    assert calls == []
    assert "object at" not in str(error.value)
