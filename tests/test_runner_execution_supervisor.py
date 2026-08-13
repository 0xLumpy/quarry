"""Parent-side contract for one authenticated execution transaction.

This file deliberately leaves publication to the next Phase-1 slice.  The
supervisor owns containment, the exact worker, the private writer handoff and
control authentication through stable stage settlement; a later repository
transaction decides whether those settled bytes may become authoritative.
"""
from __future__ import annotations

import hashlib
import inspect
import os
import subprocess
import threading
import time
from dataclasses import FrozenInstanceError, is_dataclass
from types import SimpleNamespace

import pytest

from quarry_recon import privfs
from quarry_recon import runner_containment as containment
from quarry_recon import runner_ipc
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_supervisor as supervisor
from quarry_recon import runner_worker


pytestmark = pytest.mark.offline

RID = "d7" * 16
WORKER_PID = 47001
LAUNCHER_PID = 47002
DATA = b"private input\x00with utf-8 bytes\n"
STDOUT = b"\xffbinary stdout\nsecond"
STDERR = b"private stderr\n"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_control_wait_slices_semantically_unbounded_budget():
    class Selector:
        def __init__(self):
            self.timeouts = []

        def select(self, timeout):
            self.timeouts.append(timeout)
            return []

    selector = Selector()
    events, consumed = supervisor._select_control(selector, (1 << 53) - 1)

    assert events == []
    assert consumed is False
    assert selector.timeouts == [supervisor._CONTROL_SELECT_SLICE_SECONDS]


def test_control_wait_consumes_a_finite_short_budget():
    class Selector:
        def select(self, timeout):
            assert timeout == 0.25
            return []

    events, consumed = supervisor._select_control(Selector(), 0.25)

    assert events == []
    assert consumed is True


def test_unbounded_supervisor_wait_slice_is_platform_safe():
    assert 0 < supervisor._CHILD_WAIT_SLICE_SECONDS < (1 << 31)


def _read_exact(fd: int, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise AssertionError("execution wire ended before the raw payload")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _data_invocation(tmp_path):
    return protocol.normalize_invocation(
        request_id=RID,
        tool="fixture",
        cmd=["secret-tool", "secret-target"],
        timeout=30,
        stdin_data=DATA.decode("utf-8"),
        raw_path=str(tmp_path / "stdout.bin"),
        stderr_path=str(tmp_path / "stderr.bin"),
        env={"TOKEN": "environment-secret"},
        base_environment={"PATH": "/private/tool/path"},
    )


def _file_invocation(tmp_path, input_path):
    return protocol.normalize_invocation(
        request_id="d8" * 16,
        tool="fixture",
        cmd=["secret-tool", "secret-target"],
        timeout=30,
        input_file=str(input_path),
        raw_path=str(tmp_path / "stdout.bin"),
        env={"TOKEN": "environment-secret"},
        base_environment={"PATH": "/private/tool/path"},
    )


def _null_invocation():
    return protocol.normalize_invocation(
        request_id="d9" * 16,
        tool="fixture",
        cmd=["secret-tool", "secret-target"],
        timeout=30,
        env={"TOKEN": "environment-secret"},
        base_environment={"PATH": "/private/tool/path"},
    )


def _stage_batch(tmp_path, invocation, roles):
    tmp_path.chmod(0o700)
    anchor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        stages = tuple(
            privfs.create_private_stage(
                anchor,
                (
                    "stdout.bin"
                    if role is protocol.StreamRole.STDOUT
                    else "stderr.bin",
                ),
            )
            for role in roles
        )
    finally:
        os.close(anchor)
    return privfs.prepare_private_stage_handoff(
        stages, invocation.worker.request_id,
    )


def _cleanup_batch(batch):
    if batch.state == "prepared":
        privfs.abort_unspawned_private_stage_handoff(batch)
    elif batch.state not in {"fenced", "committed", "aborted"}:
        privfs.fence_private_stage_handoff(batch)


def _ready(request, *, digest=None, worker_pid=WORKER_PID):
    return protocol.ReadyFrame(
        request_id=request.request_id,
        worker_pid=worker_pid,
        request_sha256=(
            protocol.request_digest(request) if digest is None else digest
        ),
    )


def _prepared(request, containment_id):
    return protocol.PreparedFrame(
        request_id=request.request_id,
        worker_pid=WORKER_PID,
        launcher_pid=LAUNCHER_PID,
        launcher_pgid=LAUNCHER_PID,
        containment_kind=protocol.ContainmentKind.CGROUP_V2,
        containment_id=containment_id,
    )


def _started(request, containment_id):
    return protocol.StartedFrame(
        request_id=request.request_id,
        worker_pid=WORKER_PID,
        tool_pid=LAUNCHER_PID,
        tool_pgid=LAUNCHER_PID,
        containment_kind=protocol.ContainmentKind.CGROUP_V2,
        containment_id=containment_id,
    )


def _stream(
    request,
    role,
    data,
    *,
    terminal,
    retained=True,
):
    claim = request.claim_for(role)
    return protocol.StreamSettlement(
        role=role,
        terminal=terminal,
        observed_bytes=len(data),
        retained_bytes=len(data) if retained else 0,
        observed_sha256=_digest(data),
        retained_sha256=_digest(data) if retained else None,
        claim_id=(
            None
            if role is protocol.StreamRole.STDIN or claim is None
            else claim.claim_id
        ),
        lines=(
            data.count(b"\n")
            if retained and role is not protocol.StreamRole.STDIN
            else 0
        ),
    )


def _settlement(request, *, stdin_data, stdout=STDOUT, stderr=STDERR):
    stdout_claimed = request.stdout_requested
    stderr_claimed = request.stderr_requested
    return protocol.WorkerSettlement(
        request_id=request.request_id,
        terminal=protocol.ExecutionTerminal.COMPLETE,
        launched=True,
        exit_code=0,
        process_group_settled=True,
        process_tree_settled=False,
        streams=(
            _stream(
                request,
                protocol.StreamRole.STDIN,
                stdin_data,
                terminal=protocol.StreamTerminal.COMPLETE,
                retained=False,
            ),
            _stream(
                request,
                protocol.StreamRole.STDOUT,
                stdout if stdout_claimed else b"",
                terminal=protocol.StreamTerminal.EOF,
                retained=stdout_claimed,
            ),
            _stream(
                request,
                protocol.StreamRole.STDERR,
                stderr if stderr_claimed else b"",
                terminal=protocol.StreamTerminal.EOF,
                retained=stderr_claimed,
            ),
        ),
        worker_pid=WORKER_PID,
        tool_pid=LAUNCHER_PID,
    )


class _ExecutionChild:
    """Popen-shaped peer that duplicates inherited FDs like a real fork."""

    def __init__(self, handler, *, pass_fds, env, events):
        request_read, parent_write = os.pipe()
        parent_read, control_write = os.pipe()
        self.stdin = os.fdopen(parent_write, "wb", buffering=0)
        self.stdout = os.fdopen(parent_read, "rb", buffering=0)
        self.pid = WORKER_PID
        self.returncode = None
        self.killed = False
        self.kill_calls = 0
        self.wait_calls = 0
        self._events = events
        self._handler_result = None
        self._forced_returncode = None
        self._request_read = request_read
        self._control_write = control_write
        self.inherited = {fd: os.dup(fd) for fd in pass_fds}

        def target():
            try:
                self._handler_result = handler(
                    request_read, control_write, self.inherited, env,
                )
            except BaseException:
                self._handler_result = 91
            finally:
                for fd in (
                    request_read,
                    control_write,
                    *self.inherited.values(),
                ):
                    try:
                        os.close(fd)
                    except OSError:
                        pass

        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls += 1
        self._thread.join(timeout)
        if self._thread.is_alive():
            raise subprocess.TimeoutExpired("execution-worker", timeout)
        if self.returncode is None:
            self.returncode = (
                self._forced_returncode
                if self._forced_returncode is not None
                else self._handler_result
            )
        self._events.append("worker_reaped")
        return self.returncode

    def kill(self):
        self.kill_calls += 1
        self.killed = True
        self._events.append("worker_killed")
        for fd in (self._request_read, self._control_write):
            try:
                os.close(fd)
            except OSError:
                pass
        if self.returncode is None:
            self._forced_returncode = -9


class _DirectHandle:
    kind = protocol.ContainmentKind.CGROUP_V2
    containment_assurance = protocol.ContainmentAssurance.COOPERATIVE_SCOPE

    def __init__(self, request_id, events):
        self.containment_id = f"direct/quarry-{request_id}"
        self.events = events
        self.bind_proofs = []
        self.verify_identities = []
        self.settlement_deadlines = []
        self.close_calls = 0
        self.terminal = False

    def bind_parked_process(self, proof):
        self.bind_proofs.append(proof)
        self.events.append("launcher_bound")
        return containment.MembershipVerification(
            True, containment.ContainmentReason.VERIFIED,
        )

    def verify_pid(self, identity):
        self.verify_identities.append(identity)
        self.events.append("tool_verified")
        return containment.MembershipVerification(
            True, containment.ContainmentReason.VERIFIED,
        )

    def kill_settle_remove(self, deadline):
        self.settlement_deadlines.append(deadline)
        self.events.append("containment_settled")
        self.terminal = True
        return containment.ContainmentSettlement(
            True,
            True,
            True,
            containment.ContainmentReason.SETTLED,
        )

    def close(self):
        self.close_calls += 1
        self.events.append("containment_closed")
        self.terminal = True


class _DirectFactory:
    def __init__(self, events):
        self.events = events
        self.calls = []
        self.handles = []

    def __call__(self, request_id):
        self.calls.append(request_id)
        self.events.append("containment_acquired")
        handle = _DirectHandle(request_id, self.events)
        self.handles.append(handle)
        return handle

    @property
    def handle(self):
        assert self.handles
        return self.handles[-1]


def _install_parent_fakes(monkeypatch, events):
    factory = _DirectFactory(events)
    monkeypatch.setattr(supervisor, "acquire_direct_cgroup_v2", factory)

    def capture_process(pid):
        events.append("worker_authenticated" if pid == WORKER_PID else "tool_authenticated")
        return containment.ProcessIdentity(pid=pid, start_time_ticks=pid + 100)

    def capture_parked(pid, parent):
        events.append("launcher_authenticated")
        assert pid == LAUNCHER_PID
        assert parent.pid == WORKER_PID
        return SimpleNamespace(
            process=containment.ProcessIdentity(
                pid=pid, start_time_ticks=pid + 100,
            ),
            parent=parent,
            state="T",
        )

    monkeypatch.setattr(supervisor, "capture_process_identity", capture_process)
    monkeypatch.setattr(
        supervisor, "capture_parked_process_identity", capture_parked,
    )
    return factory


def _spawn_factory(handler, events, calls, batch=None):
    def factory(argv, **kwargs):
        events.append("worker_spawned")
        if batch is not None:
            assert batch.state == "spawn_prepared"
        calls.append((argv, kwargs))
        return _ExecutionChild(
            handler,
            pass_fds=kwargs.get("pass_fds", ()),
            env=kwargs["env"],
            events=events,
        )

    return factory


def _assert_fixed_execution_spawn(call, *, expected_fds):
    argv, kwargs = call
    assert argv == [
        supervisor.sys.executable,
        "-I",
        "-m",
        "quarry_recon.runner_worker",
    ]
    assert kwargs["stdin"] is subprocess.PIPE
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["close_fds"] is True
    assert kwargs["start_new_session"] is True
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == "/"
    assert kwargs["bufsize"] == 0
    assert kwargs["text"] is False
    assert set(kwargs["pass_fds"]) == set(expected_fds)
    rendered = repr(argv) + repr(kwargs)
    for secret in (
        "secret-tool",
        "secret-target",
        "environment-secret",
        "/private/tool/path",
    ):
        assert secret not in rendered


def test_execution_api_is_additive_and_keeps_bootstrap_shape_stable():
    signature = inspect.signature(supervisor.supervise_execution)
    assert tuple(signature.parameters) == (
        "invocation", "stage_batch", "deadline", "clock", "popen_factory",
    )
    assert signature.parameters["invocation"].kind \
        is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert signature.parameters["stage_batch"].kind \
        is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["stage_batch"].default is None
    assert all(
        signature.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        for name in ("deadline", "clock", "popen_factory")
    )
    assert tuple(inspect.signature(supervisor.bootstrap_worker).parameters) == (
        "request", "deadline", "clock", "popen_factory",
    )
    assert is_dataclass(supervisor.ExecutionOutcome)
    assert supervisor.ExecutionReason.COMPLETE.value == "complete"
    assert supervisor.ExecutionReason.CONTROL_FAILED.value == "control_failed"


def test_data_execution_transfers_writers_before_hash_bound_go_and_settles(
    tmp_path, monkeypatch,
):
    invocation = _data_invocation(tmp_path)
    request = invocation.worker
    batch = _stage_batch(
        tmp_path,
        invocation,
        (protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR),
    )
    events = []
    calls = []
    direct = _install_parent_fakes(monkeypatch, events)

    real_settle = privfs.settle_private_stage_handoff

    def settle_after_all_owners(*args, **kwargs):
        assert "worker_reaped" in events
        assert "containment_settled" in events
        events.append("stages_settled")
        return real_settle(*args, **kwargs)

    monkeypatch.setattr(privfs, "settle_private_stage_handoff", settle_after_all_owners)
    monkeypatch.setattr(
        supervisor,
        "settle_private_stage_handoff",
        settle_after_all_owners,
        raising=False,
    )

    def peer(command_fd, control_fd, inherited, env):
        decoded = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        assert decoded == request
        assert _read_exact(command_fd, decoded.stdin_bytes) == DATA
        events.append("data_received")
        prepared = _prepared(decoded, direct.handle.containment_id)
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(decoded))
            + protocol.encode_prepared(prepared),
        )
        command = protocol.decode_command(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        assert batch.state == "parent_writers_closed"
        assert "launcher_bound" in events
        assert command == protocol.WorkerCommand(
            request_id=decoded.request_id,
            request_sha256=protocol.request_digest(decoded),
            worker_pid=WORKER_PID,
            command=protocol.WorkerCommandKind.GO,
            prepared_sha256=protocol.prepared_digest(prepared),
        )
        events.append("go_received")

        stdout_fd = inherited[int(env[runner_worker.STDOUT_FD_ENV])]
        stderr_fd = inherited[int(env[runner_worker.STDERR_FD_ENV])]
        runner_ipc.write_all(stdout_fd, STDOUT)
        runner_ipc.write_all(stderr_fd, STDERR)
        os.close(stdout_fd)
        os.close(stderr_fd)
        inherited.pop(int(env[runner_worker.STDOUT_FD_ENV]))
        inherited.pop(int(env[runner_worker.STDERR_FD_ENV]))
        runner_ipc.write_all(
            control_fd,
            protocol.encode_started(_started(decoded, direct.handle.containment_id))
            + protocol.encode_settlement(
                _settlement(decoded, stdin_data=DATA),
            ),
        )
        return 0

    try:
        outcome = supervisor.supervise_execution(
            invocation,
            stage_batch=batch,
            deadline=time.monotonic() + 3,
            popen_factory=_spawn_factory(peer, events, calls, batch),
        )

        assert outcome.reason is supervisor.ExecutionReason.COMPLETE
        assert outcome.transaction_complete is True
        assert outcome.worker_reaped is True
        assert outcome.control_eof is True
        assert outcome.validated.capture_complete is True
        assert outcome.validated.mechanically_settled is True
        assert batch.state == "settled"
        assert tuple(
            (proof.role, proof.size, proof.sha256, proof.lines)
            for proof in outcome.artifact_proofs
        ) == (
            ("stdout", len(STDOUT), _digest(STDOUT), STDOUT.count(b"\n")),
            ("stderr", len(STDERR), _digest(STDERR), STDERR.count(b"\n")),
        )
        assert events.index("containment_acquired") < events.index("worker_spawned")
        assert events.index("launcher_authenticated") < events.index("launcher_bound")
        assert events.index("launcher_bound") < events.index("go_received")
        assert events.index("go_received") < events.index("tool_verified")
        assert events.index("worker_reaped") < events.index("containment_settled")
        assert events.index("containment_settled") < events.index("stages_settled")
        assert direct.calls == [request.request_id]
        assert direct.handle.terminal is True
        assert len(calls) == 1
        pass_fds = calls[0][1]["pass_fds"]
        assert len(pass_fds) == 2
        _assert_fixed_execution_spawn(calls[0], expected_fds=pass_fds)
        assert set(calls[0][1]["env"]) == {
            runner_worker.EXPECTED_PARENT_PID_ENV,
            runner_worker.EXECUTION_ENV,
            runner_worker.STDOUT_FD_ENV,
            runner_worker.STDERR_FD_ENV,
        }
        with pytest.raises((FrozenInstanceError, AttributeError)):
            outcome.reason = supervisor.ExecutionReason.CONTROL_FAILED
    finally:
        _cleanup_batch(batch)


def test_file_input_is_inherited_once_without_path_disclosure(
    tmp_path, monkeypatch,
):
    input_bytes = b"file input\x00\xff\n"
    input_path = tmp_path / "private-input.bin"
    input_path.write_bytes(input_bytes)
    input_path.chmod(0o600)
    invocation = _file_invocation(tmp_path, input_path)
    request = invocation.worker
    batch = _stage_batch(tmp_path, invocation, (protocol.StreamRole.STDOUT,))
    events = []
    calls = []
    direct = _install_parent_fakes(monkeypatch, events)

    def peer(command_fd, control_fd, inherited, env):
        decoded = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        prepared = _prepared(decoded, direct.handle.containment_id)
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(decoded))
            + protocol.encode_prepared(prepared),
        )
        command = protocol.decode_command(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        assert command.command is protocol.WorkerCommandKind.GO
        stdin_fd = inherited[int(env[runner_worker.STDIN_FD_ENV])]
        stdout_fd = inherited[int(env[runner_worker.STDOUT_FD_ENV])]
        assert _read_exact(stdin_fd, len(input_bytes)) == input_bytes
        assert os.read(stdin_fd, 1) == b""
        runner_ipc.write_all(stdout_fd, STDOUT)
        for inherited_fd in (stdin_fd, stdout_fd):
            os.close(inherited_fd)
        inherited.pop(int(env[runner_worker.STDIN_FD_ENV]))
        inherited.pop(int(env[runner_worker.STDOUT_FD_ENV]))
        runner_ipc.write_all(
            control_fd,
            protocol.encode_started(_started(decoded, direct.handle.containment_id))
            + protocol.encode_settlement(
                _settlement(decoded, stdin_data=input_bytes, stderr=b""),
            ),
        )
        return 0

    try:
        outcome = supervisor.supervise_execution(
            invocation,
            stage_batch=batch,
            deadline=time.monotonic() + 3,
            popen_factory=_spawn_factory(peer, events, calls, batch),
        )

        assert outcome.transaction_complete is True
        assert outcome.validated.capture_complete is True
        stdin_stream = next(
            stream
            for stream in outcome.settlement.streams
            if stream.role is protocol.StreamRole.STDIN
        )
        assert stdin_stream.observed_sha256 == _digest(input_bytes)
        argv, kwargs = calls[0]
        env = kwargs["env"]
        assert set(env) == {
            runner_worker.EXPECTED_PARENT_PID_ENV,
            runner_worker.EXECUTION_ENV,
            runner_worker.STDIN_FD_ENV,
            runner_worker.STDOUT_FD_ENV,
        }
        input_fd = int(env[runner_worker.STDIN_FD_ENV])
        stdout_fd = int(env[runner_worker.STDOUT_FD_ENV])
        assert input_fd != stdout_fd
        _assert_fixed_execution_spawn(
            calls[0], expected_fds=(input_fd, stdout_fd),
        )
        assert str(input_path) not in repr(argv) + repr(kwargs)
    finally:
        _cleanup_batch(batch)


def test_invalid_ready_authentication_never_sends_go_and_still_reaps(
    monkeypatch,
):
    invocation = _null_invocation()
    request = invocation.worker
    events = []
    calls = []
    direct = _install_parent_fakes(monkeypatch, events)
    command_eof = threading.Event()
    observed = []

    def peer(command_fd, control_fd, _inherited, _env):
        decoded = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(decoded, digest="ab" * 32)),
        )
        os.close(control_fd)
        try:
            observed.append(os.read(command_fd, 1))
        except OSError:
            observed.append(None)
        finally:
            command_eof.set()
        return 0

    outcome = supervisor.supervise_execution(
        invocation,
        deadline=time.monotonic() + 3,
        popen_factory=_spawn_factory(peer, events, calls),
    )

    assert command_eof.wait(1)
    assert observed in ([b""], [None])
    assert outcome.reason is supervisor.ExecutionReason.CONTROL_FAILED
    assert outcome.transaction_complete is False
    assert outcome.worker_reaped is True
    assert calls[0][1]["pass_fds"] == ()
    assert calls[0][1]["env"] == {
        runner_worker.EXPECTED_PARENT_PID_ENV: str(os.getpid()),
        runner_worker.EXECUTION_ENV: "1",
    }
    assert direct.handle.terminal is True
    assert "launcher_bound" not in events
    assert "worker_killed" in events


def test_cancellation_before_parked_binding_fences_stages_and_reaps_exact_worker(
    tmp_path, monkeypatch,
):
    invocation = _data_invocation(tmp_path)
    batch = _stage_batch(
        tmp_path,
        invocation,
        (protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR),
    )
    request = invocation.worker
    events = []
    calls = []
    direct = _install_parent_fakes(monkeypatch, events)
    cancellation = KeyboardInterrupt("cancel parked authentication")
    observed = []
    command_eof = threading.Event()

    def cancel_capture(_pid, _parent):
        raise cancellation

    monkeypatch.setattr(
        supervisor, "capture_parked_process_identity", cancel_capture,
    )

    def peer(command_fd, control_fd, _inherited, _env):
        decoded = protocol.decode_request(runner_ipc.read_frame(
            command_fd, max_frame_bytes=protocol.MAX_FRAME_BYTES,
        ))
        assert _read_exact(command_fd, decoded.stdin_bytes) == DATA
        runner_ipc.write_all(
            control_fd,
            protocol.encode_ready(_ready(decoded))
            + protocol.encode_prepared(
                _prepared(decoded, direct.handle.containment_id),
            ),
        )
        try:
            observed.append(os.read(command_fd, 1))
        except OSError:
            observed.append(None)
        finally:
            command_eof.set()
        return 0

    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            supervisor.supervise_execution(
                invocation,
                stage_batch=batch,
                deadline=time.monotonic() + 3,
                popen_factory=_spawn_factory(peer, events, calls, batch),
            )

        assert caught.value is cancellation
        assert command_eof.wait(1)
        assert observed in ([b""], [None])
        assert batch.state == "fenced"
        assert "worker_killed" in events
        assert "worker_reaped" in events
        assert "containment_settled" in events
        assert direct.handle.terminal is True
        assert "launcher_bound" not in events
    finally:
        _cleanup_batch(batch)
