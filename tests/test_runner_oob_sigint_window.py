"""Bounded, source-stamped SIGINT deadline posture for OOB control."""
from __future__ import annotations

import os
import sys
import time
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import runner, runner_native, runner_protocol as protocol
from quarry_recon import runner_repository, runner_supervisor, store
from quarry_recon import runner_streams, runner_worker


pytestmark = [pytest.mark.offline, pytest.mark.synthetic_process]


def _launcher():
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    try:
        return runner_worker._spawn_execution_launcher(
            inherited_fds=(request_read, control_write),
        )
    finally:
        for fd in (request_read, request_write, control_read, control_write):
            try:
                os.close(fd)
            except OSError:
                pass


def _close_launcher(launcher) -> None:
    try:
        launcher.abort_and_reap()
    finally:
        for name in ("stdin_write_fd", "stdout_read_fd", "stderr_read_fd"):
            fd = getattr(launcher, name, -1)
            if type(fd) is int and fd >= 0:
                os.close(fd)
                setattr(launcher, name, -1)


def _settle(tmp_path, script: str, *, execution_window: float = .10,
            settlement_window: float = .45):
    invocation = protocol.normalize_invocation(
        request_id=os.urandom(16).hex(),
        tool="interactsh-client",
        cmd=(sys.executable, "-c", script),
        timeout=1,
        env={}, base_environment={},
        raw_path=tmp_path / "stdout", stderr_path=tmp_path / "stderr",
        _deadline_sigint=True,
    )
    stdout_fd = os.open(tmp_path / "stdout.stage", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    stderr_fd = os.open(tmp_path / "stderr.stage", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    launcher = _launcher()
    try:
        assert launcher.prove_stopped()
        now = time.monotonic()
        result = runner_streams._run_stream_engine(
            invocation.worker, launcher, stdin_data=invocation.stdin_data,
            stdout_stage_fd=stdout_fd, stderr_stage_fd=stderr_fd,
            execution_deadline=now + execution_window,
            settlement_deadline=now + settlement_window,
        )
        stdout = os.pread(stdout_fd, os.fstat(stdout_fd).st_size, 0)
        return invocation.worker, result, stdout
    finally:
        _close_launcher(launcher)
        os.close(stdout_fd)
        os.close(stderr_fd)


def test_deadline_sigint_drains_then_authenticates_only_exit_one(tmp_path):
    request, settlement, stdout = _settle(
        tmp_path,
        "import os,signal,time;"
        "signal.signal(signal.SIGINT,lambda *_: (os.write(1,b'persisted\\n'),(_ for _ in ()).throw(SystemExit(1)))[1]);"
        "time.sleep(10)",
    )

    assert request.deadline_sigint is True
    assert protocol.WorkerRequest.from_dict(request.to_dict()) == request
    assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert settlement.detail == "sigint_deadline_exit"
    assert settlement.exit_code == 1
    assert stdout == b"persisted\n"


def test_early_exit_one_is_not_marked_as_sigint_deadline_completion(tmp_path):
    _request, settlement, _stdout = _settle(tmp_path, "raise SystemExit(1)")

    assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert settlement.exit_code == 1
    assert settlement.detail is None


def test_sigint_survivor_is_hard_killed_at_fixed_settlement_deadline(tmp_path):
    started = time.monotonic()
    _request, settlement, _stdout = _settle(
        tmp_path,
        "import signal,time;signal.signal(signal.SIGINT,signal.SIG_IGN);time.sleep(10)",
        settlement_window=.35,
    )

    assert time.monotonic() - started < 1.5
    assert settlement.terminal is protocol.ExecutionTerminal.WORKER_FAILED
    assert settlement.detail == "settlement_deadline"


def _repository_result_for(request, settlement):
    digest = sha256(b"").hexdigest()
    validated = protocol.ValidatedSettlement(
        worker=settlement,
        mechanically_settled=True,
        containment_assurance=protocol.ContainmentAssurance.COOPERATIVE_SCOPE,
        escape_protected=False,
        tree_proven=False,
        clean_eligible=True,
        capture_complete=True,
        _authority=protocol._VALIDATION_AUTHORITY,
    )
    execution = runner_supervisor.ExecutionOutcome(
        reason=runner_supervisor.ExecutionReason.COMPLETE,
        request_id=request.request_id, worker_pid=123, settlement=settlement,
        validated=validated, worker_returncode=0, worker_spawned=True,
        worker_reaped=True, control_eof=True, go_command_sent=True,
        parent_pipes_closed=True, containment_settled=True, stages_settled=True,
        _authority=runner_supervisor._EXECUTION_OUTCOME_AUTHORITY,
    )
    outcome = runner_repository.RepositoryExecutionOutcome(
        execution=execution,
        publication=runner_repository.RepositoryPublication.NOT_REQUESTED,
        requested_roles=(),
        discarded_roles=(protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR),
    )
    discard = runner_repository.RepositoryOutput.discard()
    return runner._repository_run_result(
        "interactsh-client", ["interactsh-client"], outcome, request=request,
        stdout=discard, stderr=discard, stdout_path=None, stderr_path=None,
        duration=0.1,
    )


def test_only_witnessed_post_sigint_exit_one_can_be_clean(tmp_path):
    request = protocol.normalize_invocation(
        request_id=os.urandom(16).hex(), tool="interactsh-client",
        cmd=("interactsh-client",), timeout=1, env={}, base_environment={},
        _deadline_sigint=True,
    ).worker
    digest = sha256(b"").hexdigest()
    streams = tuple(
        protocol.StreamSettlement(
            role=role,
            terminal=(protocol.StreamTerminal.COMPLETE
                      if role is protocol.StreamRole.STDIN else protocol.StreamTerminal.EOF),
            observed_bytes=0, retained_bytes=0, observed_sha256=digest,
            retained_sha256=None,
        )
        for role in protocol.StreamRole
    )
    witnessed = protocol.WorkerSettlement(
        request_id=request.request_id, terminal=protocol.ExecutionTerminal.COMPLETE,
        launched=True, exit_code=1, process_group_settled=True,
        process_tree_settled=False, streams=streams, worker_pid=123, tool_pid=456,
        detail="sigint_deadline_exit",
    )

    clean = _repository_result_for(request, witnessed)
    early = _repository_result_for(request, replace(witnessed, detail=None))

    assert clean.status is runner.Status.EMPTY
    assert clean.meta["deadline_sigint"] is True
    assert clean.meta["execution_terminal"] == "complete"
    assert clean.meta["process_group_settled"] is True
    assert clean.meta["process_tree_settled"] is False
    assert clean.meta["execution_request_id"] == request.request_id
    assert clean.meta["execution_detail"] == "sigint_deadline_exit"
    assert early.status is runner.Status.FAILED


def _running_run(project: Path, run_id: str) -> store.Run:
    run = store.Run.create(project, "oob-control.example", run_id=run_id)
    run.write_state("running")
    return run


def _native_sigint_outcome(tmp_path, monkeypatch, *, detail: str | None):
    run = _running_run(tmp_path, "native-" + (detail or "early"))
    final = run.dir / "raw" / "oob" / "interactsh.session"
    command = [
        sys.executable, "-c", "pass", str(final),
    ]
    policy = runner_native.RepositoryNativeOutput.file(
        3, "raw", "oob", "interactsh.session",
    )

    def supervise(_run, invocation, **_kwargs):
        Path(invocation.worker.argv[3]).write_text("resumable-session")
        return SimpleNamespace(
            clean=True,
            execution=SimpleNamespace(settlement=SimpleNamespace(
                terminal=protocol.ExecutionTerminal.COMPLETE,
                exit_code=1,
                detail=detail,
            )),
        )

    def result(tool, cmd, _outcome, **_kwargs):
        return runner.RunResult(
            tool, cmd, runner.Status.EMPTY, 1, 0.0, None, 0,
            meta={"started": True, "repository_ownership_settled": True},
        )

    monkeypatch.setattr(runner_repository, "supervise_repository_execution", supervise)
    monkeypatch.setattr(runner, "_repository_run_result", result)
    observed = runner.run(
        "interactsh-client", command, repository=run,
        source_id="params.oob_control",
        stdout=runner_repository.RepositoryOutput.discard(),
        stderr=runner_repository.RepositoryOutput.discard(),
        native_outputs=(policy,), timeout=20,
    )
    return observed, final


def test_native_outputs_publish_only_for_witnessed_sigint_exit_one(tmp_path, monkeypatch):
    published, published_path = _native_sigint_outcome(
        tmp_path, monkeypatch, detail="sigint_deadline_exit",
    )

    assert published_path.read_text() == "resumable-session"
    assert published.meta["native_outputs"]["clean"] is True
    assert runner.native_output_current(published, published_path) is True


def test_native_outputs_roll_back_early_exit_one(tmp_path, monkeypatch):
    rolled_back, final = _native_sigint_outcome(tmp_path, monkeypatch, detail=None)

    assert not final.exists()
    assert rolled_back.meta["native_outputs"]["clean"] is False
    assert runner.native_output_current(rolled_back, final) is False
