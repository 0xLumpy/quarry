"""Phase 1 contract for repository-owned OSINT tool execution.

An OSINT session is a repository in miniature: tool output is private evidence,
finalization seals it, and two handles or processes must not invent independent
authority for the same session directory.  These tests deliberately exercise
the public composition seam rather than accepting an object-local lock as a
substitute for durable session ownership.
"""
from __future__ import annotations

import hashlib
import os
import select
import signal
import stat
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import osint, privfs
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_repository
from quarry_recon import runner_supervisor as supervisor


pytestmark = pytest.mark.offline

TARGET = "acme.example"
SESSION_ID = "20260813-120000"
WORKER_PID = 61231
TOOL_PID = 61232
STDOUT = b"\xffosint repository evidence\nsecond\n"


class FixtureClockFault(RuntimeError):
    pass


class FixturePublicationFault(OSError):
    pass


class FixtureFinalizationFault(RuntimeError):
    pass


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _session(project: Path, *, session_id: str = SESSION_ID):
    return osint.OsintSession(project, TARGET, ts=session_id)


def _profile():
    return SimpleNamespace(
        target=TARGET,
        path=Path("/fixture/profile.yaml"),
        apex_domains=[TARGET],
        asn=[],
        org_names=[],
        brands=[],
    )


def _policies(session, *, publish=True):
    stdout = (
        session.output(session.raw_path("fixture", "stdout.bin"))
        if publish else session.output()
    )
    return stdout, session.output()


def _invocation(session, stdout, stderr, *, request_byte="a7"):
    raw_path = (
        os.path.abspath(str(session.dir.joinpath(*stdout.components)))
        if stdout.disposition is runner_repository.ArtifactDisposition.PUBLISH
        else None
    )
    stderr_path = (
        os.path.abspath(str(session.dir.joinpath(*stderr.components)))
        if stderr.disposition is runner_repository.ArtifactDisposition.PUBLISH
        else None
    )
    return protocol.normalize_invocation(
        request_id=request_byte * 16,
        tool="fixture",
        cmd=["fixture", "--bounded"],
        timeout=30,
        raw_path=raw_path,
        stderr_path=stderr_path,
        base_environment={"PATH": "/private/tool/path"},
    )


def _write_exact(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        assert written > 0
        view = view[written:]


def _settle_batch(invocation, batch, payload=STDOUT):
    request = invocation.worker
    roles = tuple(
        claim.role for claim in request.descriptor_claims
        if claim.role in (protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR)
    )
    authority = privfs._prepare_private_stage_transfer_authority(
        batch, request_id=request.request_id,
    )

    def spawn(writer_fds):
        assert len(writer_fds) == len(roles)
        for role, fd in zip(roles, writer_fds):
            _write_exact(fd, payload if role is protocol.StreamRole.STDOUT else b"")
            os.fsync(fd)
        return SimpleNamespace(pid=WORKER_PID)

    _child, authority = privfs._spawn_with_private_stage_handoff(
        batch, authority, spawn,
    )
    privfs._bind_private_stage_transfer_authority(
        batch, authority, worker_pid=WORKER_PID,
    )
    receipt = privfs.transfer_private_stage_handoff(batch, authority)
    return privfs.settle_private_stage_handoff(
        batch,
        receipt,
        worker_reaped=True,
        claims=tuple(
            (request.claim_for(role).claim_id, role.value) for role in roles
        ),
    )


def _stream(request, role, data, proof_by_role):
    proof = proof_by_role.get(role)
    return protocol.StreamSettlement(
        role=role,
        terminal=protocol.StreamTerminal.EOF,
        observed_bytes=len(data),
        retained_bytes=0 if proof is None else len(data),
        observed_sha256=_digest(data),
        retained_sha256=None if proof is None else _digest(data),
        claim_id=None if proof is None else request.claim_for(role).claim_id,
        lines=0 if proof is None else data.count(b"\n"),
        detail=None,
    )


def _complete_outcome(invocation, proofs=(), payload=STDOUT):
    request = invocation.worker
    proof_by_role = {
        protocol.StreamRole(proof.role): proof for proof in proofs
    }
    empty = b""
    settlement = protocol.WorkerSettlement(
        request_id=request.request_id,
        terminal=protocol.ExecutionTerminal.COMPLETE,
        launched=True,
        exit_code=0,
        process_group_settled=True,
        process_tree_settled=False,
        streams=(
            protocol.StreamSettlement(
                role=protocol.StreamRole.STDIN,
                terminal=protocol.StreamTerminal.COMPLETE,
                observed_bytes=0,
                retained_bytes=0,
                observed_sha256=_digest(empty),
                retained_sha256=None,
                claim_id=None,
                lines=0,
                detail=None,
            ),
            _stream(
                request,
                protocol.StreamRole.STDOUT,
                payload if request.stdout_requested else empty,
                proof_by_role,
            ),
            _stream(
                request,
                protocol.StreamRole.STDERR,
                empty,
                proof_by_role,
            ),
        ),
        worker_pid=WORKER_PID,
        tool_pid=TOOL_PID,
        detail=None,
    )
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
    return supervisor.ExecutionOutcome(
        reason=supervisor.ExecutionReason.COMPLETE,
        request_id=request.request_id,
        worker_pid=WORKER_PID,
        settlement=settlement,
        validated=validated,
        artifact_proofs=tuple(proofs),
        worker_returncode=0,
        worker_spawned=True,
        worker_reaped=True,
        control_eof=True,
        go_command_sent=True,
        parent_pipes_closed=True,
        containment_settled=True,
        stages_settled=True,
        _authority=supervisor._EXECUTION_OUTCOME_AUTHORITY,
    )


def _successful_supervisor(*, observe=None):
    def execute(invocation, *, stage_batch, deadline, clock, popen_factory):
        if observe is not None:
            observe(invocation, stage_batch)
        proofs = _settle_batch(invocation, stage_batch) if stage_batch is not None else ()
        return _complete_outcome(invocation, proofs)

    return execute


def _claim_markers(session) -> list[Path]:
    claim_dir = session.dir / ".execution-claims"
    return sorted(claim_dir.iterdir()) if claim_dir.is_dir() else []


def _tree_snapshot(root: Path):
    root = Path(root)
    if not root.exists():
        return None
    result = []
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        payload = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        link = os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
        result.append((
            str(path.relative_to(root)), stat.S_IFMT(info.st_mode),
            stat.S_IMODE(info.st_mode), info.st_dev, info.st_ino, payload, link,
        ))
    return result


def _run_supervisor(session, invocation, stdout, stderr):
    return runner_repository.supervise_osint_execution(
        session,
        invocation,
        stdout=stdout,
        stderr=stderr,
        deadline=time.monotonic() + 10,
    )


def _reap_bounded(pid: int, timeout=5.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    _waited, status = os.waitpid(pid, 0)
    pytest.fail(f"forked OSINT authority did not settle (wait status {status})")


def test_exact_session_type_is_required_before_claim_stage_or_spawn(tmp_path, monkeypatch):
    class Lookalike(osint.OsintSession):
        pass

    session = Lookalike(tmp_path, TARGET, ts=SESSION_ID)
    stdout, stderr = _policies(session)
    invocation = _invocation(session, stdout, stderr)
    spawned = []
    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        lambda *args, **kwargs: spawned.append((args, kwargs)),
    )
    before = _tree_snapshot(session.dir)

    with pytest.raises(TypeError, match="exact|session|authority"):
        _run_supervisor(session, invocation, stdout, stderr)

    assert not spawned
    assert not _claim_markers(session)
    assert _tree_snapshot(session.dir) == before


@pytest.mark.parametrize("replacement", ["directory", "symlink"])
def test_session_root_substitution_refuses_before_claim_stage_or_spawn(
    tmp_path, monkeypatch, replacement,
):
    session = _session(tmp_path)
    stdout, stderr = _policies(session)
    invocation = _invocation(session, stdout, stderr)
    original = session.dir.with_name(session.dir.name + "-original")
    outside = tmp_path / "outside"
    outside.mkdir()
    session.dir.rename(original)
    if replacement == "directory":
        session.dir.mkdir(mode=0o700)
    else:
        session.dir.symlink_to(outside, target_is_directory=True)
    replacement_before = _tree_snapshot(outside if replacement == "symlink" else session.dir)
    spawned = []
    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        lambda *args, **kwargs: spawned.append((args, kwargs)),
    )

    with pytest.raises((RuntimeError, OSError), match="identity|unsafe|unavailable"):
        _run_supervisor(session, invocation, stdout, stderr)

    assert not spawned
    assert not (original / ".execution-claims").exists()
    assert _tree_snapshot(outside if replacement == "symlink" else session.dir) == replacement_before


def test_symlinked_raw_ancestor_never_redirects_stage_or_publication(tmp_path, monkeypatch):
    session = _session(tmp_path)
    stdout = runner_repository.RepositoryOutput.publish("raw", "fixture", "stdout.bin")
    stderr = runner_repository.RepositoryOutput.discard()
    invocation = _invocation(session, stdout, stderr)
    outside = tmp_path / "outside"
    outside.mkdir()
    session.raw.rmdir()
    session.raw.symlink_to(outside, target_is_directory=True)
    before = _tree_snapshot(outside)
    spawned = []
    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        lambda *args, **kwargs: spawned.append((args, kwargs)),
    )

    with pytest.raises((RuntimeError, OSError)):
        _run_supervisor(session, invocation, stdout, stderr)

    assert not spawned
    assert _tree_snapshot(outside) == before
    assert not _claim_markers(session)


def test_cross_handle_finalize_vs_execution_race_has_exactly_one_winner(
    tmp_path, monkeypatch,
):
    executor = _session(tmp_path)
    finalizer = _session(tmp_path)
    stdout, stderr = _policies(executor, publish=False)
    invocation = _invocation(executor, stdout, stderr)
    monkeypatch.setattr(
        runner_repository, "supervise_execution", _successful_supervisor(),
    )
    entered = threading.Event()
    release = threading.Event()
    original_finalize = finalizer._finalize

    def paused_finalize(profile):
        entered.set()
        assert release.wait(5), "fixture did not release finalization"
        return original_finalize(profile)

    monkeypatch.setattr(finalizer, "_finalize", paused_finalize)
    results = {}

    def finish():
        try:
            results["finalize"] = finalizer.finalize(_profile())
        except BaseException as exc:  # preserve the exact competing disposition
            results["finalize_error"] = exc

    def execute():
        try:
            results["execute"] = _run_supervisor(
                executor, invocation, stdout, stderr,
            )
        except BaseException as exc:
            results["execute_error"] = exc

    finish_thread = threading.Thread(target=finish, daemon=True)
    execute_thread = threading.Thread(target=execute, daemon=True)
    finish_thread.start()
    assert entered.wait(5)
    execute_thread.start()
    time.sleep(0.05)
    release.set()
    finish_thread.join(5)
    execute_thread.join(5)
    assert not finish_thread.is_alive() and not execute_thread.is_alive()

    winners = int("finalize" in results) + int("execute" in results)
    assert winners == 1, results
    if "finalize" in results:
        assert (finalizer.dir / "manifest.json").is_file()
    else:
        assert not (finalizer.dir / "manifest.json").exists()
        assert not _claim_markers(executor)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_cross_process_finalize_vs_execution_race_has_exactly_one_winner(
    tmp_path, monkeypatch,
):
    executor = _session(tmp_path)
    stdout, stderr = _policies(executor, publish=False)
    invocation = _invocation(executor, stdout, stderr, request_byte="b8")
    monkeypatch.setattr(
        runner_repository, "supervise_execution", _successful_supervisor(),
    )
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    result_read, result_write = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - assertions remain in the parent
        os.close(ready_read)
        os.close(release_write)
        os.close(result_read)
        try:
            finalizer = _session(tmp_path)
            original_finalize = finalizer._finalize

            def paused_finalize(profile):
                os.write(ready_write, b"ready\n")
                if os.read(release_read, 1) != b"x":
                    raise RuntimeError("parent did not release finalization")
                return original_finalize(profile)

            finalizer._finalize = paused_finalize
            finalizer.finalize(_profile())
            os.write(result_write, b"success\n")
        except BaseException as exc:
            detail = f"error:{type(exc).__name__}:{exc}\n".encode("utf-8")[:2048]
            try:
                os.write(result_write, detail)
            except OSError:
                pass
            os._exit(70)
        os._exit(0)

    os.close(ready_write)
    os.close(release_read)
    os.close(result_write)
    execution = {}

    def execute():
        try:
            execution["result"] = _run_supervisor(
                executor, invocation, stdout, stderr,
            )
        except BaseException as exc:
            execution["error"] = exc

    child_status = None
    try:
        ready, _, _ = select.select([ready_read], [], [], 5)
        assert ready and os.read(ready_read, len(b"ready\n")) == b"ready\n"
        thread = threading.Thread(target=execute, daemon=True)
        thread.start()
        time.sleep(0.05)
        os.write(release_write, b"x")
        child_status = _reap_bounded(child_pid)
        thread.join(5)
        assert not thread.is_alive()
    finally:
        for fd in (ready_read, release_write):
            try:
                os.close(fd)
            except OSError:
                pass
        if child_status is None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child_pid, 0)
            except ChildProcessError:
                pass

    child_detail = os.read(result_read, 2048).decode("utf-8", errors="replace")
    os.close(result_read)
    child_won = os.waitstatus_to_exitcode(child_status) == 0 and child_detail == "success\n"
    execution_won = "result" in execution
    assert int(child_won) + int(execution_won) == 1, (child_detail, execution)


def test_clock_fault_after_settlement_fences_stages_and_preserves_prior(
    tmp_path, monkeypatch,
):
    session = _session(tmp_path)
    stdout, stderr = _policies(session)
    invocation = _invocation(session, stdout, stderr, request_byte="c9")
    final = session.dir.joinpath(*stdout.components)
    final.parent.mkdir(parents=True, exist_ok=True)
    final.write_bytes(b"prior authoritative evidence")
    final.chmod(0o600)
    captured = {}
    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        _successful_supervisor(observe=lambda _inv, batch: captured.setdefault("batch", batch)),
    )
    calls = 0

    def faulting_clock():
        nonlocal calls
        calls += 1
        if calls == 1:
            return 1.0
        raise FixtureClockFault("clock failed after settlement")

    with pytest.raises(FixtureClockFault, match="after settlement"):
        runner_repository.supervise_osint_execution(
            session,
            invocation,
            stdout=stdout,
            stderr=stderr,
            deadline=10.0,
            clock=faulting_clock,
        )

    assert captured["batch"].state == "fenced"
    assert final.read_bytes() == b"prior authoritative evidence"
    assert len(_claim_markers(session)) <= 1


def test_publication_fault_fences_stages_and_never_claims_success(
    tmp_path, monkeypatch,
):
    session = _session(tmp_path)
    stdout, stderr = _policies(session)
    invocation = _invocation(session, stdout, stderr, request_byte="da")
    final = session.dir.joinpath(*stdout.components)
    captured = {}
    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        _successful_supervisor(observe=lambda _inv, batch: captured.setdefault("batch", batch)),
    )

    def fail_publication(_batch, _proofs):
        raise FixturePublicationFault("publication syscall failed")

    monkeypatch.setattr(privfs, "publish_private_stage_handoff", fail_publication)
    returned = None
    try:
        returned = _run_supervisor(session, invocation, stdout, stderr)
    except FixturePublicationFault:
        pass

    assert returned is None or not returned.clean
    assert captured["batch"].state == "fenced"
    assert not final.exists()
    assert len(_claim_markers(session)) <= 1


def test_finalization_fault_rolls_back_or_durably_refuses_later_execution(
    tmp_path, monkeypatch,
):
    session = _session(tmp_path)

    def fail_report(*_args, **_kwargs):
        raise FixtureFinalizationFault("report failed after manifest write")

    monkeypatch.setattr(osint.osint_report, "render", fail_report)
    with pytest.raises(FixtureFinalizationFault, match="after manifest"):
        session.finalize(_profile())

    manifest = session.dir / "manifest.json"
    if manifest.exists():
        with pytest.raises((RuntimeError, OSError)):
            session.output(session.raw_path("fixture", "too-late.bin"))
    else:
        policy = session.output(session.raw_path("fixture", "retry.bin"))
        assert policy.components == ("raw", "fixture", "retry.bin")


@pytest.mark.parametrize("cancellation", [KeyboardInterrupt(), SystemExit(23)])
def test_cancellation_after_supervisor_reap_fences_and_preserves_exact_signal(
    tmp_path, monkeypatch, cancellation,
):
    session = _session(tmp_path, session_id=f"{SESSION_ID}-{type(cancellation).__name__}")
    stdout, stderr = _policies(session)
    invocation = _invocation(session, stdout, stderr, request_byte="eb")
    captured = {"reaped": False}

    def cancel_after_reap(invocation, *, stage_batch, deadline, clock, popen_factory):
        _settle_batch(invocation, stage_batch)
        captured["batch"] = stage_batch
        captured["reaped"] = True
        raise cancellation

    monkeypatch.setattr(runner_repository, "supervise_execution", cancel_after_reap)

    with pytest.raises(type(cancellation)) as caught:
        _run_supervisor(session, invocation, stdout, stderr)

    assert caught.value is cancellation
    assert captured["reaped"] is True
    assert captured["batch"].state == "fenced"
    assert not session.dir.joinpath(*stdout.components).exists()
    assert len(_claim_markers(session)) <= 1


def test_success_publishes_exact_stdout_then_every_handle_observes_finalization(
    tmp_path, monkeypatch,
):
    executor = _session(tmp_path)
    finalizer = _session(tmp_path)
    stdout, stderr = _policies(executor)
    invocation = _invocation(executor, stdout, stderr, request_byte="fc")
    final = executor.dir.joinpath(*stdout.components)
    final.write_bytes(b"prior bytes")
    final.chmod(0o600)
    monkeypatch.setattr(
        runner_repository, "supervise_execution", _successful_supervisor(),
    )

    outcome = _run_supervisor(executor, invocation, stdout, stderr)

    assert outcome.clean
    assert final.read_bytes() == STDOUT
    assert not _claim_markers(executor)
    report = finalizer.finalize(_profile())
    assert report.is_file()
    assert (finalizer.dir / "manifest.json").is_file()
    for handle in (executor, finalizer, _session(tmp_path)):
        with pytest.raises((RuntimeError, OSError)):
            handle.output(handle.dir / "raw" / "fixture" / "late.bin")


def test_output_authority_never_accepts_or_serializes_an_ambient_path(tmp_path):
    session = _session(tmp_path)
    outside = tmp_path / "outside.bin"
    before = _tree_snapshot(tmp_path)

    with pytest.raises(ValueError, match="different session"):
        session.output(outside)
    with pytest.raises(ValueError, match="raw evidence"):
        session.output(session.dir / "manifest.json")
    assert _tree_snapshot(tmp_path) == before

    stdout, stderr = _policies(session)
    invocation = _invocation(session, stdout, stderr, request_byte="1d")
    wire = protocol.encode_request(invocation.worker)
    assert os.fsencode(session.dir) not in wire
    assert os.fsencode(outside) not in wire
    assert str(session.dir) not in repr(stdout)
    assert not isinstance(stdout, (str, Path, os.PathLike))
