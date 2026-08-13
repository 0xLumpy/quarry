"""Phase 1 repository/execution publication composition contract.

The execution supervisor deliberately stops at authenticated private stages.
This suite defines the repository-owned seam which holds the base-evidence
claim, makes stdout/stderr ownership explicit, and decides publication only
from the exact parent-authenticated outcome.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import privfs
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_repository
from quarry_recon import runner_supervisor as supervisor
from quarry_recon import store
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline

REQUEST_ID = "a7" * 16
WORKER_PID = 51231
TOOL_PID = 51232
STDOUT = b"\xffrepository stdout\nsecond\n"
STDERR = b"diagnostic stderr\n"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _running_run(tmp_path, run_id="repository-execution"):
    run = store.Run.create(tmp_path, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _invocation(run, *, stdout, stderr):
    return protocol.normalize_invocation(
        request_id=REQUEST_ID,
        tool="fixture",
        cmd=["fixture", "--bounded"],
        timeout=30,
        raw_path=(str(run.dir.joinpath(*stdout.components))
                  if stdout.disposition is runner_repository.ArtifactDisposition.PUBLISH
                  else None),
        stderr_path=(str(run.dir.joinpath(*stderr.components))
                     if stderr.disposition is runner_repository.ArtifactDisposition.PUBLISH
                     else None),
        base_environment={"PATH": "/private/tool/path"},
    )


def _write_exact(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        assert written > 0
        view = view[written:]


def _settle_batch(invocation, batch, payload_by_role):
    request = invocation.worker
    claimed_roles = tuple(
        claim.role for claim in request.descriptor_claims
        if claim.role in (protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR)
    )
    assert batch.state == "prepared"
    authority = privfs._prepare_private_stage_transfer_authority(
        batch, request_id=request.request_id,
    )

    def spawn(writer_fds):
        assert len(writer_fds) == len(claimed_roles)
        for role, fd in zip(claimed_roles, writer_fds):
            _write_exact(fd, payload_by_role[role])
            os.fsync(fd)
        return SimpleNamespace(pid=WORKER_PID)

    _child, authority = privfs._spawn_with_private_stage_handoff(
        batch, authority, spawn,
    )
    privfs._bind_private_stage_transfer_authority(
        batch, authority, worker_pid=WORKER_PID,
    )
    receipt = privfs.transfer_private_stage_handoff(batch, authority)
    proofs = privfs.settle_private_stage_handoff(
        batch,
        receipt,
        worker_reaped=True,
        claims=tuple(
            (request.claim_for(role).claim_id, role.value)
            for role in claimed_roles
        ),
    )
    return proofs


def _output_stream(request, role, data, proof_by_role):
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


def _complete_outcome(invocation, proofs, payload_by_role):
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
            _output_stream(
                request,
                protocol.StreamRole.STDOUT,
                payload_by_role.get(protocol.StreamRole.STDOUT, empty),
                proof_by_role,
            ),
            _output_stream(
                request,
                protocol.StreamRole.STDERR,
                payload_by_role.get(protocol.StreamRole.STDERR, empty),
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
        artifact_proofs=proofs,
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


def _incomplete_outcome(invocation, proofs):
    return supervisor.ExecutionOutcome(
        reason=supervisor.ExecutionReason.INCOMPLETE,
        request_id=invocation.worker.request_id,
        artifact_proofs=proofs,
        stages_settled=True,
        _authority=supervisor._EXECUTION_OUTCOME_AUTHORITY,
    )


def _fake_supervisor(payload_by_role, *, complete=True, observe=None):
    def execute(invocation, *, stage_batch, deadline, clock, popen_factory):
        assert deadline > clock()
        if observe is not None:
            observe(invocation, stage_batch)
        proofs = (
            _settle_batch(invocation, stage_batch, payload_by_role)
            if stage_batch is not None else ()
        )
        if complete:
            return _complete_outcome(invocation, proofs, payload_by_role)
        return _incomplete_outcome(invocation, proofs)

    return execute


def _policy_pair(*, stdout=None, stderr=None):
    return (
        stdout or runner_repository.RepositoryOutput.discard(),
        stderr or runner_repository.RepositoryOutput.discard(),
    )


def test_clean_execution_holds_claim_then_publishes_exact_requested_stdout(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path)
    stdout, stderr = _policy_pair(stdout=runner_repository.RepositoryOutput.publish(
        "raw", "probe", "fixture", "stdout.bin",
    ))
    final = run.dir.joinpath(*stdout.components)
    privfs.private_dir(final.parent)
    final.write_bytes(b"prior authoritative bytes")
    final.chmod(0o600)

    def observe(_invocation, stage_batch):
        assert final.read_bytes() == b"prior authoritative bytes"
        assert stage_batch.state == "prepared"
        observer = store.Run.open(tmp_path, run.target, run.run_id)
        with pytest.raises(ContractError, match="live artifact claim"):
            observer.begin_finalization()
        assert observer.state == "running"

    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        _fake_supervisor(
            {protocol.StreamRole.STDOUT: STDOUT}, observe=observe,
        ),
    )
    invocation = _invocation(run, stdout=stdout, stderr=stderr)

    result = runner_repository.supervise_repository_execution(
        run,
        invocation,
        stdout=stdout,
        stderr=stderr,
        deadline=runner_repository.time.monotonic() + 5,
    )

    assert result.clean is True
    assert result.publication is runner_repository.RepositoryPublication.PUBLISHED
    assert result.ownership_settled is True
    assert result.requested_roles == (protocol.StreamRole.STDOUT,)
    assert result.discarded_roles == (protocol.StreamRole.STDERR,)
    assert result.published is result.execution.artifact_proofs
    assert result.uncertain == result.unpublished == ()
    assert final.read_bytes() == STDOUT
    assert result.published[0].sha256 == _digest(STDOUT)
    assert not list((tmp_path / "recon" / "state" / "claims" / run.run_id).iterdir())
    with pytest.raises((FrozenInstanceError, AttributeError)):
        result.publication = runner_repository.RepositoryPublication.FENCED
    assert str(tmp_path) not in repr(result)


def test_discard_is_explicit_and_creates_no_output_stage_or_artifact(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, run_id="discarded-output")
    stdout, stderr = _policy_pair()
    seen = []

    def execute(invocation, *, stage_batch, deadline, clock, popen_factory):
        seen.append(stage_batch)
        return _complete_outcome(
            invocation,
            (),
            {
                protocol.StreamRole.STDOUT: b"observed but discarded",
                protocol.StreamRole.STDERR: b"diagnostic discarded",
            },
        )

    monkeypatch.setattr(runner_repository, "supervise_execution", execute)
    invocation = _invocation(run, stdout=stdout, stderr=stderr)
    result = runner_repository.supervise_repository_execution(
        run,
        invocation,
        stdout=stdout,
        stderr=stderr,
        deadline=runner_repository.time.monotonic() + 5,
    )

    assert seen == [None]
    assert result.clean is True
    assert result.publication is runner_repository.RepositoryPublication.NOT_REQUESTED
    assert result.ownership_settled is True
    assert result.requested_roles == ()
    assert result.discarded_roles == (
        protocol.StreamRole.STDOUT, protocol.StreamRole.STDERR,
    )
    assert result.published == result.uncertain == result.unpublished == ()
    assert not [path for path in run.raw.rglob("*") if path.is_file()]


def test_nonclean_execution_fences_settled_bytes_and_preserves_prior_final(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, run_id="nonclean-execution")
    stdout, stderr = _policy_pair(stdout=runner_repository.RepositoryOutput.publish(
        "raw", "probe", "fixture", "stdout.bin",
    ))
    final = run.dir.joinpath(*stdout.components)
    privfs.private_dir(final.parent)
    final.write_bytes(b"old")
    final.chmod(0o600)
    batches = []

    def observe(_invocation, batch):
        batches.append(batch)

    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        _fake_supervisor(
            {protocol.StreamRole.STDOUT: b"stable but incomplete"},
            complete=False,
            observe=observe,
        ),
    )
    result = runner_repository.supervise_repository_execution(
        run,
        _invocation(run, stdout=stdout, stderr=stderr),
        stdout=stdout,
        stderr=stderr,
        deadline=runner_repository.time.monotonic() + 5,
    )

    assert result.clean is False
    assert result.publication is runner_repository.RepositoryPublication.FENCED
    assert result.ownership_settled is True
    assert result.published == result.uncertain == ()
    assert result.unpublished == result.execution.artifact_proofs
    assert batches[0].state == "fenced"
    assert final.read_bytes() == b"old"


def test_later_publication_failure_returns_exact_committed_partition(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, run_id="partial-publication")
    stdout, stderr = _policy_pair(
        stdout=runner_repository.RepositoryOutput.publish(
            "raw", "probe", "fixture", "stdout.bin",
        ),
        stderr=runner_repository.RepositoryOutput.publish(
            "raw", "probe", "fixture", "stderr.bin",
        ),
    )
    stdout_final = run.dir.joinpath(*stdout.components)
    stderr_final = run.dir.joinpath(*stderr.components)
    privfs.private_dir(stdout_final.parent)
    stdout_final.write_bytes(b"old stdout")
    stderr_final.write_bytes(b"old stderr")
    stdout_final.chmod(0o600)
    stderr_final.chmod(0o600)
    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        _fake_supervisor({
            protocol.StreamRole.STDOUT: STDOUT,
            protocol.StreamRole.STDERR: STDERR,
        }),
    )
    real_rename = privfs.os.rename

    def fail_stderr(source, destination, *args, **kwargs):
        if destination == "stderr.bin":
            raise OSError("second publication failed")
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(privfs.os, "rename", fail_stderr)
    result = runner_repository.supervise_repository_execution(
        run,
        _invocation(run, stdout=stdout, stderr=stderr),
        stdout=stdout,
        stderr=stderr,
        deadline=runner_repository.time.monotonic() + 5,
    )

    assert result.clean is False
    assert result.publication is runner_repository.RepositoryPublication.PARTIAL
    assert result.ownership_settled is True
    assert result.published == result.execution.artifact_proofs[:1]
    assert result.uncertain == ()
    assert result.unpublished == result.execution.artifact_proofs[1:]
    assert stdout_final.read_bytes() == STDOUT
    assert stderr_final.read_bytes() == b"old stderr"


def test_unreaped_execution_keeps_durable_claim_and_publishes_nothing(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, run_id="unreaped-owner")
    stdout, stderr = _policy_pair(stdout=runner_repository.RepositoryOutput.publish(
        "raw", "probe", "fixture", "stdout.bin",
    ))
    final = run.dir.joinpath(*stdout.components)
    privfs.private_dir(final.parent)
    final.write_bytes(b"old")
    final.chmod(0o600)

    def unreaped(invocation, *, stage_batch, deadline, clock, popen_factory):
        assert stage_batch.state == "prepared"
        return supervisor.ExecutionOutcome(
            reason=supervisor.ExecutionReason.REAP_FAILED,
            request_id=invocation.worker.request_id,
            worker_pid=WORKER_PID,
            worker_spawned=True,
            worker_reaped=False,
            parent_pipes_closed=True,
            containment_settled=False,
            stages_settled=False,
            _authority=supervisor._EXECUTION_OUTCOME_AUTHORITY,
        )

    monkeypatch.setattr(runner_repository, "supervise_execution", unreaped)
    result = runner_repository.supervise_repository_execution(
        run,
        _invocation(run, stdout=stdout, stderr=stderr),
        stdout=stdout,
        stderr=stderr,
        deadline=runner_repository.time.monotonic() + 5,
    )

    assert result.clean is False
    assert result.publication is runner_repository.RepositoryPublication.FENCED
    assert result.ownership_settled is False
    assert result.published == result.uncertain == result.unpublished == ()
    assert final.read_bytes() == b"old"
    claim_dir = tmp_path / "recon" / "state" / "claims" / run.run_id
    assert len(list(claim_dir.iterdir())) == 1
    with pytest.raises(ContractError, match="live artifact claim"):
        run.begin_finalization()


def test_expired_shared_deadline_fences_settled_stage_before_publication(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, run_id="publication-deadline")
    stdout, stderr = _policy_pair(stdout=runner_repository.RepositoryOutput.publish(
        "raw", "probe", "fixture", "stdout.bin",
    ))
    final = run.dir.joinpath(*stdout.components)
    privfs.private_dir(final.parent)
    final.write_bytes(b"old")
    final.chmod(0o600)
    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        _fake_supervisor({protocol.StreamRole.STDOUT: STDOUT}),
    )
    readings = iter((1.0, 1.0, 5.0))

    result = runner_repository.supervise_repository_execution(
        run,
        _invocation(run, stdout=stdout, stderr=stderr),
        stdout=stdout,
        stderr=stderr,
        deadline=5.0,
        clock=lambda: next(readings),
    )

    assert result.clean is False
    assert result.publication is runner_repository.RepositoryPublication.FENCED
    assert result.ownership_settled is True
    assert result.unpublished == result.execution.artifact_proofs
    assert result.fault_operation == "publish"
    assert final.read_bytes() == b"old"
    assert not list((tmp_path / "recon" / "state" / "claims" / run.run_id).iterdir())


def test_policy_mismatch_is_rejected_before_claim_stage_or_supervisor(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, run_id="policy-mismatch")
    stdout, stderr = _policy_pair(stdout=runner_repository.RepositoryOutput.publish(
        "raw", "probe", "fixture", "expected.bin",
    ))
    invocation = protocol.normalize_invocation(
        request_id=REQUEST_ID,
        tool="fixture",
        cmd=["fixture"],
        raw_path=str(run.dir / "raw" / "probe" / "fixture" / "other.bin"),
        base_environment={},
    )
    before = tuple(sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")))
    monkeypatch.setattr(
        runner_repository,
        "supervise_execution",
        lambda *args, **kwargs: pytest.fail("mismatched policy reached supervisor"),
    )

    with pytest.raises(ContractError, match="stdout policy"):
        runner_repository.supervise_repository_execution(
            run,
            invocation,
            stdout=stdout,
            stderr=stderr,
            deadline=runner_repository.time.monotonic() + 5,
        )

    after = tuple(sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")))
    assert after == before
    assert not (tmp_path / "recon" / "state" / "claims" / run.run_id).exists()


@pytest.mark.parametrize("components", [
    ("raw", "probe", "fixture", "../escape"),
    ("raw", "probe", "fixture", "a/b"),
    ("exports", "probe", "fixture", "not-base.txt"),
])
def test_publish_policy_validates_base_identity_without_filesystem_effects(
    tmp_path, components,
):
    before = tuple(tmp_path.iterdir())
    with pytest.raises(ContractError):
        runner_repository.RepositoryOutput.publish(*components)
    assert tuple(tmp_path.iterdir()) == before
