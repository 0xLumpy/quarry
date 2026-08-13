"""Phase 1: durable lifecycle markers remain terminal under cancellation."""
from __future__ import annotations

import inspect
import os
import sys
from types import SimpleNamespace

import pytest

from quarry_recon import runner_repository, runner_supervisor, store
from quarry_recon.runner_protocol import StreamRole


pytestmark = pytest.mark.offline


def _running_run(project, run_id: str):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _open_fds() -> set[tuple[int, str]]:
    observed = set()
    for entry in (os.scandir("/proc/self/fd") if os.path.isdir("/proc/self/fd") else ()):
        try:
            target = os.readlink(entry.path)
            if target.startswith("/proc/") and target.endswith("/fd"):
                continue
            observed.add((int(entry.name), target))
        except OSError:
            pass
    return observed


def _cancel_once(function, target_line: int, call, cancellation_type):
    cancellation = cancellation_type(f"cancel source line {target_line}")
    fired = False

    def trace(frame, event, _arg):
        nonlocal fired
        if (frame.f_code is function.__code__ and event == "line"
                and frame.f_lineno == target_line and not fired):
            fired = True
            sys.settrace(None)
            raise cancellation
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(cancellation_type) as caught:
            call()
    finally:
        sys.settrace(previous)
    assert fired
    assert caught.value is cancellation


def _executed_lines(function, call) -> set[int]:
    lines = set()

    def trace(frame, event, _arg):
        if frame.f_code is function.__code__ and event == "line":
            lines.add(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        call()
    finally:
        sys.settrace(previous)
    return lines


def _create_marker(run):
    with run._mutation(store.MutationScope.BASE_EVIDENCE):
        return run._create_artifact_claim_marker()


def _release_marker(run, marker):
    with run._mutation(store.MutationScope.CONTROL):
        run._release_artifact_claim_marker(*marker)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_legacy_marker_create_source_lines_leave_no_owner(
    tmp_path, cancellation_type,
):
    operation = store.Run._create_artifact_claim_marker
    discovery = _running_run(tmp_path / "discovery", "marker-create-discovery")
    created = []
    lines = _executed_lines(operation, lambda: created.append(_create_marker(discovery)))
    _release_marker(discovery, created[0])

    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"case-{index}"
        run = _running_run(project, f"marker-create-{index}")
        before = _open_fds()
        _cancel_once(
            operation, target_line, lambda: _create_marker(run), cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        assert run._live_artifact_claim_count() == 0, f"source line {target_line}"
        store.Run.open(project, run.target, run.run_id).begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_legacy_marker_release_source_lines_are_terminal(
    tmp_path, cancellation_type,
):
    operation = store.Run._release_artifact_claim_marker
    discovery = _running_run(tmp_path / "discovery", "marker-release-discovery")
    marker = _create_marker(discovery)
    lines = _executed_lines(operation, lambda: _release_marker(discovery, marker))
    source, start = inspect.getsourcelines(operation)
    owned_line = next(
        start + index for index, text in enumerate(source)
        if text.lstrip().startswith("with _SettlementFence")
        and text.startswith(" " * 12)
    )

    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"case-{index}"
        run = _running_run(project, f"marker-release-{index}")
        marker = _create_marker(run)
        before = _open_fds()
        _cancel_once(
            operation,
            target_line,
            lambda: _release_marker(run, marker),
            cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        live = run._live_artifact_claim_count()
        if target_line < owned_line:
            # Cancellation before the inner fence is entered precedes the
            # release effect.  The durable marker remains the safe truth and a
            # retry consumes it without descriptor residue.
            assert live == 1, f"source line {target_line}"
            _release_marker(run, marker)
        else:
            assert live == 0, f"source line {target_line}"
        store.Run.open(project, run.target, run.run_id).begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation",
    [
        store.Run._live_artifact_claim_count,
        store._ArtifactClaimRegistryRead.read,
        store._ArtifactClaimRegistryRead.settle,
    ],
)
def test_live_marker_count_source_lines_close_every_descriptor(
    tmp_path, cancellation_type, operation,
):
    discovery = _running_run(tmp_path / "discovery", "marker-read-discovery")
    discovery_markers = (_create_marker(discovery), _create_marker(discovery))
    lines = _executed_lines(operation, discovery._live_artifact_claim_count)
    assert lines
    for marker in discovery_markers:
        _release_marker(discovery, marker)

    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"case-{index}"
        run = _running_run(project, f"marker-read-{index}")
        markers = (_create_marker(run), _create_marker(run))
        before = _open_fds()
        _cancel_once(
            operation,
            target_line,
            run._live_artifact_claim_count,
            cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        assert run._live_artifact_claim_count() == 2, f"source line {target_line}"
        for marker in markers:
            _release_marker(run, marker)
        store.Run.open(project, run.target, run.run_id).begin_finalization()


def _settled_execution(invocation, **_kwargs):
    return runner_supervisor.ExecutionOutcome(
        reason=runner_supervisor.ExecutionReason.INCOMPLETE,
        request_id=invocation.worker.request_id,
        stages_settled=True,
        _authority=runner_supervisor._EXECUTION_OUTCOME_AUTHORITY,
    )


def _run_owned_execution(run):
    request_id = "ab" * 16
    invocation = SimpleNamespace(worker=SimpleNamespace(request_id=request_id))
    discard = runner_repository.RepositoryOutput.discard()
    return runner_repository._supervise_owned_execution(
        invocation,
        policies=((StreamRole.STDOUT, discard), (StreamRole.STDERR, discard)),
        deadline=1.0,
        clock=lambda: 0.0,
        popen_factory=lambda: None,
        acquire_claim=lambda: runner_repository._DurableRunClaim.acquire(run),
        prepare_batch=lambda: None,
        publish_batch=lambda _batch, _proofs: pytest.fail("unexpected publication"),
    )


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation",
    [
        runner_repository._supervise_owned_execution,
        runner_repository._supervise_owned_execution_claimed,
        runner_repository._ExecutionClaimOwner.acquire,
        runner_repository._ExecutionClaimOwner.prepare,
        runner_repository._ExecutionClaimOwner.supervise,
        runner_repository._ExecutionClaimOwner.settle,
        runner_repository._DurableRunClaim.acquire,
        runner_repository._DurableRunClaim._settle,
        runner_repository._DurableRunClaim.release,
        store._ArtifactMarkerRelease.allocate,
        store._ArtifactMarkerRelease.settle,
    ],
)
def test_repository_execution_claim_source_lines_are_terminal(
    tmp_path, monkeypatch, cancellation_type, operation,
):
    monkeypatch.setattr(runner_repository, "supervise_execution", _settled_execution)
    discovery = _running_run(tmp_path / "discovery", "runner-claim-discovery")
    lines = _executed_lines(operation, lambda: _run_owned_execution(discovery))
    assert lines

    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"case-{index}"
        run = _running_run(project, f"runner-claim-{index}")
        before = _open_fds()
        _cancel_once(
            operation,
            target_line,
            lambda: _run_owned_execution(run),
            cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        assert run._live_artifact_claim_count() == 0, f"source line {target_line}"
        store.Run.open(project, run.target, run.run_id).begin_finalization()


def test_artifact_claim_repr_reports_the_instance_state(tmp_path):
    run = _running_run(tmp_path, "claim-repr")

    with run.artifact_claim() as claim:
        assert repr(claim) == "ArtifactClaim(state='claimed')"
        claim.fence()
        assert repr(claim) == "ArtifactClaim(state='fenced')"
