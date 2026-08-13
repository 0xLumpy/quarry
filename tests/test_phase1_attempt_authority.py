"""Phase 1: managed attempt allocation and writability probes use Run authority."""
from __future__ import annotations

import multiprocessing
import os
import sys

import pytest

from quarry_recon import budget, runner, store
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


def _running_run(project, run_id="attempt-authority"):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _allocate_in_child(project, ready, release, output):
    run = store.Run.open(project, "acme.example", "attempt-process")
    ready.set()
    release.wait(5)
    output.put(run.fresh_artifact_dir("raw", "probe", "fixture").name)


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


def _cancel_once(function, target_line: int, call, cancellation_type=KeyboardInterrupt):
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


def test_managed_attempts_are_unique_and_private(tmp_path):
    run = _running_run(tmp_path)

    first = runner.fresh_artifact_dir(run.dir / "raw" / "probe" / "fixture")
    second = run.fresh_artifact_dir("raw", "probe", "fixture")

    assert (first.name, second.name) == ("attempt-0", "attempt-1")
    assert first.stat().st_mode & 0o777 == 0o700
    assert second.stat().st_mode & 0o777 == 0o700


def test_managed_attempt_allocation_refuses_after_seal_without_side_effect(tmp_path):
    run = _running_run(tmp_path)
    run.begin_finalization()
    base = run.dir / "raw" / "probe" / "fixture"

    with pytest.raises(ContractError):
        runner.fresh_artifact_dir(base)

    assert not base.exists()


def test_managed_attempt_allocation_refuses_a_planted_link(tmp_path):
    run = _running_run(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    base = run.raw_path("probe", "fixture", "placeholder").parent
    (base / "attempt-0").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ContractError):
        run.fresh_artifact_dir("raw", "probe", "fixture")

    assert not list(outside.iterdir())


def test_managed_attempts_serialize_across_processes(tmp_path):
    run = _running_run(tmp_path, run_id="attempt-process")
    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()
    release = ctx.Event()
    output = ctx.Queue()
    process = ctx.Process(
        target=_allocate_in_child,
        args=(tmp_path, ready, release, output),
    )
    process.start()
    assert ready.wait(5)
    parent = run.fresh_artifact_dir("raw", "probe", "fixture")
    release.set()
    child_name = output.get(timeout=5)
    process.join(5)

    assert process.exitcode == 0
    assert {parent.name, child_name} == {"attempt-0", "attempt-1"}


def test_managed_writability_probe_never_publishes_a_probe(tmp_path):
    run = _running_run(tmp_path)
    attempt = run.fresh_artifact_dir("raw", "probe", "fixture")

    assert budget.store_writable(attempt) is True
    assert list(attempt.iterdir()) == []
    assert run._live_artifact_claim_count() == 0


def test_managed_writability_probe_refuses_after_seal(tmp_path):
    run = _running_run(tmp_path)
    attempt = run.fresh_artifact_dir("raw", "probe", "fixture")
    run.begin_finalization()

    assert budget.store_writable(attempt) is False
    assert list(attempt.iterdir()) == []
    assert run._live_artifact_claim_count() == 0


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("method_name", ["fresh_artifact_dir", "create_artifact_dir"])
def test_directory_allocation_source_line_cancellation_settles_descriptors(
    tmp_path, method_name, cancellation_type,
):
    method = getattr(store.Run, method_name)

    def invoke(run):
        if method_name == "fresh_artifact_dir":
            return method(run, "raw", "probe", "trace")
        return method(run, "raw", "probe", "trace", "exact")

    discovery = _running_run(tmp_path / "discovery", f"{method_name}-discovery")
    lines = _executed_lines(method, lambda: invoke(discovery))
    for index, target_line in enumerate(sorted(lines)):
        run = _running_run(
            tmp_path / f"case-{index}", f"{method_name}-{index}",
        )
        before = _open_fds()
        _cancel_once(
            method, target_line, lambda: invoke(run), cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        assert run._live_artifact_claim_count() == 0, f"source line {target_line}"
        # A cancellation before mkdir leaves no attempt.  One delivered after
        # mkdir may retain exactly one durable, private, empty allocation.
        root = run.dir / "raw" / "probe" / "trace"
        attempts = list(root.iterdir()) if root.is_dir() else []
        assert len(attempts) <= 1
        if attempts:
            assert attempts[0].is_dir()
            assert not list(attempts[0].iterdir())
            assert attempts[0].stat().st_mode & 0o777 == 0o700
        store.Run.open(tmp_path / f"case-{index}", "acme.example", run.run_id).begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_artifact_claim_cleanup_source_line_cancellation_is_terminal(
    tmp_path, cancellation_type,
):
    generator = store.Run.artifact_claim.__wrapped__

    def invoke(run):
        with run.artifact_claim("raw", "probe", "claim", "value.txt") as claim:
            writer = claim.open_writer()
            os.write(writer, b"candidate")
            os.close(writer)

    discovery = _running_run(tmp_path / "claim-discovery", "claim-discovery")
    lines = _executed_lines(generator, lambda: invoke(discovery))
    # The body-yield line belongs to the caller's arbitrary work, not repository
    # cleanup.  The matrix exercises every source line after it.
    import inspect
    source, start = inspect.getsourcelines(generator)
    yield_line = next(
        start + index for index, text in enumerate(source)
        if "yield claim" in text
    )
    for index, target_line in enumerate(sorted(line for line in lines if line > yield_line)):
        project = tmp_path / f"claim-{index}"
        run = _running_run(project, f"claim-{index}")
        before = _open_fds()
        _cancel_once(
            generator, target_line, lambda: invoke(run), cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        assert run._live_artifact_claim_count() == 0, f"source line {target_line}"
        assert not list(run.raw.rglob("*.stage"))
        store.Run.open(project, "acme.example", run.run_id).begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    ("method_name", "operation_name"),
    [
        ("fresh_artifact_dir", "allocate_fresh"),
        ("create_artifact_dir", "create_exact"),
    ],
)
def test_directory_allocation_effect_lines_are_owned_by_active_fences(
    tmp_path, method_name, operation_name, cancellation_type,
):
    operation = getattr(store._ArtifactDirectoryAllocation, operation_name)

    def invoke(run):
        if method_name == "fresh_artifact_dir":
            return run.fresh_artifact_dir("raw", "probe", "owned")
        return run.create_artifact_dir("raw", "probe", "owned", "exact")

    discovery = _running_run(tmp_path / "effect-discovery", "effect-discovery")
    lines = _executed_lines(operation, lambda: invoke(discovery))
    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"effect-{index}"
        run = _running_run(project, f"effect-{index}")
        before = _open_fds()
        _cancel_once(
            operation, target_line, lambda: invoke(run), cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        store.Run.open(project, "acme.example", run.run_id).begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation",
    [
        store._ArtifactClaim.open_writer,
        store._ArtifactClaim.fence,
        store._ArtifactClaim._settle,
        store._ArtifactMarkerRelease.settle,
        store._OwnedDescriptor.allocate,
        store._OwnedDescriptor.close_once,
        store._close_owned_descriptors_twice,
        store._SettlementOwner.reconcile,
        store._SettlementFence.__exit__,
    ],
)
def test_claim_effect_and_cleanup_lines_are_owned_by_active_fences(
    tmp_path, operation, cancellation_type,
):
    def invoke(run):
        with run.artifact_claim("raw", "probe", "owned", "value.txt") as claim:
            writer = claim.open_writer()
            os.write(writer, b"unpublished")

    discovery = _running_run(tmp_path / "owner-discovery", "owner-discovery")
    lines = _executed_lines(operation, lambda: invoke(discovery))
    assert lines
    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"owner-{index}"
        run = _running_run(project, f"owner-{index}")
        before = _open_fds()
        _cancel_once(
            operation, target_line, lambda: invoke(run), cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        assert run._live_artifact_claim_count() == 0, f"source line {target_line}"
        assert not list(run.raw.rglob("*.stage"))
        assert not (run.raw / "probe" / "owned" / "value.txt").exists()
        store.Run.open(project, "acme.example", run.run_id).begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_claim_publication_source_line_cancellation_is_terminal_and_preserves_truth(
    tmp_path, cancellation_type,
):
    operation = store._ArtifactClaim.publish
    components = ("raw", "probe", "publish", "value.txt")

    def seed(run):
        with run.artifact_claim(*components) as claim:
            writer = claim.open_writer()
            os.write(writer, b"prior")
            os.close(writer)
            claim.publish()

    def invoke(run):
        with run.artifact_claim(*components) as claim:
            writer = claim.open_writer()
            os.write(writer, b"candidate")
            os.close(writer)
            claim.publish()

    discovery = _running_run(tmp_path / "publish-discovery", "publish-discovery")
    seed(discovery)
    lines = _executed_lines(operation, lambda: invoke(discovery))
    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"publish-{index}"
        run = _running_run(project, f"publish-{index}")
        seed(run)
        before = _open_fds()
        _cancel_once(
            operation, target_line, lambda: invoke(run), cancellation_type,
        )
        assert _open_fds() == before, f"source line {target_line}"
        assert run._live_artifact_claim_count() == 0
        assert not list(run.raw.rglob("*.stage"))
        assert run.dir.joinpath(*components).read_bytes() in {
            b"prior", b"candidate",
        }
        store.Run.open(project, "acme.example", run.run_id).begin_finalization()
