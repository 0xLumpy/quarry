"""Phase 1, step 6c: durable artifact claims and repository-owned base writers.

The repository lock from step 6a protects short mutations, but a tool or native
writer necessarily outlives one lock acquisition.  These tests define the
capability which bridges that interval: the repository owns the destination and
the caller receives only a disposable writer, never an ambient final ``Path``.
"""
from __future__ import annotations

import json
import os
import select
import signal
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import budget, events, metrics, runner, store
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


def _running_run(project, run_id="artifact-authority"):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _tree_snapshot(root):
    """Content/metadata snapshot which deliberately ignores read-only atime changes."""
    root = Path(root).resolve()
    if not root.exists():
        return None
    snapshot = []
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        payload = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        link = os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
        snapshot.append((str(path.relative_to(root)), stat.S_IFMT(info.st_mode),
                         stat.S_IMODE(info.st_mode), info.st_ino, info.st_size,
                         info.st_mtime_ns, payload, link))
    return snapshot


def _result_fixture(tool="fixture"):
    return SimpleNamespace(
        tool=tool,
        status=SimpleNamespace(value="success"),
        exit_code=0,
        duration=0.01,
        stdout_lines=1,
        note="",
        cmd=(tool,),
        stderr_tail="",
    )


def _reap_bounded(pid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    pytest.fail(f"forked claimant did not settle (wait status {status})")


def test_path_scoped_claim_is_an_opaque_publish_and_fence_capability(tmp_path):
    run = _running_run(tmp_path)
    final = run.dir / "raw" / "native" / "fixture" / "body.bin"

    with run.artifact_claim("raw", "native", "fixture", "body.bin") as claim:
        assert not isinstance(claim, (str, Path, os.PathLike))
        with pytest.raises(TypeError):
            os.fspath(claim)
        for ambient_name in ("path", "final_path", "destination"):
            assert not hasattr(claim, ambient_name), (
                f"artifact claims must not expose an ambient {ambient_name}"
            )
        for operation in ("open_writer", "publish", "fence"):
            assert callable(getattr(claim, operation, None)), (
                f"artifact claims require a repository-owned {operation}() operation"
            )
        assert str(tmp_path) not in repr(claim)

        writer = claim.open_writer()
        assert type(writer) is int and writer >= 0
        os.write(writer, b"\x00native\xffevidence\n")
        os.close(writer)
        claim.publish()

    assert final.read_bytes() == b"\x00native\xffevidence\n"
    assert stat.S_IMODE(final.stat().st_mode) == 0o600


def test_unpublished_claim_is_fenced_on_context_exit(tmp_path):
    run = _running_run(tmp_path, run_id="fenced-claim")
    final = run.dir / "raw" / "native" / "fixture" / "partial.bin"

    with pytest.raises(RuntimeError, match="fixture interruption"):
        with run.artifact_claim("raw", "native", "fixture", "partial.bin") as claim:
            writer = claim.open_writer()
            os.write(writer, b"unpublished prefix")
            os.close(writer)
            raise RuntimeError("fixture interruption")

    assert not final.exists()
    assert not [path for path in run.raw.rglob("*") if path.is_file()], (
        "fencing a native claim must not leave an unnamed or authoritative file in the base tree"
    )


@pytest.mark.parametrize("components", [
    ("raw", "native", "fixture", "../escape"),
    ("raw", "native", "fixture", "/absolute"),
    ("raw", "native", "fixture", "a/b"),
    ("raw", "native", "fixture", "bad\\name"),
    ("raw", "native", "fixture", "\x00"),
])
def test_claim_identity_is_validated_before_repository_side_effects(tmp_path, components):
    run = _running_run(tmp_path, run_id="invalid-claim")
    before = _tree_snapshot(tmp_path)

    with pytest.raises(ContractError):
        with run.artifact_claim(*components):
            pytest.fail("an invalid artifact identity entered its claim body")

    assert _tree_snapshot(tmp_path) == before


def test_path_scoped_claim_refuses_after_seal_without_a_stage_side_effect(tmp_path):
    run = _running_run(tmp_path, run_id="sealed-claim")
    run.begin_finalization()
    before = _tree_snapshot(tmp_path)

    with pytest.raises(ContractError, match="sealed"):
        with run.artifact_claim("raw", "native", "fixture", "too-late.bin"):
            pytest.fail("a sealed run granted base-artifact authority")

    assert run.state == "finalizing"
    assert _tree_snapshot(tmp_path) == before


def test_claim_held_by_another_process_is_visible_to_begin_finalization(tmp_path):
    run = _running_run(tmp_path, run_id="forked-claim")
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    detail_read, detail_write = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - assertions and reporting stay in the parent
        os.close(ready_read)
        os.close(release_write)
        os.close(detail_read)
        try:
            child_run = store.Run.open(tmp_path, "acme.example", run.run_id)
            with child_run.artifact_claim("raw", "fork", "fixture", "held.bin"):
                os.write(ready_write, b"claimed\n")
                if os.read(release_read, 1) != b"x":
                    raise AssertionError("parent did not release the artifact claim")
        except BaseException as exc:
            try:
                os.write(detail_write, f"{type(exc).__name__}: {exc}".encode("utf-8")[:2048])
            except OSError:
                pass
            os._exit(70)
        os._exit(0)

    os.close(ready_write)
    os.close(release_read)
    os.close(detail_write)
    child_status = None
    try:
        ready, _, _ = select.select([ready_read], [], [], 3)
        if not ready:
            detail = os.read(detail_read, 2048).decode("utf-8", errors="replace")
            pytest.fail(f"forked artifact claim did not become ready: {detail}")
        message = os.read(ready_read, len(b"claimed\n"))
        if message != b"claimed\n":
            detail = os.read(detail_read, 2048).decode("utf-8", errors="replace")
            pytest.fail(f"forked artifact claim exited before acquisition: {detail}")

        sealer = store.Run.open(tmp_path, "acme.example", run.run_id)
        with pytest.raises(ContractError, match="live artifact claim"):
            sealer.begin_finalization()
        assert sealer.state == "running"

        os.write(release_write, b"x")
        child_status = _reap_bounded(child_pid)
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

    detail = os.read(detail_read, 2048).decode("utf-8", errors="replace")
    os.close(detail_read)
    assert os.waitstatus_to_exitcode(child_status) == 0, detail
    sealer.begin_finalization()
    assert sealer.state == "finalizing"


def test_tool_record_committed_by_another_handle_is_not_instance_local(tmp_path):
    run = _running_run(tmp_path, run_id="durable-tool-record")
    writer = store.Run.open(tmp_path, "acme.example", run.run_id)
    finalizer = store.Run.open(tmp_path, "acme.example", run.run_id)

    writer.record("probe", _result_fixture("probe-fixture"))

    [record] = finalizer.tool_runs("probe")
    assert record.tool == "probe-fixture" and record.status == "success"
    finalizer.begin_finalization()
    assert [record.tool for record in finalizer.tool_runs("probe")] == ["probe-fixture"]


def test_event_sink_uses_run_authority_and_cannot_append_after_the_seal(tmp_path):
    run = _running_run(tmp_path, run_id="event-authority")
    events.reset()
    try:
        events.configure(run)
        sink = run.dir / "events.jsonl"
        events.emit("fixture", "authority-test", value="before")
        before = sink.read_bytes()
        assert json.loads(before.decode("utf-8"))["value"] == "before"

        run.begin_finalization()
        before_tree = _tree_snapshot(tmp_path)
        events.emit("fixture", "authority-test", value="after")

        assert sink.read_bytes() == before
        assert _tree_snapshot(tmp_path) == before_tree
        degraded = events.observability_degraded()
        assert degraded and degraded["writes_failed"] == 1
    finally:
        events.reset()


@pytest.mark.parametrize("operation", ["checkpoint", "save"])
def test_retained_budget_checkpoint_path_cannot_mutate_after_the_seal(tmp_path, operation):
    run = _running_run(tmp_path, run_id=f"sealed-budget-{operation}")
    state_file = run.raw_path("probe", "fixture", "resume.state.json")
    ledger = budget.Ledger(state_file, lane="probe.fixture")
    run.begin_finalization()
    before = _tree_snapshot(tmp_path)

    try:
        accepted = getattr(ledger, operation)()
    except ContractError:
        accepted = False

    assert accepted is False
    assert _tree_snapshot(tmp_path) == before


def test_budget_pruning_cannot_delete_checkpoint_evidence_after_the_seal(tmp_path):
    run = _running_run(tmp_path, run_id="sealed-budget-prune")
    state_base = run.raw_path("content", "fixture", "anchor").parent
    old = budget.state_path(state_base, "content.fixture", "old-fingerprint")
    old.write_text("owned checkpoint evidence")
    run.begin_finalization()
    before = _tree_snapshot(tmp_path)

    with pytest.raises(ContractError):
        budget.prune_state(state_base, "content.fixture", "new-fingerprint")

    assert _tree_snapshot(tmp_path) == before


def test_metrics_writer_refuses_a_finished_run_until_it_is_explicitly_reopened(tmp_path):
    run = _running_run(tmp_path, run_id="sealed-metrics")
    run.begin_finalization()
    run.write_state("finished")
    before = _tree_snapshot(tmp_path)

    with pytest.raises(ContractError):
        metrics.write(run, [], 1.0, 0.1, 2.0)

    assert _tree_snapshot(tmp_path) == before


def test_legacy_runner_path_cannot_launch_or_publish_into_a_sealed_run(tmp_path, monkeypatch):
    run = _running_run(tmp_path, run_id="sealed-runner")
    final = run.raw_path("probe", "fixture", "stdout.bin")
    run.begin_finalization()
    before = _tree_snapshot(tmp_path)
    launches = []

    def forbidden_launch(*args, **kwargs):
        launches.append((args, kwargs))
        raise AssertionError("a sealed ambient output path reached process launch")

    monkeypatch.setattr(runner.subprocess, "Popen", forbidden_launch)

    result = runner.run(
        "fixture",
        [sys.executable, "-c", "print('late evidence')"],
        raw_path=final,
        timeout=3,
    )

    assert not launches
    assert result.status is runner.Status.FAILED
    assert result.started is False
    assert any(fault.get("kind") == "machinery" for fault in result.meta.get("faults", ()))
    assert not final.exists()
    assert _tree_snapshot(tmp_path) == before
