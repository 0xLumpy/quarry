"""Phase 1: managed attempt allocation and writability probes use Run authority."""
from __future__ import annotations

import multiprocessing
import os

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
