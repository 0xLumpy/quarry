"""Step 5: native argv outputs remain private until repository settlement."""
from __future__ import annotations

import dataclasses
import os
import select
import signal
import stat
import sys
from pathlib import Path

import pytest

from quarry_recon import runner_native, store
from quarry_recon.runner_native import (
    NativeOutputAdoption,
    NativeOutputTransaction,
    NativeOutputUnsupported,
    RepositoryNativeOutput,
    prepare_native_outputs,
)
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


def _running_run(project: Path, run_id: str) -> store.Run:
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _python_command(source: str, *arguments: Path) -> tuple[str, ...]:
    return (sys.executable, "-c", source, *(str(argument) for argument in arguments))


def _run_child(transaction: NativeOutputTransaction) -> None:
    """Run the rewritten Python fixture argv in a real forked child."""
    command = transaction.rewritten_cmd
    assert command[:2] == (sys.executable, "-c")
    detail_read, detail_write = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - the parent owns assertions
        os.close(detail_read)
        try:
            sys.argv = [command[0], *command[3:]]
            exec(compile(command[2], "<native-output-fixture>", "exec"), {})
        except BaseException as exc:
            try:
                os.write(
                    detail_write,
                    f"{type(exc).__name__}: {exc}".encode("utf-8")[:2048],
                )
            finally:
                os._exit(70)
        os._exit(0)
    os.close(detail_write)
    _, status = os.waitpid(child, 0)
    detail = os.read(detail_read, 2048).decode("utf-8", errors="replace")
    os.close(detail_read)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, detail


def _publish_file(run: store.Run, components: tuple[str, ...], body: bytes) -> Path:
    final = run.dir.joinpath(*components)
    command = _python_command(
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(sys.argv[2].encode())",
        final,
        Path(body.decode("ascii")),
    )
    policy = RepositoryNativeOutput.file(3, *components)
    transaction = prepare_native_outputs(run, command, (policy,))
    _run_child(transaction)
    receipt = transaction.finish(clean=True)
    assert receipt.clean
    return final


def _attempt_directories(run: store.Run) -> list[Path]:
    root = run.project_dir / "recon" / "state" / "native-stages" / run.run_id
    return [] if not root.exists() else list(root.iterdir())


def _reap_child(child: int) -> int:
    waited, status = os.waitpid(child, 0)
    assert waited == child
    return status


def test_exact_file_binding_is_private_then_durably_committed(tmp_path):
    run = _running_run(tmp_path, "native-file")
    final = run.dir / "raw" / "native" / "fixture" / "body.bin"
    command = _python_command(
        "from pathlib import Path; import os,sys; p=Path(sys.argv[1]); "
        "p.write_bytes(b'\\x00native\\xff'); os.chmod(p, 0o644)",
        final,
    )
    policy = RepositoryNativeOutput.file(3, "raw", "native", "fixture", "body.bin")

    transaction = prepare_native_outputs(run, command, (policy,))

    assert transaction.rewritten_cmd[:3] == command[:3]
    assert transaction.rewritten_cmd[3] != str(final)
    assert "native-stages" in transaction.rewritten_cmd[3]
    assert not final.exists()
    assert stat.S_IMODE(Path(transaction.rewritten_cmd[3]).parent.stat().st_mode) == 0o700
    assert run._live_artifact_claim_count() == 1

    _run_child(transaction)
    assert not final.exists(), "the child must never publish its own output"
    receipt = transaction.finish(clean=True)

    assert receipt.clean
    assert [item.policy_index for item in receipt.committed] == [0]
    assert not receipt.uncertain and not receipt.unpublished
    assert receipt.committed[0].present
    assert receipt.committed[0].size == len(b"\x00native\xff")
    assert final.read_bytes() == b"\x00native\xff"
    assert stat.S_IMODE(final.stat().st_mode) == 0o600
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_multiple_file_policies_have_disjoint_exact_receipt(tmp_path):
    run = _running_run(tmp_path, "native-multifile")
    first = run.dir / "raw" / "probe" / "nuclei.jsonl"
    second = run.dir / "raw" / "probe" / "nmap.xml"
    command = _python_command(
        "from pathlib import Path; import sys; "
        "Path(sys.argv[1]).write_text('one'); Path(sys.argv[2]).write_text('two')",
        first,
        second,
    )
    policies = (
        RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl"),
        RepositoryNativeOutput.file(4, "raw", "probe", "nmap.xml"),
    )

    transaction = prepare_native_outputs(run, command, policies)
    assert len(set(transaction.rewritten_cmd[3:5])) == 2
    _run_child(transaction)
    receipt = transaction.finish(clean=True)

    assert receipt.clean
    assert tuple(item.policy_index for item in receipt.committed) == (0, 1)
    assert first.read_text() == "one"
    assert second.read_text() == "two"


def test_tree_rewrites_root_and_descendant_and_normalizes_every_leaf(tmp_path):
    run = _running_run(tmp_path, "native-tree")
    final = run.dir / "raw" / "crawl" / "gowitness"
    report = final / "gowitness.jsonl"
    command = _python_command(
        "from pathlib import Path; import os,sys; root=Path(sys.argv[1]); "
        "(root/'screens').mkdir(); (root/'screens'/'shot.png').write_bytes(b'png'); "
        "Path(sys.argv[2]).write_text('report'); os.chmod(root/'screens', 0o755); "
        "os.chmod(root/'screens'/'shot.png', 0o644)",
        final,
        report,
    )
    policy = RepositoryNativeOutput.tree(
        ((3, ()), (4, ("gowitness.jsonl",))),
        "raw", "crawl", "gowitness",
    )

    transaction = prepare_native_outputs(run, command, (policy,))
    staged_root = Path(transaction.rewritten_cmd[3])
    assert Path(transaction.rewritten_cmd[4]) == staged_root / "gowitness.jsonl"
    assert staged_root.is_dir()
    assert not final.exists()
    _run_child(transaction)
    receipt = transaction.finish(clean=True)

    assert receipt.clean and receipt.committed[0].present
    assert report.read_text() == "report"
    assert (final / "screens" / "shot.png").read_bytes() == b"png"
    for path in (final, final / "screens"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    for path in (report, final / "screens" / "shot.png"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_tree_can_seed_and_replace_a_prior_authenticated_generation(tmp_path):
    run = _running_run(tmp_path, "native-tree-prior")
    final = run.dir / "raw" / "crawl" / "gowitness"
    initial = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness",
    )
    first = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'prior.txt').write_text('prior')",
            final,
        ),
        (initial,),
    )
    _run_child(first)
    assert first.finish(clean=True).clean

    accumulating = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness", seed_prior=True,
    )
    second = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; root=Path(sys.argv[1]); "
            "assert (root/'prior.txt').read_text() == 'prior'; "
            "(root/'current.txt').write_text('current')",
            final,
        ),
        (accumulating,),
    )
    _run_child(second)
    receipt = second.finish(clean=True)

    assert receipt.clean
    assert (final / "prior.txt").read_text() == "prior"
    assert (final / "current.txt").read_text() == "current"
    assert not any(path.name.startswith(".quarry-native-tree-")
                   for path in final.parent.iterdir())


def test_optional_tree_commits_an_authenticated_empty_current_generation(tmp_path):
    run = _running_run(tmp_path, "native-tree-empty")
    final = run.dir / "raw" / "crawl" / "gowitness"
    initial = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness",
    )
    first = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'stale.txt').write_text('stale')",
            final,
        ),
        (initial,),
    )
    _run_child(first)
    assert first.finish(clean=True).clean

    optional = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness", required=False,
    )
    second = prepare_native_outputs(
        run,
        _python_command("import sys", final),
        (optional,),
    )
    _run_child(second)
    receipt = second.finish(clean=True)

    assert receipt.clean
    assert receipt.committed[0].present
    assert final.is_dir() and list(final.iterdir()) == []


def test_required_file_absence_is_unpublished_and_preserves_prior(tmp_path):
    run = _running_run(tmp_path, "native-required-absent")
    components = ("raw", "probe", "nuclei.jsonl")
    final = _publish_file(run, components, b"prior")
    policy = RepositoryNativeOutput.file(3, *components)
    transaction = prepare_native_outputs(
        run,
        _python_command("import sys", final),
        (policy,),
    )
    _run_child(transaction)

    receipt = transaction.finish(clean=True)

    assert not receipt.clean
    assert not receipt.committed and not receipt.uncertain
    assert tuple(item.policy_index for item in receipt.unpublished) == (0,)
    assert receipt.fault_operation == "validate"
    assert final.read_bytes() == b"prior"
    assert run._live_artifact_claim_count() == 0


def test_optional_file_absence_is_an_explicit_committed_deletion(tmp_path):
    run = _running_run(tmp_path, "native-optional-absent")
    components = ("raw", "probe", "optional.jsonl")
    final = _publish_file(run, components, b"prior")
    policy = RepositoryNativeOutput.file(3, *components, required=False)
    transaction = prepare_native_outputs(
        run,
        _python_command("import sys", final),
        (policy,),
    )
    _run_child(transaction)

    receipt = transaction.finish(clean=True)

    assert receipt.clean
    assert len(receipt.committed) == 1
    assert not receipt.committed[0].present
    assert not final.exists()


def test_nonclean_execution_fences_stage_without_touching_prior(tmp_path):
    run = _running_run(tmp_path, "native-nonclean")
    components = ("raw", "probe", "nuclei.jsonl")
    final = _publish_file(run, components, b"prior")
    policy = RepositoryNativeOutput.file(3, *components)
    transaction = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('partial')",
            final,
        ),
        (policy,),
    )
    _run_child(transaction)

    receipt = transaction.finish(clean=False)

    assert not receipt.clean
    assert receipt.fault_operation == "execute"
    assert len(receipt.unpublished) == 1
    assert final.read_bytes() == b"prior"
    assert not receipt.claim_retained
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_tree_link_or_hardlink_is_refused_before_publication(tmp_path):
    run = _running_run(tmp_path, "native-tree-unsafe")
    final = run.dir / "raw" / "crawl" / "gowitness"
    policy = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness",
    )
    transaction = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import os,sys; root=Path(sys.argv[1]); "
            "(root/'proof').write_text('proof'); os.link(root/'proof', root/'alias')",
            final,
        ),
        (policy,),
    )
    _run_child(transaction)

    receipt = transaction.finish(clean=True)

    assert not receipt.clean
    assert receipt.fault_operation == "validate"
    assert len(receipt.unpublished) == 1
    assert not final.exists()
    assert run._live_artifact_claim_count() == 0


def test_reported_exchange_error_is_reconciled_without_rollback(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "native-tree-reconcile")
    final = run.dir / "raw" / "crawl" / "gowitness"
    policy = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness",
    )
    first = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'generation').write_text('prior')",
            final,
        ),
        (policy,),
    )
    _run_child(first)
    assert first.finish(clean=True).clean

    second = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'generation').write_text('current')",
            final,
        ),
        (policy,),
    )
    _run_child(second)
    real_exchange = runner_native._rename_exchange

    def exchange_then_report_error(*arguments):
        real_exchange(*arguments)
        raise OSError("reported exchange fault")

    monkeypatch.setattr(runner_native, "_rename_exchange", exchange_then_report_error)
    receipt = second.finish(clean=True)

    assert not receipt.clean
    assert len(receipt.committed) == 1
    assert not receipt.uncertain and not receipt.unpublished
    assert receipt.fault_operation == "publish"
    assert (final / "generation").read_text() == "current"
    assert not receipt.claim_retained
    assert run._live_artifact_claim_count() == 0


def test_clean_exchange_refusal_preserves_prior_and_is_unpublished(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "native-tree-refusal")
    final = run.dir / "raw" / "crawl" / "gowitness"
    policy = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness",
    )
    first = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'generation').write_text('prior')",
            final,
        ),
        (policy,),
    )
    _run_child(first)
    assert first.finish(clean=True).clean
    second = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'generation').write_text('current')",
            final,
        ),
        (policy,),
    )
    _run_child(second)

    def unavailable(*_arguments):
        raise NativeOutputUnsupported("fixture exchange refusal")

    monkeypatch.setattr(runner_native, "_rename_exchange", unavailable)
    receipt = second.finish(clean=True)

    assert not receipt.clean
    assert len(receipt.unpublished) == 1
    assert not receipt.uncertain and not receipt.committed
    assert receipt.fault_operation == "publish"
    assert (final / "generation").read_text() == "prior"
    assert run._live_artifact_claim_count() == 0


def test_post_exchange_fsync_fault_is_uncertain_and_retains_prior_and_claim(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path, "native-tree-fsync")
    final = run.dir / "raw" / "crawl" / "gowitness"
    policy = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness",
    )
    first = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'generation').write_text('prior')",
            final,
        ),
        (policy,),
    )
    _run_child(first)
    assert first.finish(clean=True).clean
    second = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'generation').write_text('current')",
            final,
        ),
        (policy,),
    )
    _run_child(second)
    real_fsync = runner_native.os.fsync
    injected = False

    def fault_after_exchange(fd):
        nonlocal injected
        if (not injected and final.is_dir()
                and (final / "generation").read_text() == "current"):
            injected = True
            raise OSError("fixture directory fsync fault")
        return real_fsync(fd)

    monkeypatch.setattr(runner_native.os, "fsync", fault_after_exchange)
    receipt = second.finish(clean=True)

    assert injected
    assert not receipt.clean
    assert len(receipt.uncertain) == 1
    assert not receipt.committed and not receipt.unpublished
    assert receipt.fault_operation == "publish"
    assert receipt.claim_retained and not receipt.cleanup_settled
    assert (final / "generation").read_text() == "current"
    retained = [
        path for path in final.parent.iterdir()
        if path.name.startswith(".quarry-native-tree-")
    ]
    assert len(retained) == 1
    assert (retained[0] / "generation").read_text() == "prior"
    assert run._live_artifact_claim_count() == 1
    observer = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(ContractError, match="live artifact claim"):
        observer.begin_finalization()


def test_unsettled_cleanup_retains_durable_claim_and_blocks_seal(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "native-retained-claim")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    transaction = prepare_native_outputs(
        run,
        _python_command("import sys", final),
        (policy,),
    )
    real_cleanup = NativeOutputTransaction._cleanup_attempt

    def cleanup_fault(_self):
        return False, OSError("fixture cleanup fault")

    monkeypatch.setattr(NativeOutputTransaction, "_cleanup_attempt", cleanup_fault)
    receipt = transaction.finish(clean=False)

    assert not receipt.clean and receipt.claim_retained
    assert not receipt.cleanup_settled
    assert run._live_artifact_claim_count() == 1
    observer = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(ContractError, match="live artifact claim"):
        observer.begin_finalization()

    monkeypatch.setattr(NativeOutputTransaction, "_cleanup_attempt", real_cleanup)
    assert real_cleanup(transaction) == (True, None)
    assert transaction._release_claim() == (True, None)
    assert run._live_artifact_claim_count() == 0


def test_live_transaction_blocks_seal_until_it_is_fenced(tmp_path):
    run = _running_run(tmp_path, "native-seal")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    transaction = prepare_native_outputs(
        run,
        _python_command("import sys", final),
        (policy,),
    )

    observer = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(ContractError, match="live artifact claim"):
        observer.begin_finalization()

    transaction.finish(clean=False)
    observer.begin_finalization()
    assert observer.state == "finalizing"


def test_cross_process_native_claim_blocks_seal_until_child_fences(tmp_path):
    run = _running_run(tmp_path, "native-cross-process-seal")
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    detail_read, detail_write = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - the parent owns assertions
        os.close(ready_read)
        os.close(release_write)
        os.close(detail_read)
        try:
            child_run = store.Run.open(tmp_path, "acme.example", run.run_id)
            final = child_run.dir / "raw" / "probe" / "nuclei.jsonl"
            policy = RepositoryNativeOutput.file(
                3, "raw", "probe", "nuclei.jsonl",
            )
            transaction = prepare_native_outputs(
                child_run,
                _python_command("import sys", final),
                (policy,),
            )
            os.write(ready_write, b"claimed")
            if os.read(release_read, 1) != b"x":
                raise AssertionError("parent did not release child transaction")
            transaction.finish(clean=False)
        except BaseException as exc:
            try:
                os.write(
                    detail_write,
                    f"{type(exc).__name__}: {exc}".encode("utf-8")[:2048],
                )
            finally:
                os._exit(70)
        os._exit(0)

    os.close(ready_write)
    os.close(release_read)
    os.close(detail_write)
    child_status = None
    try:
        ready, _, _ = select.select([ready_read], [], [], 5)
        if not ready or os.read(ready_read, len(b"claimed")) != b"claimed":
            detail = os.read(detail_read, 2048).decode("utf-8", errors="replace")
            pytest.fail(f"forked native claimant did not become ready: {detail}")
        observer = store.Run.open(tmp_path, "acme.example", run.run_id)
        with pytest.raises(ContractError, match="live artifact claim"):
            observer.begin_finalization()
        os.write(release_write, b"x")
        child_status = _reap_child(child)
        assert os.WIFEXITED(child_status) and os.WEXITSTATUS(child_status) == 0
        observer.begin_finalization()
        assert observer.state == "finalizing"
    finally:
        for fd in (ready_read, release_write, detail_read):
            try:
                os.close(fd)
            except OSError:
                pass
        if child_status is None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)


def test_cancellation_is_reraised_only_after_fence_and_receipt(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "native-cancel")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    transaction = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('partial')",
            final,
        ),
        (policy,),
    )
    _run_child(transaction)

    def cancel(_self):
        raise KeyboardInterrupt("fixture cancellation")

    monkeypatch.setattr(NativeOutputTransaction, "_snapshots", cancel)
    with pytest.raises(KeyboardInterrupt, match="fixture cancellation"):
        transaction.finish(clean=True)

    receipt = transaction.finish(clean=False)
    assert not receipt.clean
    assert receipt.fault_operation == "validate"
    assert len(receipt.unpublished) == 1
    assert not receipt.claim_retained
    assert not final.exists()
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_policy_is_closed_immutable_and_mismatch_refuses_before_claim(tmp_path):
    run = _running_run(tmp_path, "native-policy")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.required = False

    wrong = _python_command("import sys", final.with_name("other.jsonl"))
    with pytest.raises(ContractError, match="does not match canonical"):
        prepare_native_outputs(run, wrong, (policy,))

    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_prepare_reconciles_interruption_after_claim_create(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(tmp_path, f"native-claim-{interruption.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    real_create = runner_native._create_known_claim

    def create_then_interrupt(*arguments):
        real_create(*arguments)
        raise interruption("fixture claim boundary")

    monkeypatch.setattr(runner_native, "_create_known_claim", create_then_interrupt)
    with pytest.raises(interruption, match="fixture claim boundary"):
        prepare_native_outputs(
            run,
            _python_command("import sys", final),
            (policy,),
        )

    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_prepare_reconciles_interruption_after_attempt_root_create(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(tmp_path, f"native-root-{interruption.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    real_create = runner_native._create_prepare_root

    def create_then_interrupt(*arguments):
        real_create(*arguments)
        raise interruption("fixture root boundary")

    monkeypatch.setattr(runner_native, "_create_prepare_root", create_then_interrupt)
    with pytest.raises(interruption, match="fixture root boundary"):
        prepare_native_outputs(
            run,
            _python_command("import sys", final),
            (policy,),
        )

    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_prepare_reconciles_interruption_after_attempt_root_open(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(tmp_path, f"native-open-{interruption.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    real_open = runner_native._open_prepare_root

    def open_then_interrupt(*arguments):
        real_open(*arguments)
        raise interruption("fixture root open boundary")

    monkeypatch.setattr(runner_native, "_open_prepare_root", open_then_interrupt)
    with pytest.raises(interruption, match="fixture root open boundary"):
        prepare_native_outputs(
            run,
            _python_command("import sys", final),
            (policy,),
        )

    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_finish_reconciles_interruption_after_attempt_cleanup(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(tmp_path, f"native-cleanup-{interruption.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    transaction = prepare_native_outputs(
        run,
        _python_command("import sys", final),
        (policy,),
    )
    real_cleanup = NativeOutputTransaction._cleanup_attempt

    def cleanup_then_interrupt(self):
        real_cleanup(self)
        raise interruption("fixture cleanup boundary")

    monkeypatch.setattr(NativeOutputTransaction, "_cleanup_attempt", cleanup_then_interrupt)
    with pytest.raises(interruption, match="fixture cleanup boundary"):
        transaction.finish(clean=False)

    receipt = transaction.finish(clean=False)
    assert not receipt.clean and not receipt.claim_retained
    assert receipt.fault_type == interruption.__name__
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_finish_reconciles_interruption_after_claim_release(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(tmp_path, f"native-release-{interruption.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    transaction = prepare_native_outputs(
        run,
        _python_command("import sys", final),
        (policy,),
    )
    real_release = NativeOutputTransaction._release_claim

    def release_then_interrupt(self):
        real_release(self)
        raise interruption("fixture release boundary")

    monkeypatch.setattr(NativeOutputTransaction, "_release_claim", release_then_interrupt)
    with pytest.raises(interruption, match="fixture release boundary"):
        transaction.finish(clean=False)

    receipt = transaction.finish(clean=False)
    assert not receipt.clean and not receipt.claim_retained
    assert receipt.fault_type == interruption.__name__
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_file_publish_create_boundary_leaves_no_unowned_hidden_stage(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(tmp_path, f"native-file-owner-{interruption.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    transaction = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('new')",
            final,
        ),
        (policy,),
    )
    _run_child(transaction)
    real_create = runner_native._create_owned_file_stage

    def create_then_interrupt(*arguments):
        real_create(*arguments)
        raise interruption("fixture file-stage boundary")

    monkeypatch.setattr(
        runner_native, "_create_owned_file_stage", create_then_interrupt,
    )
    with pytest.raises(interruption, match="fixture file-stage boundary"):
        transaction.finish(clean=True)

    receipt = transaction.finish(clean=False)
    assert not receipt.clean and len(receipt.unpublished) == 1
    assert not receipt.claim_retained and receipt.cleanup_settled
    assert not final.exists()
    parent = run.dir / "raw" / "probe"
    assert not any(path.name.startswith(".quarry-native-file-")
                   for path in parent.iterdir())
    assert run._live_artifact_claim_count() == 0


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_tree_publish_create_boundary_leaves_no_unowned_hidden_stage(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(tmp_path, f"native-tree-owner-{interruption.__name__.lower()}")
    final = run.dir / "raw" / "crawl" / "gowitness"
    policy = RepositoryNativeOutput.tree(
        ((3, ()),), "raw", "crawl", "gowitness",
    )
    transaction = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; "
            "(Path(sys.argv[1])/'shot').write_text('new')",
            final,
        ),
        (policy,),
    )
    _run_child(transaction)
    real_create = runner_native._create_owned_tree

    def create_then_interrupt(*arguments):
        real_create(*arguments)
        raise interruption("fixture tree-stage boundary")

    monkeypatch.setattr(runner_native, "_create_owned_tree", create_then_interrupt)
    with pytest.raises(interruption, match="fixture tree-stage boundary"):
        transaction.finish(clean=True)

    receipt = transaction.finish(clean=False)
    assert not receipt.clean and len(receipt.unpublished) == 1
    assert not receipt.claim_retained and receipt.cleanup_settled
    assert not final.exists()
    parent = run.dir / "raw" / "crawl"
    assert not any(path.name.startswith(".quarry-native-tree-")
                   for path in parent.iterdir())
    assert run._live_artifact_claim_count() == 0


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_terminal_receipt_boundary_cannot_relabel_committed_output(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(tmp_path, f"native-receipt-{interruption.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    transaction = prepare_native_outputs(
        run,
        _python_command(
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('new')",
            final,
        ),
        (policy,),
    )
    _run_child(transaction)
    real_store = NativeOutputTransaction._store_receipt

    def store_then_interrupt(*arguments):
        real_store(*arguments)
        raise interruption("fixture receipt boundary")

    monkeypatch.setattr(NativeOutputTransaction, "_store_receipt", store_then_interrupt)
    with pytest.raises(interruption, match="fixture receipt boundary"):
        transaction.finish(clean=True)

    receipt = transaction.finish(clean=False)
    assert receipt.clean and len(receipt.committed) == 1
    assert not receipt.uncertain and not receipt.unpublished
    assert final.read_text() == "new"
    assert run._live_artifact_claim_count() == 0


@pytest.mark.parametrize(
    "exception_type", [RuntimeError, KeyboardInterrupt, SystemExit],
)
def test_preallocated_adoption_fences_prepare_return_boundary(
    tmp_path, exception_type,
):
    run = _running_run(tmp_path, f"native-adopt-{exception_type.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    adoption = NativeOutputAdoption()
    transaction = None
    primary = exception_type("fixture after prepare return")

    def wrapper():
        prepare_native_outputs(
            run,
            _python_command("import sys", final),
            (policy,),
            adoption=adoption,
        )
        raise primary

    try:
        transaction = wrapper()
    except BaseException as caught:
        receipt = adoption.fence()
        assert caught is primary
    else:  # pragma: no cover - the fixture always raises
        pytest.fail("prepare return boundary did not raise")

    assert transaction is None
    assert receipt is not None
    assert not receipt.clean and len(receipt.unpublished) == 1
    assert receipt.cleanup_settled and not receipt.claim_retained
    assert adoption.fence() is receipt
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize(
    "exception_type", [RuntimeError, KeyboardInterrupt, SystemExit],
)
def test_adoption_idempotently_fences_raw_prepare_owner(
    tmp_path, monkeypatch, exception_type,
):
    run = _running_run(tmp_path, f"native-raw-adopt-{exception_type.__name__.lower()}")
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    adoption = NativeOutputAdoption()
    primary = exception_type("fixture raw prepare boundary")
    real_create = runner_native._create_prepare_root

    def create_then_interrupt(*arguments):
        real_create(*arguments)
        raise primary

    monkeypatch.setattr(runner_native, "_create_prepare_root", create_then_interrupt)
    with pytest.raises(exception_type) as caught:
        prepare_native_outputs(
            run,
            _python_command("import sys", final),
            (policy,),
            adoption=adoption,
        )

    assert caught.value is primary
    receipt = adoption.fence()
    assert receipt is not None
    assert not receipt.clean and len(receipt.unpublished) == 1
    assert receipt.cleanup_settled and not receipt.claim_retained
    assert adoption.fence() is receipt
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def test_adoption_is_exact_and_single_use_before_side_effects(tmp_path):
    run = _running_run(tmp_path, "native-adoption-closed")
    first = run.dir / "raw" / "probe" / "one.jsonl"
    second = run.dir / "raw" / "probe" / "two.jsonl"
    adoption = NativeOutputAdoption()

    with pytest.raises(TypeError, match="exact owner"):
        prepare_native_outputs(
            run,
            _python_command("import sys", first),
            (RepositoryNativeOutput.file(3, "raw", "probe", "one.jsonl"),),
            adoption=object(),
        )
    transaction = prepare_native_outputs(
        run,
        _python_command("import sys", first),
        (RepositoryNativeOutput.file(3, "raw", "probe", "one.jsonl"),),
        adoption=adoption,
    )
    with pytest.raises(ContractError, match="already used"):
        prepare_native_outputs(
            run,
            _python_command("import sys", second),
            (RepositoryNativeOutput.file(3, "raw", "probe", "two.jsonl"),),
            adoption=adoption,
        )

    assert adoption.fence() == transaction.finish(clean=False)
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_adoption_transaction_fence_preserves_cleanup_cancellation(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(
        tmp_path, f"native-adopt-tx-cancel-{interruption.__name__.lower()}",
    )
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    adoption = NativeOutputAdoption()
    transaction = prepare_native_outputs(
        run,
        _python_command("import sys", final),
        (policy,),
        adoption=adoption,
    )
    cancellation = interruption("fixture adoption transaction cancellation")
    real_cleanup = NativeOutputTransaction._cleanup_attempt

    def cleanup_then_interrupt(self):
        real_cleanup(self)
        raise cancellation

    monkeypatch.setattr(
        NativeOutputTransaction, "_cleanup_attempt", cleanup_then_interrupt,
    )
    ordinary_primary = RuntimeError("fixture ordinary caller primary")
    try:
        raise ordinary_primary
    except RuntimeError as caught:
        assert caught is ordinary_primary
        with pytest.raises(interruption) as interrupted:
            adoption.fence()

    assert interrupted.value is cancellation
    receipt = adoption.fence()
    assert receipt is transaction.finish(clean=False)
    assert receipt.cleanup_settled and not receipt.claim_retained
    assert receipt.fault_type == interruption.__name__
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


def _raw_adoption_after_ordinary_prepare_failure(
    tmp_path, monkeypatch, run_id: str,
):
    run = _running_run(tmp_path, run_id)
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    adoption = NativeOutputAdoption()
    primary = RuntimeError("fixture ordinary prepare primary")
    real_create = runner_native._create_prepare_root

    def create_then_fail(owner):
        real_create(owner)
        raise primary

    with monkeypatch.context() as setup:
        setup.setattr(runner_native, "_create_prepare_root", create_then_fail)
        setup.setattr(NativeOutputAdoption, "fence", lambda self: None)
        with pytest.raises(RuntimeError) as caught:
            prepare_native_outputs(
                run,
                _python_command("import sys", final),
                (policy,),
                adoption=adoption,
            )

    assert caught.value is primary
    assert run._live_artifact_claim_count() == 1
    assert len(_attempt_directories(run)) == 1
    return run, adoption


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_raw_adoption_fence_preserves_cleanup_cancellation(
    tmp_path, monkeypatch, interruption,
):
    run, adoption = _raw_adoption_after_ordinary_prepare_failure(
        tmp_path,
        monkeypatch,
        f"native-adopt-raw-cleanup-{interruption.__name__.lower()}",
    )
    cancellation = interruption("fixture raw cleanup cancellation")
    real_cleanup = runner_native._cleanup_prepare_ownership
    calls = 0

    def cleanup_then_interrupt(*arguments):
        nonlocal calls
        result = real_cleanup(*arguments)
        calls += 1
        if calls == 1:
            raise cancellation
        return result

    monkeypatch.setattr(
        runner_native, "_cleanup_prepare_ownership", cleanup_then_interrupt,
    )
    with pytest.raises(interruption) as interrupted:
        adoption.fence()

    assert interrupted.value is cancellation
    receipt = adoption.fence()
    assert receipt is not None
    assert receipt.cleanup_settled and not receipt.claim_retained
    assert receipt.fault_type == interruption.__name__
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_raw_adoption_fence_preserves_release_cancellation(
    tmp_path, monkeypatch, interruption,
):
    run, adoption = _raw_adoption_after_ordinary_prepare_failure(
        tmp_path,
        monkeypatch,
        f"native-adopt-raw-release-{interruption.__name__.lower()}",
    )
    cancellation = interruption("fixture raw release cancellation")
    real_release = runner_native._release_known_claim_locked
    calls = 0

    def release_then_interrupt(*arguments):
        nonlocal calls
        result = real_release(*arguments)
        calls += 1
        if calls == 1:
            raise cancellation
        return result

    monkeypatch.setattr(
        runner_native, "_release_known_claim_locked", release_then_interrupt,
    )
    with pytest.raises(interruption) as interrupted:
        adoption.fence()

    assert interrupted.value is cancellation
    receipt = adoption.fence()
    assert receipt is not None
    assert receipt.cleanup_settled and not receipt.claim_retained
    assert receipt.fault_type == interruption.__name__
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_prepare_preserves_cleanup_cancellation_over_ordinary_primary(
    tmp_path, monkeypatch, interruption,
):
    run = _running_run(
        tmp_path, f"native-prepare-cleanup-{interruption.__name__.lower()}",
    )
    final = run.dir / "raw" / "probe" / "nuclei.jsonl"
    policy = RepositoryNativeOutput.file(3, "raw", "probe", "nuclei.jsonl")
    adoption = NativeOutputAdoption()
    primary = RuntimeError("fixture ordinary prepare primary")
    cancellation = interruption("fixture prepare cleanup cancellation")
    real_create = runner_native._create_prepare_root
    real_cleanup = runner_native._cleanup_prepare_ownership
    calls = 0

    def create_then_fail(owner):
        real_create(owner)
        raise primary

    def cleanup_then_interrupt(*arguments):
        nonlocal calls
        result = real_cleanup(*arguments)
        calls += 1
        if calls == 1:
            raise cancellation
        return result

    monkeypatch.setattr(runner_native, "_create_prepare_root", create_then_fail)
    monkeypatch.setattr(
        runner_native, "_cleanup_prepare_ownership", cleanup_then_interrupt,
    )
    with pytest.raises(interruption) as interrupted:
        prepare_native_outputs(
            run,
            _python_command("import sys", final),
            (policy,),
            adoption=adoption,
        )

    assert interrupted.value is cancellation
    assert interrupted.value.__cause__ is primary
    receipt = adoption.fence()
    assert receipt is not None
    assert receipt.cleanup_settled and not receipt.claim_retained
    assert receipt.fault_type == interruption.__name__
    assert run._live_artifact_claim_count() == 0
    assert _attempt_directories(run) == []
