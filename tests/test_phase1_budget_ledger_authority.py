"""Authority regressions for managed budget completion ledgers."""
from __future__ import annotations

import contextlib
import json
import os
import stat
import threading
from pathlib import Path

import pytest

from quarry_recon import budget, privfs, store
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


@contextlib.contextmanager
def _umask(value: int):
    previous = os.umask(value)
    try:
        yield
    finally:
        os.umask(previous)


def _run(tmp_path, run_id: str):
    run = store.Run.create(tmp_path, "acme.example", run_id=run_id)
    run.write_state("running")
    state = run.raw_path("budget", "lane", "resume.state.json")
    artifact = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "budget", "lane", "payload.bin"),
        b"digest-bound budget payload",
    )
    return run, state, artifact


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _tree(root: Path):
    snapshot = {}
    for path in sorted(root.rglob("*")):
        key = str(path.relative_to(root))
        observed = path.lstat()
        snapshot[key] = (
            stat.S_IFMT(observed.st_mode), stat.S_IMODE(observed.st_mode),
            path.read_bytes() if path.is_file() else None,
        )
    return snapshot


def test_managed_ledger_journal_and_snapshot_are_private_replayable_and_sealable(
    tmp_path,
):
    with _umask(0o022):
        run, state, artifact = _run(tmp_path, "budget-private")
        ledger = budget.Ledger(state, lane="crawl.budget")
        assert ledger.checkpoint()
        assert ledger.record("https://t/item", artifact)
        assert _mode(ledger.journal) == 0o600

        replayed = budget.Ledger(state, lane="crawl.budget")
        assert replayed.has("https://t/item")
        assert replayed.artifact("https://t/item") == artifact

        assert ledger.save()
        assert _mode(state) == 0o600
        assert _mode(ledger.journal) == 0o600
        assert json.loads(ledger.journal.read_text()) == {
            "v": ledger.JOURNAL_SCHEMA,
            "l": ledger.lane,
            "k": "ckpt",
        }
        compacted = budget.Ledger(state, lane="crawl.budget")
        assert compacted.has("https://t/item")
        assert compacted.artifact("https://t/item") == artifact
        run.begin_finalization()
        sealed = budget.Ledger(state, lane="crawl.budget")
        assert sealed.has("https://t/item")
        assert sealed.artifact("https://t/item") == artifact


def test_managed_tail_repair_serializes_a_cooperative_repair_and_append(
    tmp_path, monkeypatch,
):
    run, state, artifact = _run(tmp_path, "budget-repair-serialization")
    ledger = budget.Ledger(state, lane="crawl.budget")
    assert ledger.record("first", artifact)
    journal = ledger.journal
    intact = journal.read_bytes()
    components = (
        "raw", "budget", "lane", "resume.state.json.journal",
    )
    run._append_base_artifact(components, b'{"v":')
    rel = str(artifact.relative_to(state.parent))
    appended = (
        json.dumps({
            "v": ledger.JOURNAL_SCHEMA,
            "l": ledger.lane,
            "i": "second",
            "r": rel,
            "d": ledger.digests[rel],
        })
        + "\n"
    ).encode("utf-8")

    loader_read = threading.Event()
    release_loader = threading.Event()
    writer_started = threading.Event()
    writer_finished = threading.Event()
    loaded = []
    failures = []
    real_read_text = Path.read_text

    def block_after_journal_read(path, *args, **kwargs):
        text = real_read_text(path, *args, **kwargs)
        if path == journal and threading.current_thread().name == "ledger-loader":
            loader_read.set()
            if not release_loader.wait(5):
                raise AssertionError("loader release timed out")
        return text

    def load_ledger():
        try:
            loaded.append(budget.Ledger(state, lane="crawl.budget"))
        except BaseException as exc:
            failures.append(exc)

    def repair_and_append():
        try:
            writer_started.set()
            run._replace_artifact(
                store.MutationScope.BASE_EVIDENCE, components, intact,
            )
            run._append_base_artifact(components, appended)
        except BaseException as exc:
            failures.append(exc)
        finally:
            writer_finished.set()

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", block_after_journal_read)
        loader = threading.Thread(target=load_ledger, name="ledger-loader")
        writer = threading.Thread(target=repair_and_append, name="ledger-writer")
        loader.start()
        assert loader_read.wait(5)
        writer.start()
        assert writer_started.wait(5)
        assert not writer_finished.wait(0.1)
        release_loader.set()
        loader.join(5)
        writer.join(5)

    assert not loader.is_alive() and not writer.is_alive()
    assert not failures and len(loaded) == 1 and loaded[0].has("first")
    replayed = budget.Ledger(state, lane="crawl.budget")
    assert replayed.has("first") and replayed.has("second")


def test_managed_snapshot_and_journal_load_serializes_concurrent_save(
    tmp_path, monkeypatch,
):
    _run_owner, state, artifact = _run(tmp_path, "budget-load-save-serialization")
    initial = budget.Ledger(state, lane="crawl.budget")
    assert initial.record("first", artifact)
    assert initial.save()
    saver = budget.Ledger(state, lane="crawl.budget")
    assert saver.record("second", artifact)
    journal = saver.journal

    snapshot_read = threading.Event()
    release_loader = threading.Event()
    saver_started = threading.Event()
    saver_finished = threading.Event()
    loaded = []
    saved = []
    failures = []
    real_read_text = Path.read_text

    def block_after_snapshot_read(path, *args, **kwargs):
        text = real_read_text(path, *args, **kwargs)
        if path == state and threading.current_thread().name == "ledger-loader":
            snapshot_read.set()
            if not release_loader.wait(5):
                raise AssertionError("loader release timed out")
        return text

    def load_ledger():
        try:
            loaded.append(budget.Ledger(state, lane="crawl.budget"))
        except BaseException as exc:
            failures.append(exc)

    def save_ledger():
        try:
            saver_started.set()
            saved.append(saver.save())
        except BaseException as exc:
            failures.append(exc)
        finally:
            saver_finished.set()

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", block_after_snapshot_read)
        loader = threading.Thread(target=load_ledger, name="ledger-loader")
        saving = threading.Thread(target=save_ledger, name="ledger-saver")
        loader.start()
        assert snapshot_read.wait(5)
        saving.start()
        assert saver_started.wait(5)
        assert not saver_finished.wait(0.1)
        assert journal.exists()
        release_loader.set()
        loader.join(5)
        saving.join(5)

    assert not loader.is_alive() and not saving.is_alive()
    assert not failures and saved == [True] and len(loaded) == 1
    assert loaded[0].has("first") and loaded[0].has("second")
    replayed = budget.Ledger(state, lane="crawl.budget")
    assert replayed.has("first") and replayed.has("second")


def test_managed_stale_ledger_refreshes_concurrent_append_before_save(tmp_path):
    run, state, artifact = _run(tmp_path, "budget-stale-save")
    second = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "budget", "lane", "concurrent-second.bin"),
        b"concurrent second payload",
    )
    stale = budget.Ledger(state, lane="crawl.budget")
    writer = budget.Ledger(state, lane="crawl.budget")
    assert writer.record("concurrent", artifact)
    assert writer.record("concurrent", second)

    assert stale.save()

    replayed = budget.Ledger(state, lane="crawl.budget")
    assert replayed.has("concurrent")
    assert replayed.artifact("concurrent") == second
    assert replayed.evidence("concurrent") == [artifact, second]
    assert len(replayed.evid["concurrent"]) == len(set(replayed.evid["concurrent"]))
    assert _mode(state) == 0o600 and _mode(replayed.journal) == 0o600


def test_managed_save_preserves_all_durable_completion_evidence_for_one_item(
    tmp_path,
):
    run, state, first = _run(tmp_path, "budget-completion-history")
    second = run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE,
        ("raw", "budget", "lane", "second.bin"),
        b"second digest-bound payload",
    )
    ledger = budget.Ledger(state, lane="crawl.budget")
    assert ledger.record("same-item", first)
    assert ledger.record("same-item", second)
    assert ledger.artifact("same-item") == second
    assert ledger.evidence("same-item") == [first, second]

    assert ledger.save()

    replayed = budget.Ledger(state, lane="crawl.budget")
    assert replayed.artifact("same-item") == second
    assert replayed.evidence("same-item") == [first, second]
    assert len(replayed.evid["same-item"]) == len(set(replayed.evid["same-item"]))


@pytest.mark.parametrize("fault_position", ["before", "after"])
@pytest.mark.parametrize("fault_type", [OSError, KeyboardInterrupt, SystemExit])
def test_managed_journal_checkpoint_fault_has_no_unlink_quarantine(
    tmp_path, monkeypatch, fault_position, fault_type,
):
    _run_owner, state, artifact = _run(
        tmp_path, f"budget-checkpoint-{fault_position}-{fault_type.__name__}",
    )
    ledger = budget.Ledger(state, lane="crawl.budget")
    assert ledger.record("item", artifact)
    journal_before = ledger.journal.read_bytes()
    real_replace = store.Run._replace_artifact
    fault = fault_type(f"journal checkpoint {fault_position} fault")

    def fault_journal(owner, scope, components, data):
        if components[-1] != "resume.state.json.journal":
            return real_replace(owner, scope, components, data)
        if fault_position == "after":
            real_replace(owner, scope, components, data)
        raise fault

    with monkeypatch.context() as patch:
        patch.setattr(store.Run, "_replace_artifact", fault_journal)
        if fault_type is OSError:
            assert ledger.save()
        else:
            with pytest.raises(fault_type) as caught:
                ledger.save()
            assert caught.value is fault

    assert state.is_file() and _mode(state) == 0o600
    assert ledger.journal.is_file() and _mode(ledger.journal) == 0o600
    if fault_position == "before":
        assert ledger.journal.read_bytes() == journal_before
    else:
        assert json.loads(ledger.journal.read_text())["k"] == "ckpt"
    assert not list(state.parent.glob(".quarry-unlink-*.stage"))
    replayed = budget.Ledger(state, lane="crawl.budget")
    assert replayed.has("item") and replayed.artifact("item") == artifact


def test_unmanaged_ledger_keeps_legacy_umask_controlled_modes(tmp_path):
    state = tmp_path / "plain" / "resume.state.json"
    artifact = tmp_path / "plain" / "payload.bin"
    with _umask(0o022):
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"unmanaged payload")
        ledger = budget.Ledger(state, lane="plain.budget")
        assert ledger.record("item", artifact)
        assert _mode(ledger.journal) == 0o644
        assert ledger.save()
        assert _mode(state) == 0o644


def test_managed_save_with_retained_journal_replays_and_remains_sealable(
    tmp_path, monkeypatch,
):
    run, state, artifact = _run(tmp_path, "budget-retained-journal")
    ledger = budget.Ledger(state, lane="crawl.budget")
    assert ledger.record("item", artifact)
    journal = ledger.journal
    retained = journal.read_bytes()
    real_replace = store.Run._replace_artifact
    replacements = []

    def retain_journal(owner, scope, components, data):
        replacements.append(components)
        if components[-1] == "resume.state.json.journal":
            raise OSError("journal retention fault")
        return real_replace(owner, scope, components, data)

    with monkeypatch.context() as patch:
        patch.setattr(store.Run, "_replace_artifact", retain_journal)
        assert ledger.save()

    assert replacements == [
        ("raw", "budget", "lane", "resume.state.json"),
        ("raw", "budget", "lane", "resume.state.json.journal"),
    ]
    assert ledger._journal_unsafe
    assert journal.read_bytes() == retained
    assert _mode(journal) == 0o600 and _mode(state) == 0o600
    replayed = budget.Ledger(state, lane="crawl.budget")
    assert replayed.has("item") and replayed.artifact("item") == artifact
    run.begin_finalization()


def test_managed_damaged_tail_repair_uses_private_replace_authority(
    tmp_path, monkeypatch,
):
    run, state, artifact = _run(tmp_path, "budget-tail-repair")
    ledger = budget.Ledger(state, lane="crawl.budget")
    assert ledger.record("item", artifact)
    journal = ledger.journal
    intact = journal.read_bytes()
    with journal.open("ab") as handle:
        handle.write(b'{"v":')

    real_replace = store.Run._replace_artifact
    replaced = []

    def observe_replace(owner, scope, components, data):
        replaced.append((scope, components, data))
        return real_replace(owner, scope, components, data)

    with monkeypatch.context() as patch:
        patch.setattr(store.Run, "_replace_artifact", observe_replace)
        replayed = budget.Ledger(state, lane="crawl.budget")

    expected_components = (
        "raw", "budget", "lane", "resume.state.json.journal",
    )
    assert replaced == [(
        store.MutationScope.BASE_EVIDENCE, expected_components, intact,
    )]
    assert replayed.has("item") and replayed.artifact("item") == artifact
    assert journal.read_bytes() == intact and _mode(journal) == 0o600
    run.begin_finalization()


@pytest.mark.parametrize("operation", ["checkpoint", "save"])
def test_managed_ledger_refuses_sealed_mutation_without_namespace_change(
    tmp_path, operation,
):
    run, state, _artifact = _run(tmp_path, f"budget-sealed-{operation}")
    ledger = budget.Ledger(state, lane="crawl.budget")
    run.begin_finalization()
    before = _tree(tmp_path)

    with pytest.raises(ContractError):
        getattr(ledger, operation)()

    assert _tree(tmp_path) == before
    assert not state.exists() and not ledger.journal.exists()


@pytest.mark.parametrize("operation", ["append", "save"])
@pytest.mark.parametrize(
    "fault_type",
    [OSError, privfs.PrivateReplaceCommittedWithFault, KeyboardInterrupt],
)
def test_reported_after_commit_fault_preserves_managed_ledger_truth(
    tmp_path, monkeypatch, operation, fault_type,
):
    run, state, artifact = _run(
        tmp_path, f"budget-{operation}-{fault_type.__name__}",
    )
    ledger = budget.Ledger(state, lane="crawl.budget")
    if operation == "save":
        assert ledger.record("item", artifact)
        method_name = "_replace_artifact"
    else:
        method_name = "_append_base_artifact"
    real = getattr(store.Run, method_name)
    fault = fault_type(f"{operation} reported after commit")

    def commit_then_report(owner, *args, **kwargs):
        real(owner, *args, **kwargs)
        raise fault

    with monkeypatch.context() as patch:
        patch.setattr(store.Run, method_name, commit_then_report)
        if issubclass(fault_type, (OSError, privfs.PrivatePathError)):
            accepted = (
                ledger.record("item", artifact)
                if operation == "append" else ledger.save()
            )
            assert accepted is False
        else:
            with pytest.raises(KeyboardInterrupt) as caught:
                (
                    ledger.record("item", artifact)
                    if operation == "append" else ledger.save()
                )
            assert caught.value is fault

    assert _mode(ledger.journal) == 0o600
    if operation == "save":
        assert _mode(state) == 0o600
    replayed = budget.Ledger(state, lane="crawl.budget")
    assert replayed.has("item") and replayed.artifact("item") == artifact
