"""Phase 1: one exact, cancellation-safe mutation authority owns each Run."""
from __future__ import annotations

import fcntl
import json
import multiprocessing
import os
import select
import shutil
import sys
import threading
from pathlib import Path

import pytest

from quarry_recon import store
from quarry_recon import privfs
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


def _running_run(project: Path, run_id: str = "mutation-authority") -> store.Run:
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _uninitialized_run(project: Path, run_id: str) -> store.Run:
    privfs.private_dir(project / "recon")
    os.mkdir(project / "recon" / run_id, privfs.DIR_MODE)
    return store.Run(
        project, "acme.example", run_id=run_id,
        _authority=store._RUN_CONSTRUCTION_AUTHORITY,
    )


def _open_fds() -> set[tuple[int, str]]:
    observed = set()
    if not os.path.isdir("/proc/self/fd"):
        return observed
    for name in os.listdir("/proc/self/fd"):
        try:
            observed.add((int(name), os.readlink(f"/proc/self/fd/{name}")))
        except OSError:
            pass
    return observed


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


def _cancel_once(function, target_line, call, cancellation_type):
    cancellation = cancellation_type(f"mutation-authority cancellation at {target_line}")
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


def _tree_bytes(root: Path) -> tuple:
    return tuple(
        (str(path.relative_to(root)), path.read_bytes())
        for path in sorted(root.rglob("*")) if path.is_file()
    )


def _owner_acquire(owner) -> None:
    settlement = store._SettlementOwner(owner.settle)
    with store._SettlementFence(settlement):
        with store._SettlementFence(settlement):
            owner.acquire()


def _lock_is_available(run: store.Run) -> bool:
    fd = os.open(run._lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


def test_creation_target_without_manifest_is_unchanged(tmp_path):
    run = store.Run.create(tmp_path, "acme.example", run_id="creation-only")
    assert not run.manifest_path.exists()
    assert store.read_run_creation_target(tmp_path, run.run_id) == "acme.example"


@pytest.mark.parametrize("operation", ["replace", "append", "state"])
def test_live_run_name_swap_never_mutates_replacement(tmp_path, monkeypatch, operation):
    run = _running_run(tmp_path, f"run-swap-{operation}")
    replacement = tmp_path / "replacement"
    displaced = tmp_path / "displaced"
    shutil.copytree(run.dir, replacement)
    replacement_before = _tree_bytes(replacement)
    original_require = store.Run._require_scope
    swapped = False

    def swap_after_validation(self, scope, owner):
        nonlocal swapped
        result = original_require(self, scope, owner)
        if not swapped:
            swapped = True
            os.rename(run.dir, displaced)
            os.rename(replacement, run.dir)
        return result

    monkeypatch.setattr(store.Run, "_require_scope", swap_after_validation)
    with pytest.raises(ContractError, match="identity changed"):
        if operation == "replace":
            run._replace_artifact(
                store.MutationScope.BASE_EVIDENCE,
                ("raw", "authority", "candidate.bin"), b"candidate",
            )
        elif operation == "append":
            run.add("ip", {"ip": "192.0.2.41", "source": "authority"})
        else:
            run.write_state("running")

    assert swapped
    assert _tree_bytes(run.dir) == replacement_before
    assert not (run.dir / "raw" / "authority" / "candidate.bin").exists()


def test_missing_lock_authority_fails_without_materializing_or_repairing(tmp_path):
    run = _running_run(tmp_path, "missing-lock")
    os.unlink(run._lock_path)
    before = _tree_bytes(tmp_path / "recon")

    with pytest.raises(ContractError, match="lock is missing"):
        with run._mutation(store.MutationScope.CONTROL):
            pytest.fail("missing lock admitted a mutation body")

    assert _tree_bytes(tmp_path / "recon") == before
    assert not run._lock_path.exists()


def test_lock_and_sidecar_pair_substitution_cannot_create_concurrent_fresh_process_entrant(tmp_path):
    run = _running_run(tmp_path, "pair-substitution")
    lock = run._lock_path
    sidecar = lock.with_name(f"{run.run_id}.lock.identity")
    held_lock = lock.with_suffix(".held")
    held_sidecar = sidecar.with_suffix(".held")

    with run._mutation(store.MutationScope.CONTROL):
        os.rename(lock, held_lock)
        os.rename(sidecar, held_sidecar)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        observed = os.fstat(fd)
        os.close(fd)
        sidecar.write_text(json.dumps({
            "schema_version": 1,
            "run_id": run.run_id,
            "device": observed.st_dev,
            "inode": observed.st_ino,
        }, sort_keys=True))
        os.chmod(sidecar, 0o600)
        marker = tmp_path / "fresh-process-entered"
        read_fd, write_fd = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - parent asserts the exact child report
            os.close(read_fd)
            try:
                for inherited in os.listdir("/proc/self/fd"):
                    inherited_fd = int(inherited)
                    if inherited_fd not in {0, 1, 2, write_fd}:
                        try:
                            os.close(inherited_fd)
                        except OSError:
                            pass
                # A freshly exec'd interpreter has no inherited thread ledger.
                store._RUN_LOCK_LOCAL.held = {}
                child_run = store.Run.open(tmp_path, "acme.example", run.run_id)
                try:
                    with child_run._mutation(store.MutationScope.CONTROL):
                        marker.write_text("entered")
                except BaseException as exc:
                    os.write(write_fd, type(exc).__name__.encode())
                else:
                    os.write(write_fd, b"ENTERED")
            finally:
                os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        assert not marker.exists()
        ready, _, _ = select.select([read_fd], [], [], 0.3)
        assert not ready, "fresh process entered through a substituted lock pair"
        os.unlink(lock)
        os.unlink(sidecar)
        os.rename(held_lock, lock)
        os.rename(held_sidecar, sidecar)
    report = os.read(read_fd, 128).decode()
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert report == "ENTERED"
    assert marker.exists(), "competitor never progressed after the exact owner released"


def test_whole_recon_substitution_cannot_create_concurrent_fresh_process_entrant(tmp_path):
    run = _running_run(tmp_path, "recon-substitution")
    recon = tmp_path / "recon"
    displaced = tmp_path / "displaced-recon"
    replacement = tmp_path / "replacement-recon"
    shutil.copytree(recon, replacement)
    marker = tmp_path / "recon-process-entered"

    with pytest.raises(ContractError, match="identity changed"):
        with run._mutation(store.MutationScope.CONTROL):
            os.rename(recon, displaced)
            os.rename(replacement, recon)
            read_fd, write_fd = os.pipe()
            child_pid = os.fork()
            if child_pid == 0:  # pragma: no cover - parent asserts the exact child report
                os.close(read_fd)
                try:
                    for inherited in os.listdir("/proc/self/fd"):
                        inherited_fd = int(inherited)
                        if inherited_fd not in {0, 1, 2, write_fd}:
                            try:
                                os.close(inherited_fd)
                            except OSError:
                                pass
                    store._RUN_LOCK_LOCAL.held = {}
                    child_run = store.Run.open(tmp_path, "acme.example", run.run_id)
                    try:
                        with child_run._mutation(store.MutationScope.CONTROL):
                            marker.write_text("entered")
                    except BaseException as exc:
                        os.write(write_fd, type(exc).__name__.encode())
                    else:
                        os.write(write_fd, b"ENTERED")
                finally:
                    os.close(write_fd)
                os._exit(0)
            os.close(write_fd)
            ready, _, _ = select.select([read_fd], [], [], 0.3)
            assert not ready, "fresh process entered through a substituted recon tree"
            assert not marker.exists()

    report = os.read(read_fd, 128).decode()
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert report in {"ENTERED", "ContractError"}
    assert marker.exists() is (report == "ENTERED")


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation",
    [store.Run._mutation.__wrapped__, store._RunMutationOwner.acquire,
     store._RunMutationOwner.settle],
)
def test_mutation_owner_source_line_cancellation_is_exact_and_settled(
    tmp_path, cancellation_type, operation,
):
    discovery = _running_run(tmp_path / "discovery", "discovery")

    def invoke(run):
        if operation is store.Run._mutation.__wrapped__:
            with run._mutation(store.MutationScope.CONTROL):
                pass
        else:
            _owner_acquire(store._RunMutationOwner(run))

    lines = _executed_lines(operation, lambda: invoke(discovery))
    assert lines
    for index, target_line in enumerate(sorted(lines)):
        run = _running_run(tmp_path / f"case-{index}", f"case-{index}")
        before_fds = _open_fds()
        _cancel_once(
            operation, target_line, lambda run=run: invoke(run), cancellation_type,
        )
        assert _open_fds() == before_fds, f"source line {target_line}"
        held = getattr(store._RUN_LOCK_LOCAL, "held", {})
        assert run._authority_key not in held, f"source line {target_line}"
        assert _lock_is_available(run), f"source line {target_line}"
        with run._mutation(store.MutationScope.CONTROL):
            pass


def test_body_cancellation_precedes_unlock_fault_and_leaves_no_stale_depth(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "cleanup-precedence")
    cancellation = KeyboardInterrupt("exact mutation cancellation")
    real_flock = fcntl.flock

    def fail_unlock(fd, operation):
        if operation == fcntl.LOCK_UN:
            raise OSError("synthetic unlock failure")
        return real_flock(fd, operation)

    monkeypatch.setattr(store.fcntl, "flock", fail_unlock)
    with pytest.raises(KeyboardInterrupt) as caught:
        with run._mutation(store.MutationScope.CONTROL):
            raise cancellation
    assert caught.value is cancellation
    assert run._authority_key not in getattr(store._RUN_LOCK_LOCAL, "held", {})


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_bootstrap_source_line_cancellation_leaves_valid_or_cleanly_retryable_authority(
    tmp_path, cancellation_type,
):
    discovery = _uninitialized_run(tmp_path / "discovery", "discovery")
    operation = store._RunMutationOwner.acquire
    lines = _executed_lines(operation, discovery._initialize_mutation_authority)
    assert lines

    for index, target_line in enumerate(sorted(lines)):
        run = _uninitialized_run(tmp_path / f"bootstrap-{index}", f"bootstrap-{index}")
        before_fds = _open_fds()
        _cancel_once(
            operation, target_line, run._initialize_mutation_authority,
            cancellation_type,
        )
        assert _open_fds() == before_fds, f"source line {target_line}"
        creation = json.loads(run.meta_path.read_text())
        lock_exists = run._lock_path.exists()
        sidecar_exists = run._lock_path.with_name(
            f"{run.run_id}.lock.identity",
        ).exists()
        witnessed = isinstance(creation.get("mutation_lock"), dict)
        assert len({lock_exists, sidecar_exists, witnessed}) == 1, target_line
        if not witnessed:
            run._initialize_mutation_authority()
        with run._mutation(store.MutationScope.CONTROL):
            pass
        assert _lock_is_available(run)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_full_create_source_line_cancellation_never_exposes_a_poisoned_run(
    tmp_path, cancellation_type,
):
    operation = store.Run.create.__func__
    discovery = tmp_path / "discovery"
    lines = _executed_lines(
        operation,
        lambda: store.Run.create(discovery, "acme.example", run_id="discovery"),
    )
    assert lines

    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"create-{cancellation_type.__name__}-{index}"
        before_fds = _open_fds()
        _cancel_once(
            operation, target_line,
            lambda project=project: store.Run.create(
                project, "acme.example", run_id="candidate",
            ),
            cancellation_type,
        )
        assert _open_fds() == before_fds, f"source line {target_line}"
        assert not getattr(store._RUN_LOCK_LOCAL, "held", {}), target_line
        assert not getattr(store._RUN_LOCK_LOCAL, "projects", {}), target_line

        listed = store.Run.list_runs(project) if project.exists() else []
        try:
            opened = store.Run.open(project, "acme.example", "candidate")
        except (FileNotFoundError, ContractError):
            opened = None
        if opened is not None:
            assert listed == [opened.dir], target_line
            assert not (opened.dir / ".creation-pending").exists(), target_line
            with opened._mutation(store.MutationScope.CONTROL):
                pass
        else:
            assert listed == [], target_line
        later = store.Run.create(
            project, "acme.example", run_id=f"later-{index}",
        )
        with later._mutation(store.MutationScope.CONTROL):
            pass


def test_run_create_name_swap_never_writes_replacement(tmp_path, monkeypatch):
    project = tmp_path / "project"
    displaced = tmp_path / "displaced"
    replacement_before = (("sentinel", b"replacement"),)
    real_bootstrap = store._bootstrap_run_tree

    def swap_after_pinned_bootstrap(anchor, identity):
        real_bootstrap(anchor, identity)
        os.rename(project / "recon" / "swapped", displaced)
        (project / "recon" / "swapped").mkdir(mode=0o700)
        (project / "recon" / "swapped" / "sentinel").write_bytes(b"replacement")

    monkeypatch.setattr(store, "_bootstrap_run_tree", swap_after_pinned_bootstrap)
    with pytest.raises(ContractError, match="identity changed|substituted"):
        store.Run.create(project, "acme.example", run_id="swapped")

    assert _tree_bytes(project / "recon" / "swapped") == replacement_before


def test_recon_swap_during_create_never_writes_replacement(tmp_path, monkeypatch):
    project = tmp_path / "project"
    displaced = tmp_path / "displaced-recon"
    real_bootstrap = store._bootstrap_run_tree

    def swap_recon_after_pinned_bootstrap(anchor, identity):
        real_bootstrap(anchor, identity)
        os.rename(project / "recon", displaced)
        (project / "recon" / "created").mkdir(parents=True, mode=0o700)
        (project / "recon" / "created" / "sentinel").write_bytes(b"replacement")

    monkeypatch.setattr(store, "_bootstrap_run_tree", swap_recon_after_pinned_bootstrap)
    with pytest.raises(ContractError, match="identity changed"):
        store.Run.create(project, "acme.example", run_id="created")

    assert _tree_bytes(project / "recon" / "created") == (("sentinel", b"replacement"),)


@pytest.mark.parametrize("selector", ["open", "latest"])
def test_read_identity_handoff_refuses_run_inode_swap(tmp_path, monkeypatch, selector):
    run = _running_run(tmp_path, f"handoff-{selector}")
    displaced = tmp_path / f"displaced-{selector}"
    replacement = tmp_path / f"replacement-{selector}"
    shutil.copytree(run.dir, replacement)
    before = _tree_bytes(replacement)

    if selector == "open":
        original = store._run_identity_from_fd

        def swap_after_read(fd, run_id):
            result = original(fd, run_id)
            if not displaced.exists():
                os.rename(run.dir, displaced)
                os.rename(replacement, run.dir)
            return result

        monkeypatch.setattr(store, "_run_identity_from_fd", swap_after_read)
        call = lambda: store.Run.open(tmp_path, "acme.example", run.run_id)
    else:
        original = store._run_snapshots

        def swap_after_snapshot(project):
            result = original(project)
            os.rename(run.dir, displaced)
            os.rename(replacement, run.dir)
            return result

        monkeypatch.setattr(store, "_run_snapshots", swap_after_snapshot)
        call = lambda: store.Run.latest(tmp_path)

    with pytest.raises(ContractError, match="identity changed"):
        call()
    assert _tree_bytes(run.dir) == before


@pytest.mark.parametrize("operation", [store._run_snapshots, store._snapshot_one_run])
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_run_enumeration_source_lines_close_all_descriptors(
    tmp_path, operation, cancellation_type,
):
    project = tmp_path / "project"
    run = _running_run(project, "enumerated")

    if operation is store._run_snapshots:
        invoke = lambda: store._run_snapshots(project)
        cleanup = lambda: None
    else:
        root = store._OwnedDescriptor()
        root.open(project / "recon", store._DIR_OPEN_FLAGS)
        invoke = lambda: store._snapshot_one_run(project / "recon", run.run_id, root)
        cleanup = lambda: store._settle_descriptor_owners((root,), "test root descriptor")

    try:
        lines = _executed_lines(operation, invoke)
        for target_line in sorted(lines):
            before_fds = _open_fds()
            _cancel_once(operation, target_line, invoke, cancellation_type)
            assert _open_fds() == before_fds, f"source line {target_line}"
    finally:
        cleanup()


def test_owner_aware_allocator_adopts_before_callback_fault(tmp_path):
    target = tmp_path / "owned"
    target.write_bytes(b"owned")
    os.chmod(target, 0o600)
    owner = store._OwnedDescriptor()
    cancellation = KeyboardInterrupt("after adoption")
    before = _open_fds()

    def open_then_cancel(destination):
        destination.adopt(os.open(target, os.O_RDONLY | os.O_NOFOLLOW))
        raise cancellation

    settlement = store._SettlementOwner(
        lambda: store._settle_descriptor_owners((owner,), "test descriptor"),
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        with store._SettlementFence(settlement):
            with store._SettlementFence(settlement):
                owner.allocate_into(open_then_cancel)
    assert caught.value is cancellation
    assert _open_fds() == before


def test_descriptor_reuse_sentinel_is_never_closed(tmp_path):
    first = tmp_path / "first"
    sentinel_path = tmp_path / "sentinel"
    first.write_bytes(b"first")
    sentinel_path.write_bytes(b"sentinel")
    owner = store._OwnedDescriptor()
    owner.open(first, os.O_RDONLY | os.O_NOFOLLOW)
    owned_fd = owner.fd
    os.close(owned_fd)
    source = os.open(sentinel_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if source != owned_fd:
            os.dup2(source, owned_fd)
        fault = owner.close_once()
        assert isinstance(fault, ContractError)
        assert os.fstat(owned_fd).st_ino == sentinel_path.stat().st_ino
    finally:
        os.close(source)
        if source != owned_fd:
            os.close(owned_fd)


def test_cross_project_opposing_nesting_refuses_without_deadlock(tmp_path):
    left = _running_run(tmp_path / "left", "left")
    right = _running_run(tmp_path / "right", "right")
    barrier = threading.Barrier(2)
    errors = []

    def oppose(first, second):
        try:
            with first._mutation(store.MutationScope.CONTROL):
                barrier.wait(timeout=5)
                with second._mutation(store.MutationScope.CONTROL):
                    pytest.fail("cross-project nesting entered")
        except ContractError as exc:
            errors.append(exc)

    threads = (
        threading.Thread(target=oppose, args=(left, right)),
        threading.Thread(target=oppose, args=(right, left)),
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert len(errors) == 2


def test_different_runs_in_one_project_serialize_on_parent_guard(tmp_path):
    left = _running_run(tmp_path, "project-left")
    right = _running_run(tmp_path, "project-right")
    entered = threading.Event()
    release = threading.Event()
    second_entered = threading.Event()

    def first():
        with left._mutation(store.MutationScope.CONTROL):
            entered.set()
            assert release.wait(5)

    def second():
        assert entered.wait(5)
        with right._mutation(store.MutationScope.CONTROL):
            second_entered.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    second_thread.start()
    assert entered.wait(5)
    assert not second_entered.wait(0.2)
    release.set()
    first_thread.join(5)
    second_thread.join(5)
    assert not first_thread.is_alive() and not second_thread.is_alive()
    assert second_entered.is_set()


def test_claim_registry_substitution_cannot_hide_live_claim(tmp_path):
    run = _running_run(tmp_path, "claim-registry-swap")
    claim = run.artifact_claim()
    claim.__enter__()
    claims = tmp_path / "recon" / "state" / "claims"
    displaced = tmp_path / "displaced-claims"
    os.rename(claims, displaced)
    (claims / run.run_id).mkdir(parents=True, mode=0o700)
    try:
        with pytest.raises(ContractError, match="claims|witness|identity changed"):
            store.Run.open(tmp_path, run.target, run.run_id).begin_finalization()
        assert run.state == "running"
        assert list((displaced / run.run_id).glob("*.claim"))
        assert not list((claims / run.run_id).glob("*.claim"))
    finally:
        shutil.rmtree(claims)
        os.rename(displaced, claims)
        claim.__exit__(None, None, None)


def test_history_name_swap_refuses_split_publication(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "history-swap")
    state = tmp_path / "recon" / "state"
    displaced = tmp_path / "displaced-history"
    original = store._ProjectStatePublisher._validate
    swapped = False

    def swap_before_validation(publisher):
        nonlocal swapped
        if not swapped:
            swapped = True
            os.rename(state / "history", displaced)
            (state / "history").mkdir(mode=0o700)
        return original(publisher)

    monkeypatch.setattr(store._ProjectStatePublisher, "_validate", swap_before_validation)
    with pytest.raises(ContractError, match="history directory changed"):
        run.write_manifest({}, [])

    assert swapped
    assert not list((state / "history").glob("*.json"))
    assert (displaced / f"{run.run_id}.json").exists()
    assert not (state / "current.txt").exists()


def _append_normalized(run, data: bytes) -> None:
    with run._mutation(store.MutationScope.BASE_EVIDENCE):
        owner = store._CanonicalLogAppendOwner(
            run, ("normalized", "ip.jsonl"), data,
        )
        settlement = store._SettlementOwner(owner.settle)
        with store._SettlementFence(settlement):
            with store._SettlementFence(settlement):
                owner.execute()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation",
    [store._CanonicalLogAppendOwner.execute,
     store._CanonicalLogAppendOwner._reconcile,
     store._CanonicalLogAppendOwner.settle],
)
@pytest.mark.parametrize("seeded", [False, True])
def test_normalized_journal_source_lines_leave_absent_prior_or_one_full_row(
    tmp_path, cancellation_type, operation, seeded,
):
    row = b'{"ip":"192.0.2.90"}\n'
    discovery = _running_run(tmp_path / "discovery", "journal-discovery")
    if seeded:
        _append_normalized(discovery, b'{"ip":"192.0.2.1"}\n')
    lines = _executed_lines(operation, lambda: _append_normalized(discovery, row))

    for index, target_line in enumerate(sorted(lines)):
        run = _running_run(
            tmp_path / f"journal-{operation.__name__}-{seeded}-{index}",
            f"journal-{index}",
        )
        path = run.normalized / "ip.jsonl"
        prior = b'{"ip":"192.0.2.1"}\n' if seeded else b""
        if seeded:
            _append_normalized(run, prior)
        before_fds = _open_fds()
        _cancel_once(
            operation, target_line, lambda: _append_normalized(run, row),
            cancellation_type,
        )
        assert _open_fds() == before_fds, target_line
        observed = path.read_bytes() if path.exists() else b""
        assert observed in {prior, prior + row}, (target_line, observed)
        assert not path.exists() or observed, target_line
        with run._mutation(store.MutationScope.CONTROL):
            pass


def test_normalized_journal_short_write_completes_exact_row(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "journal-short-write")
    row = b'{"ip":"192.0.2.91"}\n'
    real_write = store.os.write

    def short_write(fd, data):
        target = ""
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            pass
        if target.endswith("normalized/ip.jsonl") and len(data) > 2:
            data = memoryview(data)[:2]
        return real_write(fd, data)

    monkeypatch.setattr(store.os, "write", short_write)
    _append_normalized(run, row)
    assert (run.normalized / "ip.jsonl").read_bytes() == row


@pytest.mark.parametrize("fault", ["write", "fsync", "close"])
def test_normalized_journal_fault_rolls_back_exact_prior(tmp_path, monkeypatch, fault):
    run = _running_run(tmp_path, f"journal-{fault}-fault")
    prior = b'{"ip":"192.0.2.1"}\n'
    row = b'{"ip":"192.0.2.92"}\n'
    _append_normalized(run, prior)
    path = run.normalized / "ip.jsonl"
    fired = False

    if fault == "write":
        original = store.os.write

        def fail(fd, data):
            nonlocal fired
            target = os.readlink(f"/proc/self/fd/{fd}")
            if target == str(path) and not fired:
                fired = True
                original(fd, memoryview(data)[:3])
                raise OSError("journal write fault")
            return original(fd, data)

        monkeypatch.setattr(store.os, "write", fail)
    elif fault == "fsync":
        original = store.os.fsync

        def fail(fd):
            nonlocal fired
            target = os.readlink(f"/proc/self/fd/{fd}")
            if target == str(path) and not fired:
                fired = True
                raise OSError("journal fsync fault")
            return original(fd)

        monkeypatch.setattr(store.os, "fsync", fail)
    else:
        original = store.os.close

        def fail(fd):
            nonlocal fired
            target = ""
            try:
                target = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                pass
            if target == str(path) and not fired:
                fired = True
                raise OSError("journal close fault")
            return original(fd)

        monkeypatch.setattr(store.os, "close", fail)

    with pytest.raises(OSError, match=f"journal {fault} fault"):
        _append_normalized(run, row)
    assert fired
    if fault == "close":
        assert path.read_bytes() == prior + row
    else:
        assert path.read_bytes() == prior


def test_normalized_journal_run_swap_never_touches_replacement(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "journal-run-swap")
    displaced = tmp_path / "journal-displaced"
    replacement = tmp_path / "journal-replacement"
    shutil.copytree(run.dir, replacement)
    before = _tree_bytes(replacement)
    original = store._CanonicalLogAppendOwner._validate_file
    swapped = False

    def swap_after_open(owner):
        nonlocal swapped
        original(owner)
        if not swapped:
            swapped = True
            os.rename(run.dir, displaced)
            os.rename(replacement, run.dir)

    monkeypatch.setattr(store._CanonicalLogAppendOwner, "_validate_file", swap_after_open)
    with pytest.raises(ContractError, match="identity changed"):
        _append_normalized(run, b'{"ip":"192.0.2.93"}\n')
    assert _tree_bytes(run.dir) == before


@pytest.mark.parametrize(
    "suffix",
    [b'{"ip":', b'{"ip":"192.0.2.94"}', b'{"ip":"192.0.2.94","x":"\xf0\x9f'],
)
def test_torn_normalized_suffix_is_degraded_and_gaps_verdict(tmp_path, suffix):
    run = _running_run(tmp_path, "torn-normalized")
    _append_normalized(run, b'{"ip":"192.0.2.1"}\n')
    with open(run.normalized / "ip.jsonl", "ab") as stream:
        stream.write(suffix)

    reopened = store.Run.open(tmp_path, run.target, run.run_id)
    folded = reopened.read_folded("ip")
    assert folded.status == "degraded"
    assert folded.dropped == 1
    summary = reopened.summary()
    assert summary["verdict"] == "complete_with_gaps"
    assert any(gap["tool"] == "normalized:ip" for gap in summary["gaps"])


@pytest.mark.parametrize("suffix", [b'{"ip":"192.0.2.95"}', b'{"ip":"\xf0\x9f'])
def test_append_refuses_existing_torn_suffix_without_losing_new_row(tmp_path, suffix):
    run = _running_run(tmp_path, "append-after-torn")
    path = run.normalized / "ip.jsonl"
    _append_normalized(run, b'{"ip":"192.0.2.1"}\n')
    with open(path, "ab") as stream:
        stream.write(suffix)
    before = path.read_bytes()

    reopened = store.Run.open(tmp_path, run.target, run.run_id)
    with pytest.raises(ContractError, match="torn suffix"):
        reopened.add("ip", {"ip": "192.0.2.96"})

    assert path.read_bytes() == before
    assert reopened.read_folded("ip").status == "degraded"


def _normalized_process_writer(project, run_id, prefix, ready, release, output):
    try:
        run = store.Run.open(project, "acme.example", run_id)
        ready.put(prefix)
        if not release.wait(10):
            raise RuntimeError("normalized writer was not released")
        for index in range(8):
            run.add("ip", {"ip": f"192.0.{prefix}.{index + 1}"})
    except BaseException as exc:
        output.put(f"{type(exc).__name__}: {exc}")
    else:
        output.put("")


def test_normalized_journal_cross_process_writers_lose_no_rows(tmp_path):
    run = _running_run(tmp_path, "normalized-processes")
    context = multiprocessing.get_context("fork")
    ready = context.Queue()
    release = context.Event()
    output = context.Queue()
    processes = [
        context.Process(
            target=_normalized_process_writer,
            args=(tmp_path, run.run_id, prefix, ready, release, output),
        )
        for prefix in (1, 2)
    ]
    for process in processes:
        process.start()
    assert {ready.get(timeout=10), ready.get(timeout=10)} == {1, 2}
    release.set()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert sorted((output.get(timeout=5), output.get(timeout=5))) == ["", ""]

    reopened = store.Run.open(tmp_path, run.target, run.run_id)
    assert set(reopened.values("ip")) == {
        f"192.0.{prefix}.{index + 1}"
        for prefix in (1, 2) for index in range(8)
    }


def test_fork_child_read_discards_inherited_mutation_ledger(tmp_path):
    run = _running_run(tmp_path, "fork-read-ledger")
    read_fd, write_fd = os.pipe()
    with run._mutation(store.MutationScope.CONTROL):
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - parent asserts the exact report
            os.close(read_fd)
            try:
                inherited = getattr(store._RUN_LOCK_LOCAL, "held", {})
                for entry in inherited.values():
                    for owner in entry.owner.descriptor_owners:
                        if owner.fd >= 0:
                            try:
                                os.close(owner.fd)
                            except OSError:
                                pass
                try:
                    opened = store.Run.open(tmp_path, run.target, run.run_id)
                    result = opened.state
                except BaseException as exc:
                    result = f"{type(exc).__name__}: {exc}"
                os.write(write_fd, result.encode())
            finally:
                os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
    report = os.read(read_fd, 1024).decode()
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert report == "running"


@pytest.mark.parametrize(
    ("helper", "components"),
    [
        (store._open_strict_directory_into, ("a", "b", "c")),
        (store._open_strict_file_into, ("a", "b", "row.json")),
    ],
)
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_strict_owner_helpers_settle_every_source_line(
    tmp_path, helper, components, cancellation_type,
):
    root = tmp_path / "root"
    (root / "a" / "b" / "c").mkdir(parents=True, mode=0o700)
    (root / "a" / "b" / "row.json").write_bytes(b"{}")
    os.chmod(root / "a", 0o700)
    os.chmod(root / "a" / "b", 0o700)
    os.chmod(root / "a" / "b" / "c", 0o700)
    os.chmod(root / "a" / "b" / "row.json", 0o600)
    anchor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def invoke():
        destination = store._OwnedDescriptor()
        settlement = store._SettlementOwner(
            lambda: store._settle_descriptor_owners(
                (destination,), "strict helper test descriptor",
            ),
        )
        with store._SettlementFence(settlement):
            with store._SettlementFence(settlement):
                helper(destination, anchor, components)

    try:
        lines = _executed_lines(helper, invoke)
        for line in sorted(lines):
            before = _open_fds()
            _cancel_once(helper, line, invoke, cancellation_type)
            assert _open_fds() == before, line
    finally:
        os.close(anchor)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_strict_helper_open_then_raise_is_owned(tmp_path, monkeypatch, cancellation_type):
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True, mode=0o700)
    os.chmod(root / "a", 0o700)
    anchor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    before = _open_fds()
    exact = cancellation_type("committed strict open")
    real_open = store._OwnedDescriptor.open
    fired = False

    def committed_then_raise(owner, *args, **kwargs):
        nonlocal fired
        result = real_open(owner, *args, **kwargs)
        if not fired and args[0] == "a":
            fired = True
            raise exact
        return result

    monkeypatch.setattr(store._OwnedDescriptor, "open", committed_then_raise)
    destination = store._OwnedDescriptor()
    with pytest.raises(cancellation_type) as caught:
        store._open_strict_directory_into(destination, anchor, ("a",))
    os.close(anchor)
    assert caught.value is exact
    assert fired
    assert len(_open_fds()) == len(before) - 1


def test_manifest_presence_conservatively_seals_base(tmp_path):
    run = _running_run(tmp_path, "manifest-seal")
    run.manifest_path.write_bytes(b"{")
    before = run.manifest_path.read_bytes()
    with pytest.raises(ContractError, match="sealed"):
        run.add("ip", {"ip": "192.0.2.201"})
    state_before = run.state_path.read_bytes()
    with pytest.raises(ContractError, match="sealed"):
        run.begin_finalization(profile_summary={}, phases_run=["fixture"])
    assert run.manifest_path.read_bytes() == before
    assert run.state_path.read_bytes() == state_before
    assert not (run.normalized / "ip.jsonl").exists()


def test_write_manifest_crosses_finalization_seal(tmp_path):
    run = _running_run(tmp_path, "manifest-workflow")
    run.write_manifest({}, ["fixture"])
    assert run.state == "finalizing"
    assert run.manifest_path.exists()
    with pytest.raises(ContractError, match="sealed"):
        run.add("ip", {"ip": "192.0.2.202"})


def test_sealed_manifest_rebuild_does_not_create_base_degradation_marker(tmp_path):
    run = _running_run(tmp_path, "sealed-damaged-ledger")
    refused = run.dir / "envelope-refused.jsonl"
    refused.write_bytes(b"not-json\n")
    os.chmod(refused, 0o600)
    run.begin_finalization()
    assert not run._degraded_path.exists()
    run.write_manifest({}, ["fixture"])
    assert not run._degraded_path.exists()
    manifest = json.loads(run.manifest_path.read_text())
    assert manifest["summary"]["verdict"] != "complete"


def test_preexisting_claim_registry_poison_refuses_new_run(tmp_path):
    first = store.Run.create(tmp_path, "acme.example", run_id="claim-root")
    poison = tmp_path / "recon" / "state" / "claims" / "poisoned"
    poison.mkdir(mode=0o700)
    marker = poison / ("a" * 32 + ".claim")
    marker.write_bytes(b"planted")
    os.chmod(marker, 0o600)
    before = _tree_bytes(poison)
    with pytest.raises(ContractError, match="claim registry already exists"):
        store.Run.create(tmp_path, "acme.example", run_id="poisoned")
    assert _tree_bytes(poison) == before
    assert [path.name for path in store.Run.list_runs(tmp_path)] == [first.run_id]


def test_empty_preexisting_claim_registry_is_never_adopted_or_removed(tmp_path):
    first = store.Run.create(tmp_path, "acme.example", run_id="claim-root-empty")
    poison = tmp_path / "recon" / "state" / "claims" / "empty-poison"
    poison.mkdir(mode=0o700)
    identity = poison.stat().st_dev, poison.stat().st_ino
    with pytest.raises(ContractError, match="claim registry already exists"):
        store.Run.create(tmp_path, "acme.example", run_id="empty-poison")
    observed = poison.stat()
    assert (observed.st_dev, observed.st_ino) == identity
    assert [path.name for path in store.Run.list_runs(tmp_path)] == [first.run_id]


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_preexisting_empty_claim_registry_survives_every_acquire_line(
    tmp_path, cancellation_type,
):
    store.Run.create(tmp_path, "acme.example", run_id="claim-seed")
    discovery_project = tmp_path / "discovery-existing-registry"
    store.Run.create(discovery_project, "acme.example", run_id="seed")
    discovery = _uninitialized_run(discovery_project, "candidate")
    discovery_registry = discovery_project / "recon" / "state" / "claims" / "candidate"
    discovery_registry.mkdir(mode=0o700)
    lines = set()

    def trace(frame, event, _arg):
        if frame.f_code is store._RunMutationOwner.acquire.__code__ and event == "line":
            lines.add(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(ContractError):
            discovery._initialize_mutation_authority()
    finally:
        sys.settrace(previous)

    for index, line in enumerate(sorted(lines)):
        project = tmp_path / f"existing-registry-{index}"
        store.Run.create(project, "acme.example", run_id="seed")
        candidate = _uninitialized_run(project, "candidate")
        registry = project / "recon" / "state" / "claims" / "candidate"
        registry.mkdir(mode=0o700)
        before = registry.stat().st_dev, registry.stat().st_ino
        _cancel_once(
            store._RunMutationOwner.acquire, line,
            candidate._initialize_mutation_authority, cancellation_type,
        )
        observed = registry.stat()
        assert (observed.st_dev, observed.st_ino) == before, line


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_claim_registry_helper_return_boundary_is_retryable(
    tmp_path, cancellation_type,
):
    store.Run.create(tmp_path, "acme.example", run_id="claim-helper-seed")
    candidate = _uninitialized_run(tmp_path, "claim-helper-candidate")
    helper = store._claim_private_directory_into
    lines = set()

    def discover(frame, event, _arg):
        if frame.f_code is helper.__code__ and event == "line":
            lines.add(frame.f_lineno)
        return discover

    owner = store._RunMutationOwner(candidate, initializing=True)
    claims_fd = os.open(
        tmp_path / "recon" / "state" / "claims",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    previous = sys.gettrace()
    try:
        sys.settrace(discover)
        helper(owner, claims_fd, candidate.run_id, privfs.DIR_MODE)
    finally:
        sys.settrace(previous)
        os.close(claims_fd)
    shutil.rmtree(tmp_path / "recon" / "state" / "claims" / candidate.run_id)

    for line in sorted(lines):
        registry = tmp_path / "recon" / "state" / "claims" / candidate.run_id
        owner = store._RunMutationOwner(candidate, initializing=True)
        claims_fd = os.open(
            registry.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        cancellation = cancellation_type(f"claim helper cancellation at {line}")
        fired = False

        def trace(frame, event, _arg):
            nonlocal fired
            if (frame.f_code is helper.__code__ and event == "line"
                    and frame.f_lineno == line and not fired):
                fired = True
                sys.settrace(None)
                raise cancellation
            return trace

        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                helper(owner, claims_fd, candidate.run_id, privfs.DIR_MODE)
        finally:
            sys.settrace(previous)
            os.close(claims_fd)
        assert caught.value is cancellation and fired
        staged = list(registry.parent.glob(".quarry-claim-*.stage"))
        if registry.exists():
            if owner.claim_registry_possible:
                registry.rmdir()
            else:
                # The helper was interrupted before the mkdir; the only other
                # permitted state is an untouched preexisting name.
                pytest.fail(f"created registry was not adopted at source line {line}")
        for path in staged:
            if owner.claim_registry_possible:
                path.rmdir()
            else:
                pytest.fail(f"staged registry was not adopted at source line {line}")


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_claim_registry_helper_lines_settle_through_run_create(
    tmp_path, cancellation_type,
):
    discovery = tmp_path / "claim-helper-discovery"
    store.Run.create(discovery, "acme.example", run_id="seed")
    lines = set()
    helper = store._claim_private_directory_into

    def trace(frame, event, _arg):
        if frame.f_code is helper.__code__ and event == "line":
            lines.add(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        store.Run.create(discovery, "acme.example", run_id="candidate")
    finally:
        sys.settrace(previous)

    for index, line in enumerate(sorted(lines)):
        project = tmp_path / f"claim-helper-create-{index}"
        store.Run.create(project, "acme.example", run_id="seed")
        _cancel_once(
            helper, line,
            lambda: store.Run.create(
                project, "acme.example", run_id="candidate",
            ),
            cancellation_type,
        )
        claims = project / "recon" / "state" / "claims"
        assert sorted(path.name for path in claims.iterdir()) == ["seed"], line


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("existing", [False, True])
def test_private_directory_publication_settles_every_source_line(
    tmp_path, cancellation_type, existing,
):
    root = tmp_path / "directory-publish"
    root.mkdir(mode=0o700)
    if existing:
        (root / "target").mkdir(mode=0o700)
        (root / "target" / "sentinel").write_bytes(b"existing")
        os.chmod(root / "target" / "sentinel", 0o600)
    parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    helper = store._publish_private_directory_into

    def invoke(name):
        destination = store._OwnedDescriptor()
        settlement = store._SettlementOwner(
            lambda: store._settle_descriptor_owners(
                (destination,), "directory publication test descriptor",
            ),
        )
        with store._SettlementFence(settlement):
            with store._SettlementFence(settlement):
                helper(destination, parent_fd, name, 0o700)

    discovery = "target" if existing else "discovery"
    lines = set()

    def trace(frame, event, _arg):
        if frame.f_code is helper.__code__ and event == "line":
            lines.add(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        invoke(discovery)
    finally:
        sys.settrace(previous)
    if not existing:
        (root / discovery).rmdir()

    try:
        for index, line in enumerate(sorted(lines)):
            name = "target" if existing else f"target-{index}"
            before = _tree_bytes(root / "target") if existing else ()
            _cancel_once(helper, line, lambda name=name: invoke(name), cancellation_type)
            assert not list(root.glob(".quarry-dir-*.stage")), line
            if existing:
                assert _tree_bytes(root / "target") == before, line
            elif (root / name).exists():
                (root / name).rmdir()
    finally:
        os.close(parent_fd)


def test_pre_epoch_history_substitution_refuses_fresh_run(tmp_path):
    first = _running_run(tmp_path, "history-first")
    first.write_manifest({}, ["fixture"])
    state = tmp_path / "recon" / "state"
    displaced = tmp_path / "history-displaced"
    os.rename(state / "history", displaced)
    (state / "history").mkdir(mode=0o700)
    with pytest.raises(ContractError, match="shared authority|history"):
        store.Run.create(tmp_path, "acme.example", run_id="history-second")
    assert not (tmp_path / "recon" / "history-second").exists()
    assert not list((state / "history").iterdir())
    assert (displaced / f"{first.run_id}.json").exists()


def test_preplanted_shared_authority_without_run_witness_is_refused(tmp_path):
    state = tmp_path / "recon" / "state"
    locks = state / "locks"
    claims = state / "claims"
    history = state / "history"
    for directory in (locks, claims, history):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
    os.chmod(tmp_path / "recon", 0o700)
    os.chmod(state, 0o700)
    planted = history / "planted.json"
    planted.write_bytes(b"sentinel")
    os.chmod(planted, 0o600)
    payload = {
        "schema_version": 1,
        "state_device": state.stat().st_dev,
        "state_inode": state.stat().st_ino,
        "locks_device": locks.stat().st_dev,
        "locks_inode": locks.stat().st_ino,
        "claims_device": claims.stat().st_dev,
        "claims_inode": claims.stat().st_ino,
        "history_device": history.stat().st_dev,
        "history_inode": history.stat().st_ino,
    }
    authority = state / "authority.identity"
    authority.write_text(json.dumps(payload, sort_keys=True))
    os.chmod(authority, 0o600)
    before = _tree_bytes(state)
    with pytest.raises(ContractError, match="creation-bound Run witness"):
        store.Run.create(tmp_path, "acme.example", run_id="candidate")
    assert _tree_bytes(state) == before
    assert store.Run.list_runs(tmp_path) == []


@pytest.mark.parametrize("planted_name", ["state", "locks", "claims", "history"])
def test_preplanted_shared_directory_without_witness_is_refused(tmp_path, planted_name):
    recon = tmp_path / "recon"
    state = recon / "state"
    if planted_name == "state":
        planted = state
    else:
        planted = state / planted_name
    planted.mkdir(parents=True, mode=0o700)
    for parent in (recon, state, planted):
        if parent.exists():
            os.chmod(parent, 0o700)
    sentinel = planted / "sentinel"
    sentinel.write_bytes(b"planted")
    os.chmod(sentinel, 0o600)
    before = _tree_bytes(planted)
    with pytest.raises(ContractError, match="planted before bootstrap"):
        store.Run.create(tmp_path, "acme.example", run_id="candidate")
    assert _tree_bytes(planted) == before
    assert store.Run.list_runs(tmp_path) == []


def test_legacy_run_remains_readable_but_mutation_refuses(tmp_path):
    run = _uninitialized_run(tmp_path, "legacy-readable")
    before = _tree_bytes(run.dir)
    reopened = store.Run.open(tmp_path, run.target, run.run_id)
    assert reopened.started == run.started
    with pytest.raises(ContractError):
        reopened.write_state("running")
    assert _tree_bytes(run.dir) == before


def _fork_after_worker_holds_local_lock(tmp_path, lock, run_id):
    held = threading.Event()
    release = threading.Event()

    def worker():
        with lock:
            held.set()
            assert release.wait(10)

    thread = threading.Thread(target=worker)
    thread.start()
    assert held.wait(5)
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - parent verifies child report
        os.close(read_fd)
        try:
            try:
                opened = store.Run.open(tmp_path, "acme.example", run_id)
                opened.write_state("running")
                result = "running"
            except BaseException as exc:
                result = f"{type(exc).__name__}: {exc}"
            os.write(write_fd, result.encode())
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    ready, _, _ = select.select([read_fd], [], [], 5)
    release.set()
    thread.join(timeout=5)
    assert ready, "child inherited a permanently locked process-local mutex"
    report = os.read(read_fd, 1024).decode()
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert report == "running"


@pytest.mark.parametrize("kind", ["project", "run"])
def test_fork_resets_worker_owned_process_local_locks(tmp_path, kind):
    run = store.Run.create(tmp_path, "acme.example", run_id=f"fork-{kind}")
    if kind == "project":
        lock = store._shared_project_lock(str(tmp_path.resolve()))
    else:
        lock = store._shared_run_lock(run._authority_key)
    _fork_after_worker_holds_local_lock(tmp_path, lock, run.run_id)
