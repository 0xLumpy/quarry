"""Phase 1, step 6a: one authority serializes base mutation and the irreversible seal.

These tests deliberately describe the repository boundary before its implementation.  They keep
``Run.open`` read-only, put coordination outside canonical run evidence, and exercise both halves of
the per-run lock: a shared/reentrant process lock and an advisory inter-process lock.
"""
from __future__ import annotations

import enum
import fcntl
import json
import os
import select
import stat
import threading
from types import SimpleNamespace

import pytest

from quarry_recon import store
from quarry_recon.state import ContractError, Fault, Gap


pytestmark = pytest.mark.offline

STARTED = "2026-08-13T10:20:30+00:00"


def _running_run(project, run_id="authority"):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _tree_snapshot(root):
    """Content/metadata snapshot which deliberately ignores read-only atime changes."""
    root = root.resolve()
    if not root.exists():
        return None
    snapshot = []
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        kind = stat.S_IFMT(info.st_mode)
        payload = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        link = os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
        snapshot.append((str(path.relative_to(root)), kind, stat.S_IMODE(info.st_mode), info.st_ino,
                         info.st_size, info.st_mtime_ns, payload, link))
    return snapshot


def _required_method(obj, name):
    method = getattr(obj, name, None)
    assert callable(method), f"{type(obj).__name__}.{name}() is part of the Step 6a contract"
    return method


def _result_fixture():
    return SimpleNamespace(
        tool="fixture",
        status=SimpleNamespace(value="success"),
        exit_code=0,
        duration=0.01,
        stdout_lines=1,
        note="",
        cmd=("fixture",),
        stderr_tail="",
    )


def _mutate_base(run, operation):
    if operation == "raw_path":
        return run.raw_path("horizontal", "fixture", "stdout.bin")
    if operation == "record":
        return run.record("horizontal", _result_fixture())
    if operation == "commit_fault":
        return run.commit_fault(Fault("machinery", where="authority-test"))
    if operation == "commit_gap":
        return run.commit_gap(Gap(source_id="authority-test", kind="unknown"))
    if operation == "add":
        return run.add("subdomain", {"host": "late.acme.example", "source": "authority-test"})
    if operation == "inherit":
        return run.inherit("subdomain", {"host": "inherited.acme.example", "source": "authority-test"})
    raise AssertionError(operation)


def test_mutation_scope_is_the_closed_repository_vocabulary():
    mutation_scope = getattr(store, "MutationScope", None)
    assert isinstance(mutation_scope, type) and issubclass(mutation_scope, enum.Enum)
    assert {member.name: member.value for member in mutation_scope} == {
        "BASE_EVIDENCE": "base_evidence",
        "FINALIZATION_METADATA": "finalization_metadata",
        "REVISION": "revision",
        "CONTROL": "control",
    }


def test_run_open_does_not_materialize_the_lock_or_missing_run_directories(tmp_path):
    run_dir = tmp_path / "recon" / "legacy"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps({
        "run_id": "legacy", "target": "acme.example", "started": STARTED,
    }))
    before = _tree_snapshot(tmp_path)

    opened = store.Run.open(tmp_path, "acme.example", "legacy")

    assert opened.run_id == "legacy" and opened.started == STARTED
    assert _tree_snapshot(tmp_path) == before
    assert not (tmp_path / "recon" / "state" / "locks" / "legacy.lock").exists()
    for name in ("raw", "normalized", "exports", "reports"):
        assert not (run_dir / name).exists()


@pytest.mark.parametrize("lifecycle", ["finalizing", "finished", "finalization_failed"])
@pytest.mark.parametrize("operation", [
    "raw_path", "record", "commit_fault", "commit_gap", "add", "inherit",
])
def test_every_public_base_mutator_rejects_after_the_base_seal(tmp_path, lifecycle, operation):
    run = _running_run(tmp_path)
    # Materialize the authority and one canonical row while BASE_EVIDENCE is still eligible.  A later
    # refusal therefore cannot be confused with lazy creation of the out-of-band lock itself.
    assert run.add("subdomain", {"host": "seed.acme.example", "source": "authority-test"})
    run.write_state("finalizing")
    if lifecycle != "finalizing":
        run.write_state(lifecycle)
    reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
    before_tree = _tree_snapshot(tmp_path)
    before_memory = (tuple(reopened.tool_runs()), tuple(reopened._faults), tuple(reopened._gaps))

    with pytest.raises(ContractError):
        _mutate_base(reopened, operation)

    assert reopened.state == lifecycle
    assert _tree_snapshot(tmp_path) == before_tree
    assert (tuple(reopened.tool_runs()), tuple(reopened._faults), tuple(reopened._gaps)) == before_memory


def test_repository_lock_has_one_exact_private_out_of_band_path(tmp_path):
    run = _running_run(tmp_path)
    assert run.add("subdomain", {"host": "seed.acme.example", "source": "authority-test"})

    lock_dir = tmp_path / "recon" / "state" / "locks"
    lock_path = lock_dir / f"{run.run_id}.lock"
    assert lock_dir.is_dir() and not lock_dir.is_symlink()
    assert stat.S_IMODE(lock_dir.stat().st_mode) == 0o700
    assert lock_path.is_file() and not lock_path.is_symlink()
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_base_mutation_waits_for_the_interprocess_flock(tmp_path):
    run = _running_run(tmp_path)
    assert run.add("subdomain", {"host": "seed.acme.example", "source": "authority-test"})
    lock_path = tmp_path / "recon" / "state" / "locks" / f"{run.run_id}.lock"
    assert lock_path.is_file(), "a base mutation must materialize the exact per-run lock"

    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    holder_pid = os.fork()
    if holder_pid == 0:  # pragma: no cover - assertions and reporting stay in the parent
        os.close(ready_read)
        os.close(release_write)
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(ready_write, b"locked\n")
            os.read(release_read, 1)
            os.close(fd)
        except BaseException:
            os._exit(70)
        os._exit(0)
    os.close(ready_write)
    os.close(release_read)
    ready, _, _ = select.select([ready_read], [], [], 3)
    if not ready:
        os.write(release_write, b"x")
        os.close(release_write)
        os.close(ready_read)
        os.waitpid(holder_pid, 0)
        pytest.fail("the external lock holder did not become ready")
    line = os.read(ready_read, len(b"locked\n"))
    if line != b"locked\n":
        os.close(release_write)
        os.close(ready_read)
        _, status = os.waitpid(holder_pid, 0)
        pytest.fail(f"external lock holder failed with wait status {status}")

    finished = threading.Event()
    errors = []

    def append():
        try:
            reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
            assert reopened.add("ip", {"ip": "192.0.2.23", "source": "authority-test"})
        except BaseException as exc:  # assertions and implementation failures must return to the test thread
            errors.append(exc)
        finally:
            finished.set()

    worker = threading.Thread(target=append, daemon=True)
    worker.start()
    blocked = not finished.wait(0.25)
    try:
        os.write(release_write, b"x")
    finally:
        os.close(release_write)
        os.close(ready_read)
    _, holder_status = os.waitpid(holder_pid, 0)
    worker.join(timeout=3)

    assert blocked, "the append escaped while another process held the run's advisory lock"
    assert finished.is_set() and not errors
    assert os.waitstatus_to_exitcode(holder_status) == 0
    assert store.Run.open(tmp_path, "acme.example", run.run_id).count("ip") == 1


def test_process_local_run_lock_is_reentrant_across_two_handles(tmp_path, monkeypatch):
    run = _running_run(tmp_path, run_id="rlock")
    first = store.Run.open(tmp_path, "acme.example", run.run_id)
    second = store.Run.open(tmp_path, "acme.example", run.run_id)
    # Neutralize flock so a nested mutation can finish only when the process-local authority is reentrant.
    monkeypatch.setattr(fcntl, "flock", lambda *args, **kwargs: None)
    if hasattr(store, "flock"):
        monkeypatch.setattr(store, "flock", lambda *args, **kwargs: None)
    original_append = store.Run._append_line
    nested = False
    finished = threading.Event()
    errors = []

    def append_with_nested_mutation(self, entity, line):
        nonlocal nested
        if not nested:
            nested = True
            try:
                assert second.add("ip", {"ip": "192.0.2.24", "source": "nested"})
            finally:
                nested = False
        return original_append(self, entity, line)

    def append():
        try:
            assert first.add("subdomain", {"host": "nested.acme.example", "source": "outer"})
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    monkeypatch.setattr(store.Run, "_append_line", append_with_nested_mutation)
    worker = threading.Thread(target=append, daemon=True)
    worker.start()
    completed = finished.wait(2)
    worker.join(timeout=0 if not completed else 1)

    assert completed, "nested mutation deadlocked: the per-run process lock is not a shared RLock"
    assert not errors
    reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
    assert reopened.count("subdomain") == 1 and reopened.count("ip") == 1


def test_live_artifact_claim_makes_begin_finalization_refuse_without_transition(tmp_path):
    run = _running_run(tmp_path)
    claimer = store.Run.open(tmp_path, "acme.example", run.run_id)
    sealer = store.Run.open(tmp_path, "acme.example", run.run_id)
    artifact_claim = _required_method(claimer, "artifact_claim")
    begin_finalization = _required_method(sealer, "begin_finalization")
    finished = threading.Event()
    errors = []

    def seal():
        try:
            begin_finalization()
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    with artifact_claim():
        worker = threading.Thread(target=seal, daemon=True)
        worker.start()
        refused_immediately = finished.wait(0.5)
        state_while_claimed = json.loads(sealer.state_path.read_text())["state"]
    worker.join(timeout=3)

    assert refused_immediately, "begin_finalization() must not wait behind a live artifact claim"
    assert len(errors) == 1 and isinstance(errors[0], ContractError)
    assert state_while_claimed == "running" and sealer.state == "running"

    begin_finalization()
    assert sealer.state == "finalizing"


def test_append_and_begin_finalization_share_one_process_lock(tmp_path, monkeypatch):
    run = _running_run(tmp_path)
    appender = store.Run.open(tmp_path, "acme.example", run.run_id)
    sealer = store.Run.open(tmp_path, "acme.example", run.run_id)
    begin_finalization = _required_method(sealer, "begin_finalization")

    # Remove only the kernel-lock effect: the race must still serialize through the shared process-local
    # authority.  Patch both common import styles without prescribing one to the implementation.
    monkeypatch.setattr(fcntl, "flock", lambda *args, **kwargs: None)
    if hasattr(store, "flock"):
        monkeypatch.setattr(store, "flock", lambda *args, **kwargs: None)

    append_entered = threading.Event()
    release_append = threading.Event()
    append_done = threading.Event()
    seal_done = threading.Event()
    errors = []
    original_append = store.Run._append_line

    def paused_append(self, entity, line):
        append_entered.set()
        if not release_append.wait(3):
            raise AssertionError("test did not release the paused append")
        return original_append(self, entity, line)

    monkeypatch.setattr(store.Run, "_append_line", paused_append)

    def append():
        try:
            assert appender.add("subdomain", {"host": "winner.acme.example", "source": "race"})
        except BaseException as exc:
            errors.append(exc)
        finally:
            append_done.set()

    def seal():
        try:
            begin_finalization()
        except BaseException as exc:
            errors.append(exc)
        finally:
            seal_done.set()

    append_thread = threading.Thread(target=append, daemon=True)
    seal_thread = threading.Thread(target=seal, daemon=True)
    append_thread.start()
    assert append_entered.wait(2)
    seal_thread.start()
    seal_escaped = seal_done.wait(0.25)
    state_during_append = json.loads(sealer.state_path.read_text())["state"]
    release_append.set()
    append_thread.join(timeout=3)
    seal_thread.join(timeout=3)

    assert not seal_escaped, "the seal escaped while an append held the process-local run lock"
    assert append_done.is_set() and seal_done.is_set() and not errors
    assert state_during_append == "running" and sealer.state == "finalizing"
    assert store.Run.open(tmp_path, "acme.example", run.run_id).count("subdomain") == 1
