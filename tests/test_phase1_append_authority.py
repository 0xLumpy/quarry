"""Phase 1: canonical JSONL appends are private replacement transactions."""
from __future__ import annotations

import errno
import multiprocessing
import os
import sys
import threading
from types import SimpleNamespace

import pytest

from quarry_recon import store


pytestmark = pytest.mark.offline

COMPONENTS = ("raw", "append", "fixture", "records.jsonl")
PRIOR = b'{"record":"prior"}\n'
CANDIDATE = b'{"record":"candidate"}\n'


class _Context:
    def __init__(self, run):
        self.run = run


def _running_run(project, run_id="append-authority"):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _seed(run, body=PRIOR):
    return run._replace_artifact(
        store.MutationScope.BASE_EVIDENCE, COMPONENTS, body,
    )


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
    cancellation = cancellation_type(f"append cancellation at {target_line}")
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


def _append_in_process(project, run_id, prefix, ready, release, output):
    try:
        run = store.Run.open(project, "acme.example", run_id)
        ready.put(prefix)
        if not release.wait(10):
            raise RuntimeError("append process was not released")
        for index in range(8):
            row = f'{{"writer":"{prefix}","index":{index}}}\n'.encode()
            run._append_base_artifact(COMPONENTS, row)
    except BaseException as exc:
        output.put(f"{type(exc).__name__}: {exc}")
    else:
        output.put("")


def _result(tool):
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


def test_append_replaces_once_with_exact_prior_plus_new_bytes(tmp_path):
    run = _running_run(tmp_path)
    path = _seed(run)
    prior_identity = (path.stat().st_dev, path.stat().st_ino)

    run._append_base_artifact(COMPONENTS, CANDIDATE)

    assert path.read_bytes() == PRIOR + CANDIDATE
    assert (path.stat().st_dev, path.stat().st_ino) != prior_identity
    assert not list(run.raw.rglob("*.stage"))
    assert run._live_artifact_claim_count() == 0


def test_first_append_atomically_creates_the_complete_file(tmp_path):
    run = _running_run(tmp_path)
    path = run.dir.joinpath(*COMPONENTS)

    run._append_base_artifact(COMPONENTS, CANDIDATE)

    assert path.read_bytes() == CANDIDATE
    assert path.stat().st_mode & 0o777 == 0o600


def test_short_writes_are_completed_only_in_the_private_stage(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "short-writes")
    path = _seed(run)
    real_write = os.write

    def short_stage_write(fd, data):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        if target.endswith(".stage") and len(data) > 2:
            data = memoryview(data)[:2]
        return real_write(fd, data)

    monkeypatch.setattr(store.os, "write", short_stage_write)
    run._append_base_artifact(COMPONENTS, CANDIDATE)

    assert path.read_bytes() == PRIOR + CANDIDATE


def test_mid_append_write_fault_preserves_exact_prior_inode(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "write-fault")
    path = _seed(run)
    prior_identity = (path.stat().st_dev, path.stat().st_ino)
    real_write = os.write
    candidate_fd = None

    def fail_candidate_write(fd, data):
        nonlocal candidate_fd
        body = bytes(data)
        if candidate_fd == fd:
            raise OSError(errno.EIO, "append fixture write fault")
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        if target.endswith(".stage") and body.startswith(CANDIDATE):
            candidate_fd = fd
            return real_write(fd, memoryview(data)[:3])
        return real_write(fd, data)

    monkeypatch.setattr(store.os, "write", fail_candidate_write)
    with pytest.raises(OSError, match="append fixture write fault"):
        run._append_base_artifact(COMPONENTS, CANDIDATE)

    assert path.read_bytes() == PRIOR
    assert (path.stat().st_dev, path.stat().st_ino) == prior_identity
    assert not list(run.raw.rglob("*.stage"))
    assert run._live_artifact_claim_count() == 0


def test_stage_fsync_fault_preserves_exact_prior_inode(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "fsync-fault")
    path = _seed(run)
    prior_identity = (path.stat().st_dev, path.stat().st_ino)
    real_fsync = os.fsync
    fired = False

    def fail_stage_fsync(fd):
        nonlocal fired
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        if target.endswith(".stage") and not fired:
            fired = True
            raise OSError(errno.EIO, "append fixture fsync fault")
        return real_fsync(fd)

    monkeypatch.setattr(store.os, "fsync", fail_stage_fsync)
    with pytest.raises(OSError, match="append fixture fsync fault"):
        run._append_base_artifact(COMPONENTS, CANDIDATE)

    assert fired
    assert path.read_bytes() == PRIOR
    assert (path.stat().st_dev, path.stat().st_ino) == prior_identity
    assert run._live_artifact_claim_count() == 0
    assert not list(run.raw.rglob("*.stage"))


def test_source_close_cancellation_is_exact_and_preserves_prior(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "close-cancellation")
    path = _seed(run)
    prior_identity = (path.stat().st_dev, path.stat().st_ino)
    real_close = os.close
    cancellation = KeyboardInterrupt("exact source close cancellation")
    fired = False

    def cancel_source_close(fd):
        nonlocal fired
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        if target == str(path) and not fired:
            fired = True
            raise cancellation
        return real_close(fd)

    monkeypatch.setattr(store.os, "close", cancel_source_close)
    with pytest.raises(KeyboardInterrupt) as caught:
        run._append_base_artifact(COMPONENTS, CANDIDATE)

    assert fired and caught.value is cancellation
    assert path.read_bytes() == PRIOR
    assert (path.stat().st_dev, path.stat().st_ino) == prior_identity
    assert run._live_artifact_claim_count() == 0
    assert not list(run.raw.rglob("*.stage"))


def test_source_name_substitution_is_refused_before_publication(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "source-substitution")
    path = _seed(run)
    retained = path.with_name("retained-prior.jsonl")
    substitute = b'{"record":"substitute"}\n'
    real_copy = store._ArtifactAppendTransaction._copy_prior

    def substitute_after_copy(transaction, writer):
        real_copy(transaction, writer)
        os.rename(path, retained)
        path.write_bytes(substitute)
        os.chmod(path, 0o600)

    monkeypatch.setattr(
        store._ArtifactAppendTransaction, "_copy_prior", substitute_after_copy,
    )
    with pytest.raises(store.ContractError, match="source (name )?changed"):
        run._append_base_artifact(COMPONENTS, CANDIDATE)

    assert retained.read_bytes() == PRIOR
    assert path.read_bytes() == substitute
    assert CANDIDATE not in path.read_bytes()
    assert run._live_artifact_claim_count() == 0
    assert not list(run.raw.rglob("*.stage"))


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation",
    [
        store.Run._append_base_artifact,
        store._ArtifactMarkerRelease.allocate,
        store._ArtifactAppendTransaction._open_prior,
        store._ArtifactAppendTransaction._write_all,
        store._ArtifactAppendTransaction._copy_prior,
        store._ArtifactAppendTransaction._verify_prior,
        store._ArtifactAppendTransaction._close_sources,
        store._ArtifactAppendTransaction.execute,
        store._ArtifactAppendTransaction.settle,
    ],
)
def test_append_source_line_cancellation_preserves_one_complete_generation(
    tmp_path, operation, cancellation_type,
):
    discovery = _running_run(tmp_path / "discovery", "discovery")
    _seed(discovery)
    lines = _executed_lines(
        operation,
        lambda: discovery._append_base_artifact(COMPONENTS, CANDIDATE),
    )
    assert lines

    for index, target_line in enumerate(sorted(lines)):
        project = tmp_path / f"case-{index}"
        run = _running_run(project, f"case-{index}")
        path = _seed(run)
        prior_identity = (path.stat().st_dev, path.stat().st_ino)
        before_fds = _open_fds()

        _cancel_once(
            operation,
            target_line,
            lambda: run._append_base_artifact(COMPONENTS, CANDIDATE),
            cancellation_type,
        )

        assert _open_fds() == before_fds, f"source line {target_line}"
        assert path.read_bytes() in {PRIOR, PRIOR + CANDIDATE}
        if path.read_bytes() == PRIOR:
            assert (path.stat().st_dev, path.stat().st_ino) == prior_identity
        assert not list(run.raw.rglob("*.stage")), f"source line {target_line}"
        assert run._live_artifact_claim_count() == 0, f"source line {target_line}"
        store.Run.open(project, "acme.example", run.run_id).begin_finalization()


def test_primary_cancellation_precedes_a_later_cleanup_fault(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "cancellation-precedence")
    path = _seed(run)
    cancellation = KeyboardInterrupt("exact append cancellation")
    real_settle = store._ArtifactAppendTransaction.settle

    def settle_then_fault(transaction):
        real_settle(transaction)
        raise OSError(errno.EIO, "later cleanup fault")

    original_write_all = store._ArtifactAppendTransaction._write_all

    def selective_write(fd, data):
        if bytes(data).startswith(CANDIDATE):
            raise cancellation
        return original_write_all(fd, data)

    monkeypatch.setattr(
        store._ArtifactAppendTransaction, "_write_all", staticmethod(selective_write),
    )
    monkeypatch.setattr(store._ArtifactAppendTransaction, "settle", settle_then_fault)

    with pytest.raises(KeyboardInterrupt) as caught:
        run._append_base_artifact(COMPONENTS, CANDIDATE)

    assert caught.value is cancellation
    assert path.read_bytes() == PRIOR
    assert run._live_artifact_claim_count() == 0
    assert not list(run.raw.rglob("*.stage"))


def test_cross_process_cross_handle_appends_are_serialized_without_loss(tmp_path):
    run = _running_run(tmp_path, "process-append")
    _seed(run, b"")
    context = multiprocessing.get_context("fork")
    ready = context.Queue()
    release = context.Event()
    output = context.Queue()
    processes = [
        context.Process(
            target=_append_in_process,
            args=(tmp_path, run.run_id, prefix, ready, release, output),
        )
        for prefix in ("left", "right")
    ]
    for process in processes:
        process.start()
    assert {ready.get(timeout=10), ready.get(timeout=10)} == {"left", "right"}
    release.set()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert sorted((output.get(timeout=5), output.get(timeout=5))) == ["", ""]

    rows = run.dir.joinpath(*COMPONENTS).read_text().splitlines()
    assert len(rows) == 16
    assert set(rows) == {
        f'{{"writer":"{prefix}","index":{index}}}'
        for prefix in ("left", "right")
        for index in range(8)
    }


def test_append_and_seal_have_one_exact_lock_order(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "append-seal-race")
    sealer = store.Run.open(tmp_path, "acme.example", run.run_id)
    path = _seed(run)
    copied = threading.Event()
    release = threading.Event()
    append_errors = []
    seal_errors = []
    real_verify = store._ArtifactAppendTransaction._verify_prior

    def pause_after_copy(transaction):
        copied.set()
        if not release.wait(10):
            raise RuntimeError("append fixture was not released")
        return real_verify(transaction)

    monkeypatch.setattr(
        store._ArtifactAppendTransaction, "_verify_prior", pause_after_copy,
    )

    def append():
        try:
            run._append_base_artifact(COMPONENTS, CANDIDATE)
        except BaseException as exc:
            append_errors.append(exc)

    def seal():
        try:
            sealer.begin_finalization()
        except BaseException as exc:
            seal_errors.append(exc)

    append_thread = threading.Thread(target=append)
    seal_thread = threading.Thread(target=seal)
    append_thread.start()
    assert copied.wait(10)
    seal_thread.start()
    seal_thread.join(0.1)
    assert seal_thread.is_alive()
    release.set()
    append_thread.join(10)
    seal_thread.join(10)

    assert not append_thread.is_alive() and not seal_thread.is_alive()
    assert append_errors == [] and seal_errors == []
    assert path.read_bytes() == PRIOR + CANDIDATE
    assert sealer.state == "finalizing"


def test_tool_run_cache_signature_tracks_replacement_generations(tmp_path):
    run = _running_run(tmp_path, "tool-cache")
    other = store.Run.open(tmp_path, "acme.example", run.run_id)
    run.record("probe", _result("first"))
    first_signature = run._tool_runs_signature

    other.record("probe", _result("second"))

    assert [record.tool for record in run.tool_runs("probe")] == ["first", "second"]
    assert run._tool_runs_signature != first_signature
    assert run._tool_runs_signature == run._tool_runs_disk_signature()


def test_failed_tool_append_preserves_disk_and_cache_generation(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "tool-cache-fault")
    run.record("probe", _result("first"))
    path = run.dir / "tool-runs.jsonl"
    before_body = path.read_bytes()
    before_identity = (path.stat().st_dev, path.stat().st_ino)
    before_signature = run._tool_runs_signature
    real_write_all = store._ArtifactAppendTransaction._write_all

    def fail_second_record(fd, data):
        if b'"tool": "second"' in bytes(data):
            raise OSError(errno.EIO, "tool record append fault")
        return real_write_all(fd, data)

    monkeypatch.setattr(
        store._ArtifactAppendTransaction, "_write_all",
        staticmethod(fail_second_record),
    )
    with pytest.raises(OSError, match="tool record append fault"):
        run.record("probe", _result("second"))

    assert path.read_bytes() == before_body
    assert (path.stat().st_dev, path.stat().st_ino) == before_identity
    assert [record.tool for record in run.tool_runs("probe")] == ["first"]
    assert run._tool_runs_signature == before_signature
    assert run._tool_runs_signature == run._tool_runs_disk_signature()


def test_params_log_uses_the_same_transactional_append(tmp_path):
    from quarry_recon.phases import params
    run = _running_run(tmp_path, "params-log")
    path = _seed(run)
    ctx = _Context(run)

    params._append_run_log(ctx, path, "params-line\n")

    assert path.read_bytes() == PRIOR + b"params-line\n"
    assert run._live_artifact_claim_count() == 0
