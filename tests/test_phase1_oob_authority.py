"""Phase 1, step 7: OOB acquisition and the base seal share one authority.

The older revision layer decided where raw bytes belonged separately from the
decision about where normalized rows belonged.  That leaves a race in which a
callback's raw proof lands in the base tree, finalization seals, and its row is
then published as a revision.  These tests define the narrower Phase 1 seam:
one repository transaction chooses a complete live commit, one complete
revision candidate, or a retryable refusal.
"""
from __future__ import annotations

import copy
import io
import json
import os
import signal
import threading
import time
from pathlib import Path

import pytest

from quarry_recon import oob, privfs, revision, store
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


def _callback(full_id="qphase1.csession01", remote="203.0.113.17") -> str:
    return json.dumps({
        "protocol": "dns",
        "unique-id": "csession01",
        "full-id": full_id,
        "q-type": "A",
        "remote-address": remote,
        "timestamp": "2026-08-13T12:00:00Z",
    }) + "\n"


def _running_run(project, run_id="oob-authority"):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _finish(run) -> None:
    """Take a running fixture through the real base commitment."""
    run.begin_finalization()
    run.write_manifest({}, ["fixture"], metrics=None, policy=None)
    run.write_state("finished")


def _finish_after_race(project, run_id) -> None:
    run = store.Run.open(project, "acme.example", run_id)
    if run.state == "running":
        _finish(run)
    elif run.state == "finalizing":
        run.write_manifest({}, ["fixture"], metrics=None, policy=None)
        run.write_state("finished")
    assert run.state == "finished"


def _base_bytes(run) -> dict[str, bytes]:
    return {
        str(path.relative_to(run.dir)): path.read_bytes()
        for path in sorted(run.dir.rglob("*"))
        if path.is_file() and "revisions" not in path.relative_to(run.dir).parts
    }


def _safe_ref(run, value: str) -> Path:
    assert isinstance(value, str) and value
    ref = Path(value)
    assert not ref.is_absolute(), f"repository reference leaked an absolute path: {value!r}"
    assert all(part not in ("", ".", "..") for part in ref.parts)
    resolved = run.dir.joinpath(*ref.parts)
    assert resolved == run.dir / ref
    return resolved


class _FakeProc:
    def __init__(self):
        self.stdout = io.StringIO("")


def _fake_interactsh(monkeypatch, captured):
    monkeypatch.setattr(oob.shutil, "which", lambda _name: "/usr/bin/interactsh-client")
    monkeypatch.setattr(
        oob, "_prepare_client_launch",
        lambda _run, command, **_kwargs: (list(command), {}),
    )
    monkeypatch.setattr(oob, "_await_register", lambda _proc, _server, _wait: ("csession01.oast.pro",
                                                                               "csession01"))
    monkeypatch.setattr(
        oob.runner, "terminate_group", lambda _proc, **_kwargs: None,
    )

    def launch(command, **kwargs):
        proc = _FakeProc()
        captured.update(command=list(command), kwargs=dict(kwargs), proc=proc)
        return proc

    monkeypatch.setattr(oob.subprocess, "Popen", launch)


def test_oob_close_uses_sigint_persistence_boundary(monkeypatch):
    observed = {}
    proc = _FakeProc()

    def terminate(current, **kwargs):
        observed["proc"] = current
        observed.update(kwargs)

    monkeypatch.setattr(oob.runner, "terminate_group", terminate)
    oob.close_session(proc)

    assert observed == {"proc": proc, "graceful_signal": signal.SIGINT}
    assert proc.stdout.closed


def test_saved_session_paths_are_run_relative_references(tmp_path):
    run = _running_run(tmp_path, "relative-session")
    log = run.dir / "raw" / "oob" / "session" / "interactions.jsonl"
    state_file = run.dir / "raw" / "oob" / "session" / "interactsh.session"
    session = {
        "domain": "csession01.oast.pro",
        "unique_id": "csession01",
        "token_map": {},
        "started": "now",
        "log": str(log),
        "session_file": str(state_file),
    }

    saved = oob.save_session(run, session)
    document = json.loads(saved.read_text())

    assert document["log"] == "raw/oob/session/interactions.jsonl"
    assert document["session_file"] == "raw/oob/session/interactsh.session"
    loaded = oob.load_session(run)
    assert _safe_ref(run, loaded["log"]) == log
    assert _safe_ref(run, loaded["session_file"]) == state_file


@pytest.mark.parametrize("field", ["log", "session_file"])
@pytest.mark.parametrize("kind", ["absolute", "traversal", "symlink"])
def test_session_consumers_refuse_escaping_repository_references(tmp_path, monkeypatch, field, kind):
    run = _running_run(tmp_path, f"unsafe-{field}-{kind}")
    outside = tmp_path / f"outside-{field}-{kind}.jsonl"
    outside.write_text(_callback())
    session_dir = run.raw_path("oob", "session", "anchor").parent
    if kind == "absolute":
        bad = str(outside.resolve())
    elif kind == "traversal":
        bad = "raw/oob/session/../../../outside.jsonl"
    else:
        link = session_dir / f"{field}.link"
        link.symlink_to(outside)
        bad = f"raw/oob/session/{link.name}"
    session = {"unique_id": "csession01", "token_map": {},
               "log": "raw/oob/session/missing.jsonl",
               "session_file": "raw/oob/session/missing.session"}
    session[field] = bad

    with pytest.raises(ContractError):
        if field == "log":
            oob.poll_session(run, session)
        else:
            # A damaged stored reference must be rejected before a client can
            # receive it on argv.  Write the fixture directly because the
            # ordinary save path must reject/normalize it too.
            session.update({"domain": "csession01.oast.pro", "server": None})
            privfs.write_private(oob.session_path(run), json.dumps(session))
            monkeypatch.setattr(oob.shutil, "which", lambda _name: "/usr/bin/interactsh-client")
            monkeypatch.setattr(
                oob.subprocess,
                "Popen",
                lambda *_args, **_kwargs: pytest.fail("unsafe session reference reached process launch"),
            )
            oob.resume_session(run, wait=0)


def test_token_issue_is_not_visible_in_memory_or_on_disk_when_the_base_is_sealed(tmp_path):
    run = _running_run(tmp_path, "sealed-token")
    session = {
        "domain": "csession01.oast.pro",
        "unique_id": "csession01",
        "token_map": {},
        "started": "now",
    }
    path = oob.save_session(run, session)
    before_session = copy.deepcopy(session)
    before_bytes = path.read_bytes()
    run.begin_finalization()

    with pytest.raises(ContractError, match="sealed"):
        oob.issue_token(session, "params.oob", "https://acme.example/", "next", run=run)

    assert session == before_session
    assert path.read_bytes() == before_bytes


def test_live_interactsh_log_and_session_claims_hold_off_the_base_seal(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "live-session-claim")
    captured = {}
    _fake_interactsh(monkeypatch, captured)

    opened = oob.open_session(run, wait=0)
    assert opened is not None
    session, proc = opened
    try:
        with pytest.raises(ContractError, match="live artifact claim"):
            store.Run.open(tmp_path, "acme.example", run.run_id).begin_finalization()
        assert run.state == "running"
        assert _safe_ref(run, session["log"]).parts[-4:] == (
            "raw", "oob", "session", "interactions.jsonl",
        )
        assert _safe_ref(run, session["session_file"]).parts[-4:] == (
            "raw", "oob", "session", "interactsh.session",
        )
    finally:
        oob.close_session(proc)

    store.Run.open(tmp_path, "acme.example", run.run_id).begin_finalization()
    assert run.state == "finalizing"


@pytest.mark.parametrize("lifecycle", ["finalizing", "unknown"])
def test_unsettled_lifecycle_refusal_is_explicitly_retryable_and_side_effect_free(tmp_path, lifecycle):
    run = _running_run(tmp_path, f"retryable-{lifecycle}")
    if lifecycle == "finalizing":
        run.begin_finalization()
    else:
        run.state_path.write_text("{ truncated lifecycle")
    source = tmp_path / f"{lifecycle}.jsonl"
    source.write_text(_callback())
    before = _base_bytes(run)

    with pytest.raises(revision.RevisionError) as caught:
        oob.import_file(run, source)

    error = caught.value
    assert getattr(error, "retryable", False) is True
    assert "retry" in str(error).lower()
    assert error.fault.challenges_completeness is True
    assert _base_bytes(run) == before
    assert not (run.dir / "revisions").exists()


def test_sealed_resume_uses_one_revision_candidate_and_never_client_writes_base(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "sealed-resume")
    session_dir = run.raw_path("oob", "session", "anchor").parent
    log = session_dir / "interactions.jsonl"
    state_file = session_dir / "interactsh.session"
    privfs.write_private(log, "")
    privfs.write_private(state_file, "opaque-interactsh-state")
    oob.save_session(run, {
        "domain": "csession01.oast.pro",
        "unique_id": "csession01",
        "token_map": {},
        "started": "now",
        "log": str(log),
        "session_file": str(state_file),
        "server": None,
    })
    _finish(run)
    base_before = _base_bytes(run)
    captured = {}
    _fake_interactsh(monkeypatch, captured)

    resumed = oob.resume_session(run, wait=0)
    assert resumed is not None
    session, proc = resumed
    try:
        command = captured["command"]
        client_log = Path(command[command.index("-o") + 1])
        client_state = Path(command[command.index("-session-file") + 1])
        for destination in (client_log, client_state):
            assert destination.is_absolute()
            assert run.dir in destination.parents
            assert run.raw not in (destination, *destination.parents)
            assert "revisions" in destination.relative_to(run.dir).parts
        assert client_log.parent == client_state.parent, (
            "one resume must stage one candidate containing both mutable client files"
        )
        assert client_state.read_bytes() == b"opaque-interactsh-state"
        assert _safe_ref(run, session["log"]) == client_log
        assert _safe_ref(run, session["session_file"]) == client_state

        # Model the client's only mutation: it writes the staged log named on
        # argv.  Polling must resolve the safe reference, never the sealed base.
        client_log.write_text(_callback())
        rows = oob.poll_session(run, session)
        assert len(rows) == 1
    finally:
        oob.close_session(proc)

    result = oob.import_polled(run, session, rows)
    assert result["revision"].status == "valid"
    assert _base_bytes(run) == base_before
    [record] = revision.combined_fold(run.dir, "oob_interaction").records.values()
    raw_ref = _safe_ref(run, record["raw_ref"])
    assert "revisions" in raw_ref.relative_to(run.dir).parts
    assert raw_ref.read_text() == _callback()


def test_revision_publication_waits_on_the_shared_run_authority(tmp_path):
    run = _running_run(tmp_path, "revision-shared-lock")
    _finish(run)
    source = tmp_path / "late.jsonl"
    source.write_text(_callback())
    started = threading.Event()
    finished = threading.Event()
    failures = []

    def publish():
        started.set()
        try:
            reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
            oob.import_file(reopened, source)
        except BaseException as exc:  # noqa: BLE001 - return thread failures to the test
            failures.append(exc)
        finally:
            finished.set()

    with run._mutation(store.MutationScope.REVISION):
        worker = threading.Thread(target=publish, daemon=True)
        worker.start()
        assert started.wait(2)
        assert not finished.wait(0.25), (
            "revision publication escaped the per-run repository authority"
        )
    worker.join(timeout=10)

    assert finished.is_set() and failures == []
    assert revision.read(run.dir).status == "valid"
    assert not (run.dir / "revisions" / ".publish.lock").exists()


def _assert_unsplit(run, import_outcome) -> None:
    base_raw = list((run.dir / "raw" / "oob" / "import").glob("*")) \
        if (run.dir / "raw" / "oob" / "import").is_dir() else []
    base_fold = store.fold_run_entity(run.dir, "oob_interaction")
    base_rows = len(base_fold.records)
    published = revision.read(run.dir)
    revised = published.status == "valid"

    assert not (base_raw and revised), "one callback split raw base proof from its revision row"
    assert not (base_rows and revised), "one callback split normalized base evidence from its revision"
    if base_raw or base_rows:
        assert len(base_raw) == base_rows == 1
        assert published.status == "absent"
        manifest = json.loads(run.manifest_path.read_text())
        assert manifest["entity_counts"]["oob_interaction"] == 1
    elif revised:
        late_raw = run.dir / "revisions" / "raw" / "oob" / "import"
        assert len(list(late_raw.glob("*"))) == 1
        assert published.entity_counts["oob_interaction"] == 1
    else:
        assert import_outcome.startswith("retryable:"), import_outcome


def _acceptable_seal_refusal(errors) -> bool:
    return (len(errors) == 1 and isinstance(errors[0], ContractError)
            and "live artifact claim" in str(errors[0]))


def test_threaded_oob_import_versus_seal_has_no_split_disposition(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "threaded-oob-seal")
    source = tmp_path / "threaded.jsonl"
    source.write_text(_callback())
    entered = threading.Event()
    release = threading.Event()
    original_parse = oob.parse_interactsh

    def paused_parse(text):
        entered.set()
        assert release.wait(5), "fixture did not release the parser"
        return original_parse(text)

    monkeypatch.setattr(oob, "parse_interactsh", paused_parse)
    import_outcome = []
    import_errors = []
    seal_errors = []

    def import_callback():
        try:
            result = oob.import_file(store.Run.open(tmp_path, "acme.example", run.run_id), source)
            import_outcome.append("revision" if result["revision"] else "live")
        except revision.RevisionError as exc:
            import_outcome.append(f"retryable:{getattr(exc, 'retryable', False)}")
        except BaseException as exc:  # noqa: BLE001
            import_errors.append(exc)

    def seal():
        try:
            _finish(store.Run.open(tmp_path, "acme.example", run.run_id))
        except BaseException as exc:  # noqa: BLE001
            seal_errors.append(exc)

    importer = threading.Thread(target=import_callback, daemon=True)
    importer.start()
    assert entered.wait(3)
    sealer = threading.Thread(target=seal, daemon=True)
    sealer.start()
    # If parsing is outside the repository transaction, let the seal win.  If
    # the live transaction/claim already owns the candidate, the sealer blocks
    # or refuses and the import wins.  Both are legitimate; a split is not.
    sealer.join(timeout=0.25)
    release.set()
    importer.join(timeout=10)
    sealer.join(timeout=10)

    assert not importer.is_alive() and not sealer.is_alive()
    assert import_errors == [] and len(import_outcome) == 1
    if seal_errors:
        assert _acceptable_seal_refusal(seal_errors), seal_errors
        _finish_after_race(tmp_path, run.run_id)
    _assert_unsplit(store.Run.open(tmp_path, "acme.example", run.run_id), import_outcome[0])


def _reap_bounded(pid, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    pytest.fail(f"forked OOB importer did not settle (wait status {status})")


def test_forked_oob_import_versus_seal_has_no_split_disposition(tmp_path, monkeypatch):
    run = _running_run(tmp_path, "forked-oob-seal")
    source = tmp_path / "forked.jsonl"
    source.write_text(_callback())
    entered_read, entered_write = os.pipe()
    release_read, release_write = os.pipe()
    result_read, result_write = os.pipe()
    original_parse = oob.parse_interactsh

    def paused_parse(text):
        os.write(entered_write, b"parsed\n")
        if os.read(release_read, 1) != b"g":
            raise AssertionError("parent did not release forked parser")
        return original_parse(text)

    monkeypatch.setattr(oob, "parse_interactsh", paused_parse)
    child = os.fork()
    if child == 0:  # pragma: no cover - the parent owns assertions and cleanup
        os.close(entered_read)
        os.close(release_write)
        os.close(result_read)
        try:
            child_run = store.Run.open(tmp_path, "acme.example", run.run_id)
            result = oob.import_file(child_run, source)
            outcome = "revision" if result["revision"] else "live"
        except revision.RevisionError as exc:
            outcome = f"retryable:{getattr(exc, 'retryable', False)}"
        except BaseException as exc:
            outcome = f"error:{type(exc).__name__}:{exc}"
        try:
            os.write(result_write, outcome.encode("utf-8")[:2048])
        finally:
            os._exit(0 if not outcome.startswith("error:") else 70)

    os.close(entered_write)
    os.close(release_read)
    os.close(result_write)
    child_status = None
    seal_errors = []

    def seal():
        try:
            _finish(store.Run.open(tmp_path, "acme.example", run.run_id))
        except BaseException as exc:  # noqa: BLE001
            seal_errors.append(exc)

    try:
        assert os.read(entered_read, len(b"parsed\n")) == b"parsed\n"
        sealer = threading.Thread(target=seal, daemon=True)
        sealer.start()
        sealer.join(timeout=0.25)
        os.write(release_write, b"g")
        child_status = _reap_bounded(child)
        sealer.join(timeout=10)
        assert not sealer.is_alive()
    finally:
        for fd in (entered_read, release_write):
            try:
                os.close(fd)
            except OSError:
                pass
        if child_status is None:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass

    outcome = os.read(result_read, 2048).decode("utf-8", errors="replace")
    os.close(result_read)
    assert os.waitstatus_to_exitcode(child_status) == 0, outcome
    assert not outcome.startswith("error:"), outcome
    if seal_errors:
        assert _acceptable_seal_refusal(seal_errors), seal_errors
        _finish_after_race(tmp_path, run.run_id)
    _assert_unsplit(store.Run.open(tmp_path, "acme.example", run.run_id), outcome)
