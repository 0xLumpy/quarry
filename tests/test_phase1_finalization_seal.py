"""Phase 1, step 6d: one irreversible base seal and derived-only re-finalization.

The short repository lock protects individual appends.  Finalization is the
other half of that authority: while holding the same process/inter-process
lock it durably flushes the canonical base, proves that no long-lived artifact
owner remains, and advances the lifecycle.  A later report may reopen only the
derived-publication bookkeeping; it never makes base writers eligible again.
"""
from __future__ import annotations

import json
import os
import signal
import stat
import threading
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from quarry_recon import events, store
from quarry_recon.cli import cli
from quarry_recon.state import ContractError


pytestmark = pytest.mark.offline


def _running_run(project, run_id="finalization-seal"):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _profile(project: Path) -> Path:
    path = project / "target.yaml"
    path.write_text(
        "TARGET: acme.example\n"
        "APEX_DOMAINS:\n"
        "  - acme.example\n"
        "MODES:\n"
        "  PASSIVE_ONLY: true\n",
    )
    return path


def _reap_bounded(pid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    pytest.fail(f"forked appender did not settle (wait status {status})")


def _fd_path(fd: int) -> Path | None:
    try:
        return Path(os.readlink(f"/proc/self/fd/{fd}"))
    except OSError:
        return None


def test_begin_finalization_fsyncs_canonical_base_files_and_directories_before_seal(
    tmp_path, monkeypatch,
):
    run = _running_run(tmp_path)
    assert run.add("subdomain", {"host": "seed.acme.example", "source": "fixture"})
    run._append_base_artifact(("events.jsonl",), b'{"event":"fixture"}\n')
    run._replace_artifact(store.MutationScope.BASE_EVIDENCE,
                          ("metrics", "summary.json"), b"{}")
    with run.artifact_claim("raw", "native", "fixture", "body.bin") as claim:
        writer = claim.open_writer()
        os.write(writer, b"base evidence")
        os.close(writer)
        claim.publish()

    real_fsync = os.fsync
    synced: dict[Path, tuple[int, str]] = {}

    def observe(fd):
        path = _fd_path(fd)
        if path is not None:
            synced[path] = (stat.S_IFMT(os.fstat(fd).st_mode), run.state)
        return real_fsync(fd)

    monkeypatch.setattr(store.os, "fsync", observe)
    run.begin_finalization()

    expected_files = {
        run.meta_path,
        run.normalized / "subdomain.jsonl",
        run.dir / "events.jsonl",
        run.dir / "metrics" / "summary.json",
        run.raw / "native" / "fixture" / "body.bin",
    }
    expected_dirs = {
        run.dir,
        run.normalized,
        run.dir / "metrics",
        run.raw,
        run.raw / "native",
        run.raw / "native" / "fixture",
    }
    assert expected_files | expected_dirs <= set(synced)
    assert all(synced[path][1] == "running" for path in expected_files | expected_dirs)
    assert all(synced[path][0] == stat.S_IFREG for path in expected_files)
    assert all(synced[path][0] == stat.S_IFDIR for path in expected_dirs)
    assert run.state == "finalizing"


def test_a_base_fsync_failure_leaves_the_run_unsealed(tmp_path, monkeypatch):
    run = _running_run(tmp_path, run_id="fsync-refusal")
    assert run.add("subdomain", {"host": "seed.acme.example", "source": "fixture"})
    target = run.normalized / "subdomain.jsonl"
    real_fsync = os.fsync

    def fail_target(fd):
        if _fd_path(fd) == target:
            raise OSError("fixture fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(store.os, "fsync", fail_target)
    with pytest.raises(OSError, match="fixture fsync failure"):
        run.begin_finalization()

    assert run.state == "running"
    assert not run.manifest_path.exists()
    assert run.count("subdomain") == 1


@pytest.mark.parametrize("contender", ["append", "claim"])
def test_a_thread_losing_to_the_seal_cannot_gain_base_authority(
    tmp_path, monkeypatch, contender,
):
    run = _running_run(tmp_path, run_id=f"seal-wins-{contender}")
    assert run.add("subdomain", {"host": "seed.acme.example", "source": "fixture"})
    target = run.normalized / "subdomain.jsonl"
    real_fsync = os.fsync
    seal_entered = threading.Event()
    release_seal = threading.Event()
    seal_done = threading.Event()
    contender_done = threading.Event()
    errors = []

    def pause_target(fd):
        if _fd_path(fd) == target and not seal_entered.is_set():
            seal_entered.set()
            if not release_seal.wait(3):
                raise AssertionError("test did not release the seal")
        return real_fsync(fd)

    monkeypatch.setattr(store.os, "fsync", pause_target)

    def seal():
        try:
            store.Run.open(tmp_path, "acme.example", run.run_id).begin_finalization()
        except BaseException as exc:
            errors.append(("seal", exc))
        finally:
            seal_done.set()

    def contend():
        try:
            opened = store.Run.open(tmp_path, "acme.example", run.run_id)
            if contender == "append":
                opened.add("subdomain", {"host": "late.acme.example", "source": "fixture"})
            else:
                with opened.artifact_claim("raw", "fixture", "late.bin"):
                    pytest.fail("a post-seal claim entered its body")
        except BaseException as exc:
            errors.append((contender, exc))
        finally:
            contender_done.set()

    seal_thread = threading.Thread(target=seal, daemon=True)
    contender_thread = threading.Thread(target=contend, daemon=True)
    seal_thread.start()
    assert seal_entered.wait(2)
    contender_thread.start()
    assert not contender_done.wait(0.25), "the contender escaped the shared seal lock"
    release_seal.set()
    seal_thread.join(timeout=3)
    contender_thread.join(timeout=3)

    assert seal_done.is_set() and contender_done.is_set()
    assert not [error for owner, error in errors if owner == "seal"]
    refused = [error for owner, error in errors if owner == contender]
    assert len(refused) == 1 and isinstance(refused[0], ContractError)
    reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
    assert reopened.state == "finalizing"
    assert reopened.count("subdomain") == 1


def test_a_process_append_settles_before_the_waiting_seal(tmp_path, monkeypatch):
    run = _running_run(tmp_path, run_id="process-append-wins")
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    detail_read, detail_write = os.pipe()
    original_append = store.Run._append_line

    def paused_append(self, entity, line):
        os.write(ready_write, b"locked\n")
        if os.read(release_read, 1) != b"x":
            raise AssertionError("parent did not release the append")
        return original_append(self, entity, line)

    monkeypatch.setattr(store.Run, "_append_line", paused_append)
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - assertions and reporting stay in the parent
        os.close(ready_read)
        os.close(release_write)
        os.close(detail_read)
        try:
            child = store.Run.open(tmp_path, "acme.example", run.run_id)
            assert child.add("subdomain", {"host": "child.acme.example", "source": "fixture"})
        except BaseException as exc:
            try:
                os.write(detail_write, f"{type(exc).__name__}: {exc}".encode()[:2048])
            except OSError:
                pass
            os._exit(70)
        os._exit(0)

    os.close(ready_write)
    os.close(release_read)
    os.close(detail_write)
    seal_done = threading.Event()
    seal_errors = []
    child_status = None
    detail = b""
    try:
        assert os.read(ready_read, len(b"locked\n")) == b"locked\n"

        def seal():
            try:
                store.Run.open(tmp_path, "acme.example", run.run_id).begin_finalization()
            except BaseException as exc:
                seal_errors.append(exc)
            finally:
                seal_done.set()

        worker = threading.Thread(target=seal, daemon=True)
        worker.start()
        assert not seal_done.wait(0.25), "the seal escaped the child process's append lock"
        os.write(release_write, b"x")
        child_status = _reap_bounded(child_pid)
        child_pid = -1
        worker.join(timeout=3)
        detail = os.read(detail_read, 2048)
    finally:
        for fd in (ready_read, release_write, detail_read):
            try:
                os.close(fd)
            except OSError:
                pass
        if child_pid > 0:
            try:
                os.write(release_write, b"x")
            except OSError:
                pass
            child_status = _reap_bounded(child_pid)

    assert os.waitstatus_to_exitcode(child_status) == 0, detail.decode(errors="replace")
    assert seal_done.is_set() and not seal_errors
    reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
    assert reopened.state == "finalizing"
    assert reopened.count("subdomain") == 1


def test_finished_run_reopens_only_derived_publication_metadata(tmp_path):
    run = _running_run(tmp_path, run_id="derived-reopen")
    assert run.add("subdomain", {"host": "seed.acme.example", "source": "fixture"})
    run.begin_finalization()
    run.write_manifest({}, ["horizontal"])
    run.write_state("finished")
    before = json.loads(run.manifest_path.read_text())

    reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
    reopened.reopen_finalization(detail="fixture report")
    assert reopened.state == "finalizing"
    with pytest.raises(ContractError):
        reopened.add("subdomain", {"host": "late.acme.example", "source": "fixture"})
    reopened.mark_stage("hotlist", "failed", detail="fixture publication failure")
    summary = reopened.reconcile_finalization()
    assert summary["verdict"] == "complete_with_gaps"

    after = json.loads(run.manifest_path.read_text())
    assert {key: value for key, value in after.items() if key != "summary"} == {
        key: value for key, value in before.items() if key != "summary"
    }
    assert after["summary"]["faults"] == [{
        "kind": "publication",
        "where": "hotlist",
        "detail": "fixture publication failure",
        "challenges_completeness": True,
    }]


def test_derived_reopen_refuses_manifest_damage_without_transition(tmp_path):
    run = _running_run(tmp_path, run_id="damaged-reopen")
    run.begin_finalization()
    run.write_manifest({}, ["horizontal"])
    run.write_state("finished")
    manifest = json.loads(run.manifest_path.read_text())
    manifest["summary"] = {}
    run.manifest_path.write_text(json.dumps(manifest))
    before_manifest = run.manifest_path.read_bytes()
    before_state = run.state_path.read_bytes()

    reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(ContractError, match="committed manifest"):
        reopened.reopen_finalization(detail="must not repair damage")

    assert run.manifest_path.read_bytes() == before_manifest
    assert run.state_path.read_bytes() == before_state
    assert reopened.state == "finished"


def test_cli_runs_base_classifiers_and_events_before_begin_finalization(tmp_path, monkeypatch):
    from quarry_recon import gadgets, phases

    monkeypatch.setattr(phases, "REGISTRY", {"horizontal": (lambda _ctx: None, "Horizontal", False)})
    real_classify = gadgets.classify
    real_begin = store.Run.begin_finalization
    classified = False
    observed = {}

    def classify(run, scope):
        nonlocal classified
        classified = True
        return real_classify(run, scope)

    def begin(run):
        rows = [json.loads(line) for line in (run.dir / "events.jsonl").read_text().splitlines()]
        observed["classified"] = classified
        observed["ownership"] = any(
            row.get("event") == events.COVERAGE_PARTIAL
            and row.get("source_id") == "evidence.ownership"
            for row in rows
        )
        return real_begin(run)

    monkeypatch.setattr(gadgets, "classify", classify)
    monkeypatch.setattr(store.Run, "begin_finalization", begin)
    result = CliRunner().invoke(
        cli, ["run", "-t", str(_profile(tmp_path)), "--phases", "horizontal", "--json"],
    )

    assert result.exit_code == 0, result.output
    assert observed == {"classified": True, "ownership": True}


def test_report_uses_the_derived_reopen_and_leaves_base_bytes_unchanged(tmp_path, monkeypatch):
    from quarry_recon import phases

    monkeypatch.setattr(phases, "REGISTRY", {"horizontal": (lambda _ctx: None, "Horizontal", False)})
    profile = _profile(tmp_path)
    first = CliRunner().invoke(cli, ["run", "-t", str(profile), "--phases", "horizontal"])
    assert first.exit_code == 0, first.output
    run_dir = next(path for path in (tmp_path / "recon").iterdir() if path.name != "state")
    canonical = [
        path for path in run_dir.rglob("*")
        if path.is_file()
        and path.name not in {"manifest.json", "state.json"}
        and "reports" not in path.parts and "exports" not in path.parts
    ]
    before = {path.relative_to(run_dir): path.read_bytes() for path in canonical}
    real_reopen = store.Run.reopen_finalization
    reopened = []

    def reopen(run, **kwargs):
        reopened.append(run.run_id)
        return real_reopen(run, **kwargs)

    monkeypatch.setattr(store.Run, "reopen_finalization", reopen)
    result = CliRunner().invoke(cli, ["report", "-t", str(profile), "--force"])

    assert result.exit_code == 0, result.output
    assert len(reopened) == 1
    assert {path.relative_to(run_dir): path.read_bytes() for path in canonical} == before
