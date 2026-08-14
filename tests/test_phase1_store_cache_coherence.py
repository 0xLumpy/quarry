"""Phase 1, step 6b: cached run handles remain coherent under the mutation authority.

The per-run lock serializes commits, but serialization alone is not cache coherence: a handle may have
folded a normalized log before another handle appends to it.  Public reads and later writes must therefore
notice the changed on-disk identity and refold before they answer from, or mutate, their instance cache.
"""
from __future__ import annotations

import json
import os
import select
import signal
import threading
import time

import pytest

from quarry_recon import store


pytestmark = pytest.mark.offline


def _running_run(project, run_id="cache-coherence"):
    run = store.Run.create(project, "acme.example", run_id=run_id)
    run.write_state("running")
    return run


def _jsonl_rows(path):
    payload = path.read_bytes()
    assert payload.endswith(b"\n"), "a committed JSONL append must end at a record boundary"
    rows = []
    for index, line in enumerate(payload.splitlines(), 1):
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            pytest.fail(f"normalized JSONL row {index} is corrupt: {exc}")
        assert isinstance(row, dict), f"normalized JSONL row {index} is not an object"
        rows.append(row)
    return rows


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


def test_cached_read_count_and_generation_observe_an_append_from_another_handle(tmp_path):
    run = _running_run(tmp_path)
    assert run.add("subdomain", {"host": "seed.acme.example", "sources": ["seed"]})

    read_handle = store.Run.open(tmp_path, "acme.example", run.run_id)
    count_handle = store.Run.open(tmp_path, "acme.example", run.run_id)
    generation_handle = store.Run.open(tmp_path, "acme.example", run.run_id)
    writer = store.Run.open(tmp_path, "acme.example", run.run_id)
    assert {row["host"] for row in read_handle.read("subdomain")} == {"seed.acme.example"}
    assert count_handle.count("subdomain") == 1
    generation_before = generation_handle.generation()
    log_path = run.normalized / "subdomain.jsonl"
    signature_before = (log_path.stat().st_dev, log_path.stat().st_ino,
                        log_path.stat().st_size, log_path.stat().st_mtime_ns)

    assert writer.add("subdomain", {"host": "late.acme.example", "sources": ["writer"]})

    signature_after = (log_path.stat().st_dev, log_path.stat().st_ino,
                       log_path.stat().st_size, log_path.stat().st_mtime_ns)
    assert signature_after != signature_before, "the fixture did not change the normalized log signature"
    # Each assertion uses a separately primed handle.  None is allowed to pass only because a previous
    # public read happened to refresh the shared object.
    assert {row["host"] for row in read_handle.read("subdomain")} == {
        "seed.acme.example", "late.acme.example",
    }
    assert count_handle.count("subdomain") == 2
    assert generation_handle.generation() != generation_before


def test_cached_merged_record_and_generation_observe_cross_handle_enrichment(tmp_path):
    run = _running_run(tmp_path, run_id="cache-enrichment")
    assert run.add("subdomain", {
        "host": "shared.acme.example", "sources": ["seed"], "title": "",
    })
    reader = store.Run.open(tmp_path, "acme.example", run.run_id)
    generation_reader = store.Run.open(tmp_path, "acme.example", run.run_id)
    writer = store.Run.open(tmp_path, "acme.example", run.run_id)
    assert reader.read("subdomain")[0]["sources"] == ["seed"]
    generation_before = generation_reader.generation()

    assert writer.add("subdomain", {
        "host": "shared.acme.example", "sources": ["enrichment"], "title": "Control panel",
    }) is False

    [merged] = reader.read("subdomain")
    assert merged["title"] == "Control panel"
    assert set(merged["sources"]) == {"seed", "enrichment"}
    assert reader.count("subdomain") == 1
    assert generation_reader.generation() != generation_before


def test_threaded_stale_handles_merge_enrichments_without_loss_or_corrupt_jsonl(tmp_path):
    run = _running_run(tmp_path, run_id="threaded-cache")
    assert run.add("subdomain", {
        "host": "shared.acme.example", "sources": ["seed"], "addresses": [],
    })
    left = store.Run.open(tmp_path, "acme.example", run.run_id)
    right = store.Run.open(tmp_path, "acme.example", run.run_id)
    assert left.count("subdomain") == right.count("subdomain") == 1

    start = threading.Barrier(3)
    errors = []

    def enrich(handle, source, address):
        try:
            start.wait(timeout=3)
            assert handle.add("subdomain", {
                "host": "shared.acme.example", "sources": [source], "addresses": [address],
            }) is False
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=enrich, args=(left, "left", "192.0.2.11"), daemon=True),
        threading.Thread(target=enrich, args=(right, "right", "192.0.2.12"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    start.wait(timeout=3)
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads), "a serialized cache mutation deadlocked"
    assert not errors
    rows = _jsonl_rows(run.normalized / "subdomain.jsonl")
    assert len(rows) == 3
    for handle in (left, right, store.Run.open(tmp_path, "acme.example", run.run_id)):
        [merged] = handle.read("subdomain")
        assert set(merged["sources"]) == {"seed", "left", "right"}
        assert set(merged["addresses"]) == {"192.0.2.11", "192.0.2.12"}


def test_forked_stale_handles_append_without_loss_or_corrupt_jsonl(tmp_path):
    run = _running_run(tmp_path, run_id="forked-cache")
    assert run.add("subdomain", {"host": "seed.acme.example", "sources": ["seed"]})
    parent_handle = store.Run.open(tmp_path, "acme.example", run.run_id)
    assert parent_handle.count("subdomain") == 1

    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    detail_read, detail_write = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - assertions and reporting stay in the parent
        os.close(ready_read)
        os.close(release_write)
        os.close(detail_read)
        try:
            child_handle = store.Run.open(tmp_path, "acme.example", run.run_id)
            if child_handle.count("subdomain") != 1:
                raise AssertionError("child did not prime the one-row cache")
            os.write(ready_write, b"ready\n")
            if os.read(release_read, 1) != b"g":
                raise AssertionError("parent did not release the child appender")
            if not child_handle.add("subdomain", {
                "host": "child.acme.example", "sources": ["child"],
            }):
                raise AssertionError("child append was not accepted as a new identity")
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
        assert ready and os.read(ready_read, len(b"ready\n")) == b"ready\n"
        os.write(release_write, b"g")
        assert parent_handle.add("subdomain", {
            "host": "parent.acme.example", "sources": ["parent"],
        })
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
    rows = _jsonl_rows(run.normalized / "subdomain.jsonl")
    assert {row["host"] for row in rows} == {
        "seed.acme.example", "parent.acme.example", "child.acme.example",
    }
    reopened = store.Run.open(tmp_path, "acme.example", run.run_id)
    assert reopened.count("subdomain") == 3
