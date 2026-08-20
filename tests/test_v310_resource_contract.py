"""V310-06 aggregate reservations, honest remainder and bounded resolver work."""
from __future__ import annotations

import gc
import io
import json
import multiprocessing
import os
import stat
import threading
import time
from collections.abc import Mapping
from pathlib import Path

import pytest

from quarry_recon import contract, netguard, remainder as remainder_contract, resource_contract

pytestmark = pytest.mark.offline


def _stream_process(start, queue, state, destination, byte):
    from quarry_recon import contract as child_contract

    governor = child_contract.DiskGovernor(
        run_max=100, reserve_bytes=0, run_state=Path(state), run_key="shared-run",
    )
    start.wait()
    try:
        count, digest = child_contract.stream_to_file(
            io.BytesIO(byte * 80), Path(destination), chunk=80, governor=governor,
        )
        queue.put(("complete", count, digest))
    except child_contract.AcquisitionTruncated as exc:
        queue.put(("truncated", exc.bytes_written, exc.limit_kind))


def _same_destination_process(start, queue, destination, byte):
    from quarry_recon import contract as child_contract

    start.wait()
    try:
        count, _digest = child_contract.stream_to_file(
            io.BytesIO(byte * 4096), Path(destination), chunk=257,
            governor=child_contract.DiskGovernor(reserve_bytes=0),
        )
        queue.put(("complete", count))
    except BaseException as exc:
        queue.put(("failed", type(exc).__name__))


def _hold_lease(destination, ready):
    from quarry_recon import resource_contract as child_resources

    with child_resources.acquisition_lease(Path(destination), timeout_s=2):
        ready.send(True)
        time.sleep(30)


def _try_inherited_lease(destination, queue):
    from quarry_recon import resource_contract as child_resources

    try:
        with child_resources.acquisition_lease(Path(destination), timeout_s=0.05):
            queue.put("incorrectly-acquired")
    except child_resources.ResourceLeaseUnavailable:
        queue.put("contended")


def _idle_child():
    time.sleep(30)


def _partial_resolution_frame(conn, _host, _stub):
    os.write(conn.fileno(), b'{"ips":')
    time.sleep(30)


class _ConstructorFaultContext:
    def __init__(self, base, fault):
        self.base = base
        self.fault = fault

    def Pipe(self, duplex):
        return self.base.Pipe(duplex)

    def Process(self, **_kwargs):
        raise self.fault


class _StartFaultProcess:
    pid = None

    def __init__(self, fault, args):
        self.fault = fault
        self.args = args

    def start(self):
        raise self.fault


class _StartFaultContext(_ConstructorFaultContext):
    def Process(self, **kwargs):
        return _StartFaultProcess(self.fault, kwargs["args"])


class _ObservedSizedCorpus:
    def __init__(self, values):
        self.values = tuple(values)
        self.consumed = 0
        self.exhaustion_proved = False

    def __len__(self):
        return len(self.values)

    def __iter__(self):
        for value in self.values:
            self.consumed += 1
            yield value
        self.exhaustion_proved = True


@pytest.fixture(autouse=True)
def _reset_governor():
    contract.reset_shared_governor()
    yield
    contract.reset_shared_governor()


def test_support_envelope_is_finite_and_does_not_call_key_only_overflow_replayable():
    envelope = resource_contract.support_envelope()
    assert envelope["schema_version"] == "quarry.resource-support-envelope.v1"
    assert envelope["store"]["whole_corpus_materialized"] is True
    assert envelope["store"]["overflow_payload_retained"] is False
    assert envelope["store"]["overflow_disposition"] == "terminal-unschedulable-gap"
    assert "disk-backed-indexed-repository" in envelope["deferred"]
    acquisition = envelope["acquisition"]
    assert acquisition["cross_process_writers_per_filesystem"] == 1
    assert acquisition["distinct_governor_groups_per_filesystem"] == 1
    assert acquisition["same_governor_threads_share_reservations"] is True
    assert acquisition["managed_durable_project_limit"] == "refused-before-contact"
    assert envelope["resolver"]["corpus_deadline_milliseconds"] > 0
    assert envelope["resolver"]["worker_processes"] == netguard._MAX_WORKERS
    assert envelope["resolver"]["terminate_grace_milliseconds"] > 0
    assert (envelope["resolver"]["hard_kill_fallback_milliseconds"]
            > envelope["resolver"]["terminate_grace_milliseconds"])
    assert envelope["resolver"]["host_utf8_bytes"] == resource_contract.MAX_RESOLVER_HOST_BYTES
    assert envelope["resolver"]["worker_result_bytes"] == (
        resource_contract.MAX_RESOLVER_RESULT_BYTES
    )
    assert envelope["resolver"]["remainder_record_bytes"] == (
        resource_contract.MAX_RESOLVER_REMAINDER_BYTES
    )


def test_two_processes_share_the_run_reservation_without_overspend(tmp_path):
    ctx = multiprocessing.get_context("fork")
    start = ctx.Event()
    queue = ctx.Queue()
    state = tmp_path / "state" / "run-bytes.json"
    destinations = [tmp_path / "one.bin", tmp_path / "two.bin"]
    children = [
        ctx.Process(target=_stream_process,
                    args=(start, queue, str(state), str(destinations[index]), byte))
        for index, byte in enumerate((b"a", b"b"))
    ]
    for child in children:
        child.start()
    start.set()
    for child in children:
        child.join(10)
        assert child.exitcode == 0
    outcomes = [queue.get(timeout=2), queue.get(timeout=2)]
    assert sorted((item[0], item[1]) for item in outcomes) == [
        ("complete", 80), ("truncated", 20),
    ]
    assert json.loads(state.read_text())["bytes"] == 100
    assert sum(path.stat().st_size for path in tmp_path.glob("*.bin*")) == 100


def test_same_destination_has_one_cross_process_writer_and_never_mixes_bytes(tmp_path):
    ctx = multiprocessing.get_context("fork")
    start = ctx.Event()
    queue = ctx.Queue()
    destination = tmp_path / "shared.bin"
    children = [
        ctx.Process(target=_same_destination_process,
                    args=(start, queue, str(destination), byte))
        for byte in (b"a", b"b")
    ]
    for child in children:
        child.start()
    start.set()
    for child in children:
        child.join(10)
        assert child.exitcode == 0
    assert sorted(queue.get(timeout=2) for _ in children) == [
        ("complete", 4096), ("complete", 4096),
    ]
    assert destination.read_bytes() in {b"a" * 4096, b"b" * 4096}
    assert not destination.with_name(destination.name + ".part").exists()


def test_process_death_releases_both_filesystem_and_destination_lease(tmp_path):
    ctx = multiprocessing.get_context("fork")
    receiver, sender = ctx.Pipe(False)
    destination = tmp_path / "owned.bin"
    holder = ctx.Process(target=_hold_lease, args=(str(destination), sender))
    holder.start()
    assert receiver.recv() is True
    holder.terminate()
    holder.join(5)
    assert holder.exitcode is not None
    with resource_contract.acquisition_lease(destination, timeout_s=1):
        destination.write_bytes(b"new owner")
    assert destination.read_bytes() == b"new owner"


def test_cleanup_cancellation_is_deferred_until_every_lease_is_released(tmp_path, monkeypatch):
    destination = tmp_path / "cleanup.bin"
    primary = KeyboardInterrupt("body cancellation")
    real_close = resource_contract.os.close
    injected = SystemExit("destination close cancellation")
    fired = {"value": False}

    def close_then_cancel(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        real_close(fd)
        if "/destination-" in target and not fired["value"]:
            fired["value"] = True
            raise injected

    monkeypatch.setattr(resource_contract.os, "close", close_then_cancel)
    with pytest.raises(KeyboardInterrupt) as caught:
        with resource_contract.acquisition_lease(destination):
            raise primary
    assert caught.value is primary
    assert injected in caught.value.resource_cleanup_errors
    assert fired["value"] is True

    # The close took effect despite raising, and every later cleanup action ran.
    with resource_contract.acquisition_lease(destination, timeout_s=0.2):
        pass


def test_forked_child_does_not_trust_the_parents_copied_lease_map(tmp_path):
    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()
    destination = tmp_path / "forked.bin"
    with resource_contract.acquisition_lease(destination):
        child = ctx.Process(target=_try_inherited_lease, args=(str(destination), queue))
        child.start()
        child.join(5)
        assert child.exitcode == 0
        assert queue.get(timeout=2) == "contended"


def test_forked_long_lived_child_does_not_keep_parent_destination_lease_alive(tmp_path):
    ctx = multiprocessing.get_context("fork")
    destination = tmp_path / "fork-leak.bin"
    child = None
    with resource_contract.acquisition_lease(destination):
        child = ctx.Process(target=_idle_child)
        child.start()
    try:
        assert child.is_alive()
        with resource_contract.acquisition_lease(destination, timeout_s=0.2):
            pass
    finally:
        child.terminate()
        child.join(5)


def test_lease_contention_is_finite_and_typed(tmp_path):
    destination = tmp_path / "busy.bin"
    with resource_contract.acquisition_lease(destination):
        # A second open-file-description in this process still contends under flock.
        with pytest.raises(resource_contract.ResourceLeaseUnavailable):
            with resource_contract.acquisition_lease(destination, timeout_s=0.02):
                pass


def test_distinct_same_process_governors_serialize_one_filesystem_reserve(tmp_path):
    start = threading.Barrier(3)
    outcomes = []
    outcomes_lock = threading.Lock()

    def free_space(_path):
        used = sum(
            candidate.stat().st_size
            for candidate in tmp_path.glob("*.bin*")
            if candidate.is_file()
        )
        return 150 - used

    def stream(name, byte):
        governor = contract.DiskGovernor(reserve_bytes=100, free_fn=free_space)
        start.wait()
        try:
            contract.stream_to_file(
                io.BytesIO(byte * 80), tmp_path / name, chunk=80,
                governor=governor,
            )
        except contract.AcquisitionTruncated as exc:
            outcome = exc.bytes_written
        else:  # pragma: no cover - the reserve makes a complete 80-byte body impossible
            outcome = 80
        with outcomes_lock:
            outcomes.append(outcome)

    threads = [
        threading.Thread(target=stream, args=("one.bin", b"a")),
        threading.Thread(target=stream, args=("two.bin", b"b")),
    ]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert sorted(outcomes) == [0, 50]
    assert sum(path.stat().st_size for path in tmp_path.glob("*.bin*")) == 50


def test_uninspectable_partial_write_forfeits_the_full_durable_grant(
        tmp_path, monkeypatch):
    destination = tmp_path / "unknown.bin"
    state = tmp_path / "run-bytes.json"
    governor = contract.DiskGovernor(
        run_max=8, reserve_bytes=0, run_state=state, run_key="unknown-write",
    )
    real_open = contract._open_part_wb

    class PartialWriter:
        def __init__(self, raw):
            self.raw = raw

        def __enter__(self):
            self.raw.__enter__()
            return self

        def __exit__(self, *args):
            return self.raw.__exit__(*args)

        def fileno(self):
            return self.raw.fileno()

        def flush(self):
            return self.raw.flush()

        def write(self, body):
            self.raw.write(body[:3])
            self.raw.flush()
            raise OSError("partial sink failure")

    monkeypatch.setattr(contract, "_open_part_wb", lambda path: PartialWriter(real_open(path)))
    monkeypatch.setattr(contract, "_ondisk_size", lambda _fh: None)
    monkeypatch.setattr(contract, "_path_size", lambda _path: None)
    with pytest.raises(contract.IncompleteAcquisition) as caught:
        contract.stream_to_file(
            io.BytesIO(b"abcdefgh"), destination, chunk=8, governor=governor,
        )
    assert destination.with_name("unknown.bin.part").read_bytes() == b"abc"
    assert json.loads(state.read_text())["bytes"] == 8
    assert governor.run_streamed == 8
    assert governor._inflight == 0
    assert caught.value.bytes_written is None
    assert caught.value.content_uncertain is True
    assert caught.value.acquisition_accounting_charged_bytes == 8


def test_ancestor_symlink_is_refused_before_any_destination_write(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    destination = alias / "body.bin"
    with pytest.raises(contract.AcquisitionLeaseBusy):
        contract.stream_to_file(
            io.BytesIO(b"must-not-land"), destination,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )
    assert list(real.iterdir()) == []


def test_parent_substitution_cannot_redirect_the_pinned_writer(tmp_path):
    parent = tmp_path / "destination"
    parent.mkdir()
    moved = tmp_path / "moved"

    class RenameOnRead(io.BytesIO):
        changed = False

        def read(self, size=-1):
            if not self.changed:
                self.changed = True
                parent.rename(moved)
                parent.mkdir()
            return super().read(size)

    with pytest.raises(contract.IncompleteAcquisition) as caught:
        contract.stream_to_file(
            RenameOnRead(b"bounded-partial"), parent / "body.bin", chunk=64,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )
    assert caught.value.partial is None
    assert caught.value.bytes_written == len(b"bounded-partial")
    assert not (parent / "body.bin").exists()
    assert not (parent / "body.bin.part").exists()
    assert (moved / "body.bin.part").read_bytes() == b"bounded-partial"


def test_atomic_remainder_replace_then_fsync_fault_reconciles_as_committed(tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[]}\n'
    real_fsync = resource_contract.os.fsync
    directory_events = []

    def fail_parent_once(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_events.append("attempt")
            if directory_events == ["attempt"]:
                raise OSError("parent fsync failed before effect")
            real_fsync(fd)
            directory_events.append("durable")
            return
        real_fsync(fd)

    monkeypatch.setattr(resource_contract.os, "fsync", fail_parent_once)
    resource_contract.atomic_private_write(destination, body)
    assert destination.read_bytes() == body
    assert directory_events == ["attempt", "attempt", "durable"]


def test_atomic_remainder_persistent_parent_fsync_failure_is_typed_uncertain(
        tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[9]}\n'
    real_fsync = resource_contract.os.fsync
    directory_attempts = []

    def fail_every_parent_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_attempts.append(len(directory_attempts) + 1)
            raise OSError(f"parent fsync failure {len(directory_attempts)}")
        real_fsync(fd)

    monkeypatch.setattr(resource_contract.os, "fsync", fail_every_parent_fsync)
    with pytest.raises(resource_contract.ResourcePublicationUncertain) as caught:
        resource_contract.atomic_private_write(destination, body)
    assert directory_attempts == [1, 2]
    assert caught.value.resource_publication_landed is True
    assert caught.value.resource_publication_durable is False
    assert caught.value.resource_publication_committed is False
    assert len(caught.value.resource_durability_errors) == 2
    assert destination.read_bytes() == body
    assert not list(tmp_path.glob(".quarry-resource-*"))


def test_atomic_remainder_replace_that_lands_then_raises_is_not_reported_lost(tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[1]}\n'
    real_replace = resource_contract.os.replace

    def land_then_raise(*args, **kwargs):
        real_replace(*args, **kwargs)
        raise OSError("replace reported after effect")

    monkeypatch.setattr(resource_contract.os, "replace", land_then_raise)
    resource_contract.atomic_private_write(destination, body)
    assert destination.read_bytes() == body


def test_atomic_remainder_committed_cancellation_is_preserved_and_annotated(tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[2]}\n'
    real_replace = resource_contract.os.replace
    cancellation = KeyboardInterrupt("after replace")

    def land_then_cancel(*args, **kwargs):
        real_replace(*args, **kwargs)
        raise cancellation

    monkeypatch.setattr(resource_contract.os, "replace", land_then_cancel)
    with pytest.raises(KeyboardInterrupt) as caught:
        resource_contract.atomic_private_write(destination, body)
    assert caught.value is cancellation
    assert caught.value.resource_publication_landed is True
    assert caught.value.resource_publication_durable is True
    assert caught.value.resource_publication_committed is True
    assert destination.read_bytes() == body


def test_atomic_normal_reconciliation_close_cancellation_is_settled_and_annotated(
        tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[5]}\n'
    real_close = resource_contract.os.close
    cancellation = KeyboardInterrupt("normal reconciliation close")
    fired = {"value": False}

    def close_after_effect(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        real_close(fd)
        if target.endswith("/remainder.json") and not fired["value"]:
            fired["value"] = True
            raise cancellation

    monkeypatch.setattr(resource_contract.os, "close", close_after_effect)
    with pytest.raises(KeyboardInterrupt) as caught:
        resource_contract.atomic_private_write(destination, body)
    assert caught.value is cancellation
    assert fired["value"] is True
    assert caught.value.resource_publication_landed is True
    assert caught.value.resource_publication_durable is True
    assert caught.value.resource_publication_committed is True
    assert destination.read_bytes() == body


def test_atomic_landed_cancellation_with_unsettled_directory_is_not_called_committed(
        tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[6]}\n'
    real_replace = resource_contract.os.replace
    real_fsync = resource_contract.os.fsync
    cancellation = KeyboardInterrupt("replace cancellation after effect")

    def land_then_cancel(*args, **kwargs):
        real_replace(*args, **kwargs)
        raise cancellation

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory durability unavailable")
        real_fsync(fd)

    monkeypatch.setattr(resource_contract.os, "replace", land_then_cancel)
    monkeypatch.setattr(resource_contract.os, "fsync", fail_directory)
    with pytest.raises(KeyboardInterrupt) as caught:
        resource_contract.atomic_private_write(destination, body)
    assert caught.value is cancellation
    assert caught.value.resource_publication_landed is True
    assert caught.value.resource_publication_durable is False
    assert caught.value.resource_publication_committed is False
    assert destination.read_bytes() == body


def test_atomic_reconciliation_close_fault_cannot_replace_original_cancellation(
        tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[4]}\n'
    real_replace = resource_contract.os.replace
    real_close = resource_contract.os.close
    cancellation = KeyboardInterrupt("original publication cancellation")
    close_fired = {"value": False}

    def land_then_cancel(*args, **kwargs):
        real_replace(*args, **kwargs)
        raise cancellation

    def close_probe_then_raise(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        real_close(fd)
        if target.endswith("/remainder.json") and not close_fired["value"]:
            close_fired["value"] = True
            raise SystemExit("reconciliation close cancellation")

    monkeypatch.setattr(resource_contract.os, "replace", land_then_cancel)
    monkeypatch.setattr(resource_contract.os, "close", close_probe_then_raise)
    with pytest.raises(KeyboardInterrupt) as caught:
        resource_contract.atomic_private_write(destination, body)
    assert caught.value is cancellation
    assert caught.value.resource_publication_committed is True
    assert close_fired["value"] is True


def test_atomic_cleanup_cancellation_after_publication_is_not_masked_or_called_lost(
        tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[3]}\n'
    real_unlink = resource_contract.os.unlink
    cancellation = KeyboardInterrupt("cleanup cancellation")

    def unlink_then_cancel(*args, **kwargs):
        try:
            real_unlink(*args, **kwargs)
        except FileNotFoundError:
            pass
        raise cancellation

    monkeypatch.setattr(resource_contract.os, "unlink", unlink_then_cancel)
    with pytest.raises(KeyboardInterrupt) as caught:
        resource_contract.atomic_private_write(destination, body)
    assert caught.value is cancellation
    assert caught.value.resource_publication_committed is True
    assert destination.read_bytes() == body


@pytest.mark.parametrize(
    "fault",
    [
        OSError("lease close reported after effect"),
        KeyboardInterrupt("lease close cancellation"),
        SystemExit("lease close exit"),
    ],
    ids=("ordinary", "keyboard-interrupt", "system-exit"),
)
def test_atomic_lease_cleanup_fault_after_durable_publication_is_annotated(
        tmp_path, monkeypatch, fault):
    destination = tmp_path / "remainder.json"
    body = b'{"work":[7]}\n'
    real_close = resource_contract.os.close
    fired = {"value": False}

    def close_lease_then_raise(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        real_close(fd)
        if ("quarry-resource-locks" in target and target.endswith(".lock")
                and not fired["value"]):
            fired["value"] = True
            raise fault

    monkeypatch.setattr(resource_contract.os, "close", close_lease_then_raise)
    with pytest.raises(type(fault)) as caught:
        resource_contract.atomic_private_write(destination, body)
    assert caught.value is fault
    assert fired["value"] is True
    assert caught.value.resource_publication_landed is True
    assert caught.value.resource_publication_durable is True
    assert caught.value.resource_publication_committed is True
    assert caught.value.resource_payload_digest.startswith("sha256:")
    assert destination.read_bytes() == body


def test_resolver_marks_durable_payload_retained_after_ordinary_lease_close_fault(
        tmp_path, monkeypatch):
    path = tmp_path / "resolver-remainder.json"
    real_close = resource_contract.os.close
    fired = {"value": False}

    def close_lease_then_raise(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        real_close(fd)
        if ("quarry-resource-locks" in target and target.endswith(".lock")
                and not fired["value"]):
            fired["value"] = True
            raise OSError("lease close reported after effect")

    monkeypatch.setattr(resource_contract.os, "close", close_lease_then_raise)
    batch = netguard.resolve_many(
        ["one.invalid"], corpus_deadline_s=0, remainder_path=path,
    )
    assert fired["value"] is True
    assert batch.remainder.detail["payload_retained"] is True
    assert batch.remainder.retriable == 1
    assert netguard.read_resolution_remainder(path)["count"] == 1


def test_resolver_does_not_call_landed_bytes_replayable_without_directory_durability(
        tmp_path, monkeypatch):
    path = tmp_path / "resolver-remainder.json"
    real_fsync = resource_contract.os.fsync
    attempts = []

    def fail_parent_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            attempts.append(len(attempts) + 1)
            raise OSError("persistent directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(resource_contract.os, "fsync", fail_parent_fsync)
    batch = netguard.resolve_many(
        ["one.invalid"], corpus_deadline_s=0, remainder_path=path,
    )
    assert attempts == [1, 2]
    assert path.exists(), "replace landed, but its crash durability was not established"
    assert batch.remainder.detail["payload_retained"] is False
    assert batch.remainder.retriable == 0
    assert batch.remainder.terminal == {"machinery": 1}
    assert "ResourcePublicationUncertain" in batch.remainder.detail["persistence_fault"]


def test_atomic_close_after_effect_is_not_double_closed_or_masked(tmp_path, monkeypatch):
    destination = tmp_path / "remainder.json"
    real_close = resource_contract.os.close
    fired = {"value": False}

    def close_then_raise(fd):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target = ""
        real_close(fd)
        if ".quarry-resource-" in target and not fired["value"]:
            fired["value"] = True
            raise OSError("close reported after effect")

    monkeypatch.setattr(resource_contract.os, "close", close_then_raise)
    with pytest.raises(OSError, match="close reported after effect"):
        resource_contract.atomic_private_write(destination, b"payload")
    assert fired["value"] is True
    assert not destination.exists()
    assert not list(tmp_path.glob(".quarry-resource-*"))


def _resolver_record(path):
    body = resource_contract.canonical_bytes({
        "schema_version": "quarry.resolver-remainder.v1",
        "lane": "netguard.resolve",
        "measure": "hosts",
        "count": 1,
        "work": [{"host": "one.invalid", "cause": "corpus-deadline"}],
    })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    path.chmod(0o600)
    return body


def test_resolver_remainder_reader_refuses_a_hardlinked_record(tmp_path):
    record = tmp_path / "record.json"
    _resolver_record(record)
    os.link(record, tmp_path / "alias.json")
    with pytest.raises(ValueError, match="single-link"):
        netguard.read_resolution_remainder(record)


@pytest.mark.parametrize("kind", ("ancestor", "final"))
def test_resolver_remainder_reader_refuses_symlink_substitution(tmp_path, kind):
    real_parent = tmp_path / "real"
    record = real_parent / "record.json"
    _resolver_record(record)
    if kind == "ancestor":
        linked_parent = tmp_path / "linked"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        candidate = linked_parent / "record.json"
    else:
        candidate = real_parent / "linked.json"
        candidate.symlink_to(record)
    with pytest.raises(ValueError, match="unreadable"):
        netguard.read_resolution_remainder(candidate)


def test_resolver_remainder_reader_refuses_fifo_and_nonprivate_mode(tmp_path):
    fifo = tmp_path / "record.fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError, match="single-link regular"):
        netguard.read_resolution_remainder(fifo)

    record = tmp_path / "record.json"
    _resolver_record(record)
    record.chmod(0o640)
    with pytest.raises(ValueError, match="single-link regular"):
        netguard.read_resolution_remainder(record)


def test_resolver_remainder_reader_refuses_in_place_mutation(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    body = _resolver_record(record)
    replacement = body.replace(b"one.invalid", b"two.invalid")
    real_read = resource_contract.os.read
    fired = {"value": False}

    def read_then_mutate(fd, size):
        chunk = real_read(fd, size)
        if chunk and not fired["value"]:
            fired["value"] = True
            record.write_bytes(replacement)
            record.chmod(0o600)
        return chunk

    monkeypatch.setattr(resource_contract.os, "read", read_then_mutate)
    with pytest.raises(ValueError, match="changed while"):
        netguard.read_resolution_remainder(record)
    assert fired["value"] is True


def test_resolver_remainder_reader_refuses_final_name_replacement(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    body = _resolver_record(record)
    moved = tmp_path / "moved.json"
    real_read = resource_contract.os.read
    fired = {"value": False}

    def read_then_replace_name(fd, size):
        chunk = real_read(fd, size)
        if chunk and not fired["value"]:
            fired["value"] = True
            record.rename(moved)
            record.write_bytes(body)
            record.chmod(0o600)
        return chunk

    monkeypatch.setattr(resource_contract.os, "read", read_then_replace_name)
    with pytest.raises(ValueError, match="changed while"):
        netguard.read_resolution_remainder(record)
    assert fired["value"] is True


def test_resolver_remainder_reader_refuses_parent_rename_substitution(tmp_path, monkeypatch):
    parent = tmp_path / "records"
    record = parent / "record.json"
    body = _resolver_record(record)
    moved = tmp_path / "moved-records"
    real_read = resource_contract.os.read
    fired = {"value": False}

    def read_then_replace_parent(fd, size):
        chunk = real_read(fd, size)
        if chunk and not fired["value"]:
            fired["value"] = True
            parent.rename(moved)
            parent.mkdir()
            replacement = parent / "record.json"
            replacement.write_bytes(body)
            replacement.chmod(0o600)
        return chunk

    monkeypatch.setattr(resource_contract.os, "read", read_then_replace_parent)
    with pytest.raises(ValueError, match="ancestor changed"):
        netguard.read_resolution_remainder(record)


@pytest.mark.parametrize(
    ("host", "cause"),
    [
        ("a" * 254, "corpus-deadline"),
        ("_invalid.invalid", "corpus-deadline"),
        ("one.invalid", "caller-selected-cause"),
    ],
    ids=("host-too-long", "host-grammar", "cause-vocabulary"),
)
def test_resolver_remainder_replay_requires_closed_host_and_cause_grammar(
        tmp_path, host, cause):
    record = tmp_path / "strict.json"
    document = {
        "schema_version": "quarry.resolver-remainder.v1",
        "lane": "netguard.resolve",
        "measure": "hosts",
        "count": 1,
        "work": [{"host": host, "cause": cause}],
    }
    record.write_bytes(resource_contract.canonical_bytes(document))
    record.chmod(0o600)
    with pytest.raises(ValueError, match="work item"):
        netguard.read_resolution_remainder(record)


def test_resolver_corpus_deadline_retains_exact_replayable_work(tmp_path, monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"mode": "hang"})
    path = tmp_path / "resolver-remainder.json"
    hosts = [f"h{index}.invalid" for index in range(32)]
    started = time.monotonic()
    batch = netguard.resolve_many(
        hosts, timeout=5, corpus_deadline_s=0.15, max_outstanding=4,
        remainder_path=path,
    )
    elapsed = time.monotonic() - started
    assert elapsed < 2
    assert batch.sealed is True and set(batch) == set(hosts)
    assert all(value == ([], "indeterminate") for value in batch.values())
    assert batch.metrics["worker_processes"] <= 4
    assert batch.metrics["outstanding_queue"] <= 4
    assert batch.metrics["deadline_expired"] is True
    record = netguard.read_resolution_remainder(path)
    assert record["count"] == len(hosts)
    assert {item["host"] for item in record["work"]} == set(hosts)
    remainder = batch.remainder.as_record()
    assert remainder["retriable"]["now"] == len(hosts)
    assert not any(remainder["terminal"].values())
    assert remainder["detail"]["payload_retained"] is True
    assert netguard.active_worker_count() == 0


def test_zero_resolver_corpus_deadline_attempts_nothing_and_retains_every_host(
        tmp_path, monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"all": ["1.2.3.4"]})
    path = tmp_path / "zero-deadline.json"
    batch = netguard.resolve_many(
        ["a.invalid", "b.invalid"], corpus_deadline_s=0,
        remainder_path=path,
    )
    assert batch.metrics["attempted_hosts"] == 0
    assert batch.metrics["deadline_expired"] is True
    assert batch.remainder.retriable == 2
    assert netguard.read_resolution_remainder(path)["count"] == 2


def test_unsized_resolver_input_is_refused_before_any_obligation_is_accepted(monkeypatch):
    contacted = {"value": False}

    def corpus():
        contacted["value"] = True
        yield "never.invalid"

    with pytest.raises(TypeError, match="finite sized"):
        netguard.resolve_many(corpus())
    assert contacted["value"] is False


def test_dishonest_sized_resolver_iterator_is_capped_then_refused(monkeypatch):
    monkeypatch.setattr(resource_contract, "MAX_RESOLVER_HOSTS", 2)

    class DishonestCorpus:
        consumed = 0

        def __len__(self):
            return 3

        def __iter__(self):
            while True:
                self.consumed += 1
                yield f"h{self.consumed}.invalid"

    corpus = DishonestCorpus()
    with pytest.raises(netguard.ResolverCorpusRefused) as caught:
        netguard.resolve_many(corpus)
    assert corpus.consumed == 4
    batch = caught.value.resolution_batch
    assert dict(batch) == {}
    assert batch.metrics["input_hosts"] is None
    assert batch.metrics["input_count_exact"] is False
    assert batch.metrics["observed_input_hosts_lower_bound"] == 4
    assert batch.remainder.unit == "netguard.resolve:corpus"
    assert batch.remainder.measure == "corpora"
    assert batch.remainder.retriable == 0
    assert batch.remainder.terminal == {"unschedulable": 1}
    assert batch.remainder.detail["reason"] == "input-too-large-or-unbounded"
    assert batch.remainder.detail["exact_host_count"] is False
    assert netguard.active_worker_count() == 0


def test_oversized_resolver_identity_is_refused_before_contact(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"all": ["1.2.3.4"]})
    with pytest.raises(ValueError, match="host inside the published byte envelope"):
        netguard.resolve_many(["x" * (resource_contract.MAX_RESOLVER_HOST_BYTES + 1)])
    assert netguard.active_worker_count() == 0


def test_partial_worker_frame_cannot_block_past_the_corpus_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(netguard, "_resolve_child", _partial_resolution_frame)
    started = time.monotonic()
    path = tmp_path / "partial-frame.json"
    batch = netguard.resolve_many(
        ["partial.invalid"], timeout=10, corpus_deadline_s=0.05,
        remainder_path=path,
    )
    assert time.monotonic() - started < 2
    assert batch["partial.invalid"] == ([], "indeterminate")
    assert netguard.read_resolution_remainder(path)["work"] == [
        {"cause": "corpus-deadline", "host": "partial.invalid"},
    ]
    assert netguard.active_worker_count() == 0


def test_process_constructor_fault_closes_both_pipe_owners_with_traceback_retained(monkeypatch):
    fault = RuntimeError("process constructor failed")
    base = multiprocessing.get_context("fork")
    monkeypatch.setattr(
        netguard, "_spawn_context", lambda: _ConstructorFaultContext(base, fault),
    )
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(RuntimeError) as caught:
        netguard.resolve_many(["constructor.invalid"], corpus_deadline_s=1)
    assert caught.value is fault
    retained = caught.value
    gc.collect()
    assert retained.__traceback__ is not None
    assert len(os.listdir("/proc/self/fd")) == before


def test_process_start_fault_closes_both_pipe_owners_with_traceback_retained(monkeypatch):
    fault = RuntimeError("process start failed")
    base = multiprocessing.get_context("fork")
    monkeypatch.setattr(
        netguard, "_spawn_context", lambda: _StartFaultContext(base, fault),
    )
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(RuntimeError) as caught:
        netguard.resolve_many(["start.invalid"], corpus_deadline_s=1)
    assert caught.value is fault
    retained = caught.value
    gc.collect()
    assert retained.__traceback__ is not None
    assert len(os.listdir("/proc/self/fd")) == before


def test_unretained_resolver_work_is_terminal_not_fake_replay(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"mode": "hang"})
    batch = netguard.resolve_many(
        ["a.invalid", "b.invalid"], timeout=2, corpus_deadline_s=0.05,
        max_outstanding=1,
    )
    remainder = batch.remainder.as_record()
    assert remainder["retriable"] == {"now": 0, "cooldown": 0}
    assert remainder["terminal"]["machinery"] == 2
    assert remainder["detail"]["payload_retained"] is False


def test_cancellation_reclaims_workers_and_attaches_durable_sealed_remainder(
        tmp_path, monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"mode": "hang"})
    path = tmp_path / "cancelled.json"
    real_wait = netguard._mpc.wait
    calls = {"count": 0}

    def interrupt_once(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise KeyboardInterrupt()
        return real_wait(*args, **kwargs)

    monkeypatch.setattr(netguard._mpc, "wait", interrupt_once)
    with pytest.raises(KeyboardInterrupt) as caught:
        netguard.resolve_many(
            [f"h{index}.invalid" for index in range(8)], timeout=10,
            corpus_deadline_s=10, max_outstanding=4, remainder_path=path,
        )
    batch = caught.value.resolution_batch
    assert batch.sealed is True
    assert batch.remainder.retriable == 8
    assert netguard.read_resolution_remainder(path)["count"] == 8
    assert netguard.active_worker_count() == 0


def test_repeated_cleanup_cancellation_is_deferred_until_all_workers_are_reaped(
        tmp_path, monkeypatch):
    import multiprocessing.process

    monkeypatch.setattr(netguard, "_STUB", {"mode": "hang"})
    original = KeyboardInterrupt("original resolver cancellation")
    wait_calls = {"count": 0}
    real_wait = netguard._mpc.wait

    def cancel_wait(*args, **kwargs):
        wait_calls["count"] += 1
        if wait_calls["count"] == 1:
            raise original
        return real_wait(*args, **kwargs)

    real_terminate = multiprocessing.process.BaseProcess.terminate
    real_join = multiprocessing.process.BaseProcess.join
    cleanup_calls = {"terminate": 0, "join": 0}

    def cancelling_terminate(self):
        cleanup_calls["terminate"] += 1
        real_terminate(self)
        if cleanup_calls["terminate"] <= 2:
            raise SystemExit("cleanup terminate cancellation")

    def cancelling_join(self, timeout=None):
        cleanup_calls["join"] += 1
        result = real_join(self, timeout)
        if cleanup_calls["join"] <= 2:
            raise KeyboardInterrupt("cleanup join cancellation")
        return result

    monkeypatch.setattr(netguard._mpc, "wait", cancel_wait)
    monkeypatch.setattr(multiprocessing.process.BaseProcess, "terminate", cancelling_terminate)
    monkeypatch.setattr(multiprocessing.process.BaseProcess, "join", cancelling_join)
    path = tmp_path / "repeated-cancellation.json"
    with pytest.raises(KeyboardInterrupt) as caught:
        netguard.resolve_many(
            [f"h{index}.invalid" for index in range(6)], timeout=10,
            corpus_deadline_s=10, max_outstanding=3, remainder_path=path,
        )
    assert caught.value is original
    assert netguard.read_resolution_remainder(path)["count"] == 6
    assert netguard.active_worker_count() == 0
    assert getattr(caught.value, "resolver_cleanup_errors", ())


def test_cleanup_cancellation_outranks_an_ordinary_resolver_fault_after_full_reap(
        tmp_path, monkeypatch):
    import multiprocessing.process

    monkeypatch.setattr(netguard, "_STUB", {"mode": "hang"})
    operation_fault = OSError("resolver wait failed")
    cleanup_cancellation = KeyboardInterrupt("terminate cancellation")
    wait_calls = {"count": 0}

    def fail_wait(*_args, **_kwargs):
        wait_calls["count"] += 1
        raise operation_fault

    real_terminate = multiprocessing.process.BaseProcess.terminate
    fired = {"value": False}

    def cancel_terminate_after_effect(self):
        real_terminate(self)
        if not fired["value"]:
            fired["value"] = True
            raise cleanup_cancellation

    monkeypatch.setattr(netguard._mpc, "wait", fail_wait)
    monkeypatch.setattr(
        multiprocessing.process.BaseProcess, "terminate", cancel_terminate_after_effect,
    )
    path = tmp_path / "cleanup-cancel.json"
    with pytest.raises(KeyboardInterrupt) as caught:
        netguard.resolve_many(
            ["a.invalid", "b.invalid"], timeout=10, corpus_deadline_s=10,
            max_outstanding=2, remainder_path=path,
        )
    assert caught.value is cleanup_cancellation
    assert caught.value.resolver_operation_error is operation_fault
    assert caught.value.resolution_batch.remainder.retriable == 2
    assert netguard.read_resolution_remainder(path)["count"] == 2
    assert netguard.active_worker_count() == 0


def test_crashed_worker_is_reclaimed_and_its_host_is_durable_remainder(tmp_path, monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"mode": "crash"})
    path = tmp_path / "crashed.json"
    batch = netguard.resolve_many(
        ["crash.invalid"], timeout=2, corpus_deadline_s=2,
        remainder_path=path,
    )
    assert batch["crash.invalid"] == ([], "indeterminate")
    assert netguard.read_resolution_remainder(path)["work"] == [
        {"cause": "worker-failure", "host": "crash.invalid"},
    ]
    assert netguard.active_worker_count() == 0


def test_late_result_cannot_mutate_published_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"mode": "slow", "delay": 0.3})
    batch = netguard.resolve_many(
        ["late.invalid"], timeout=2, corpus_deadline_s=0.05,
        remainder_path=tmp_path / "late.json",
    )
    before = dict(batch)
    time.sleep(0.35)
    assert dict(batch) == before == {"late.invalid": ([], "indeterminate")}
    with pytest.raises(TypeError, match="sealed"):
        batch["late.invalid"] = (["9.9.9.9"], "ok")
    assert netguard.active_worker_count() == 0


def test_resolution_batch_has_no_base_dict_or_nested_mutation_bypass(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"all": ["1.2.3.4"]})
    batch = netguard.resolve_many(["sealed.invalid"], corpus_deadline_s=1)
    assert isinstance(batch, Mapping)
    assert not isinstance(batch, dict)
    addresses = batch["sealed.invalid"][0]
    assert isinstance(addresses, tuple)
    with pytest.raises(TypeError):
        dict.__setitem__(batch, "sealed.invalid", (["9.9.9.9"], "ok"))
    with pytest.raises(AttributeError):
        addresses.append("9.9.9.9")
    with pytest.raises(TypeError):
        batch.metrics["resolved_hosts"] = 0
    with pytest.raises(TypeError, match="sealed"):
        batch.sealed = False
    assert batch["sealed.invalid"] == (["1.2.3.4"], "ok")


def test_resolution_batch_deep_snapshots_its_mutable_remainder():
    source = remainder_contract.Remainder(
        lane="netguard.resolve",
        unit="netguard.resolve:hosts",
        measure="hosts",
        model="project_progress",
        terminal={"machinery": 1},
        detail={"nested": {"causes": ["worker-failure"]}},
    )
    batch = netguard.ResolutionBatch(
        {}, unresolved_hosts=(), remainder=source, metrics={},
    )
    source.terminal["machinery"] = 9
    source.detail["nested"]["causes"].append("late")

    snapshot = batch.remainder
    assert isinstance(snapshot, tuple)
    assert snapshot.terminal == {"machinery": 1}
    assert snapshot.detail["nested"]["causes"] == ("worker-failure",)
    snapshot.validate()
    with pytest.raises(TypeError):
        snapshot.terminal["machinery"] = 0
    with pytest.raises(TypeError):
        snapshot.detail["nested"]["new"] = True
    with pytest.raises(AttributeError):
        snapshot.detail["nested"]["causes"].append("cancelled")
    with pytest.raises((AttributeError, TypeError)):
        snapshot.now = 7
    with pytest.raises((AttributeError, TypeError)):
        object.__setattr__(snapshot, "now", 7)
    with pytest.raises(TypeError):
        dict.__setitem__(snapshot.detail, "nested", {})

    detached = snapshot.as_record()
    detached["terminal"]["machinery"] = 0
    detached["detail"]["nested"]["causes"].append("cancelled")
    assert snapshot.terminal == {"machinery": 1}
    assert snapshot.detail["nested"]["causes"] == ("worker-failure",)


def test_oversize_resolver_corpus_is_refused_with_exact_durable_work(tmp_path, monkeypatch):
    monkeypatch.setattr(resource_contract, "MAX_RESOLVER_HOSTS", 2)
    path = tmp_path / "oversize.json"
    corpus = _ObservedSizedCorpus(["a.invalid", "b.invalid", "c.invalid"])
    with pytest.raises(netguard.ResolverCorpusRefused) as caught:
        netguard.resolve_many(corpus, remainder_path=path)
    batch = caught.value.resolution_batch
    assert corpus.consumed == 3 and corpus.exhaustion_proved is True
    assert batch.metrics["attempted_hosts"] == 0
    assert batch.remainder.retriable == 3
    assert netguard.read_resolution_remainder(path)["count"] == 3


def test_far_oversize_resolver_corpus_is_terminal_without_materializing_a_fake_payload(
        tmp_path, monkeypatch):
    monkeypatch.setattr(resource_contract, "MAX_RESOLVER_HOSTS", 2)
    path = tmp_path / "must-not-be-created.json"
    corpus = _ObservedSizedCorpus(
        ["a.invalid", "b.invalid", "c.invalid", "d.invalid"],
    )
    with pytest.raises(netguard.ResolverCorpusRefused) as caught:
        netguard.resolve_many(corpus, remainder_path=path)
    batch = caught.value.resolution_batch
    assert corpus.consumed == 4 and corpus.exhaustion_proved is False
    assert dict(batch) == {}
    assert batch.metrics["input_hosts"] is None
    assert batch.metrics["unresolved_hosts"] is None
    assert batch.metrics["input_count_exact"] is False
    assert batch.metrics["observed_input_hosts_lower_bound"] == 4
    assert batch.remainder.retriable == 0
    assert batch.remainder.terminal == {"unschedulable": 1}
    assert batch.remainder.detail["payload_retained"] is False
    assert batch.remainder.detail["replayable"] is False
    assert batch.remainder.detail["reason"] == "input-too-large-or-unbounded"
    assert batch.remainder.detail["exact_host_count"] is False
    assert batch.remainder.detail["observed_hosts_lower_bound"] == 4
    assert not path.exists()


def test_aggregate_snapshot_counts_process_tree_rss_disk_fds_and_processes(tmp_path):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"x" * 4096)
    ctx = multiprocessing.get_context("fork")
    child = ctx.Process(target=_idle_child)
    child.start()
    try:
        deadline = time.monotonic() + 2
        snapshot = resource_contract.aggregate_snapshot(disk_root=tmp_path)
        while snapshot.peak_process_count < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
            snapshot = resource_contract.aggregate_snapshot(disk_root=tmp_path)
        assert snapshot.complete is True
        assert snapshot.peak_aggregate_rss_bytes > 0
        assert snapshot.peak_disk_bytes >= 4096
        assert snapshot.peak_fd_count > 0
        assert snapshot.peak_process_count >= 2
    finally:
        child.terminate()
        child.join(5)


def test_snapshot_missing_disk_root_is_incomplete_and_record_keys_match_gate_contract(tmp_path):
    snapshot = resource_contract.aggregate_snapshot(disk_root=tmp_path / "missing")
    assert snapshot.complete is False
    assert set(snapshot.as_record()) == resource_contract._RESOURCE_KEYS
