"""Focused authority gates for deterministic managed-acquisition leases."""
from __future__ import annotations

import io
import fcntl
import errno
import inspect
import os
import select
import signal
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from quarry_recon import contract, privfs, store


pytestmark = pytest.mark.offline


def _run(tmp_path: Path, run_id="acquisition-claim"):
    run = store.Run.create(tmp_path, "acme.example", run_id=run_id)
    run.write_state("running")
    dest = run.raw_path("params", "managed", "body.bin")
    return run, dest, tuple(dest.relative_to(run.dir).parts)


def _claim_markers(run) -> list[Path]:
    return list((run.project_dir / "recon" / "state" / "claims" / run.run_id).glob("*.claim"))


def test_destination_marker_is_deterministic_live_and_blocks_sealing(tmp_path):
    run, _dest, components = _run(tmp_path)
    expected_name, _key, _body = store._managed_acquisition_marker_material(
        run.run_id, components,
    )

    with run.managed_acquisition_claim(*components) as transaction:
        markers = _claim_markers(run)
        assert [marker.name for marker in markers] == [expected_name]
        assert len(expected_name.removesuffix(".claim")) == 32
        opened = store.Run.open(tmp_path, "acme.example", run.run_id)
        started = time.monotonic()
        with pytest.raises(Exception, match="live artifact claim"):
            opened.begin_finalization()
        assert time.monotonic() - started < 0.5
        transaction.settle_precontact()

    assert _claim_markers(run) == []
    run.begin_finalization()


def test_same_destination_threads_serialize_but_distinct_destinations_do_not(tmp_path):
    run, first, first_components = _run(tmp_path, "thread-destination-lease")
    second = run.raw_path("params", "managed", "other.bin")
    second_components = tuple(second.relative_to(run.dir).parts)
    entered_first = threading.Event()
    release_first = threading.Event()
    entered_same = threading.Event()
    entered_other = threading.Event()

    def owner():
        with run.managed_acquisition_claim(*first_components) as transaction:
            entered_first.set()
            assert release_first.wait(5)
            transaction.settle_precontact()

    def same():
        opened = store.Run.open(tmp_path, "acme.example", run.run_id)
        with opened.managed_acquisition_claim(*first_components) as transaction:
            entered_same.set()
            transaction.settle_precontact()

    def other():
        opened = store.Run.open(tmp_path, "acme.example", run.run_id)
        with opened.managed_acquisition_claim(*second_components) as transaction:
            entered_other.set()
            transaction.settle_precontact()

    first_thread = threading.Thread(target=owner)
    same_thread = threading.Thread(target=same)
    other_thread = threading.Thread(target=other)
    first_thread.start()
    assert entered_first.wait(5)
    same_thread.start(); other_thread.start()
    assert entered_other.wait(2)
    assert not entered_same.wait(0.1)
    release_first.set()
    for thread in (first_thread, same_thread, other_thread):
        thread.join(5)
        assert not thread.is_alive()
    assert entered_same.is_set() and _claim_markers(run) == []


def test_cancelled_existing_marker_waiter_cannot_drop_live_owner_advisory(tmp_path, monkeypatch):
    run, _dest, components = _run(tmp_path, "cancelled-waiter-advisory")
    owner_context = run.managed_acquisition_claim(*components)
    owner = owner_context.__enter__()
    cancellation = KeyboardInterrupt("cancel existing-marker waiter")
    waiter_reached = threading.Event()
    waiter_errors: list[BaseException] = []

    def cancel_wait(waiter_marker):
        assert waiter_marker.marker.identity == owner.marker.marker.identity
        waiter_reached.set()
        raise cancellation

    monkeypatch.setattr(
        store._ManagedAcquisitionMarker, "_wait_for_existing", cancel_wait,
    )

    def wait_for_owner():
        try:
            opened = store.Run.open(tmp_path, "acme.example", run.run_id)
            with opened.managed_acquisition_claim(*components):
                pytest.fail("cancelled waiter entered the destination lease")
        except BaseException as exc:
            waiter_errors.append(exc)

    waiter = threading.Thread(target=wait_for_owner)
    waiter.start(); waiter.join(2)
    assert waiter_reached.is_set() and not waiter.is_alive()
    assert waiter_errors == [cancellation]
    active = store._ACQUISITION_ACTIVE.get(owner.marker.local_key)
    assert active is not None and active[2] is owner.marker

    started = time.monotonic()
    with pytest.raises(store.ManagedAcquisitionRefused, match="already claimed"):
        with run.managed_acquisition_claim(*components):
            pytest.fail("recursive owner re-entered after waiter cancellation")
    assert time.monotonic() - started < 0.5

    owner.settle_precontact()
    owner_context.__exit__(None, None, None)
    assert owner.marker.local_key not in store._ACQUISITION_ACTIVE
    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()


def test_process_waiter_accepts_clean_unlink_before_owner_unlock(tmp_path, monkeypatch):
    run, _dest, components = _run(tmp_path, "unlink-before-unlock")
    unlinked_read, unlinked_write = os.pipe()
    release_read, release_write = os.pipe()
    real_unlink = os.unlink
    paused = False

    def pause_after_marker_unlink(path, *, dir_fd=None):
        nonlocal paused
        result = real_unlink(path, dir_fd=dir_fd)
        if str(path).endswith(".claim") and not paused:
            paused = True
            os.write(unlinked_write, b"u")
            assert os.read(release_read, 1) == b"x"
        return result

    monkeypatch.setattr(os, "unlink", pause_after_marker_unlink)
    owner = os.fork()
    if owner == 0:  # pragma: no cover - parent owns assertions
        try:
            os.close(unlinked_read); os.close(release_write)
            opened = store.Run.open(tmp_path, "acme.example", run.run_id)
            with opened.managed_acquisition_claim(*components) as transaction:
                transaction.settle_precontact()
        except BaseException:
            os._exit(70)
        os._exit(0)

    os.close(unlinked_write); os.close(release_read)
    ready, _, _ = select.select([unlinked_read], [], [], 5)
    assert ready and os.read(unlinked_read, 1) == b"u"
    monkeypatch.setattr(os, "unlink", real_unlink)
    waiter_result = tmp_path / "waiter-result"
    waiter = os.fork()
    if waiter == 0:  # pragma: no cover - parent owns assertions
        try:
            os.close(unlinked_read); os.close(release_write)
            opened = store.Run.open(tmp_path, "acme.example", run.run_id)
            with opened.managed_acquisition_claim(*components) as transaction:
                waiter_result.write_text("entered")
                transaction.settle_precontact()
        except BaseException as exc:
            waiter_result.write_text(f"error:{type(exc).__name__}:{exc}")
            os._exit(70)
        os._exit(0)

    time.sleep(0.1)
    assert not waiter_result.exists()
    os.write(release_write, b"x")
    _, owner_status = os.waitpid(owner, 0)
    _, waiter_status = os.waitpid(waiter, 0)
    os.close(unlinked_read); os.close(release_write)
    assert os.waitstatus_to_exitcode(owner_status) == 0
    assert os.waitstatus_to_exitcode(waiter_status) == 0
    assert waiter_result.read_text() == "entered"


def test_process_crash_leaves_stale_marker_and_never_recycles_contact_authority(tmp_path):
    run, _dest, components = _run(tmp_path, "crash-stale-destination")
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - parent owns assertions
        try:
            os.close(ready_read); os.close(release_write)
            opened = store.Run.open(tmp_path, "acme.example", run.run_id)
            with opened.managed_acquisition_claim(*components):
                os.write(ready_write, b"x")
                os.read(release_read, 1)
        finally:
            os._exit(0)

    os.close(ready_write); os.close(release_read)
    try:
        ready, _, _ = select.select([ready_read], [], [], 5)
        assert ready and os.read(ready_read, 1) == b"x"
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
    finally:
        os.close(ready_read); os.close(release_write)

    opened = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(store.ManagedAcquisitionRefused, match="crash-stale"):
        with opened.managed_acquisition_claim(*components):
            pytest.fail("a crash-stale lease granted authority")
    assert len(_claim_markers(run)) == 1


def test_process_crash_in_release_quarantine_never_recycles_contact_authority(
    tmp_path, monkeypatch,
):
    run, _dest, components = _run(tmp_path, "crash-release-quarantine")
    other_components = components[:-1] + ("other.bin",)
    ready_read, ready_write = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - parent owns assertions
        try:
            os.close(ready_read)
            opened = store.Run.open(tmp_path, "acme.example", run.run_id)
            with opened.managed_acquisition_claim(*components) as transaction:
                release = store._ManagedPairRelease(
                    transaction.marker, lambda: None,
                )
                transaction.marker.release_owner = release
                with opened._mutation(store.MutationScope.BASE_EVIDENCE):
                    release._provisional_unlink_locked()
                    release._unlink_exact_name_locked(
                        transaction.marker.name, expected_after=1,
                    )
                    os.fsync(transaction.marker.directory.fd)
                os.write(ready_write, b"q")
                signal.pause()
        except BaseException:
            os._exit(70)
        os._exit(0)

    os.close(ready_write)
    try:
        ready, _, _ = select.select([ready_read], [], [], 5)
        assert ready and os.read(ready_read, 1) == b"q"
        deterministic = store._managed_acquisition_marker_material(
            run.run_id, components,
        )[0]
        markers = _claim_markers(run)
        assert len(markers) == 1 and markers[0].name != deterministic
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
    finally:
        os.close(ready_read)

    opened = store.Run.open(tmp_path, "acme.example", run.run_id)
    quarantine, = _claim_markers(run)
    saved = quarantine.with_name(quarantine.name + ".saved")
    real_open = store._OwnedDescriptor.open
    substituted = False

    def substitute_between_scan_stat_and_open(
        owner, path, flags, mode=0o777, *, dir_fd=None,
    ):
        nonlocal substituted
        if str(path) == quarantine.name and not substituted:
            substituted = True
            quarantine.rename(saved)
            quarantine.write_bytes(b"foreign claim replacement")
            quarantine.chmod(0o600)
        return real_open(owner, path, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(
            store._OwnedDescriptor, "open",
            substitute_between_scan_stat_and_open,
        )
        with pytest.raises(
            store.ManagedAcquisitionRefused, match="changed while scanned",
        ):
            with opened.managed_acquisition_claim(*components):
                pytest.fail("a substituted quarantine granted authority")
    assert substituted
    quarantine.unlink()
    saved.rename(quarantine)

    started = time.monotonic()
    with pytest.raises(
        store.ManagedAcquisitionRefused, match="crash-stale.*release name",
    ):
        with opened.managed_acquisition_claim(*components):
            pytest.fail("a quarantined crash marker granted contact authority")
    assert time.monotonic() - started < 0.5
    # The registry scan matches the full canonical destination body, so an
    # unrelated destination in the same Run remains independently usable.
    with opened.managed_acquisition_claim(*other_components) as transaction:
        transaction.settle_precontact()


def test_live_marker_substitution_refuses_contender_and_owner_preserves_substitute(tmp_path):
    run, _dest, components = _run(tmp_path, "substituted-destination")
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def owner():
        try:
            with run.managed_acquisition_claim(*components) as transaction:
                transaction.settle_precontact()
                entered.set()
                assert release.wait(5)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=owner)
    thread.start()
    assert entered.wait(5)
    marker = _claim_markers(run)[0]
    marker.unlink()
    marker.write_text('{"substituted":true}')
    marker.chmod(0o600)

    opened = store.Run.open(tmp_path, "acme.example", run.run_id)
    started = time.monotonic()
    with pytest.raises(store.ManagedAcquisitionRefused, match="substituted|unsafe"):
        with opened.managed_acquisition_claim(*components):
            pytest.fail("a substituted lease granted authority")
    assert time.monotonic() - started < 0.5
    release.set(); thread.join(5)
    assert errors and marker.read_text() == '{"substituted":true}'


def test_live_marker_substitution_refuses_body_publication_before_namespace_effect(tmp_path):
    run, dest, components = _run(tmp_path, "substituted-before-body-cas")
    context = run.managed_acquisition_claim(*components)
    transaction = context.__enter__()
    transaction.settle_precontact()
    writer = transaction.open_writer()
    contract.stream_to_fd(
        io.BytesIO(b"candidate must remain unpublished"), writer,
        budget_path=dest.parent,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    marker = _claim_markers(run)[0]
    marker.unlink()
    marker.write_text('{"substituted":true}')
    marker.chmod(0o600)

    with pytest.raises(store.ManagedAcquisitionRefused, match="substituted|unsafe"):
        transaction.publish_body_if_absent()
    with pytest.raises(store.ManagedAcquisitionRefused):
        context.__exit__(None, None, None)

    assert not dest.exists()
    assert marker.read_text() == '{"substituted":true}'


def test_owned_marker_body_must_remain_byte_exact_before_stage_effect(tmp_path):
    run, dest, components = _run(tmp_path, "owned-marker-body-exact")
    context = run.managed_acquisition_claim(*components)
    transaction = context.__enter__()
    transaction.settle_precontact()
    marker = _claim_markers(run)[0]
    changed = transaction.marker.body[:-1] + b',"extra":true}'
    marker.write_bytes(changed)
    marker.chmod(0o600)

    with pytest.raises(store.ManagedAcquisitionRefused, match="body changed"):
        transaction.open_writer()
    with pytest.raises(store.ManagedAcquisitionRefused, match="body changed"):
        context.__exit__(None, None, None)
    assert not dest.exists() and marker.read_bytes() == changed


def test_exact_marker_descriptor_must_hold_flock_before_stage_effect(tmp_path):
    run, dest, components = _run(tmp_path, "owned-marker-flock-exact")
    context = run.managed_acquisition_claim(*components)
    transaction = context.__enter__()
    transaction.settle_precontact()
    owner_fd = transaction.marker.marker.fd
    marker = _claim_markers(run)[0]
    fcntl.flock(owner_fd, fcntl.LOCK_UN)
    foreign_fd = os.open(marker, os.O_RDWR | os.O_NOFOLLOW)
    fcntl.flock(foreign_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(store.ManagedAcquisitionRefused, match="another owner"):
            transaction.open_writer()
        with pytest.raises(store.ManagedAcquisitionRefused, match="another owner"):
            context.__exit__(None, None, None)
        assert not dest.exists()
    finally:
        fcntl.flock(foreign_fd, fcntl.LOCK_UN)
        os.close(foreign_fd)


def test_forked_child_cannot_use_or_settle_parent_destination_lease(tmp_path):
    run, _dest, components = _run(tmp_path, "fork-inherited-destination")
    context = run.managed_acquisition_claim(*components)
    transaction = context.__enter__()
    transaction.settle_precontact()
    marker = _claim_markers(run)[0]
    child = os.fork()
    if child == 0:  # pragma: no cover - parent owns assertions
        result = 0
        try:
            try:
                transaction.snapshot(components)
            except store.ManagedAcquisitionRefused:
                result |= 1
            try:
                context.__exit__(None, None, None)
            except store.ManagedAcquisitionRefused:
                result |= 2
            if marker.exists():
                result |= 4
        finally:
            os._exit(0 if result == 7 else 70)

    _waited, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert marker.exists()
    opened = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(Exception, match="live artifact claim"):
        opened.begin_finalization()
    context.__exit__(None, None, None)
    assert not marker.exists()
    opened.begin_finalization()


def test_fork_child_preserves_reused_borrowed_writer_fd_and_closes_owned_graph(tmp_path):
    run, _dest, components = _run(tmp_path, "fork-reused-borrowed-writer")
    context = run.managed_acquisition_claim(*components)
    transaction = context.__enter__()
    transaction.settle_precontact()
    writer = transaction.open_writer()
    os.close(writer)

    sentinel_path = tmp_path / "fork-fd-sentinel"
    sentinel_path.write_bytes(b"sentinel")
    source = os.open(sentinel_path, os.O_RDONLY)
    if source != writer:
        os.dup2(source, writer)
        os.close(source)
    sentinel_fd = writer
    assert os.read(sentinel_fd, 8) == b"sentinel"
    os.lseek(sentinel_fd, 0, os.SEEK_SET)

    stage = transaction.artifact._stage
    owned_fds = {
        transaction.anchor.fd,
        transaction.parent.fd,
        transaction.marker.marker.fd,
        transaction.marker.directory.fd,
        stage.file_fd,
        stage.parent_fd,
        stage.anchor_fd,
    }
    owned_fds.discard(-1)
    owned_fds.discard(sentinel_fd)
    assert owned_fds

    child = os.fork()
    if child == 0:  # pragma: no cover - parent owns assertions
        result = 0
        try:
            os.lseek(sentinel_fd, 0, os.SEEK_SET)
            if os.read(sentinel_fd, 8) == b"sentinel":
                result |= 1
            if all(
                _descriptor_is_closed(fd)
                for fd in owned_fds
            ):
                result |= 2
        finally:
            os._exit(0 if result == 3 else 70)

    _waited, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    os.close(sentinel_fd)
    context.__exit__(None, None, None)
    assert _claim_markers(run) == []


def _descriptor_is_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError as exc:
        return exc.errno == errno.EBADF
    return False


def test_idle_fork_child_does_not_keep_dead_parent_destination_flock_live(tmp_path):
    run, _dest, components = _run(tmp_path, "fork-idle-child-destination")
    status_read, status_write = os.pipe()
    idle_read, idle_write = os.pipe()
    owner = os.fork()
    if owner == 0:  # pragma: no cover - parent owns assertions
        try:
            os.close(status_read); os.close(idle_write)
            opened = store.Run.open(tmp_path, "acme.example", run.run_id)
            with opened.managed_acquisition_claim(*components):
                ready_read, ready_write = os.pipe()
                idle_child = os.fork()
                if idle_child == 0:
                    os.close(ready_read)
                    os.write(ready_write, b"r")
                    os.close(ready_write)
                    os.read(idle_read, 1)
                    os._exit(0)
                os.close(ready_write); os.close(idle_read)
                if os.read(ready_read, 1) != b"r":
                    os._exit(71)
                os.close(ready_read)
                os.write(status_write, f"{idle_child}\n".encode("ascii"))
                signal.pause()
        except BaseException:
            os._exit(70)
        os._exit(0)

    os.close(status_write); os.close(idle_read)
    contender = None
    contender_read = contender_write = None
    idle_child = None
    try:
        ready, _, _ = select.select([status_read], [], [], 5)
        assert ready
        idle_child = int(os.read(status_read, 64).strip())
        assert idle_child > 0
        assert len(_claim_markers(run)) == 1
        os.kill(owner, signal.SIGKILL)
        os.waitpid(owner, 0)
        os.kill(idle_child, 0)

        contender_read, contender_write = os.pipe()
        contender = os.fork()
        if contender == 0:  # pragma: no cover - parent owns assertions
            try:
                os.close(contender_read)
                opened = store.Run.open(tmp_path, "acme.example", run.run_id)
                try:
                    with opened.managed_acquisition_claim(*components):
                        result = b"entered"
                except store.ManagedAcquisitionRefused as exc:
                    result = f"refused:{exc}".encode("utf-8")
                os.write(contender_write, result)
            except BaseException as exc:
                os.write(
                    contender_write,
                    f"error:{type(exc).__name__}:{exc}".encode("utf-8"),
                )
                os._exit(70)
            os._exit(0)

        os.close(contender_write); contender_write = None
        prompt, _, _ = select.select([contender_read], [], [], 1)
        assert prompt, "contender blocked on an idle child's inherited marker OFD"
        result = os.read(contender_read, 4096).decode("utf-8")
        _waited, status = os.waitpid(contender, 0)
        contender = None
        assert os.waitstatus_to_exitcode(status) == 0
        assert result.startswith("refused:") and "crash-stale" in result
        with pytest.raises(Exception, match="live artifact claim"):
            run.begin_finalization()
    finally:
        if contender is not None:
            os.kill(contender, signal.SIGKILL)
            os.waitpid(contender, 0)
        for fd in (status_read, contender_read, contender_write):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if idle_child is not None:
            try:
                os.kill(idle_child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        os.close(idle_write)


def test_claim_streams_one_stage_and_never_replaces_a_prior(tmp_path):
    run, dest, components = _run(tmp_path, "claim-cas")
    dest.write_bytes(b"prior")
    dest.chmod(0o600)
    with run.managed_acquisition_claim(*components) as claim:
        claim.settle_precontact()
        writer = claim.open_writer()
        contract.stream_to_fd(
            io.BytesIO(b"candidate"), writer, budget_path=dest.parent,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )
        assert claim.publish_body_if_absent() is False
    assert dest.read_bytes() == b"prior"
    assert not list(dest.parent.glob(".quarry-*.stage"))


def test_repeated_companion_prior_replay_leaves_no_private_stage_growth(tmp_path):
    run, dest, components = _run(tmp_path, "companion-prior-no-growth")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    dest.write_bytes(b"prior-body")
    dest.chmod(0o600)
    receipt.write_bytes(b'{"prior":true}')
    receipt.chmod(0o600)

    for _ in range(16):
        with run.managed_acquisition_claim(*components) as claim:
            claim.settle_precontact()
            writer = claim.open_writer()
            contract.stream_to_fd(
                io.BytesIO(b"candidate"), writer, budget_path=dest.parent,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
            assert claim.publish_body_if_absent() is False
            assert claim.publish_companion_if_absent(
                receipt_components, b'{"candidate":true}',
            ) is False

    assert dest.read_bytes() == b"prior-body"
    assert receipt.read_bytes() == b'{"prior":true}'
    assert not list(dest.parent.glob(".quarry-*.stage"))
    assert _claim_markers(run) == []


def test_companion_publication_replays_only_the_exact_staged_generation(
    tmp_path, monkeypatch,
):
    run, _dest, components = _run(tmp_path, "companion-exact-replay")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    body = b'{"complete":true}'
    real_sync = privfs._fsync_managed
    fired = False

    def sync_then_report(fd):
        nonlocal fired
        if (not fired and stat.S_ISDIR(os.fstat(fd).st_mode)
                and receipt.exists()):
            fired = True
            real_sync(fd)
            raise OSError("companion directory fsync reported after commit")
        return real_sync(fd)

    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_fsync_managed", sync_then_report)
            with pytest.raises(privfs.PrivatePublishIfAbsentUncertain):
                transaction.publish_companion_if_absent(receipt_components, body)
        assert transaction.publish_companion_if_absent(receipt_components, body)
        assert transaction.publish_companion_if_absent(receipt_components, body)
        with pytest.raises(store.ContractError, match="changed on replay"):
            transaction.publish_companion_if_absent(receipt_components, body + b"x")

    assert fired and receipt.read_bytes() == body
    assert _claim_markers(run) == []


def _line_containing(function, needle: str, *, occurrence: int | None = None) -> int:
    lines, first = inspect.getsourcelines(function)
    matches = [first + index for index, line in enumerate(lines) if needle in line]
    if occurrence is not None:
        assert 0 <= occurrence < len(matches), (function, needle, matches)
        return matches[occurrence]
    assert len(matches) == 1, (function, needle, matches)
    return matches[0]


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_companion_owner_adoption_freezes_identity_before_exact_cancellation(
    tmp_path, cancellation_type,
):
    run, _dest, components = _run(
        tmp_path, f"companion-adoption-{cancellation_type.__name__}",
    )
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    body = b'{"adoption":"exact"}'
    cancellation = cancellation_type("companion canceled after owner adoption")
    operation = store._ManagedAcquisitionTransaction.publish_companion_if_absent
    after_adoption = _line_containing(operation, "artifact = companion.artifact")
    fired = False

    def trace(frame, event, _arg):
        nonlocal fired
        if (frame.f_code is operation.__code__ and event == "line"
                and frame.f_lineno == after_adoption and not fired):
            fired = True
            sys.settrace(None)
            raise cancellation
        return trace

    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()
        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                transaction.publish_companion_if_absent(receipt_components, body)
        finally:
            sys.settrace(previous)
        assert fired and caught.value is cancellation
        assert transaction.publish_companion_if_absent(receipt_components, body)

    assert receipt.read_bytes() == body
    assert _claim_markers(run) == []


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_companion_full_stage_is_authenticated_after_exact_write_cancellation(
    tmp_path, cancellation_type,
):
    run, _dest, components = _run(
        tmp_path, f"companion-full-write-{cancellation_type.__name__}",
    )
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    body = b'{"full-write":"retained and authenticated"}'
    cancellation = cancellation_type("companion canceled after full write")
    operation = store._ManagedAcquisitionTransaction.publish_companion_if_absent
    before_adoption = _line_containing(
        operation, "companion.staged = True", occurrence=0,
    )
    fired = False

    def trace(frame, event, _arg):
        nonlocal fired
        if (frame.f_code is operation.__code__ and event == "line"
                and frame.f_lineno == before_adoption and not fired):
            fired = True
            sys.settrace(None)
            raise cancellation
        return trace

    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()
        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                transaction.publish_companion_if_absent(receipt_components, body)
        finally:
            sys.settrace(previous)
        assert fired and caught.value is cancellation
        assert transaction.publish_companion_if_absent(receipt_components, body)

    assert receipt.read_bytes() == body
    assert _claim_markers(run) == []


def test_companion_full_write_then_reported_fault_replays_exact_stage(
    tmp_path, monkeypatch,
):
    run, _dest, components = _run(tmp_path, "companion-full-write-fault")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    body = b'{"write":"landed before error"}'
    real_write = os.write
    fired = False

    def write_then_report(fd, data):
        nonlocal fired
        written = real_write(fd, data)
        if not fired:
            fired = True
            assert written == len(data)
            raise OSError("companion write reported after all bytes landed")
        return written

    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()
        with monkeypatch.context() as patch:
            patch.setattr(os, "write", write_then_report)
            with pytest.raises(OSError, match="all bytes landed"):
                transaction.publish_companion_if_absent(receipt_components, body)
        assert transaction.publish_companion_if_absent(receipt_components, body)

    assert fired and receipt.read_bytes() == body
    assert _claim_markers(run) == []


def test_companion_partial_write_fault_is_not_adopted_as_exact_stage(
    tmp_path, monkeypatch,
):
    run, _dest, components = _run(tmp_path, "companion-partial-write-fault")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    body = b'{"write":"only a prefix lands"}'
    real_write = os.write
    fired = False

    def write_prefix_then_report(fd, data):
        nonlocal fired
        if not fired:
            fired = True
            written = real_write(fd, data[: max(1, len(data) // 2)])
            assert 0 < written < len(data)
            raise OSError("companion write failed after a prefix")
        return real_write(fd, data)

    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()
        with monkeypatch.context() as patch:
            patch.setattr(os, "write", write_prefix_then_report)
            with pytest.raises(OSError, match="after a prefix"):
                transaction.publish_companion_if_absent(receipt_components, body)
        with pytest.raises(store.ContractError, match="partial or changed"):
            transaction.publish_companion_if_absent(receipt_components, body)

    assert fired and not receipt.exists()
    assert not list(receipt.parent.glob(".quarry-*.stage"))
    assert _claim_markers(run) == []


@pytest.mark.parametrize("forgery", [b"short", b'{"receipt":"FORGED"}'])
def test_companion_sealed_digest_refuses_same_inode_rewrite_before_cas(
    tmp_path, monkeypatch, forgery,
):
    run, _dest, components = _run(tmp_path, "companion-pre-cas-forgery")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    body = b'{"receipt":"EXACT!"}'
    assert len(forgery) != len(body) or forgery != body
    real_publish = privfs.publish_private_stage_if_absent
    fired = False

    def rewrite_then_publish(stage, target):
        nonlocal fired
        if not fired:
            fired = True
            fd = os.open(
                stage.temporary_name,
                os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
                dir_fd=stage.parent_fd,
            )
            try:
                view = memoryview(forgery)
                while view:
                    written = os.write(fd, view)
                    assert written > 0
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
        return real_publish(stage, target)

    with pytest.raises(privfs.PrivatePathUnsafe, match="changed after sealing"):
        with run.managed_acquisition_claim(*components) as transaction:
            transaction.settle_precontact()
            with monkeypatch.context() as patch:
                patch.setattr(
                    privfs, "publish_private_stage_if_absent",
                    rewrite_then_publish,
                )
                transaction.publish_companion_if_absent(receipt_components, body)

    assert fired and not receipt.exists()
    assert not list(receipt.parent.glob(".quarry-*.stage"))
    assert _claim_markers(run) == []


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_companion_committed_then_exact_wrapper_cancellation_replays_true(
    tmp_path, monkeypatch, cancellation_type,
):
    run, _dest, components = _run(
        tmp_path, f"companion-commit-cancel-{cancellation_type.__name__}",
    )
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    body = b'{"terminal":"committed"}'
    cancellation = cancellation_type("companion wrapper canceled after commit")
    real_publish = privfs.publish_private_stage_if_absent
    fired = False

    def publish_then_cancel(stage, target):
        nonlocal fired
        published = real_publish(stage, target)
        if published and not fired:
            fired = True
            raise cancellation
        return published

    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()
        with monkeypatch.context() as patch:
            patch.setattr(
                privfs, "publish_private_stage_if_absent", publish_then_cancel,
            )
            with pytest.raises(cancellation_type) as caught:
                transaction.publish_companion_if_absent(receipt_components, body)
        assert fired and caught.value is cancellation
        assert transaction.publish_companion_if_absent(receipt_components, body)

    assert receipt.read_bytes() == body
    assert _claim_markers(run) == []


def test_companion_terminal_false_cas_replays_false(tmp_path):
    run, _dest, components = _run(tmp_path, "companion-false-replay")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt = run.dir.joinpath(*receipt_components)
    receipt.write_bytes(b'{"prior":true}')
    receipt.chmod(0o600)

    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()
        assert not transaction.publish_companion_if_absent(
            receipt_components, b'{"candidate":true}',
        )
        assert not transaction.publish_companion_if_absent(
            receipt_components, b'{"candidate":true}',
        )

    assert receipt.read_bytes() == b'{"prior":true}'
    assert _claim_markers(run) == []


def _publish_managed_pair(run, dest, components, body=b"managed pair body"):
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    receipt_bytes = b'{"managed":"pair"}'
    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()
        writer = transaction.open_writer()
        contract.stream_to_fd(
            io.BytesIO(body), writer, budget_path=dest.parent,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )
        assert transaction.publish_body_if_absent() is True
        assert transaction.publish_companion_if_absent(
            receipt_components, receipt_bytes,
        ) is True
        body_snapshot = transaction.snapshot(components)
        receipt_snapshot = transaction.snapshot(
            receipt_components, content_limit=1024 * 1024,
        )
        assert body_snapshot is not None and receipt_snapshot is not None
    return receipt_components, body_snapshot, receipt_snapshot


def test_contact_attempt_without_terminal_pair_retains_marker_but_drains_owner(
    tmp_path,
):
    run, _dest, components = _run(tmp_path, "contact-without-terminal")
    baseline_fds = len(os.listdir("/proc/self/fd"))
    transaction = None
    with pytest.raises(store.ManagedAcquisitionRefused, match="abandoned"):
        with run.managed_acquisition_claim(*components) as transaction:
            transaction.mark_contact_attempted()

    assert transaction is not None
    assert transaction.settlement_state == "retained-uncertain"
    assert len(_claim_markers(run)) == 1
    assert len(os.listdir("/proc/self/fd")) <= baseline_fds + 1
    assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS
    started = time.monotonic()
    with pytest.raises(store.ManagedAcquisitionRefused, match="crash-stale"):
        with run.managed_acquisition_claim(*components):
            pass
    assert time.monotonic() - started < 0.5
    with pytest.raises(Exception, match="live artifact claim"):
        store.Run.open(tmp_path, "acme.example", run.run_id).begin_finalization()


def test_certified_pair_is_revalidated_immediately_before_marker_release(tmp_path):
    run, dest, components = _run(tmp_path, "pair-currentness")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    body = b"exact terminal pair"
    receipt_bytes = b'{"terminal":true}'
    transaction = None
    with pytest.raises(store.ManagedAcquisitionRefused, match="changed before release"):
        with run.managed_acquisition_claim(*components) as transaction:
            transaction.mark_contact_attempted()
            writer = transaction.open_writer()
            contract.stream_to_fd(
                io.BytesIO(body), writer, budget_path=dest.parent,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
            assert transaction.publish_body_if_absent() is True
            assert transaction.publish_companion_if_absent(
                receipt_components, receipt_bytes,
            ) is True
            body_snapshot = transaction.snapshot(components)
            receipt_snapshot = transaction.snapshot(
                receipt_components, content_limit=1024 * 1024,
            )
            certificate = transaction.certify_pair(
                body_snapshot, receipt_snapshot,
            )
            assert certificate.body.digest == body_snapshot.digest
            # Same inode, changed bytes after the earlier certificate.  The
            # settlement epoch must observe this before marker unlink.
            dest.write_bytes(b"foreign post-certificate rewrite")

    assert transaction is not None
    assert transaction.settlement_state == "retained-uncertain"
    assert len(_claim_markers(run)) == 1


def test_certified_current_pair_releases_marker_after_contact(tmp_path):
    run, dest, components = _run(tmp_path, "pair-current-release")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    with run.managed_acquisition_claim(*components) as transaction:
        transaction.mark_contact_attempted()
        writer = transaction.open_writer()
        contract.stream_to_fd(
            io.BytesIO(b"body"), writer, budget_path=dest.parent,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )
        assert transaction.publish_body_if_absent()
        assert transaction.publish_companion_if_absent(
            receipt_components, b'{"receipt":true}',
        )
        body_snapshot = transaction.snapshot(components)
        receipt_snapshot = transaction.snapshot(
            receipt_components, content_limit=1024 * 1024,
        )
        transaction.certify_pair(body_snapshot, receipt_snapshot)

    assert transaction.settlement_state == "released"
    assert _claim_markers(run) == []
    run.begin_finalization()


@pytest.mark.parametrize("sibling_kind", ["foreign", "body-hardlink"])
def test_terminal_certificate_refuses_a_present_mutually_exclusive_sibling(
    tmp_path, sibling_kind,
):
    run, dest, components = _run(
        tmp_path, f"pair-sibling-present-{sibling_kind}",
    )
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    absent_components = components[:-1] + (components[-1] + ".part",)
    sibling = run.dir.joinpath(*absent_components)
    transaction = None

    expected = (
        store.ContractError
        if sibling_kind == "body-hardlink"
        else store.ManagedAcquisitionRefused
    )
    expected_match = (
        "canonical base file"
        if sibling_kind == "body-hardlink"
        else "mutually exclusive sibling"
    )
    with pytest.raises(expected, match=expected_match):
        with run.managed_acquisition_claim(*components) as transaction:
            transaction.mark_contact_attempted()
            writer = transaction.open_writer()
            contract.stream_to_fd(
                io.BytesIO(b"certified body"), writer,
                budget_path=dest.parent,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
            assert transaction.publish_body_if_absent()
            assert transaction.publish_companion_if_absent(
                receipt_components, b'{"receipt":true}',
            )
            body = transaction.snapshot(components)
            receipt = transaction.snapshot(
                receipt_components, content_limit=1024 * 1024,
            )
            if sibling_kind == "body-hardlink":
                os.link(dest, sibling)
            else:
                sibling.write_bytes(b"foreign mutually exclusive sibling")
                sibling.chmod(0o600)
            transaction.certify_pair(
                body, receipt, absent_components=absent_components,
            )

    assert transaction is not None
    assert transaction.settlement_state == "retained-uncertain"
    assert len(_claim_markers(run)) == 1
    assert sibling.exists()


@pytest.mark.parametrize("boundary", ["after-certificate", "inside-release"])
def test_terminal_certificate_revalidates_absent_sibling_at_marker_release(
    tmp_path, monkeypatch, boundary,
):
    run, dest, components = _run(
        tmp_path, f"pair-sibling-release-{boundary}",
    )
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    absent_components = components[:-1] + (components[-1] + ".part",)
    sibling = run.dir.joinpath(*absent_components)
    real_provisional = store._ManagedPairRelease._provisional_unlink_locked
    fired = False

    def plant_inside_release(release):
        nonlocal fired
        result = real_provisional(release)
        if not fired:
            fired = True
            sibling.write_bytes(b"sibling planted after release precheck")
            sibling.chmod(0o600)
        return result

    transaction = None
    with monkeypatch.context() as patch:
        if boundary == "inside-release":
            patch.setattr(
                store._ManagedPairRelease, "_provisional_unlink_locked",
                plant_inside_release,
            )
        with pytest.raises(store.ManagedAcquisitionRefused):
            with run.managed_acquisition_claim(*components) as transaction:
                transaction.mark_contact_attempted()
                writer = transaction.open_writer()
                contract.stream_to_fd(
                    io.BytesIO(b"release exclusion body"), writer,
                    budget_path=dest.parent,
                    governor=contract.DiskGovernor(reserve_bytes=0),
                )
                assert transaction.publish_body_if_absent()
                assert transaction.publish_companion_if_absent(
                    receipt_components, b'{"receipt":"release"}',
                )
                body = transaction.snapshot(components)
                receipt = transaction.snapshot(
                    receipt_components, content_limit=1024 * 1024,
                )
                transaction.certify_pair(
                    body, receipt, absent_components=absent_components,
                )
                if boundary == "after-certificate":
                    sibling.write_bytes(b"sibling planted after certificate")
                    sibling.chmod(0o600)

    assert transaction is not None
    assert transaction.settlement_state == "retained-uncertain"
    assert len(_claim_markers(run)) == 1
    assert sibling.exists()


@pytest.mark.parametrize("selected", ["complete", "partial"])
@pytest.mark.parametrize("sibling_kind", ["foreign", "body-hardlink"])
@pytest.mark.parametrize("boundary", ["delete-helper", "final-exact-unlink"])
def test_terminal_marker_delete_revalidates_the_full_acquisition_triad(
    tmp_path, monkeypatch, selected, sibling_kind, boundary,
):
    run, dest, components = _run(
        tmp_path,
        f"triad-terminal-delete-{selected}-{sibling_kind}-{boundary}",
    )
    part_components = components[:-1] + (components[-1] + ".part",)
    body_components, absent_components = (
        (components, part_components)
        if selected == "complete"
        else (part_components, components)
    )
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    body_path = run.dir.joinpath(*body_components)
    sibling = run.dir.joinpath(*absent_components)
    real_delete = store._ManagedPairRelease._delete_quarantine_locked
    real_unlink = store._ManagedPairRelease._unlink_exact_name_locked
    fired = False

    def plant_sibling():
        nonlocal fired
        if not fired:
            fired = True
            if sibling_kind == "body-hardlink":
                os.link(body_path, sibling)
            else:
                sibling.write_bytes(b"foreign sibling at terminal delete")
                sibling.chmod(0o600)

    def plant_at_terminal_delete(release):
        plant_sibling()
        return real_delete(release)

    def plant_at_final_exact_unlink(release, name, **kwargs):
        if name == release.quarantine:
            plant_sibling()
        return real_unlink(release, name, **kwargs)

    transaction = None
    with monkeypatch.context() as patch:
        if boundary == "delete-helper":
            patch.setattr(
                store._ManagedPairRelease, "_delete_quarantine_locked",
                plant_at_terminal_delete,
            )
        else:
            patch.setattr(
                store._ManagedPairRelease, "_unlink_exact_name_locked",
                plant_at_final_exact_unlink,
            )
        with pytest.raises((store.ManagedAcquisitionRefused, store.ContractError)):
            with run.managed_acquisition_claim(*components) as transaction:
                transaction.mark_contact_attempted()
                writer = transaction.open_writer()
                contract.stream_to_fd(
                    io.BytesIO(b"terminal acquisition triad body"), writer,
                    budget_path=dest.parent,
                    governor=contract.DiskGovernor(reserve_bytes=0),
                )
                assert transaction.publish_body_if_absent(body_components)
                assert transaction.publish_companion_if_absent(
                    receipt_components, b'{"receipt":"triad"}',
                )
                body = transaction.snapshot(body_components)
                receipt = transaction.snapshot(
                    receipt_components, content_limit=1024 * 1024,
                )
                transaction.certify_pair(
                    body, receipt, absent_components=absent_components,
                )

    assert fired and transaction is not None
    assert transaction.settlement_state == "retained-uncertain"
    assert len(_claim_markers(run)) == 1
    assert sibling.exists()


def _exercise_settlement_control(run, dest, components, operation_name):
    """Exercise one public settlement control and drain its expected outcome."""
    transaction = None
    try:
        with run.managed_acquisition_claim(*components) as transaction:
            if operation_name == "mark_contact_attempted":
                transaction.mark_contact_attempted()
            elif operation_name == "retain_uncertain":
                transaction.retain_uncertain("source-line uncertainty")
            elif operation_name == "settle_precontact":
                transaction.settle_precontact()
            elif operation_name == "certify_pair":
                receipt_components = components[:-1] + (
                    components[-1] + ".acq.json",
                )
                absent_components = components[:-1] + (
                    components[-1] + ".part",
                )
                writer = transaction.open_writer()
                contract.stream_to_fd(
                    io.BytesIO(b"source-line certified body"), writer,
                    budget_path=dest.parent,
                    governor=contract.DiskGovernor(reserve_bytes=0),
                )
                assert transaction.publish_body_if_absent()
                assert transaction.publish_companion_if_absent(
                    receipt_components, b'{"source-line":"receipt"}',
                )
                body = transaction.snapshot(components)
                receipt = transaction.snapshot(
                    receipt_components, content_limit=1024 * 1024,
                )
                transaction.certify_pair(
                    body, receipt, absent_components=absent_components,
                )
            else:  # pragma: no cover - test helper misuse
                raise AssertionError(operation_name)
    except store.ManagedAcquisitionRefused:
        pass
    return transaction


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation_name",
    [
        "mark_contact_attempted", "retain_uncertain",
        "settle_precontact", "certify_pair",
    ],
)
def test_each_settlement_control_line_is_fail_closed_unless_proof_was_adopted(
    tmp_path, cancellation_type, operation_name,
):
    operation = getattr(store._ManagedAcquisitionTransaction, operation_name)
    probe_run, probe_dest, probe_components = _run(
        tmp_path / "probe", f"control-probe-{operation_name}",
    )
    reached = _executed_lines(
        operation,
        lambda: _exercise_settlement_control(
            probe_run, probe_dest, probe_components, operation_name,
        ),
    )
    assert reached

    for index, line in enumerate(sorted(reached)):
        run, dest, components = _run(
            tmp_path / f"{cancellation_type.__name__}-{index}",
            f"control-{operation_name}-{index}",
        )
        cancellation = cancellation_type(
            f"{operation_name} source line {line}",
        )
        transaction = None
        forced = KeyboardInterrupt("force marker restoration")
        fired = False

        def trace(frame, event, _arg):
            nonlocal fired
            if (frame.f_code is operation.__code__ and event == "line"
                    and frame.f_lineno == line and not fired):
                fired = True
                sys.settrace(None)
                raise cancellation
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                with run.managed_acquisition_claim(*components) as transaction:
                    if operation_name == "certify_pair":
                        receipt_components = components[:-1] + (
                            components[-1] + ".acq.json",
                        )
                        absent_components = components[:-1] + (
                            components[-1] + ".part",
                        )
                        writer = transaction.open_writer()
                        contract.stream_to_fd(
                            io.BytesIO(b"source-line certified body"), writer,
                            budget_path=dest.parent,
                            governor=contract.DiskGovernor(reserve_bytes=0),
                        )
                        assert transaction.publish_body_if_absent()
                        assert transaction.publish_companion_if_absent(
                            receipt_components,
                            b'{"source-line":"receipt"}',
                        )
                        body = transaction.snapshot(components)
                        receipt = transaction.snapshot(
                            receipt_components, content_limit=1024 * 1024,
                        )
                        operation(
                            transaction, body, receipt,
                            absent_components=absent_components,
                        )
                    elif operation_name == "retain_uncertain":
                        operation(transaction, "source-line uncertainty")
                    else:
                        operation(transaction)
        finally:
            sys.settrace(previous)

        assert fired and caught.value is cancellation
        assert transaction is not None
        adopted_proof = (
            transaction.clean_precontact
            or transaction.terminal_certificate is not None
        )
        if adopted_proof:
            assert transaction.settlement_state == "released"
            assert _claim_markers(run) == []
        else:
            assert transaction.settlement_state == "retained-uncertain"
            assert len(_claim_markers(run)) == 1
        assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS


@pytest.mark.parametrize("replace_name", [False, True])
def test_pair_is_revalidated_inside_marker_release_boundary(
    tmp_path, monkeypatch, replace_name,
):
    run, dest, components = _run(
        tmp_path, f"pair-release-boundary-{replace_name}",
    )
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    real_validate = None
    fired = False

    def tamper_after_precheck(release):
        nonlocal fired
        result = real_validate(release)
        if not fired:
            fired = True
            if replace_name:
                dest.unlink()
                dest.write_bytes(b"foreign replacement at release")
                dest.chmod(0o600)
            else:
                dest.write_bytes(b"foreign rewrite at release")
        return result

    transaction = None
    with monkeypatch.context() as patch:
        real_validate = store._ManagedPairRelease._provisional_unlink_locked
        patch.setattr(
            store._ManagedPairRelease, "_provisional_unlink_locked",
            tamper_after_precheck,
        )
        with pytest.raises(
            store.ManagedAcquisitionRefused, match="changed|revalidated",
        ):
            with run.managed_acquisition_claim(*components) as transaction:
                transaction.mark_contact_attempted()
                writer = transaction.open_writer()
                contract.stream_to_fd(
                    io.BytesIO(b"release boundary body"), writer,
                    budget_path=dest.parent,
                    governor=contract.DiskGovernor(reserve_bytes=0),
                )
                assert transaction.publish_body_if_absent()
                assert transaction.publish_companion_if_absent(
                    receipt_components, b'{"release":"boundary"}',
                )
                body = transaction.snapshot(components)
                receipt = transaction.snapshot(
                    receipt_components, content_limit=1024 * 1024,
                )
                transaction.certify_pair(body, receipt)

    assert fired and transaction is not None
    assert transaction.settlement_state == "retained-uncertain"
    assert len(_claim_markers(run)) == 1


def test_persistent_marker_unlink_fault_cannot_become_false_release(
    tmp_path, monkeypatch,
):
    run, _dest, components = _run(tmp_path, "persistent-marker-unlink")
    real_unlink = os.unlink

    def refuse_marker_unlink(path, *, dir_fd=None):
        if str(path).endswith(".claim"):
            raise OSError("persistent marker unlink failure")
        return real_unlink(path, dir_fd=dir_fd)

    transaction = None
    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", refuse_marker_unlink)
        with pytest.raises(OSError, match="persistent marker unlink failure"):
            with run.managed_acquisition_claim(*components) as transaction:
                transaction.settle_precontact()

    assert transaction is not None
    assert transaction.settlement_state == "live"
    assert transaction.marker.released is False
    assert _claim_markers(run)
    assert id(transaction) in store._LIVE_MANAGED_ACQUISITIONS
    try:
        transaction.settle()
    except BaseException:
        pass
    assert transaction.settlement_state == "retained-uncertain"
    assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_each_marker_restoration_line_keeps_only_complete_durable_evidence(
    tmp_path, monkeypatch, cancellation_type,
):
    operation = store._ManagedPairRelease.ensure_restored

    def invoke(case, trace=None):
        run, dest, components = _run(case, "restore-line")
        receipt_components = components[:-1] + (
            components[-1] + ".acq.json",
        )
        transaction = None
        real_provisional = store._ManagedPairRelease._provisional_unlink_locked

        def unlink_then_tamper(release):
            real_provisional(release)
            dest.write_bytes(b"force post-unlink pair mismatch")
            dest.chmod(0o600)

        with monkeypatch.context() as patch:
            patch.setattr(
                store._ManagedPairRelease,
                "_provisional_unlink_locked",
                unlink_then_tamper,
            )
            previous = sys.gettrace()
            try:
                if trace is not None:
                    sys.settrace(trace)
                with pytest.raises(BaseException) as escaped:
                    with run.managed_acquisition_claim(*components) as transaction:
                        transaction.mark_contact_attempted()
                        writer = transaction.open_writer()
                        contract.stream_to_fd(
                            io.BytesIO(b"restoration matrix body"), writer,
                            budget_path=dest.parent,
                            governor=contract.DiskGovernor(reserve_bytes=0),
                        )
                        assert transaction.publish_body_if_absent()
                        assert transaction.publish_companion_if_absent(
                            receipt_components, b'{"restore":"matrix"}',
                        )
                        body = transaction.snapshot(components)
                        receipt = transaction.snapshot(
                            receipt_components, content_limit=1024 * 1024,
                        )
                        transaction.certify_pair(body, receipt)
            finally:
                sys.settrace(previous)
        return run, components, transaction, escaped.value

    reached = set()

    def probe_trace(frame, event, _arg):
        if frame.f_code is operation.__code__ and event == "line":
            reached.add(frame.f_lineno)
        return probe_trace

    invoke(tmp_path / "probe", probe_trace)
    assert reached
    for index, line in enumerate(sorted(reached)):
        cancellation = cancellation_type(f"marker restoration line {line}")
        fired = False

        def trace(frame, event, _arg):
            nonlocal fired
            if (frame.f_code is operation.__code__ and event == "line"
                    and frame.f_lineno == line and not fired):
                fired = True
                sys.settrace(None)
                raise cancellation
            return trace

        run, components, transaction, escaped = invoke(
            tmp_path / f"{cancellation_type.__name__}-{index}", trace,
        )
        assert fired
        assert escaped is cancellation
        markers = _claim_markers(run)
        assert len(markers) == 1, (line, type(escaped).__name__, str(escaped))
        expected = store._managed_acquisition_marker_material(
            run.run_id, components,
        )[2]
        assert markers[0].read_bytes() == expected
        assert len(list(markers[0].parent.glob("*.claim"))) == 1
        assert transaction.settlement_state == "retained-uncertain"
        assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS
        started = time.monotonic()
        with pytest.raises(store.ManagedAcquisitionRefused, match="crash-stale"):
            with run.managed_acquisition_claim(*components):
                pass
        assert time.monotonic() - started < 0.5


def _exercise_pair_restoration(run, dest, components, holder=None):
    receipt_components = components[:-1] + (
        components[-1] + ".acq.json",
    )
    with run.managed_acquisition_claim(*components) as transaction:
        if holder is not None:
            holder.append(transaction)
        transaction.mark_contact_attempted()
        writer = transaction.open_writer()
        contract.stream_to_fd(
            io.BytesIO(b"restoration authority body"), writer,
            budget_path=dest.parent,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )
        assert transaction.publish_body_if_absent()
        assert transaction.publish_companion_if_absent(
            receipt_components, b'{"restore":"authority"}',
        )
        body = transaction.snapshot(components)
        receipt = transaction.snapshot(
            receipt_components, content_limit=1024 * 1024,
        )
        transaction.certify_pair(body, receipt)
    return transaction


def test_marker_restoration_never_repairs_a_substituted_generation(
    tmp_path, monkeypatch,
):
    run, dest, components = _run(tmp_path, "restore-substitution")
    real_provisional = store._ManagedPairRelease._provisional_unlink_locked
    real_restore = store._ManagedPairRelease.ensure_restored
    cancellation = KeyboardInterrupt("cancel after restoration substitution")
    restoration_started = False
    substituted = False

    def unlink_then_tamper(release):
        nonlocal restoration_started
        real_provisional(release)
        dest.write_bytes(b"force pair postcheck mismatch")
        dest.chmod(0o600)
        restoration_started = True

    def substitute_before_restoration(release):
        nonlocal substituted
        if restoration_started and not substituted:
            marker = (
                run.project_dir / "recon" / "state" / "claims" /
                run.run_id / release.marker.name
            )
            hidden = marker.with_name(marker.name + ".hidden")
            marker.rename(hidden)
            marker.write_bytes(b"foreign deterministic marker")
            marker.chmod(0o600)
            substituted = True
            raise cancellation
        return real_restore(release)

    transactions = []
    with monkeypatch.context() as patch:
        patch.setattr(
            store._ManagedPairRelease,
            "_provisional_unlink_locked",
            unlink_then_tamper,
        )
        patch.setattr(
            store._ManagedPairRelease, "ensure_restored",
            substitute_before_restoration,
        )
        with pytest.raises(KeyboardInterrupt) as caught:
            _exercise_pair_restoration(
                run, dest, components, transactions,
            )

    transaction, = transactions
    assert caught.value is cancellation
    assert substituted
    assert any(
        marker.read_bytes() == b"foreign deterministic marker"
        for marker in _claim_markers(run)
    )
    assert transaction.settlement_state == "live"
    assert id(transaction) in store._LIVE_MANAGED_ACQUISITIONS
    started = time.monotonic()
    with pytest.raises(store.ManagedAcquisitionRefused):
        with run.managed_acquisition_claim(*components):
            pass
    assert time.monotonic() - started < 0.5
    deterministic = (
        run.project_dir / "recon" / "state" / "claims" / run.run_id /
        store._managed_acquisition_marker_material(run.run_id, components)[0]
    )
    deterministic.unlink()
    deterministic.with_name(deterministic.name + ".hidden").unlink()
    try:
        transaction.settle()
    except BaseException:
        pass
    assert transaction.settlement_state == "retained-uncertain"
    assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS


@pytest.mark.parametrize("fault_point", ["rename", "directory-fsync"])
def test_persistent_restoration_fault_retains_truthful_named_evidence(
    tmp_path, monkeypatch, fault_point,
):
    run, dest, components = _run(tmp_path, f"restore-{fault_point}")
    real_provisional = store._ManagedPairRelease._provisional_unlink_locked
    from quarry_recon import privfs
    real_rename = privfs._renameat2_noreplace
    real_fsync = os.fsync
    restoration_started = False
    transactions = []

    def unlink_then_tamper(release):
        nonlocal restoration_started
        real_provisional(release)
        dest.write_bytes(b"force pair postcheck mismatch")
        dest.chmod(0o600)
        restoration_started = True

    def fail_restoration_rename(*args, **kwargs):
        if (fault_point == "rename" and len(args) >= 4
                and str(args[1]).endswith(".claim")
                and str(args[3]).endswith(".claim")):
            raise OSError("persistent restoration rename fault")
        return real_rename(*args, **kwargs)

    def fail_restoration_fsync(fd):
        if (restoration_started and fault_point == "directory-fsync"
                and transactions
                and fd == transactions[0].marker.directory.fd):
            raise OSError("persistent restoration fsync fault")
        return real_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(
            store._ManagedPairRelease,
            "_provisional_unlink_locked",
            unlink_then_tamper,
        )
        patch.setattr(privfs, "_renameat2_noreplace", fail_restoration_rename)
        patch.setattr(os, "fsync", fail_restoration_fsync)
        with pytest.raises((OSError, store.ManagedAcquisitionRefused)):
            _exercise_pair_restoration(
                run, dest, components, transactions,
            )

    transaction, = transactions
    markers = _claim_markers(run)
    assert markers
    expected = store._managed_acquisition_marker_material(
        run.run_id, components,
    )[2]
    assert all(marker.read_bytes() == expected for marker in markers)
    assert transaction.settlement_state in {"live", "retained-uncertain"}
    if transaction.settlement_state == "live":
        assert id(transaction) in store._LIVE_MANAGED_ACQUISITIONS
    else:
        assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS
    with pytest.raises(Exception):
        run.begin_finalization()
    started = time.monotonic()
    with pytest.raises(store.ManagedAcquisitionRefused):
        with run.managed_acquisition_claim(*components):
            pass
    assert time.monotonic() - started < 0.5
    if transaction.settlement_state == "live":
        try:
            transaction.settle()
        except BaseException:
            pass
        assert transaction.settlement_state == "retained-uncertain"
        assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_atfork_child_closes_the_exact_live_restoration_descriptor(
    tmp_path, monkeypatch,
):
    run, dest, components = _run(tmp_path, "restore-atfork")
    real_provisional = store._ManagedPairRelease._provisional_unlink_locked
    real_restore = store._ManagedPairRelease.ensure_restored
    restoration_started = False
    forked = False
    child_observation = []
    transactions = []

    def unlink_then_tamper(release):
        nonlocal restoration_started
        real_provisional(release)
        dest.write_bytes(b"force pair postcheck mismatch")
        dest.chmod(0o600)
        restoration_started = True

    def fork_while_restoration_owned(release):
        nonlocal forked
        if restoration_started and not forked:
            forked = True
            owned_fd = transactions[0].marker.marker.fd
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read_fd)
                try:
                    os.fstat(owned_fd)
                except OSError as exc:
                    state = b"closed" if exc.errno == errno.EBADF else b"error"
                else:
                    state = b"open"
                os.write(write_fd, state)
                os.close(write_fd)
                os._exit(0)
            os.close(write_fd)
            child_observation.append(os.read(read_fd, 32))
            os.close(read_fd)
            waited, status = os.waitpid(child, 0)
            assert waited == child and os.waitstatus_to_exitcode(status) == 0
        return real_restore(release)

    with monkeypatch.context() as patch:
        patch.setattr(
            store._ManagedPairRelease,
            "_provisional_unlink_locked",
            unlink_then_tamper,
        )
        patch.setattr(
            store._ManagedPairRelease, "ensure_restored",
            fork_while_restoration_owned,
        )
        with pytest.raises(store.ManagedAcquisitionRefused):
            _exercise_pair_restoration(
                run, dest, components, transactions,
            )

    transaction, = transactions
    assert forked and child_observation == [b"closed"]
    assert transaction.marker.marker.fd < 0
    assert transaction.settlement_state == "retained-uncertain"
    assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS
    marker, = _claim_markers(run)
    assert marker.read_bytes() == store._managed_acquisition_marker_material(
        run.run_id, components,
    )[2]


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
@pytest.mark.parametrize("substitute_name", ["deterministic", "quarantine"])
def test_release_position_substitution_never_grants_cross_process_authority(
    tmp_path, monkeypatch, substitute_name,
):
    run, dest, components = _run(
        tmp_path, f"release-substitute-{substitute_name}",
    )
    real_positions = store._ManagedPairRelease._positions_locked
    both_observations = 0
    planted = None
    hidden = None
    transactions = []

    def substitute_after_position_check(release, *, allow_both=False):
        nonlocal both_observations, planted, hidden
        result = real_positions(release, allow_both=allow_both)
        if result == (True, True):
            both_observations += 1
            # The first both-name observation adopts the overlap.  Substitute
            # after the later delete precheck returns, reproducing the exact
            # helper-return/name-use race while another authentic `.claim`
            # name still protects the destination.
            if both_observations == 2:
                registry = (
                    run.project_dir / "recon" / "state" / "claims" /
                    run.run_id
                )
                selected = (
                    release.marker.name
                    if substitute_name == "deterministic"
                    else release.quarantine
                )
                planted = registry / selected
                hidden = registry / f"{selected}.hidden"
                planted.rename(hidden)
                planted.write_bytes(b"foreign release-name substitute")
                planted.chmod(0o600)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(
            store._ManagedPairRelease, "_positions_locked",
            substitute_after_position_check,
        )
        with pytest.raises(store.ManagedAcquisitionRefused):
            _exercise_pair_restoration(
                run, dest, components, transactions,
            )

    transaction, = transactions
    assert both_observations >= 2 and planted is not None and hidden is not None
    assert transaction.settlement_state == "live"
    assert id(transaction) in store._LIVE_MANAGED_ACQUISITIONS

    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:  # pragma: no cover - parent owns assertions
        os.close(read_fd)
        try:
            opened = store.Run.open(tmp_path, "acme.example", run.run_id)
            try:
                with opened.managed_acquisition_claim(*components):
                    result = b"entered"
            except store.ManagedAcquisitionRefused as exc:
                result = f"refused:{exc}".encode("utf-8")
            os.write(write_fd, result)
        except BaseException as exc:
            os.write(
                write_fd,
                f"error:{type(exc).__name__}:{exc}".encode("utf-8"),
            )
            os._exit(70)
        os._exit(0)

    os.close(write_fd)
    ready, _, _ = select.select([read_fd], [], [], 1)
    assert ready, "release-name substitution let a contender block"
    result = os.read(read_fd, 4096).decode("utf-8")
    os.close(read_fd)
    waited, status = os.waitpid(child, 0)
    assert waited == child and os.waitstatus_to_exitcode(status) == 0
    assert result.startswith("refused:"), result

    # Restore the authentic exact name solely to settle this intentionally
    # fail-stopped test owner and prove its process-local graph drains.
    planted.unlink()
    hidden.rename(planted)
    try:
        transaction.settle()
    except BaseException:
        pass
    assert transaction.settlement_state == "retained-uncertain"
    assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_each_postunlink_pair_release_line_restores_uncertainty_or_proves_release(
    tmp_path, cancellation_type,
):
    operation = store._ManagedPairRelease.execute
    probe_run, probe_dest, probe_components = _run(
        tmp_path / "probe", "pair-postunlink-probe",
    )
    probe_receipt = probe_components[:-1] + (
        probe_components[-1] + ".acq.json",
    )

    def acquire_pair(run, dest, components, receipt_components):
        with run.managed_acquisition_claim(*components) as transaction:
            transaction.mark_contact_attempted()
            writer = transaction.open_writer()
            contract.stream_to_fd(
                io.BytesIO(b"postunlink matrix body"), writer,
                budget_path=dest.parent,
                governor=contract.DiskGovernor(reserve_bytes=0),
            )
            assert transaction.publish_body_if_absent()
            assert transaction.publish_companion_if_absent(
                receipt_components, b'{"postunlink":"matrix"}',
            )
            body = transaction.snapshot(components)
            receipt = transaction.snapshot(
                receipt_components, content_limit=1024 * 1024,
            )
            transaction.certify_pair(body, receipt)
        return transaction

    reached = _executed_lines(
        operation,
        lambda: acquire_pair(
            probe_run, probe_dest, probe_components, probe_receipt,
        ),
    )
    # ``execute`` lines at/after the provisional call can observe the marker
    # unlinked; earlier lines are covered by the settlement-control matrix.
    provisional_call = _line_containing(operation, "self._provisional_unlink_locked()")
    postunlink_lines = {line for line in reached if line >= provisional_call}
    assert postunlink_lines

    for index, line in enumerate(sorted(postunlink_lines)):
        run, dest, components = _run(
            tmp_path / f"{cancellation_type.__name__}-{index}",
            f"pair-postunlink-{index}",
        )
        receipt_components = components[:-1] + (
            components[-1] + ".acq.json",
        )
        cancellation = cancellation_type(f"postunlink release line {line}")
        transaction = None
        fired = False

        def trace(frame, event, _arg):
            nonlocal fired
            if (frame.f_code is operation.__code__ and event == "line"
                    and frame.f_lineno == line and not fired):
                fired = True
                sys.settrace(None)
                raise cancellation
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                transaction = acquire_pair(
                    run, dest, components, receipt_components,
                )
        finally:
            sys.settrace(previous)
        assert fired and caught.value is cancellation
        # Cancellation after terminal adoption may release; every earlier
        # post-unlink cancellation must restore a durable stale marker.
        if _claim_markers(run):
            assert len(_claim_markers(run)) == 1
        else:
            assert transaction is None or transaction.settlement_state == "released"


def test_certified_pair_settlement_reported_fault_keeps_released_terminal_truth(
    tmp_path, monkeypatch,
):
    run, dest, components = _run(tmp_path, "pair-release-reported-fault")
    receipt_components = components[:-1] + (components[-1] + ".acq.json",)
    real_settle = store._ManagedAcquisitionMarker.settle
    fired = False
    transaction = None

    def settle_then_report(marker, pre_unlink=None):
        nonlocal fired
        real_settle(marker, pre_unlink)
        if not fired:
            fired = True
            raise OSError("marker settlement reported after durable release")

    with monkeypatch.context() as patch:
        patch.setattr(store._ManagedAcquisitionMarker, "settle", settle_then_report)
        with pytest.raises(OSError, match="reported after durable release"):
            with run.managed_acquisition_claim(*components) as transaction:
                transaction.mark_contact_attempted()
                writer = transaction.open_writer()
                contract.stream_to_fd(
                    io.BytesIO(b"body"), writer, budget_path=dest.parent,
                    governor=contract.DiskGovernor(reserve_bytes=0),
                )
                assert transaction.publish_body_if_absent()
                assert transaction.publish_companion_if_absent(
                    receipt_components, b'{"receipt":true}',
                )
                body_snapshot = transaction.snapshot(components)
                receipt_snapshot = transaction.snapshot(
                    receipt_components, content_limit=1024 * 1024,
                )
                transaction.certify_pair(body_snapshot, receipt_snapshot)

    assert fired and transaction is not None
    assert transaction.settlement_state == "released"
    assert _claim_markers(run) == []
    assert dest.read_bytes() == b"body"
    assert run.dir.joinpath(*receipt_components).exists()
    run.begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_composite_discard_finishes_receipt_and_preserves_exact_primary(
    tmp_path, monkeypatch, cancellation_type,
):
    run, dest, components = _run(
        tmp_path, f"discard-pair-{cancellation_type.__name__}",
    )
    receipt_components, body_snapshot, receipt_snapshot = _publish_managed_pair(
        run, dest, components,
    )
    operation = store._ManagedDiscardComposite.reconcile
    receipt_line = _line_containing(operation, "self._remove(self.receipt)")
    cancellation = cancellation_type("between body and receipt discard")
    fired = False
    real_settle = store._ManagedAcquisitionTransaction.settle

    def trace(frame, event, _arg):
        nonlocal fired
        if (frame.f_code is operation.__code__ and event == "line"
                and frame.f_lineno == receipt_line and not fired):
            fired = True
            sys.settrace(None)
            raise cancellation
        return trace

    def settle_then_report(transaction):
        real_settle(transaction)
        raise OSError("discard context settlement reported after release")

    with monkeypatch.context() as patch:
        patch.setattr(
            store._ManagedAcquisitionTransaction, "settle", settle_then_report,
        )
        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                with run.managed_acquisition_claim(*components) as transaction:
                    transaction.discard_pair(
                        components, body_snapshot,
                        receipt_components, receipt_snapshot,
                    )
        finally:
            sys.settrace(previous)

    assert fired and caught.value is cancellation
    ledger = getattr(cancellation, "managed_discard", None)
    assert type(ledger) is store.ManagedDiscardLedger
    assert ledger.body.state.startswith("removed")
    assert ledger.receipt.state.startswith("removed")
    assert not dest.exists() and not run.dir.joinpath(*receipt_components).exists()
    assert _claim_markers(run) == []
    run.begin_finalization()


def _prearmed_discard_claim_events(run, components):
    operation = store.Run.managed_acquisition_discard_claim.__wrapped__
    events = []

    def trace(frame, event, _arg):
        if frame.f_code is operation.__code__ and event == "line":
            events.append(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with run.managed_acquisition_discard_claim(*components) as transaction:
            assert transaction.clean_precontact
            assert transaction.discard_started
    finally:
        sys.settrace(previous)
    return events


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_each_prearmed_discard_claim_line_drains_without_stale_marker(
    tmp_path, cancellation_type,
):
    probe_run, _probe_dest, probe_components = _run(
        tmp_path / "probe", "discard-claim-line-probe",
    )
    events = _prearmed_discard_claim_events(probe_run, probe_components)
    assert events
    assert _claim_markers(probe_run) == []

    operation = store.Run.managed_acquisition_discard_claim.__wrapped__
    for target in range(1, len(events) + 1):
        run, _dest, components = _run(
            tmp_path / f"{cancellation_type.__name__}-{target}",
            f"discard-claim-line-{target}",
        )
        cancellation = cancellation_type(
            f"prearmed discard claim occurrence {target}",
        )
        occurrence = 0
        fired = False
        live_before = frozenset(store._LIVE_MANAGED_ACQUISITIONS)

        def trace(frame, event, _arg):
            nonlocal occurrence, fired
            if frame.f_code is operation.__code__ and event == "line":
                occurrence += 1
                if occurrence == target and not fired:
                    fired = True
                    sys.settrace(None)
                    raise cancellation
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                with run.managed_acquisition_discard_claim(*components):
                    pass
        finally:
            sys.settrace(previous)

        assert fired and caught.value is cancellation, (target, events[target - 1])
        assert _claim_markers(run) == [], (target, events[target - 1])
        assert frozenset(store._LIVE_MANAGED_ACQUISITIONS) == live_before
        run.begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(("operation", "at_unregister"), [
    (store._register_live_managed_acquisition, False),
    (store._unregister_live_managed_acquisition, True),
])
def test_prearmed_discard_registry_transition_preserves_exact_and_drains(
    tmp_path, cancellation_type, operation, at_unregister,
):
    run, _dest, components = _run(
        tmp_path,
        f"discard-registry-{'out' if at_unregister else 'in'}-"
        f"{cancellation_type.__name__}",
    )
    line = _line_containing(operation, "with _RUN_LOCKS_GUARD")
    cancellation = cancellation_type(
        f"exact {operation.__name__} cancellation",
    )
    fired = False
    live_before = frozenset(store._LIVE_MANAGED_ACQUISITIONS)

    def trace(frame, event, _arg):
        nonlocal fired
        if (frame.f_code is operation.__code__ and event == "line"
                and frame.f_lineno == line and not fired):
            fired = True
            sys.settrace(None)
            raise cancellation
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        with pytest.raises(cancellation_type) as caught:
            with run.managed_acquisition_discard_claim(*components):
                assert at_unregister
    finally:
        sys.settrace(previous)

    assert fired and caught.value is cancellation
    assert _claim_markers(run) == []
    assert frozenset(store._LIVE_MANAGED_ACQUISITIONS) == live_before
    run.begin_finalization()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_prearmed_discard_yield_gap_preserves_pair_and_exact_primary(
    tmp_path, cancellation_type,
):
    run, dest, components = _run(
        tmp_path, f"discard-yield-gap-{cancellation_type.__name__}",
    )
    receipt_components, body_snapshot, receipt_snapshot = _publish_managed_pair(
        run, dest, components,
    )
    cancellation = cancellation_type("exact cancellation before discard_pair")

    with pytest.raises(cancellation_type) as caught:
        with run.managed_acquisition_discard_claim(*components) as transaction:
            assert transaction.clean_precontact and transaction.discard_started
            raise cancellation

    assert caught.value is cancellation
    assert dest.read_bytes() == b"managed pair body"
    assert run.dir.joinpath(*receipt_components).read_bytes() == b'{"managed":"pair"}'
    assert body_snapshot is not None and receipt_snapshot is not None
    assert _claim_markers(run) == []
    run.begin_finalization()


def test_prearmed_discard_claim_returns_terminal_pair_ledger(tmp_path):
    run, dest, components = _run(tmp_path, "discard-prearmed-terminal")
    receipt_components, body_snapshot, receipt_snapshot = _publish_managed_pair(
        run, dest, components,
    )

    with run.managed_acquisition_discard_claim(*components) as transaction:
        ledger = transaction.discard_pair(
            components, body_snapshot,
            receipt_components, receipt_snapshot,
        )

    assert type(ledger) is store.ManagedDiscardLedger
    assert ledger.body.state.startswith("removed")
    assert ledger.receipt.state.startswith("removed")
    assert not dest.exists() and not run.dir.joinpath(*receipt_components).exists()
    assert _claim_markers(run) == []
    run.begin_finalization()


_DISCARD_CANCELLATION_BOUNDARIES = (
    store._ManagedDiscardComposite._remove,
    store._ManagedDiscardComposite.reconcile,
    store._settle_managed_discard_escape,
    store._managed_discard_execute,
    store._managed_discard_middle,
    store._managed_discard_inner,
    store._managed_discard_outer,
    store._ManagedDiscardFence.__exit__,
    store._managed_discard_fenced,
    store._managed_discard_public_middle,
    store._managed_discard_public_inner,
    store._managed_discard_public_outer,
    store._managed_discard_public_export,
)


def _discard_boundary_lines(
    monkeypatch, operation, run, dest, components,
    receipt_components, body_snapshot, receipt_snapshot,
):
    reached = set()
    seeded = False
    real_remove = store._ManagedAcquisitionTransaction.remove_if_matches
    seed = OSError("discard boundary coverage seed")

    def seed_once(transaction, target_components, expected):
        nonlocal seeded
        if not seeded:
            seeded = True
            raise seed
        return real_remove(transaction, target_components, expected)

    def trace(frame, event, _arg):
        if frame.f_code is operation.__code__ and event == "line":
            reached.add(frame.f_lineno)
        return trace

    with monkeypatch.context() as patch:
        patch.setattr(
            store._ManagedAcquisitionTransaction,
            "remove_if_matches", seed_once,
        )
        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(OSError) as caught:
                with run.managed_acquisition_claim(*components) as transaction:
                    transaction.discard_pair(
                        components, body_snapshot,
                        receipt_components, receipt_snapshot,
                    )
        finally:
            sys.settrace(previous)
    assert caught.value is seed and seeded
    assert not dest.exists()
    assert not run.dir.joinpath(*receipt_components).exists()
    return reached


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("operation", _DISCARD_CANCELLATION_BOUNDARIES)
def test_each_composite_discard_boundary_line_preserves_ledger_and_exact_primary(
    tmp_path, monkeypatch, cancellation_type, operation,
):
    probe_run, probe_dest, probe_components = _run(
        tmp_path / "probe", f"discard-boundary-probe-{operation.__name__}",
    )
    probe_receipt, probe_body, probe_receipt_snapshot = _publish_managed_pair(
        probe_run, probe_dest, probe_components,
    )
    reached = _discard_boundary_lines(
        monkeypatch, operation, probe_run, probe_dest, probe_components,
        probe_receipt, probe_body, probe_receipt_snapshot,
    )
    assert reached

    for index, line in enumerate(sorted(reached)):
        run, dest, components = _run(
            tmp_path / f"{cancellation_type.__name__}-{index}",
            f"discard-boundary-{operation.__name__}-{index}",
        )
        receipt_components, body_snapshot, receipt_snapshot = (
            _publish_managed_pair(run, dest, components)
        )
        cancellation = cancellation_type(
            f"{operation.__name__} source line {line}",
        )
        seeded = False
        fired = False
        real_remove = store._ManagedAcquisitionTransaction.remove_if_matches
        seed = OSError("discard boundary execution seed")

        def seed_once(transaction, target_components, expected):
            nonlocal seeded
            if not seeded:
                seeded = True
                raise seed
            return real_remove(transaction, target_components, expected)

        def trace(frame, event, _arg):
            nonlocal fired
            if (frame.f_code is operation.__code__ and event == "line"
                    and frame.f_lineno == line and not fired):
                fired = True
                sys.settrace(None)
                raise cancellation
            return trace

        with monkeypatch.context() as patch:
            patch.setattr(
                store._ManagedAcquisitionTransaction,
                "remove_if_matches", seed_once,
            )
            previous = sys.gettrace()
            try:
                sys.settrace(trace)
                with pytest.raises(cancellation_type) as caught:
                    with run.managed_acquisition_claim(*components) as transaction:
                        transaction.discard_pair(
                            components, body_snapshot,
                            receipt_components, receipt_snapshot,
                        )
            finally:
                sys.settrace(previous)

        assert fired and caught.value is cancellation
        ledger = getattr(cancellation, "managed_discard", None)
        assert type(ledger) is store.ManagedDiscardLedger, (line, seeded)
        assert ledger.body.state.startswith("removed"), (line, ledger, seeded)
        assert ledger.receipt.state.startswith("removed")
        assert not dest.exists()
        assert not run.dir.joinpath(*receipt_components).exists()
        assert _claim_markers(run) == []


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_nested_discard_handler_occurrences_reconcile_and_attach_ledger(
    tmp_path, monkeypatch, cancellation_type,
):
    baseline_fds = len(os.listdir("/proc/self/fd"))
    wrapper_codes = frozenset({
        store._ManagedDiscardFence.__exit__.__code__,
        store._settle_managed_discard_escape.__code__,
        store._managed_discard_middle.__code__,
        store._managed_discard_inner.__code__,
        store._managed_discard_outer.__code__,
        store._managed_discard_fenced.__code__,
        store._managed_discard_public_middle.__code__,
        store._managed_discard_public_inner.__code__,
        store._managed_discard_public_outer.__code__,
        store._managed_discard_public_export.__code__,
        store._managed_discard_public_reserved.__code__,
        store._managed_discard_public_final.__code__,
    })

    def invoke(case, target_occurrence=None):
        run, dest, components = _run(case, "discard-occurrence")
        receipt_components, body_snapshot, receipt_snapshot = (
            _publish_managed_pair(run, dest, components)
        )
        real_remove = store._ManagedAcquisitionTransaction.remove_if_matches
        seed = OSError("discard occurrence seed")
        second = cancellation_type("discard outer handler cancellation")
        seeded = False
        occurrence = 0
        events = []

        def seed_once(transaction, target_components, expected):
            nonlocal seeded
            if not seeded:
                seeded = True
                raise seed
            return real_remove(transaction, target_components, expected)

        def trace(frame, event, _arg):
            nonlocal occurrence
            if event == "line" and seeded and frame.f_code in wrapper_codes:
                events.append((frame.f_code, frame.f_lineno))
                occurrence += 1
                if occurrence == target_occurrence:
                    sys.settrace(None)
                    raise second
            return trace

        with monkeypatch.context() as patch:
            patch.setattr(
                store._ManagedAcquisitionTransaction,
                "remove_if_matches", seed_once,
            )
            previous = sys.gettrace()
            try:
                sys.settrace(trace)
                with pytest.raises(BaseException) as escaped:
                    with run.managed_acquisition_claim(*components) as transaction:
                        transaction.discard_pair(
                            components, body_snapshot,
                            receipt_components, receipt_snapshot,
                        )
            finally:
                sys.settrace(previous)
        return (
            run, dest, receipt_components, seed, second,
            escaped.value, events, transaction,
        )

    baseline = invoke(tmp_path / "probe")
    events = baseline[-2]
    assert events
    unclassified = []
    for occurrence in range(1, len(events) + 1):
        (
            run, dest, receipt_components, _seed, second,
            escaped, _case_events, transaction,
        ) = invoke(tmp_path / f"occurrence-{occurrence}", occurrence)
        assert escaped is second, occurrence
        ledger = getattr(escaped, "managed_discard", None)
        if type(ledger) is not store.ManagedDiscardLedger:
            unclassified.append(occurrence)
        else:
            assert ledger.body.state.startswith("removed")
            assert ledger.receipt.state.startswith("removed")
        assert not dest.exists()
        assert not run.dir.joinpath(*receipt_components).exists()
        assert _claim_markers(run) == []
        assert transaction.settlement_state == "released"
        assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS
        assert len(os.listdir("/proc/self/fd")) <= baseline_fds + 1

    # A fresh asynchronous cancellation inside the one finite final reserve
    # has no further Python handler.  For each exempt occurrence the assertions
    # above still prove the exact object escaped, both names are terminal,
    # marker/fd/map truth is drained, and no later namespace effect remains.
    # Every earlier occurrence, including both identical discard-fence exits
    # and their caller lines, is ledger-classified.
    assert unclassified
    first_final = unclassified[0]
    assert all(
        code is store._settle_managed_discard_escape.__code__
        or code is store._managed_discard_public_final.__code__
        for index, (code, _line) in enumerate(events, 1)
        if index in unclassified
    )
    assert all(
        code is store._settle_managed_discard_escape.__code__
        or code is store._managed_discard_public_final.__code__
        for code, _line in events[first_final - 1:]
    )




@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_release_unlink_commit_preserves_exact_cancellation_and_settles_marker(
    tmp_path, monkeypatch, cancellation_type,
):
    run, _dest, components = _run(
        tmp_path, f"release-{cancellation_type.__name__}",
    )
    real_unlink = os.unlink
    cancellation = cancellation_type("exact marker release cancellation")
    fired = False

    def unlink_then_cancel(path, *, dir_fd=None):
        nonlocal fired
        if str(path).endswith(".claim") and not fired:
            fired = True
            real_unlink(path, dir_fd=dir_fd)
            raise cancellation
        return real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", unlink_then_cancel)
    with pytest.raises(cancellation_type) as caught:
        with run.managed_acquisition_claim(*components) as transaction:
            transaction.settle_precontact()
    assert fired and caught.value is cancellation
    markers = _claim_markers(run)
    if markers:
        assert transaction.settlement_state == "retained-uncertain"
        with pytest.raises(Exception, match="live artifact claim"):
            run.begin_finalization()
    else:
        assert transaction.settlement_state == "released"
        run.begin_finalization()


def test_repeated_destination_claims_leave_no_descriptor_or_marker_growth(tmp_path):
    run, _dest, components = _run(tmp_path, "claim-fd-growth")
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(64):
        with run.managed_acquisition_claim(*components) as transaction:
            transaction.settle_precontact()
    after = len(os.listdir("/proc/self/fd"))
    assert after <= before + 2
    assert _claim_markers(run) == []


def test_one_shot_artifact_fence_cancellation_cannot_release_abandoned_marker(
    tmp_path, monkeypatch,
):
    run, _dest, components = _run(tmp_path, "fence-cancel-abandon")
    context = run.managed_acquisition_claim(*components)
    transaction = context.__enter__()
    transaction.settle_precontact()
    cancellation = KeyboardInterrupt("cancel first artifact fence")
    real_fence = store._ArtifactClaim.fence
    calls = 0

    def cancel_once(artifact):
        nonlocal calls
        if artifact is transaction.artifact and calls == 0:
            calls += 1
            raise cancellation
        return real_fence(artifact)

    monkeypatch.setattr(store._ArtifactClaim, "fence", cancel_once)
    with pytest.raises(KeyboardInterrupt) as caught:
        context.__exit__(None, None, None)

    assert caught.value is cancellation and calls == 1
    assert transaction.marker.abandoned
    assert not transaction.marker.released
    assert not transaction.settled
    assert len(_claim_markers(run)) == 1
    with pytest.raises(Exception, match="live artifact claim"):
        run.begin_finalization()
    started = time.monotonic()
    with pytest.raises(store.ManagedAcquisitionRefused, match="crash-stale"):
        with run.managed_acquisition_claim(*components):
            pass
    assert time.monotonic() - started < 0.5


def test_persistent_terminal_stage_cleanup_fault_retains_registry_and_fork_graph(
    tmp_path, monkeypatch,
):
    run, _dest, components = _run(tmp_path, "persistent-terminal-cleanup")
    context = run.managed_acquisition_claim(*components)
    transaction = context.__enter__()
    transaction.settle_precontact()
    writer = transaction.open_writer()
    os.write(writer, b"candidate")
    real_inspect = privfs._inspect_descriptor_claim

    def keep_source_writer_pending(claim, *, allow_unlinked):
        if claim.kind == "source_writer":
            raise KeyboardInterrupt("persistent source-writer cleanup fault")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(
            privfs, "_inspect_descriptor_claim", keep_source_writer_pending,
        )
        with pytest.raises(privfs.PrivatePathError):
            context.__exit__(None, None, None)

        stage = transaction.artifact._stage
        ledger = stage._cleanup_ledger
        assert stage.state == "aborted"
        assert ledger is not None and ledger.pending
        assert len(_claim_markers(run)) == 1
        assert id(transaction) in store._LIVE_MANAGED_ACQUISITIONS
        pending_fds = tuple(
            claim.fd for claim in ledger.claims if claim.fd >= 0
        )
        assert pending_fds

        child = os.fork()
        if child == 0:  # pragma: no cover - parent owns assertions
            result = 0
            try:
                if id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS:
                    result |= 1
                if all(_descriptor_is_closed(fd) for fd in pending_fds):
                    result |= 2
                if len(_claim_markers(run)) == 1:
                    result |= 4
            finally:
                os._exit(0 if result == 7 else 70)

        _waited, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0

    transaction.artifact.fence()
    with pytest.raises(Exception, match="abandoned"):
        transaction.settle()
    assert id(transaction) not in store._LIVE_MANAGED_ACQUISITIONS
    assert len(_claim_markers(run)) == 1


def test_persistent_body_cas_uncertainty_retains_live_lease_and_blocks_finalization(
    tmp_path, monkeypatch,
):
    run, dest, components = _run(tmp_path, "persistent-cas-uncertainty")
    real_sync = privfs._fsync_managed

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("persistent body directory durability failure")
        return real_sync(fd)

    monkeypatch.setattr(privfs, "_fsync_managed", fail_directory)
    baseline_fds = len(os.listdir("/proc/self/fd"))
    claim_context = run.managed_acquisition_claim(*components)
    claim = claim_context.__enter__()
    claim.settle_precontact()
    writer = claim.open_writer()
    contract.stream_to_fd(
        io.BytesIO(b"possibly landed body"), writer, budget_path=dest.parent,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    with pytest.raises(privfs.PrivatePublishIfAbsentUncertain):
        claim.publish_body_if_absent()
    with pytest.raises(Exception):
        claim_context.__exit__(None, None, None)

    assert dest.read_bytes() == b"possibly landed body"
    assert len(_claim_markers(run)) == 1
    assert len(os.listdir("/proc/self/fd")) <= baseline_fds + 1
    started = time.monotonic()
    with pytest.raises(store.ManagedAcquisitionRefused, match="crash-stale"):
        with run.managed_acquisition_claim(*components):
            pass
    assert time.monotonic() - started < 0.5
    retry_error: list[BaseException] = []
    retry_done = threading.Event()

    def retry():
        try:
            opened_retry = store.Run.open(tmp_path, "acme.example", run.run_id)
            with opened_retry.managed_acquisition_claim(*components):
                pass
        except BaseException as exc:
            retry_error.append(exc)
        finally:
            retry_done.set()

    retry_thread = threading.Thread(target=retry)
    retry_thread.start()
    assert retry_done.wait(0.5)
    retry_thread.join(1)
    assert retry_error and isinstance(
        retry_error[0], store.ManagedAcquisitionRefused,
    )
    opened = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(Exception, match="live artifact claim"):
        opened.begin_finalization()


def test_persistent_companion_cas_uncertainty_retains_destination_lease(
    tmp_path, monkeypatch,
):
    run, dest, components = _run(tmp_path, "persistent-companion-uncertainty")
    receipt = components[:-1] + (components[-1] + ".acq.json",)
    baseline_fds = len(os.listdir("/proc/self/fd"))
    claim_context = run.managed_acquisition_claim(*components)
    claim = claim_context.__enter__()
    claim.settle_precontact()
    writer = claim.open_writer()
    contract.stream_to_fd(
        io.BytesIO(b"durable body"), writer, budget_path=dest.parent,
        governor=contract.DiskGovernor(reserve_bytes=0),
    )
    assert claim.publish_body_if_absent() is True
    real_sync = privfs._fsync_managed

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("persistent receipt directory durability failure")
        return real_sync(fd)

    monkeypatch.setattr(privfs, "_fsync_managed", fail_directory)
    with pytest.raises(privfs.PrivatePublishIfAbsentUncertain):
        claim.publish_companion_if_absent(receipt, b"{}")
    with pytest.raises(Exception):
        claim_context.__exit__(None, None, None)

    assert len(_claim_markers(run)) == 1
    assert len(os.listdir("/proc/self/fd")) <= baseline_fds + 1
    started = time.monotonic()
    with pytest.raises(store.ManagedAcquisitionRefused, match="crash-stale"):
        with run.managed_acquisition_claim(*components):
            pass
    assert time.monotonic() - started < 0.5
    retry_error: list[BaseException] = []

    def retry():
        try:
            opened_retry = store.Run.open(tmp_path, "acme.example", run.run_id)
            with opened_retry.managed_acquisition_claim(*components):
                pass
        except BaseException as exc:
            retry_error.append(exc)

    retry_thread = threading.Thread(target=retry)
    retry_thread.start(); retry_thread.join(0.5)
    assert not retry_thread.is_alive()
    assert retry_error and isinstance(
        retry_error[0], store.ManagedAcquisitionRefused,
    )
    opened = store.Run.open(tmp_path, "acme.example", run.run_id)
    with pytest.raises(Exception, match="live artifact claim"):
        opened.begin_finalization()


def _executed_lines(function, call):
    reached = set()

    def trace(frame, event, _arg):
        if frame.f_code is function.__code__ and event == "line":
            reached.add(frame.f_lineno)
        return trace

    previous = sys.gettrace()
    try:
        sys.settrace(trace)
        call()
    finally:
        sys.settrace(previous)
    return reached


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_each_marker_allocation_line_preserves_exact_cancellation_without_fd_leak(
    tmp_path, cancellation_type,
):
    probe_run, _dest, probe_components = _run(tmp_path / "probe", "line-probe")
    reached = _executed_lines(
        store._ManagedAcquisitionMarker._open_attempt_locked,
        lambda: _enter_and_exit(probe_run, probe_components),
    )
    for index, line in enumerate(sorted(reached)):
        case = tmp_path / f"{cancellation_type.__name__}-{index}"
        run, _dest, components = _run(case, "line-cancel")
        cancellation = cancellation_type(f"marker allocation line {line}")
        fired = False

        def trace(frame, event, _arg):
            nonlocal fired
            if (frame.f_code is store._ManagedAcquisitionMarker._open_attempt_locked.__code__
                    and event == "line" and frame.f_lineno == line and not fired):
                fired = True
                sys.settrace(None)
                raise cancellation
            return trace

        before = len(os.listdir("/proc/self/fd"))
        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                with run.managed_acquisition_claim(*components):
                    pass
        finally:
            sys.settrace(previous)
        assert fired and caught.value is cancellation
        assert len(os.listdir("/proc/self/fd")) <= before + 2
        markers = _claim_markers(run)
        if markers:
            with pytest.raises(Exception, match="live artifact claim"):
                run.begin_finalization()
        else:
            run.begin_finalization()


def _enter_and_exit(run, components):
    with run.managed_acquisition_claim(*components) as transaction:
        transaction.settle_precontact()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "operation",
    [store._ManagedAcquisitionMarker._settle_locked,
     store._ManagedAcquisitionMarker.settle],
)
def test_each_marker_settlement_line_preserves_exact_cancellation_and_releases(
    tmp_path, cancellation_type, operation,
):
    probe_run, _dest, probe_components = _run(
        tmp_path / "settle-probe", "settle-probe",
    )
    reached = _executed_lines(
        operation, lambda: _enter_and_exit(probe_run, probe_components),
    )
    for index, line in enumerate(sorted(reached)):
        case = tmp_path / f"{operation.__name__}-{cancellation_type.__name__}-{index}"
        run, _dest, components = _run(case, "settle-cancel")
        cancellation = cancellation_type(f"marker settlement line {line}")
        fired = False

        def trace(frame, event, _arg):
            nonlocal fired
            if (frame.f_code is operation.__code__ and event == "line"
                    and frame.f_lineno == line and not fired):
                fired = True
                sys.settrace(None)
                raise cancellation
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                _enter_and_exit(run, components)
        finally:
            sys.settrace(previous)
        assert fired and caught.value is cancellation
        markers = _claim_markers(run)
        if markers:
            with pytest.raises(Exception, match="live artifact claim"):
                run.begin_finalization()
        else:
            run.begin_finalization()


def test_same_thread_recursive_destination_claim_refuses_without_deadlock(tmp_path):
    run, _dest, components = _run(tmp_path, "same-thread-recursion")
    with run.managed_acquisition_claim(*components) as transaction:
        started = time.monotonic()
        with pytest.raises(store.ManagedAcquisitionRefused, match="already claimed"):
            with run.managed_acquisition_claim(*components):
                pass
        assert time.monotonic() - started < 0.5
        transaction.settle_precontact()


def _discard_once(run, dest, components):
    with run.managed_acquisition_claim(*components) as claim:
        writer = claim.open_writer()
        contract.stream_to_fd(
            io.BytesIO(b"discard body"), writer, budget_path=dest.parent,
            governor=contract.DiskGovernor(reserve_bytes=0),
        )
        assert claim.publish_body_if_absent() is True
        owned = claim.snapshot(components)
        assert owned is not None
        claim.settle_precontact()
        return claim.remove_if_matches(components, owned)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_each_discard_line_reconciles_truth_before_exact_cancellation_escapes(
    tmp_path, cancellation_type,
):
    probe_run, probe_dest, probe_components = _run(
        tmp_path / "discard-probe", "discard-probe",
    )
    reached = _executed_lines(
        store._ManagedAcquisitionTransaction._remove_if_matches_inner,
        lambda: _discard_once(probe_run, probe_dest, probe_components),
    )
    for index, line in enumerate(sorted(reached)):
        case = tmp_path / f"discard-{cancellation_type.__name__}-{index}"
        run, dest, components = _run(case, "discard-cancel")
        cancellation = cancellation_type(f"discard line {line}")
        fired = False

        def trace(frame, event, _arg):
            nonlocal fired
            if (frame.f_code is store._ManagedAcquisitionTransaction._remove_if_matches_inner.__code__
                    and event == "line" and frame.f_lineno == line and not fired):
                fired = True
                sys.settrace(None)
                raise cancellation
            return trace

        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            with pytest.raises(cancellation_type) as caught:
                _discard_once(run, dest, components)
        finally:
            sys.settrace(previous)
        assert fired and caught.value is cancellation
        fact = getattr(cancellation, "managed_removal", None)
        assert type(fact) is store.ManagedRemoval
        if fact.state.startswith("removed"):
            assert not dest.exists()
        elif fact.state in {"unremoved", "changed"}:
            assert dest.read_bytes() == b"discard body"
        else:
            assert fact.state == "absent" and not dest.exists()
        assert _claim_markers(run) == []
        run.begin_finalization()
