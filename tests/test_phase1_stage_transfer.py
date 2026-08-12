"""Phase 1 parent-writer close evidence and post-spawn fencing contracts."""
from __future__ import annotations

import dataclasses
import errno
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import privfs


pytestmark = pytest.mark.offline

REQUEST_ID = "0123456789abcdef0123456789abcdef"
OTHER_REQUEST_ID = "11111111111111111111111111111111"
WORKER_PID = 4242


@pytest.fixture
def private_root(tmp_path: Path):
    os.chmod(tmp_path, privfs.DIR_MODE)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield tmp_path, fd
    finally:
        os.close(fd)


def _write_exact(fd: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        try:
            count = os.write(fd, data[written:])
        except InterruptedError:
            continue
        if count <= 0:
            raise OSError("test stage write made no progress")
        written += count


def _make_stages(root_fd: int, count: int = 3, *, stem: str = "result"):
    stages = []
    try:
        for index in range(count):
            stage = privfs.create_private_stage(root_fd, (f"{stem}-{index}",))
            _write_exact(stage.file_fd, f"payload-{index}".encode())
            stages.append(stage)
        return tuple(stages)
    except BaseException:
        for stage in stages:
            if stage.state in {"open", "sealed"}:
                stage.abort()
        raise


def _prepare(root_fd: int, count: int = 3, *, request_id: str = REQUEST_ID,
             stem: str = "result"):
    stages = _make_stages(root_fd, count, stem=stem)
    batch = privfs.prepare_private_stage_handoff(stages, request_id)
    return stages, batch


def _prepare_authority(batch, *, request_id: str = REQUEST_ID):
    return privfs._prepare_private_stage_transfer_authority(
        batch, request_id=request_id,
    )


def _bind(batch, authority, *, worker_pid: int = WORKER_PID):
    return privfs._bind_private_stage_transfer_authority(
        batch, authority, worker_pid=worker_pid,
    )


def _spawn(batch, authority, *, worker_pid: int = WORKER_PID):
    writers = _reserved_writers(batch)
    child = SimpleNamespace(pid=worker_pid)
    calls = 0

    def spawn_callback(pass_fds):
        nonlocal calls
        calls += 1
        assert pass_fds == writers
        return child

    returned_child, returned_authority = privfs._spawn_with_private_stage_handoff(
        batch, authority, spawn_callback,
    )
    assert calls == 1
    assert returned_child is child
    assert returned_authority is authority
    return child


def _park(batch, *, request_id: str = REQUEST_ID, worker_pid: int = WORKER_PID):
    authority = _prepare_authority(batch, request_id=request_id)
    assert _spawn(batch, authority, worker_pid=worker_pid).pid == worker_pid
    assert _bind(batch, authority, worker_pid=worker_pid) is authority
    return authority


def _settle(batch) -> None:
    if batch.state == "prepared":
        batch.abort()
    elif batch.state == "spawn_prepared":
        authority = object.__getattribute__(batch, "_transfer_authority")
        privfs._abort_private_stage_spawn(batch, authority)
    elif batch.state == "worker_spawned_unverified":
        privfs.fence_private_stage_handoff(batch)
    elif batch.state == "worker_claim_bound":
        # The caller-attested worker correlation is represented by this boundary.
        privfs.fence_private_stage_handoff(batch)
    elif batch.state in {"parent_writers_closed", "transfer_uncertain"}:
        privfs.fence_private_stage_handoff(batch)


def _all_owned_fds(batch, stages) -> tuple[int, ...]:
    ledger = object.__getattribute__(batch, "_cleanup_ledger")
    return tuple(claim.fd for claim in ledger.claims if claim.fd >= 0)


def _reserved_writers(batch) -> tuple[int, ...]:
    """Inspect ledger-owned writers without treating them as spawn authority."""
    ledger = object.__getattribute__(batch, "_cleanup_ledger")
    return tuple(stage_claim.writer.fd for stage_claim in ledger.stage_claims)


def _ledger(batch):
    return object.__getattribute__(batch, "_cleanup_ledger")


def _batch_claim(batch, index: int, kind: str):
    return getattr(_ledger(batch).stage_claims[index], kind)


def _assert_public_stage_fds_tombstoned(stages) -> None:
    assert all(
        (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
        for stage in stages
    )


def _unpublished_paths(root: Path) -> list[Path]:
    return sorted(root.rglob(".quarry-*.stage"))


def _assert_unpublished_payloads(root: Path, expected: list[bytes]) -> None:
    assert sorted(path.read_bytes() for path in _unpublished_paths(root)) == sorted(expected)
    assert not list(root.rglob(".quarry-discard-*.stage"))


def _assert_closed(fd: int) -> None:
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF


def _reuse_as_unrelated_private_file(root: Path, exposed_fd: int) -> int:
    """Replace a stale exposed number with a different valid private-file inode."""
    try:
        os.close(exposed_fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    decoy = root / f"unrelated-{os.urandom(8).hex()}"
    opened = os.open(
        decoy,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        privfs.FILE_MODE,
    )
    os.fchmod(opened, privfs.FILE_MODE)
    if opened != exposed_fd:
        os.dup2(opened, exposed_fd)
        os.close(opened)
    os.write(exposed_fd, b"unrelated")
    return exposed_fd


def _make_nested_stage(root: Path, root_fd: int, *, stem: str):
    parent = root / f"{stem}-parent"
    parent.mkdir()
    os.chmod(parent, privfs.DIR_MODE)
    stage = privfs.create_private_stage(root_fd, (parent.name, f"{stem}-result"))
    _write_exact(stage.file_fd, b"payload")
    return parent, stage


def _prepare_nested(root: Path, root_fd: int, *, stem: str):
    _, stage = _make_nested_stage(root, root_fd, stem=stem)
    batch = privfs.prepare_private_stage_handoff((stage,), REQUEST_ID)
    return stage, batch


def _reuse_as_unrelated_private_dir(
    root: Path, exposed_fd: int, temporary_name: str,
) -> tuple[int, Path, bytes]:
    decoy = root / f"decoy-{os.urandom(8).hex()}"
    decoy.mkdir()
    os.chmod(decoy, privfs.DIR_MODE)
    marker = b"unrelated-directory-marker"
    planted = decoy / temporary_name
    planted.write_bytes(marker)
    os.chmod(planted, privfs.FILE_MODE)
    try:
        os.close(exposed_fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
    opened = os.open(decoy, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if opened != exposed_fd:
        os.dup2(opened, exposed_fd)
        os.close(opened)
    return exposed_fd, decoy, marker


def _assert_decoy_dir_untouched(
    decoy_fd: int, decoy: Path, temporary_name: str, marker: bytes,
) -> None:
    os.fstat(decoy_fd)
    marker_fd = os.open(
        temporary_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=decoy_fd,
    )
    try:
        assert os.read(marker_fd, len(marker) + 1) == marker
    finally:
        os.close(marker_fd)
    assert (decoy / temporary_name).read_bytes() == marker
    assert not list(decoy.glob(".quarry-discard-*.stage"))


def _advance_directory_cleanup_case(batch, cleanup_state: str):
    authority = _prepare_authority(batch)
    if cleanup_state in {"worker_spawned_unverified", "worker_claim_bound"}:
        _spawn(batch, authority)
    if cleanup_state == "worker_claim_bound":
        _bind(batch, authority)
    return authority


def _assert_handoff_error(error, operation: str) -> None:
    assert isinstance(error, privfs.PrivateStageHandoffError)
    assert error.operation == operation
    assert error.components == ()
    assert str(error) == f"private stage handoff {operation} failed"


def _assert_state_error(error, operation: str, state: str) -> None:
    assert isinstance(error, privfs.PrivateStageStateError)
    assert (error.operation, error.state) == (operation, state)
    assert error.components == ()
    assert str(error) == f"private stage operation {operation} is invalid in state {state}"


def _assert_secret_safe(value, stages, *, request_id: str = REQUEST_ID) -> None:
    rendered = repr(value)
    assert request_id not in rendered
    for stage in stages:
        assert stage.temporary_name not in rendered
        assert stage.destination_name not in rendered
        assert "/".join(stage.components) not in rendered


def test_transfer_is_exact_batch_bound_and_returns_a_frozen_ordered_receipt(
    private_root,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    identities = tuple(stage.file_identity for stage in stages)
    authority = _park(batch)

    try:
        receipt = privfs.transfer_private_stage_handoff(batch, authority)

        assert isinstance(receipt, privfs.PrivateStageParentCloseReceipt)
        assert tuple(field.name for field in dataclasses.fields(receipt)) == (
            "request_id", "claimed_worker_pid", "file_identities", "state",
        )
        assert receipt.request_id == REQUEST_ID
        assert receipt.claimed_worker_pid == WORKER_PID
        assert receipt.file_identities == identities
        assert receipt.state == "parent_writers_closed"
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            receipt.state = "prepared"

        assert batch.state == "parent_writers_closed"
        assert batch.pass_fds == ()
        assert tuple(stage.state for stage in stages) == ("parent_writers_closed",) * 3
        assert tuple(
            stage_claim.writer.disposition
            for stage_claim in _ledger(batch).stage_claims
        ) == ("closed_clean",) * 3
        assert all(not stage_claim.writer.errors
                   for stage_claim in _ledger(batch).stage_claims)
        for writer in writers:
            _assert_closed(writer)
        _assert_secret_safe(authority, stages)
        _assert_secret_safe(receipt, stages)
        assert str(identities) not in repr(receipt)
    finally:
        _settle(batch)


def test_cleanup_ledger_is_the_batchs_only_descriptor_authority(private_root):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 3)
    ledger = _ledger(batch)
    try:
        assert not hasattr(batch, "_writer_fds")
        assert not hasattr(batch, "_pin_fds")
        assert tuple(stage_claim.writer.fd for stage_claim in ledger.stage_claims)
        assert tuple(stage_claim.pin.fd for stage_claim in ledger.stage_claims)
        _assert_public_stage_fds_tombstoned(stages)
    finally:
        batch.abort()


@pytest.mark.parametrize("worker_pid", [True, 0, -1, 1 << 31, "4242"])
def test_spawn_callback_invalid_pid_fences_before_returning(
    private_root, worker_pid,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd, 1)
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)
    callback_calls = 0

    def malformed_child(pass_fds):
        nonlocal callback_calls
        callback_calls += 1
        assert pass_fds == writers
        return SimpleNamespace(pid=worker_pid)

    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs._spawn_with_private_stage_handoff(
            batch, authority, malformed_child,
        )

    _assert_handoff_error(caught.value, "mark_spawned")
    assert callback_calls == 1
    _assert_secret_safe(caught.value, stages)
    assert batch.state == "fenced" and batch.pass_fds == ()
    assert stages[0].state == "fenced"
    assert authority.pass_fds == ()
    for writer in writers:
        _assert_closed(writer)
    with pytest.raises(privfs.PrivateStageStateError) as aborted:
        batch.abort()
    _assert_state_error(aborted.value, "abort_handoff", "fenced")
    _assert_unpublished_payloads(root, [b"payload-0"])


def test_spawn_mark_cancellation_is_reported_and_fenced(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 2)
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)
    real_force = privfs._force_worker_spawned_unverified_state

    def mark_then_interrupt(*args, **kwargs):
        real_force(*args, **kwargs)
        raise KeyboardInterrupt("cancel after Popen boundary")

    with monkeypatch.context() as patch:
        patch.setattr(
            privfs, "_force_worker_spawned_unverified_state", mark_then_interrupt,
        )
        with pytest.raises(privfs.PrivateStageSpawnUncertain) as caught:
            _spawn(batch, authority)

    _assert_handoff_error(caught.value, "mark_spawned")
    assert caught.value.authority is authority
    assert caught.value.claimed_worker_pid == WORKER_PID
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced",) * 2
    assert authority.pass_fds == ()
    for writer in writers:
        _assert_closed(writer)


def test_mismatched_worker_claim_never_upgrades_unverified_worker(private_root):
    _, root_fd = private_root
    (stage,), batch = _prepare(root_fd, 1)
    authority = _prepare_authority(batch)
    _spawn(batch, authority)

    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        _bind(batch, authority, worker_pid=WORKER_PID + 1)
    _assert_handoff_error(caught.value, "bind_worker")
    assert batch.state == stage.state == "worker_spawned_unverified"
    privfs.fence_private_stage_handoff(batch)
    assert batch.state == stage.state == "fenced"


def test_worker_authority_rejects_wrong_request_without_claiming(private_root):
    _, root_fd = private_root
    _, batch = _prepare(root_fd, 1)
    writers = _reserved_writers(batch)

    try:
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            _prepare_authority(batch, request_id=OTHER_REQUEST_ID)
        _assert_handoff_error(caught.value, "bind_worker")
        assert batch.state == "prepared" and batch.pass_fds == ()

        authority = _park(batch)
        assert privfs.transfer_private_stage_handoff(batch, authority).request_id == REQUEST_ID
    finally:
        _settle(batch)


def test_bind_moves_the_whole_batch_to_worker_claim_bound_and_hides_writers(private_root):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    names = tuple(stage.temporary_name for stage in stages)

    authority = _park(batch)
    try:
        assert batch.state == "worker_claim_bound"
        assert batch.pass_fds == ()
        assert tuple(stage.state for stage in stages) == ("worker_claim_bound",) * 3
        for writer in writers:
            os.fstat(writer)

        with pytest.raises(privfs.PrivateStageStateError) as caught:
            batch.abort()
        _assert_state_error(caught.value, "abort_handoff", "worker_claim_bound")
        assert batch.state == "worker_claim_bound"
        assert not list(root.glob(".quarry-discard-*.stage"))
        assert all(
            (root.joinpath(*stage.components[:-1]) / name).is_file()
            for stage, name in zip(stages, names)
        )

        receipt = privfs.transfer_private_stage_handoff(batch, authority)
        assert receipt.state == "parent_writers_closed"
    finally:
        _settle(batch)


@pytest.mark.parametrize(
    "state",
    [
        "spawn_prepared",
        "worker_spawned_unverified",
        "worker_claim_bound",
        "parent_writers_closed",
        "transfer_uncertain",
    ],
)
def test_batch_context_with_primary_fences_every_post_reservation_state(
    private_root, monkeypatch, state,
):
    root, root_fd = private_root
    for index in range(3):
        destination = root / f"result-{index}"
        destination.write_bytes(f"prior-{index}".encode())
        os.chmod(destination, privfs.FILE_MODE)
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    all_fds = _all_owned_fds(batch, stages)
    authority = _prepare_authority(batch)
    if state != "spawn_prepared":
        _spawn(batch, authority)
    if state in {"worker_claim_bound", "parent_writers_closed", "transfer_uncertain"}:
        _bind(batch, authority)
    if state == "parent_writers_closed":
        privfs.transfer_private_stage_handoff(batch, authority)
    elif state == "transfer_uncertain":
        real_close = privfs._close_owned
        reported = False

        def close_then_report(fd):
            nonlocal reported
            result = real_close(fd)
            if fd == writers[0] and not reported:
                reported = True
                return OSError(errno.EIO, "ambiguous writer close")
            return result

        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", close_then_report)
            with pytest.raises(privfs.PrivateStageTransferUncertain):
                privfs.transfer_private_stage_handoff(batch, authority)
        assert reported

    primary = RuntimeError("primary work failed")
    with pytest.raises(RuntimeError) as caught:
        with batch:
            raise primary

    assert caught.value is primary
    assert not hasattr(primary, "private_cleanup_error")
    assert batch.state == "fenced" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("fenced",) * 3
    assert [(root / f"result-{index}").read_bytes() for index in range(3)] == [
        b"prior-0", b"prior-1", b"prior-2",
    ]
    _assert_unpublished_payloads(
        root, [b"payload-0", b"payload-1", b"payload-2"],
    )
    for fd in all_fds:
        _assert_closed(fd)


def test_bind_transition_cancellation_stays_claim_bound_and_exposes_recovery_authority(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd, 2, stem="bind-secret")
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)
    _spawn(batch, authority)
    real_force = privfs._force_worker_claim_bound_state
    interrupted = False

    def force_then_interrupt(*args, **kwargs):
        nonlocal interrupted
        real_force(*args, **kwargs)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("cancel claim bind")

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_force_worker_claim_bound_state", force_then_interrupt)
        with pytest.raises(privfs.PrivateStageBindUncertain) as caught:
            _bind(batch, authority)

    assert interrupted
    _assert_handoff_error(caught.value, "bind_worker")
    assert caught.value.authority is authority
    _assert_secret_safe(caught.value, stages)
    assert batch.state == "worker_claim_bound" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("worker_claim_bound",) * 2
    assert not list(root.glob(".quarry-discard-*.stage"))
    for writer in writers:
        os.fstat(writer)
    with pytest.raises(privfs.PrivateStageStateError) as aborted:
        batch.abort()
    _assert_state_error(aborted.value, "abort_handoff", "worker_claim_bound")

    privfs.fence_private_stage_handoff(batch)
    for writer in writers:
        _assert_closed(writer)


def test_only_callback_spawn_api_can_consume_one_worker_authority(private_root):
    _, root_fd = private_root
    _, batch = _prepare(root_fd, 1)
    writers = _reserved_writers(batch)
    assert batch.state == "prepared" and batch.pass_fds == ()
    authority = _prepare_authority(batch)

    try:
        assert batch.state == "spawn_prepared" and batch.pass_fds == ()
        assert authority.pass_fds == ()
        assert not hasattr(privfs, "_private_stage_spawn_attempt")
        assert not hasattr(privfs, "_PrivateStageSpawnAttempt")
        with pytest.raises(privfs.PrivateStageHandoffError) as raw_borrow:
            privfs._borrow_private_stage_spawn_fds(batch, authority)
        _assert_handoff_error(raw_borrow.value, "borrow_spawn")
        with pytest.raises(privfs.PrivateStageHandoffError) as raw_mark:
            privfs._mark_private_stage_worker_spawned(
                batch, authority, worker_pid=WORKER_PID,
            )
        _assert_handoff_error(raw_mark.value, "mark_spawned")
        with pytest.raises(privfs.PrivateStageStateError) as caught:
            _prepare_authority(batch)
        _assert_state_error(caught.value, "bind_worker", "spawn_prepared")
        assert authority.pass_fds == ()

        _spawn(batch, authority)
        with pytest.raises(privfs.PrivateStageStateError) as replay:
            privfs._spawn_with_private_stage_handoff(
                batch, authority, lambda _pass_fds: SimpleNamespace(pid=WORKER_PID),
            )
        _assert_state_error(replay.value, "borrow_spawn", "worker_spawned_unverified")
        _bind(batch, authority)
        assert authority.pass_fds == ()
        assert privfs.transfer_private_stage_handoff(batch, authority).claimed_worker_pid == WORKER_PID
    finally:
        _settle(batch)


@pytest.mark.parametrize("pause_at", ["callback", "mark"])
def test_spawn_callback_holds_every_stage_lock_through_mark_against_fence(
    private_root, monkeypatch, pause_at,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 2)
    writers = _reserved_writers(batch)
    all_fds = _all_owned_fds(batch, stages)
    authority = _prepare_authority(batch)
    pause_entered = threading.Event()
    continue_spawn = threading.Event()
    fence_started = threading.Event()
    callback_calls = 0
    results = {}
    real_mark = privfs._force_worker_spawned_unverified_state

    def spawn_callback(pass_fds):
        nonlocal callback_calls
        callback_calls += 1
        assert pass_fds == writers
        if pause_at == "callback":
            pause_entered.set()
            assert continue_spawn.wait(5)
        return SimpleNamespace(pid=WORKER_PID)

    def pause_mark(*args, **kwargs):
        if pause_at == "mark":
            pause_entered.set()
            assert continue_spawn.wait(5)
        return real_mark(*args, **kwargs)

    def run_spawn():
        try:
            results["spawn"] = privfs._spawn_with_private_stage_handoff(
                batch, authority, spawn_callback,
            )
        except BaseException as exc:
            results["spawn_error"] = exc

    def run_fence():
        fence_started.set()
        try:
            privfs.fence_private_stage_handoff(batch)
        except BaseException as exc:
            results["fence_error"] = exc

    spawn_thread = threading.Thread(target=run_spawn, daemon=True)
    fence_thread = threading.Thread(target=run_fence, daemon=True)
    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_force_worker_spawned_unverified_state", pause_mark)
        spawn_thread.start()
        assert pause_entered.wait(5)
        fence_thread.start()
        assert fence_started.wait(5)
        assert fence_thread.is_alive()
        assert batch.state in {"spawn_prepared", "worker_spawned_unverified"}
        for writer in writers:
            os.fstat(writer)
        continue_spawn.set()
        spawn_thread.join(5)
        fence_thread.join(5)

    assert not spawn_thread.is_alive() and not fence_thread.is_alive()
    assert callback_calls == 1
    assert set(results) == {"spawn"}
    child, returned_authority = results["spawn"]
    assert child.pid == WORKER_PID and returned_authority is authority
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced",) * 2
    for fd in all_fds:
        _assert_closed(fd)


def test_spawn_callback_base_exception_after_simulated_popen_fences_once(
    private_root,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd, 2)
    all_fds = _all_owned_fds(batch, stages)
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)
    primary = KeyboardInterrupt("cancel after simulated Popen")
    callback_calls = 0

    def cancelled_callback(pass_fds):
        nonlocal callback_calls
        callback_calls += 1
        assert pass_fds == writers
        raise primary

    with pytest.raises(KeyboardInterrupt) as caught:
        privfs._spawn_with_private_stage_handoff(
            batch, authority, cancelled_callback,
        )

    assert caught.value is primary
    assert callback_calls == 1
    assert not hasattr(primary, "private_cleanup_error")
    assert batch.state == "fenced" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("fenced",) * 2
    _assert_unpublished_payloads(root, [b"payload-0", b"payload-1"])
    for fd in all_fds:
        _assert_closed(fd)


def test_spawn_callback_handler_entry_interruption_still_fences_before_unlock(
    private_root,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 2)
    ledger = _ledger(batch)
    all_fds = _all_owned_fds(batch, stages)
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)
    armed = [False]
    injected = [False]
    callback_calls = 0

    def failed_callback(pass_fds):
        nonlocal callback_calls
        callback_calls += 1
        assert pass_fds == writers
        armed[0] = True
        raise OSError(errno.EIO, "simulated Popen outcome unknown")

    def trace_handler(frame, event, arg):
        if (event == "line" and armed[0] and not injected[0]
                and frame.f_code.co_name == "_spawn_with_private_stage_handoff"):
            injected[0] = True
            armed[0] = False
            raise KeyboardInterrupt("cancel callback recovery handler")
        return trace_handler

    caught = None
    sys.settrace(trace_handler)
    try:
        try:
            privfs._spawn_with_private_stage_handoff(
                batch, authority, failed_callback,
            )
        except BaseException as exc:
            caught = exc
    finally:
        sys.settrace(None)

    assert injected == [True]
    assert isinstance(caught, KeyboardInterrupt)
    assert callback_calls == 1
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced", "fenced")
    assert authority.pass_fds == ()
    assert object.__getattribute__(authority, "_consumed") is True
    assert object.__getattribute__(authority, "_borrowed") is False
    assert object.__getattribute__(batch, "_transfer_authority") is None
    assert not ledger.pending
    for fd in all_fds:
        _assert_closed(fd)

    # Lifecycle locks were released despite the second interruption.
    finished = threading.Event()

    def replay_fence():
        privfs.fence_private_stage_handoff(batch)
        finished.set()

    thread = threading.Thread(target=replay_fence, daemon=True)
    thread.start()
    thread.join(5)
    assert finished.is_set() and not thread.is_alive()


def test_spawn_success_finally_entry_interruption_retains_reachable_unverified_attempt(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd, 2)
    ledger = _ledger(batch)
    all_fds = _all_owned_fds(batch, stages)
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)
    child = SimpleNamespace(pid=WORKER_PID)
    armed = [False]
    injected = [False]
    callback_calls = 0
    real_mark = privfs._mark_private_stage_worker_spawned_locked

    def successful_callback(pass_fds):
        nonlocal callback_calls
        callback_calls += 1
        assert pass_fds == writers
        return child

    def mark_then_arm(*args, **kwargs):
        result = real_mark(*args, **kwargs)
        assert batch.state == "worker_spawned_unverified"
        armed[0] = True
        return result

    def trace_finally_entry(frame, event, arg):
        if (event == "line" and armed[0] and not injected[0]
                and frame.f_code.co_name == "_spawn_with_private_stage_handoff"
                and frame.f_locals.get("result") is not None):
            injected[0] = True
            armed[0] = False
            raise KeyboardInterrupt("cancel successful spawn finally entry")
        return trace_finally_entry

    caught = None
    sys.settrace(trace_finally_entry)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                privfs, "_mark_private_stage_worker_spawned_locked", mark_then_arm,
            )
            try:
                privfs._spawn_with_private_stage_handoff(
                    batch, authority, successful_callback,
                )
            except BaseException as exc:
                caught = exc
    finally:
        sys.settrace(None)

    assert injected == [True]
    assert isinstance(caught, KeyboardInterrupt)
    assert callback_calls == 1
    # This outermost async-injection seam is outside cooperative cancellation's
    # automatic-recovery contract pending an explicit architecture decision.  It
    # must nevertheless retain one exact, nonpublishable attempt for the supervisor.
    assert batch.state == "worker_spawned_unverified"
    assert tuple(stage.state for stage in stages) == (
        "worker_spawned_unverified", "worker_spawned_unverified",
    )
    assert object.__getattribute__(batch, "_transfer_authority") is authority
    assert object.__getattribute__(authority, "_consumed") is False
    assert object.__getattribute__(authority, "_borrowed") is True
    assert authority.pass_fds == ()
    assert object.__getattribute__(batch, "_transfer_receipt") is None
    assert ledger.pending
    pending = tuple(
        claim for claim in ledger.claims
        if claim.disposition not in privfs._DESCRIPTOR_CLAIM_TERMINAL
    )
    assert {claim.fd for claim in pending} == set(all_fds)
    for fd in all_fds:
        os.fstat(fd)
    assert all(not (root / stage.destination_name).exists() for stage in stages)
    for stage in stages:
        for operation in (
            lambda stage=stage: privfs.seal_private_stage(stage),
            lambda stage=stage: privfs.replace_private_stage(stage),
            stage.abort,
        ):
            with pytest.raises(privfs.PrivateStageStateError):
                operation()

    errors = []

    def supervisor_fence():
        try:
            privfs.fence_private_stage_handoff(batch)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=supervisor_fence, daemon=True)
    thread.start()
    thread.join(5)
    assert not thread.is_alive() and errors == []
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced", "fenced")
    assert object.__getattribute__(authority, "_consumed") is True
    assert object.__getattribute__(authority, "_borrowed") is False
    assert object.__getattribute__(batch, "_transfer_authority") is None
    assert object.__getattribute__(batch, "_transfer_receipt") is None
    assert not ledger.pending
    for fd in all_fds:
        _assert_closed(fd)


def test_spawn_callback_missing_pid_fences_before_returning(private_root):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 1)
    all_fds = _all_owned_fds(batch, stages)
    authority = _prepare_authority(batch)

    with pytest.raises(AttributeError):
        privfs._spawn_with_private_stage_handoff(
            batch, authority, lambda _pass_fds: SimpleNamespace(),
        )

    assert batch.state == stages[0].state == "fenced"
    for fd in all_fds:
        _assert_closed(fd)


def test_spawn_callback_refuses_a_reused_writer_without_invocation_and_is_fenceable(
    private_root,
):
    root, root_fd = private_root
    (stage,), batch = _prepare(root_fd, 1)
    writer = _reserved_writers(batch)[0]
    authority = _prepare_authority(batch)
    decoy_fd = _reuse_as_unrelated_private_file(root, writer)
    callback_calls = 0

    def forbidden_callback(_pass_fds):
        nonlocal callback_calls
        callback_calls += 1
        return SimpleNamespace(pid=WORKER_PID)

    try:
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs._spawn_with_private_stage_handoff(
                batch, authority, forbidden_callback,
            )
        _assert_handoff_error(caught.value, "borrow_spawn")
        assert callback_calls == 0
        assert batch.state == stage.state == "spawn_prepared"
        assert batch.pass_fds == authority.pass_fds == ()
        os.fstat(decoy_fd)

        with pytest.raises(privfs.PrivateStageHandoffError) as fenced:
            privfs.fence_private_stage_handoff(batch)
        _assert_handoff_error(fenced.value, "fence")
        assert batch.state == stage.state == "fenced"
        os.fstat(decoy_fd)
    finally:
        os.close(decoy_fd)


def test_exact_abort_spawn_consumes_and_closes_the_reserved_batch(private_root):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd, 2)
    owned_fds = _all_owned_fds(batch, stages)
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)

    assert batch.state == "spawn_prepared" and batch.pass_fds == ()
    assert authority.pass_fds == ()
    assert privfs._abort_private_stage_spawn(batch, authority) is None

    assert batch.state == "aborted" and batch.pass_fds == ()
    assert authority.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("aborted",) * 2
    _assert_unpublished_payloads(root, [b"payload-0", b"payload-1"])
    assert not list(root.glob("result-*"))
    for fd in owned_fds:
        _assert_closed(fd)

    # Only the exact, now-consumed authority has an idempotent replay.
    assert privfs._abort_private_stage_spawn(batch, authority) is None
    with pytest.raises(privfs.PrivateStageStateError) as caught:
        _bind(batch, authority)
    _assert_state_error(caught.value, "bind_worker", "aborted")


def test_abort_spawn_rejects_wrong_authority_without_consuming_the_batch(private_root):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 1)
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)

    try:
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs._abort_private_stage_spawn(batch, object())
        _assert_handoff_error(caught.value, "abort_spawn")
        assert batch.state == stages[0].state == "spawn_prepared"
        assert batch.pass_fds == () and authority.pass_fds == ()
        for writer in writers:
            os.fstat(writer)
    finally:
        privfs._abort_private_stage_spawn(batch, authority)


def test_abort_spawn_replay_requires_the_exact_consumed_authority(private_root):
    _, root_fd = private_root
    _, batch = _prepare(root_fd, 1)
    authority = _prepare_authority(batch)
    privfs._abort_private_stage_spawn(batch, authority)

    assert privfs._abort_private_stage_spawn(batch, authority) is None
    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs._abort_private_stage_spawn(batch, object())
    _assert_handoff_error(caught.value, "abort_spawn")
    assert batch.state == "aborted"


def test_abort_spawn_rejects_cross_batch_authority_without_consuming_either(
    private_root,
):
    _, root_fd = private_root
    stages_a, batch_a = _prepare(root_fd, 1, stem="first")
    stages_b, batch_b = _prepare(
        root_fd, 1, stem="second", request_id=OTHER_REQUEST_ID,
    )
    writers_a = _reserved_writers(batch_a)
    writers_b = _reserved_writers(batch_b)
    authority = _prepare_authority(batch_a)
    authority_b = _prepare_authority(batch_b, request_id=OTHER_REQUEST_ID)

    try:
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs._abort_private_stage_spawn(batch_b, authority)
        _assert_handoff_error(caught.value, "abort_spawn")
        assert batch_a.state == batch_b.state == "spawn_prepared"
        assert batch_a.pass_fds == batch_b.pass_fds == ()
        assert authority.pass_fds == ()
        assert authority_b.pass_fds == ()
        for writer in writers_a:
            os.fstat(writer)
        for writer in writers_b:
            os.fstat(writer)
    finally:
        privfs._abort_private_stage_spawn(batch_a, authority)
        privfs._abort_private_stage_spawn(batch_b, authority_b)

    assert tuple(stage.state for stage in stages_a) == ("aborted",)
    assert tuple(stage.state for stage in stages_b) == ("aborted",)


def test_generic_abort_cannot_consume_spawn_prepared(private_root):
    root, root_fd = private_root
    (stage,), batch = _prepare(root_fd, 1)
    writers = _reserved_writers(batch)
    authority = _prepare_authority(batch)

    with pytest.raises(privfs.PrivateStageStateError) as batch_error:
        batch.abort()
    _assert_state_error(batch_error.value, "abort_handoff", "spawn_prepared")
    with pytest.raises(privfs.PrivateStageStateError) as stage_error:
        stage.abort()
    _assert_state_error(stage_error.value, "abort", "spawn_prepared")
    with stage:
        pass

    assert batch.state == stage.state == "spawn_prepared"
    assert batch.pass_fds == () and authority.pass_fds == ()
    assert not list(root.glob(".quarry-discard-*.stage"))
    privfs._abort_private_stage_spawn(batch, authority)


def test_ambiguous_popen_boundary_fences_spawn_prepared_without_publication(
    private_root,
):
    root, root_fd = private_root
    destination = root / "result-0"
    destination.write_bytes(b"prior")
    os.chmod(destination, privfs.FILE_MODE)
    stages, batch = _prepare(root_fd, 1)
    owned = _all_owned_fds(batch, stages)
    authority = _prepare_authority(batch)

    with batch:
        pass
    assert batch.state == stages[0].state == "fenced"
    assert authority.pass_fds == ()
    assert destination.read_bytes() == b"prior"
    _assert_unpublished_payloads(root, [b"payload-0"])
    for fd in owned:
        _assert_closed(fd)


@pytest.mark.parametrize("has_primary", [False, True])
def test_post_reservation_context_reports_fence_fault_without_masking_primary(
    private_root, monkeypatch, has_primary,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 2, stem="context-secret")
    all_fds = _all_owned_fds(batch, stages)
    authority = _park(batch)
    real_inspect = privfs._inspect_descriptor_claim
    injected = False

    def inspect_then_interrupt(claim, *, allow_unlinked):
        nonlocal injected
        if not injected:
            injected = True
            raise KeyboardInterrupt("injected pre-auth cleanup fault")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    primary = RuntimeError("primary work failed")
    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_inspect_descriptor_claim", inspect_then_interrupt)
        if has_primary:
            with pytest.raises(RuntimeError) as caught:
                with batch:
                    raise primary
            assert caught.value is primary
            cleanup = caught.value.private_cleanup_error
        else:
            with pytest.raises(privfs.PrivateStageHandoffError) as caught:
                with batch:
                    pass
            cleanup = caught.value

    assert injected
    _assert_handoff_error(cleanup, "fence")
    _assert_secret_safe(cleanup, stages)
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced",) * 2
    for fd in all_fds:
        _assert_closed(fd)


def test_transfer_receipt_cannot_be_forged():
    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs.PrivateStageParentCloseReceipt(
            request_id=REQUEST_ID,
            claimed_worker_pid=WORKER_PID,
            file_identities=((1, 2),),
            _constructor_token=object(),
        )
    _assert_handoff_error(caught.value, "transfer")


def test_wrong_authority_and_replay_are_refused(private_root):
    _, root_fd = private_root
    _, batch = _prepare(root_fd, 1)
    authority = _park(batch)

    try:
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs.transfer_private_stage_handoff(batch, object())
        _assert_handoff_error(caught.value, "transfer")
        assert batch.state == "worker_claim_bound"

        receipt = privfs.transfer_private_stage_handoff(batch, authority)
        with pytest.raises(privfs.PrivateStageStateError) as replay:
            privfs.transfer_private_stage_handoff(batch, authority)
        _assert_state_error(replay.value, "transfer", "parent_writers_closed")
        assert receipt.state == "parent_writers_closed"
    finally:
        _settle(batch)


@pytest.mark.parametrize("operation", ["transfer", "abort_spawn", "claim_bound_fence"])
def test_reused_exposed_writer_number_is_never_closed_as_stage_authority(
    private_root, operation,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd, 1)
    writer = _reserved_writers(batch)[0]
    authority = _prepare_authority(batch)
    if operation != "abort_spawn":
        _spawn(batch, authority)
        _bind(batch, authority)
    decoy_fd = _reuse_as_unrelated_private_file(root, writer)

    try:
        if operation == "transfer":
            with pytest.raises(privfs.PrivateStageTransferUncertain) as caught:
                privfs.transfer_private_stage_handoff(batch, authority)
            _assert_handoff_error(caught.value, "transfer")
            assert batch.state == "transfer_uncertain"
        elif operation == "abort_spawn":
            with pytest.raises(privfs.PrivateStageHandoffError) as caught:
                privfs._abort_private_stage_spawn(batch, authority)
            _assert_handoff_error(caught.value, "abort_spawn")
            assert batch.state == "aborted"
        else:
            with pytest.raises(privfs.PrivateStageHandoffError) as caught:
                privfs.fence_private_stage_handoff(batch)
            _assert_handoff_error(caught.value, "fence")
            assert batch.state == "fenced"

        # Identity mismatch proves this integer is not ours to close.
        claim = _batch_claim(batch, 0, "writer")
        assert claim.disposition == "identity_rejected"
        assert claim.errors
        os.fstat(decoy_fd)
        os.write(decoy_fd, b"-still-open")
    finally:
        os.close(decoy_fd)
        _settle(batch)
    assert tuple(stage.state for stage in stages) in {
        ("aborted",), ("fenced",),
    }


def test_same_inode_hardlink_anomaly_reports_uncertain_but_closes_writer_once(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    (stage,), batch = _prepare(root_fd, 1)
    writer = _reserved_writers(batch)[0]
    authority = _park(batch)
    os.link(
        stage.temporary_name,
        "extra-stage-link",
        src_dir_fd=root_fd,
        dst_dir_fd=root_fd,
    )
    calls = []
    real_close = privfs._close_owned

    def tracked_close(fd):
        if fd == writer:
            calls.append(fd)
        return real_close(fd)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", tracked_close)
            with pytest.raises(privfs.PrivateStageTransferUncertain):
                privfs.transfer_private_stage_handoff(batch, authority)
        assert calls == [writer]
        _assert_closed(writer)
        claim = _batch_claim(batch, 0, "writer")
        assert claim.disposition == "closed_after_fault"
        assert claim.errors
        assert object.__getattribute__(batch, "_transfer_receipt") is None
    finally:
        os.unlink("extra-stage-link", dir_fd=root_fd)
        _settle(batch)
    assert batch.state == "fenced"


def test_writer_ebadf_is_gone_nonclean_and_terminal_replay_never_recloses(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 2)
    writers = _reserved_writers(batch)
    target = _batch_claim(batch, 0, "writer")
    authority = _park(batch)
    os.close(target.fd)
    calls = []
    real_close = privfs._close_owned

    def tracked_close(fd):
        calls.append(fd)
        return real_close(fd)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", tracked_close)
            with pytest.raises(privfs.PrivateStageTransferUncertain):
                privfs.transfer_private_stage_handoff(batch, authority)

        assert target.disposition == "gone" and target.errors
        assert target.fd == -1
        assert writers[0] not in calls
        assert calls.count(writers[1]) == 1
        assert object.__getattribute__(batch, "_transfer_receipt") is None
        before = tuple(calls)
        privfs.fence_private_stage_handoff(batch)
        assert tuple(calls) == before
    finally:
        _settle(batch)


def test_exact_close_fault_gets_one_identity_checked_recovery_but_no_receipt(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 2)
    writers = _reserved_writers(batch)
    target = _batch_claim(batch, 0, "writer")
    authority = _park(batch)
    calls = []
    real_close = privfs._close_owned

    def fail_once_without_closing(fd):
        if fd in writers:
            calls.append(fd)
        if fd == target.fd and calls.count(fd) == 1:
            return OSError(errno.EIO, "close reported before settlement")
        return real_close(fd)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", fail_once_without_closing)
            with pytest.raises(privfs.PrivateStageTransferUncertain) as caught:
                privfs.transfer_private_stage_handoff(batch, authority)

        _assert_handoff_error(caught.value, "transfer")
        assert calls == [writers[0], writers[0], writers[1]]
        assert target.disposition == "closed_after_fault"
        assert target.errors
        assert object.__getattribute__(batch, "_transfer_receipt") is None
        for writer in writers:
            _assert_closed(writer)
    finally:
        _settle(batch)


def test_persistent_exact_close_fault_exhausts_lifetime_budget_without_retry(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 1)
    target = _batch_claim(batch, 0, "writer")
    target_fd = target.fd
    authority = _park(batch)
    calls = 0

    def fail_without_closing(fd):
        nonlocal calls
        if fd == target_fd:
            calls += 1
            return OSError(errno.EIO, "persistent close fault")
        return privfs._close_owned(fd)

    # Avoid recursive use of the patched symbol for non-target descriptors.
    real_close = privfs._close_owned

    def fail_target_only(fd):
        if fd == target_fd:
            return fail_without_closing(fd)
        return real_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_close_owned", fail_target_only)
        with pytest.raises(privfs.PrivateStageTransferUncertain):
            privfs.transfer_private_stage_handoff(batch, authority)

    assert batch.state == "transfer_uncertain"
    assert target.disposition == "close_started"
    assert target.fd == target_fd
    assert target.errors and calls >= 2
    os.fstat(target_fd)
    assert object.__getattribute__(batch, "_transfer_receipt") is None

    calls_after_transfer = calls
    with pytest.raises(privfs.PrivateStageHandoffError):
        privfs.fence_private_stage_handoff(batch)
    assert calls == calls_after_transfer == 2
    assert target.disposition == "close_started" and target.fd == target_fd
    os.fstat(target_fd)
    assert object.__getattribute__(batch, "_transfer_receipt") is None
    os.close(target_fd)


@pytest.mark.parametrize(
    "cleanup_state",
    ["abort_spawn", "spawn_prepared", "worker_spawned_unverified", "worker_claim_bound"],
)
@pytest.mark.parametrize("directory_fd", ["parent_fd", "anchor_fd"])
def test_spawn_cleanup_never_uses_or_closes_a_reused_directory_number(
    private_root, cleanup_state, directory_fd,
):
    root, root_fd = private_root
    stage, batch = _prepare_nested(
        root, root_fd, stem=f"stale-{cleanup_state}-{directory_fd}",
    )
    authority = _advance_directory_cleanup_case(batch, cleanup_state)
    kind = directory_fd.removesuffix("_fd")
    exposed = _batch_claim(batch, 0, kind).fd
    decoy_fd, decoy, marker = _reuse_as_unrelated_private_dir(
        root, exposed, stage.temporary_name,
    )

    try:
        operation = "abort_spawn" if cleanup_state == "abort_spawn" else "fence"
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            if cleanup_state == "abort_spawn":
                privfs._abort_private_stage_spawn(batch, authority)
            else:
                privfs.fence_private_stage_handoff(batch)
        _assert_handoff_error(caught.value, operation)
        terminal = "aborted" if cleanup_state == "abort_spawn" else "fenced"
        assert batch.state == stage.state == terminal
        assert batch.pass_fds == ()
        assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
        assert not (root / stage.components[0] / stage.destination_name).exists()
        _assert_decoy_dir_untouched(
            decoy_fd, decoy, stage.temporary_name, marker,
        )
    finally:
        try:
            os.close(decoy_fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise


@pytest.mark.parametrize(
    "cleanup_state",
    ["abort_spawn", "spawn_prepared", "worker_spawned_unverified", "worker_claim_bound"],
)
@pytest.mark.parametrize("directory_fd", ["parent_fd", "anchor_fd"])
def test_spawn_cleanup_closes_an_authentic_directory_with_unsafe_metadata_once(
    private_root, monkeypatch, cleanup_state, directory_fd,
):
    root, root_fd = private_root
    stage, batch = _prepare_nested(
        root, root_fd, stem=f"mode-{cleanup_state}-{directory_fd}",
    )
    authority = _advance_directory_cleanup_case(batch, cleanup_state)
    kind = directory_fd.removesuffix("_fd")
    exposed = _batch_claim(batch, 0, kind).fd
    os.fchmod(exposed, 0o750)
    calls = []
    real_close = privfs._close_owned

    def tracked_close(fd):
        if fd == exposed:
            calls.append(fd)
        return real_close(fd)

    operation = "abort_spawn" if cleanup_state == "abort_spawn" else "fence"
    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_close_owned", tracked_close)
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            if cleanup_state == "abort_spawn":
                privfs._abort_private_stage_spawn(batch, authority)
            else:
                privfs.fence_private_stage_handoff(batch)

    _assert_handoff_error(caught.value, operation)
    terminal = "aborted" if cleanup_state == "abort_spawn" else "fenced"
    assert batch.state == stage.state == terminal
    assert calls == [exposed]
    _assert_closed(exposed)


@pytest.mark.parametrize("operation", ["abort_unspawned", "abort_spawn", "fence"])
def test_batch_cleanup_uses_only_private_claims_and_never_mutates_a_name(
    private_root, monkeypatch, operation,
):
    root, root_fd = private_root
    parent, stage = _make_nested_stage(
        root, root_fd, stem=f"private-cleanup-{operation}",
    )
    temporary_name = stage.temporary_name
    public_parent = stage.parent_fd
    batch = privfs.prepare_private_stage_handoff((stage,), REQUEST_ID)
    owned_fds = _all_owned_fds(batch, (stage,))
    _assert_public_stage_fds_tombstoned((stage,))
    decoy_info = _reuse_as_unrelated_private_dir(
        root, public_parent, temporary_name,
    )
    authority = None
    if operation in {"abort_spawn", "fence"}:
        authority = _prepare_authority(batch)
    if operation == "fence":
        _spawn(batch, authority)

    def forbidden_name_mutation(*_args, **_kwargs):
        raise AssertionError("batch cleanup must be close-only")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_discard_named_claim", forbidden_name_mutation)
            if operation == "abort_unspawned":
                privfs.abort_unspawned_private_stage_handoff(batch)
            elif operation == "abort_spawn":
                privfs._abort_private_stage_spawn(batch, authority)
            else:
                privfs.fence_private_stage_handoff(batch)

        decoy_fd, decoy, marker = decoy_info
        _assert_decoy_dir_untouched(
            decoy_fd, decoy, temporary_name, marker,
        )
        terminal = "fenced" if operation == "fence" else "aborted"
        assert stage.state == terminal
        if batch is not None:
            assert batch.state == terminal and batch.pass_fds == ()
        assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
        for fd in owned_fds:
            _assert_closed(fd)
        assert (parent / temporary_name).read_bytes() == b"payload"
        assert not list(parent.glob(".quarry-discard-*.stage"))
    finally:
        try:
            os.close(decoy_info[0])
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise


def test_parent_writer_copies_close_once_before_supervisor_may_release(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    _, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    authority = _park(batch)
    events = []
    real_close = privfs._close_owned

    def tracked_close(fd):
        if fd in writers:
            events.append(("close", fd))
        return real_close(fd)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", tracked_close)
            receipt = privfs.transfer_private_stage_handoff(batch, authority)
            events.append(("receipt", receipt.claimed_worker_pid))
            # This stands in for the future supervisor's independent GO write.
            events.append(("release", receipt.claimed_worker_pid))

        assert events == [
            *(("close", fd) for fd in writers),
            ("receipt", WORKER_PID),
            ("release", WORKER_PID),
        ]
        assert all(events.count(("close", fd)) == 1 for fd in writers)
    finally:
        _settle(batch)


def test_writer_claim_escape_after_close_is_identity_rechecked_before_recovery(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    authority = _park(batch)
    calls = []
    real_close = privfs._close_owned
    injected = False

    def close_then_escape(fd):
        nonlocal injected
        if fd in writers:
            calls.append(fd)
        result = real_close(fd)
        if fd == writers[0] and not injected:
            injected = True
            raise KeyboardInterrupt("cancel after captured writer close")
        return result

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", close_then_escape)
            with pytest.raises(privfs.PrivateStageTransferUncertain) as caught:
                privfs.transfer_private_stage_handoff(batch, authority)

        assert injected
        assert calls == list(writers)
        _assert_handoff_error(caught.value, "transfer")
        assert batch.state == "transfer_uncertain" and batch.pass_fds == ()
        assert tuple(stage.state for stage in stages) == ("transfer_uncertain",) * 3
        for writer in writers:
            _assert_closed(writer)
        dispositions = tuple(
            stage_claim.writer.disposition for stage_claim in _ledger(batch).stage_claims
        )
        assert dispositions == ("close_ambiguous", "closed_clean", "closed_clean")
    finally:
        _settle(batch)


@pytest.mark.parametrize("operation", ["transfer", "fence"])
def test_post_terminal_transition_base_exception_drains_every_captured_claim(
    private_root, monkeypatch, operation,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    all_fds = _all_owned_fds(batch, stages)
    authority = _park(batch)
    injected = False

    if operation == "transfer":
        seam_name = "_force_transfer_state"
        real_force = privfs._force_transfer_state

        def force_then_interrupt(*args, **kwargs):
            nonlocal injected
            result = real_force(*args, **kwargs)
            if not injected:
                injected = True
                raise KeyboardInterrupt("cancel after transfer terminalization")
            return result

        expected_error = privfs.PrivateStageTransferUncertain
    else:
        seam_name = "_force_fenced_state"
        real_force = privfs._force_fenced_state

        def force_then_interrupt(*args, **kwargs):
            nonlocal injected
            result = real_force(*args, **kwargs)
            if not injected:
                injected = True
                raise KeyboardInterrupt("cancel after fence terminalization")
            return result

        expected_error = privfs.PrivateStageHandoffError

    with monkeypatch.context() as patch:
        patch.setattr(privfs, seam_name, force_then_interrupt)
        with pytest.raises(expected_error) as caught:
            if operation == "transfer":
                privfs.transfer_private_stage_handoff(batch, authority)
            else:
                privfs.fence_private_stage_handoff(batch)

    assert injected
    _assert_handoff_error(caught.value, operation)
    if operation == "transfer":
        assert batch.state == "transfer_uncertain"
        assert tuple(stage.state for stage in stages) == ("transfer_uncertain",) * 3
        for writer in writers:
            _assert_closed(writer)
        privfs.fence_private_stage_handoff(batch)
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced",) * 3
    for fd in all_fds:
        _assert_closed(fd)


def test_transfer_per_claim_escape_does_not_strand_a_writer_suffix(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    authority = _park(batch)
    real_inspect = privfs._inspect_descriptor_claim
    interrupted = False

    def interrupt_before_one_claim(claim, *, allow_unlinked):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("cancel before first captured writer close")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_inspect_descriptor_claim", interrupt_before_one_claim)
            with pytest.raises(privfs.PrivateStageTransferUncertain) as caught:
                privfs.transfer_private_stage_handoff(batch, authority)

        assert interrupted
        _assert_handoff_error(caught.value, "transfer")
        assert batch.state == "transfer_uncertain"
        for writer in writers:
            _assert_closed(writer)
        assert tuple(
            stage_claim.writer.disposition for stage_claim in _ledger(batch).stage_claims
        ) == ("closed_after_fault", "closed_clean", "closed_clean")
    finally:
        _settle(batch)


@pytest.mark.parametrize("fault_kind", ["returned_error", "base_exception"])
def test_any_ambiguous_close_consumes_the_whole_transfer_without_retry(
    private_root, monkeypatch, fault_kind,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    authority = _park(batch)
    calls = []
    real_close = privfs._close_owned

    def ambiguous_close(fd):
        if fd not in writers:
            return real_close(fd)
        calls.append(fd)
        result = real_close(fd)
        if fd == writers[1]:
            if fault_kind == "base_exception":
                raise KeyboardInterrupt("cancel after ambiguous writer close")
            return OSError(errno.EIO, "ambiguous writer close")
        return result

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", ambiguous_close)
            with pytest.raises(privfs.PrivateStageTransferUncertain) as caught:
                privfs.transfer_private_stage_handoff(batch, authority)

        _assert_handoff_error(caught.value, "transfer")
        assert batch.state == "transfer_uncertain" and batch.pass_fds == ()
        assert tuple(stage.state for stage in stages) == ("transfer_uncertain",) * 3
        assert calls == list(writers)
        assert all(calls.count(fd) == 1 for fd in writers)
        for writer in writers:
            _assert_closed(writer)
        _assert_secret_safe(caught.value, stages)

        with pytest.raises(privfs.PrivateStageStateError) as replay:
            privfs.transfer_private_stage_handoff(batch, authority)
        _assert_state_error(replay.value, "transfer", "transfer_uncertain")
    finally:
        _settle(batch)


@pytest.mark.parametrize("uncertain", [False, True])
def test_fence_retains_unique_unpublished_names_and_closes_all_authority(
    private_root, monkeypatch, uncertain,
):
    root, root_fd = private_root
    for index in range(3):
        destination = root / f"result-{index}"
        destination.write_bytes(f"prior-{index}".encode())
        os.chmod(destination, privfs.FILE_MODE)
    stages, batch = _prepare(root_fd)
    all_fds = _all_owned_fds(batch, stages)
    writers = _reserved_writers(batch)
    authority = _park(batch)

    if uncertain:
        real_close = privfs._close_owned
        interrupted = False

        def interrupt_once_after_close(fd):
            nonlocal interrupted
            result = real_close(fd)
            if fd in writers and not interrupted:
                interrupted = True
                raise KeyboardInterrupt("cancel transfer")
            return result

        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", interrupt_once_after_close)
            with pytest.raises(privfs.PrivateStageTransferUncertain):
                privfs.transfer_private_stage_handoff(batch, authority)
    else:
        privfs.transfer_private_stage_handoff(batch, authority)

    assert privfs.fence_private_stage_handoff(batch) is None
    assert batch.state == "fenced" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("fenced",) * 3
    assert all((stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
               for stage in stages)
    _assert_unpublished_payloads(
        root, [b"payload-0", b"payload-1", b"payload-2"],
    )
    assert [(root / f"result-{index}").read_bytes() for index in range(3)] == [
        b"prior-0", b"prior-1", b"prior-2",
    ]
    for fd in all_fds:
        _assert_closed(fd)


def test_fence_worker_claim_bound_closes_each_retained_parent_writer_once(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    all_fds = _all_owned_fds(batch, stages)
    _park(batch)
    calls = []
    real_close = privfs._close_owned

    def tracked_close(fd):
        if fd in writers:
            calls.append(fd)
        return real_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_close_owned", tracked_close)
        privfs.fence_private_stage_handoff(batch)

    assert calls == list(writers)
    assert all(calls.count(fd) == 1 for fd in writers)
    assert batch.state == "fenced" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("fenced",) * 3
    _assert_unpublished_payloads(
        root, [b"payload-0", b"payload-1", b"payload-2"],
    )
    for fd in all_fds:
        _assert_closed(fd)


def test_fence_is_idempotent_but_refuses_an_unspawned_prepared_batch(private_root):
    _, root_fd = private_root
    _, batch = _prepare(root_fd, 1)

    with pytest.raises(privfs.PrivateStageStateError) as caught:
        privfs.fence_private_stage_handoff(batch)
    _assert_state_error(caught.value, "fence", "prepared")
    assert batch.state == "prepared" and batch.pass_fds == ()

    authority = _park(batch)
    privfs.transfer_private_stage_handoff(batch, authority)
    assert privfs.fence_private_stage_handoff(batch) is None
    assert privfs.fence_private_stage_handoff(batch) is None
    assert batch.state == "fenced"


def test_fence_refuses_an_aborted_batch(private_root):
    _, root_fd = private_root
    _, batch = _prepare(root_fd, 1)
    batch.abort()

    with pytest.raises(privfs.PrivateStageStateError) as caught:
        privfs.fence_private_stage_handoff(batch)
    _assert_state_error(caught.value, "fence", "aborted")


def test_fence_is_close_only_and_leaves_a_substituted_name_untouched(
    private_root,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd, stem="credential-output")
    all_fds = _all_owned_fds(batch, stages)
    authority = _park(batch)
    privfs.transfer_private_stage_handoff(batch, authority)
    victim = stages[1]
    original_name = victim.temporary_name
    os.unlink(original_name, dir_fd=root_fd)
    planted = os.open(
        original_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        privfs.FILE_MODE,
        dir_fd=root_fd,
    )
    _write_exact(planted, b"substituted-evidence")
    os.close(planted)

    assert privfs.fence_private_stage_handoff(batch) is None

    assert batch.state == "fenced" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("fenced",) * 3
    assert (root / original_name).read_bytes() == b"substituted-evidence"
    assert not list(root.glob(".quarry-discard-*.stage"))
    for fd in all_fds:
        _assert_closed(fd)
    assert privfs.fence_private_stage_handoff(batch) is None


def test_fence_cancellation_is_fixed_safe_and_closes_every_descriptor(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd, stem="fence-secret")
    all_fds = _all_owned_fds(batch, stages)
    authority = _park(batch)
    privfs.transfer_private_stage_handoff(batch, authority)
    real_inspect = privfs._inspect_descriptor_claim
    interrupted = False

    def inspect_then_interrupt(claim, *, allow_unlinked):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("cancel fence cleanup")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_inspect_descriptor_claim", inspect_then_interrupt)
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs.fence_private_stage_handoff(batch)

    assert interrupted
    _assert_handoff_error(caught.value, "fence")
    _assert_secret_safe(caught.value, stages)
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced",) * 3
    _assert_unpublished_payloads(
        root, [b"payload-0", b"payload-1", b"payload-2"],
    )
    for fd in all_fds:
        _assert_closed(fd)


@pytest.mark.parametrize("kind", ["writer", "pin", "parent", "anchor"])
def test_fenced_replay_drains_each_kind_of_persistent_preauth_claim(
    private_root, monkeypatch, kind,
):
    _, root_fd = private_root
    stages, batch = _prepare(root_fd, 3)
    authority = _park(batch)
    assert authority is object.__getattribute__(batch, "_transfer_authority")
    ledger = _ledger(batch)
    target = _batch_claim(batch, 0, kind)
    suffix = tuple(claim for claim in ledger.claims if claim is not target)
    target_fd = target.fd
    real_inspect = privfs._inspect_descriptor_claim

    def keep_target_pending(claim, *, allow_unlinked):
        if claim is target:
            raise KeyboardInterrupt(f"defer {kind} authentication")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_inspect_descriptor_claim", keep_target_pending)
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs.fence_private_stage_handoff(batch)

    _assert_handoff_error(caught.value, "fence")
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced",) * 3
    _assert_public_stage_fds_tombstoned(stages)
    assert target.disposition == "pending" and target.fd == target_fd
    os.fstat(target_fd)
    assert all(claim.disposition in privfs._DESCRIPTOR_CLAIM_TERMINAL
               for claim in suffix)

    assert privfs.fence_private_stage_handoff(batch) is None
    assert not ledger.pending
    _assert_closed(target_fd)
    settled = tuple(claim.disposition for claim in ledger.claims)
    assert privfs.fence_private_stage_handoff(batch) is None
    assert tuple(claim.disposition for claim in ledger.claims) == settled


@pytest.mark.parametrize("operation", ["seal", "replace", "abort"])
@pytest.mark.parametrize("uncertain", [False, True])
def test_spawned_or_uncertain_stage_is_never_individually_publishable(
    private_root, monkeypatch, operation, uncertain,
):
    _, root_fd = private_root
    (stage,), batch = _prepare(root_fd, 1)
    writers = _reserved_writers(batch)
    authority = _park(batch)

    if uncertain:
        real_close = privfs._close_owned

        def interrupt_after_close(fd):
            result = real_close(fd)
            if fd in writers:
                raise KeyboardInterrupt("ambiguous close")
            return result

        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", interrupt_after_close)
            with pytest.raises(privfs.PrivateStageTransferUncertain):
                privfs.transfer_private_stage_handoff(batch, authority)
        state = "transfer_uncertain"
    else:
        privfs.transfer_private_stage_handoff(batch, authority)
        state = "parent_writers_closed"

    call = {
        "seal": lambda: privfs.seal_private_stage(stage),
        "replace": lambda: privfs.replace_private_stage(stage),
        "abort": stage.abort,
    }[operation]
    try:
        with pytest.raises(privfs.PrivateStageStateError) as caught:
            call()
        _assert_state_error(caught.value, operation, state)
        assert batch.state == stage.state == state
    finally:
        _settle(batch)


def test_transfer_and_fence_share_one_batch_wide_lifecycle_lock(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stages, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    authority = _park(batch)
    close_entered = threading.Event()
    continue_transfer = threading.Event()
    fence_started = threading.Event()
    result = {}
    real_close = privfs._close_owned

    def pause_first_writer(fd):
        if fd == writers[0]:
            close_entered.set()
            assert continue_transfer.wait(5)
        return real_close(fd)

    def run_transfer():
        try:
            result["receipt"] = privfs.transfer_private_stage_handoff(batch, authority)
        except BaseException as exc:
            result["transfer_error"] = exc

    def run_fence():
        try:
            fence_started.set()
            privfs.fence_private_stage_handoff(batch)
        except BaseException as exc:
            result["fence_error"] = exc

    transfer_thread = threading.Thread(target=run_transfer, daemon=True)
    fence_thread = threading.Thread(target=run_fence, daemon=True)
    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_close_owned", pause_first_writer)
        transfer_thread.start()
        assert close_entered.wait(5)
        fence_thread.start()
        assert fence_started.wait(5)
        assert fence_thread.is_alive()
        continue_transfer.set()
        transfer_thread.join(5)
        fence_thread.join(5)

    assert not transfer_thread.is_alive() and not fence_thread.is_alive()
    assert set(result) == {"receipt"}
    assert result["receipt"].state == "parent_writers_closed"
    assert batch.state == "fenced"
    assert tuple(stage.state for stage in stages) == ("fenced",) * 3
    _assert_unpublished_payloads(
        root, [b"payload-0", b"payload-1", b"payload-2"],
    )


def test_bind_and_no_child_abort_share_lock_and_never_resurrect_unverified_state(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    (stage,), batch = _prepare(root_fd, 1)
    authority = _prepare_authority(batch)
    _spawn(batch, authority)
    bind_entered = threading.Event()
    continue_bind = threading.Event()
    abort_started = threading.Event()
    results = {}
    real_force = privfs._force_worker_claim_bound_state

    def pause_bind(*args, **kwargs):
        bind_entered.set()
        assert continue_bind.wait(5)
        return real_force(*args, **kwargs)

    def run_bind():
        try:
            results["bind"] = _bind(batch, authority)
        except BaseException as exc:
            results["bind_error"] = exc

    def run_abort():
        abort_started.set()
        try:
            privfs._abort_private_stage_spawn(batch, authority)
        except BaseException as exc:
            results["abort_error"] = exc

    bind_thread = threading.Thread(target=run_bind, daemon=True)
    abort_thread = threading.Thread(target=run_abort, daemon=True)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_force_worker_claim_bound_state", pause_bind)
            bind_thread.start()
            assert bind_entered.wait(5)
            abort_thread.start()
            assert abort_started.wait(5)
            assert abort_thread.is_alive()
            continue_bind.set()
            bind_thread.join(5)
            abort_thread.join(5)

        assert not bind_thread.is_alive() and not abort_thread.is_alive()
        assert results.get("bind") is authority
        _assert_state_error(
            results["abort_error"], "abort_spawn", "worker_claim_bound",
        )
        assert batch.state == stage.state == "worker_claim_bound"
    finally:
        _settle(batch)


def test_two_concurrent_transfers_have_exactly_one_winner(private_root, monkeypatch):
    _, root_fd = private_root
    _, batch = _prepare(root_fd)
    writers = _reserved_writers(batch)
    authority = _park(batch)
    close_entered = threading.Event()
    continue_transfer = threading.Event()
    second_started = threading.Event()
    results = []
    real_close = privfs._close_owned

    def pause_first_writer(fd):
        if fd == writers[0]:
            close_entered.set()
            assert continue_transfer.wait(5)
        return real_close(fd)

    def run_transfer(*, second: bool):
        try:
            if second:
                second_started.set()
            results.append(privfs.transfer_private_stage_handoff(batch, authority))
        except BaseException as exc:
            results.append(exc)

    first = threading.Thread(target=run_transfer, kwargs={"second": False}, daemon=True)
    second = threading.Thread(target=run_transfer, kwargs={"second": True}, daemon=True)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", pause_first_writer)
            first.start()
            assert close_entered.wait(5)
            second.start()
            assert second_started.wait(5)
            assert second.is_alive()
            continue_transfer.set()
            first.join(5)
            second.join(5)

        receipts = [item for item in results
                    if isinstance(item, privfs.PrivateStageParentCloseReceipt)]
        errors = [item for item in results if isinstance(item, BaseException)]
        assert len(receipts) == len(errors) == 1
        _assert_state_error(errors[0], "transfer", "parent_writers_closed")
        assert batch.state == "parent_writers_closed"
    finally:
        _settle(batch)
