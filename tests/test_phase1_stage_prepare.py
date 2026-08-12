"""Phase 1 private-stage handoff preparation and pre-spawn rollback."""
from __future__ import annotations

import errno
import fcntl
import os
import sys
import threading
from pathlib import Path

import pytest

from quarry_recon import privfs
from quarry_recon.privfs import (
    PrivateStageHandoffError,
    PrivateStageStateError,
    abort_unspawned_private_stage_handoff,
    prepare_private_stage_handoff,
)


pytestmark = pytest.mark.offline

REQUEST_ID = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def private_root(tmp_path: Path):
    os.chmod(tmp_path, privfs.DIR_MODE)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield tmp_path, fd
    finally:
        os.close(fd)


def _make_stages(root_fd: int, count: int = 3, *, stem: str = "result"):
    stages = []
    for index in range(count):
        stage = privfs.create_private_stage(root_fd, (f"{stem}-{index}",))
        data = f"payload-{index}".encode()
        written = 0
        try:
            while written < len(data):
                try:
                    count_written = os.write(stage.file_fd, data[written:])
                except InterruptedError:
                    continue
                if count_written <= 0:
                    raise OSError("test stage write made no progress")
                written += count_written
        except BaseException:
            stage.abort()
            raise
        stages.append(stage)
    return tuple(stages)


def _snapshot(stages):
    return tuple((stage.state, stage.file_fd) for stage in stages)


def _abort_live(stages) -> None:
    for stage in stages:
        if stage.state in {"open", "sealed"}:
            stage.abort()


def _assert_handoff_error(error: PrivateStageHandoffError, operation: str) -> None:
    assert error.operation == operation
    assert error.components == ()
    assert str(error) == f"private stage handoff {operation} failed"


def _assert_state_error(error: PrivateStageStateError, operation: str, state: str) -> None:
    assert (error.operation, error.state) == (operation, state)
    assert error.components == ()
    assert str(error) == f"private stage operation {operation} is invalid in state {state}"


def _assert_closed(fd: int) -> None:
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF


def _live_fd_targets() -> tuple[str, ...]:
    """Stable process-FD snapshot excluding /proc's transient enumeration FD."""
    targets = []
    for name in os.listdir("/proc/self/fd"):
        try:
            targets.append(os.readlink(f"/proc/self/fd/{name}"))
        except FileNotFoundError:
            continue
    return tuple(sorted(targets))


def _batch_owned_fds(batch, stages) -> tuple[int, ...]:
    ledger = object.__getattribute__(batch, "_cleanup_ledger")
    return tuple(
        claim.fd for claim in ledger.claims if claim.fd >= 0
    )


def _unpublished(root: Path) -> list[Path]:
    """Return unique unpublished stage names retained for later locked GC."""
    return sorted(
        path for path in root.glob(".quarry-*.stage")
        if not path.name.startswith(".quarry-discard-")
    )


def _discarded(root: Path) -> list[Path]:
    return sorted(root.glob(".quarry-discard-*.stage"))


def _batch_claim(batch, index: int, kind: str):
    stage_claim = object.__getattribute__(batch, "_cleanup_ledger").stage_claims[index]
    return getattr(stage_claim, kind)


def _assert_public_stage_fds_tombstoned(stages) -> None:
    assert all(
        (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
        for stage in stages
    )


def _interrupt_next_prepare_line_after(armed: list[bool]):
    """Return a trace hook that cuts the first caller-visible post-allocation gap."""
    injected = [False]

    def tracer(frame, event, arg):
        if (event == "line"
                and frame.f_code.co_name
                == "_prepare_private_stage_handoff_transaction_locked"
                and armed[0] and not injected[0]):
            injected[0] = True
            armed[0] = False
            raise KeyboardInterrupt("cancel after private descriptor allocation")
        return tracer

    return tracer, injected


def _reuse_as_unrelated_private_file(root: Path, exposed_fd: int) -> int:
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
    os.write(stage.file_fd, b"payload")
    return stage, parent


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


def test_stage_context_defers_cleanup_after_handoff(private_root):
    _, root_fd = private_root
    batch = None

    with privfs.create_private_stage(root_fd, ("result",)) as stage:
        os.write(stage.file_fd, b"payload")
        batch = prepare_private_stage_handoff((stage,), REQUEST_ID)

    assert batch is not None
    assert batch.state == "prepared"
    assert stage.state == "handoff_prepared"
    assert batch.pass_fds == ()
    batch.abort()


def test_batch_context_owns_pre_spawn_cleanup(private_root):
    root, root_fd = private_root
    stages = _make_stages(root_fd, 3)
    owned_fds = ()

    with prepare_private_stage_handoff(stages, REQUEST_ID) as batch:
        owned_fds = _batch_owned_fds(batch, stages)
        assert batch.state == "prepared"

    assert batch.state == "aborted"
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    assert len(_unpublished(root)) == 3
    for fd in owned_fds:
        _assert_closed(fd)


def test_batch_context_preserves_a_primary_exception(private_root, monkeypatch):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    cleanup = KeyboardInterrupt("cleanup cancellation")

    def fail_abort(batch):
        raise cleanup

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "abort_unspawned_private_stage_handoff", fail_abort)
        with pytest.raises(RuntimeError, match="primary") as caught:
            with batch:
                raise RuntimeError("primary")

    assert caught.value.private_cleanup_error is cleanup
    # The injected abort never consumed authority; restore it with the real API.
    abort_unspawned_private_stage_handoff(batch)


def test_partial_pin_failure_aborts_and_drains_all_registered_authority(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 3)
    writers = tuple(stage.file_fd for stage in stages)
    opened_pins = []
    real_open = privfs._open_strict_file_in

    def fail_second_pin(*args, **kwargs):
        if opened_pins:
            raise KeyboardInterrupt("cancel second pin")
        fd = real_open(*args, **kwargs)
        opened_pins.append(fd)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_open_strict_file_in", fail_second_pin)
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff(stages, REQUEST_ID)
    _assert_handoff_error(caught.value, "prepare")
    assert isinstance(caught.value.__cause__, KeyboardInterrupt)
    assert _snapshot(stages) == (("aborted", -1),) * 3
    _assert_public_stage_fds_tombstoned(stages)
    _assert_closed(opened_pins[0])
    for writer in writers:
        _assert_closed(writer)


def test_prepare_serializes_concurrent_public_abort(private_root, monkeypatch):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 3)
    writers = tuple(stage.file_fd for stage in stages)
    first_transition = threading.Event()
    continue_prepare = threading.Event()
    abort_started = threading.Event()
    result = {}
    real_set_stage = privfs._set_stage

    def pause_after_first_transition(stage, field, value):
        real_set_stage(stage, field, value)
        if (stage is stages[0] and field == "state"
                and value == "handoff_prepared"):
            first_transition.set()
            assert continue_prepare.wait(5)

    def prepare_in_thread():
        try:
            result["batch"] = prepare_private_stage_handoff(stages, REQUEST_ID)
        except BaseException as exc:
            result["prepare_error"] = exc

    def abort_in_thread():
        abort_started.set()
        try:
            stages[1].abort()
        except BaseException as exc:
            result["abort_error"] = exc

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_set_stage", pause_after_first_transition)
        prepare_thread = threading.Thread(target=prepare_in_thread)
        abort_thread = threading.Thread(target=abort_in_thread)
        prepare_thread.start()
        assert first_transition.wait(5)
        abort_thread.start()
        assert abort_started.wait(5)
        # The abort cannot consume stage 2 while prepare owns the whole set.
        assert abort_thread.is_alive()
        continue_prepare.set()
        prepare_thread.join(5)
        abort_thread.join(5)

    assert not prepare_thread.is_alive() and not abort_thread.is_alive()
    assert "prepare_error" not in result
    batch = result["batch"]
    try:
        assert isinstance(result.get("abort_error"), PrivateStageStateError)
        assert batch.pass_fds == ()
        for writer in writers:
            _assert_closed(writer)
        _assert_public_stage_fds_tombstoned(stages)
    finally:
        batch.abort()


@pytest.mark.parametrize("count", [1, 3])
def test_prepare_transfers_ordered_writable_stages(private_root, count):
    _, root_fd = private_root
    stages = _make_stages(root_fd, count)
    writers = tuple(stage.file_fd for stage in stages)

    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    try:
        assert batch.state == "prepared"
        assert batch.pass_fds == ()
        for writer in writers:
            _assert_closed(writer)
        assert tuple(stage.state for stage in stages) == ("handoff_prepared",) * count
        _assert_public_stage_fds_tombstoned(stages)
        private_fds = _batch_owned_fds(batch, stages)
        assert len(private_fds) == 4 * count
        assert len(set(private_fds)) == len(private_fds)
        assert set(private_fds).isdisjoint(writers)
        assert all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                   for fd in private_fds)
        for index, stage in enumerate(stages):
            claim = _batch_claim(batch, index, "writer")
            observed = os.fstat(claim.fd)
            assert (observed.st_dev, observed.st_ino) == stage.file_identity
    finally:
        batch.abort()


def test_partial_private_duplicate_failure_aborts_and_drains_sources(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 2)
    before = tuple(
        (stage.file_fd, stage.parent_fd, stage.anchor_fd) for stage in stages
    )
    returned = []
    calls = 0
    real_duplicate = privfs._duplicate_private_claim

    def fail_after_first_duplicate(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt("cancel duplicate allocation")
        claim = real_duplicate(*args, **kwargs)
        returned.append(claim.fd)
        return claim

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_duplicate_private_claim", fail_after_first_duplicate)
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff(stages, REQUEST_ID)

    _assert_handoff_error(caught.value, "prepare")
    assert isinstance(caught.value.__cause__, KeyboardInterrupt)
    assert tuple(stage.state for stage in stages) == ("aborted", "aborted")
    _assert_public_stage_fds_tombstoned(stages)
    for fd in returned:
        _assert_closed(fd)
    for descriptors in before:
        for fd in descriptors:
            _assert_closed(fd)


def test_prepare_post_drain_interruption_retains_an_exact_live_private_claim(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    target = [None]
    target_fd = [-1]
    duplicate_calls = 0
    armed = [False]
    injected = [False]
    real_duplicate = privfs._duplicate_private_claim
    real_close = privfs._close_owned
    real_drain = privfs._drain_private_stage_ledger

    def fail_second_duplicate(claim, source_fd, **kwargs):
        nonlocal duplicate_calls
        duplicate_calls += 1
        if duplicate_calls == 2:
            raise OSError(errno.EIO, "second private duplicate failed")
        result = real_duplicate(claim, source_fd, **kwargs)
        if target[0] is None:
            target[0] = result
            target_fd[0] = result.fd
        return result

    def keep_first_duplicate_exact_live(fd):
        if fd == target_fd[0]:
            return OSError(errno.EIO, "exact private close failed")
        return real_close(fd)

    def drain_then_arm(ledger, *args, **kwargs):
        result = real_drain(ledger, *args, **kwargs)
        if ledger.pending and not armed[0] and target[0] in ledger.claims:
            armed[0] = True
        return result

    def trace_after_drain(frame, event, arg):
        if (event == "line" and armed[0] and not injected[0]
                and frame.f_code.co_name
                == "_prepare_private_stage_handoff_transaction_locked"):
            injected[0] = True
            armed[0] = False
            raise KeyboardInterrupt("cancel after pending-ledger drain")
        return trace_after_drain

    caught = None
    sys.settrace(trace_after_drain)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_duplicate_private_claim", fail_second_duplicate)
            patch.setattr(privfs, "_close_owned", keep_first_duplicate_exact_live)
            patch.setattr(privfs, "_drain_private_stage_ledger", drain_then_arm)
            try:
                prepare_private_stage_handoff((stage,), REQUEST_ID)
            except BaseException as exc:
                caught = exc
    finally:
        sys.settrace(None)

    try:
        assert injected == [True]
        assert isinstance(caught, PrivateStageHandoffError)
        _assert_handoff_error(caught, "prepare")
        assert stage.state == "aborted"
        _assert_public_stage_fds_tombstoned((stage,))
        ledger = object.__getattribute__(stage, "_cleanup_ledger")
        assert ledger is not None and ledger.pending
        assert target[0] in ledger.claims
        assert target[0].fd == target_fd[0]
        assert target[0].disposition == "close_started"
        observed = os.fstat(target_fd[0])
        assert (observed.st_dev, observed.st_ino) == stage.file_identity
        assert all(
            claim is target[0]
            or claim.disposition in privfs._DESCRIPTOR_CLAIM_TERMINAL
            for claim in ledger.claims
        )
    finally:
        if target_fd[0] >= 0:
            try:
                observed = os.fstat(target_fd[0])
            except OSError:
                pass
            else:
                if (observed.st_dev, observed.st_ino) == stage.file_identity:
                    os.close(target_fd[0])


@pytest.mark.parametrize("allocation", ["duplicate", "pin"])
def test_line_interruption_after_fd_allocation_cannot_lose_the_returned_claim(
    private_root, monkeypatch, allocation,
):
    _, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    armed = [False]
    returned_fds = []
    tracer, injected = _interrupt_next_prepare_line_after(armed)

    if allocation == "duplicate":
        seam = "_duplicate_private_claim"
        real_allocate = privfs._duplicate_private_claim

        def allocate(*args, **kwargs):
            claim = real_allocate(*args, **kwargs)
            returned_fds.append(claim.fd)
            armed[0] = True
            return claim
    else:
        seam = "_open_strict_file_in"
        real_allocate = privfs._open_strict_file_in

        def allocate(*args, **kwargs):
            fd = real_allocate(*args, **kwargs)
            returned_fds.append(fd)
            armed[0] = True
            return fd

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, seam, allocate)
            sys.settrace(tracer)
            try:
                with pytest.raises(PrivateStageHandoffError) as caught:
                    prepare_private_stage_handoff((stage,), REQUEST_ID)
            finally:
                sys.settrace(None)

        _assert_handoff_error(caught.value, "prepare")
        assert injected == [True]
        assert returned_fds
        assert stage.state == "aborted"
        _assert_public_stage_fds_tombstoned((stage,))
        for fd in returned_fds:
            _assert_closed(fd)
        for fd in originals:
            _assert_closed(fd)
    finally:
        sys.settrace(None)
        _abort_live((stage,))


def test_prepare_closes_a_fresh_pin_that_opens_a_substituted_name(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    original_name = stage.temporary_name
    held_name = "held-authentic-stage"
    os.rename(original_name, held_name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    planted = os.open(
        original_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        privfs.FILE_MODE,
        dir_fd=root_fd,
    )
    os.write(planted, b"same-size")
    os.close(planted)
    captured_pin = []
    real_open = privfs._open_strict_file_in

    def capture_pin(*args, **kwargs):
        result = real_open(*args, **kwargs)
        claim = kwargs.get("_claim")
        if claim is not None and claim.kind == "pin":
            captured_pin.append((result, os.fstat(result)))
        return result

    before_targets = _live_fd_targets()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_open_strict_file_in", capture_pin)
            with pytest.raises(PrivateStageHandoffError) as caught:
                prepare_private_stage_handoff((stage,), REQUEST_ID)

        _assert_handoff_error(caught.value, "prepare")
        assert captured_pin
        for fd, _identity_stat in captured_pin:
            _assert_closed(fd)
        assert stage.state == "aborted"
        _assert_public_stage_fds_tombstoned((stage,))
        assert object.__getattribute__(stage, "_cleanup_ledger") is None
        after_targets = _live_fd_targets()
        assert len(after_targets) == len(before_targets) - len(originals)
        assert not (root / stage.destination_name).exists()
        assert (root / original_name).read_bytes() == b"same-size"
        assert (root / held_name).read_bytes() == b"payload-0"
    finally:
        for fd, expected in captured_pin:
            try:
                observed = os.fstat(fd)
            except OSError:
                continue
            if (observed.st_dev, observed.st_ino) == (
                expected.st_dev, expected.st_ino,
            ):
                os.close(fd)


def test_source_close_fault_aborts_prepare_even_when_exact_recovery_closes_it(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    calls = []
    real_close = privfs._close_owned

    def fail_source_writer_once(fd):
        if fd == originals[0]:
            calls.append(fd)
            if calls.count(fd) == 1:
                return OSError(errno.EIO, "source writer close fault")
        return real_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_close_owned", fail_source_writer_once)
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff((stage,), REQUEST_ID)

    _assert_handoff_error(caught.value, "prepare")
    assert calls == [originals[0], originals[0]]
    assert stage.state == "aborted"
    _assert_public_stage_fds_tombstoned((stage,))
    ledger = object.__getattribute__(stage, "_cleanup_ledger")
    assert ledger is not None and not ledger.pending
    source_writer = next(
        claim for claim in ledger.claims if claim.kind == "source_writer"
    )
    assert source_writer.disposition == "closed_after_fault"
    assert source_writer.errors
    for fd in originals:
        _assert_closed(fd)
    for operation in (
        lambda: privfs.seal_private_stage(stage),
        lambda: privfs.replace_private_stage(stage),
    ):
        with pytest.raises(PrivateStageStateError):
            operation()


def test_failed_pretransition_cleanup_terminalizes_sources_and_replays_pending_claim(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    real_duplicate = privfs._duplicate_private_claim
    real_inspect = privfs._inspect_descriptor_claim
    duplicate_calls = 0
    blocked_fd = None

    def fail_after_one_duplicate(*args, **kwargs):
        nonlocal duplicate_calls, blocked_fd
        duplicate_calls += 1
        if duplicate_calls == 2:
            raise KeyboardInterrupt("cancel later duplicate")
        claim = real_duplicate(*args, **kwargs)
        blocked_fd = claim.fd
        return claim

    def keep_private_duplicate_pending(claim, *, allow_unlinked):
        if claim.fd == blocked_fd:
            raise KeyboardInterrupt("defer duplicate cleanup")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_duplicate_private_claim", fail_after_one_duplicate)
        patch.setattr(privfs, "_inspect_descriptor_claim", keep_private_duplicate_pending)
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff((stage,), REQUEST_ID)

    _assert_handoff_error(caught.value, "prepare")
    assert stage.state == "aborted"
    _assert_public_stage_fds_tombstoned((stage,))
    ledger = object.__getattribute__(stage, "_cleanup_ledger")
    assert ledger is not None and ledger.pending
    assert {claim.kind for claim in ledger.claims} >= {
        "writer", "source_writer", "source_parent", "source_anchor",
    }
    source_claims = {
        claim.kind: claim
        for claim in ledger.claims
        if claim.kind.startswith("source_")
    }
    assert object.__getattribute__(source_claims["source_writer"], "_identity") \
        == stage.file_identity
    assert object.__getattribute__(source_claims["source_parent"], "_identity") \
        == stage.parent_identity
    assert object.__getattribute__(source_claims["source_anchor"], "_identity") \
        == stage.anchor_identity
    assert all(
        claim.disposition in privfs._DESCRIPTOR_CLAIM_TERMINAL
        for claim in source_claims.values()
    )

    for operation in (
        lambda: privfs.seal_private_stage(stage),
        lambda: privfs.replace_private_stage(stage),
        lambda: prepare_private_stage_handoff((stage,), REQUEST_ID),
    ):
        with pytest.raises(PrivateStageStateError):
            operation()

    retained = tuple(claim.fd for claim in ledger.claims if claim.fd >= 0)
    assert stage.abort() is None
    assert not ledger.pending
    assert stage._cleanup_ledger is None
    for fd in retained:
        _assert_closed(fd)


def test_prepare_recovery_entry_interruption_reconciles_every_stage(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 2, stem="recover-entry")
    original_claims = {
        fd: identity
        for stage in stages
        for fd, identity in (
            (stage.file_fd, stage.file_identity),
            (stage.parent_fd, stage.parent_identity),
            (stage.anchor_fd, stage.anchor_identity),
        )
    }
    allocated_claims = {}
    armed = [False]
    injected = [False]
    real_duplicate = privfs._duplicate_private_claim
    real_open = privfs._open_strict_file_in
    real_drain = privfs._drain_private_stage_ledger

    def trace_recovery(frame, event, arg):
        if (event == "line" and armed[0] and not injected[0]
                and frame.f_code.co_name
                == "_prepare_private_stage_handoff_transaction_locked"):
            injected[0] = True
            armed[0] = False
            raise KeyboardInterrupt("cancel on prepare recovery entry")
        return trace_recovery

    def duplicate(claim, source_fd):
        result = real_duplicate(claim, source_fd)
        allocated_claims[result.fd] = object.__getattribute__(result, "_identity")
        return result

    def open_pin(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        claim = kwargs.get("_claim")
        if claim is not None:
            allocated_claims[fd] = object.__getattribute__(claim, "_identity")
        return fd

    def drain(ledger, *args, **kwargs):
        kinds = kwargs.get("kinds")
        if kinds and "source_writer" in kinds:
            armed[0] = True
            raise OSError(errno.EIO, "force source-drain recovery")
        return real_drain(ledger, *args, **kwargs)

    caught = None
    sys.settrace(trace_recovery)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_duplicate_private_claim", duplicate)
            patch.setattr(privfs, "_open_strict_file_in", open_pin)
            patch.setattr(privfs, "_drain_private_stage_ledger", drain)
            try:
                prepare_private_stage_handoff(stages, REQUEST_ID)
            except BaseException as exc:
                caught = exc
    finally:
        sys.settrace(None)

    try:
        assert injected == [True]
        assert isinstance(caught, PrivateStageHandoffError)
        _assert_handoff_error(caught, "prepare")
        assert tuple(stage.state for stage in stages) == ("aborted", "aborted")
        _assert_public_stage_fds_tombstoned(stages)
        ledgers = tuple(
            object.__getattribute__(stage, "_cleanup_ledger") for stage in stages
        )
        assert ledgers[0] is ledgers[1] and ledgers[0] is not None
        ledger = ledgers[0]
        assert {claim.kind for claim in ledger.claims} >= {
            "writer", "pin", "parent", "anchor",
            "source_writer", "source_parent", "source_anchor",
        }
        assert all(
            claim.disposition in privfs._DESCRIPTOR_CLAIM_TERMINAL
            for claim in ledger.claims
        )
    finally:
        for stage in stages:
            if stage.state in {"open", "sealed", "aborted"}:
                try:
                    stage.abort()
                except BaseException:
                    pass
        for fd, identity in {**original_claims, **allocated_claims}.items():
            try:
                observed = os.fstat(fd)
            except OSError:
                continue
            if (observed.st_dev, observed.st_ino) == identity:
                os.close(fd)


def test_batch_repr_discloses_no_descriptors_request_or_paths(private_root):
    root, root_fd = private_root
    stages = _make_stages(root_fd, stem="credential-output")
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    try:
        rendered = repr(batch)
        assert "PrivateStageHandoffBatch" in rendered
        assert "prepared" in rendered
        assert "fd" not in rendered.lower()
        assert repr(batch.pass_fds) not in rendered
        assert REQUEST_ID not in rendered
        assert str(root) not in rendered
        for stage in stages:
            assert stage.destination_name not in rendered
            assert stage.temporary_name not in rendered
        ledger = object.__getattribute__(batch, "_cleanup_ledger")
        for value in (ledger, *ledger.claims, *ledger.stage_claims):
            rendered = repr(value)
            assert REQUEST_ID not in rendered
            assert str(root) not in rendered
            assert all(stage.temporary_name not in rendered for stage in stages)
            assert all(stage.destination_name not in rendered for stage in stages)
        for claim in ledger.claims:
            assert f"fd={claim.fd}" not in repr(claim)
            with pytest.raises(AttributeError):
                claim.disposition = "closed_clean"
    finally:
        batch.abort()


def test_terminal_batch_abort_replay_drains_a_persistent_pending_claim(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 3)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    ledger = object.__getattribute__(batch, "_cleanup_ledger")
    target = ledger.stage_claims[0].writer
    suffix = tuple(claim for claim in ledger.claims if claim is not target)
    target_fd = target.fd
    real_inspect = privfs._inspect_descriptor_claim

    def keep_target_pending(claim, *, allow_unlinked):
        if claim is target:
            raise KeyboardInterrupt("persistent pre-auth interruption")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_inspect_descriptor_claim", keep_target_pending)
        with pytest.raises(PrivateStageHandoffError) as caught:
            batch.abort()

    _assert_handoff_error(caught.value, "abort_handoff")
    assert batch.state == "aborted"
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    _assert_public_stage_fds_tombstoned(stages)
    assert target.disposition == "pending" and target.fd == target_fd
    os.fstat(target_fd)
    assert all(claim.disposition in privfs._DESCRIPTOR_CLAIM_TERMINAL
               for claim in suffix)

    assert batch.abort() is None
    assert not ledger.pending
    _assert_closed(target_fd)
    settled = tuple(claim.disposition for claim in ledger.claims)
    assert batch.abort() is None
    assert tuple(claim.disposition for claim in ledger.claims) == settled


def test_repeated_abort_replay_keeps_descriptor_error_history_bounded(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    ledger = object.__getattribute__(batch, "_cleanup_ledger")
    target = ledger.stage_claims[0].writer
    real_inspect = privfs._inspect_descriptor_claim

    def persistent_control_fault(claim, *, allow_unlinked):
        if claim is target:
            raise KeyboardInterrupt("persistent pre-auth control fault")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_inspect_descriptor_claim", persistent_control_fault)
        for _ in range(32):
            with pytest.raises(PrivateStageHandoffError):
                batch.abort()

    assert batch.state == "aborted" and ledger.pending
    assert target.disposition == "pending"
    cap = getattr(privfs, "_MAX_DESCRIPTOR_CLAIM_ERRORS", 2)
    assert 1 <= len(target.errors) <= cap
    dropped = object.__getattribute__(target, "_dropped_error_count")
    assert dropped >= 30
    assert batch.abort() is None
    assert not ledger.pending


def test_descriptor_claim_has_a_lifetime_budget_of_two_close_starts(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    ledger = object.__getattribute__(batch, "_cleanup_ledger")
    target = ledger.stage_claims[0].writer
    target_fd = target.fd
    calls = 0
    real_close = privfs._close_owned

    def persistent_close_fault(fd):
        nonlocal calls
        if fd == target_fd:
            calls += 1
            return OSError(errno.EIO, "persistent exact close fault")
        return real_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_close_owned", persistent_close_fault)
        with pytest.raises(PrivateStageHandoffError):
            batch.abort()

    assert calls == 2
    assert target.disposition == "close_started" and target.fd == target_fd
    os.fstat(target_fd)

    calls_after_first_drain = calls
    with pytest.raises(PrivateStageHandoffError):
        batch.abort()
    assert calls == calls_after_first_drain == 2
    assert target.disposition == "close_started" and target.fd == target_fd
    os.fstat(target_fd)
    os.close(target_fd)


def test_base_abort_terminal_replay_drains_a_persistent_pending_claim(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    real_inspect = privfs._inspect_descriptor_claim

    def keep_source_writer_pending(claim, *, allow_unlinked):
        if claim.kind == "source_writer":
            raise KeyboardInterrupt("persistent base-abort interruption")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_inspect_descriptor_claim", keep_source_writer_pending)
        with pytest.raises(privfs.PrivatePathError):
            stage.abort()

    assert stage.state == "aborted"
    _assert_public_stage_fds_tombstoned((stage,))
    assert _unpublished(root) == []
    assert [path.read_bytes() for path in _discarded(root)] == [b"payload-0"]
    ledger = object.__getattribute__(stage, "_cleanup_ledger")
    assert ledger is not None and ledger.pending
    target, *suffix = ledger.claims
    assert target.kind == "source_writer" and target.disposition == "pending"
    assert all(claim.disposition in privfs._DESCRIPTOR_CLAIM_TERMINAL
               for claim in suffix)
    assert {claim.fd for claim in ledger.claims if claim.fd >= 0} == {originals[0]}

    for operation in (
        lambda: privfs.seal_private_stage(stage),
        lambda: privfs.replace_private_stage(stage),
    ):
        with pytest.raises(PrivateStageStateError):
            operation()

    assert stage.abort() is None
    assert stage._cleanup_ledger is None
    for fd in originals:
        _assert_closed(fd)


def test_base_abort_post_quarantine_interruption_reconciles_attached_ledger(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    original_name = stage.temporary_name
    armed = [False]
    injected = [False]
    captured_ledger = [None]
    captured_claims = []
    real_discard = privfs._discard_named_claim

    def discard_then_arm(*args, **kwargs):
        result = real_discard(*args, **kwargs)
        captured_ledger[0] = object.__getattribute__(stage, "_cleanup_ledger")
        captured_claims.extend(
            (claim.fd, object.__getattribute__(claim, "_identity"))
            for claim in captured_ledger[0].claims
            if claim.fd >= 0
        )
        armed[0] = True
        return result

    def trace_after_quarantine(frame, event, arg):
        if (event == "line" and armed[0] and not injected[0]
                and frame.f_code.co_name == "abort_private_stage"):
            injected[0] = True
            armed[0] = False
            raise KeyboardInterrupt("cancel after quarantine")
        return trace_after_quarantine

    caught = None
    sys.settrace(trace_after_quarantine)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_discard_named_claim", discard_then_arm)
            try:
                stage.abort()
            except BaseException as exc:
                caught = exc
    finally:
        sys.settrace(None)

    try:
        assert injected == [True]
        assert isinstance(caught, privfs.PrivatePathError)
        assert stage.state == "aborted"
        _assert_public_stage_fds_tombstoned((stage,))
        assert captured_ledger[0] is not None
        assert all(
            claim.disposition in privfs._DESCRIPTOR_CLAIM_TERMINAL
            for claim in captured_ledger[0].claims
        )
        assert not captured_ledger[0].pending
        assert not (root / original_name).exists()
        assert [path.read_bytes() for path in _discarded(root)] == [b"payload-0"]
        for fd in originals:
            _assert_closed(fd)
        for fd, _identity_value in captured_claims:
            _assert_closed(fd)
    finally:
        for fd, identity in captured_claims:
            try:
                observed = os.fstat(fd)
            except OSError:
                continue
            if (observed.st_dev, observed.st_ino) == identity:
                os.close(fd)


def test_base_abort_quarantine_verification_open_is_registered_before_next_line(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    original_name = stage.temporary_name
    armed = [False]
    injected = [False]
    opened = []
    verifier = [None]
    ledger = [None]
    real_open = privfs._open_strict_file_in

    def open_then_arm(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        component = args[1] if len(args) > 1 else kwargs.get("component")
        claim = kwargs.get("_claim")
        if (isinstance(component, str)
                and component.startswith(".quarry-discard-")
                and claim is not None):
            assert claim.fd == fd
            opened.append((fd, os.fstat(fd)))
            ledger[0] = object.__getattribute__(stage, "_cleanup_ledger")
            verifier[0] = claim
            assert verifier[0] in ledger[0].claims
            armed[0] = True
        return fd

    def trace_verifier(frame, event, arg):
        if (event == "line" and armed[0] and not injected[0]
                and frame.f_code.co_name == "_discard_named_claim"):
            injected[0] = True
            armed[0] = False
            raise KeyboardInterrupt("cancel after quarantine verification open")
        return trace_verifier

    before_targets = _live_fd_targets()
    caught = None
    sys.settrace(trace_verifier)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_open_strict_file_in", open_then_arm)
            try:
                stage.abort()
            except BaseException as exc:
                caught = exc
    finally:
        sys.settrace(None)

    try:
        assert injected == [True]
        assert isinstance(caught, privfs.PrivatePathError)
        assert opened and verifier[0] is not None
        assert verifier[0] in ledger[0].claims
        assert verifier[0].disposition in privfs._DESCRIPTOR_CLAIM_TERMINAL
        assert stage.state == "aborted"
        _assert_public_stage_fds_tombstoned((stage,))
        assert not (root / original_name).exists()
        assert [path.read_bytes() for path in _discarded(root)] == [b"payload-0"]
        for fd in originals:
            _assert_closed(fd)
        for fd, _observed in opened:
            _assert_closed(fd)
        after_targets = _live_fd_targets()
        assert len(after_targets) == len(before_targets) - len(originals)
    finally:
        for fd, expected in opened:
            try:
                observed = os.fstat(fd)
            except OSError:
                continue
            if (observed.st_dev, observed.st_ino) == (
                expected.st_dev, expected.st_ino,
            ):
                os.close(fd)


def test_base_abort_handler_entry_interruption_keeps_public_fds_tombstoned(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    original_name = stage.temporary_name
    armed = [False]
    injected = [False]
    ledger = [None]

    def discard_fails_after_checking_transition(*args, **kwargs):
        assert stage.state == "aborted"
        _assert_public_stage_fds_tombstoned((stage,))
        ledger[0] = object.__getattribute__(stage, "_cleanup_ledger")
        assert ledger[0] is not None
        armed[0] = True
        raise OSError(errno.EIO, "quarantine failed")

    def trace_handler(frame, event, arg):
        if (event == "line" and armed[0] and not injected[0]
                and frame.f_code.co_name == "abort_private_stage"):
            injected[0] = True
            armed[0] = False
            raise KeyboardInterrupt("cancel quarantine error handler")
        return trace_handler

    caught = None
    sys.settrace(trace_handler)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_discard_named_claim", discard_fails_after_checking_transition)
            try:
                stage.abort()
            except BaseException as exc:
                caught = exc
    finally:
        sys.settrace(None)

    assert injected == [True]
    assert isinstance(caught, privfs.PrivatePathError)
    assert stage.state == "aborted"
    _assert_public_stage_fds_tombstoned((stage,))
    assert ledger[0] is not None and not ledger[0].pending
    assert (root / original_name).read_bytes() == b"payload-0"
    assert _discarded(root) == []
    for fd in originals:
        _assert_closed(fd)


def test_line_interruption_during_base_abort_cannot_leave_partial_open_authority(
    private_root,
):
    root, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    originals = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    injected = [False]

    def tracer(frame, event, arg):
        if (event == "line" and not injected[0]
                and stage.state in {"open", "sealed"}
                and stage.file_fd == -1
                and (stage.parent_fd >= 0 or stage.anchor_fd >= 0)):
            injected[0] = True
            raise KeyboardInterrupt("cancel during base-abort terminalization")
        return tracer

    sys.settrace(tracer)
    try:
        caught = None
        try:
            stage.abort()
        except BaseException as exc:
            caught = exc
    finally:
        sys.settrace(None)

    # State-first terminalization may eliminate the unsafe line-visible predicate
    # entirely.  If a future implementation exposes it, the injected interruption
    # must still be reconciled into the fixed public cleanup error.
    if injected[0]:
        assert isinstance(caught, privfs.PrivatePathError)
    else:
        assert caught is None
    assert stage.state == "aborted"
    _assert_public_stage_fds_tombstoned((stage,))
    assert _unpublished(root) == []
    assert [path.read_bytes() for path in _discarded(root)] == [b"payload-0"]
    ledger = object.__getattribute__(stage, "_cleanup_ledger")
    if ledger is not None and ledger.pending:
        assert stage.abort() is None
    for fd in originals:
        _assert_closed(fd)


def test_line_interruption_during_batch_abort_reconciles_every_member(
    private_root,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 3)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    ledger = object.__getattribute__(batch, "_cleanup_ledger")
    owned = tuple(claim.fd for claim in ledger.claims)
    injected = [False]

    def tracer(frame, event, arg):
        if (event == "line" and not injected[0]
                and batch.state == "aborted"
                and any(stage.state != "aborted" for stage in stages)):
            injected[0] = True
            raise KeyboardInterrupt("cancel during batch-abort terminalization")
        return tracer

    sys.settrace(tracer)
    try:
        with pytest.raises(BaseException) as caught:
            batch.abort()
    finally:
        sys.settrace(None)

    assert injected == [True]
    assert isinstance(caught.value, PrivateStageHandoffError)
    assert batch.state == "aborted"
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    _assert_public_stage_fds_tombstoned(stages)
    if ledger.pending:
        assert batch.abort() is None
    for fd in owned:
        _assert_closed(fd)


def test_shared_recovery_ledger_serializes_concurrent_stage_abort_replay(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 2)
    real_inspect = privfs._inspect_descriptor_claim

    def keep_one_source_pending(claim, *, allow_unlinked):
        if claim.kind == "source_writer" and claim._components == stages[0].components:
            raise KeyboardInterrupt("retain one shared source claim")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_inspect_descriptor_claim", keep_one_source_pending)
        with pytest.raises(PrivateStageHandoffError):
            prepare_private_stage_handoff(stages, REQUEST_ID)

    assert tuple(stage.state for stage in stages) == ("aborted", "aborted")
    _assert_public_stage_fds_tombstoned(stages)
    ledgers = tuple(object.__getattribute__(stage, "_cleanup_ledger") for stage in stages)
    assert ledgers[0] is ledgers[1]
    ledger = ledgers[0]
    assert ledger is not None and ledger.pending
    target = next(claim for claim in ledger.claims
                  if claim.kind == "source_writer" and claim.fd >= 0)
    target_fd = target.fd
    close_entered = threading.Event()
    release_close = threading.Event()
    second_started = threading.Event()
    second_done = threading.Event()
    calls = []
    errors = []
    real_close = privfs._close_owned

    def pause_first_close(fd):
        if fd == target_fd:
            calls.append(fd)
            if len(calls) == 1:
                close_entered.set()
                assert release_close.wait(5)
        return real_close(fd)

    def replay(stage, *, second=False):
        if second:
            second_started.set()
        try:
            stage.abort()
        except BaseException as exc:
            errors.append(exc)
        finally:
            if second:
                second_done.set()

    first = threading.Thread(target=replay, args=(stages[0],), daemon=True)
    second = threading.Thread(
        target=replay, args=(stages[1],), kwargs={"second": True}, daemon=True,
    )
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_close_owned", pause_first_close)
            first.start()
            assert close_entered.wait(5)
            second.start()
            assert second_started.wait(5)
            assert not second_done.wait(0.05)
            assert calls == [target_fd]
            release_close.set()
            first.join(5)
            second.join(5)
    finally:
        release_close.set()
        first.join(1)
        second.join(1)

    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert calls == [target_fd]
    assert not ledger.pending
    _assert_closed(target_fd)


def test_prepare_requires_an_exact_stage_tuple(private_root):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    before = _snapshot(stages)
    try:
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff(list(stages), REQUEST_ID)
        _assert_handoff_error(caught.value, "prepare")
        assert _snapshot(stages) == before
    finally:
        _abort_live(stages)


def test_prepare_rejects_a_stage_with_a_predeclared_digest(private_root):
    _, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("preloaded",), b"payload")
    before = (stage.state, stage.file_fd, stage.expected_digest)

    try:
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff((stage,), REQUEST_ID)

        _assert_handoff_error(caught.value, "prepare")
        assert (stage.state, stage.file_fd, stage.expected_digest) == before
        os.fstat(stage.file_fd)
    finally:
        _abort_live((stage,))


@pytest.mark.parametrize("count", [0, 4])
def test_prepare_rejects_out_of_range_cardinality_without_transition(private_root, count):
    _, root_fd = private_root
    stages = _make_stages(root_fd, count)
    before = _snapshot(stages)
    try:
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff(stages, REQUEST_ID)
        _assert_handoff_error(caught.value, "prepare")
        assert _snapshot(stages) == before
    finally:
        _abort_live(stages)


def test_prepare_rejects_a_duplicate_stage_without_transition(private_root):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    writer = stages[0].file_fd
    try:
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff((stages[0], stages[0]), REQUEST_ID)
        _assert_handoff_error(caught.value, "prepare")
        assert (stages[0].state, stages[0].file_fd) == ("open", writer)
        os.fstat(writer)
    finally:
        _abort_live(stages)


@pytest.mark.parametrize("request_id", [
    None, True, "", "0" * 31, "A" * 32, "g" * 32,
])
def test_prepare_rejects_an_invalid_request_without_transition(private_root, request_id):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    before = _snapshot(stages)
    try:
        with pytest.raises(PrivateStageHandoffError) as caught:
            prepare_private_stage_handoff(stages, request_id)
        _assert_handoff_error(caught.value, "prepare")
        assert _snapshot(stages) == before
        if isinstance(request_id, str) and request_id:
            assert request_id not in str(caught.value)
    finally:
        _abort_live(stages)


def test_prepare_rejects_a_sealed_member_without_transition(private_root):
    _, root_fd = private_root
    stages = _make_stages(root_fd)
    privfs.seal_private_stage(stages[1])
    before = _snapshot(stages)
    try:
        with pytest.raises(PrivateStageStateError) as caught:
            prepare_private_stage_handoff(stages, REQUEST_ID)
        _assert_state_error(caught.value, "prepare", "sealed")
        assert _snapshot(stages) == before
    finally:
        _abort_live(stages)


def test_prepare_refuses_a_substituted_name_without_transition(private_root):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    stage = stages[0]
    before = _snapshot(stages)
    os.unlink(stage.temporary_name, dir_fd=stage.parent_fd)
    planted = os.open(
        stage.temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        privfs.FILE_MODE,
        dir_fd=stage.parent_fd,
    )
    os.write(planted, b"substitute")
    os.close(planted)
    with pytest.raises(privfs.PrivatePathUnsafe, match="substitut"):
        prepare_private_stage_handoff(stages, REQUEST_ID)
    assert _snapshot(stages) == before
    os.fstat(stage.file_fd)
    os.unlink(stage.temporary_name, dir_fd=stage.parent_fd)
    # The retained stage inode was unlinked by the substitution setup.  Ordinary
    # abort may report that cleanup anomaly, but it must still terminalize all FDs.
    with pytest.raises(privfs.PrivatePathError):
        stage.abort()
    assert stage.state == "aborted"
    _assert_public_stage_fds_tombstoned((stage,))


def test_prepare_refuses_a_hardlinked_stage_without_transition(private_root):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    stage = stages[0]
    before = _snapshot(stages)
    planted_name = "attacker-hardlink"
    os.link(
        stage.temporary_name,
        planted_name,
        src_dir_fd=stage.parent_fd,
        dst_dir_fd=stage.parent_fd,
    )
    try:
        with pytest.raises(privfs.PrivatePathUnsafe):
            prepare_private_stage_handoff(stages, REQUEST_ID)
        assert _snapshot(stages) == before
        assert os.fstat(stage.file_fd).st_nlink == 2
    finally:
        os.unlink(planted_name, dir_fd=stage.parent_fd)
        _abort_live(stages)


def test_prepare_baseexception_after_tombstone_aborts_and_drains_all_authority(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd)
    before = _snapshot(stages)
    real_set_stage = privfs._set_stage
    interrupted = False

    def interrupt_after_set(stage, field, value):
        nonlocal interrupted
        real_set_stage(stage, field, value)
        if not interrupted and field == "state" and value == "handoff_prepared":
            interrupted = True
            raise KeyboardInterrupt("cancel first handoff transition")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_set_stage", interrupt_after_set)
            with pytest.raises(PrivateStageHandoffError) as caught:
                prepare_private_stage_handoff(stages, REQUEST_ID)
        assert interrupted
        _assert_handoff_error(caught.value, "prepare")
        assert isinstance(caught.value.__cause__, KeyboardInterrupt)
        assert _snapshot(stages) == (("aborted", -1),) * 3
        _assert_public_stage_fds_tombstoned(stages)
        for _, writer in before:
            _assert_closed(writer)
    finally:
        _abort_live(stages)


@pytest.mark.parametrize("operation", ["seal", "replace", "abort"])
def test_individual_stage_operations_refuse_a_prepared_stage(private_root, operation):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    stage = stages[0]
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    action = {
        "seal": lambda: privfs.seal_private_stage(stage),
        "replace": lambda: privfs.replace_private_stage(stage),
        "abort": stage.abort,
    }[operation]
    try:
        with pytest.raises(PrivateStageStateError) as caught:
            action()
        _assert_state_error(caught.value, operation, "handoff_prepared")
        assert stage.state == "handoff_prepared"
        assert batch.state == "prepared"
        assert batch.pass_fds == ()
    finally:
        batch.abort()


def test_abort_settles_all_stages_and_closes_every_owned_descriptor(private_root):
    root, root_fd = private_root
    for index in range(3):
        destination = root / f"result-{index}"
        destination.write_bytes(f"prior-{index}".encode())
        os.chmod(destination, privfs.FILE_MODE)
    stages = _make_stages(root_fd)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    owned_fds = _batch_owned_fds(batch, stages)

    abort_unspawned_private_stage_handoff(batch)

    assert batch.state == "aborted"
    assert batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    assert all((stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
               for stage in stages)
    for fd in owned_fds:
        _assert_closed(fd)
    assert [(root / f"result-{index}").read_bytes() for index in range(3)] == [
        b"prior-0", b"prior-1", b"prior-2",
    ]
    assert sorted(path.read_bytes() for path in _unpublished(root)) == [
        b"payload-0", b"payload-1", b"payload-2",
    ]


def test_abort_is_idempotent(private_root):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 1)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)

    assert batch.abort() is None
    assert abort_unspawned_private_stage_handoff(batch) is None
    assert batch.state == "aborted"
    assert batch.pass_fds == ()
    assert stages[0].state == "aborted"


def test_abort_never_touches_a_reused_public_writer_number(private_root):
    root, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    writer = stage.file_fd
    batch = prepare_private_stage_handoff((stage,), REQUEST_ID)
    decoy_fd = _reuse_as_unrelated_private_file(root, writer)

    try:
        assert batch.abort() is None
        assert batch.state == stage.state == "aborted"
        assert batch.pass_fds == ()
        # Preparation closed the public number before it could be reused.  Batch
        # cleanup owns a different private duplicate and never touches this decoy.
        os.fstat(decoy_fd)
        os.write(decoy_fd, b"-still-open")
    finally:
        try:
            os.close(decoy_fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise


def test_abort_reports_same_inode_hardlink_but_closes_writer_once(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    batch = prepare_private_stage_handoff((stage,), REQUEST_ID)
    writer = _batch_claim(batch, 0, "writer").fd
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

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_close_owned", tracked_close)
        with pytest.raises(PrivateStageHandoffError) as caught:
            batch.abort()

    _assert_handoff_error(caught.value, "abort_handoff")
    assert batch.state == stage.state == "aborted"
    assert calls == [writer]
    _assert_closed(writer)
    os.unlink("extra-stage-link", dir_fd=root_fd)


@pytest.mark.parametrize("operation", ["stage_abort", "batch_abort"])
@pytest.mark.parametrize("directory_fd", ["parent_fd", "anchor_fd"])
def test_unspawned_abort_never_uses_or_closes_a_reused_directory_number(
    private_root, operation, directory_fd,
):
    root, root_fd = private_root
    stage, _ = _make_nested_stage(root, root_fd, stem=f"{operation}-{directory_fd}")
    batch = None
    if operation == "batch_abort":
        batch = prepare_private_stage_handoff((stage,), REQUEST_ID)
    exposed = (
        getattr(stage, directory_fd)
        if batch is None
        else _batch_claim(batch, 0, directory_fd.removesuffix("_fd")).fd
    )
    decoy_fd, decoy, marker = _reuse_as_unrelated_private_dir(
        root, exposed, stage.temporary_name,
    )

    try:
        if operation == "stage_abort":
            with pytest.raises(privfs.PrivatePathError):
                stage.abort()
        else:
            with pytest.raises(PrivateStageHandoffError) as caught:
                batch.abort()
            _assert_handoff_error(caught.value, "abort_handoff")

        assert stage.state == "aborted"
        assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
        if batch is not None:
            assert batch.state == "aborted" and batch.pass_fds == ()
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


@pytest.mark.parametrize("operation", ["stage_abort", "batch_abort"])
@pytest.mark.parametrize("directory_fd", ["parent_fd", "anchor_fd"])
def test_unspawned_abort_closes_an_authentic_directory_with_unsafe_metadata_once(
    private_root, monkeypatch, operation, directory_fd,
):
    root, root_fd = private_root
    stage, _ = _make_nested_stage(root, root_fd, stem=f"mode-{operation}-{directory_fd}")
    batch = None
    if operation == "batch_abort":
        batch = prepare_private_stage_handoff((stage,), REQUEST_ID)
    exposed = (
        getattr(stage, directory_fd)
        if batch is None
        else _batch_claim(batch, 0, directory_fd.removesuffix("_fd")).fd
    )
    os.fchmod(exposed, 0o750)
    calls = []
    real_close = privfs._close_owned

    def tracked_close(fd):
        if fd == exposed:
            calls.append(fd)
        return real_close(fd)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_close_owned", tracked_close)
        if operation == "stage_abort":
            with pytest.raises(privfs.PrivatePathError):
                stage.abort()
        else:
            with pytest.raises(PrivateStageHandoffError) as caught:
                batch.abort()
            _assert_handoff_error(caught.value, "abort_handoff")

    assert stage.state == "aborted"
    if batch is not None:
        assert batch.state == "aborted"
    assert calls == [exposed]
    _assert_closed(exposed)


def test_batch_abort_is_close_only_and_never_mutates_a_substituted_name(private_root):
    root, root_fd = private_root
    stages = _make_stages(root_fd, stem="vault-secret")
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    owned_fds = _batch_owned_fds(batch, stages)
    names = tuple(stage.temporary_name for stage in stages)
    victim = stages[1]
    os.unlink(victim.temporary_name, dir_fd=root_fd)
    planted = os.open(
        victim.temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        privfs.FILE_MODE,
        dir_fd=root_fd,
    )
    os.write(planted, b"substitute")
    os.close(planted)

    assert abort_unspawned_private_stage_handoff(batch) is None

    assert batch.state == "aborted" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    for fd in owned_fds:
        _assert_closed(fd)
    assert all(name.startswith(".quarry-") for name in names)
    assert b"substitute" in {path.read_bytes() for path in _unpublished(root)}


def test_abort_cancellation_settles_every_stage_and_raises_a_fixed_error(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stages = _make_stages(root_fd, stem="cancel-secret")
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    owned_fds = _batch_owned_fds(batch, stages)
    names = tuple(stage.temporary_name for stage in stages)
    real_inspect = privfs._inspect_descriptor_claim
    interrupted = False

    def inspect_then_interrupt(claim, *, allow_unlinked):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("cancel handoff cleanup")
        return real_inspect(claim, allow_unlinked=allow_unlinked)

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_inspect_descriptor_claim", inspect_then_interrupt)
        with pytest.raises(PrivateStageHandoffError) as caught:
            abort_unspawned_private_stage_handoff(batch)

    assert interrupted
    _assert_handoff_error(caught.value, "abort_handoff")
    assert batch.state == "aborted" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    for fd in owned_fds:
        _assert_closed(fd)
    assert len(_unpublished(root)) == 3
    message = str(caught.value)
    assert REQUEST_ID not in message
    assert all(stage.destination_name not in message for stage in stages)
    assert all(name not in message for name in names)


def test_abort_transition_interruption_reconciles_and_closes_all_authority(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stages = _make_stages(root_fd, 3, stem="transition-cancel")
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    owned_fds = _batch_owned_fds(batch, stages)

    real_drain = privfs._drain_private_descriptor_claim
    interrupted = False

    def interrupt_after_one_claim(claim, *, allow_unlinked=True):
        nonlocal interrupted
        result = real_drain(claim, allow_unlinked=allow_unlinked)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("cancel after one descriptor settlement")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_drain_private_descriptor_claim", interrupt_after_one_claim)
        with pytest.raises(PrivateStageHandoffError) as caught:
            batch.abort()

    _assert_handoff_error(caught.value, "abort_handoff")
    assert isinstance(caught.value.__cause__, KeyboardInterrupt)
    assert interrupted
    assert batch.state == "aborted" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    assert all((stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
               for stage in stages)
    assert len(_unpublished(root)) == 3
    for fd in owned_fds:
        _assert_closed(fd)


@pytest.mark.parametrize("operation", ["seal", "replace", "abort"])
def test_prepare_winner_serializes_each_individual_stage_operation(
    private_root, monkeypatch, operation,
):
    _, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    writer = stage.file_fd
    prepare_inside = threading.Event()
    release_prepare = threading.Event()
    operation_started = threading.Event()
    operation_done = threading.Event()
    result = {}
    real_set_stage = privfs._set_stage

    def pause_prepared_transition(candidate, field, value):
        real_set_stage(candidate, field, value)
        if candidate is stage and field == "state" and value == "handoff_prepared":
            prepare_inside.set()
            assert release_prepare.wait(5)

    def run_prepare():
        try:
            result["batch"] = prepare_private_stage_handoff((stage,), REQUEST_ID)
        except BaseException as exc:
            result["prepare_error"] = exc

    def run_operation():
        operation_started.set()
        try:
            if operation == "seal":
                privfs.seal_private_stage(stage)
            elif operation == "replace":
                privfs.replace_private_stage(stage)
            else:
                stage.abort()
        except BaseException as exc:
            result["operation_error"] = exc
        finally:
            operation_done.set()

    prepare_thread = threading.Thread(target=run_prepare, daemon=True)
    operation_thread = threading.Thread(target=run_operation, daemon=True)
    batch = None
    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_set_stage", pause_prepared_transition)
            prepare_thread.start()
            assert prepare_inside.wait(5)
            operation_thread.start()
            assert operation_started.wait(5)
            assert not operation_done.wait(0.05)
            release_prepare.set()
            prepare_thread.join(5)
            operation_thread.join(5)

        assert not prepare_thread.is_alive()
        assert not operation_thread.is_alive()
        assert "prepare_error" not in result
        batch = result["batch"]
        error = result.get("operation_error")
        assert isinstance(error, PrivateStageStateError)
        _assert_state_error(error, operation, "handoff_prepared")
        assert batch.pass_fds == ()
        _assert_closed(writer)
    finally:
        release_prepare.set()
        prepare_thread.join(1)
        operation_thread.join(1)
        if batch is not None and batch.state == "prepared":
            batch.abort()
        elif stage.state in {"open", "sealed"}:
            stage.abort()


@pytest.mark.parametrize(
    ("operation", "settled_state"),
    [("seal", "sealed"), ("replace", "committed"), ("abort", "aborted")],
)
def test_individual_stage_operation_winner_serializes_prepare(
    private_root, monkeypatch, operation, settled_state,
):
    _, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    operation_inside = threading.Event()
    release_operation = threading.Event()
    prepare_started = threading.Event()
    prepare_done = threading.Event()
    result = {}
    real_validate = privfs._validate_live_stage
    real_drain = privfs._drain_private_descriptor_claim

    def pause_validation(candidate, observed_operation):
        if candidate is stage and observed_operation == operation:
            operation_inside.set()
            assert release_operation.wait(5)
        return real_validate(candidate, observed_operation)

    def pause_abort_drain(claim, *, allow_unlinked=True):
        operation_inside.set()
        assert release_operation.wait(5)
        return real_drain(claim, allow_unlinked=allow_unlinked)

    def run_operation():
        try:
            if operation == "seal":
                privfs.seal_private_stage(stage)
            elif operation == "replace":
                privfs.replace_private_stage(stage)
            else:
                stage.abort()
        except BaseException as exc:
            result["operation_error"] = exc

    def run_prepare():
        prepare_started.set()
        try:
            result["batch"] = prepare_private_stage_handoff((stage,), REQUEST_ID)
        except BaseException as exc:
            result["prepare_error"] = exc
        finally:
            prepare_done.set()

    operation_thread = threading.Thread(target=run_operation, daemon=True)
    prepare_thread = threading.Thread(target=run_prepare, daemon=True)
    try:
        with monkeypatch.context() as patch:
            if operation == "abort":
                patch.setattr(
                    privfs, "_drain_private_descriptor_claim", pause_abort_drain,
                )
            else:
                patch.setattr(privfs, "_validate_live_stage", pause_validation)
            operation_thread.start()
            assert operation_inside.wait(5)
            prepare_thread.start()
            assert prepare_started.wait(5)
            assert not prepare_done.wait(0.05)
            release_operation.set()
            operation_thread.join(5)
            prepare_thread.join(5)

        assert not operation_thread.is_alive()
        assert not prepare_thread.is_alive()
        assert "operation_error" not in result
        assert "batch" not in result
        error = result.get("prepare_error")
        assert isinstance(error, PrivateStageStateError)
        _assert_state_error(error, "prepare", settled_state)
        assert stage.state == settled_state
    finally:
        release_operation.set()
        operation_thread.join(1)
        prepare_thread.join(1)
        batch = result.get("batch")
        if batch is not None and batch.state == "prepared":
            batch.abort()
        elif stage.state in {"open", "sealed"}:
            stage.abort()


def test_reversed_overlapping_prepares_have_one_winner_and_do_not_deadlock(
    private_root,
):
    _, root_fd = private_root
    stages = _make_stages(root_fd, 2)
    start = threading.Barrier(3, timeout=5)
    results = []

    def run_prepare(ordered_stages, request_id):
        try:
            start.wait()
            results.append(prepare_private_stage_handoff(ordered_stages, request_id))
        except BaseException as exc:
            results.append(exc)

    threads = [
        threading.Thread(
            target=run_prepare,
            args=(stages, REQUEST_ID),
            daemon=True,
        ),
        threading.Thread(
            target=run_prepare,
            args=(tuple(reversed(stages)), "1" * 32),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(5)

    batches = [item for item in results if isinstance(item, privfs.PrivateStageHandoffBatch)]
    errors = [item for item in results if isinstance(item, BaseException)]
    try:
        assert all(not thread.is_alive() for thread in threads)
        assert len(batches) == 1
        assert len(errors) == 1
        assert isinstance(errors[0], PrivateStageStateError)
        _assert_state_error(errors[0], "prepare", "handoff_prepared")
    finally:
        for batch in batches:
            if batch.state == "prepared":
                batch.abort()
        _abort_live(stages)


def test_concurrent_batch_abort_is_serialized_and_idempotent(private_root):
    root, root_fd = private_root
    stages = _make_stages(root_fd, 3)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    owned_fds = _batch_owned_fds(batch, stages)
    start = threading.Barrier(3, timeout=5)
    errors = []

    def run_abort():
        try:
            start.wait()
            batch.abort()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run_abort, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(5)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert batch.state == "aborted"
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    assert len(_unpublished(root)) == 3
    for fd in owned_fds:
        _assert_closed(fd)


def test_batch_context_exit_can_race_explicit_abort(private_root):
    root, root_fd = private_root
    stages = _make_stages(root_fd, 3)
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    owned_fds = _batch_owned_fds(batch, stages)
    leave_context = threading.Barrier(2, timeout=5)
    errors = []

    def run_context():
        try:
            with batch:
                leave_context.wait()
        except BaseException as exc:
            errors.append(exc)

    def run_abort():
        try:
            leave_context.wait()
            batch.abort()
        except BaseException as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=run_context, daemon=True),
        threading.Thread(target=run_abort, daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert batch.state == "aborted"
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    assert len(_unpublished(root)) == 3
    for fd in owned_fds:
        _assert_closed(fd)


def test_prepare_cancellation_releases_lifecycle_lock_for_another_thread(
    private_root, monkeypatch,
):
    _, root_fd = private_root
    (stage,) = _make_stages(root_fd, 1)
    writer = stage.file_fd
    result = {}
    interrupted = False
    real_set_stage = privfs._set_stage

    def interrupt_after_transition(candidate, field, value):
        nonlocal interrupted
        real_set_stage(candidate, field, value)
        if not interrupted and field == "state" and value == "handoff_prepared":
            interrupted = True
            raise KeyboardInterrupt("cancel prepared transition")

    def run_prepare():
        try:
            result["batch"] = prepare_private_stage_handoff((stage,), REQUEST_ID)
        except BaseException as exc:
            result["prepare_error"] = exc

    prepare_thread = threading.Thread(target=run_prepare, daemon=True)
    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_set_stage", interrupt_after_transition)
        prepare_thread.start()
        prepare_thread.join(5)

    assert not prepare_thread.is_alive()
    assert interrupted
    assert isinstance(result.get("prepare_error"), PrivateStageHandoffError)
    assert (stage.state, stage.file_fd) == ("aborted", -1)
    _assert_closed(writer)

    abort_errors = []

    def run_abort():
        try:
            stage.abort()
        except BaseException as exc:
            abort_errors.append(exc)

    abort_thread = threading.Thread(target=run_abort, daemon=True)
    abort_thread.start()
    abort_thread.join(5)

    assert not abort_thread.is_alive()
    assert abort_errors == []
    assert stage.state == "aborted"
