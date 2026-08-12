"""Phase 1 private-stage handoff preparation and pre-spawn rollback."""
from __future__ import annotations

import errno
import os
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
    return tuple(
        privfs.stage_private_bytes(
            root_fd,
            (f"{stem}-{index}",),
            f"payload-{index}".encode(),
        )
        for index in range(count)
    )


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


def _batch_owned_fds(batch, stages) -> tuple[int, ...]:
    pins = object.__getattribute__(batch, "_pin_fds")
    return tuple(dict.fromkeys(batch.pass_fds + pins
                              + tuple(stage.parent_fd for stage in stages)
                              + tuple(stage.anchor_fd for stage in stages)))


def _discarded(root: Path) -> list[Path]:
    return sorted(root.glob(".quarry-discard-*.stage"))


def test_stage_context_defers_cleanup_after_handoff(private_root):
    _, root_fd = private_root
    batch = None

    with privfs.stage_private_bytes(root_fd, ("result",), b"payload") as stage:
        batch = prepare_private_stage_handoff((stage,), REQUEST_ID)

    assert batch is not None
    assert batch.state == "prepared"
    assert stage.state == "handoff_prepared"
    assert batch.pass_fds
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
    assert len(_discarded(root)) == 3
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


def test_partial_pin_failure_closes_prior_pins_and_preserves_writers(
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

    try:
        with monkeypatch.context() as patch:
            patch.setattr(privfs, "_open_strict_file_in", fail_second_pin)
            with pytest.raises(KeyboardInterrupt, match="cancel second pin"):
                prepare_private_stage_handoff(stages, REQUEST_ID)
        assert _snapshot(stages) == tuple(("open", fd) for fd in writers)
        _assert_closed(opened_pins[0])
        for writer in writers:
            os.fstat(writer)
    finally:
        _abort_live(stages)


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
        assert batch.pass_fds == writers
        for writer in batch.pass_fds:
            os.fstat(writer)
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
        assert batch.pass_fds == writers
        assert tuple(stage.state for stage in stages) == ("handoff_prepared",) * count
        assert tuple(stage.file_fd for stage in stages) == (-1,) * count
        for index, (stage, writer) in enumerate(zip(stages, batch.pass_fds)):
            assert os.write(writer, bytes((65 + index,))) == 1
            observed = os.fstat(writer)
            assert (observed.st_dev, observed.st_ino) == stage.file_identity
    finally:
        batch.abort()


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
    finally:
        batch.abort()


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
    try:
        with pytest.raises(privfs.PrivatePathUnsafe, match="substitut"):
            prepare_private_stage_handoff(stages, REQUEST_ID)
        assert _snapshot(stages) == before
        os.fstat(stage.file_fd)
    finally:
        os.unlink(stage.temporary_name, dir_fd=stage.parent_fd)
        _abort_live(stages)


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


def test_prepare_baseexception_rolls_back_first_logical_transition(private_root, monkeypatch):
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
        assert _snapshot(stages) == before
        for _, writer in before:
            os.fstat(writer)
            assert os.write(writer, b"!") == 1
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
        assert batch.pass_fds
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
    assert sorted(path.read_bytes() for path in _discarded(root)) == [
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


def test_abort_substitution_settles_every_stage_and_raises_a_fixed_error(private_root):
    root, root_fd = private_root
    stages = _make_stages(root_fd, stem="vault-secret")
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    owned_fds = _batch_owned_fds(batch, stages)
    names = tuple(stage.temporary_name for stage in stages)
    victim = stages[1]
    os.unlink(victim.temporary_name, dir_fd=victim.parent_fd)
    planted = os.open(
        victim.temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        privfs.FILE_MODE,
        dir_fd=victim.parent_fd,
    )
    os.write(planted, b"substitute")
    os.close(planted)

    with pytest.raises(PrivateStageHandoffError) as caught:
        abort_unspawned_private_stage_handoff(batch)

    _assert_handoff_error(caught.value, "abort_handoff")
    assert batch.state == "aborted" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    for fd in owned_fds:
        _assert_closed(fd)
    message = str(caught.value)
    assert REQUEST_ID not in message
    assert all(stage.destination_name not in message for stage in stages)
    assert all(name not in message for name in names)
    assert b"substitute" in {path.read_bytes() for path in _discarded(root)}


def test_abort_cancellation_settles_every_stage_and_raises_a_fixed_error(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stages = _make_stages(root_fd, stem="cancel-secret")
    batch = prepare_private_stage_handoff(stages, REQUEST_ID)
    owned_fds = _batch_owned_fds(batch, stages)
    names = tuple(stage.temporary_name for stage in stages)
    real_discard = privfs._discard_named_claim
    interrupted = False

    def discard_then_interrupt(*args, **kwargs):
        nonlocal interrupted
        real_discard(*args, **kwargs)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("cancel handoff cleanup")

    with monkeypatch.context() as patch:
        patch.setattr(privfs, "_discard_named_claim", discard_then_interrupt)
        with pytest.raises(PrivateStageHandoffError) as caught:
            abort_unspawned_private_stage_handoff(batch)

    assert interrupted
    _assert_handoff_error(caught.value, "abort_handoff")
    assert batch.state == "aborted" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    for fd in owned_fds:
        _assert_closed(fd)
    assert len(_discarded(root)) == 3
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

    def interrupt_partial_transition(candidate, members):
        object.__setattr__(candidate, "_writer_fds", ())
        raise KeyboardInterrupt("cancel partial abort transition")

    with monkeypatch.context() as patch:
        patch.setattr(
            privfs, "_begin_unspawned_handoff_abort", interrupt_partial_transition,
        )
        with pytest.raises(PrivateStageHandoffError) as caught:
            batch.abort()

    _assert_handoff_error(caught.value, "abort_handoff")
    assert isinstance(caught.value.__cause__, KeyboardInterrupt)
    assert batch.state == "aborted" and batch.pass_fds == ()
    assert tuple(stage.state for stage in stages) == ("aborted",) * 3
    assert all((stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
               for stage in stages)
    assert len(_discarded(root)) == 3
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
        assert batch.pass_fds == (writer,)
        os.fstat(writer)
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
    real_discard = privfs._discard_named_claim

    def pause_validation(candidate, observed_operation):
        if candidate is stage and observed_operation == operation:
            operation_inside.set()
            assert release_operation.wait(5)
        return real_validate(candidate, observed_operation)

    def pause_abort_discard(parent_fd, name, retained_fd, components):
        operation_inside.set()
        assert release_operation.wait(5)
        return real_discard(parent_fd, name, retained_fd, components)

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
                patch.setattr(privfs, "_discard_named_claim", pause_abort_discard)
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
    assert len(_discarded(root)) == 3
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
    assert len(_discarded(root)) == 3
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
    assert (stage.state, stage.file_fd) == ("open", writer)

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
    _assert_closed(writer)
