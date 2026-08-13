"""Phase 1 worker-stage settlement and durable publication contracts.

The worker is only the writable capture owner.  These tests exercise the parent
boundary that authenticates exact stage bytes after worker reap and consumes the
batch in one terminal publication decision.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from quarry_recon import privfs


pytestmark = pytest.mark.offline

REQUEST_ID = "0123456789abcdef0123456789abcdef"
WORKER_PID = 4242
CLAIM_IDS = (
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
    "33333333333333333333333333333333",
)


@pytest.fixture
def private_root(tmp_path: Path):
    os.chmod(tmp_path, privfs.DIR_MODE)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield tmp_path, fd
    finally:
        os.close(fd)


def _write_exact(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("test stage write made no progress")
        offset += written


def _private_file(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    os.chmod(path, privfs.FILE_MODE)
    return path


def _roles(count: int) -> tuple[str, ...]:
    return {
        1: ("stdout",),
        2: ("stdout", "stderr"),
        3: ("stdin", "stdout", "stderr"),
    }[count]


def _claims(count: int) -> tuple[tuple[str, str], ...]:
    return tuple(zip(CLAIM_IDS, _roles(count)))


def _make_transferred_batch(
    root_fd: int,
    payloads: tuple[bytes, ...],
    *,
    stem: str = "result",
    request_id: str = REQUEST_ID,
    retain_writer: int | None = None,
):
    stages = tuple(
        privfs.create_private_stage(root_fd, (f"{stem}-{index}",))
        for index in range(len(payloads))
    )
    for stage, payload in zip(stages, payloads):
        _write_exact(stage.file_fd, payload)

    batch = privfs.prepare_private_stage_handoff(stages, request_id)
    authority = privfs._prepare_private_stage_transfer_authority(
        batch, request_id=request_id,
    )
    duplicate = None

    def spawn(pass_fds):
        nonlocal duplicate
        assert len(pass_fds) == len(stages)
        if retain_writer is not None:
            duplicate = os.dup(pass_fds[retain_writer])
        return SimpleNamespace(pid=WORKER_PID)

    child, returned = privfs._spawn_with_private_stage_handoff(
        batch, authority, spawn,
    )
    assert child.pid == WORKER_PID and returned is authority
    privfs._bind_private_stage_transfer_authority(
        batch, authority, worker_pid=WORKER_PID,
    )
    receipt = privfs.transfer_private_stage_handoff(batch, authority)
    return stages, batch, receipt, duplicate


def _fence_if_owned(batch) -> None:
    if batch.state in {
        "worker_spawned_unverified", "worker_claim_bound",
        "parent_writers_closed", "transfer_uncertain", "settled", "publishing",
    }:
        privfs.fence_private_stage_handoff(batch)


def _assert_state_error(error, operation: str, state: str) -> None:
    assert isinstance(error, privfs.PrivateStageStateError)
    assert (error.operation, error.state) == (operation, state)


def test_settlement_requires_the_retained_receipt_and_exact_reaped_attestation(
    private_root,
):
    _, root_fd = private_root
    _, batch, receipt, _ = _make_transferred_batch(root_fd, (b"payload\n",))
    _, other, other_receipt, _ = _make_transferred_batch(
        root_fd, (b"other\n",), stem="other",
    )
    try:
        for candidate, worker_reaped in (
            (object(), True),
            (other_receipt, True),
            (receipt, False),
            (receipt, 1),
        ):
            with pytest.raises(privfs.PrivateStageHandoffError) as caught:
                privfs.settle_private_stage_handoff(
                    batch, candidate, worker_reaped=worker_reaped,
                    claims=_claims(1),
                )
            assert caught.value.operation == "settle"
            assert batch.state == "parent_writers_closed"

        proofs = privfs.settle_private_stage_handoff(
            batch, receipt, worker_reaped=True, claims=_claims(1),
        )
        assert batch.state == "settled"
        assert proofs[0].claim_id == CLAIM_IDS[0]
    finally:
        _fence_if_owned(batch)
        _fence_if_owned(other)


@pytest.mark.parametrize("claims", [
    [(CLAIM_IDS[0], "stdout")],
    ((CLAIM_IDS[0], "stderr"), (CLAIM_IDS[1], "stdout")),
    ((CLAIM_IDS[0], "stdout"), (CLAIM_IDS[0], "stderr")),
    ((CLAIM_IDS[0], "stdout"), (CLAIM_IDS[1], "stdout")),
    (("A" * 32, "stdout"), (CLAIM_IDS[1], "stderr")),
    ((CLAIM_IDS[0], "stdout", "extra"), (CLAIM_IDS[1], "stderr")),
])
def test_settlement_rejects_noncanonical_claim_shapes_without_consuming_batch(
    private_root, claims,
):
    _, root_fd = private_root
    _, batch, receipt, _ = _make_transferred_batch(
        root_fd, (b"out\n", b"err\n"),
    )
    try:
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs.settle_private_stage_handoff(
                batch, receipt, worker_reaped=True, claims=claims,
            )
        assert caught.value.operation == "settle"
        assert batch.state == "parent_writers_closed"
    finally:
        _fence_if_owned(batch)


def test_settlement_proofs_authenticate_exact_ordered_inode_bytes_and_lines(
    private_root,
):
    _, root_fd = private_root
    payloads = (b"input\x00", b"one\ntwo\n", b"\xfferror\n")
    stages, batch, receipt, _ = _make_transferred_batch(root_fd, payloads)
    try:
        proofs = privfs.settle_private_stage_handoff(
            batch, receipt, worker_reaped=True, claims=_claims(3),
        )

        assert isinstance(proofs, tuple)
        assert tuple(field.name for field in dataclasses.fields(proofs[0])) == (
            "claim_id", "role", "components", "dev", "ino", "size", "sha256",
            "lines",
        )
        assert tuple(proof.claim_id for proof in proofs) == CLAIM_IDS
        assert tuple(proof.role for proof in proofs) == _roles(3)
        assert tuple(proof.components for proof in proofs) == tuple(
            stage.components for stage in stages
        )
        assert tuple(proof.file_identity for proof in proofs) == tuple(
            stage.file_identity for stage in stages
        )
        assert tuple(proof.size for proof in proofs) == tuple(map(len, payloads))
        assert tuple(proof.sha256 for proof in proofs) == tuple(
            hashlib.sha256(payload).hexdigest() for payload in payloads
        )
        assert tuple(proof.lines for proof in proofs) == (None, 2, 1)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            proofs[0].size = 0
    finally:
        _fence_if_owned(batch)


def test_settlement_rejects_a_substituted_stage_name_and_preserves_prior_final(
    private_root,
):
    root, root_fd = private_root
    prior = _private_file(root / "result-0", b"old")
    (stage,), batch, receipt, _ = _make_transferred_batch(
        root_fd, (b"trusted",),
    )
    held = root / "held-original"
    os.rename(root / stage.temporary_name, held)
    _private_file(root / stage.temporary_name, b"trusted")
    try:
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs.settle_private_stage_handoff(
                batch, receipt, worker_reaped=True, claims=_claims(1),
            )
        assert caught.value.operation == "settle"
        assert isinstance(caught.value.__cause__, privfs.PrivatePathUnsafe)
        assert "substituted" in str(caught.value.__cause__)
        assert batch.state == "parent_writers_closed"
        assert prior.read_bytes() == b"old"
        assert held.read_bytes() == b"trusted"
    finally:
        _fence_if_owned(batch)


def test_publication_requires_the_exact_retained_proof_tuple(
    private_root,
):
    root, root_fd = private_root
    _private_file(root / "result-0", b"old")
    _, batch, receipt, _ = _make_transferred_batch(root_fd, (b"new",))
    proofs = privfs.settle_private_stage_handoff(
        batch, receipt, worker_reaped=True, claims=_claims(1),
    )

    copied = tuple([*proofs])
    assert copied == proofs and copied is not proofs
    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs.publish_private_stage_handoff(batch, copied)
    assert caught.value.operation == "publish"
    assert batch.state == "fenced"
    assert (root / "result-0").read_bytes() == b"old"


def test_publication_reauthenticates_proof_bytes_after_settlement(private_root):
    root, root_fd = private_root
    _private_file(root / "result-0", b"old")
    _, batch, receipt, writer = _make_transferred_batch(
        root_fd, (b"trusted",), retain_writer=0,
    )
    assert writer is not None
    try:
        proofs = privfs.settle_private_stage_handoff(
            batch, receipt, worker_reaped=True, claims=_claims(1),
        )
        os.pwrite(writer, b"hostile", 0)
        os.fsync(writer)
        with pytest.raises(privfs.PrivateStageHandoffError) as caught:
            privfs.publish_private_stage_handoff(batch, proofs)
        assert caught.value.operation == "publish"
        assert batch.state == "fenced"
        assert (root / "result-0").read_bytes() == b"old"
    finally:
        os.close(writer)
        _fence_if_owned(batch)


def test_publication_rejects_name_substitution_after_settlement(private_root):
    root, root_fd = private_root
    _private_file(root / "result-0", b"old")
    (stage,), batch, receipt, _ = _make_transferred_batch(
        root_fd, (b"trusted",),
    )
    proofs = privfs.settle_private_stage_handoff(
        batch, receipt, worker_reaped=True, claims=_claims(1),
    )
    held = root / "held-original"
    os.rename(root / stage.temporary_name, held)
    _private_file(root / stage.temporary_name, b"trusted")

    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs.publish_private_stage_handoff(batch, proofs)
    assert caught.value.operation == "publish"
    assert batch.state == "fenced"
    assert (root / "result-0").read_bytes() == b"old"
    assert held.read_bytes() == b"trusted"


def test_nonlanded_rename_failure_preserves_prior_final_and_consumes_batch(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    _private_file(root / "result-0", b"old")
    (stage,), batch, receipt, _ = _make_transferred_batch(root_fd, (b"new",))
    proofs = privfs.settle_private_stage_handoff(
        batch, receipt, worker_reaped=True, claims=_claims(1),
    )
    real_rename = os.rename

    def fail_stage(source, destination, *args, **kwargs):
        if (source, destination) == (stage.temporary_name, stage.destination_name):
            raise OSError("rename failed")
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(privfs.os, "rename", fail_stage)
    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs.publish_private_stage_handoff(batch, proofs)
    assert caught.value.operation == "publish"
    assert isinstance(caught.value.__cause__, OSError)
    assert batch.state == "fenced"
    assert (root / "result-0").read_bytes() == b"old"

    with pytest.raises(privfs.PrivateStageStateError) as replay:
        privfs.publish_private_stage_handoff(batch, proofs)
    _assert_state_error(replay.value, "publish", "fenced")


def test_publication_cancellation_before_rename_fences_and_preserves_prior_final(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    _private_file(root / "result-0", b"old")
    _, batch, receipt, _ = _make_transferred_batch(root_fd, (b"new",))
    proofs = privfs.settle_private_stage_handoff(
        batch, receipt, worker_reaped=True, claims=_claims(1),
    )

    def cancel(_fd):
        raise KeyboardInterrupt()

    monkeypatch.setattr(privfs, "_fsync_managed", cancel)
    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs.publish_private_stage_handoff(batch, proofs)
    assert caught.value.operation == "publish"
    assert isinstance(caught.value.__cause__, KeyboardInterrupt)
    assert batch.state == "fenced"
    assert (root / "result-0").read_bytes() == b"old"


def test_batch_failure_cannot_leave_an_unauthenticated_partial_final(
    private_root, monkeypatch,
):
    """A failed all-sinks transaction must preserve every prior authoritative final."""
    root, root_fd = private_root
    _private_file(root / "result-0", b"old-out")
    _private_file(root / "result-1", b"old-err")
    stages, batch, receipt, _ = _make_transferred_batch(
        root_fd, (b"new-out", b"new-err"),
    )
    proofs = privfs.settle_private_stage_handoff(
        batch, receipt, worker_reaped=True, claims=_claims(2),
    )
    real_rename = os.rename

    def fail_second(source, destination, *args, **kwargs):
        if destination == stages[1].destination_name:
            raise OSError("second rename failed")
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(privfs.os, "rename", fail_second)
    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs.publish_private_stage_handoff(batch, proofs)
    assert caught.value.operation == "publish"
    assert batch.state == "fenced"
    assert (root / "result-0").read_bytes() == b"old-out"
    assert (root / "result-1").read_bytes() == b"old-err"


def test_clean_publication_is_exact_and_cannot_be_replayed(private_root):
    root, root_fd = private_root
    payloads = (b"out\n", b"err\x00\n")
    _private_file(root / "result-0", b"old-out")
    _private_file(root / "result-1", b"old-err")
    stages, batch, receipt, _ = _make_transferred_batch(root_fd, payloads)
    proofs = privfs.settle_private_stage_handoff(
        batch, receipt, worker_reaped=True, claims=_claims(2),
    )

    assert privfs.publish_private_stage_handoff(batch, proofs) is proofs
    assert batch.state == "committed"
    assert tuple(stage.state for stage in stages) == ("committed", "committed")
    assert tuple((root / f"result-{index}").read_bytes()
                 for index in range(2)) == payloads

    with pytest.raises(privfs.PrivateStageStateError) as publish_replay:
        privfs.publish_private_stage_handoff(batch, proofs)
    _assert_state_error(publish_replay.value, "publish", "committed")
    with pytest.raises(privfs.PrivateStageStateError) as settle_replay:
        privfs.settle_private_stage_handoff(
            batch, receipt, worker_reaped=True, claims=_claims(2),
        )
    _assert_state_error(settle_replay.value, "settle", "committed")


@pytest.mark.parametrize("operation", ["abort", "seal", "replace"])
def test_transferred_stage_handle_cannot_revive_batch_owned_authority(
    private_root, operation,
):
    _, root_fd = private_root
    (stage,), batch, _, _ = _make_transferred_batch(root_fd, (b"payload",))
    try:
        with pytest.raises(privfs.PrivateStageStateError) as caught:
            if operation == "abort":
                stage.abort()
            elif operation == "seal":
                privfs.seal_private_stage(stage)
            else:
                privfs.replace_private_stage(stage)
        _assert_state_error(caught.value, operation, "parent_writers_closed")
        assert batch.state == "parent_writers_closed"
        assert stage.file_fd == stage.parent_fd == stage.anchor_fd == -1
    finally:
        _fence_if_owned(batch)


def test_settlement_cancellation_requires_explicit_fence_and_never_publishes(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    _private_file(root / "result-0", b"old")
    _, batch, receipt, _ = _make_transferred_batch(root_fd, (b"new",))

    def cancel(_fd):
        raise KeyboardInterrupt()

    monkeypatch.setattr(privfs, "_fsync_managed", cancel)
    with pytest.raises(privfs.PrivateStageHandoffError) as caught:
        privfs.settle_private_stage_handoff(
            batch, receipt, worker_reaped=True, claims=_claims(1),
        )
    assert caught.value.operation == "settle"
    assert isinstance(caught.value.__cause__, KeyboardInterrupt)
    assert batch.state == "parent_writers_closed"
    assert (root / "result-0").read_bytes() == b"old"

    privfs.fence_private_stage_handoff(batch)
    assert batch.state == "fenced"
    assert (root / "result-0").read_bytes() == b"old"
