"""Phase 1 same-parent no-replace private-stage publication."""
from __future__ import annotations

import errno
import inspect
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

from quarry_recon import privfs


pytestmark = pytest.mark.offline


@pytest.fixture
def private_root(tmp_path: Path):
    os.chmod(tmp_path, privfs.DIR_MODE)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield tmp_path, fd
    finally:
        os.close(fd)


def _private_dir(path: Path) -> Path:
    path.mkdir()
    os.chmod(path, privfs.DIR_MODE)
    return path


def _private_file(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    os.chmod(path, privfs.FILE_MODE)
    return path


def _stages(path: Path) -> list[Path]:
    return list(path.glob(".quarry-*.stage"))


def _open_fds() -> set[int]:
    return {int(item) for item in os.listdir("/proc/self/fd") if item.isdigit()}


def _line(function, fragment: str) -> int:
    lines, start = inspect.getsourcelines(function)
    matches = [start + index for index, text in enumerate(lines) if fragment in text]
    assert len(matches) == 1
    return matches[0]


_ACTION_TERMINAL_CODES = frozenset({
    privfs._renameat2_noreplace.__code__,
    privfs._noreplace_target_components.__code__,
    privfs._new_noreplace_cleanup_ledger.__code__,
    privfs._register_noreplace_claim.__code__,
    privfs._open_strict_file_in.__code__,
    privfs._duplicate_private_claim.__code__,
    privfs._fd_claims.populate_allocation_slot.__code__,
    privfs._fd_claims.populate_claim.__code__,
    privfs._noreplace_claims_by_kind.__code__,
    privfs._noreplace_cleanup_claims.__code__,
    privfs._noreplace_fds.__code__,
    privfs._validate_declared_noreplace_parent.__code__,
    privfs._open_noreplace_file_claim.__code__,
    privfs._noreplace_claim_name_stable.__code__,
    privfs._authenticate_noreplace_target_claim.__code__,
    privfs._noreplace_named_stage_matches.__code__,
    privfs._noreplace_destination_matches_stage.__code__,
    privfs._noreplace_target_exists_stably.__code__,
    privfs._noreplace_existing_target_still_matches.__code__,
    privfs._publish_private_stage_if_absent_public_export.__code__,
    privfs._publish_private_stage_if_absent_public_outer.__code__,
    privfs._publish_private_stage_if_absent_public_inner.__code__,
    privfs._publish_private_stage_if_absent_public_middle.__code__,
    privfs._publish_private_stage_if_absent_fenced.__code__,
    privfs._publish_private_stage_if_absent_locked.__code__,
    privfs._arm_noreplace_stage.__code__,
    privfs._start_noreplace_action.__code__,
    privfs._reconcile_noreplace_action.__code__,
    privfs._finish_noreplace_commit.__code__,
    privfs._drain_noreplace_claim_once.__code__,
    privfs._drain_noreplace_claims.__code__,
    privfs._drain_noreplace_cleanup.__code__,
    privfs._compact_noreplace_replay_claims.__code__,
    privfs._settle_noreplace_public_escape.__code__,
    privfs._PrivateNoreplacePublicFence.__enter__.__code__,
    privfs._PrivateNoreplacePublicFence.__exit__.__code__,
}) - (
    # These are the consecutive effect-free entry-chain events that CPython
    # 3.10 emits before the first SETUP_FINALLY becomes active.  A dedicated,
    # non-skipped test below proves their exact pre-operation invariants.
    {privfs._publish_private_stage_if_absent_public_export.__code__}
    if sys.version_info[:2] == (3, 10) else set()
)


def _invoke_in_private_case(root: Path, name: str, trace=None):
    case = _private_dir(root / name)
    target_parent = _private_dir(case / "nested")
    case_fd = os.open(case, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stage = privfs.stage_private_bytes(
        case_fd, ("nested", "neutral"), b"candidate",
    )
    privfs.seal_private_stage(stage)
    import sys
    previous = sys.gettrace()
    if trace is not None:
        sys.settrace(trace)
    try:
        result = privfs.publish_private_stage_if_absent(
            stage, ("nested", "result"),
        )
        return target_parent, stage, result, None
    except BaseException as error:
        return target_parent, stage, None, error
    finally:
        sys.settrace(previous)
        os.close(case_fd)


def _invoke_existing_private_case(root: Path, name: str, trace=None):
    case = _private_dir(root / name)
    _private_file(case / "result", b"prior")
    case_fd = os.open(case, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stage = privfs.stage_private_bytes(case_fd, ("neutral",), b"candidate")
    privfs.seal_private_stage(stage)
    import sys
    previous = sys.gettrace()
    if trace is not None:
        sys.settrace(trace)
    try:
        result = privfs.publish_private_stage_if_absent(stage, ("result",))
        return case, stage, result, None
    except BaseException as error:
        return case, stage, None, error
    finally:
        sys.settrace(previous)
        os.close(case_fd)


def _invoke_uncertain_replay_case(root: Path, name: str, trace=None):
    case = _private_dir(root / name)
    case_fd = os.open(case, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stage = privfs.stage_private_bytes(case_fd, ("neutral",), b"candidate")
    privfs.seal_private_stage(stage)
    real_sync = privfs._fsync_managed

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "persistent directory fsync failure")
        return real_sync(fd)

    privfs._fsync_managed = fail_directory
    try:
        with pytest.raises(privfs.PrivatePublishIfAbsentUncertain):
            privfs.publish_private_stage_if_absent(stage, ("result",))
        import sys
        previous = sys.gettrace()
        if trace is not None:
            sys.settrace(trace)
        try:
            result = privfs.publish_private_stage_if_absent(stage, ("result",))
            return case, stage, result, None
        except BaseException as error:
            return case, stage, None, error
        finally:
            sys.settrace(previous)
    finally:
        privfs._fsync_managed = real_sync
        os.close(case_fd)


def test_absent_target_commits_exact_stage_and_consumes_authority(private_root):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"immutable")

    assert privfs.publish_private_stage_if_absent(stage, ("result",)) is True
    assert stage.state == "committed"
    assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
    assert (root / "result").read_bytes() == b"immutable"
    assert _stages(root) == []


def test_target_may_change_only_final_leaf_within_same_pinned_parent(private_root):
    root, root_fd = private_root
    nested = _private_dir(root / "nested")
    stage = privfs.stage_private_bytes(
        root_fd, ("nested", "neutral.stage"), b"body",
    )
    try:
        with pytest.raises(privfs.PrivatePathUnsafe, match="final leaf"):
            privfs.publish_private_stage_if_absent(stage, ("other", "body.bin"))
        assert not (root / "other").exists()
        assert stage.state == "open"

        assert privfs.publish_private_stage_if_absent(
            stage, ("nested", "body.bin"),
        ) is True
    finally:
        stage.abort()
    assert (nested / "body.bin").read_bytes() == b"body"


def test_existing_target_is_untouched_and_stage_remains_abortable(private_root):
    root, root_fd = private_root
    prior = _private_file(root / "result", b"prior")
    identity = (prior.stat().st_dev, prior.stat().st_ino)
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")

    assert privfs.publish_private_stage_if_absent(stage, ("result",)) is False
    assert stage.state == "sealed"
    assert stage._cleanup_ledger is None
    assert (prior.stat().st_dev, prior.stat().st_ino) == identity
    assert prior.read_bytes() == b"prior"
    assert root.joinpath(stage.temporary_name).read_bytes() == b"candidate"

    stage.abort()
    assert prior.read_bytes() == b"prior"


def test_prior_appearing_at_action_boundary_wins_without_overwrite(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_action = privfs._renameat2_noreplace

    def appear_then_act(*args):
        _private_file(root / "result", b"winner")
        return real_action(*args)

    monkeypatch.setattr(privfs, "_renameat2_noreplace", appear_then_act)
    assert privfs.publish_private_stage_if_absent(stage, ("result",)) is False
    assert stage.state == "sealed"
    assert (root / "result").read_bytes() == b"winner"
    assert root.joinpath(stage.temporary_name).read_bytes() == b"candidate"
    stage.abort()


def test_false_result_rejects_action_boundary_declared_parent_swap(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    managed = _private_dir(root / "managed")
    _private_file(managed / "result", b"prior")
    stage = privfs.stage_private_bytes(
        root_fd, ("managed", "neutral"), b"candidate",
    )
    real_action = privfs._renameat2_noreplace

    def swap_parent_then_refuse(*args):
        managed.rename(root / "held")
        _private_dir(root / "managed")
        return real_action(*args)

    monkeypatch.setattr(
        privfs, "_renameat2_noreplace", swap_parent_then_refuse,
    )
    with pytest.raises(privfs.PrivatePublishIfAbsentUncertain) as error:
        privfs.publish_private_stage_if_absent(
            stage, ("managed", "result"),
        )
    assert error.value.state == "uncertain"
    assert stage.state == "replaced_uncertain"
    assert not (root / "managed" / "result").exists()
    assert (root / "held" / "result").read_bytes() == b"prior"
    assert root.joinpath("held", stage.temporary_name).read_bytes() == b"candidate"
    stage.abort()


def test_false_result_rejects_target_swap_after_prior_check(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    _private_file(root / "result", b"prior")
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_check = privfs._noreplace_existing_target_still_matches
    swapped = False

    def swap_after_prior_check(*args, **kwargs):
        nonlocal swapped
        result = real_check(*args, **kwargs)
        if not swapped:
            swapped = True
            (root / "result").rename(root / "old-prior")
            _private_file(root / "result", b"replacement")
        return result

    monkeypatch.setattr(
        privfs,
        "_noreplace_existing_target_still_matches",
        swap_after_prior_check,
    )
    with pytest.raises(privfs.PrivatePublishIfAbsentUncertain) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert error.value.state == "uncertain"
    assert stage.state == "replaced_uncertain"
    assert swapped
    assert (root / "old-prior").read_bytes() == b"prior"
    assert (root / "result").read_bytes() == b"replacement"
    stage.abort()


def test_false_result_rejects_same_inode_rewrite_after_prior_check(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    _private_file(root / "result", b"prior")
    alias = os.open(root / "result", os.O_RDWR | os.O_NOFOLLOW)
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_check = privfs._noreplace_existing_target_still_matches
    rewritten = False

    def rewrite_after_prior_check(*args, **kwargs):
        nonlocal rewritten
        result = real_check(*args, **kwargs)
        if not rewritten:
            rewritten = True
            os.pwrite(alias, b"other", 0)
            os.fsync(alias)
        return result

    monkeypatch.setattr(
        privfs,
        "_noreplace_existing_target_still_matches",
        rewrite_after_prior_check,
    )
    try:
        with pytest.raises(privfs.PrivatePublishIfAbsentUncertain) as error:
            privfs.publish_private_stage_if_absent(stage, ("result",))
        assert error.value.state == "uncertain"
        assert stage.state == "replaced_uncertain"
        assert rewritten
        assert (root / "result").read_bytes() == b"other"
    finally:
        os.close(alias)
        stage.abort()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_action_refusal_preserves_exact_cancellation_and_unpublished_stage(
    private_root, monkeypatch, cancellation_type,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    cancellation = cancellation_type("stop action")
    monkeypatch.setattr(
        privfs,
        "_renameat2_noreplace",
        lambda *args: (_ for _ in ()).throw(cancellation),
    )

    with pytest.raises(cancellation_type) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert error.value is cancellation
    assert error.value.operation == "publish_if_absent"
    assert error.value.state == "unpublished"
    assert stage.state == "sealed"
    assert not (root / "result").exists()
    assert root.joinpath(stage.temporary_name).read_bytes() == b"candidate"
    stage.abort()


def test_clean_syscall_refusal_is_replayed_as_original_error(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    refusal = OSError(errno.ENOSPC, "no room")
    monkeypatch.setattr(
        privfs,
        "_renameat2_noreplace",
        lambda *args: (_ for _ in ()).throw(refusal),
    )

    with pytest.raises(OSError) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert error.value is refusal
    assert stage.state == "sealed"
    assert not (root / "result").exists()
    assert root.joinpath(stage.temporary_name).read_bytes() == b"candidate"
    stage.abort()


def test_land_then_report_fault_is_committed_with_fault(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_action = privfs._renameat2_noreplace
    reported = OSError(errno.EIO, "reported after landing")

    def land_then_report(*args):
        real_action(*args)
        raise reported

    monkeypatch.setattr(privfs, "_renameat2_noreplace", land_then_report)
    with pytest.raises(privfs.PrivatePublishIfAbsentCommittedWithFault) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert error.value.operation == "publish_if_absent"
    assert error.value.state == "committed_with_fault"
    assert error.value.action_error is reported
    assert stage.state == "committed"
    assert (root / "result").read_bytes() == b"candidate"
    assert _stages(root) == []


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_land_then_cancel_preserves_exact_terminal_cancellation(
    private_root, monkeypatch, cancellation_type,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_action = privfs._renameat2_noreplace
    cancellation = cancellation_type("stop after landing")

    def land_then_cancel(*args):
        real_action(*args)
        raise cancellation

    monkeypatch.setattr(privfs, "_renameat2_noreplace", land_then_cancel)
    with pytest.raises(cancellation_type) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert error.value is cancellation
    assert error.value.operation == "publish_if_absent"
    assert error.value.state == "committed"
    assert stage.state == "committed"
    assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
    assert (root / "result").read_bytes() == b"candidate"


def test_directory_fsync_failure_is_uncertain_and_replay_commits(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_sync = privfs._fsync_managed
    failed = False

    def fail_directory(fd):
        nonlocal failed
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
            failed = True
            raise OSError(errno.EIO, "directory fsync failed")
        return real_sync(fd)

    monkeypatch.setattr(privfs, "_fsync_managed", fail_directory)
    with pytest.raises(privfs.PrivatePublishIfAbsentUncertain) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert error.value.state == "uncertain"
    assert error.value.cleanup_pending is True
    assert stage.state == "replaced_uncertain"
    assert stage._cleanup_ledger.pending is True
    assert (root / "result").read_bytes() == b"candidate"

    assert privfs.publish_private_stage_if_absent(stage, ("result",)) is True
    assert stage.state == "committed"
    assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)


def test_persistent_directory_fsync_replay_keeps_claims_and_fds_bounded(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_sync = privfs._fsync_managed

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "persistent directory fsync failure")
        return real_sync(fd)

    monkeypatch.setattr(privfs, "_fsync_managed", fail_directory)
    baseline_count = len(_open_fds())
    for _ in range(128):
        with pytest.raises(privfs.PrivatePublishIfAbsentUncertain) as error:
            privfs.publish_private_stage_if_absent(stage, ("result",))
        assert error.value.state == "uncertain"
        assert stage.state == "replaced_uncertain"
        assert len(stage._cleanup_ledger.claims) <= 8
        assert len(_open_fds()) <= baseline_count + 5
    assert (root / "result").read_bytes() == b"candidate"
    stage.abort()
    assert len(_open_fds()) == baseline_count - 3


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_directory_fsync_cancellation_is_exact_after_terminal_reconciliation(
    private_root, monkeypatch, cancellation_type,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_sync = privfs._fsync_managed
    cancellation = cancellation_type("stop durability")
    failed = False

    def cancel_directory(fd):
        nonlocal failed
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
            failed = True
            raise cancellation
        return real_sync(fd)

    monkeypatch.setattr(privfs, "_fsync_managed", cancel_directory)
    with pytest.raises(cancellation_type) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert error.value is cancellation
    assert error.value.state == "committed"
    assert stage.state == "committed"
    assert (root / "result").read_bytes() == b"candidate"
    assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)


def test_parent_name_substitution_refuses_publication(private_root):
    root, root_fd = private_root
    managed = _private_dir(root / "managed")
    stage = privfs.stage_private_bytes(
        root_fd, ("managed", "neutral"), b"candidate",
    )
    managed.rename(root / "held")
    _private_dir(root / "managed")

    with pytest.raises(privfs.PrivatePathUnsafe, match="declared path"):
        privfs.publish_private_stage_if_absent(
            stage, ("managed", "result"),
        )
    assert not (root / "managed" / "result").exists()
    assert not (root / "held" / "result").exists()
    stage.abort()


def test_named_stage_substitution_is_refused_without_touching_target(private_root):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    privfs.seal_private_stage(stage)
    os.rename(stage.temporary_name, "held-original", src_dir_fd=stage.parent_fd,
              dst_dir_fd=stage.parent_fd)
    planted = os.open(
        stage.temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        privfs.FILE_MODE,
        dir_fd=stage.parent_fd,
    )
    os.write(planted, b"planted")
    os.close(planted)

    with pytest.raises(privfs.PrivatePathUnsafe, match="substituted"):
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert not (root / "result").exists()
    with pytest.raises(privfs.PrivatePathUnsafe, match="cleanup refused"):
        stage.abort()


def test_uncertain_abort_consumes_retained_cleanup_authority(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    owned = (stage.file_fd, stage.parent_fd, stage.anchor_fd)
    real_sync = privfs._fsync_managed

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "directory fsync failed")
        return real_sync(fd)

    monkeypatch.setattr(privfs, "_fsync_managed", fail_directory)
    with pytest.raises(privfs.PrivatePublishIfAbsentUncertain):
        privfs.publish_private_stage_if_absent(stage, ("result",))
    stage.abort()
    assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
    for fd in owned:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert (root / "result").read_bytes() == b"candidate"


def test_replay_rejects_a_different_target(private_root, monkeypatch):
    _, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_sync = privfs._fsync_managed

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "directory fsync failed")
        return real_sync(fd)

    monkeypatch.setattr(privfs, "_fsync_managed", fail_directory)
    with pytest.raises(privfs.PrivatePublishIfAbsentUncertain):
        privfs.publish_private_stage_if_absent(stage, ("result",))
    with pytest.raises(privfs.PrivateStageStateError):
        privfs.publish_private_stage_if_absent(stage, ("other",))
    stage.abort()


def test_cas_outcome_operation_and_state_are_immutable():
    for outcome, expected_state in (
        (
            privfs.PrivatePublishIfAbsentUncertain(
                "uncertain", components=("result",),
            ),
            "uncertain",
        ),
        (
            privfs.PrivatePublishIfAbsentCommittedWithFault(
                "committed", components=("result",),
            ),
            "committed_with_fault",
        ),
    ):
        assert outcome.operation == "publish_if_absent"
        assert outcome.state == expected_state
        with pytest.raises(AttributeError):
            outcome.operation = "forged"
        with pytest.raises(AttributeError):
            outcome.state = "forged"
        for name in ("operation", "state"):
            with pytest.raises(AttributeError):
                delattr(outcome, name)
            with pytest.raises((AttributeError, TypeError)):
                outcome.__dict__[name] = "forged"
        assert outcome.operation == "publish_if_absent"
        assert outcome.state == expected_state


def test_same_inode_fd_reuse_after_close_effect_is_never_closed(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    stage_pin = stage.file_fd
    real_close = os.close
    reused: list[int] = []
    fired = False

    def close_effect_then_reuse(descriptor):
        nonlocal fired
        if (descriptor == stage_pin and stage.state == "committed"
                and not fired):
            fired = True
            real_close(descriptor)
            replacement = os.open(root / "result", os.O_RDONLY | os.O_NOFOLLOW)
            assert replacement == descriptor
            reused.append(replacement)
            raise OSError(errno.EIO, "close reported after taking effect")
        return real_close(descriptor)

    monkeypatch.setattr(privfs.os, "close", close_effect_then_reuse)
    with pytest.raises(
        privfs.PrivatePublishIfAbsentCommittedWithFault,
    ) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert error.value.state == "committed_with_fault"
    assert stage.state == "committed"
    assert os.read(reused[0], 9) == b"candidate"
    os.close(reused.pop())
    stage.abort()


def test_final_target_pin_detects_name_substitution_before_commit(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    real_match = privfs._noreplace_destination_matches_stage
    landed_checks = 0

    def substitute_after_settlement_match(*args, **kwargs):
        nonlocal landed_checks
        claim = real_match(*args, **kwargs)
        if claim is not None:
            landed_checks += 1
            if landed_checks == 2:
                os.rename(
                    "result", "held-stage",
                    src_dir_fd=stage.parent_fd,
                    dst_dir_fd=stage.parent_fd,
                )
                planted = os.open(
                    "result",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    privfs.FILE_MODE,
                    dir_fd=stage.parent_fd,
                )
                os.write(planted, b"substitute")
                os.close(planted)
        return claim

    monkeypatch.setattr(
        privfs,
        "_noreplace_destination_matches_stage",
        substitute_after_settlement_match,
    )
    with pytest.raises(privfs.PrivatePublishIfAbsentUncertain) as error:
        privfs.publish_private_stage_if_absent(stage, ("result",))
    assert landed_checks == 2
    assert error.value.state == "uncertain"
    assert stage.state == "replaced_uncertain"
    assert (root / "result").read_bytes() == b"substitute"
    assert (root / "held-stage").read_bytes() == b"candidate"
    stage.abort()


def test_final_target_pin_detects_same_inode_rewrite_before_commit(
    private_root, monkeypatch,
):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    alias = os.dup(stage.file_fd)
    real_match = privfs._noreplace_destination_matches_stage
    landed_checks = 0

    def rewrite_after_settlement_match(*args, **kwargs):
        nonlocal landed_checks
        claim = real_match(*args, **kwargs)
        if claim is not None:
            landed_checks += 1
            if landed_checks == 2:
                os.pwrite(alias, b"hostile!!", 0)
                os.fsync(alias)
        return claim

    monkeypatch.setattr(
        privfs,
        "_noreplace_destination_matches_stage",
        rewrite_after_settlement_match,
    )
    try:
        with pytest.raises(privfs.PrivatePublishIfAbsentUncertain) as error:
            privfs.publish_private_stage_if_absent(stage, ("result",))
        assert landed_checks == 2
        assert error.value.state == "uncertain"
        assert stage.state == "replaced_uncertain"
        assert (root / "result").read_bytes() == b"hostile!!"
    finally:
        os.close(alias)
        stage.abort()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_outer_handler_and_serialized_wrapper_occurrences_classify_cancellation(
    private_root, monkeypatch, cancellation_type,
):
    root, _ = private_root
    wrapper_codes = frozenset({
        privfs._publish_private_stage_if_absent_fenced.__code__,
        privfs._PrivateNoreplacePublicFence.__exit__.__code__,
        privfs._settle_noreplace_public_escape.__code__,
        privfs._publish_private_stage_if_absent_public_middle.__code__,
        privfs._publish_private_stage_if_absent_public_inner.__code__,
        privfs._publish_private_stage_if_absent_public_outer.__code__,
    })
    # The private export handler is the finite reserve that classifies a fresh
    # cancellation raised from every lower settlement handler.  Requiring a
    # further injected cancellation inside that final reserve would merely move
    # the same last-handler boundary outward without bound.

    def invoke(name: str, target_occurrence: int | None):
        case = _private_dir(root / name)
        case_fd = os.open(
            case, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        stage = privfs.stage_private_bytes(
            case_fd, ("neutral",), b"candidate",
        )
        real_action = privfs._renameat2_noreplace
        first = KeyboardInterrupt("first terminal cancellation")
        second = cancellation_type("outer handler cancellation")
        landed = False
        occurrence = 0
        events: list[tuple[object, int]] = []

        def land_then_cancel(*args):
            nonlocal landed
            real_action(*args)
            landed = True
            raise first

        def trace(frame, event, arg):
            nonlocal occurrence
            if event == "line" and landed and frame.f_code in wrapper_codes:
                events.append((frame.f_code, frame.f_lineno))
                occurrence += 1
                if occurrence == target_occurrence:
                    import sys
                    sys.settrace(None)
                    raise second
            return trace

        import sys
        previous = sys.gettrace()
        monkeypatch.setattr(privfs, "_renameat2_noreplace", land_then_cancel)
        sys.settrace(trace)
        try:
            with pytest.raises(BaseException) as escaped:
                privfs.publish_private_stage_if_absent(stage, ("result",))
        finally:
            sys.settrace(previous)
            monkeypatch.setattr(privfs, "_renameat2_noreplace", real_action)
            os.close(case_fd)
        return case, stage, first, second, escaped.value, events

    _, baseline_stage, first, _, escaped, events = invoke("baseline", None)
    assert escaped is first
    assert escaped.state == "committed"
    baseline_stage.abort()
    assert events
    assert any(code in wrapper_codes for code, _ in events)

    unclassified: list[int] = []
    for occurrence in range(1, len(events) + 1):
        before_fds = _open_fds()
        case, stage, _, second, escaped, _ = invoke(
            f"{cancellation_type.__name__}-{occurrence}", occurrence,
        )
        assert escaped is second, f"boundary occurrence {occurrence}"
        if getattr(escaped, "operation", None) != "publish_if_absent":
            unclassified.append(occurrence)
        else:
            assert escaped.state == "committed"
        assert stage.state == "committed"
        assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (-1, -1, -1)
        assert isinstance(stage._cleanup_ledger, privfs._PrivateStageCleanupLedger)
        assert stage._cleanup_ledger.pending is False
        assert (case / "result").read_bytes() == b"candidate"
        stage.abort()
        assert _open_fds() == before_fds
    # Only the contiguous final reserve invocation may lack metadata: a fresh
    # second asynchronous cancellation there has no further active Python
    # handler.  Its exact object and fully reconciled committed truth were still
    # asserted above.  Every earlier settle-helper/handler occurrence classifies.
    assert unclassified
    assert unclassified == list(range(unclassified[0], len(events) + 1))
    first_final = unclassified[0]
    assert events[first_final - 1][0] is privfs._settle_noreplace_public_escape.__code__
    assert all(
        code is privfs._settle_noreplace_public_escape.__code__
        for code, _ in events[first_final - 1:]
    )


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_existing_target_cleanup_cancellation_is_exact_and_retryable(
    private_root, cancellation_type,
):
    root, _ = private_root
    target_line = _line(
        privfs._drain_noreplace_claim_once,
        'object.__setattr__(claim, "_fd", -1); os.close(descriptor)',
    )
    cancellation = cancellation_type("existing-target cleanup")
    injected = False

    def trace(frame, event, arg):
        nonlocal injected
        if (not injected and event == "line"
                and frame.f_code is privfs._drain_noreplace_claim_once.__code__
                and frame.f_lineno == target_line):
            import sys
            injected = True
            sys.settrace(None)
            raise cancellation
        return trace

    before_fds = _open_fds()
    case, stage, result, error = _invoke_existing_private_case(
        root, cancellation_type.__name__, trace,
    )
    assert injected
    assert result is None
    assert error is cancellation
    assert error.operation == "publish_if_absent"
    assert error.state == "unpublished"
    assert stage.state == "sealed"
    assert (case / "result").read_bytes() == b"prior"
    assert privfs.publish_private_stage_if_absent(stage, ("result",)) is False
    assert stage.state == "sealed"
    stage.abort()
    assert _open_fds() == before_fds


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("boundary", [
    *(
        [privfs._publish_private_stage_if_absent_public_export]
        if sys.version_info[:2] != (3, 10) else []
    ),
    privfs._publish_private_stage_if_absent_public_outer,
    privfs._publish_private_stage_if_absent_public_inner,
    privfs._publish_private_stage_if_absent_public_middle,
])
def test_public_entry_line_cancellation_has_unpublished_metadata(
    private_root, cancellation_type, boundary,
):
    root, _ = private_root
    target_line = _line(boundary, "try: return _publish_private_stage_if_absent")
    cancellation = cancellation_type("public entry")
    injected = False

    def trace(frame, event, arg):
        nonlocal injected
        if (not injected and event == "line" and frame.f_code is boundary.__code__
                and frame.f_lineno == target_line):
            import sys
            injected = True
            sys.settrace(None)
            raise cancellation
        return trace

    before_fds = _open_fds()
    case, stage, result, error = _invoke_existing_private_case(
        root, f"{boundary.__name__}-{cancellation_type.__name__}", trace,
    )
    assert injected
    assert result is None
    assert error is cancellation
    assert error.operation == "publish_if_absent"
    assert error.state == "unpublished"
    assert stage.state == "sealed"
    assert (case / "result").read_bytes() == b"prior"
    assert privfs.publish_private_stage_if_absent(stage, ("result",)) is False
    stage.abort()
    assert _open_fds() == before_fds


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("boundary", [
    privfs.publish_private_stage_if_absent,
    *(
        [privfs._publish_private_stage_if_absent_public_export]
        if sys.version_info[:2] == (3, 10) else []
    ),
])
def test_public_trampoline_entry_trace_is_wholly_preoperation(
    private_root, cancellation_type, boundary, monkeypatch,
):
    root, root_fd = private_root
    _private_file(root / "result", b"prior")
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    privfs.seal_private_stage(stage)
    target_line = _line(
        boundary,
        (
            "return _publish_private_stage_if_absent_public_export"
            if boundary is privfs.publish_private_stage_if_absent
            else "try: return _publish_private_stage_if_absent_public_outer"
        ),
    )
    cancellation = cancellation_type("pre-operation entry")
    injected = False
    before_fds = _open_fds()
    before_stage = tuple(
        (slot, getattr(stage, slot)) for slot in privfs.PrivateFileStage.__slots__
    )

    def snapshot_names():
        return tuple(sorted(
            (
                entry.name,
                entry.inode(),
                stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode),
                Path(entry.path).read_bytes(),
            )
            for entry in os.scandir(root)
        ))

    def lock_is_free():
        acquired: list[bool] = []

        def probe():
            held = stage._lifecycle_lock.acquire(blocking=False)
            acquired.append(held)
            if held:
                stage._lifecycle_lock.release()

        thread = threading.Thread(target=probe)
        thread.start()
        thread.join()
        return acquired == [True]

    before_names = snapshot_names()
    assert lock_is_free()
    action_calls = 0
    real_action = privfs._renameat2_noreplace

    def record_action(*args, **kwargs):
        nonlocal action_calls
        action_calls += 1
        return real_action(*args, **kwargs)

    monkeypatch.setattr(privfs, "_renameat2_noreplace", record_action)

    def trace(frame, event, arg):
        nonlocal injected
        if (not injected and event == "line"
                and frame.f_code is boundary.__code__
                and frame.f_lineno == target_line):
            injected = True
            sys.settrace(None)
            raise cancellation
        return trace

    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        with pytest.raises(cancellation_type) as error:
            privfs.publish_private_stage_if_absent(stage, ("result",))
    finally:
        sys.settrace(previous)
    assert injected
    assert error.value is cancellation
    assert not hasattr(error.value, "operation")
    assert not hasattr(error.value, "state")
    assert tuple(
        (slot, getattr(stage, slot)) for slot in privfs.PrivateFileStage.__slots__
    ) == before_stage
    assert snapshot_names() == before_names
    assert (root / "result").read_bytes() == b"prior"
    assert action_calls == 0
    assert lock_is_free()
    assert _open_fds() == before_fds
    stage.abort()


def test_terminal_source_line_cancellation_is_reconciled(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("neutral",), b"candidate")
    target_line = _line(
        privfs._finish_noreplace_commit,
        "cleanup_errors, cleanup_pending =",
    )
    cancellation = KeyboardInterrupt("terminal source line")
    previous = None

    def trace(frame, event, arg):
        if (event == "line" and frame.f_code is privfs._finish_noreplace_commit.__code__
                and frame.f_lineno == target_line):
            import sys
            sys.settrace(None)
            raise cancellation
        return trace

    import sys
    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        with pytest.raises(KeyboardInterrupt) as error:
            privfs.publish_private_stage_if_absent(stage, ("result",))
    finally:
        sys.settrace(previous)
    assert error.value is cancellation
    assert error.value.state == "committed"
    assert stage.state == "committed"
    assert (root / "result").read_bytes() == b"candidate"
    stage.abort()


def test_each_reached_action_and_terminal_source_line_preserves_cancellation(
    private_root,
):
    root, _ = private_root
    visited: set[tuple[object, int]] = set()

    def record(frame, event, arg):
        if event == "line" and frame.f_code in _ACTION_TERMINAL_CODES:
            visited.add((frame.f_code, frame.f_lineno))
        return record

    _, clean_stage, clean_result, clean_error = _invoke_in_private_case(
        root, "record", record,
    )
    assert clean_error is None
    assert clean_result is True
    clean_stage.abort()
    assert visited

    for cancellation_type in (KeyboardInterrupt, SystemExit):
        for index, (code, target_line) in enumerate(sorted(
            visited, key=lambda item: (item[0].co_firstlineno, item[1]),
        )):
            before_fds = _open_fds()
            cancellation = cancellation_type(
                f"cancel {code.co_name}:{target_line}",
            )
            injected = False

            def interrupt(frame, event, arg):
                nonlocal injected
                if (not injected and event == "line"
                        and frame.f_code is code
                        and frame.f_lineno == target_line):
                    import sys
                    injected = True
                    sys.settrace(None)
                    raise cancellation
                return interrupt

            case, stage, result, error = _invoke_in_private_case(
                root,
                f"{cancellation_type.__name__}-{index}",
                interrupt,
            )
            assert injected, f"source line {code.co_name}:{target_line}"
            assert result is None, f"source line {code.co_name}:{target_line}"
            assert error is cancellation, f"source line {code.co_name}:{target_line}"
            assert getattr(error, "operation", None) == "publish_if_absent", (
                f"source line {code.co_name}:{target_line}"
            )
            assert error.state in {"unpublished", "uncertain", "committed"}
            assert stage.state in {
                "open", "sealed", "replaced_uncertain", "committed",
            }, f"source line {code.co_name}:{target_line}"
            if stage.state == "committed":
                assert (case / "result").read_bytes() == b"candidate"
            elif stage.state in {"open", "sealed"}:
                assert not (case / "result").exists()
                assert privfs.publish_private_stage_if_absent(
                    stage, stage.components[:-1] + ("result",),
                ) is True
                assert stage.state == "committed"
            stage.abort()
            assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (
                -1, -1, -1,
            ), f"source line {code.co_name}:{target_line}"
            assert _open_fds() == before_fds, (
                f"source line {code.co_name}:{target_line}"
            )


def test_each_reached_existing_target_line_preserves_cancellation(private_root):
    root, _ = private_root
    visited: set[tuple[object, int]] = set()

    def record(frame, event, arg):
        if event == "line" and frame.f_code in _ACTION_TERMINAL_CODES:
            visited.add((frame.f_code, frame.f_lineno))
        return record

    _, clean_stage, clean_result, clean_error = _invoke_existing_private_case(
        root, "existing-record", record,
    )
    assert clean_error is None
    assert clean_result is False
    clean_stage.abort()
    assert visited

    for cancellation_type in (KeyboardInterrupt, SystemExit):
        for index, (code, target_line) in enumerate(sorted(
            visited, key=lambda item: (item[0].co_firstlineno, item[1]),
        )):
            before_fds = _open_fds()
            cancellation = cancellation_type(
                f"existing {code.co_name}:{target_line}",
            )
            injected = False

            def interrupt(frame, event, arg):
                nonlocal injected
                if (not injected and event == "line" and frame.f_code is code
                        and frame.f_lineno == target_line):
                    import sys
                    injected = True
                    sys.settrace(None)
                    raise cancellation
                return interrupt

            case, stage, result, error = _invoke_existing_private_case(
                root,
                f"existing-{cancellation_type.__name__}-{index}",
                interrupt,
            )
            assert injected, f"source line {code.co_name}:{target_line}"
            assert result is None, f"source line {code.co_name}:{target_line}"
            assert error is cancellation, f"source line {code.co_name}:{target_line}"
            assert getattr(error, "operation", None) == "publish_if_absent", (
                f"source line {code.co_name}:{target_line}"
            )
            assert error.state in {"unpublished", "uncertain"}
            assert (case / "result").read_bytes() == b"prior"
            if stage.state in {"sealed", "replaced_uncertain"}:
                assert privfs.publish_private_stage_if_absent(
                    stage, ("result",),
                ) is False
            stage.abort()
            assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (
                -1, -1, -1,
            ), f"source line {code.co_name}:{target_line}"
            assert _open_fds() == before_fds, (
                f"source line {code.co_name}:{target_line}"
            )


def test_each_reached_replay_compaction_line_preserves_cancellation(private_root):
    root, _ = private_root
    code = privfs._compact_noreplace_replay_claims.__code__
    visited: set[int] = set()

    def record(frame, event, arg):
        if event == "line" and frame.f_code is code:
            visited.add(frame.f_lineno)
        return record

    _, stage, _, baseline_error = _invoke_uncertain_replay_case(
        root, "replay-record", record,
    )
    assert isinstance(baseline_error, privfs.PrivatePublishIfAbsentUncertain)
    stage.abort()
    assert visited

    for cancellation_type in (KeyboardInterrupt, SystemExit):
        for index, target_line in enumerate(sorted(visited)):
            before_fds = _open_fds()
            cancellation = cancellation_type(
                f"replay compaction {target_line}",
            )
            injected = False

            def interrupt(frame, event, arg):
                nonlocal injected
                if (not injected and event == "line" and frame.f_code is code
                        and frame.f_lineno == target_line):
                    import sys
                    injected = True
                    sys.settrace(None)
                    raise cancellation
                return interrupt

            case, stage, result, error = _invoke_uncertain_replay_case(
                root,
                f"replay-{cancellation_type.__name__}-{index}",
                interrupt,
            )
            assert injected, target_line
            assert result is None, target_line
            assert error is cancellation, target_line
            assert error.operation == "publish_if_absent"
            assert error.state == "uncertain"
            assert stage.state == "replaced_uncertain"
            assert (case / "result").read_bytes() == b"candidate"
            stage.abort()
            assert _open_fds() == before_fds, target_line
