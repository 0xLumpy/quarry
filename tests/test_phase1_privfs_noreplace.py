"""Phase 1 same-parent no-replace private-stage publication."""
from __future__ import annotations

import errno
import inspect
import os
import stat
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


def _line(function, fragment: str) -> int:
    lines, start = inspect.getsourcelines(function)
    matches = [start + index for index, text in enumerate(lines) if fragment in text]
    assert len(matches) == 1
    return matches[0]


_ACTION_TERMINAL_CODES = frozenset({
    privfs._renameat2_noreplace.__code__,
    privfs._noreplace_target_components.__code__,
    privfs._new_noreplace_cleanup_ledger.__code__,
    privfs._noreplace_cleanup_claims.__code__,
    privfs._noreplace_fds.__code__,
    privfs._validate_declared_noreplace_parent.__code__,
    privfs._noreplace_named_stage_matches.__code__,
    privfs._noreplace_destination_matches_stage.__code__,
    privfs._noreplace_target_exists_stably.__code__,
    privfs.publish_private_stage_if_absent.__code__,
    privfs._publish_private_stage_if_absent_locked.__code__,
    privfs._arm_noreplace_stage.__code__,
    privfs._start_noreplace_action.__code__,
    privfs._reconcile_noreplace_action.__code__,
    privfs._finish_noreplace_commit.__code__,
    privfs._drain_noreplace_cleanup.__code__,
})


def _invoke_in_private_case(root: Path, name: str, trace=None):
    case = _private_dir(root / name)
    case_fd = os.open(case, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stage = privfs.stage_private_bytes(case_fd, ("neutral",), b"candidate")
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
            assert stage.state in {
                "open", "sealed", "replaced_uncertain", "committed",
            }, f"source line {code.co_name}:{target_line}"
            if stage.state == "committed":
                assert (case / "result").read_bytes() == b"candidate"
            elif stage.state in {"open", "sealed"}:
                assert not (case / "result").exists()
                assert privfs.publish_private_stage_if_absent(
                    stage, ("result",),
                ) is True
                assert stage.state == "committed"
            stage.abort()
            assert (stage.file_fd, stage.parent_fd, stage.anchor_fd) == (
                -1, -1, -1,
            ), f"source line {code.co_name}:{target_line}"
