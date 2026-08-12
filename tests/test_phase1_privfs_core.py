"""Phase 1 strict descriptor-relative private-filesystem primitives."""
from __future__ import annotations

import os
import string
import socket
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


def _private_file(path: Path, data: bytes = b"evidence") -> Path:
    path.write_bytes(data)
    os.chmod(path, privfs.FILE_MODE)
    return path


def _stages(path: Path) -> list[Path]:
    prefix = ".quarry-"
    suffix = ".stage"
    return [
        candidate
        for candidate in path.iterdir()
        if candidate.name.startswith(prefix)
        and candidate.name.endswith(suffix)
        and len(candidate.name[len(prefix):-len(suffix)]) == 32
        and all(char in string.hexdigits for char in candidate.name[len(prefix):-len(suffix)])
    ]


def _discarded(path: Path) -> list[Path]:
    return list(path.glob(".quarry-discard-*.stage"))


def test_strict_open_reads_an_exact_private_file(private_root):
    root, root_fd = private_root
    first = _private_dir(root / "first")
    _private_dir(first / "second")
    _private_file(first / "second" / "evidence.json", b"full fidelity")

    fd = privfs.open_strict_file_at(root_fd, ("first", "second", "evidence.json"))
    try:
        assert os.read(fd, 100) == b"full fidelity"
    finally:
        os.close(fd)


@pytest.mark.parametrize("depth", range(3))
def test_strict_walk_refuses_a_symlink_at_every_directory_depth(private_root, depth):
    root, root_fd = private_root
    outside = _private_dir(root / "outside")
    cursor = root
    components = ("one", "two", "three")
    for index, component in enumerate(components):
        candidate = cursor / component
        if index == depth:
            candidate.symlink_to(outside, target_is_directory=True)
            break
        cursor = _private_dir(candidate)

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.open_strict_dir_at(root_fd, components)


def test_strict_file_open_refuses_a_symlink_leaf(private_root):
    root, root_fd = private_root
    outside = _private_file(root / "outside", b"must not be read")
    (root / "evidence").symlink_to(outside)

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.open_strict_file_at(root_fd, ("evidence",))


def test_missing_directory_and_file_are_typed(private_root):
    root, root_fd = private_root
    _private_dir(root / "present")

    with pytest.raises(privfs.PrivatePathMissing):
        privfs.open_strict_dir_at(root_fd, ("absent",))
    with pytest.raises(privfs.PrivatePathMissing):
        privfs.open_strict_file_at(root_fd, ("present", "absent"))


@pytest.mark.parametrize(
    "components",
    [
        [],
        ("",),
        (".",),
        ("..",),
        ("a/b",),
        ("a\\b",),
        ("nul\x00",),
        ("line\nfeed",),
        ("\ud800",),
        ("x" * 256,),
        tuple("x" for _ in range(65)),
    ],
)
def test_invalid_components_fail_before_descriptor_access(private_root, monkeypatch, components):
    _, root_fd = private_root
    touched = []
    real_dup = os.dup
    monkeypatch.setattr(privfs.os, "dup", lambda fd: touched.append(fd) or real_dup(fd))

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.open_strict_file_at(root_fd, components)
    assert touched == []


def test_non_integer_anchor_is_rejected_before_descriptor_access(monkeypatch):
    touched = []
    monkeypatch.setattr(privfs.os, "dup", lambda fd: touched.append(fd) or -1)

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.open_strict_dir_at(True, ())
    assert touched == []


def test_unsupported_strict_platform_is_typed_before_descriptor_access(monkeypatch):
    touched = []
    monkeypatch.setattr(privfs, "_STRICT_CAPABILITY_GAPS", ("descriptor-relative open",))
    monkeypatch.setattr(privfs.os, "dup", lambda fd: touched.append(fd))

    with pytest.raises(privfs.PrivatePathUnsupported, match="descriptor-relative open"):
        privfs.open_strict_dir_at(3, ())
    assert touched == []


def test_unsupported_filesystem_fsync_is_typed(private_root, monkeypatch):
    _, root_fd = private_root
    monkeypatch.setattr(
        privfs.os,
        "fsync",
        lambda fd: (_ for _ in ()).throw(OSError(getattr(os, "EINVAL", 22), "unsupported")),
    )
    with pytest.raises(privfs.PrivatePathUnsupported, match="fsync durability"):
        privfs.durable_replace_private(root_fd, ("result",), b"evidence")


def test_systemic_open_failure_is_not_reclassified(private_root, monkeypatch):
    root, root_fd = private_root
    _private_dir(root / "child")
    real_open = os.open

    def exhausted(path, flags, *args, **kwargs):
        if path == "child":
            raise OSError(24, "too many open files")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(privfs.os, "open", exhausted)
    with pytest.raises(OSError) as error:
        privfs.open_strict_dir_at(root_fd, ("child",))
    assert error.value.errno == 24
    assert not isinstance(error.value, privfs.PrivatePathError)


def test_printable_unicode_component_is_lossless(private_root):
    root, root_fd = private_root
    _private_file(root / "доказ.json", b"raw")
    fd = privfs.open_strict_file_at(root_fd, ("доказ.json",))
    os.close(fd)


def test_anchor_intermediate_and_file_modes_are_exact(private_root):
    root, root_fd = private_root
    child = _private_dir(root / "child")
    evidence = _private_file(child / "evidence")

    os.chmod(root, 0o750)
    with pytest.raises(privfs.LegacyModeMismatch) as anchor_error:
        privfs.open_strict_file_at(root_fd, ("child", "evidence"))
    assert (anchor_error.value.expected, anchor_error.value.actual) == (0o700, 0o750)

    os.chmod(root, 0o700)
    os.chmod(child, 0o755)
    with pytest.raises(privfs.LegacyModeMismatch):
        privfs.open_strict_file_at(root_fd, ("child", "evidence"))

    os.chmod(child, 0o700)
    os.chmod(evidence, 0o640)
    with pytest.raises(privfs.LegacyModeMismatch) as file_error:
        privfs.open_strict_file_at(root_fd, ("child", "evidence"))
    assert (file_error.value.expected, file_error.value.actual) == (0o600, 0o640)


def test_foreign_owner_is_structurally_unsafe(private_root, monkeypatch):
    root, root_fd = private_root
    _private_file(root / "evidence")
    actual = os.geteuid()
    monkeypatch.setattr(privfs.os, "geteuid", lambda: actual + 1)

    with pytest.raises(privfs.PrivatePathUnsafe) as error:
        privfs.open_strict_file_at(root_fd, ("evidence",))
    assert not isinstance(error.value, privfs.LegacyModeMismatch)


def test_hardlinked_file_is_unsafe(private_root):
    root, root_fd = private_root
    evidence = _private_file(root / "evidence")
    os.link(evidence, root / "second-name")

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.open_strict_file_at(root_fd, ("evidence",))


def test_fifo_and_socket_are_refused_without_blocking(private_root):
    root, root_fd = private_root
    os.mkfifo(root / "fifo", 0o600)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            sock.bind(str(root / "socket"))
        except PermissionError:
            pytest.skip("sandbox does not permit pathname Unix sockets")
        with pytest.raises(privfs.PrivatePathUnsafe):
            privfs.open_strict_file_at(root_fd, ("fifo",))
        with pytest.raises(privfs.PrivatePathUnsafe):
            privfs.open_strict_file_at(root_fd, ("socket",))
    finally:
        sock.close()


def test_explicit_repair_only_removes_excess_mode_bits(private_root):
    root, root_fd = private_root
    loose_dir = _private_dir(root / "loose-dir")
    loose_file = _private_file(root / "loose-file")
    os.chmod(loose_dir, 0o755)
    os.chmod(loose_file, 0o664)

    dir_receipt = privfs.repair_legacy_mode_at(root_fd, ("loose-dir",), is_dir=True)
    file_receipt = privfs.repair_legacy_mode_at(root_fd, ("loose-file",), is_dir=False)
    assert (dir_receipt.before_mode, dir_receipt.after_mode) == (0o755, 0o700)
    assert (file_receipt.before_mode, file_receipt.after_mode) == (0o664, 0o600)
    assert file_receipt.inode == loose_file.stat().st_ino
    assert stat.S_IMODE(loose_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(loose_file.stat().st_mode) == 0o600
    assert privfs.repair_legacy_mode_at(root_fd, ("loose-file",), is_dir=False) is None


def test_owned_non_writable_project_boundary_can_open_strict_root(tmp_path):
    os.chmod(tmp_path, 0o755)
    _private_dir(tmp_path / "recon")
    anchor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        managed = privfs.open_strict_root_at(anchor, "recon")
        os.close(managed)
    finally:
        os.close(anchor)


def test_explicit_root_repair_returns_identity_receipt(private_root):
    root, root_fd = private_root
    os.chmod(root, 0o755)
    receipt = privfs.repair_legacy_mode_at(root_fd, (), is_dir=True)
    assert receipt.components == ()
    assert receipt.object_kind == "directory"
    assert (receipt.before_mode, receipt.after_mode) == (0o755, 0o700)


@pytest.mark.parametrize("mode", [0o4700, 0o2700, 0o1700])
def test_explicit_repair_refuses_special_mode_bits(private_root, mode):
    root, root_fd = private_root
    directory = _private_dir(root / "legacy")
    os.chmod(directory, mode)
    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.repair_legacy_mode_at(root_fd, ("legacy",), is_dir=True)
    assert stat.S_IMODE(directory.stat().st_mode) == mode


@pytest.mark.parametrize("mode", [0o400, 0o200, 0o000])
def test_explicit_repair_never_adds_missing_owner_permissions(private_root, mode):
    root, root_fd = private_root
    evidence = _private_file(root / "evidence")
    os.chmod(evidence, mode)

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.repair_legacy_mode_at(root_fd, ("evidence",), is_dir=False)
    assert stat.S_IMODE(evidence.stat().st_mode) == mode


def test_explicit_repair_refuses_hardlinks_and_symlinks(private_root):
    root, root_fd = private_root
    linked = _private_file(root / "linked")
    os.link(linked, root / "other-link")
    (root / "symlink").symlink_to(linked)

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.repair_legacy_mode_at(root_fd, ("linked",), is_dir=False)
    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.repair_legacy_mode_at(root_fd, ("symlink",), is_dir=False)


def test_repair_fsync_failure_reports_a_changed_uncertain_receipt(private_root, monkeypatch):
    root, root_fd = private_root
    evidence = _private_file(root / "legacy")
    os.chmod(evidence, 0o644)
    monkeypatch.setattr(
        privfs.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("repair fsync failed")),
    )

    with pytest.raises(privfs.LegacyRepairUncertain) as error:
        privfs.repair_legacy_mode_at(root_fd, ("legacy",), is_dir=False)
    assert error.value.receipt.inode == evidence.stat().st_ino
    assert (error.value.receipt.before_mode, error.value.receipt.after_mode) == (0o644, 0o600)
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600


def test_repair_cancellation_after_fchmod_preserves_the_landed_receipt(private_root, monkeypatch):
    root, root_fd = private_root
    evidence = _private_file(root / "legacy")
    os.chmod(evidence, 0o644)
    real_fchmod = os.fchmod

    def change_then_interrupt(fd, mode):
        real_fchmod(fd, mode)
        raise KeyboardInterrupt()

    monkeypatch.setattr(privfs.os, "fchmod", change_then_interrupt)
    with pytest.raises(privfs.LegacyRepairUncertain) as error:
        privfs.repair_legacy_mode_at(root_fd, ("legacy",), is_dir=False)
    assert isinstance(error.value.__cause__, KeyboardInterrupt)
    assert error.value.receipt.inode == evidence.stat().st_ino
    assert (error.value.receipt.before_mode, error.value.receipt.after_mode) == (0o644, 0o600)
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600


def test_stage_is_unpublished_until_explicit_replace(private_root):
    root, root_fd = private_root
    destination = _private_file(root / "result", b"old")
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"new")
    try:
        assert destination.read_bytes() == b"old"
        assert len(_stages(root)) == 1
        privfs.replace_private_stage(stage)
    finally:
        stage.abort()
    assert destination.read_bytes() == b"new"
    assert _stages(root) == []


def test_stage_capability_claim_fields_are_read_only(private_root):
    _, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"new")
    try:
        with pytest.raises(AttributeError):
            stage.destination_name = "redirected"
        with pytest.raises(AttributeError):
            stage.__dict__["destination_name"] = "redirected"
    finally:
        stage.abort()


def test_stage_handle_is_not_a_same_process_security_boundary(private_root):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"new")
    object.__setattr__(stage, "_destination_name", "redirected")
    try:
        privfs.replace_private_stage(stage)
    finally:
        stage.abort()
    assert not (root / "result").exists()
    assert (root / "redirected").read_bytes() == b"new"


def test_private_stage_constructor_rejects_forged_handles():
    with pytest.raises(privfs.PrivatePathUnsafe, match="strict staging API"):
        privfs.PrivateFileStage(
            anchor_fd=1,
            parent_fd=2,
            file_fd=3,
            temporary_name="stage",
            destination_name="result",
            components=("result",),
            parent_identity=(1, 2),
            file_identity=(1, 3),
            _constructor_token=object(),
        )


def test_durable_replace_fsyncs_file_then_directory(private_root, monkeypatch):
    root, root_fd = private_root
    calls = []
    real_fsync = privfs.os.fsync

    def record(fd):
        calls.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        return real_fsync(fd)

    monkeypatch.setattr(privfs.os, "fsync", record)
    privfs.durable_replace_private(root_fd, ("result",), b"new evidence")

    assert calls == ["file", "dir"]
    assert (root / "result").read_bytes() == b"new evidence"
    assert stat.S_IMODE((root / "result").stat().st_mode) == 0o600


def test_new_stage_mode_is_exact_even_under_restrictive_umask(private_root):
    root, root_fd = private_root
    previous = os.umask(0o777)
    try:
        privfs.durable_replace_private(root_fd, ("result",), b"evidence")
    finally:
        os.umask(previous)
    assert stat.S_IMODE((root / "result").stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_replace_refuses_an_unsafe_existing_destination(private_root, kind):
    root, root_fd = private_root
    outside = _private_file(root / "outside", b"outside")
    destination = root / "result"
    if kind == "symlink":
        destination.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, destination)
    else:
        os.mkfifo(destination, 0o600)

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.durable_replace_private(root_fd, ("result",), b"replacement")

    assert outside.read_bytes() == b"outside"
    assert _stages(root) == []


def test_replace_refuses_a_legacy_mode_destination_without_repair(private_root):
    root, root_fd = private_root
    destination = _private_file(root / "result", b"old")
    os.chmod(destination, 0o644)

    with pytest.raises(privfs.LegacyModeMismatch):
        privfs.durable_replace_private(root_fd, ("result",), b"new")
    assert destination.read_bytes() == b"old"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o644
    assert _stages(root) == []


def test_named_stage_substitution_is_detected(private_root):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"trusted")
    privfs.seal_private_stage(stage)
    os.unlink(stage.temporary_name, dir_fd=stage.parent_fd)
    planted = os.open(
        stage.temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=stage.parent_fd,
    )
    os.write(planted, b"substitute")
    os.close(planted)
    with pytest.raises(privfs.PrivatePathUnsafe, match="substituted"):
        privfs.replace_private_stage(stage)
    with pytest.raises(privfs.PrivatePathUnsafe, match="cleanup refused"):
        stage.abort()
    assert not (root / "result").exists()
    quarantined = _discarded(root)
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"substitute"


def test_abort_never_unlinks_a_quarantined_name(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"trusted")
    monkeypatch.setattr(
        privfs.os,
        "unlink",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unlink is unsafe")),
    )
    stage.abort()
    assert _stages(root) == []
    assert len(_discarded(root)) == 1


def test_parent_path_substitution_cannot_redirect_a_pinned_stage(private_root):
    root, root_fd = private_root
    managed = _private_dir(root / "managed")
    _private_dir(managed / "inner")
    outside = _private_dir(root / "outside")
    stage = privfs.stage_private_bytes(root_fd, ("managed", "inner", "result"), b"trusted")

    managed.rename(root / "held")
    (root / "managed").symlink_to(outside, target_is_directory=True)
    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.replace_private_stage(stage)
    stage.abort()

    assert not (root / "held" / "inner" / "result").exists()
    assert not (outside / "inner").exists()


def test_rename_that_lands_then_raises_is_not_reported_as_clean_failure(private_root, monkeypatch):
    root, root_fd = private_root
    _private_file(root / "result", b"old")
    real_rename = os.rename

    def land_then_raise(*args, **kwargs):
        real_rename(*args, **kwargs)
        raise OSError("reported after rename")

    monkeypatch.setattr(privfs.os, "rename", land_then_raise)
    with pytest.raises(privfs.PrivateReplaceCommittedWithFault, match="durably reconciled"):
        privfs.durable_replace_private(root_fd, ("result",), b"new")
    assert (root / "result").read_bytes() == b"new"
    assert _stages(root) == []


def test_file_fsync_failure_preserves_prior_destination(private_root, monkeypatch):
    root, root_fd = private_root
    destination = _private_file(root / "result", b"old")
    real_fsync = privfs.os.fsync

    def fail_file(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("file fsync failed")
        return real_fsync(fd)

    monkeypatch.setattr(privfs.os, "fsync", fail_file)
    with pytest.raises(OSError, match="file fsync failed"):
        privfs.durable_replace_private(root_fd, ("result",), b"new")
    assert destination.read_bytes() == b"old"
    assert _stages(root) == []


def test_stage_close_failure_is_explicit_and_does_not_publish(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"new")
    write_fd = stage.file_fd
    real_close = os.close
    failed = False

    def close_then_report(fd):
        nonlocal failed
        real_close(fd)
        if fd == write_fd and not failed:
            failed = True
            raise OSError("close reported failure")

    monkeypatch.setattr(privfs.os, "close", close_then_report)
    with pytest.raises(privfs.PrivatePathError, match="did not close cleanly"):
        privfs.replace_private_stage(stage)
    stage.abort()
    assert not (root / "result").exists()
    assert _stages(root) == []


def test_post_durability_close_failure_is_explicit_but_committed(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"new")
    parent_fd = stage.parent_fd
    real_close = os.close
    failed = False

    def close_then_report(fd):
        nonlocal failed
        real_close(fd)
        if fd == parent_fd and not failed:
            failed = True
            raise OSError("parent close reported failure")

    monkeypatch.setattr(privfs.os, "close", close_then_report)
    with pytest.raises(privfs.PrivateReplaceCommittedWithFault, match="replacement completed"):
        privfs.replace_private_stage(stage)
    assert stage.state == "committed"
    assert (root / "result").read_bytes() == b"new"


def test_replace_failure_preserves_prior_destination(private_root, monkeypatch):
    root, root_fd = private_root
    destination = _private_file(root / "result", b"old")
    real_rename = os.rename

    def fail_publication(source, destination, *args, **kwargs):
        if destination == "result":
            raise OSError("rename failed")
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(privfs.os, "rename", fail_publication)

    with pytest.raises(OSError, match="rename failed"):
        privfs.durable_replace_private(root_fd, ("result",), b"new")
    assert destination.read_bytes() == b"old"
    assert _stages(root) == []


def test_directory_fsync_failure_is_an_uncertain_landed_replace(private_root, monkeypatch):
    root, root_fd = private_root
    _private_file(root / "result", b"old")
    real_fsync = privfs.os.fsync

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory fsync failed")
        return real_fsync(fd)

    monkeypatch.setattr(privfs.os, "fsync", fail_directory)
    with pytest.raises(privfs.PrivateReplaceUncertain) as error:
        privfs.durable_replace_private(root_fd, ("result",), b"new")
    assert isinstance(error.value.__cause__, OSError)
    assert (root / "result").read_bytes() == b"new"
    assert _stages(root) == []


def test_abort_quarantines_a_source_substitution_instead_of_deleting_it(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"trusted")
    privfs.seal_private_stage(stage)
    original_name = stage.temporary_name
    real_rename = os.rename
    swapped = False

    def substitute_then_rename(source, destination, *args, **kwargs):
        nonlocal swapped
        if source == original_name and not swapped:
            swapped = True
            real_rename(source, "held-original", *args, **kwargs)
            planted = os.open(
                source,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=stage.parent_fd,
            )
            os.write(planted, b"substitute")
            os.close(planted)
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(privfs.os, "rename", substitute_then_rename)
    with pytest.raises(privfs.PrivatePathUnsafe, match="cleanup refused"):
        stage.abort()

    assert (root / "held-original").read_bytes() == b"trusted"
    quarantined = list(root.glob(".quarry-discard-*.stage"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == b"substitute"


def test_destination_is_reconciled_again_after_directory_fsync(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"trusted")
    real_fsync = os.fsync
    swapped = False

    def sync_then_substitute(fd):
        nonlocal swapped
        result = real_fsync(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not swapped:
            swapped = True
            (root / "result").rename(root / "held-result")
            _private_file(root / "result", b"substitute")
        return result

    monkeypatch.setattr(privfs.os, "fsync", sync_then_substitute)
    with pytest.raises(privfs.PrivateReplaceUncertain, match="did not settle"):
        privfs.replace_private_stage(stage)
    assert stage.state == "replaced_uncertain"
    assert (root / "held-result").read_bytes() == b"trusted"
    assert (root / "result").read_bytes() == b"substitute"


def test_same_length_mutation_through_a_duplicate_writer_is_not_committed(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"trusted")
    duplicate = os.dup(stage.file_fd)
    real_rename = os.rename

    def rename_then_mutate(source, destination, *args, **kwargs):
        result = real_rename(source, destination, *args, **kwargs)
        if destination == "result":
            os.pwrite(duplicate, b"hostile", 0)
            os.fsync(duplicate)
        return result

    monkeypatch.setattr(privfs.os, "rename", rename_then_mutate)
    try:
        with pytest.raises(privfs.PrivateReplaceUncertain, match="did not settle"):
            privfs.replace_private_stage(stage)
    finally:
        os.close(duplicate)
    assert stage.state == "replaced_uncertain"
    assert (root / "result").read_bytes() == b"hostile"


def test_directory_fsync_cancellation_closes_every_stage_descriptor(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"trusted")
    owned = (stage.anchor_fd, stage.parent_fd)
    real_fsync = os.fsync

    def interrupt_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise KeyboardInterrupt()
        return real_fsync(fd)

    monkeypatch.setattr(privfs.os, "fsync", interrupt_directory)
    with pytest.raises(privfs.PrivateReplaceUncertain) as error:
        privfs.replace_private_stage(stage)
    assert isinstance(error.value.__cause__, KeyboardInterrupt)
    assert stage.state == "replaced_uncertain"
    assert (stage.anchor_fd, stage.parent_fd, stage.file_fd) == (-1, -1, -1)
    for fd in owned:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_cancellation_after_first_landed_reconciliation_is_fenced(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"trusted")
    owned = (stage.anchor_fd, stage.parent_fd)
    real_matches = privfs._destination_matches_stage
    calls = 0

    def reconcile_then_interrupt(candidate):
        nonlocal calls
        result = real_matches(candidate)
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt()
        return result

    monkeypatch.setattr(privfs, "_destination_matches_stage", reconcile_then_interrupt)
    with pytest.raises(privfs.PrivateReplaceUncertain) as error:
        privfs.replace_private_stage(stage)
    assert isinstance(error.value.__cause__, KeyboardInterrupt)
    assert stage.state == "replaced_uncertain"
    assert (stage.anchor_fd, stage.parent_fd, stage.file_fd) == (-1, -1, -1)
    assert (root / "result").read_bytes() == b"trusted"
    for fd in owned:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_cancellation_after_directory_fsync_returns_is_fenced(private_root, monkeypatch):
    root, root_fd = private_root
    stage = privfs.stage_private_bytes(root_fd, ("result",), b"trusted")
    owned = (stage.anchor_fd, stage.parent_fd)
    real_sync = privfs._fsync_managed

    def sync_then_interrupt(fd):
        real_sync(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise KeyboardInterrupt()

    monkeypatch.setattr(privfs, "_fsync_managed", sync_then_interrupt)
    with pytest.raises(privfs.PrivateReplaceUncertain) as error:
        privfs.replace_private_stage(stage)
    assert isinstance(error.value.__cause__, KeyboardInterrupt)
    assert stage.state == "replaced_uncertain"
    assert (stage.anchor_fd, stage.parent_fd, stage.file_fd) == (-1, -1, -1)
    assert (root / "result").read_bytes() == b"trusted"
    for fd in owned:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_stage_write_failure_cleans_up_without_publication(private_root, monkeypatch):
    root, root_fd = private_root
    monkeypatch.setattr(
        privfs.os, "write", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("write failed")),
    )
    with pytest.raises(OSError, match="write failed"):
        privfs.stage_private_bytes(root_fd, ("result",), b"new")
    assert not (root / "result").exists()
    assert _stages(root) == []
    assert len(_discarded(root)) == 1


def test_strict_file_open_closes_result_when_parent_close_reports_failure(private_root, monkeypatch):
    root, root_fd = private_root
    _private_file(root / "evidence")
    real_open = os.open
    real_close = os.close
    result_fd = -1
    failed = False

    def record_open(path, flags, *args, **kwargs):
        nonlocal result_fd
        fd = real_open(path, flags, *args, **kwargs)
        if path == "evidence":
            result_fd = fd
        return fd

    def close_parent_then_report(fd):
        nonlocal failed
        real_close(fd)
        if result_fd >= 0 and fd != result_fd and not failed:
            failed = True
            raise OSError("parent close reported failure")

    monkeypatch.setattr(privfs.os, "open", record_open)
    monkeypatch.setattr(privfs.os, "close", close_parent_then_report)
    with pytest.raises(OSError, match="parent close reported failure"):
        privfs.open_strict_file_at(root_fd, ("evidence",))
    with pytest.raises(OSError):
        os.fstat(result_fd)


def test_repair_close_fault_preserves_the_committed_receipt(private_root, monkeypatch):
    root, root_fd = private_root
    evidence = _private_file(root / "legacy")
    os.chmod(evidence, 0o644)
    real_fchmod = os.fchmod
    real_close = os.close
    changed = False
    failed = False

    def record_change(fd, mode):
        nonlocal changed
        real_fchmod(fd, mode)
        changed = True

    def close_then_report(fd):
        nonlocal failed
        real_close(fd)
        if changed and not failed:
            failed = True
            raise OSError("repair close reported failure")

    monkeypatch.setattr(privfs.os, "fchmod", record_change)
    monkeypatch.setattr(privfs.os, "close", close_then_report)
    with pytest.raises(privfs.LegacyRepairCommittedWithFault) as error:
        privfs.repair_legacy_mode_at(root_fd, ("legacy",), is_dir=False)
    assert error.value.receipt.inode == evidence.stat().st_ino
    assert (error.value.receipt.before_mode, error.value.receipt.after_mode) == (0o644, 0o600)


def test_invalid_payload_is_rejected_before_filesystem_access(private_root, monkeypatch):
    _, root_fd = private_root
    touched = []
    real_dup = os.dup
    monkeypatch.setattr(privfs.os, "dup", lambda fd: touched.append(fd) or real_dup(fd))

    with pytest.raises(privfs.PrivatePathUnsafe):
        privfs.durable_replace_private(root_fd, ("result",), bytearray(b"not exact"))
    assert touched == []
