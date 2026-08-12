"""Focused hermetic tests for the preparatory cooperative containment backend.

Temporary directories below model control-file I/O and descriptor ownership only.
They are never exposed through production discovery and therefore never claim to be
a cgroup filesystem.  Kernel availability remains the real, read-only host probe.
"""
from __future__ import annotations

import errno
import os
import stat
import time
from pathlib import Path

import pytest

from quarry_recon import runner_containment as containment
from quarry_recon.runner_protocol import ContainmentKind

pytestmark = pytest.mark.offline

REQUEST_ID = "0123456789abcdef0123456789abcdef"


def _write_control(directory: Path, name: str, content: str = "") -> None:
    path = directory / name
    path.write_text(content)
    path.chmod(0o600)


def _populate_leaf(directory: Path) -> None:
    _write_control(directory, "cgroup.type", "domain\n")
    _write_control(directory, "cgroup.events", "populated 0\nfrozen 0\n")
    _write_control(directory, "cgroup.procs")
    _write_control(directory, "cgroup.kill")


def _fake_cgroup_rmdir(name: str, parent_fd: int) -> None:
    """Model cgroupfs rmdir, whose virtual control files do not block removal."""
    child_fd = os.open(name, containment._DIR_FLAGS, dir_fd=parent_fd)
    try:
        for entry in os.listdir(child_fd):
            info = os.stat(entry, dir_fd=child_fd, follow_symlinks=False)
            if stat.S_ISREG(info.st_mode):
                os.unlink(entry, dir_fd=child_fd)
    finally:
        os.close(child_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _acquire_fixture(monkeypatch, tmp_path: Path):
    delegated = tmp_path / "delegated"
    delegated.mkdir(parents=True)
    parent_fd = os.open(delegated, containment._DIR_FLAGS)

    def create_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        _populate_leaf(delegated / name)

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", create_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    discovered = containment._DiscoveredParent(parent_fd, "/delegated")
    try:
        handle = containment._acquire_from_parent(REQUEST_ID, discovered)
    finally:
        discovered.close()
    return handle, delegated / f"quarry-{REQUEST_ID}"


def _proc_stat(pid: int, start_time: int) -> str:
    # Fields after comm begin at field 3 (state); starttime is field 22 / index 19.
    tail = ["S"] + ["0"] * 18 + [str(start_time)] + ["0"] * 4
    return f"{pid} (fixture command) " + " ".join(tail) + "\n"


def _install_fake_proc(monkeypatch, tmp_path: Path, *, pid: int,
                       start_time: int, membership: str) -> Path:
    proc = tmp_path / "proc"
    process = proc / str(pid)
    (process / "task" / str(pid)).mkdir(parents=True)
    _write_control(process, "stat", _proc_stat(pid, start_time))
    _write_control(process, "cgroup", f"0::{membership}\n")
    monkeypatch.setattr(containment, "_PROC_ROOT", str(proc))
    return process


def test_real_read_only_host_probe_never_claims_acquired_authority():
    probe = containment.probe_direct_cgroup_v2()
    assert probe.kind is ContainmentKind.CGROUP_V2
    assert probe.cooperative_only is True
    assert probe.cooperative_settlement_capable is False
    assert probe.tree_proof_capable is False
    # This disposable workspace mounts cgroup2 read-only. Keep the assertion
    # portable for a developer who intentionally runs the suite in a delegation.
    mounts = containment._cgroup2_mounts(
        containment._read_bounded_path(containment._MOUNTINFO))
    if mounts and not any(mount.writable for mount in mounts):
        assert probe.candidate is False
        assert probe.reason is containment.ContainmentReason.CGROUP_V2_MOUNT_READ_ONLY


def test_probe_is_candidate_only_and_never_creates_a_leaf(monkeypatch, tmp_path):
    mount = tmp_path / "cgroup"
    current = mount / "delegated"
    current.mkdir(parents=True)
    _write_control(current, "cgroup.procs", f"0\n{os.getpid()}\n")
    _write_control(current, "cgroup.threads")
    _write_control(current, "cgroup.subtree_control")
    membership = tmp_path / "self.cgroup"
    membership.write_text("0::/delegated\n")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"1 0 0:1 / {mount} rw - cgroup2 cgroup2 rw\n")
    monkeypatch.setattr(containment, "_SELF_CGROUP", str(membership))
    monkeypatch.setattr(containment, "_MOUNTINFO", str(mountinfo))
    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf",
                        lambda *_args: pytest.fail("a probe performed acquisition"))

    probe = containment.probe_direct_cgroup_v2()

    assert probe == containment.ContainmentProbe(
        True, containment.ContainmentReason.CANDIDATE)
    assert {path.name for path in current.iterdir()} == {
        "cgroup.procs", "cgroup.threads", "cgroup.subtree_control",
    }


def test_probe_refuses_a_symlinked_current_cgroup_component(monkeypatch, tmp_path):
    mount = tmp_path / "cgroup"
    outside = tmp_path / "outside"
    mount.mkdir()
    outside.mkdir()
    (mount / "delegated").symlink_to(outside, target_is_directory=True)
    membership = tmp_path / "self.cgroup"
    membership.write_text("0::/delegated\n")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(f"1 0 0:1 / {mount} rw - cgroup2 cgroup2 rw\n")
    monkeypatch.setattr(containment, "_SELF_CGROUP", str(membership))
    monkeypatch.setattr(containment, "_MOUNTINFO", str(mountinfo))
    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)

    probe = containment.probe_direct_cgroup_v2()

    assert probe.candidate is False
    assert probe.reason is containment.ContainmentReason.CURRENT_CGROUP_UNSAFE


def test_mountinfo_decodes_escaped_fields_and_maps_mount_root():
    mounts = containment._cgroup2_mounts(
        "31 22 0:27 /delegated\\040root /sys/fs/cgroup\\040view "
        "rw,nosuid - cgroup2 cgroup2 rw\n")

    assert mounts == (containment._Mount(
        "/delegated root", "/sys/fs/cgroup view", True),)
    assert containment._relative_candidates(
        "/delegated root", "/delegated root/jobs/run-1")[0] == ("jobs", "run-1")


@pytest.mark.parametrize("text, expected", [
    ("0::/\n", "/"),
    ("7:cpu:/old\n0::/user.slice/job.scope\n", "/user.slice/job.scope"),
])
def test_unified_membership_accepts_exactly_one_v2_record(text, expected):
    assert containment._unified_membership(text) == expected


@pytest.mark.parametrize("text", [
    "", "1:name:/legacy\n", "0::/one\n0::/two\n", "0:/bad:/path\n",
])
def test_unified_membership_rejects_missing_or_duplicate_records(text):
    with pytest.raises(containment.ContainmentUnsupported) as caught:
        containment._unified_membership(text)
    assert caught.value.reason is containment.ContainmentReason.CURRENT_CGROUP_MISSING


def test_pid_readback_ignores_zero_self_marker_but_expected_pid_stays_positive():
    assert containment._parse_pid_lines(b"0\n123\n") == frozenset({123})
    with pytest.raises(containment.ContainmentFailure) as negative:
        containment._parse_pid_lines(b"-1\n")
    assert negative.value.reason is containment.ContainmentReason.PROCESS_CGROUP_MALFORMED
    with pytest.raises(containment.ContainmentFailure) as oversized:
        containment._parse_pid_lines(f"{1 << 31}\n".encode())
    assert oversized.value.reason is containment.ContainmentReason.PROCESS_CGROUP_MALFORMED
    with pytest.raises(containment.ContainmentRefused) as expected:
        containment.ProcessIdentity(0, 1)
    assert expected.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_INVALID


@pytest.mark.parametrize("request_id", ["", "A" * 32, "0" * 31, "0" * 31 + "/"])
def test_invalid_request_id_refuses_before_discovery(monkeypatch, request_id):
    monkeypatch.setattr(containment, "_discover_parent",
                        lambda: pytest.fail("invalid input reached filesystem discovery"))
    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.acquire_direct_cgroup_v2(request_id)
    assert caught.value.reason is containment.ContainmentReason.REQUEST_ID_INVALID


def test_acquisition_proves_leaf_controls_and_scopes_assurance(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    try:
        assert leaf.is_dir()
        assert handle.kind is ContainmentKind.CGROUP_V2
        assert handle.assurance is containment.ContainmentAssurance.COOPERATIVE_TREE
        assert handle.cooperative_settlement_capable is True
        assert handle.tree_proof_capable is False
        assert handle.escape_protected is False
        assert handle.membership == f"/delegated/quarry-{REQUEST_ID}"
        assert handle.containment_id == f"direct/quarry-{REQUEST_ID}"
    finally:
        handle.close()


def test_collision_is_a_typed_refusal_and_preserves_existing_leaf(monkeypatch, tmp_path):
    delegated = tmp_path / "delegated"
    leaf = delegated / f"quarry-{REQUEST_ID}"
    leaf.mkdir(parents=True)
    marker = leaf / "prior"
    marker.write_text("owned elsewhere")
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated")
    try:
        with pytest.raises(containment.ContainmentRefused) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
    finally:
        discovered.close()
    assert caught.value.reason is containment.ContainmentReason.LEAF_COLLISION
    assert marker.read_text() == "owned elsewhere"


def test_missing_leaf_control_rolls_back_created_attempt(monkeypatch, tmp_path):
    delegated = tmp_path / "delegated"
    delegated.mkdir()

    def incomplete_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, dir_fd=dir_fd)
        child = delegated / name
        _write_control(child, "cgroup.type", "domain\n")

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", incomplete_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated")
    try:
        with pytest.raises(containment.ContainmentError) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
    finally:
        discovered.close()
    assert caught.value.reason is containment.ContainmentReason.LEAF_CONTROL_UNUSABLE
    assert not (delegated / f"quarry-{REQUEST_ID}").exists()


def test_symlinked_leaf_control_is_never_followed(monkeypatch, tmp_path):
    delegated = tmp_path / "delegated"
    outside = tmp_path / "outside"
    delegated.mkdir()
    outside.write_text("do not touch")

    def planted_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, dir_fd=dir_fd)
        child = delegated / name
        _write_control(child, "cgroup.type", "domain\n")
        _write_control(child, "cgroup.events", "populated 0\n")
        (child / "cgroup.procs").symlink_to(outside)

    def remove_planted(name: str, parent_fd: int) -> None:
        child_fd = os.open(name, containment._DIR_FLAGS, dir_fd=parent_fd)
        try:
            for entry in os.listdir(child_fd):
                os.unlink(entry, dir_fd=child_fd)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=parent_fd)

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", planted_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", remove_planted)
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated")
    try:
        with pytest.raises(containment.ContainmentError) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
    finally:
        discovered.close()
    assert caught.value.reason is containment.ContainmentReason.LEAF_CONTROL_UNUSABLE
    assert outside.read_text() == "do not touch"


@pytest.mark.parametrize("cgroup_type", ["threaded\n", "domain threaded\n", "domain (invalid)\n"])
def test_acquisition_refuses_non_domain_leaf_type(monkeypatch, tmp_path, cgroup_type):
    delegated = tmp_path / "delegated"
    delegated.mkdir()

    def invalid_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, dir_fd=dir_fd)
        child = delegated / name
        _populate_leaf(child)
        (child / "cgroup.type").write_text(cgroup_type)

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", invalid_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated")
    try:
        with pytest.raises(containment.ContainmentUnsupported) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
    finally:
        discovered.close()
    assert caught.value.reason is containment.ContainmentReason.LEAF_DOMAIN_UNUSABLE


def test_absent_cgroup_kill_is_typed_unsupported_and_rolls_back(monkeypatch, tmp_path):
    delegated = tmp_path / "delegated"
    delegated.mkdir()

    def old_kernel_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, dir_fd=dir_fd)
        child = delegated / name
        _populate_leaf(child)
        (child / "cgroup.kill").unlink()

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", old_kernel_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated")
    try:
        with pytest.raises(containment.ContainmentUnsupported) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
    finally:
        discovered.close()
    assert caught.value.reason is containment.ContainmentReason.CGROUP_KILL_UNAVAILABLE
    assert caught.value.os_errno == errno.ENOENT
    assert not (delegated / f"quarry-{REQUEST_ID}").exists()


def test_baseexception_during_acquisition_closes_controls_and_rolls_back(
        monkeypatch, tmp_path):
    delegated = tmp_path / "delegated"
    delegated.mkdir()
    opened: list[int] = []
    real_open_control = containment._open_control

    def create_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, dir_fd=dir_fd)
        _populate_leaf(delegated / name)

    def tracking_open(dir_fd: int, name: str, flags: int, **kwargs) -> int:
        fd = real_open_control(dir_fd, name, flags, **kwargs)
        if name in ("cgroup.procs", "cgroup.events"):
            opened.append(fd)
        return fd

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", create_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(containment, "_open_control", tracking_open)
    monkeypatch.setattr(containment, "_open_leaf_kill",
                        lambda _fd: (_ for _ in ()).throw(KeyboardInterrupt()))
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated")
    try:
        with pytest.raises(KeyboardInterrupt):
            containment._acquire_from_parent(REQUEST_ID, discovered)
    finally:
        discovered.close()
    for fd in opened:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    assert not (delegated / f"quarry-{REQUEST_ID}").exists()


def test_parent_binds_one_parked_identity_and_verifies_membership(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, started = 4141, 88111
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated")
    (process / "stat").write_text(_proc_stat(pid, started).replace(") S ", ") T "))
    real_write = containment.os.write

    def model_migration(fd: int, payload: bytes) -> int:
        written = real_write(fd, payload)
        if fd == handle._procs_write_fd:
            (leaf / "cgroup.procs").write_bytes(payload)
            (process / "cgroup").write_text(f"0::{handle.membership}\n")
        return written

    monkeypatch.setattr(containment.os, "write", model_migration)
    try:
        result = handle.bind_pid(containment.ProcessIdentity(pid, started))
        assert result.verified is True
        assert result.reason is containment.ContainmentReason.VERIFIED
        assert (leaf / "cgroup.procs").read_text() == f"{pid}\n"
        with pytest.raises(containment.ContainmentRefused) as caught:
            handle.bind_pid(containment.ProcessIdentity(pid, started))
        assert caught.value.reason is containment.ContainmentReason.BINDING_ALREADY_USED
    finally:
        handle.close()


def test_parent_refuses_to_bind_an_unparked_child(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, started = 4142, 88112
    _install_fake_proc(monkeypatch, tmp_path, pid=pid, start_time=started,
                       membership=handle.membership)
    try:
        result = handle.bind_pid(containment.ProcessIdentity(pid, started))
        assert result.verified is False
        assert result.reason is containment.ContainmentReason.PROCESS_NOT_PARKED
        assert not (leaf / "cgroup.procs").read_bytes()
    finally:
        handle.close()


def test_pid_verification_binds_start_time_proc_path_and_leaf_membership(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, started = 4242, 99123
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership=handle.membership)
    (leaf / "cgroup.procs").write_text(f"{pid}\n")
    try:
        identity = containment.ProcessIdentity(pid, started)
        assert handle.verify_pid(identity) == containment.MembershipVerification(
            True, containment.ContainmentReason.VERIFIED)

        _write_control(process, "stat", _proc_stat(pid, started + 1))
        changed = handle.verify_pid(identity)
        assert changed.verified is False
        assert changed.reason is containment.ContainmentReason.PROCESS_IDENTITY_CHANGED
    finally:
        handle.close()


def test_pid_verification_refuses_matching_pid_outside_leaf(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, started = 4243, 99124
    _install_fake_proc(monkeypatch, tmp_path, pid=pid, start_time=started,
                       membership="/delegated/sibling")
    (leaf / "cgroup.procs").write_text(f"{pid}\n")
    try:
        result = handle.verify_pid(containment.ProcessIdentity(pid, started))
        assert result.verified is False
        assert result.reason is containment.ContainmentReason.PROCESS_CGROUP_MISMATCH
    finally:
        handle.close()


def test_parent_bind_refuses_pid_reuse_before_writing(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, started = 4244, 99125
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started + 1,
        membership=handle.membership)
    (process / "stat").write_text(
        _proc_stat(pid, started + 1).replace(") S ", ") T "))
    try:
        result = handle.bind_pid(containment.ProcessIdentity(pid, started))
        assert result.verified is False
        assert result.reason is containment.ContainmentReason.PROCESS_IDENTITY_CHANGED
        assert not (leaf / "cgroup.procs").read_bytes()
    finally:
        handle.close()


def test_recursive_empty_kill_and_remove_settles_cooperative_tree(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    child = leaf / "child"
    grandchild = child / "grandchild"
    grandchild.mkdir(parents=True)
    _write_control(child, "cgroup.events", "populated 0\n")
    _write_control(grandchild, "cgroup.events", "populated 0\n")

    result = handle.kill_settle_remove(time.monotonic() + 2)

    assert result.cooperative_settled is True
    assert result.tree_settled is False
    assert result.escape_protected is False
    assert result.reason is containment.ContainmentReason.SETTLED
    assert not leaf.exists()


def test_descendants_are_removed_deepest_first(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "child" / "grandchild").mkdir(parents=True)
    removals: list[str] = []

    def recording_rmdir(name: str, parent_fd: int) -> None:
        removals.append(name)
        _fake_cgroup_rmdir(name, parent_fd)

    monkeypatch.setattr(containment, "_rmdir_cgroup", recording_rmdir)
    result = handle.kill_settle_remove(time.monotonic() + 1)

    assert result.cooperative_settled is True
    assert result.tree_settled is False
    assert removals == ["grandchild", "child", f"quarry-{REQUEST_ID}"]


def test_settlement_uses_one_deadline_and_never_removes_populated_leaf(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "cgroup.events").write_text("populated 1\n")
    clock = {"now": 10.0}
    monkeypatch.setattr(containment.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(containment.time, "sleep",
                        lambda seconds: clock.__setitem__("now", clock["now"] + seconds))
    try:
        result = handle.kill_settle_remove(10.05)
        assert result.killed is True
        assert result.empty is False
        assert result.removed is False
        assert result.reason is containment.ContainmentReason.DEADLINE_EXPIRED
        assert leaf.is_dir()
        assert (leaf / "cgroup.kill").read_bytes() == b"1\n"
        assert clock["now"] == pytest.approx(10.05)
    finally:
        handle.close()


@pytest.mark.parametrize("deadline", [10**400, -(10**400), float("inf"), float("nan"), True])
def test_invalid_huge_or_nonfinite_deadline_is_typed(monkeypatch, tmp_path, deadline):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    try:
        with pytest.raises(containment.ContainmentRefused) as caught:
            handle.kill_settle_remove(deadline)
        assert caught.value.reason is containment.ContainmentReason.DEADLINE_INVALID
        assert not (leaf / "cgroup.kill").read_bytes()
    finally:
        handle.close()


def test_descendant_depth_limit_is_typed_without_python_recursion(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    current = leaf
    monkeypatch.setattr(containment, "_MAX_DESCENDANT_DEPTH", 3)
    for index in range(4):
        current = current / f"child-{index}"
        current.mkdir()
    try:
        result = handle.kill_settle_remove(time.monotonic() + 1)
        assert result.reason is containment.ContainmentReason.DESCENDANT_LIMIT
        assert result.cooperative_settled is False
        assert leaf.is_dir()
    finally:
        handle.close()


def test_descendant_cardinality_limit_is_typed_and_bounded(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    monkeypatch.setattr(containment, "_MAX_DESCENDANT_CGROUPS", 2)
    for index in range(3):
        (leaf / f"child-{index}").mkdir()
    try:
        result = handle.kill_settle_remove(time.monotonic() + 1)
        assert result.reason is containment.ContainmentReason.DESCENDANT_LIMIT
        assert result.cooperative_settled is False
        assert leaf.is_dir()
    finally:
        handle.close()


def test_descendant_close_failure_is_typed_and_does_not_escape(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    child = leaf / "child"
    child.mkdir()
    child_inode = child.stat().st_ino
    real_close = containment.os.close
    failed = {"once": False}

    def close_with_one_fault(fd: int) -> None:
        try:
            is_child = os.fstat(fd).st_ino == child_inode
        except OSError:
            is_child = False
        if is_child and not failed["once"]:
            failed["once"] = True
            raise OSError(errno.EIO, "fixture")
        real_close(fd)

    monkeypatch.setattr(containment.os, "close", close_with_one_fault)
    try:
        result = handle.kill_settle_remove(time.monotonic() + 1)
        assert result.reason is containment.ContainmentReason.REMOVE_FAILED
        assert result.os_errno == errno.EIO
        assert result.cooperative_settled is False
        assert leaf.is_dir()
    finally:
        handle.close()


@pytest.mark.parametrize("seam, fail_call", [
    ("scandir", 1), ("scandir", 2), ("append", 1), ("append", 2),
])
def test_cancellation_at_root_or_child_ownership_transfer_leaks_no_fd(
        monkeypatch, tmp_path, seam, fail_call):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "child").mkdir()
    captured: list[int] = []
    calls = {"count": 0}
    if seam == "scandir":
        real_scandir = containment.os.scandir

        def interrupt_scandir(fd: int):
            calls["count"] += 1
            if calls["count"] == fail_call:
                captured.append(fd)
                raise KeyboardInterrupt()
            return real_scandir(fd)

        monkeypatch.setattr(containment.os, "scandir", interrupt_scandir)
    else:
        real_append = containment._append_walk_frame

        def interrupt_append(stack, frame):
            calls["count"] += 1
            if calls["count"] == fail_call:
                captured.append(frame.fd)
                raise KeyboardInterrupt()
            return real_append(stack, frame)

        monkeypatch.setattr(containment, "_append_walk_frame", interrupt_append)
    try:
        with pytest.raises(KeyboardInterrupt):
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert len(captured) == 1
        with pytest.raises(OSError) as caught:
            os.fstat(captured[0])
        assert caught.value.errno == errno.EBADF
    finally:
        handle.close()


def test_symlinked_descendant_refuses_removal(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "planted").symlink_to(tmp_path, target_is_directory=True)
    try:
        result = handle.kill_settle_remove(time.monotonic() + 1)
        assert result.tree_settled is False
        assert result.reason is containment.ContainmentReason.DESCENDANT_UNSAFE
        assert leaf.is_dir()
    finally:
        handle.close()


def test_leaf_name_swap_is_detected_before_kill(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    original = leaf.with_name("original-leaf")
    leaf.rename(original)
    leaf.mkdir()
    try:
        result = handle.kill_settle_remove(time.monotonic() + 1)
        assert result == containment.ContainmentSettlement(
            False, False, False, containment.ContainmentReason.LEAF_IDENTITY_CHANGED)
        assert not (original / "cgroup.kill").read_bytes()
    finally:
        handle.close()


def test_unsupported_kill_write_is_typed_and_preserves_leaf(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    real_write = containment.os.write

    def unsupported(fd: int, data: bytes) -> int:
        if fd == handle._kill_fd:
            raise OSError(errno.EOPNOTSUPP, "fixture")
        return real_write(fd, data)

    monkeypatch.setattr(containment.os, "write", unsupported)
    try:
        result = handle.kill_settle_remove(time.monotonic() + 1)
        assert result.reason is containment.ContainmentReason.KILL_FAILED
        assert result.os_errno == errno.EOPNOTSUPP
        assert result.tree_settled is False
        assert leaf.is_dir()
    finally:
        handle.close()


def test_close_attempts_every_descriptor_when_one_close_fails(monkeypatch, tmp_path):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [handle._kill_fd, handle._events_fd, handle._procs_write_fd,
             handle._procs_read_fd, handle._leaf_fd, handle._parent_fd]
    failed = owned[0]
    real_close = containment.os.close
    attempted: list[int] = []

    def faulty_close(fd: int) -> None:
        attempted.append(fd)
        if fd == failed:
            raise OSError(errno.EIO, "fixture")
        real_close(fd)

    monkeypatch.setattr(containment.os, "close", faulty_close)
    handle.close()

    assert attempted == owned
    assert all(getattr(handle, name) == -1 for name in (
        "_kill_fd", "_events_fd", "_procs_write_fd", "_procs_read_fd",
        "_leaf_fd", "_parent_fd"))
    real_close(failed)


def test_pgid_fallback_can_never_claim_tree_proof():
    fallback = containment.PgidFallback(1234)
    assert fallback.kind is ContainmentKind.PGID
    assert fallback.assurance is containment.ContainmentAssurance.PROCESS_GROUP
    assert fallback.tree_proof_capable is False
    assert fallback.escape_protected is False


def test_fixed_errors_do_not_disclose_rejected_values():
    secret = "not-a-valid-id-API_TOKEN_very-secret"
    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.acquire_direct_cgroup_v2(secret)
    rendered = str(caught.value)
    assert secret not in rendered
    assert rendered == "ContainmentRefused:request_id_invalid"


def test_fake_rmdir_reports_nonempty_as_os_error(tmp_path):
    """Guard the fixture boundary: it never silently deletes child cgroups."""
    parent = tmp_path / "parent"
    child = parent / "child"
    nested = child / "nested"
    nested.mkdir(parents=True)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    try:
        with pytest.raises(OSError) as caught:
            _fake_cgroup_rmdir("child", parent_fd)
        assert caught.value.errno in (errno.ENOTEMPTY, errno.EEXIST)
    finally:
        os.close(parent_fd)
