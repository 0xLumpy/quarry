"""Focused hermetic tests for the preparatory cooperative containment backend.

Temporary directories below model control-file I/O and descriptor ownership only.
They are never exposed through production discovery and therefore never claim to be
a cgroup filesystem.  Kernel availability remains the real, read-only host probe.
"""
from __future__ import annotations

import errno
import inspect
import os
import shutil
import stat
import sys
import time
from pathlib import Path

import pytest

from quarry_recon import runner_containment as containment
from quarry_recon.runner_protocol import ContainmentAssurance, ContainmentKind

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


def _proc_stat(
    pid: int,
    start_time: int,
    *,
    state: str = "S",
    parent_pid: int = 0,
    process_group: int = 0,
    session: int = 0,
) -> str:
    # Fields after comm begin at field 3 (state); starttime is field 22 / index 19.
    tail = [
        state,
        str(parent_pid),
        str(process_group),
        str(session),
        *(["0"] * 15),
        str(start_time),
        *(["0"] * 4),
    ]
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


def _descriptor_is_closed(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError as exc:
        return exc.errno == errno.EBADF
    return False


def _close_if_open(close, fd: int) -> None:
    try:
        close(fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise


def _source_line(function, text: str, *, occurrence: int = 1) -> int:
    """Return one exact executable source line without pinning file offsets."""
    source, first = inspect.getsourcelines(function)
    matches = [
        first + offset for offset, line in enumerate(source)
        if text in line
    ]
    return matches[occurrence - 1]


def _install_hermetic_discovery(monkeypatch, tmp_path: Path):
    """Install one writable, current fake hierarchy for ownership tests."""
    mount = tmp_path / "mount"
    parent = tmp_path / "parent"
    mount.mkdir()
    parent.mkdir()
    opened = {"mount": -1, "parent": -1}
    checked = {"value": False}

    def open_mount(_path: str) -> int:
        opened["mount"] = os.open(mount, containment._DIR_FLAGS)
        return opened["mount"]

    def open_parent(_mount_fd: int, _components: tuple[str, ...]) -> int:
        opened["parent"] = os.open(parent, containment._DIR_FLAGS)
        return opened["parent"]

    def check_parent(_fd: int) -> None:
        checked["value"] = True

    monkeypatch.setattr(containment, "_require_features", lambda: None)
    monkeypatch.setattr(
        containment, "_read_bounded_path",
        lambda path: ("0::/delegated\n" if path == containment._SELF_CGROUP
                      else "fixture mountinfo\n"),
    )
    monkeypatch.setattr(containment, "_unified_membership",
                        lambda _text: "/delegated")
    monkeypatch.setattr(
        containment, "_cgroup2_mounts",
        lambda _text: (containment._Mount("/", str(mount), True),),
    )
    monkeypatch.setattr(containment, "_relative_candidates",
                        lambda _root, _membership: ((),))
    monkeypatch.setattr(containment, "_open_absolute_dir", open_mount)
    monkeypatch.setattr(containment, "_walk_dir", open_parent)
    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(
        containment, "_read_control",
        lambda _fd, _name, **_kwargs: f"{os.getpid()}\n".encode(),
    )
    monkeypatch.setattr(containment, "_check_parent_candidate", check_parent)
    return opened, checked


def test_open_absolute_dir_component_transfer_cancellation_closes_both_fds(
        monkeypatch, tmp_path):
    target = tmp_path / "component"
    target.mkdir()
    cancellation = KeyboardInterrupt("cancel component descriptor transfer")
    real_open = containment.os.open
    real_close = containment.os.close
    opened: list[int] = []
    fired = False
    previous_trace = sys.gettrace()

    def recording_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if ((path == "/" and kwargs.get("dir_fd") is None)
                or kwargs.get("dir_fd") in opened):
            opened.append(fd)
        return fd

    def interrupt_after_component_open(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is containment._open_absolute_dir.__code__):
            current = frame.f_locals.get("current")
            following = frame.f_locals.get("following")
            if (type(current) is containment._DescriptorCloseClaim
                    and type(following) is containment._DescriptorCloseClaim
                    and current.fd >= 0 and following.fd >= 0
                    and current.fd != following.fd):
                fired = True
                raise cancellation
        return interrupt_after_component_open

    monkeypatch.setattr(containment.os, "open", recording_open)
    try:
        sys.settrace(interrupt_after_component_open)
        with pytest.raises(KeyboardInterrupt) as caught:
            containment._open_absolute_dir(str(target))
        assert caught.value is cancellation
        assert fired is True
        assert len(opened) == 2
        assert [_descriptor_is_closed(fd) for fd in opened] == [True, True]
    finally:
        sys.settrace(previous_trace)
        for fd in opened:
            _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("operation", ["absolute", "walk"])
def test_directory_open_owner_entry_cancellation_closes_initial_fd(
        monkeypatch, tmp_path, cancellation_type, operation):
    parent = tmp_path / "parent"
    parent.mkdir()
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    cancellation = cancellation_type(f"cancel {operation} initial directory ownership")
    real_open = containment.os.open
    real_dup = containment.os.dup
    real_close = containment.os.close
    opened = -1
    fired = False
    previous_trace = sys.gettrace()
    target = containment._open_absolute_dir if operation == "absolute" else containment._walk_dir

    def recording_open(path, flags, *args, **kwargs):
        nonlocal opened
        fd = real_open(path, flags, *args, **kwargs)
        if operation == "absolute" and path == "/":
            opened = fd
        return fd

    def recording_dup(fd: int) -> int:
        nonlocal opened
        opened = real_dup(fd)
        return opened

    def interrupt_after_initial_allocation(frame, event, _arg):
        nonlocal fired
        claim = frame.f_locals.get("current", frame.f_locals.get("fd"))
        claim_fd = getattr(claim, "fd", claim if type(claim) is int else -1)
        if (not fired and event == "line" and frame.f_code is target.__code__
                and opened >= 0 and claim_fd == opened):
            fired = True
            raise cancellation
        return interrupt_after_initial_allocation

    monkeypatch.setattr(containment.os, "open", recording_open)
    monkeypatch.setattr(containment.os, "dup", recording_dup)
    try:
        sys.settrace(interrupt_after_initial_allocation)
        with pytest.raises(cancellation_type) as caught:
            (target("/") if operation == "absolute" else target(parent_fd, ()))
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, opened)
        _close_if_open(real_close, parent_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("operation", ["absolute", "walk"])
def test_directory_open_ordinary_primary_recovery_entry_drains_all_claims(
        monkeypatch, tmp_path, cancellation_type, operation):
    parent = tmp_path / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    cancellation = cancellation_type(f"cancel {operation} recovery entry")
    ordinary_primary = RuntimeError("fixture directory traversal primary")
    real_open = containment.os.open
    real_dup = containment.os.dup
    real_close = containment.os.close
    opened: list[int] = []
    previous_trace = sys.gettrace()
    fired = False
    target = (containment._open_absolute_dir if operation == "absolute"
              else containment._walk_dir)

    def recording_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if operation == "absolute":
            opened.append(fd)
        return fd

    def recording_dup(fd: int) -> int:
        duplicated = real_dup(fd)
        if operation == "walk":
            opened.append(duplicated)
        return duplicated

    def ordinary_component_fault(path, flags, *args, **kwargs):
        if operation == "walk" and kwargs.get("dir_fd") in opened:
            raise ordinary_primary
        return recording_open(path, flags, *args, **kwargs)

    def interrupt_recovery_entry(frame, event, _arg):
        nonlocal fired
        claims = frame.f_locals.get("claims")
        if (not fired and event == "line" and frame.f_code is target.__code__
                and frame.f_locals.get("boundary") is ordinary_primary
                and isinstance(claims, list) and claims
                and any(claim.fd >= 0 for claim in claims)):
            fired = True
            raise cancellation
        return interrupt_recovery_entry

    if operation == "absolute":
        calls = 0

        def fault_second_open(path, flags, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ordinary_primary
            return recording_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(containment.os, "open", fault_second_open)
    else:
        monkeypatch.setattr(containment.os, "open", ordinary_component_fault)
        monkeypatch.setattr(containment.os, "dup", recording_dup)
    try:
        sys.settrace(interrupt_recovery_entry)
        with pytest.raises(cancellation_type) as caught:
            (target(str(child)) if operation == "absolute"
             else target(parent_fd, ("child",)))
        assert caught.value is cancellation
        assert fired is True
        assert opened and all(_descriptor_is_closed(fd) for fd in opened)
    finally:
        sys.settrace(previous_trace)
        for fd in opened:
            _close_if_open(real_close, fd)
        _close_if_open(real_close, parent_fd)


def test_open_proc_pid_root_close_cancellation_after_child_open_closes_both(
        monkeypatch, tmp_path):
    pid = 4811
    proc = tmp_path / "proc"
    (proc / str(pid)).mkdir(parents=True)
    cancellation = KeyboardInterrupt("cancel proc-root close")
    real_open = containment.os.open
    real_close = containment.os.close
    opened: dict[str, int] = {}
    fired = False
    previous_trace = sys.gettrace()

    def open_proc_root(_path: str) -> int:
        fd = real_open(proc, containment._DIR_FLAGS)
        opened["root"] = fd
        return fd

    def recording_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if kwargs.get("dir_fd") == opened.get("root") and path == str(pid):
            opened["child"] = fd
        return fd

    owner_code = getattr(
        containment, "_open_proc_pid_owner", containment._open_proc_pid,
    ).__code__

    def return_with_both_claims_live(observed_pid, *, root, child):
        containment._populate_allocation_claim(
            root, lambda: open_proc_root(containment._PROC_ROOT),
        )
        containment._populate_allocation_claim(
            child,
            lambda: recording_open(
                str(observed_pid), containment._DIR_FLAGS, dir_fd=root.fd,
            ),
        )
        return child.fd

    def interrupt_before_root_close(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is owner_code
                and "child" in opened
                and not _descriptor_is_closed(opened["root"])
                and not _descriptor_is_closed(opened["child"])):
            fired = True
            raise cancellation
        return interrupt_before_root_close

    monkeypatch.setattr(containment, "_open_absolute_dir", open_proc_root)
    monkeypatch.setattr(containment.os, "open", recording_open)
    monkeypatch.setattr(
        containment, "_open_proc_pid_transaction", return_with_both_claims_live,
    )
    try:
        sys.settrace(interrupt_before_root_close)
        with pytest.raises(KeyboardInterrupt) as caught:
            containment._open_proc_pid(pid)
        assert caught.value is cancellation
        assert fired is True
        assert set(opened) == {"root", "child"}
        assert all(_descriptor_is_closed(fd) for fd in opened.values())
    finally:
        sys.settrace(previous_trace)
        for fd in opened.values():
            _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_open_proc_pid_owner_return_boundary_cancellation_closes_child(
        monkeypatch, tmp_path, cancellation_type):
    pid = 4817
    proc = tmp_path / "proc"
    (proc / str(pid)).mkdir(parents=True)
    cancellation = cancellation_type("cancel proc owner return boundary")
    real_transaction = containment._open_proc_pid_transaction
    real_close = containment.os.close
    child_fd = -1
    fired = False
    previous_trace = sys.gettrace()

    monkeypatch.setattr(containment, "_PROC_ROOT", str(proc))

    def recording_transaction(observed_pid, *, root, child):
        nonlocal child_fd
        child_fd = real_transaction(observed_pid, root=root, child=child)
        return child_fd

    def interrupt_return_boundary(frame, event, _arg):
        nonlocal fired
        root = frame.f_locals.get("root")
        child = frame.f_locals.get("child")
        if (not fired and event == "line"
                and frame.f_code is containment._open_proc_pid_owner.__code__
                and frame.f_locals.get("result") == child_fd and child_fd >= 0
                and type(root) is containment._DescriptorCloseClaim
                and root.fd == -1
                and type(child) is containment._DescriptorCloseClaim
                and child.fd == child_fd and not _descriptor_is_closed(child_fd)):
            fired = True
            raise cancellation
        return interrupt_return_boundary

    monkeypatch.setattr(
        containment, "_open_proc_pid_transaction", recording_transaction,
    )
    try:
        sys.settrace(interrupt_return_boundary)
        with pytest.raises(cancellation_type) as caught:
            containment._open_proc_pid_owner(pid)
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(child_fd)
    finally:
        sys.settrace(previous_trace)
        if child_fd >= 0:
            _close_if_open(real_close, child_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_open_proc_claim_fingerprint_fault_then_close_cancellation_is_reconciled(
        monkeypatch, tmp_path, cancellation_type):
    fd = os.open(tmp_path, containment._DIR_FLAGS)
    real_close = containment.os.close
    cancellation = cancellation_type("cancel proc-claim rollback close")
    close_calls = 0
    real_fingerprint = containment._fd_fingerprint

    fingerprint_calls = 0

    def fingerprint_fault_once(observed_fd: int):
        nonlocal fingerprint_calls
        fingerprint_calls += 1
        if fingerprint_calls == 1:
            raise OSError(errno.EIO, "fixture fingerprint fault")
        return real_fingerprint(observed_fd)

    def interrupt_first_close(observed_fd: int) -> None:
        nonlocal close_calls
        if observed_fd == fd:
            close_calls += 1
            if close_calls == 1:
                raise cancellation
        real_close(observed_fd)

    monkeypatch.setattr(containment, "_open_proc_pid", lambda _pid: fd)
    monkeypatch.setattr(containment, "_fd_fingerprint", fingerprint_fault_once)
    monkeypatch.setattr(containment.os, "close", interrupt_first_close)
    try:
        with pytest.raises(cancellation_type) as caught:
            containment._open_proc_close_claim(4812, "fixture_proc_fd")
        assert caught.value is cancellation
        assert close_calls == 1
        os.fstat(fd)
    finally:
        _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_capture_process_identity_cleanup_entry_cancellation_outranks_primary(
        monkeypatch, tmp_path, cancellation_type):
    pid = 4815
    _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=91_005,
        membership="/fixture",
    )
    cancellation = cancellation_type("cancel capture cleanup entry")
    ordinary_primary = RuntimeError("fixture ordinary proc read fault")
    real_open_claim = containment._open_proc_close_claim
    real_close = containment.os.close
    opened = -1
    fired = False
    previous_trace = sys.gettrace()

    def recording_open_claim(observed_pid: int, attribute: str):
        nonlocal opened
        claim = real_open_claim(observed_pid, attribute)
        opened = claim.fd
        return claim

    def ordinary_read_fault(_fd: int) -> int:
        raise ordinary_primary

    def interrupt_cleanup_entry(frame, event, _arg):
        nonlocal fired
        claim = frame.f_locals.get("claim")
        claims = frame.f_locals.get("claims")
        if (not fired and event == "line"
                and frame.f_code is containment.capture_process_identity.__code__
                and frame.f_locals.get("primary") is ordinary_primary
                and type(claim) is containment._DescriptorCloseClaim
                and claims == (claim,) and claim.fd == opened
                and not _descriptor_is_closed(opened)):
            fired = True
            raise cancellation
        return interrupt_cleanup_entry

    monkeypatch.setattr(containment, "_open_proc_close_claim", recording_open_claim)
    monkeypatch.setattr(containment, "_proc_start_time", ordinary_read_fault)
    try:
        sys.settrace(interrupt_cleanup_entry)
        with pytest.raises(cancellation_type) as caught:
            containment.capture_process_identity(pid)
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
    finally:
        sys.settrace(previous_trace)
        if opened >= 0:
            _close_if_open(real_close, opened)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_open_proc_claim_cleanup_entry_cancellation_outranks_fingerprint_primary(
        monkeypatch, tmp_path, cancellation_type):
    fd = os.open(tmp_path, containment._DIR_FLAGS)
    cancellation = cancellation_type("cancel proc fingerprint cleanup entry")
    ordinary_primary = RuntimeError("fixture ordinary fingerprint fault")
    real_close = containment.os.close
    fired = False
    previous_trace = sys.gettrace()

    def ordinary_fingerprint_fault(observed_fd: int):
        assert observed_fd == fd
        raise ordinary_primary

    def interrupt_cleanup_entry(frame, event, _arg):
        nonlocal fired
        claim = frame.f_locals.get("claim")
        if (not fired and event == "line"
                and frame.f_code is containment._open_proc_close_claim.__code__
                and frame.f_locals.get("primary") is ordinary_primary
                and type(claim) is containment._DescriptorCloseClaim
                and claim.fd == fd and not _descriptor_is_closed(fd)):
            fired = True
            raise cancellation
        return interrupt_cleanup_entry

    monkeypatch.setattr(containment, "_open_proc_pid", lambda _pid: fd)
    monkeypatch.setattr(containment, "_fd_fingerprint", ordinary_fingerprint_fault)
    try:
        sys.settrace(interrupt_cleanup_entry)
        with pytest.raises(cancellation_type) as caught:
            containment._open_proc_close_claim(4816, "fixture_proc_fd")
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, fd)


def test_open_proc_claim_persistent_fingerprint_fault_closes_once_without_blind_retry(
        monkeypatch, tmp_path):
    fd = os.open(tmp_path, containment._DIR_FLAGS)
    real_close = containment.os.close
    close_calls = 0

    def persistent_fingerprint_fault(_fd: int):
        raise OSError(errno.EIO, "fixture persistent fingerprint fault")

    def recording_close(observed_fd: int) -> None:
        nonlocal close_calls
        if observed_fd == fd:
            close_calls += 1
        real_close(observed_fd)

    monkeypatch.setattr(containment, "_open_proc_pid", lambda _pid: fd)
    monkeypatch.setattr(containment, "_fd_fingerprint", persistent_fingerprint_fault)
    monkeypatch.setattr(containment.os, "close", recording_close)
    try:
        with pytest.raises(containment.ContainmentFailure) as caught:
            containment._open_proc_close_claim(4813, "fixture_proc_fd")
        assert caught.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
        assert caught.value.os_errno == errno.EIO
        assert close_calls == 1
        assert _descriptor_is_closed(fd)
    finally:
        _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_open_proc_claim_persistent_fingerprint_fault_never_retries_ambiguous_close(
        monkeypatch, tmp_path, cancellation_type):
    fd = os.open(tmp_path, containment._DIR_FLAGS)
    real_close = containment.os.close
    cancellation = cancellation_type("cancel unauthenticated proc close")
    close_calls = 0

    def persistent_fingerprint_fault(_fd: int):
        raise OSError(errno.EIO, "fixture persistent fingerprint fault")

    def interrupt_close(observed_fd: int) -> None:
        nonlocal close_calls
        if observed_fd == fd:
            close_calls += 1
            raise cancellation
        real_close(observed_fd)

    monkeypatch.setattr(containment, "_open_proc_pid", lambda _pid: fd)
    monkeypatch.setattr(containment, "_fd_fingerprint", persistent_fingerprint_fault)
    monkeypatch.setattr(containment.os, "close", interrupt_close)
    try:
        with pytest.raises(cancellation_type) as caught:
            containment._open_proc_close_claim(4814, "fixture_proc_fd")
        assert caught.value is cancellation
        assert close_calls == 1
        os.fstat(fd)
    finally:
        real_close(fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_same_inode_numeric_reuse_after_ambiguous_close_is_never_retried(
        monkeypatch, tmp_path, cancellation_type):
    directory = tmp_path / "same-directory"
    directory.mkdir()
    fd = os.open(directory, containment._DIR_FLAGS)
    claim = containment._new_close_claim("fixture_fd", fd)
    cancellation = cancellation_type("cancel after same-inode close and reuse")
    real_close = containment.os.close
    close_calls = 0
    replacement = -1

    def close_reopen_same_inode_then_interrupt(observed_fd: int) -> None:
        nonlocal close_calls, replacement
        if observed_fd == fd:
            close_calls += 1
            if close_calls == 1:
                real_close(observed_fd)
                replacement = os.open(directory, containment._DIR_FLAGS)
                assert replacement == fd
                raise cancellation
        real_close(observed_fd)

    monkeypatch.setattr(
        containment.os, "close", close_reopen_same_inode_then_interrupt,
    )
    try:
        caught, _close_errno, clean = containment._close_claims_fenced((claim,))
        assert caught is cancellation
        assert clean is False
        assert close_calls == 1
        assert claim.disposition == "close_ambiguous"
        os.fstat(replacement)

        replay, _replay_errno, replay_clean = containment._close_claims_fenced((claim,))
        assert replay is None
        assert replay_clean is False
        assert close_calls == 1
        os.fstat(replacement)
    finally:
        if replacement >= 0:
            real_close(replacement)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_allocation_claim_preliminary_fstat_cancellation_is_not_swallowed(
        monkeypatch, tmp_path, cancellation_type):
    fd = os.open(tmp_path, containment._DIR_FLAGS)
    real_fstat = containment.os.fstat
    real_close = containment.os.close
    cancellation = cancellation_type("cancel allocation identity capture")
    fired = False

    def interrupt_once(observed_fd: int):
        nonlocal fired
        if observed_fd == fd and not fired:
            fired = True
            raise cancellation
        return real_fstat(observed_fd)

    claim = containment._new_allocation_claim("fixture_fd")
    monkeypatch.setattr(containment.os, "fstat", interrupt_once)
    try:
        with pytest.raises(cancellation_type) as caught:
            containment._populate_allocation_claim(claim, lambda: fd)
        assert caught.value is cancellation
        cleanup_cancellation, _close_errno, clean = containment._close_claims_fenced(
            (claim,),
        )
        assert cleanup_cancellation is None
        assert clean is True
        assert _descriptor_is_closed(fd)
    finally:
        _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["entry", "postclose"])
def test_direct_close_line_cancellation_drains_every_descriptor(
        monkeypatch, tmp_path, cancellation_type, seam):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [handle._kill_fd, handle._events_fd, handle._procs_write_fd,
             handle._procs_read_fd, handle._leaf_fd, handle._parent_fd]
    target = owned[0]
    cancellation = cancellation_type(f"cancel close {seam}")
    fired = False
    previous_trace = sys.gettrace()

    def interrupt_close_transition(frame, event, _arg):
        nonlocal fired
        if (fired or event != "line"
                or frame.f_code is not containment._invoke_close_claim.__code__):
            return interrupt_close_transition
        claim = frame.f_locals.get("claim")
        if not isinstance(claim, containment._DescriptorCloseClaim) or claim.fd != target:
            return interrupt_close_transition
        should_fire = (
            (seam == "entry" and claim.attempts == 0
             and claim.disposition in ("pending", "fresh_owned"))
            or (seam == "postclose" and claim.attempts == 1
                and claim.disposition == "close_started"
                and _descriptor_is_closed(target))
        )
        if should_fire:
            fired = True
            raise cancellation
        return interrupt_close_transition

    try:
        sys.settrace(interrupt_close_transition)
        with pytest.raises(cancellation_type) as caught:
            handle.close()
        assert caught.value is cancellation
        assert fired is True
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert handle._closed is True
        assert handle._closing is False
    finally:
        sys.settrace(previous_trace)
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["before_drain", "before_finalize"])
def test_direct_close_outer_transition_cancellation_still_finalizes_owner(
        monkeypatch, tmp_path, cancellation_type, seam):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [handle._kill_fd, handle._events_fd, handle._procs_write_fd,
             handle._procs_read_fd, handle._leaf_fd, handle._parent_fd]
    cancellation = cancellation_type(f"cancel owner close {seam}")
    fired = False
    previous_trace = sys.gettrace()
    close_transaction_code = getattr(
        handle, "_close_owned_transaction", handle.close,
    ).__func__.__code__

    def interrupt_owner_transition(frame, event, _arg):
        nonlocal fired
        if (fired or event != "line"
                or frame.f_code is not close_transaction_code):
            return interrupt_owner_transition
        claims = handle._close_claims
        if (seam == "before_drain" and handle._closing
                and all(claim.attempts == 0 for claim in claims)):
            fired = True
            raise cancellation
        if (seam == "before_finalize" and not handle._closed
                and all(claim.disposition in containment._CLOSE_TERMINAL
                        for claim in claims)):
            fired = True
            raise cancellation
        return interrupt_owner_transition

    try:
        sys.settrace(interrupt_owner_transition)
        with pytest.raises(cancellation_type) as caught:
            handle.close()
        assert caught.value is cancellation
        assert fired is True
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert handle._closed is True
        assert handle._closing is False
        with pytest.raises(containment.ContainmentFailure) as replay:
            handle.close()
        assert replay.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
    finally:
        sys.settrace(previous_trace)
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_direct_close_cancellation_between_closed_and_unclosing_normalizes_state(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [handle._kill_fd, handle._events_fd, handle._procs_write_fd,
             handle._procs_read_fd, handle._leaf_fd, handle._parent_fd]
    cancellation = cancellation_type("cancel between closed and unclosing")
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._close_owned_transaction.__func__.__code__

    def interrupt_partial_finalization(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line" and frame.f_code is transaction_code
                and handle._closed is True and handle._closing is True):
            fired = True
            raise cancellation
        return interrupt_partial_finalization

    try:
        sys.settrace(interrupt_partial_finalization)
        with pytest.raises(cancellation_type) as caught:
            handle.close()
        assert caught.value is cancellation
        assert fired is True
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert handle._closed is True
        assert handle._closing is False
        assert handle._close_clean is False
        with pytest.raises(containment.ContainmentFailure) as replay:
            handle.close()
        assert replay.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
    finally:
        sys.settrace(previous_trace)
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["owner_entry", "close_helper_call"])
def test_read_bounded_path_cancellation_reconciles_owned_descriptor(
        monkeypatch, tmp_path, cancellation_type, seam):
    source = tmp_path / "bounded-input"
    source.write_text("fixture\n")
    cancellation = cancellation_type(f"cancel bounded path {seam}")
    real_open = containment.os.open
    real_close = containment.os.close
    opened = -1
    fired = False
    previous_trace = sys.gettrace()

    def recording_open(path, flags, *args, **kwargs):
        nonlocal opened
        fd = real_open(path, flags, *args, **kwargs)
        if path == str(source):
            opened = fd
        return fd

    def interrupt_owner_boundary(frame, event, _arg):
        nonlocal fired
        if (fired or event != "line"
                or frame.f_code is not containment._read_bounded_path.__code__
                or frame.f_locals.get("fd") != opened or opened < 0):
            return interrupt_owner_boundary
        raw_present = "raw" in frame.f_locals
        claim = frame.f_locals.get("claim")
        close_pending = (
            type(claim) is containment._DescriptorCloseClaim
            and frame.f_locals.get("result") == "fixture\n"
            and claim.fd == opened
            and claim.disposition not in containment._CLOSE_TERMINAL
            and not _descriptor_is_closed(opened)
        )
        if ((seam == "owner_entry" and not raw_present)
                or (seam == "close_helper_call" and close_pending)):
            fired = True
            raise cancellation
        return interrupt_owner_boundary

    monkeypatch.setattr(containment.os, "open", recording_open)
    try:
        sys.settrace(interrupt_owner_boundary)
        with pytest.raises(cancellation_type) as caught:
            containment._read_bounded_path(str(source))
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
    finally:
        sys.settrace(previous_trace)
        if opened >= 0:
            _close_if_open(real_close, opened)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after_physical_close", [False, True])
def test_discovered_parent_close_is_single_attempt_and_never_closes_reuse(
        monkeypatch, tmp_path, cancellation_type, after_physical_close):
    directory = tmp_path / "delegated-parent"
    directory.mkdir()
    fd = os.open(directory, containment._DIR_FLAGS)
    discovered = containment._DiscoveredParent(fd, "/delegated")
    cancellation = cancellation_type("cancel discovered parent close")
    real_close = containment.os.close
    close_calls = 0
    replacement = -1

    def interrupting_close(observed_fd: int) -> None:
        nonlocal close_calls, replacement
        if observed_fd != fd:
            real_close(observed_fd)
            return
        close_calls += 1
        if after_physical_close:
            real_close(observed_fd)
            candidate = os.open(directory, containment._DIR_FLAGS)
            if candidate != fd:
                os.dup2(candidate, fd, inheritable=False)
                real_close(candidate)
            replacement = fd
        raise cancellation

    monkeypatch.setattr(containment.os, "close", interrupting_close)
    try:
        with pytest.raises(cancellation_type) as caught:
            discovered.close()
        assert caught.value is cancellation
        assert close_calls == 1
        assert discovered.fd == -1
        if after_physical_close:
            os.fstat(replacement)
        else:
            os.fstat(fd)

        discovered.close()
        assert close_calls == 1
        os.fstat(fd)
    finally:
        _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["owner_entry", "close_invocation"])
@pytest.mark.parametrize(
    "target_name", ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"],
)
def test_parent_candidate_control_cancellation_has_bounded_ownership(
        monkeypatch, tmp_path, cancellation_type, seam, target_name):
    parent = tmp_path / "candidate"
    parent.mkdir()
    for name in ("cgroup.procs", "cgroup.threads", "cgroup.subtree_control"):
        _write_control(parent, name)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    cancellation = cancellation_type(f"cancel {target_name} {seam}")
    real_open_control = containment._open_control
    real_close = containment.os.close
    target_fd = -1
    target_close_calls = 0
    fired = False
    previous_trace = sys.gettrace()

    def recording_open_control(dir_fd: int, name: str, flags: int, **kwargs):
        nonlocal target_fd
        fd = real_open_control(dir_fd, name, flags, **kwargs)
        if name == target_name:
            target_fd = fd
        return fd

    def interrupting_close(observed_fd: int) -> None:
        nonlocal target_close_calls
        if seam == "close_invocation" and observed_fd == target_fd:
            target_close_calls += 1
            raise cancellation
        real_close(observed_fd)

    def interrupt_owner_entry(frame, event, _arg):
        nonlocal fired
        if (seam == "owner_entry" and not fired and event == "line"
                and frame.f_code is containment._check_parent_candidate.__code__
                and target_fd >= 0 and frame.f_locals.get("control") == target_fd):
            fired = True
            raise cancellation
        return interrupt_owner_entry

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment.os, "access", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(containment, "_open_control", recording_open_control)
    monkeypatch.setattr(containment.os, "close", interrupting_close)
    try:
        sys.settrace(interrupt_owner_entry)
        with pytest.raises(cancellation_type) as caught:
            containment._check_parent_candidate(parent_fd)
        assert caught.value is cancellation
        assert target_fd >= 0
        if seam == "owner_entry":
            assert fired is True
            assert _descriptor_is_closed(target_fd)
        else:
            assert target_close_calls == 1
            os.fstat(target_fd)
    finally:
        sys.settrace(previous_trace)
        if target_fd >= 0:
            _close_if_open(real_close, target_fd)
        _close_if_open(real_close, parent_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["mount_owner", "parent_owner", "return_boundary"])
def test_discovery_cancellation_drains_mount_and_parent_authorities(
        monkeypatch, tmp_path, cancellation_type, seam):
    opened, checked = _install_hermetic_discovery(monkeypatch, tmp_path)
    cancellation = cancellation_type(f"cancel discovery {seam}")
    real_close = containment.os.close
    fired = False
    previous_trace = sys.gettrace()

    def interrupt_discovery(frame, event, _arg):
        nonlocal fired
        if (fired or event != "line"
                or frame.f_code is not containment._discover_parent.__code__):
            return interrupt_discovery
        mount_owned = (opened["mount"] >= 0
                       and frame.f_locals.get("mount_fd") == opened["mount"])
        parent_owned = (opened["parent"] >= 0
                        and frame.f_locals.get("parent_fd") == opened["parent"])
        should_fire = (
            (seam == "mount_owner" and mount_owned and not parent_owned)
            or (seam == "parent_owner" and parent_owned
                and not checked["value"])
            or (seam == "return_boundary" and parent_owned
                and checked["value"])
        )
        if should_fire:
            fired = True
            raise cancellation
        return interrupt_discovery

    try:
        sys.settrace(interrupt_discovery)
        with pytest.raises(cancellation_type) as caught:
            containment._discover_parent()
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened["mount"])
        if opened["parent"] >= 0:
            assert _descriptor_is_closed(opened["parent"])
    finally:
        sys.settrace(previous_trace)
        for fd in opened.values():
            if fd >= 0:
                _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("operation", ["probe", "acquire"])
def test_public_discovery_return_is_immediately_owned(
        monkeypatch, tmp_path, cancellation_type, operation):
    directory = tmp_path / "delegated"
    directory.mkdir()
    fd = os.open(directory, containment._DIR_FLAGS)
    discovered = containment._DiscoveredParent(fd, "/delegated")
    cancellation = cancellation_type(f"cancel {operation} discovery adoption")
    real_close = containment.os.close
    fired = False
    previous_trace = sys.gettrace()
    function = (containment.probe_direct_cgroup_v2 if operation == "probe"
                else containment.acquire_direct_cgroup_v2)

    def interrupt_discovery_adoption(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line" and frame.f_code is function.__code__
                and frame.f_locals.get("discovered") is discovered
                and discovered.fd == fd):
            fired = True
            raise cancellation
        return interrupt_discovery_adoption

    monkeypatch.setattr(containment, "_discover_parent", lambda: discovered)
    if operation == "acquire":
        monkeypatch.setattr(
            containment, "_acquire_from_parent",
            lambda *_args: pytest.fail("cancellation crossed discovery adoption"),
        )
    try:
        sys.settrace(interrupt_discovery_adoption)
        with pytest.raises(cancellation_type) as caught:
            function() if operation == "probe" else function(REQUEST_ID)
        assert caught.value is cancellation
        assert fired is True
        assert discovered.fd == -1
        assert _descriptor_is_closed(fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, fd)


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
        assert (handle.containment_assurance
                is ContainmentAssurance.COOPERATIVE_SCOPE)
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
                        lambda _fd, **_kwargs: (
                            _ for _ in ()).throw(KeyboardInterrupt()))
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


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_acquisition_leaf_open_before_adoption_is_recovered_and_rolled_back(
        monkeypatch, tmp_path, cancellation_type):
    delegated = tmp_path / "delegated"
    delegated.mkdir()
    leaf_name = f"quarry-{REQUEST_ID}"
    cancellation = cancellation_type("cancel leaf fd adoption")
    real_open = containment.os.open
    opened = -1
    fired = False
    previous_trace = sys.gettrace()

    def create_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, dir_fd=dir_fd)
        _populate_leaf(delegated / name)

    def recording_open(path, flags, *args, **kwargs):
        nonlocal opened
        fd = real_open(path, flags, *args, **kwargs)
        if path == leaf_name and kwargs.get("dir_fd") == discovered.fd:
            opened = fd
        return fd

    def interrupt_before_append(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is containment._acquire_from_parent.__code__
                and frame.f_locals.get("leaf_fd") == opened
                and opened not in frame.f_locals.get("fds", ())):
            fired = True
            raise cancellation
        return interrupt_before_append

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", create_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated",
    )
    parent_fd = discovered.fd
    monkeypatch.setattr(containment.os, "open", recording_open)
    try:
        sys.settrace(interrupt_before_append)
        with pytest.raises(cancellation_type) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
        assert not (delegated / leaf_name).exists()
        assert discovered.fd == parent_fd
        os.fstat(parent_fd)
    finally:
        sys.settrace(previous_trace)
        discovered.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("role", ["procs_read", "procs_write", "events", "kill"])
def test_acquisition_control_open_before_adoption_is_recovered_and_rolled_back(
        monkeypatch, tmp_path, cancellation_type, role):
    delegated = tmp_path / "delegated"
    delegated.mkdir()
    leaf_name = f"quarry-{REQUEST_ID}"
    cancellation = cancellation_type(f"cancel {role} fd adoption")
    real_open_control = containment._open_control
    real_open_kill = containment._open_leaf_kill
    opened = -1
    fired = False
    previous_trace = sys.gettrace()

    def create_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, dir_fd=dir_fd)
        _populate_leaf(delegated / name)

    def tracking_open_control(dir_fd: int, name: str, flags: int, **kwargs):
        nonlocal opened
        fd = real_open_control(dir_fd, name, flags, **kwargs)
        expected = {
            "procs_read": ("cgroup.procs", containment._READ_FLAGS),
            "procs_write": ("cgroup.procs", containment._WRITE_FLAGS),
            "events": ("cgroup.events", containment._READ_FLAGS),
            "kill": ("cgroup.kill", containment._WRITE_FLAGS),
        }.get(role)
        if expected == (name, flags):
            opened = fd
        return fd

    def tracking_open_kill(dir_fd: int, **kwargs) -> int:
        nonlocal opened
        fd = real_open_kill(dir_fd, **kwargs)
        if role == "kill":
            opened = fd
        return fd

    def interrupt_before_append(frame, event, _arg):
        nonlocal fired
        if (fired or event != "line"
                or frame.f_code is not containment._acquire_from_parent.__code__
                or opened < 0 or opened in frame.f_locals.get("fds", ())):
            return interrupt_before_append
        local_name = {
            "procs_read": "procs_read",
            "procs_write": "procs_write",
            "events": "events",
            "kill": "kill",
        }[role]
        if frame.f_locals.get(local_name) == opened:
            fired = True
            raise cancellation
        return interrupt_before_append

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", create_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(containment, "_open_control", tracking_open_control)
    monkeypatch.setattr(containment, "_open_leaf_kill", tracking_open_kill)
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated",
    )
    parent_fd = discovered.fd
    try:
        sys.settrace(interrupt_before_append)
        with pytest.raises(cancellation_type) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
        assert not (delegated / leaf_name).exists()
        assert discovered.fd == parent_fd
        os.fstat(parent_fd)
    finally:
        sys.settrace(previous_trace)
        discovered.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_public_acquire_pending_return_cancellation_recovers_transferred_handle(
        monkeypatch, tmp_path, cancellation_type):
    delegated = tmp_path / "delegated"
    delegated.mkdir()
    leaf = delegated / f"quarry-{REQUEST_ID}"
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated",
    )
    cancellation = cancellation_type("cancel pending public acquisition return")
    real_acquire = containment._acquire_from_parent
    captured: list[containment.DirectCgroupV2] = []
    fired = False
    previous_trace = sys.gettrace()

    def create_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        _populate_leaf(delegated / name)

    def recording_acquire(request_id: str, owner):
        handle = real_acquire(request_id, owner)
        captured.append(handle)
        return handle

    def interrupt_pending_return(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is containment.acquire_direct_cgroup_v2.__code__
                and frame.f_locals.get("discovered") is discovered
                and discovered.fd == -1 and captured):
            fired = True
            raise cancellation
        return interrupt_pending_return

    monkeypatch.setattr(containment, "_discover_parent", lambda: discovered)
    monkeypatch.setattr(containment, "_acquire_from_parent", recording_acquire)
    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", create_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    try:
        sys.settrace(interrupt_pending_return)
        with pytest.raises(cancellation_type) as caught:
            containment.acquire_direct_cgroup_v2(REQUEST_ID)
        assert caught.value is cancellation
        assert fired is True
        assert len(captured) == 1
        handle = captured[0]
        owned = [
            handle._kill_fd, handle._events_fd, handle._procs_write_fd,
            handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
        ]
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert not leaf.exists()
    finally:
        sys.settrace(previous_trace)
        if captured:
            try:
                captured[0].close()
            except containment.ContainmentError:
                pass
        if leaf.exists():
            cleanup_parent = os.open(delegated, containment._DIR_FLAGS)
            try:
                _fake_cgroup_rmdir(leaf.name, cleanup_parent)
            finally:
                os.close(cleanup_parent)
        if discovered.fd >= 0:
            discovered.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_unpublished_handle_close_entry_cancellation_drains_parent_and_terminalizes(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    child_fds = owned[:-1]
    parent_fd = owned[-1]
    ordinary_primary = RuntimeError("fixture unpublished return fault")
    cancellation = cancellation_type("cancel before unpublished handle close")
    fired = False
    previous_trace = sys.gettrace()

    def interrupt_close_entry(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is containment._rollback_unpublished_handle.__code__
                and frame.f_locals.get("handle") is handle
                and handle._removed is True and handle._closed is False
                and all(_descriptor_is_closed(fd) for fd in child_fds)
                and not _descriptor_is_closed(parent_fd)):
            fired = True
            raise cancellation
        return interrupt_close_entry

    try:
        sys.settrace(interrupt_close_entry)
        with pytest.raises(cancellation_type) as caught:
            containment._rollback_unpublished_handle(handle, ordinary_primary)
        assert caught.value is cancellation
        assert fired is True
        assert not leaf.exists()
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert handle._closed is True
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_unpublished_handle_authenticated_pre_remove_cancellation_recovers(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    ordinary_primary = RuntimeError("fixture unpublished publication fault")
    cancellation = cancellation_type("cancel before unpublished removal")
    fired = False
    previous_trace = sys.gettrace()

    def interrupt_pre_remove(frame, event, _arg):
        nonlocal fired
        attempt = frame.f_locals.get("attempt")
        if (not fired and event == "line"
                and frame.f_code is containment._remove_authenticated_once.__code__
                and type(attempt) is containment._RemoveAttempt
                and attempt.state == "not_started"
                and "named" in frame.f_locals and leaf.is_dir()):
            fired = True
            raise cancellation
        return interrupt_pre_remove

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    try:
        sys.settrace(interrupt_pre_remove)
        with pytest.raises(cancellation_type) as caught:
            containment._rollback_unpublished_handle(handle, ordinary_primary)
        assert caught.value is cancellation
        assert fired is True
        assert not leaf.exists()
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert handle._removed is True
        assert handle._closed is True
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["before_child_close", "before_remove_owner"])
def test_unpublished_rollback_caller_boundary_cancellation_drains_everything(
        monkeypatch, tmp_path, cancellation_type, seam):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    control_fds = owned[:4]
    leaf_fd = owned[4]
    parent_fd = owned[-1]
    ordinary_primary = RuntimeError("fixture unpublished boundary fault")
    cancellation = cancellation_type(f"cancel unpublished {seam}")
    fired = False
    previous_trace = sys.gettrace()

    def interrupt_caller_boundary(frame, event, _arg):
        nonlocal fired
        if (fired or event != "line"
                or frame.f_code is not containment._rollback_unpublished_handle.__code__
                or frame.f_locals.get("handle") is not handle
                or frame.f_locals.get("removable") is not True):
            return interrupt_caller_boundary
        attempt = frame.f_locals.get("remove_attempt")
        controls_open = [not _descriptor_is_closed(fd) for fd in control_fds]
        leaf_open = not _descriptor_is_closed(leaf_fd)
        parent_open = not _descriptor_is_closed(parent_fd)
        should_fire = (
            seam == "before_child_close" and all(controls_open)
            and leaf_open and parent_open
            or seam == "before_remove_owner" and not any(controls_open)
            and leaf_open
            and parent_open and type(attempt) is containment._RemoveAttempt
            and attempt.state == "not_started"
        )
        if should_fire:
            fired = True
            raise cancellation
        return interrupt_caller_boundary

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    try:
        sys.settrace(interrupt_caller_boundary)
        with pytest.raises(cancellation_type) as caught:
            containment._rollback_unpublished_handle(handle, ordinary_primary)
        assert caught.value is cancellation
        assert fired is True
        assert not leaf.exists()
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert handle._removed is True
        assert handle._closed is True
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_unpublished_probe_primary_first_recovery_line_drains_and_rolls_back(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    publication_primary = RuntimeError("fixture unpublished publication fault")
    probe_primary = RuntimeError("fixture unpublished identity probe fault")
    cancellation = cancellation_type("cancel unpublished probe recovery")
    real_identity = handle._leaf_identity_current
    real_finish = containment._finish_unpublished_rollback
    identity_calls = 0
    finish_calls = 0
    fired = False
    previous_trace = sys.gettrace()

    def ordinary_first_identity_probe() -> bool:
        nonlocal identity_calls
        identity_calls += 1
        if identity_calls == 1:
            raise probe_primary
        return real_identity()

    def recording_finish(*args, **kwargs):
        nonlocal finish_calls
        finish_calls += 1
        return real_finish(*args, **kwargs)

    def interrupt_first_probe_recovery_line(frame, event, _arg):
        nonlocal fired
        state = frame.f_locals.get("state")
        if (not fired and event == "line"
                and frame.f_code is containment._rollback_unpublished_handle.__code__
                and frame.f_locals.get("boundary") is probe_primary
                and type(state) is containment._UnpublishedRollbackState
                and state.probe_complete is False and finish_calls == 0
                and all(not _descriptor_is_closed(fd) for fd in owned)):
            fired = True
            raise cancellation
        return interrupt_first_probe_recovery_line

    monkeypatch.setattr(handle, "_leaf_identity_current",
                        ordinary_first_identity_probe)
    monkeypatch.setattr(containment, "_finish_unpublished_rollback",
                        recording_finish)
    try:
        sys.settrace(interrupt_first_probe_recovery_line)
        with pytest.raises(cancellation_type) as caught:
            containment._rollback_unpublished_handle(
                handle, publication_primary,
            )
        assert caught.value is cancellation
        assert fired is True
        assert identity_calls >= 2
        assert finish_calls >= 1
        assert not leaf.exists()
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)
        assert handle._removed is True
        assert handle._closed is True
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)
        if leaf.exists():
            cleanup_parent = os.open(leaf.parent, containment._DIR_FLAGS)
            try:
                _fake_cgroup_rmdir(leaf.name, cleanup_parent)
            finally:
                os.close(cleanup_parent)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_failed_acquisition_cleanup_call_boundary_drains_and_rolls_back(
        monkeypatch, tmp_path, cancellation_type):
    delegated = tmp_path / "delegated"
    leaf = delegated / "pending-leaf"
    leaf.mkdir(parents=True)
    _populate_leaf(leaf)
    parent_fd = os.open(delegated, containment._DIR_FLAGS)
    raw_fds = [
        os.open(leaf, containment._DIR_FLAGS),
        os.open(leaf / "cgroup.events", containment._READ_FLAGS),
        os.open(leaf / "cgroup.procs", containment._WRITE_FLAGS),
    ]
    claims = tuple(
        containment._new_close_claim(f"fixture_{index}", fd)
        for index, fd in enumerate(raw_fds)
    )
    preserve = containment.ContainmentFailure(
        containment.ContainmentReason.LEAF_CONTROL_UNUSABLE,
    )
    cancellation = cancellation_type("cancel before failed-acquisition close fence")
    real_fence = containment._close_claims_fenced
    real_close = containment.os.close
    fence_calls = 0

    def interrupt_first_fence(*args, **kwargs):
        nonlocal fence_calls
        fence_calls += 1
        if fence_calls == 1:
            raise cancellation
        return real_fence(*args, **kwargs)

    monkeypatch.setattr(containment, "_close_claims_fenced", interrupt_first_fence)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    try:
        with pytest.raises(cancellation_type) as caught:
            containment._cleanup_failed_acquisition(
                claims=claims, created=True, leaf_name=leaf.name,
                parent_fd=parent_fd, preserve=preserve,
            )
        assert caught.value is cancellation
        assert fence_calls == 3
        assert all(_descriptor_is_closed(fd) for fd in raw_fds)
        assert not leaf.exists()
        os.fstat(parent_fd)
    finally:
        for fd in raw_fds:
            _close_if_open(real_close, fd)
        if leaf.exists():
            _fake_cgroup_rmdir(leaf.name, parent_fd)
        _close_if_open(real_close, parent_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_failed_acquisition_post_drain_removal_owner_boundary_recovers(
        monkeypatch, tmp_path, cancellation_type):
    delegated = tmp_path / "delegated"
    leaf = delegated / "pending-leaf"
    leaf.mkdir(parents=True)
    _populate_leaf(leaf)
    parent_fd = os.open(delegated, containment._DIR_FLAGS)
    leaf_fd = os.open(leaf, containment._DIR_FLAGS)
    control_fds = [
        os.open(leaf / "cgroup.events", containment._READ_FLAGS),
        os.open(leaf / "cgroup.procs", containment._WRITE_FLAGS),
    ]
    observed = os.fstat(leaf_fd)
    identity = (observed.st_dev, observed.st_ino)
    leaf_claim = containment._new_close_claim("fixture_leaf", leaf_fd)
    control_claims = tuple(
        containment._new_close_claim(f"fixture_control_{index}", fd)
        for index, fd in enumerate(control_fds)
    )
    claims = (leaf_claim, *control_claims)
    preserve = containment.ContainmentFailure(
        containment.ContainmentReason.LEAF_CONTROL_UNUSABLE,
    )
    cancellation = cancellation_type("cancel failed acquisition removal owner")
    fired = False
    previous_trace = sys.gettrace()

    def interrupt_removal_owner(frame, event, _arg):
        nonlocal fired
        attempt = frame.f_locals.get("remove_attempt")
        if (not fired and event == "line"
                and frame.f_code is containment._cleanup_failed_acquisition.__code__
                and type(attempt) is containment._RemoveAttempt
                and attempt.state == "not_started"
                and all(_descriptor_is_closed(fd) for fd in control_fds)
                and not _descriptor_is_closed(leaf_fd) and leaf.is_dir()):
            fired = True
            raise cancellation
        return interrupt_removal_owner

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    try:
        sys.settrace(interrupt_removal_owner)
        with pytest.raises(cancellation_type) as caught:
            containment._cleanup_failed_acquisition(
                claims=claims, created=True, leaf_name=leaf.name,
                parent_fd=parent_fd, preserve=preserve,
                leaf_identity=identity,
            )
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(leaf_fd)
        assert all(_descriptor_is_closed(fd) for fd in control_fds)
        assert not leaf.exists()
        os.fstat(parent_fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(os.close, leaf_fd)
        for fd in control_fds:
            _close_if_open(os.close, fd)
        if leaf.exists():
            _fake_cgroup_rmdir(leaf.name, parent_fd)
        _close_if_open(os.close, parent_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["before_stat", "before_rmdir"])
def test_failed_acquisition_authenticated_removal_entry_cancellation_recovers(
        monkeypatch, tmp_path, cancellation_type, seam):
    delegated = tmp_path / "delegated"
    leaf = delegated / "pending-leaf"
    leaf.mkdir(parents=True)
    _populate_leaf(leaf)
    parent_fd = os.open(delegated, containment._DIR_FLAGS)
    leaf_fd = os.open(leaf, containment._DIR_FLAGS)
    observed = os.fstat(leaf_fd)
    identity = (observed.st_dev, observed.st_ino)
    claim = containment._new_close_claim("fixture_leaf", leaf_fd)
    preserve = containment.ContainmentFailure(
        containment.ContainmentReason.LEAF_CONTROL_UNUSABLE,
    )
    cancellation = cancellation_type(f"cancel failed acquisition {seam}")
    fired = False
    previous_trace = sys.gettrace()

    def interrupt_remove_entry(frame, event, _arg):
        nonlocal fired
        attempt = frame.f_locals.get("attempt")
        should_fire = (
            seam == "before_stat" and "named" not in frame.f_locals
            or seam == "before_rmdir" and "named" in frame.f_locals
        )
        if (not fired and event == "line"
                and frame.f_code is containment._remove_authenticated_once.__code__
                and type(attempt) is containment._RemoveAttempt
                and attempt.state == "not_started" and should_fire
                and leaf.is_dir()):
            fired = True
            raise cancellation
        return interrupt_remove_entry

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    try:
        sys.settrace(interrupt_remove_entry)
        with pytest.raises(cancellation_type) as caught:
            containment._cleanup_failed_acquisition(
                claims=(claim,), created=True, leaf_name=leaf.name,
                parent_fd=parent_fd, preserve=preserve,
                leaf_identity=identity,
            )
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(leaf_fd)
        assert not leaf.exists()
        os.fstat(parent_fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(os.close, leaf_fd)
        if leaf.exists():
            _fake_cgroup_rmdir(leaf.name, parent_fd)
        _close_if_open(os.close, parent_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_failed_acquisition_post_rmdir_anchor_close_cancellation_recovers(
        monkeypatch, tmp_path, cancellation_type):
    delegated = tmp_path / "failed-post-rmdir-anchor"
    leaf = delegated / "pending-leaf"
    leaf.mkdir(parents=True)
    _populate_leaf(leaf)
    parent_fd = os.open(delegated, containment._DIR_FLAGS)
    leaf_fd = os.open(leaf, containment._DIR_FLAGS)
    observed = os.fstat(leaf_fd)
    identity = (observed.st_dev, observed.st_ino)
    claim = containment._new_close_claim("fixture_leaf", leaf_fd)
    preserve = RuntimeError("fixture failed acquisition primary")
    cancellation = cancellation_type("cancel acquisition anchor close")
    remove_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    cleanup_line = _source_line(
        containment._cleanup_failed_acquisition,
        "interrupted, anchor_errno, anchor_clean = _close_claims_guarded(",
    )

    def recording_rmdir(name: str, dir_fd: int) -> None:
        nonlocal remove_calls
        if name == leaf.name and dir_fd == parent_fd:
            remove_calls += 1
        _fake_cgroup_rmdir(name, dir_fd)

    def interrupt_anchor_close_call(frame, event, _arg):
        nonlocal fired
        attempt = frame.f_locals.get("remove_attempt")
        if (not fired and event == "line"
                and frame.f_code is containment._cleanup_failed_acquisition.__code__
                and frame.f_lineno == cleanup_line
                and type(attempt) is containment._RemoveAttempt
                and attempt.state == "removed" and remove_calls == 1
                and frame.f_locals.get("leaf_claim") is claim
                and claim.disposition not in containment._CLOSE_TERMINAL
                and not _descriptor_is_closed(leaf_fd)):
            fired = True
            raise cancellation
        return interrupt_anchor_close_call

    monkeypatch.setattr(containment, "_rmdir_cgroup", recording_rmdir)
    try:
        sys.settrace(interrupt_anchor_close_call)
        with pytest.raises(cancellation_type) as caught:
            containment._cleanup_failed_acquisition(
                claims=(claim,), created=True, leaf_name=leaf.name,
                parent_fd=parent_fd, preserve=preserve,
                leaf_identity=identity, leaf_claim=claim,
            )
        assert caught.value is cancellation
        assert fired is True and remove_calls == 1
        assert not leaf.exists()
        assert _descriptor_is_closed(leaf_fd)
        assert claim.disposition in containment._CLOSE_TERMINAL
        os.fstat(parent_fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(os.close, leaf_fd)
        if leaf.exists():
            _fake_cgroup_rmdir(leaf.name, parent_fd)
        _close_if_open(os.close, parent_fd)


def test_failed_acquisition_rollback_never_removes_reused_leaf_name(
        monkeypatch, tmp_path):
    delegated = tmp_path / "delegated"
    delegated.mkdir()
    leaf_name = f"quarry-{REQUEST_ID}"
    leaf = delegated / leaf_name
    moved = delegated / "original-created-leaf"
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated",
    )
    real_stat = containment.os.stat
    swapped = False
    replacement_identity = None

    def create_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        _populate_leaf(delegated / name)

    def swap_before_named_identity(path, *args, **kwargs):
        nonlocal swapped, replacement_identity
        if (not swapped and path == leaf_name
                and kwargs.get("dir_fd") == discovered.fd):
            swapped = True
            leaf.rename(moved)
            leaf.mkdir()
            _populate_leaf(leaf)
            observed = real_stat(path, *args, **kwargs)
            replacement_identity = (observed.st_dev, observed.st_ino)
            return observed
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", create_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(containment.os, "stat", swap_before_named_identity)
    try:
        with pytest.raises(containment.ContainmentError):
            containment._acquire_from_parent(REQUEST_ID, discovered)
        assert swapped is True
        observed = real_stat(leaf, follow_symlinks=False)
        assert (observed.st_dev, observed.st_ino) == replacement_identity
        assert moved.is_dir()
    finally:
        discovered.close()
        for directory in (leaf, moved):
            if directory.exists():
                cleanup_parent = os.open(delegated, containment._DIR_FLAGS)
                try:
                    _fake_cgroup_rmdir(directory.name, cleanup_parent)
                finally:
                    os.close(cleanup_parent)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_mkdir_helper_internal_cancellation_never_blindly_removes_unproven_name(
        monkeypatch, tmp_path, cancellation_type):
    delegated = tmp_path / "delegated"
    delegated.mkdir()
    leaf_name = f"quarry-{REQUEST_ID}"
    leaf = delegated / leaf_name
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated",
    )
    cancellation = cancellation_type("cancel inside mkdir helper")
    rmdir_calls = 0

    def create_then_interrupt(name: str, dir_fd: int) -> None:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        _populate_leaf(delegated / name)
        raise cancellation

    def recording_rmdir(name: str, parent_fd: int) -> None:
        nonlocal rmdir_calls
        rmdir_calls += 1
        _fake_cgroup_rmdir(name, parent_fd)

    monkeypatch.setattr(containment, "_mkdir_leaf", create_then_interrupt)
    monkeypatch.setattr(containment, "_rmdir_cgroup", recording_rmdir)
    try:
        with pytest.raises(cancellation_type) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
        assert caught.value is cancellation
        assert rmdir_calls == 0
        assert leaf.is_dir()
        os.fstat(discovered.fd)
    finally:
        if leaf.exists():
            _fake_cgroup_rmdir(leaf_name, discovered.fd)
        discovered.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_mkdir_return_to_created_commit_gap_is_rolled_back_if_observable(
        monkeypatch, tmp_path, cancellation_type):
    delegated = tmp_path / "delegated"
    delegated.mkdir()
    leaf_name = f"quarry-{REQUEST_ID}"
    leaf = delegated / leaf_name
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated",
    )
    cancellation = cancellation_type("cancel after mkdir helper return")
    helper_returned = False
    fired = False
    rmdir_calls = 0
    result = None
    caught_cancellation = None
    previous_trace = sys.gettrace()

    def create_leaf(name: str, dir_fd: int) -> None:
        nonlocal helper_returned
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        _populate_leaf(delegated / name)
        helper_returned = True

    def recording_rmdir(name: str, parent_fd: int) -> None:
        nonlocal rmdir_calls
        rmdir_calls += 1
        _fake_cgroup_rmdir(name, parent_fd)

    def interrupt_visible_commit_gap(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is containment._acquire_from_parent.__code__
                and helper_returned and frame.f_locals.get("created") is False
                and leaf.is_dir()):
            fired = True
            raise cancellation
        return interrupt_visible_commit_gap

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment, "_mkdir_leaf", create_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", recording_rmdir)
    try:
        sys.settrace(interrupt_visible_commit_gap)
        try:
            result = containment._acquire_from_parent(REQUEST_ID, discovered)
        except cancellation_type as exc:
            caught_cancellation = exc
        finally:
            sys.settrace(previous_trace)

        assert helper_returned is True
        if fired:
            assert caught_cancellation is cancellation
            assert rmdir_calls == 1
            assert not leaf.exists()
            os.fstat(discovered.fd)
        else:
            # A packed helper-return/action-fact commit has no supported Python
            # line boundary at which to inject.  Normal acquisition is then the
            # proof that ownership was committed rather than abandoned.
            assert caught_cancellation is None
            assert type(result) is containment.DirectCgroupV2
            assert discovered.fd == -1
    finally:
        sys.settrace(previous_trace)
        if result is not None:
            try:
                result.close()
            except containment.ContainmentError:
                pass
        if leaf.exists():
            cleanup_parent = os.open(delegated, containment._DIR_FLAGS)
            try:
                _fake_cgroup_rmdir(leaf_name, cleanup_parent)
            finally:
                os.close(cleanup_parent)
        if discovered.fd >= 0:
            discovered.close()


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


def _bind_started_fixture(monkeypatch, tmp_path, *, pid: int, started: int):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    process = _install_fake_proc(
        monkeypatch,
        tmp_path,
        pid=pid,
        start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid,
        started,
        state="T",
        process_group=pid,
        session=pid,
    ))
    real_write = containment.os.write

    def model_migration(fd: int, payload: bytes) -> int:
        written = real_write(fd, payload)
        if fd == handle._procs_write_fd:
            (leaf / "cgroup.procs").write_bytes(payload)
            (process / "cgroup").write_text(f"0::{handle.membership}\n")
        return written

    monkeypatch.setattr(containment.os, "write", model_migration)
    identity = containment.ProcessIdentity(pid, started)
    assert handle.bind_pid(identity).verified is True
    return handle, leaf, process, identity


@pytest.mark.parametrize(("state", "listed", "verified", "reason"), [
    ("S", True, True, containment.ContainmentReason.VERIFIED),
    ("Z", False, True, containment.ContainmentReason.VERIFIED),
    ("S", False, False, containment.ContainmentReason.LEAF_MEMBERSHIP_MISSING),
    ("X", True, False, containment.ContainmentReason.PROCESS_GONE),
    ("x", False, False, containment.ContainmentReason.PROCESS_GONE),
])
def test_started_verification_requires_live_leaf_or_exact_unreaped_zombie(
        monkeypatch, tmp_path, state, listed, verified, reason):
    pid, started = 42430, 199_124
    handle, leaf, process, identity = _bind_started_fixture(
        monkeypatch, tmp_path, pid=pid, started=started,
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state=state, process_group=pid, session=pid,
    ))
    (leaf / "cgroup.procs").write_text(f"{pid}\n" if listed else "")
    try:
        result = handle.verify_started_pid(identity)
        assert result.verified is verified
        assert result.reason is reason
    finally:
        handle.close()


@pytest.mark.parametrize("mutation", ["start", "cgroup", "leaf"])
def test_started_zombie_verification_rejects_changed_authority(
        monkeypatch, tmp_path, mutation):
    pid, started = 42431, 199_125
    handle, leaf, process, identity = _bind_started_fixture(
        monkeypatch, tmp_path, pid=pid, started=started,
    )
    (process / "stat").write_text(_proc_stat(
        pid,
        started + (mutation == "start"),
        state="Z",
        process_group=pid,
        session=pid,
    ))
    (leaf / "cgroup.procs").write_text("")
    if mutation == "cgroup":
        (process / "cgroup").write_text("0::/delegated/sibling\n")
    if mutation == "leaf":
        handle._leaf_identity = (0, 0)
    try:
        result = handle.verify_started_pid(identity)
        assert result.verified is False
        assert result.reason is {
            "start": containment.ContainmentReason.PROCESS_IDENTITY_CHANGED,
            "cgroup": containment.ContainmentReason.PROCESS_CGROUP_MISMATCH,
            "leaf": containment.ContainmentReason.LEAF_IDENTITY_CHANGED,
        }[mutation]
    finally:
        handle.close()


def test_started_verification_accepts_exact_live_to_zombie_transition(
        monkeypatch, tmp_path):
    pid, started = 42432, 199_126
    handle, leaf, process, identity = _bind_started_fixture(
        monkeypatch, tmp_path, pid=pid, started=started,
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="S", process_group=pid, session=pid,
    ))
    (leaf / "cgroup.procs").write_text("")
    real_stat = containment._proc_stat_identity
    samples = 0

    def transition_to_zombie(fd):
        nonlocal samples
        observed = real_stat(fd)
        samples += 1
        if samples == 1:
            (process / "stat").write_text(_proc_stat(
                pid, started, state="Z", process_group=pid, session=pid,
            ))
        return observed

    monkeypatch.setattr(containment, "_proc_stat_identity", transition_to_zombie)
    try:
        result = handle.verify_started_pid(identity)
        assert result == containment.MembershipVerification(
            True, containment.ContainmentReason.VERIFIED,
        )
        assert samples == 2
    finally:
        handle.close()


def test_started_verification_refuses_a_reaped_zombie(monkeypatch, tmp_path):
    pid, started = 42433, 199_127
    handle, leaf, process, identity = _bind_started_fixture(
        monkeypatch, tmp_path, pid=pid, started=started,
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="Z", process_group=pid, session=pid,
    ))
    (leaf / "cgroup.procs").write_text("")
    shutil.rmtree(process)
    try:
        result = handle.verify_started_pid(identity)
        assert result.verified is False
        assert result.reason is containment.ContainmentReason.PROCESS_GONE
    finally:
        handle.close()


def test_failed_binding_attempt_cannot_authorize_zombie_continuity(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, started = 42434, 199_128
    process = _install_fake_proc(
        monkeypatch,
        tmp_path,
        pid=pid,
        start_time=started,
        membership=handle.membership,
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", process_group=pid, session=pid,
    ))
    identity = containment.ProcessIdentity(pid, started)
    real_write = containment.os.write

    def refuse_migration(fd: int, payload: bytes) -> int:
        if fd == handle._procs_write_fd:
            return len(payload)
        return real_write(fd, payload)

    monkeypatch.setattr(containment.os, "write", refuse_migration)
    try:
        attempted = handle.bind_pid(identity)
        assert attempted.verified is False
        assert attempted.reason is containment.ContainmentReason.LEAF_MEMBERSHIP_MISSING
        assert handle._binding_attempted is True
        assert handle._bound_identity is None
        (process / "stat").write_text(_proc_stat(
            pid, started, state="Z", process_group=pid, session=pid,
        ))
        (leaf / "cgroup.procs").write_text("")
        with pytest.raises(containment.ContainmentRefused) as caught:
            handle.verify_started_pid(identity)
        assert caught.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_INVALID
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


@pytest.mark.parametrize("state", ["T", "t"])
def test_capture_parked_process_identity_binds_stable_parent_and_child_proc_handles(
        monkeypatch, tmp_path, state):
    pid, parent_pid = 4341, 4241
    started, parent_started = 77_001, 66_001
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid,
        started,
        state=state,
        parent_pid=parent_pid,
        process_group=pid,
        session=pid,
    ))
    real_open_proc = containment._open_proc_pid
    real_read_control = containment._read_control
    opened: list[tuple[int, int]] = []
    stat_reads: list[int] = []

    def recording_open_proc(observed_pid: int) -> int:
        fd = real_open_proc(observed_pid)
        opened.append((observed_pid, fd))
        return fd

    def recording_read_control(fd: int, name: str, *args, **kwargs):
        if name == "stat":
            stat_reads.append(fd)
        return real_read_control(fd, name, *args, **kwargs)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment, "_read_control", recording_read_control)

    proof = containment.capture_parked_process_identity(
        pid, containment.ProcessIdentity(parent_pid, parent_started),
    )

    assert proof.process == containment.ProcessIdentity(pid, started)
    assert proof.parent == containment.ProcessIdentity(parent_pid, parent_started)
    assert proof.state == state
    assert repr(proof) == "ParkedProcessIdentity(verified=True)"
    rendered = repr(proof)
    for hidden in (str(pid), str(parent_pid), str(started), str(parent_started)):
        assert hidden not in rendered
    assert not hasattr(proof, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        proof.state = "S"
    assert tuple(item[0] for item in opened) == (parent_pid, pid)
    parent_fd, child_fd = opened[0][1], opened[1][1]
    assert stat_reads == [parent_fd, child_fd, child_fd, parent_fd]
    for fd in (parent_fd, child_fd):
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


def test_parked_process_identity_cannot_be_forged():
    with pytest.raises((TypeError, containment.ContainmentRefused)):
        containment.ParkedProcessIdentity(
            process=containment.ProcessIdentity(4340, 77_000),
            parent=containment.ProcessIdentity(4240, 66_000),
            state="T",
        )


@pytest.mark.parametrize("state", ["S", "R", "D"])
def test_capture_parked_process_identity_requires_both_samples_stopped(
        monkeypatch, tmp_path, state):
    pid, parent_pid = 4342, 4242
    started, parent_started = 77_002, 66_002
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid,
        started,
        state=state,
        parent_pid=parent_pid,
        process_group=pid,
        session=pid,
    ))

    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_NOT_PARKED


@pytest.mark.parametrize("state", ["Z", "X", "x"])
def test_capture_parked_process_identity_rejects_terminal_child(
        monkeypatch, tmp_path, state):
    pid, parent_pid = 4342, 4242
    started, parent_started = 77_002, 66_002
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state=state, parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))

    with pytest.raises(containment.ContainmentFailure) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_GONE


@pytest.mark.parametrize("changed_field", ["parent_pid", "process_group", "session", "pid"])
def test_capture_parked_process_identity_requires_exact_process_relationship(
        monkeypatch, tmp_path, changed_field):
    pid, parent_pid = 4343, 4243
    started, parent_started = 77_003, 66_003
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    values = {
        "pid": pid,
        "parent_pid": parent_pid,
        "process_group": pid,
        "session": pid,
    }
    values[changed_field] += 1
    if changed_field == "pid":
        # Keep the observed process internally self-consistent.  It must still bind
        # the exact numeric /proc entry requested by the parent.
        values["process_group"] += 1
        values["session"] += 1
    (process / "stat").write_text(_proc_stat(
        values["pid"],
        started,
        state="T",
        parent_pid=values["parent_pid"],
        process_group=values["process_group"],
        session=values["session"],
    ))

    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_INVALID


def test_capture_parked_process_identity_rejects_pid_reuse_between_samples(
        monkeypatch, tmp_path):
    pid, parent_pid = 4344, 4244
    started, parent_started = 77_004, 66_004
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    samples = iter((
        _proc_stat(pid, started, state="T", parent_pid=parent_pid,
                   process_group=pid, session=pid).encode("ascii"),
        _proc_stat(pid, started + 1, state="T", parent_pid=parent_pid,
                   process_group=pid, session=pid).encode("ascii"),
    ))
    child_fd = -1
    real_open_proc = containment._open_proc_pid
    real_read_control = containment._read_control

    def recording_open_proc(observed_pid: int) -> int:
        nonlocal child_fd
        fd = real_open_proc(observed_pid)
        if observed_pid == pid:
            child_fd = fd
        return fd

    def changing_stat(fd: int, name: str, *args, **kwargs):
        if name == "stat" and fd == child_fd:
            return next(samples)
        return real_read_control(fd, name, *args, **kwargs)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment, "_read_control", changing_stat)
    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_CHANGED


@pytest.mark.parametrize(
    "changed_field,changed_value",
    [
        ("state", "t"),
        ("parent_pid", 4244 + 1),
        ("process_group", 4344 + 1),
        ("session", 4344 + 1),
        ("pid", 4344 + 1),
    ],
)
def test_capture_parked_process_identity_rejects_any_child_tuple_change(
        monkeypatch, tmp_path, changed_field, changed_value):
    pid, parent_pid = 4344, 4244
    started, parent_started = 77_004, 66_004
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    first = {
        "pid": pid,
        "state": "T",
        "parent_pid": parent_pid,
        "process_group": pid,
        "session": pid,
    }
    second = dict(first)
    second[changed_field] = changed_value
    samples = iter((
        _proc_stat(
            first["pid"], started, state=first["state"],
            parent_pid=first["parent_pid"],
            process_group=first["process_group"], session=first["session"],
        ).encode("ascii"),
        _proc_stat(
            second["pid"], started, state=second["state"],
            parent_pid=second["parent_pid"],
            process_group=second["process_group"], session=second["session"],
        ).encode("ascii"),
    ))
    child_fd = -1
    real_open_proc = containment._open_proc_pid
    real_read_control = containment._read_control

    def recording_open_proc(observed_pid: int) -> int:
        nonlocal child_fd
        fd = real_open_proc(observed_pid)
        if observed_pid == pid:
            child_fd = fd
        return fd

    def changing_stat(fd: int, name: str, *args, **kwargs):
        if name == "stat" and fd == child_fd:
            return next(samples)
        return real_read_control(fd, name, *args, **kwargs)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment, "_read_control", changing_stat)
    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_CHANGED


def test_capture_parked_process_identity_rejects_parent_pid_reuse_after_child_proof(
        monkeypatch, tmp_path):
    pid, parent_pid = 4346, 4246
    started, parent_started = 77_006, 66_006
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    samples = {
        parent_pid: iter((
            _proc_stat(parent_pid, parent_started).encode("ascii"),
            _proc_stat(parent_pid, parent_started + 1).encode("ascii"),
        )),
        pid: iter((
            _proc_stat(pid, started, state="T", parent_pid=parent_pid,
                       process_group=pid, session=pid).encode("ascii"),
            _proc_stat(pid, started, state="T", parent_pid=parent_pid,
                       process_group=pid, session=pid).encode("ascii"),
        )),
    }
    fd_to_pid: dict[int, int] = {}
    real_open_proc = containment._open_proc_pid
    real_read_control = containment._read_control

    def recording_open_proc(observed_pid: int) -> int:
        fd = real_open_proc(observed_pid)
        fd_to_pid[fd] = observed_pid
        return fd

    def changing_stat(fd: int, name: str, *args, **kwargs):
        if name == "stat":
            return next(samples[fd_to_pid[fd]])
        return real_read_control(fd, name, *args, **kwargs)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment, "_read_control", changing_stat)
    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_CHANGED


def test_capture_parked_process_identity_allows_nonterminal_parent_state_drift(
        monkeypatch, tmp_path):
    pid, parent_pid = 4355, 4255
    started, parent_started = 77_015, 66_015
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    samples = {
        parent_pid: iter((
            _proc_stat(parent_pid, parent_started, state="R").encode("ascii"),
            _proc_stat(parent_pid, parent_started, state="S").encode("ascii"),
        )),
        pid: iter((
            _proc_stat(pid, started, state="T", parent_pid=parent_pid,
                       process_group=pid, session=pid).encode("ascii"),
            _proc_stat(pid, started, state="T", parent_pid=parent_pid,
                       process_group=pid, session=pid).encode("ascii"),
        )),
    }
    fd_to_pid: dict[int, int] = {}
    real_open_proc = containment._open_proc_pid
    real_read_control = containment._read_control

    def recording_open_proc(observed_pid: int) -> int:
        fd = real_open_proc(observed_pid)
        fd_to_pid[fd] = observed_pid
        return fd

    def changing_stat(fd: int, name: str, *args, **kwargs):
        if name == "stat":
            return next(samples[fd_to_pid[fd]])
        return real_read_control(fd, name, *args, **kwargs)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment, "_read_control", changing_stat)
    proof = containment.capture_parked_process_identity(
        pid, containment.ProcessIdentity(parent_pid, parent_started),
    )
    assert proof.process == containment.ProcessIdentity(pid, started)
    assert proof.parent == containment.ProcessIdentity(parent_pid, parent_started)


def test_capture_parked_process_identity_rejects_initial_parent_start_mismatch(
        monkeypatch, tmp_path):
    pid, parent_pid = 4348, 4248
    started, parent_started = 77_008, 66_008
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started + 1,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))

    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_CHANGED


def test_capture_parked_process_identity_rejects_parent_stat_pid_mismatch(
        monkeypatch, tmp_path):
    pid, parent_pid = 4351, 4251
    started, parent_started = 77_011, 66_011
    parent = _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    (parent / "stat").write_text(_proc_stat(parent_pid + 1, parent_started))
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))

    with pytest.raises(containment.ContainmentRefused) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_INVALID


@pytest.mark.parametrize("parent_state", ["Z", "X", "x"])
def test_capture_parked_process_identity_rejects_terminal_parent(
        monkeypatch, tmp_path, parent_state):
    pid, parent_pid = 4349, 4249
    started, parent_started = 77_009, 66_009
    parent = _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    (parent / "stat").write_text(_proc_stat(
        parent_pid, parent_started, state=parent_state,
    ))
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))

    with pytest.raises(containment.ContainmentFailure) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_GONE


def test_capture_parked_process_identity_rejects_missing_expected_parent(
        monkeypatch, tmp_path):
    pid, parent_pid, started = 4347, 4247, 77_007
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))

    with pytest.raises(containment.ContainmentFailure) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, 66_007),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_GONE


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stat_read", [1, 2, 3, 4])
def test_capture_parked_process_identity_closes_both_proc_handles_on_cancellation(
        monkeypatch, tmp_path, cancellation_type, stat_read):
    pid, parent_pid = 4350, 4250
    started, parent_started = 77_010, 66_010
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    cancellation = cancellation_type("cancel parked identity capture")
    real_open_proc = containment._open_proc_pid
    real_read_control = containment._read_control
    opened: list[int] = []
    reads = 0

    def recording_open_proc(observed_pid: int) -> int:
        fd = real_open_proc(observed_pid)
        opened.append(fd)
        return fd

    def interrupting_read(fd: int, name: str, *args, **kwargs):
        nonlocal reads
        if name == "stat":
            reads += 1
            if reads == stat_read:
                raise cancellation
        return real_read_control(fd, name, *args, **kwargs)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment, "_read_control", interrupting_read)
    with pytest.raises(cancellation_type) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value is cancellation
    assert len(opened) == 2
    for fd in opened:
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_read_control_close_cancellation_reconciles_transient_stat_fd(
        monkeypatch, tmp_path, cancellation_type):
    directory = tmp_path / "proc-entry"
    directory.mkdir()
    _write_control(directory, "stat", "fixture\n")
    directory_fd = os.open(directory, containment._DIR_FLAGS)
    cancellation = cancellation_type("cancel stat control close")
    real_open_control = containment._open_control
    real_close = containment.os.close
    stat_fd = -1
    close_calls = 0

    def recording_open_control(dir_fd, name, flags, **kwargs):
        nonlocal stat_fd
        fd = real_open_control(dir_fd, name, flags, **kwargs)
        if name == "stat":
            stat_fd = fd
        return fd

    def interrupt_first_close(fd: int) -> None:
        nonlocal close_calls
        if fd == stat_fd:
            close_calls += 1
            if close_calls == 1:
                raise cancellation
        real_close(fd)

    monkeypatch.setattr(containment, "_open_control", recording_open_control)
    monkeypatch.setattr(containment.os, "close", interrupt_first_close)
    try:
        with pytest.raises(cancellation_type) as caught:
            containment._read_control(
                directory_fd, "stat",
                reason=containment.ContainmentReason.PROCESS_GONE,
                failure=True,
            )
        assert caught.value is cancellation
        assert stat_fd >= 0
        assert close_calls == 1
        os.fstat(stat_fd)
    finally:
        _close_if_open(real_close, stat_fd)
        _close_if_open(real_close, directory_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_read_control_owner_entry_cancellation_closes_returned_fd(
        monkeypatch, tmp_path, cancellation_type):
    directory = tmp_path / "proc-entry-owner"
    directory.mkdir()
    _write_control(directory, "stat", "fixture\n")
    directory_fd = os.open(directory, containment._DIR_FLAGS)
    cancellation = cancellation_type("cancel control-fd ownership")
    real_open_control = containment._open_control
    real_close = containment.os.close
    opened = -1
    fired = False
    previous_trace = sys.gettrace()

    def recording_open_control(dir_fd, name, flags, **kwargs):
        nonlocal opened
        opened = real_open_control(dir_fd, name, flags, **kwargs)
        return opened

    def interrupt_after_open(frame, event, _arg):
        nonlocal fired
        claim = frame.f_locals.get("claim")
        if (not fired and event == "line"
                and frame.f_code is containment._read_control.__code__
                and frame.f_locals.get("fd") == opened
                and isinstance(claim, containment._DescriptorCloseClaim)
                and claim.fd == opened):
            fired = True
            raise cancellation
        return interrupt_after_open

    monkeypatch.setattr(containment, "_open_control", recording_open_control)
    try:
        sys.settrace(interrupt_after_open)
        with pytest.raises(cancellation_type) as caught:
            containment._read_control(directory_fd, "stat")
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, opened)
        _close_if_open(real_close, directory_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_read_control_success_cleanup_call_cancellation_closes_returned_fd(
        monkeypatch, tmp_path, cancellation_type):
    directory = tmp_path / "control-cleanup-call"
    directory.mkdir()
    _write_control(directory, "stat", "fixture\n")
    directory_fd = os.open(directory, containment._DIR_FLAGS)
    cancellation = cancellation_type("cancel successful control cleanup call")
    real_open_control = containment._open_control
    real_close = containment.os.close
    opened = -1
    fired = False
    previous_trace = sys.gettrace()

    def recording_open_control(dir_fd, name, flags, **kwargs):
        nonlocal opened
        opened = real_open_control(dir_fd, name, flags, **kwargs)
        return opened

    def interrupt_cleanup_call(frame, event, _arg):
        nonlocal fired
        claim = frame.f_locals.get("claim")
        if (not fired and event == "line"
                and frame.f_code is containment._read_control.__code__
                and frame.f_locals.get("result") == b"fixture\n"
                and frame.f_locals.get("primary") is None
                and type(claim) is containment._DescriptorCloseClaim
                and claim.fd == opened
                and claim.disposition not in containment._CLOSE_TERMINAL
                and not _descriptor_is_closed(opened)):
            fired = True
            raise cancellation
        return interrupt_cleanup_call

    monkeypatch.setattr(containment, "_open_control", recording_open_control)
    try:
        sys.settrace(interrupt_cleanup_call)
        with pytest.raises(cancellation_type) as caught:
            containment._read_control(directory_fd, "stat")
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, opened)
        _close_if_open(real_close, directory_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_cleanup_cancellation_outranks_ordinary_capture_primary(
        monkeypatch, tmp_path, cancellation_type):
    pid, started = 4370, 79_010
    _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    cancellation = cancellation_type("cancel proc cleanup after read fault")
    real_open_proc_claim = containment._open_proc_close_claim
    real_close = containment.os.close
    proc_fd = -1
    close_calls = 0

    def recording_claim(observed_pid: int, attribute: str):
        nonlocal proc_fd
        claim = real_open_proc_claim(observed_pid, attribute)
        proc_fd = claim.fd
        return claim

    def ordinary_primary(_fd: int):
        raise OSError(errno.EIO, "fixture stat read fault")

    def interrupt_first_close(fd: int) -> None:
        nonlocal close_calls
        if fd == proc_fd:
            close_calls += 1
            if close_calls == 1:
                raise cancellation
        real_close(fd)

    monkeypatch.setattr(containment, "_open_proc_close_claim", recording_claim)
    monkeypatch.setattr(containment, "_proc_start_time", ordinary_primary)
    monkeypatch.setattr(containment.os, "close", interrupt_first_close)
    try:
        with pytest.raises(cancellation_type) as caught:
            containment.capture_process_identity(pid)
        assert caught.value is cancellation
        assert close_calls == 1
        os.fstat(proc_fd)
    finally:
        _close_if_open(real_close, proc_fd)


@pytest.mark.parametrize("operation", ["capture", "bind", "verify"])
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_proc_claim_owner_entry_cancellation_closes_returned_claim(
        monkeypatch, tmp_path, operation, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, started = 4371, 79_011
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership=handle.membership,
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", process_group=pid, session=pid,
    ))
    cancellation = cancellation_type(f"cancel {operation} claim ownership")
    real_open_claim = containment._open_proc_close_claim
    real_close = containment.os.close
    opened: list[int] = []
    writes = 0
    fired = False
    previous_trace = sys.gettrace()

    def recording_claim(observed_pid: int, attribute: str):
        claim = real_open_claim(observed_pid, attribute)
        opened.append(claim.fd)
        return claim

    target = {
        "capture": containment.capture_process_identity,
        "bind": handle.bind_pid,
        "verify": handle.verify_pid,
    }[operation]
    target_code = getattr(target, "__func__", target).__code__

    def interrupt_after_claim_return(frame, event, _arg):
        nonlocal fired
        claim = frame.f_locals.get("claim")
        if (not fired and event == "line" and frame.f_code is target_code
                and isinstance(claim, containment._DescriptorCloseClaim)
                and claim.fd in opened):
            fired = True
            raise cancellation
        return interrupt_after_claim_return

    monkeypatch.setattr(containment, "_open_proc_close_claim", recording_claim)
    # The trace must fire before any migration, so this guard is only observable
    # if ownership recovery fails and execution incorrectly continues.
    real_write = containment.os.write

    def guarded_write(fd: int, payload: bytes) -> int:
        nonlocal writes
        if fd == handle._procs_write_fd:
            writes += 1
        return real_write(fd, payload)

    monkeypatch.setattr(containment.os, "write", guarded_write)
    try:
        sys.settrace(interrupt_after_claim_return)
        with pytest.raises(cancellation_type) as caught:
            target(containment.ProcessIdentity(pid, started)) if operation != "capture" else target(pid)
        assert caught.value is cancellation
        assert fired is True
        assert opened and all(_descriptor_is_closed(fd) for fd in opened)
        assert writes == 0
    finally:
        sys.settrace(previous_trace)
        for fd in opened:
            _close_if_open(real_close, fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_finish_proc_claim_cleanup_call_cancellation_closes_claim(
        monkeypatch, tmp_path, cancellation_type):
    fd = os.open(tmp_path, containment._DIR_FLAGS)
    claim = containment._new_close_claim("fixture_proc_fd", fd)
    cancellation = cancellation_type("cancel generic proc finish cleanup")
    real_close = containment.os.close
    fired = False
    previous_trace = sys.gettrace()
    result = containment.MembershipVerification(
        False, containment.ContainmentReason.PROCESS_CGROUP_MISMATCH,
    )

    def interrupt_cleanup_call(frame, event, _arg):
        nonlocal fired
        claims = frame.f_locals.get("claims")
        if (not fired and event == "line"
                and frame.f_code is containment._finish_proc_claim.__code__
                and claims == (claim,) and claim.fd == fd
                and claim.disposition not in containment._CLOSE_TERMINAL
                and not _descriptor_is_closed(fd)):
            fired = True
            raise cancellation
        return interrupt_cleanup_call

    try:
        sys.settrace(interrupt_cleanup_call)
        with pytest.raises(cancellation_type) as caught:
            containment._finish_proc_claim(
                claim, primary=None, result=result,
            )
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_parked_bind_parent_claim_entry_cancellation_closes_authority(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, parent_pid = 4372, 4272
    started, parent_started = 79_012, 68_012
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    proof = containment.capture_parked_process_identity(
        pid, containment.ProcessIdentity(parent_pid, parent_started),
    )
    cancellation = cancellation_type("cancel parked parent claim ownership")
    real_open_claim = containment._open_proc_close_claim
    real_close = containment.os.close
    opened: list[int] = []
    writes = 0
    fired = False
    previous_trace = sys.gettrace()

    def recording_claim(observed_pid: int, attribute: str):
        claim = real_open_claim(observed_pid, attribute)
        opened.append(claim.fd)
        return claim

    real_write = containment.os.write

    def guarded_write(fd: int, payload: bytes) -> int:
        nonlocal writes
        if fd == handle._procs_write_fd:
            writes += 1
        return real_write(fd, payload)

    def interrupt_after_parent_claim(frame, event, _arg):
        nonlocal fired
        claim = frame.f_locals.get("parent_claim")
        if (not fired and event == "line"
                and frame.f_code is handle.bind_parked_process.__func__.__code__
                and isinstance(claim, containment._DescriptorCloseClaim)
                and claim.fd in opened
                and frame.f_locals.get("child_claim") is None):
            fired = True
            raise cancellation
        return interrupt_after_parent_claim

    monkeypatch.setattr(containment, "_open_proc_close_claim", recording_claim)
    monkeypatch.setattr(containment.os, "write", guarded_write)
    try:
        sys.settrace(interrupt_after_parent_claim)
        with pytest.raises(cancellation_type) as caught:
            handle.bind_parked_process(proof)
        assert caught.value is cancellation
        assert fired is True
        assert opened and all(_descriptor_is_closed(fd) for fd in opened)
        assert writes == 0
    finally:
        sys.settrace(previous_trace)
        for fd in opened:
            _close_if_open(real_close, fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("target_role", ["child", "parent"])
def test_capture_proc_close_cancellation_never_retries_numeric_fd_and_drains_peer(
        monkeypatch, tmp_path, cancellation_type, target_role):
    pid, parent_pid = 4352, 4252
    started, parent_started = 77_012, 66_012
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    cancellation = cancellation_type("cancel proc descriptor close")
    real_open_proc = containment._open_proc_pid
    real_close = containment.os.close
    proc_fds: dict[str, int] = {}
    attempted: list[int] = []
    interrupted = False

    def recording_open_proc(observed_pid: int) -> int:
        fd = real_open_proc(observed_pid)
        proc_fds["parent" if observed_pid == parent_pid else "child"] = fd
        return fd

    def interrupting_close(fd: int) -> None:
        nonlocal interrupted
        if fd in proc_fds.values():
            attempted.append(fd)
        if (proc_fds.get(target_role) == fd and not interrupted):
            interrupted = True
            raise cancellation
        real_close(fd)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment.os, "close", interrupting_close)
    with pytest.raises(cancellation_type) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value is cancellation
    child_fd, parent_fd = proc_fds["child"], proc_fds["parent"]
    assert attempted == [child_fd, parent_fd]
    target_fd = proc_fds[target_role]
    peer_fd = proc_fds["parent" if target_role == "child" else "child"]
    os.fstat(target_fd)
    assert _descriptor_is_closed(peer_fd)
    real_close(target_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("target_role", ["child", "parent"])
def test_capture_proc_close_after_physical_close_never_closes_reused_directory_fd(
        monkeypatch, tmp_path, cancellation_type, target_role):
    pid, parent_pid = 4353, 4253
    started, parent_started = 77_013, 66_013
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    foreign = tmp_path / "foreign-proc-directory"
    foreign.mkdir()
    cancellation = cancellation_type("cancel after proc descriptor close")
    real_open_proc = containment._open_proc_pid
    real_close = containment.os.close
    proc_fds: dict[str, int] = {}
    attempted: list[int] = []
    replacement = -1

    def recording_open_proc(observed_pid: int) -> int:
        fd = real_open_proc(observed_pid)
        proc_fds["parent" if observed_pid == parent_pid else "child"] = fd
        return fd

    def close_then_interrupt(fd: int) -> None:
        nonlocal replacement
        if fd in proc_fds.values():
            attempted.append(fd)
        if proc_fds.get(target_role) == fd and replacement < 0:
            real_close(fd)
            candidate = os.open(foreign, containment._DIR_FLAGS)
            if candidate != fd:
                os.dup2(candidate, fd, inheritable=False)
                real_close(candidate)
            replacement = fd
            raise cancellation
        real_close(fd)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment.os, "close", close_then_interrupt)
    try:
        with pytest.raises(cancellation_type) as caught:
            containment.capture_parked_process_identity(
                pid, containment.ProcessIdentity(parent_pid, parent_started),
            )
        assert caught.value is cancellation
        assert attempted == [proc_fds["child"], proc_fds["parent"]]
        os.fstat(replacement)
        peer = proc_fds["parent" if target_role == "child" else "child"]
        with pytest.raises(OSError) as closed:
            os.fstat(peer)
        assert closed.value.errno == errno.EBADF
    finally:
        if replacement >= 0:
            real_close(replacement)


@pytest.mark.parametrize("target_role", ["child", "parent"])
def test_capture_proc_ordinary_close_fault_drains_peer_without_retry(
        monkeypatch, tmp_path, target_role):
    pid, parent_pid = 4354, 4254
    started, parent_started = 77_014, 66_014
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    real_open_proc = containment._open_proc_pid
    real_close = containment.os.close
    proc_fds: dict[str, int] = {}
    attempted: list[int] = []

    def recording_open_proc(observed_pid: int) -> int:
        fd = real_open_proc(observed_pid)
        proc_fds["parent" if observed_pid == parent_pid else "child"] = fd
        return fd

    def faulty_close(fd: int) -> None:
        if fd in proc_fds.values():
            attempted.append(fd)
        if proc_fds.get(target_role) == fd:
            raise OSError(errno.EIO, "fixture")
        real_close(fd)

    monkeypatch.setattr(containment, "_open_proc_pid", recording_open_proc)
    monkeypatch.setattr(containment.os, "close", faulty_close)
    with pytest.raises(containment.ContainmentFailure) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
    assert caught.value.os_errno == errno.EIO
    assert attempted == [proc_fds["child"], proc_fds["parent"]]
    failed_fd = proc_fds[target_role]
    peer = proc_fds["parent" if target_role == "child" else "child"]
    os.fstat(failed_fd)
    with pytest.raises(OSError) as closed:
        os.fstat(peer)
    assert closed.value.errno == errno.EBADF
    real_close(failed_fd)


@pytest.mark.parametrize("raw", [
    b"malformed\n",
    b"4345 (unterminated T 4245 4345 4345\n",
    b"4345 (fixture) T 4245 4345 4345 " + b"0 " * 15 + b"-1\n",
    b"4345 (fixture) \xff 4245 4345 4345 " + b"0 " * 20 + b"\n",
])
def test_capture_parked_process_identity_rejects_malformed_stat(
        monkeypatch, tmp_path, raw):
    pid, parent_pid, parent_started = 4345, 4245, 66_005
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=77_005,
        membership="/delegated",
    )
    (process / "stat").write_bytes(raw)

    with pytest.raises(containment.ContainmentFailure) as caught:
        containment.capture_parked_process_identity(
            pid, containment.ProcessIdentity(parent_pid, parent_started),
        )
    assert caught.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_INVALID


def test_bind_parked_process_requires_private_proof_and_revalidates_before_one_bind(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, parent_pid = 4361, 4261
    started, parent_started = 78_001, 67_001
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    expected_parent = containment.ProcessIdentity(parent_pid, parent_started)
    proof = containment.capture_parked_process_identity(pid, expected_parent)
    real_write = containment.os.write
    bind_writes: list[bytes] = []

    def model_migration(fd: int, payload: bytes) -> int:
        written = real_write(fd, payload)
        if fd == handle._procs_write_fd:
            bind_writes.append(payload)
            (leaf / "cgroup.procs").write_bytes(payload)
            (process / "cgroup").write_text(f"0::{handle.membership}\n")
        return written

    monkeypatch.setattr(containment.os, "write", model_migration)
    try:
        with pytest.raises(containment.ContainmentRefused) as not_proof:
            handle.bind_parked_process(proof.process)
        assert not_proof.value.reason is containment.ContainmentReason.PROCESS_IDENTITY_INVALID
        assert bind_writes == []

        result = handle.bind_parked_process(proof)
        assert result == containment.MembershipVerification(
            True, containment.ContainmentReason.VERIFIED,
        )
        assert bind_writes == [f"{pid}\n".encode("ascii")]

        with pytest.raises(containment.ContainmentRefused) as replay:
            handle.bind_parked_process(proof)
        assert replay.value.reason is containment.ContainmentReason.BINDING_ALREADY_USED
        assert bind_writes == [f"{pid}\n".encode("ascii")]
    finally:
        handle.close()


@pytest.mark.parametrize("relationship", ["parent_pid", "process_group", "session"])
def test_bind_parked_process_rejects_relationship_drift_after_recapture(
        monkeypatch, tmp_path, relationship):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, parent_pid = 4368, 4268
    started, parent_started = 78_008, 67_008
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    valid_stat = _proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    )
    (process / "stat").write_text(valid_stat)
    proof = containment.capture_parked_process_identity(
        pid, containment.ProcessIdentity(parent_pid, parent_started),
    )
    real_write = containment.os.write
    bind_writes = 0
    fired = False
    previous_trace = sys.gettrace()
    bind_code = handle.bind_parked_process.__func__.__code__

    def drift_after_last_prewrite_observation(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line" and frame.f_code is bind_code
                and frame.f_locals.get("child_before") is not None
                and handle._binding_attempted is False):
            values = {
                "parent_pid": parent_pid,
                "process_group": pid,
                "session": pid,
            }
            values[relationship] += 1
            (process / "stat").write_text(_proc_stat(
                pid, started, state="T", **values,
            ))
            fired = True
        return drift_after_last_prewrite_observation

    def recording_write(fd: int, payload: bytes) -> int:
        nonlocal bind_writes
        if fd == handle._procs_write_fd:
            bind_writes += 1
        return real_write(fd, payload)

    monkeypatch.setattr(containment.os, "write", recording_write)
    try:
        sys.settrace(drift_after_last_prewrite_observation)
        result = handle.bind_parked_process(proof)
        assert fired is True
        assert result == containment.MembershipVerification(
            False, containment.ContainmentReason.PROCESS_IDENTITY_CHANGED,
        )
        assert bind_writes == 1
    finally:
        sys.settrace(previous_trace)
        handle.close()


@pytest.mark.parametrize(
    "drift", ["continued", "stopped_state", "reparented", "reused", "parent_reused"],
)
def test_bind_parked_process_rejects_stale_proof_without_binding(
        monkeypatch, tmp_path, drift):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, parent_pid = 4362, 4262
    started, parent_started = 78_002, 67_002
    parent = _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    proof = containment.capture_parked_process_identity(
        pid, containment.ProcessIdentity(parent_pid, parent_started),
    )
    if drift == "continued":
        (process / "stat").write_text(_proc_stat(
            pid, started, state="S", parent_pid=parent_pid,
            process_group=pid, session=pid,
        ))
    elif drift == "stopped_state":
        (process / "stat").write_text(_proc_stat(
            pid, started, state="t", parent_pid=parent_pid,
            process_group=pid, session=pid,
        ))
    elif drift == "reparented":
        (process / "stat").write_text(_proc_stat(
            pid, started, state="T", parent_pid=parent_pid + 1,
            process_group=pid, session=pid,
        ))
    elif drift == "reused":
        (process / "stat").write_text(_proc_stat(
            pid, started + 1, state="T", parent_pid=parent_pid,
            process_group=pid, session=pid,
        ))
    else:
        (parent / "stat").write_text(_proc_stat(parent_pid, parent_started + 1))
    real_write = containment.os.write
    bind_writes: list[bytes] = []

    def recording_write(fd: int, payload: bytes) -> int:
        if fd == handle._procs_write_fd:
            bind_writes.append(payload)
        return real_write(fd, payload)

    monkeypatch.setattr(containment.os, "write", recording_write)
    try:
        with pytest.raises(containment.ContainmentRefused):
            handle.bind_parked_process(proof)
        assert bind_writes == []
        assert not (leaf / "cgroup.procs").read_bytes()
    finally:
        handle.close()


def test_bind_parked_process_refuses_named_leaf_swap_before_migration(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, parent_pid = 4364, 4264
    started, parent_started = 78_004, 67_004
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    proof = containment.capture_parked_process_identity(
        pid, containment.ProcessIdentity(parent_pid, parent_started),
    )
    original = leaf.with_name("original-leaf-before-bind")
    leaf.rename(original)
    leaf.mkdir()
    real_write = containment.os.write
    bind_calls = 0

    def recording_write(fd: int, payload: bytes) -> int:
        nonlocal bind_calls
        if fd == handle._procs_write_fd:
            bind_calls += 1
        return real_write(fd, payload)

    monkeypatch.setattr(containment.os, "write", recording_write)
    try:
        result = handle.bind_parked_process(proof)
        assert result == containment.MembershipVerification(
            False, containment.ContainmentReason.LEAF_IDENTITY_CHANGED,
        )
        assert bind_calls == 0
        assert handle._binding_attempted is False
    finally:
        handle.close()


def test_bind_parked_process_rechecks_named_leaf_identity_after_migration(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, parent_pid = 4365, 4265
    started, parent_started = 78_005, 67_005
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    proof = containment.capture_parked_process_identity(
        pid, containment.ProcessIdentity(parent_pid, parent_started),
    )
    real_write = containment.os.write
    bind_calls = 0

    def migrate_then_swap(fd: int, payload: bytes) -> int:
        nonlocal bind_calls
        written = real_write(fd, payload)
        if fd == handle._procs_write_fd:
            bind_calls += 1
            (leaf / "cgroup.procs").write_bytes(payload)
            (process / "cgroup").write_text(f"0::{handle.membership}\n")
            original = leaf.with_name("original-leaf-after-bind")
            leaf.rename(original)
            leaf.mkdir()
        return written

    monkeypatch.setattr(containment.os, "write", migrate_then_swap)
    try:
        result = handle.bind_parked_process(proof)
        assert result == containment.MembershipVerification(
            False, containment.ContainmentReason.LEAF_IDENTITY_CHANGED,
        )
        assert bind_calls == 1
        assert handle._binding_attempted is True
    finally:
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after_physical_write", [False, True])
def test_bind_parked_process_cancellation_consumes_the_single_bind_attempt(
        monkeypatch, tmp_path, cancellation_type, after_physical_write):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path / "cgroup-fixture")
    pid, parent_pid = 4363, 4263
    started, parent_started = 78_003, 67_003
    _install_fake_proc(
        monkeypatch, tmp_path, pid=parent_pid, start_time=parent_started,
        membership="/delegated",
    )
    process = _install_fake_proc(
        monkeypatch, tmp_path, pid=pid, start_time=started,
        membership="/delegated",
    )
    (process / "stat").write_text(_proc_stat(
        pid, started, state="T", parent_pid=parent_pid,
        process_group=pid, session=pid,
    ))
    proof = containment.capture_parked_process_identity(
        pid, containment.ProcessIdentity(parent_pid, parent_started),
    )
    cancellation = cancellation_type("cancel cgroup bind")
    real_write = containment.os.write
    bind_calls = 0

    def interrupting_write(fd: int, payload: bytes) -> int:
        nonlocal bind_calls
        if fd != handle._procs_write_fd:
            return real_write(fd, payload)
        bind_calls += 1
        if after_physical_write:
            real_write(fd, payload)
        raise cancellation

    monkeypatch.setattr(containment.os, "write", interrupting_write)
    try:
        with pytest.raises(cancellation_type) as caught:
            handle.bind_parked_process(proof)
        assert caught.value is cancellation
        assert bind_calls == 1

        with pytest.raises(containment.ContainmentRefused) as replay:
            handle.bind_parked_process(proof)
        assert replay.value.reason is containment.ContainmentReason.BINDING_ALREADY_USED
        assert bind_calls == 1
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


def test_expired_settlement_still_invokes_kill_once_and_samples_populated(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "cgroup.events").write_text("populated 1\n")
    real_write = containment.os.write
    kill_calls: list[bytes] = []
    populated_calls = 0

    def recording_write(fd: int, payload: bytes) -> int:
        if fd == handle._kill_fd:
            kill_calls.append(payload)
        return real_write(fd, payload)

    def recording_populated() -> bool:
        nonlocal populated_calls
        populated_calls += 1
        return True

    monkeypatch.setattr(containment.os, "write", recording_write)
    monkeypatch.setattr(containment.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(handle, "populated", recording_populated)
    try:
        result = handle.kill_settle_remove(10.0)
        assert result == containment.ContainmentSettlement(
            True, False, False, containment.ContainmentReason.DEADLINE_EXPIRED,
        )
        assert kill_calls == [b"1\n"]
        assert populated_calls == 1
    finally:
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after_physical_write", [False, True])
def test_kill_cancellation_is_committed_once_and_never_retried(
        monkeypatch, tmp_path, cancellation_type, after_physical_write):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "cgroup.events").write_text("populated 1\n")
    cancellation = cancellation_type("cancel cgroup kill")
    real_write = containment.os.write
    kill_calls = 0
    populated_calls = 0

    def interrupting_write(fd: int, payload: bytes) -> int:
        nonlocal kill_calls
        if fd != handle._kill_fd:
            return real_write(fd, payload)
        kill_calls += 1
        if after_physical_write:
            real_write(fd, payload)
        raise cancellation

    def recording_populated() -> bool:
        nonlocal populated_calls
        populated_calls += 1
        return True

    monkeypatch.setattr(containment.os, "write", interrupting_write)
    monkeypatch.setattr(containment.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(handle, "populated", recording_populated)
    try:
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(10.0)
        assert caught.value is cancellation

        result = handle.kill_settle_remove(10.0)
        assert result == containment.ContainmentSettlement(
            False, False, False, containment.ContainmentReason.KILL_AMBIGUOUS,
        )
        assert kill_calls == 1
        assert populated_calls == 2
    finally:
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["prewrite", "postwrite"])
def test_kill_line_cancellation_after_attempt_commit_is_ambiguous_and_sampled(
        monkeypatch, tmp_path, cancellation_type, seam):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "cgroup.events").write_text("populated 1\n")
    cancellation = cancellation_type(f"cancel kill {seam}")
    real_write = containment.os.write
    kill_writes = 0
    populated_calls = 0
    fired = False
    previous_trace = sys.gettrace()

    def recording_write(fd: int, payload: bytes) -> int:
        nonlocal kill_writes
        if fd == handle._kill_fd:
            kill_writes += 1
        return real_write(fd, payload)

    def recording_populated() -> bool:
        nonlocal populated_calls
        populated_calls += 1
        return True

    def interrupt_kill_transition(frame, event, _arg):
        nonlocal fired
        if (fired or event != "line"
                or frame.f_code is not handle._request_kill_once.__func__.__code__
                or handle._kill_state != "attempting"):
            return interrupt_kill_transition
        written = frame.f_locals.get("written")
        if ((seam == "prewrite" and "written" not in frame.f_locals)
                or (seam == "postwrite" and written == 2)):
            fired = True
            raise cancellation
        return interrupt_kill_transition

    monkeypatch.setattr(containment.os, "write", recording_write)
    monkeypatch.setattr(handle, "populated", recording_populated)
    monkeypatch.setattr(containment.time, "monotonic", lambda: 10.0)
    try:
        sys.settrace(interrupt_kill_transition)
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(10.0)
        assert caught.value is cancellation
        assert fired is True
        expected_writes = 0 if seam == "prewrite" else 1
        assert kill_writes == expected_writes
        assert populated_calls == 1

        result = handle.kill_settle_remove(10.0)
        assert result == containment.ContainmentSettlement(
            False, False, False, containment.ContainmentReason.KILL_AMBIGUOUS,
        )
        assert kill_writes == expected_writes
        assert populated_calls == 2
    finally:
        sys.settrace(previous_trace)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_kill_caller_boundary_cancellation_samples_after_conclusive_write(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "cgroup.events").write_text("populated 1\n")
    cancellation = cancellation_type("cancel after conclusive kill write")
    populated_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    helper_code = handle._request_kill_and_sample_once.__func__.__code__

    def recording_populated() -> bool:
        nonlocal populated_calls
        populated_calls += 1
        return True

    def interrupt_before_sample(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is helper_code
                and handle._kill_state == "write_complete"
                and populated_calls == 0):
            fired = True
            raise cancellation
        return interrupt_before_sample

    monkeypatch.setattr(handle, "populated", recording_populated)
    monkeypatch.setattr(containment.time, "monotonic", lambda: 10.0)
    try:
        sys.settrace(interrupt_before_sample)
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(10.0)
        assert caught.value is cancellation
        assert fired is True
        assert populated_calls == 1
        replay = handle.kill_settle_remove(10.0)
        assert replay.killed is True
        assert populated_calls == 2
    finally:
        sys.settrace(previous_trace)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_kill_post_population_cancellation_does_not_repeat_committed_sample(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "cgroup.events").write_text("populated 1\n")
    cancellation = cancellation_type("cancel after population sample")
    populated_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    helper_code = handle._request_kill_and_sample_once.__func__.__code__

    def recording_populated() -> bool:
        nonlocal populated_calls
        populated_calls += 1
        return True

    def interrupt_after_sample(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line" and frame.f_code is helper_code
                and frame.f_locals.get("occupied") is True
                and populated_calls == 1):
            fired = True
            raise cancellation
        return interrupt_after_sample

    monkeypatch.setattr(handle, "populated", recording_populated)
    monkeypatch.setattr(containment.time, "monotonic", lambda: 10.0)
    try:
        sys.settrace(interrupt_after_sample)
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(10.0)
        assert caught.value is cancellation
        assert fired is True
        assert populated_calls == 1
        assert handle._kill_state == "write_complete"
        assert handle._kill_sent is True
        assert (leaf / "cgroup.kill").read_bytes() == b"1\n"

        replay = handle.kill_settle_remove(10.0)
        assert replay.killed is True
        assert populated_calls == 2
    finally:
        sys.settrace(previous_trace)
        handle.close()


def test_short_kill_write_is_failed_and_never_retried(monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "cgroup.events").write_text("populated 1\n")
    real_write = containment.os.write
    kill_calls = 0

    def short_write(fd: int, payload: bytes) -> int:
        nonlocal kill_calls
        if fd == handle._kill_fd:
            kill_calls += 1
            return 1
        return real_write(fd, payload)

    monkeypatch.setattr(containment.os, "write", short_write)
    try:
        first = handle.kill_settle_remove(time.monotonic() + 1)
        replay = handle.kill_settle_remove(time.monotonic() + 1)
        assert first.reason is replay.reason is containment.ContainmentReason.KILL_FAILED
        assert first.killed is replay.killed is False
        assert kill_calls == 1
    finally:
        handle.close()


def test_ordinary_exception_from_kill_write_is_failed_and_never_retried(
        monkeypatch, tmp_path):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    real_write = containment.os.write
    kill_calls = 0
    populated_calls = 0

    def ordinary_fault(fd: int, payload: bytes) -> int:
        nonlocal kill_calls
        if fd == handle._kill_fd:
            kill_calls += 1
            raise RuntimeError("fixture ordinary kill-write fault")
        return real_write(fd, payload)

    def recording_populated() -> bool:
        nonlocal populated_calls
        populated_calls += 1
        return True

    monkeypatch.setattr(containment.os, "write", ordinary_fault)
    monkeypatch.setattr(handle, "populated", recording_populated)
    monkeypatch.setattr(containment.time, "monotonic", lambda: 10.0)
    try:
        first = handle.kill_settle_remove(10.0)
        assert first == containment.ContainmentSettlement(
            False, False, False, containment.ContainmentReason.KILL_FAILED,
        )
        assert kill_calls == 1
        assert populated_calls == 1

        replay = handle.kill_settle_remove(10.0)
        assert replay == first
        assert kill_calls == 1
        assert populated_calls == 2
    finally:
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_rmdir_success_and_removed_fact_have_one_replay_honest_boundary(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    cancellation = cancellation_type("cancel after successful cgroup removal")
    rmdir_complete = False
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._kill_settle_remove_transaction.__func__.__code__
    first_result = None
    caught_cancellation = None

    def recording_rmdir(name: str, parent_fd: int) -> None:
        nonlocal rmdir_complete
        _fake_cgroup_rmdir(name, parent_fd)
        rmdir_complete = True

    def interrupt_visible_remove_gap(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line" and frame.f_code is transaction_code
                and rmdir_complete and handle._removed is False):
            fired = True
            raise cancellation
        return interrupt_visible_remove_gap

    monkeypatch.setattr(containment, "_rmdir_cgroup", recording_rmdir)
    try:
        sys.settrace(interrupt_visible_remove_gap)
        try:
            first_result = handle.kill_settle_remove(time.monotonic() + 1)
        except cancellation_type as exc:
            caught_cancellation = exc
        finally:
            sys.settrace(previous_trace)

        assert rmdir_complete is True
        assert not leaf.exists()
        if fired:
            assert caught_cancellation is cancellation
            assert handle._removed is True
            replay = handle.kill_settle_remove(time.monotonic() + 1)
            assert replay == containment.ContainmentSettlement(
                True, True, True, containment.ContainmentReason.SETTLED,
            )
        else:
            assert caught_cancellation is None
            assert first_result == containment.ContainmentSettlement(
                True, True, True, containment.ContainmentReason.SETTLED,
            )
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_removed_fact_to_terminal_cache_cancellation_drains_and_replays_truth(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    cancellation = cancellation_type("cancel after durable removal fact")
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._kill_settle_remove_transaction.__func__.__code__

    def interrupt_after_removed_fact(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line" and frame.f_code is transaction_code
                and handle._removed is True
                and handle._settlement_cache is None
                and handle._closed is False):
            fired = True
            raise cancellation
        return interrupt_after_removed_fact

    try:
        sys.settrace(interrupt_after_removed_fact)
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert not leaf.exists()
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert handle._closed is True

        try:
            replay = handle.kill_settle_remove(time.monotonic() + 1)
        except containment.ContainmentFailure as exc:
            assert exc.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
            with pytest.raises(containment.ContainmentFailure) as repeated:
                handle.kill_settle_remove(time.monotonic() + 1)
            assert repeated.value.reason is exc.reason
            assert repeated.value.os_errno == exc.os_errno
        except containment.ContainmentRefused as exc:
            pytest.fail(f"terminal removal replay was refused as {exc.reason.value}")
        else:
            assert replay == containment.ContainmentSettlement(
                True, True, True, containment.ContainmentReason.SETTLED,
            )
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_removed_settlement_close_primary_then_handler_cancellation_replays_truth(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    ordinary = RuntimeError("fixture pre-action settlement close fault")
    cancellation = cancellation_type("cancel removed-settlement recovery")
    real_close = handle.close
    close_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._kill_settle_remove_transaction.__func__.__code__

    def ordinary_first_close() -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise ordinary
        real_close()

    def interrupt_first_removed_handler_line(frame, event, _arg):
        nonlocal fired
        attempt = frame.f_locals.get("remove_attempt")
        if (not fired and event == "line" and frame.f_code is transaction_code
                and frame.f_locals.get("exc") is ordinary
                and type(attempt) is containment._RemoveAttempt
                and attempt.state == "removed" and handle._removed is True
                and handle._settlement_cache is None
                and handle._closed is False and close_calls == 1):
            fired = True
            raise cancellation
        return interrupt_first_removed_handler_line

    monkeypatch.setattr(handle, "close", ordinary_first_close)
    try:
        sys.settrace(interrupt_first_removed_handler_line)
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert not leaf.exists()
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)
        assert handle._closed is True

        try:
            replay = handle.kill_settle_remove(time.monotonic() + 1)
        except containment.ContainmentFailure as exc:
            assert exc.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
            with pytest.raises(containment.ContainmentFailure) as repeated:
                handle.kill_settle_remove(time.monotonic() + 1)
            assert repeated.value.reason is exc.reason
            assert repeated.value.os_errno == exc.os_errno
        except containment.ContainmentRefused as exc:
            pytest.fail(f"removed settlement replay was refused as {exc.reason.value}")
        else:
            assert replay == containment.ContainmentSettlement(
                True, True, True, containment.ContainmentReason.SETTLED,
            )
    finally:
        sys.settrace(previous_trace)
        try:
            real_close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


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


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_root_walk_frame_cleanup_entry_cancellation_drains_pre_stack_authority(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    cancellation = cancellation_type("cancel root pre-stack cleanup")
    ordinary_primary = RuntimeError("fixture root append fault")
    real_scandir = containment.os.scandir
    real_close = containment.os.close
    root_frame = None
    root_fd = -1
    root_iterator = None
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._remove_descendants_owned.__func__.__code__

    class RecordingIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.wrapped)

        def close(self):
            self.wrapped.close()
            self.closed = True

    def recording_scandir(fd: int):
        nonlocal root_iterator
        root_iterator = RecordingIterator(real_scandir(fd))
        return root_iterator

    def ordinary_append_fault(_stack, frame) -> None:
        nonlocal root_frame, root_fd
        root_frame = frame
        root_fd = frame.fd
        raise ordinary_primary

    def interrupt_cleanup_entry(frame, event, _arg):
        nonlocal fired
        owned = frame.f_locals.get("root_frame")
        if (not fired and event == "line" and frame.f_code is transaction_code
                and frame.f_locals.get("exc") is ordinary_primary
                and owned is root_frame and root_frame is not None
                and frame.f_locals.get("stack") == []
                and root_fd >= 0 and not _descriptor_is_closed(root_fd)):
            fired = True
            raise cancellation
        return interrupt_cleanup_entry

    monkeypatch.setattr(containment.os, "scandir", recording_scandir)
    monkeypatch.setattr(containment, "_append_walk_frame", ordinary_append_fault)
    try:
        sys.settrace(interrupt_cleanup_entry)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert root_frame is not None
        assert _descriptor_is_closed(root_fd)
        assert root_iterator is not None and root_iterator.closed is True
    finally:
        sys.settrace(previous_trace)
        if root_iterator is not None:
            root_iterator.close()
        if root_frame is not None:
            _close_if_open(real_close, root_fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_child_walk_frame_cleanup_entry_cancellation_drains_pre_stack_authority(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "child").mkdir()
    cancellation = cancellation_type("cancel child pre-stack cleanup")
    ordinary_primary = RuntimeError("fixture child append fault")
    real_append = containment._append_walk_frame
    real_scandir = containment.os.scandir
    real_close = containment.os.close
    frames: list[containment._WalkFrame] = []
    frame_fds: list[int] = []
    iterators = []
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._remove_descendants_owned.__func__.__code__

    class RecordingIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.wrapped)

        def close(self):
            self.wrapped.close()
            self.closed = True

    def recording_scandir(fd: int):
        iterator = RecordingIterator(real_scandir(fd))
        iterators.append(iterator)
        return iterator

    def fail_child_append(stack, frame) -> None:
        frames.append(frame)
        frame_fds.append(frame.fd)
        if len(frames) == 2:
            raise ordinary_primary
        real_append(stack, frame)

    def interrupt_cleanup_entry(frame, event, _arg):
        nonlocal fired
        child_frame = frame.f_locals.get("child_frame")
        stack = frame.f_locals.get("stack")
        if (not fired and event == "line" and frame.f_code is transaction_code
                and frame.f_locals.get("exc") is ordinary_primary
                and len(frames) == 2 and child_frame is frames[1]
                and isinstance(stack, list) and child_frame not in stack
                and not _descriptor_is_closed(frame_fds[1])):
            fired = True
            raise cancellation
        return interrupt_cleanup_entry

    monkeypatch.setattr(containment.os, "scandir", recording_scandir)
    monkeypatch.setattr(containment, "_append_walk_frame", fail_child_append)
    try:
        sys.settrace(interrupt_cleanup_entry)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert len(frames) == 2 and len(iterators) == 2
        assert all(_descriptor_is_closed(fd) for fd in frame_fds)
        assert all(iterator.closed for iterator in iterators)
    finally:
        sys.settrace(previous_trace)
        for iterator in iterators:
            iterator.close()
        for fd in frame_fds:
            _close_if_open(real_close, fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("fault_at", ["root", "child"])
def test_traversal_outer_owned_frames_cleanup_entry_drains_after_append_fault(
        monkeypatch, tmp_path, cancellation_type, fault_at):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    if fault_at == "child":
        (leaf / "child").mkdir()
    cancellation = cancellation_type(f"cancel outer {fault_at} cleanup")
    ordinary_primary = RuntimeError(f"fixture {fault_at} append fault")
    real_append = containment._append_walk_frame
    real_scandir = containment.os.scandir
    real_close = containment.os.close
    frames: list[containment._WalkFrame] = []
    frame_fds: list[int] = []
    iterators = []
    fired = False
    ordinary_raised = False
    previous_trace = sys.gettrace()
    transaction_code = handle._remove_descendants_owned.__func__.__code__

    class RecordingIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.wrapped)

        def close(self):
            self.wrapped.close()
            self.closed = True

    def recording_scandir(fd: int):
        iterator = RecordingIterator(real_scandir(fd))
        iterators.append(iterator)
        return iterator

    def ordinary_append_fault(stack, frame) -> None:
        nonlocal ordinary_raised
        frames.append(frame)
        frame_fds.append(frame.fd)
        target_call = 1 if fault_at == "root" else 2
        if len(frames) == target_call:
            ordinary_raised = True
            raise ordinary_primary
        real_append(stack, frame)

    def interrupt_outer_cleanup(frame, event, _arg):
        nonlocal fired
        owned = frame.f_locals.get("owned_frames")
        stack = frame.f_locals.get("stack")
        root_recovery_entry = (
            fault_at == "root"
            and frame.f_locals.get("primary") is ordinary_primary
            and "cleanup_cancellation" in frame.f_locals
            and frame.f_locals["cleanup_cancellation"] is None
        )
        child_finally_entry = (
            fault_at == "child" and ordinary_raised
            and "cleanup_cancellation" in frame.f_locals
            and frame.f_locals["cleanup_cancellation"] is None
            and isinstance(frame.f_locals.get("interrupted_frames"), list)
            and isinstance(stack, list) and len(frames) == 2
            and frames[0] in stack and frames[1] not in stack
        )
        if (not fired and event == "line" and frame.f_code is transaction_code
                and (root_recovery_entry or child_finally_entry)
                and isinstance(owned, list) and frames
                and all(candidate in owned for candidate in frames)
                and all(not _descriptor_is_closed(fd) for fd in frame_fds)
                and iterators and all(not iterator.closed for iterator in iterators)):
            fired = True
            raise cancellation
        return interrupt_outer_cleanup

    monkeypatch.setattr(containment.os, "scandir", recording_scandir)
    monkeypatch.setattr(containment, "_append_walk_frame", ordinary_append_fault)
    try:
        sys.settrace(interrupt_outer_cleanup)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert frame_fds and all(_descriptor_is_closed(fd) for fd in frame_fds)
        assert iterators and all(iterator.closed for iterator in iterators)
    finally:
        sys.settrace(previous_trace)
        for iterator in iterators:
            iterator.close()
        for fd in frame_fds:
            _close_if_open(real_close, fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_root_append_primary_first_outer_recovery_line_drains_frame(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    ordinary = RuntimeError("fixture root append primary")
    cancellation = cancellation_type("cancel first root recovery line")
    real_scandir = containment.os.scandir
    real_close = containment.os.close
    root_frame: containment._WalkFrame | None = None
    root_fd = -1
    root_iterator = None
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._remove_descendants_owned.__func__.__code__

    class RecordingIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.wrapped)

        def close(self):
            self.wrapped.close()
            self.closed = True

    def recording_scandir(fd: int):
        nonlocal root_iterator
        root_iterator = RecordingIterator(real_scandir(fd))
        return root_iterator

    def fail_root_append(_stack, frame) -> None:
        nonlocal root_frame, root_fd
        root_frame = frame
        root_fd = frame.fd
        raise ordinary

    def interrupt_first_outer_recovery_line(frame, event, _arg):
        nonlocal fired
        owned = frame.f_locals.get("owned_frames")
        if (not fired and event == "line" and frame.f_code is transaction_code
                and frame.f_locals.get("primary") is ordinary
                and frame.f_locals.get("cleanup_complete", False) is False
                and frame.f_locals.get("cleanup_cancellation") is None
                and root_frame is not None and root_fd >= 0
                and isinstance(owned, list) and root_frame in owned
                and not _descriptor_is_closed(root_fd)
                and root_iterator is not None and not root_iterator.closed):
            fired = True
            raise cancellation
        return interrupt_first_outer_recovery_line

    monkeypatch.setattr(containment.os, "scandir", recording_scandir)
    monkeypatch.setattr(containment, "_append_walk_frame", fail_root_append)
    try:
        sys.settrace(interrupt_first_outer_recovery_line)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(root_fd)
        assert root_iterator is not None and root_iterator.closed is True
    finally:
        sys.settrace(previous_trace)
        if root_iterator is not None:
            root_iterator.wrapped.close()
        if root_fd >= 0:
            _close_if_open(real_close, root_fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_internal_main_traversal_try_header_cancellation_drains_owned_root(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    cancellation = cancellation_type("cancel internal main traversal try")
    real_append = containment._append_walk_frame
    real_scandir = containment.os.scandir
    real_close = containment.os.close
    frames: list[containment._WalkFrame] = []
    frame_fds: list[int] = []
    iterators = []
    fired = False
    previous_trace = sys.gettrace()
    transaction = containment.DirectCgroupV2._remove_descendants_owned
    main_try_line = _source_line(transaction, "while stack:") - 1

    class RecordingIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.wrapped)

        def close(self):
            self.wrapped.close()
            self.closed = True

    def recording_scandir(fd: int):
        iterator = RecordingIterator(real_scandir(fd))
        iterators.append(iterator)
        return iterator

    def recording_append(stack, frame) -> None:
        frames.append(frame)
        frame_fds.append(frame.fd)
        real_append(stack, frame)

    def interrupt_main_try(frame, event, _arg):
        nonlocal fired
        owned = frame.f_locals.get("owned_frames")
        stack = frame.f_locals.get("stack")
        if (not fired and event == "line"
                and frame.f_code is transaction.__code__
                and frame.f_lineno == main_try_line
                and len(frames) == 1 and isinstance(owned, list)
                and frames[0] in owned
                and isinstance(stack, list) and stack == frames
                and len(iterators) == 1 and not iterators[0].closed
                and not _descriptor_is_closed(frame_fds[0])):
            fired = True
            raise cancellation
        return interrupt_main_try

    monkeypatch.setattr(containment.os, "scandir", recording_scandir)
    monkeypatch.setattr(containment, "_append_walk_frame", recording_append)
    try:
        sys.settrace(interrupt_main_try)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert len(frames) == len(frame_fds) == len(iterators) == 1
        assert _descriptor_is_closed(frame_fds[0])
        assert iterators[0].closed is True
        assert frames[0].close_claim is not None
        assert frames[0].close_claim.attempts == 1
        assert frames[0].close_claim.disposition in containment._CLOSE_TERMINAL
    finally:
        sys.settrace(previous_trace)
        for iterator in iterators:
            iterator.wrapped.close()
        for fd in frame_fds:
            _close_if_open(real_close, fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_internal_final_cleanup_try_header_cancellation_drains_stacked_ledger(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "child" / "grandchild").mkdir(parents=True)
    ordinary = RuntimeError("fixture stacked traversal clock primary")
    cancellation = cancellation_type("cancel internal final cleanup try")
    real_append = containment._append_walk_frame
    real_scandir = containment.os.scandir
    real_close = containment.os.close
    frames: list[containment._WalkFrame] = []
    frame_fds: list[int] = []
    iterators = []
    ready = False
    clock_failed = False
    fired = False
    previous_trace = sys.gettrace()
    transaction = containment.DirectCgroupV2._remove_descendants_owned
    cleanup_try_line = _source_line(
        transaction, "cleanup_cancellation: BaseException | None = None",
        occurrence=2,
    ) - 1

    class RecordingIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.wrapped)

        def close(self):
            self.wrapped.close()
            self.closed = True

    def recording_scandir(fd: int):
        iterator = RecordingIterator(real_scandir(fd))
        iterators.append(iterator)
        return iterator

    def recording_append(stack, frame) -> None:
        nonlocal ready
        frames.append(frame)
        frame_fds.append(frame.fd)
        real_append(stack, frame)
        if len(frames) == 3:
            ready = True

    def fail_clock_after_stack():
        nonlocal clock_failed
        if ready:
            clock_failed = True
            raise ordinary
        return 10.0

    def interrupt_cleanup_try(frame, event, _arg):
        nonlocal fired
        owned = frame.f_locals.get("owned_frames")
        if (not fired and event == "line"
                and frame.f_code is transaction.__code__
                and frame.f_lineno == cleanup_try_line
                and clock_failed and len(frames) == 3
                and isinstance(owned, list)
                and all(candidate in owned for candidate in frames)
                and all(not _descriptor_is_closed(fd) for fd in frame_fds)
                and all(not iterator.closed for iterator in iterators)):
            fired = True
            raise cancellation
        return interrupt_cleanup_try

    monkeypatch.setattr(containment.os, "scandir", recording_scandir)
    monkeypatch.setattr(containment, "_append_walk_frame", recording_append)
    monkeypatch.setattr(containment.time, "monotonic", fail_clock_after_stack)
    try:
        sys.settrace(interrupt_cleanup_try)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, 11.0)
        assert caught.value is cancellation
        assert fired is True and clock_failed is True
        assert len(frames) == len(frame_fds) == len(iterators) == 3
        assert all(_descriptor_is_closed(fd) for fd in frame_fds)
        assert all(iterator.closed for iterator in iterators)
        assert all(frame.close_claim is not None for frame in frames)
        assert all(frame.close_claim.attempts == 1 for frame in frames)
        assert all(frame.close_claim.disposition in containment._CLOSE_TERMINAL
                   for frame in frames)
    finally:
        sys.settrace(previous_trace)
        for iterator in iterators:
            iterator.wrapped.close()
        for fd in frame_fds:
            _close_if_open(real_close, fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["cleanup_call", "cleanup_argument"])
def test_inner_walk_ledger_fence_cleanup_boundary_drains_through_outer_fence(
        monkeypatch, tmp_path, cancellation_type, seam):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    root = tmp_path / f"inner-ledger-fence-{seam}"
    parent = root / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    root_fd = os.open(root, containment._DIR_FLAGS)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    child_fd = os.open(child, containment._DIR_FLAGS)
    parent_st = os.fstat(parent_fd)
    child_st = os.fstat(child_fd)
    parent_frame = containment._WalkFrame(
        parent_fd, None, 1, parent_fd=root_fd, name=parent.name,
        identity=(parent_st.st_dev, parent_st.st_ino), ready_to_remove=True,
    )
    child_frame = containment._WalkFrame(
        child_fd, None, 2, parent_fd=parent_fd, name=child.name,
        identity=(child_st.st_dev, child_st.st_ino), ready_to_remove=True,
    )
    ordinary = RuntimeError("fixture inner ledger fence primary")
    cancellation = cancellation_type(f"cancel inner ledger fence {seam}")
    real_remove = containment._remove_authenticated_fenced
    real_close = containment.os.close
    real_frame_close = containment._WalkFrame.close
    real_fence_init = containment._WalkLedgerFence.__init__
    events: list[str] = []
    child_parent_open: list[bool] = []
    fences: list[containment._WalkLedgerFence] = []
    captured_ledger = None
    body_calls = 0
    body_raised = False
    fired = False
    previous_trace = sys.gettrace()
    exit_method = containment._WalkLedgerFence.__exit__
    target_text = {
        "cleanup_call": "cleanup = _close_walk_frames_guarded(",
        "cleanup_argument": "tuple(reversed(self._frames)),",
    }[seam]
    target_line = _source_line(exit_method, target_text)

    def recording_fence_init(fence, frames) -> None:
        real_fence_init(fence, frames)
        fences.append(fence)

    def synthetic_body(_directory_fd: int, _deadline: float,
                       owned_frames: list[containment._WalkFrame]) -> None:
        nonlocal captured_ledger, body_calls, body_raised
        body_calls += 1
        captured_ledger = owned_frames
        owned_frames.extend((parent_frame, child_frame))
        body_raised = True
        raise ordinary

    def recording_remove(*args, **kwargs) -> None:
        name = kwargs["name"]
        events.append(f"remove:{name}")
        if name == child.name:
            child_parent_open.append(
                kwargs["parent_fd"] == parent_fd
                and not _descriptor_is_closed(parent_fd)
            )
        real_remove(*args, **kwargs)

    def recording_frame_close(frame, *, strict: bool,
                              retain_fd: bool = False) -> None:
        if frame is child_frame and not retain_fd:
            events.append("close:child")
        elif frame is parent_frame and not retain_fd:
            events.append("close:parent")
        real_frame_close(frame, strict=strict, retain_fd=retain_fd)

    def interrupt_inner_exit(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is exit_method.__code__
                and frame.f_lineno == target_line
                and len(fences) == 2 and frame.f_locals.get("self") is fences[1]
                and frame.f_locals.get("primary") is ordinary
                and body_calls == 1 and body_raised
                and fences[0]._frames is captured_ledger
                and fences[1]._frames is captured_ledger
                and captured_ledger == [parent_frame, child_frame]
                and not _descriptor_is_closed(child_fd)
                and not _descriptor_is_closed(parent_fd)):
            fired = True
            raise cancellation
        return interrupt_inner_exit

    monkeypatch.setattr(handle, "_remove_descendants_owned", synthetic_body)
    monkeypatch.setattr(
        containment._WalkLedgerFence, "__init__", recording_fence_init,
    )
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", recording_remove,
    )
    monkeypatch.setattr(containment._WalkFrame, "close", recording_frame_close)
    try:
        sys.settrace(interrupt_inner_exit)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True and body_calls == 1 and body_raised is True
        assert len(fences) == 2
        assert events == [
            f"remove:{child.name}", "close:child",
            f"remove:{parent.name}", "close:parent",
        ]
        assert child_parent_open == [True]
        assert child_frame.remove_attempt.state == "removed"
        assert parent_frame.remove_attempt.state == "removed"
        assert child_frame.close_claim is not None
        assert parent_frame.close_claim is not None
        assert child_frame.close_claim.attempts == 1
        assert parent_frame.close_claim.attempts == 1
        assert child_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert parent_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert _descriptor_is_closed(child_fd)
        assert _descriptor_is_closed(parent_fd)
        assert not child.exists() and not parent.exists()
        os.fstat(root_fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, child_fd)
        _close_if_open(real_close, parent_fd)
        if child.exists():
            child.rmdir()
        if parent.exists():
            parent.rmdir()
        _close_if_open(real_close, root_fd)
        handle.close()


def test_walk_ledger_fences_redrain_inert_and_preserve_ordinary_primary(
        monkeypatch, tmp_path):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    root = tmp_path / "ordinary-ledger-fences"
    parent = root / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    root_fd = os.open(root, containment._DIR_FLAGS)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    child_fd = os.open(child, containment._DIR_FLAGS)
    parent_st = os.fstat(parent_fd)
    child_st = os.fstat(child_fd)
    parent_frame = containment._WalkFrame(
        parent_fd, None, 1, parent_fd=root_fd, name=parent.name,
        identity=(parent_st.st_dev, parent_st.st_ino), ready_to_remove=True,
    )
    child_frame = containment._WalkFrame(
        child_fd, None, 2, parent_fd=parent_fd, name=child.name,
        identity=(child_st.st_dev, child_st.st_ino), ready_to_remove=True,
    )
    ordinary = RuntimeError("fixture ordinary nested ledger failure")
    real_remove = containment._remove_authenticated_fenced
    real_close = containment.os.close
    real_frame_close = containment._WalkFrame.close
    real_fence_init = containment._WalkLedgerFence.__init__
    real_guard = containment._close_walk_frames_guarded
    events: list[str] = []
    close_entries: list[str] = []
    child_parent_open: list[bool] = []
    cleanup_ledgers: list[tuple[containment._WalkFrame, ...]] = []
    fences: list[containment._WalkLedgerFence] = []
    captured_ledger = None
    body_calls = 0

    def recording_fence_init(fence, frames) -> None:
        real_fence_init(fence, frames)
        fences.append(fence)

    def synthetic_body(_directory_fd: int, _deadline: float,
                       owned_frames: list[containment._WalkFrame]) -> None:
        nonlocal captured_ledger, body_calls
        body_calls += 1
        captured_ledger = owned_frames
        owned_frames.extend((parent_frame, child_frame))
        raise ordinary

    def recording_guard(frames):
        cleanup_ledgers.append(frames)
        return real_guard(frames)

    def recording_remove(*args, **kwargs) -> None:
        name = kwargs["name"]
        events.append(f"remove:{name}")
        if name == child.name:
            child_parent_open.append(
                kwargs["parent_fd"] == parent_fd
                and not _descriptor_is_closed(parent_fd)
            )
        real_remove(*args, **kwargs)

    def recording_frame_close(frame, *, strict: bool,
                              retain_fd: bool = False) -> None:
        role = (
            "child" if frame is child_frame
            else "parent" if frame is parent_frame else None
        )
        claim = frame.close_claim
        if role is not None and not retain_fd:
            close_entries.append(role)
            if (claim is not None
                    and claim.disposition not in containment._CLOSE_TERMINAL):
                events.append(f"close:{role}")
        real_frame_close(frame, strict=strict, retain_fd=retain_fd)

    monkeypatch.setattr(handle, "_remove_descendants_owned", synthetic_body)
    monkeypatch.setattr(
        containment._WalkLedgerFence, "__init__", recording_fence_init,
    )
    monkeypatch.setattr(
        containment, "_close_walk_frames_guarded", recording_guard,
    )
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", recording_remove,
    )
    monkeypatch.setattr(containment._WalkFrame, "close", recording_frame_close)
    try:
        with pytest.raises(RuntimeError) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is ordinary
        assert body_calls == 1 and len(fences) == 2
        assert fences[0]._frames is captured_ledger
        assert fences[1]._frames is captured_ledger
        assert cleanup_ledgers == [
            (child_frame, parent_frame), (child_frame, parent_frame),
        ]
        assert events == [
            f"remove:{child.name}", "close:child",
            f"remove:{parent.name}", "close:parent",
        ]
        assert close_entries == ["child", "parent", "child", "parent"]
        assert child_parent_open == [True]
        assert child_frame.remove_attempt.state == "removed"
        assert parent_frame.remove_attempt.state == "removed"
        assert child_frame.close_claim is not None
        assert parent_frame.close_claim is not None
        assert child_frame.close_claim.attempts == 1
        assert parent_frame.close_claim.attempts == 1
        assert child_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert parent_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert _descriptor_is_closed(child_fd)
        assert _descriptor_is_closed(parent_fd)
        assert not child.exists() and not parent.exists()
        os.fstat(root_fd)
    finally:
        _close_if_open(real_close, child_fd)
        _close_if_open(real_close, parent_fd)
        if child.exists():
            child.rmdir()
        if parent.exists():
            parent.rmdir()
        _close_if_open(real_close, root_fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_descendant_frame_close_cancellation_does_not_leak_child_fd(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    child = leaf / "child"
    child.mkdir()
    cancellation = cancellation_type("cancel descendant frame close")
    real_open = containment.os.open
    real_close = containment.os.close
    target_fd = -1
    close_calls = 0

    def capture_traversal_child(path, flags, *args, **kwargs):
        nonlocal target_fd
        fd = real_open(path, flags, *args, **kwargs)
        if (target_fd < 0 and path == "child"
                and kwargs.get("dir_fd") is not None):
            target_fd = fd
        return fd

    def interrupt_child_close(fd: int) -> None:
        nonlocal close_calls
        if fd == target_fd:
            close_calls += 1
            if close_calls == 1:
                raise cancellation
        real_close(fd)

    monkeypatch.setattr(containment.os, "open", capture_traversal_child)
    monkeypatch.setattr(containment.os, "close", interrupt_child_close)
    try:
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is cancellation
        assert target_fd >= 0
        assert close_calls == 1
        assert not _descriptor_is_closed(target_fd)
    finally:
        _close_if_open(real_close, target_fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_descendant_ready_remove_caller_cancellation_removes_once_and_closes_anchor(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    child = leaf / "child"
    child.mkdir()
    cancellation = cancellation_type("cancel descendant ready remove call")
    real_open = containment.os.open
    real_remove = containment._remove_authenticated_fenced
    real_close = containment.os.close
    target_fd = -1
    target_frame = None
    remove_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    transaction = containment.DirectCgroupV2._remove_descendants_owned
    remove_line = _source_line(
        transaction, "_remove_authenticated_fenced(",
    )

    def capture_child_open(path, flags, *args, **kwargs):
        nonlocal target_fd
        fd = real_open(path, flags, *args, **kwargs)
        if (target_fd < 0 and path == "child"
                and kwargs.get("dir_fd") is not None):
            target_fd = fd
        return fd

    def recording_remove(*args, **kwargs) -> None:
        nonlocal remove_calls
        remove_calls += 1
        real_remove(*args, **kwargs)

    def interrupt_ready_remove_call(frame, event, _arg):
        nonlocal fired, target_frame
        candidate = frame.f_locals.get("frame")
        attempt = getattr(candidate, "remove_attempt", None)
        if (not fired and event == "line"
                and frame.f_code is transaction.__code__
                and frame.f_lineno == remove_line
                and type(candidate) is containment._WalkFrame
                and candidate.name == "child"
                and candidate.ready_to_remove is True
                and candidate.iterator is None
                and type(attempt) is containment._RemoveAttempt
                and attempt.state == "not_started" and remove_calls == 0
                and candidate.close_claim is not None
                and candidate.close_claim.fd == target_fd
                and not _descriptor_is_closed(target_fd)):
            target_frame = candidate
            fired = True
            raise cancellation
        return interrupt_ready_remove_call

    monkeypatch.setattr(containment.os, "open", capture_child_open)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", recording_remove,
    )
    try:
        sys.settrace(interrupt_ready_remove_call)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True and target_frame is not None
        assert remove_calls == 1
        assert not child.exists()
        assert _descriptor_is_closed(target_fd)
        assert target_frame.close_claim is not None
        assert target_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert target_frame.remove_attempt.state == "removed"
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, target_fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_ready_remove_cleanup_fence_call_cancellation_retries_once_before_close(
        monkeypatch, tmp_path, cancellation_type):
    parent = tmp_path / "ready-cleanup-parent"
    child = parent / "child"
    child.mkdir(parents=True)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    child_fd = os.open(child, containment._DIR_FLAGS)
    observed = os.fstat(child_fd)
    frame = containment._WalkFrame(
        child_fd, None, 1, parent_fd=parent_fd, name=child.name,
        identity=(observed.st_dev, observed.st_ino), ready_to_remove=True,
    )
    cancellation = cancellation_type("cancel ready cleanup remove call")
    real_remove = containment._remove_authenticated_fenced
    remove_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    cleanup_line = _source_line(
        containment._close_walk_frame_owned,
        "_remove_authenticated_fenced(",
    )

    def recording_remove(*args, **kwargs) -> None:
        nonlocal remove_calls
        remove_calls += 1
        real_remove(*args, **kwargs)

    def interrupt_cleanup_remove_call(py_frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and py_frame.f_code is containment._close_walk_frame_owned.__code__
                and py_frame.f_lineno == cleanup_line
                and py_frame.f_locals.get("frame") is frame
                and frame.remove_attempt.state == "not_started"
                and remove_calls == 0 and not _descriptor_is_closed(child_fd)):
            fired = True
            raise cancellation
        return interrupt_cleanup_remove_call

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", recording_remove,
    )
    try:
        sys.settrace(interrupt_cleanup_remove_call)
        caught = containment._close_walk_frames_guarded((frame,))
        assert caught is cancellation
        assert fired is True
        assert remove_calls == 1
        assert frame.remove_attempt.state == "removed"
        assert not child.exists()
        assert _descriptor_is_closed(child_fd)
        assert frame.close_claim is not None
        assert frame.close_claim.disposition in containment._CLOSE_TERMINAL
    finally:
        sys.settrace(previous_trace)
        _close_if_open(os.close, child_fd)
        if child.exists():
            child.rmdir()
        _close_if_open(os.close, parent_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_stacked_ready_remove_cleanup_retries_child_before_closing_ancestor(
        monkeypatch, tmp_path, cancellation_type):
    root = tmp_path / "stacked-ready-cleanup"
    parent = root / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    root_fd = os.open(root, containment._DIR_FLAGS)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    child_fd = os.open(child, containment._DIR_FLAGS)
    parent_st = os.fstat(parent_fd)
    child_st = os.fstat(child_fd)
    parent_frame = containment._WalkFrame(
        parent_fd, None, 1, parent_fd=root_fd, name=parent.name,
        identity=(parent_st.st_dev, parent_st.st_ino), ready_to_remove=True,
    )
    child_frame = containment._WalkFrame(
        child_fd, None, 2, parent_fd=parent_fd, name=child.name,
        identity=(child_st.st_dev, child_st.st_ino), ready_to_remove=True,
    )
    cancellation = cancellation_type("cancel stacked child cleanup removal")
    real_remove = containment._remove_authenticated_fenced
    real_close = containment.os.close
    real_frame_close = containment._WalkFrame.close
    removals: list[str] = []
    anchor_closes: list[str] = []
    child_parent_open: list[bool] = []
    fired = False
    previous_trace = sys.gettrace()
    cleanup_line = _source_line(
        containment._close_walk_frame_owned,
        "_remove_authenticated_fenced(",
    )

    def recording_remove(*args, **kwargs) -> None:
        name = kwargs["name"]
        removals.append(name)
        if name == child.name:
            child_parent_open.append(
                kwargs["parent_fd"] == parent_fd
                and not _descriptor_is_closed(parent_fd)
            )
        real_remove(*args, **kwargs)

    def recording_frame_close(frame, *, strict: bool,
                              retain_fd: bool = False) -> None:
        if frame is child_frame and not retain_fd:
            anchor_closes.append("child")
        elif frame is parent_frame and not retain_fd:
            anchor_closes.append("parent")
        real_frame_close(frame, strict=strict, retain_fd=retain_fd)

    def interrupt_child_remove_call(py_frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and py_frame.f_code is containment._close_walk_frame_owned.__code__
                and py_frame.f_lineno == cleanup_line
                and py_frame.f_locals.get("frame") is child_frame
                and child_frame.remove_attempt.state == "not_started"
                and removals == []
                and child_frame.parent_fd == parent_fd
                and not _descriptor_is_closed(parent_fd)):
            fired = True
            raise cancellation
        return interrupt_child_remove_call

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", recording_remove,
    )
    monkeypatch.setattr(containment._WalkFrame, "close", recording_frame_close)
    try:
        sys.settrace(interrupt_child_remove_call)
        caught = containment._close_walk_frames_guarded(
            (child_frame, parent_frame),
        )
        assert caught is cancellation
        assert fired is True
        assert removals == [child.name, parent.name]
        assert child_parent_open == [True]
        assert anchor_closes == ["child", "parent"]
        assert child_frame.remove_attempt.state == "removed"
        assert parent_frame.remove_attempt.state == "removed"
        assert not child.exists() and not parent.exists()
        assert _descriptor_is_closed(child_fd)
        assert _descriptor_is_closed(parent_fd)
        assert child_frame.close_claim is not None
        assert parent_frame.close_claim is not None
        assert child_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert parent_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        os.fstat(root_fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, child_fd)
        _close_if_open(real_close, parent_fd)
        if child.exists():
            child.rmdir()
        if parent.exists():
            parent.rmdir()
        _close_if_open(real_close, root_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_stacked_ready_condition_cancellation_reconciles_child_before_ancestor(
        monkeypatch, tmp_path, cancellation_type):
    root = tmp_path / "stacked-ready-condition"
    parent = root / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    root_fd = os.open(root, containment._DIR_FLAGS)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    child_fd = os.open(child, containment._DIR_FLAGS)
    parent_st = os.fstat(parent_fd)
    child_st = os.fstat(child_fd)
    parent_frame = containment._WalkFrame(
        parent_fd, None, 1, parent_fd=root_fd, name=parent.name,
        identity=(parent_st.st_dev, parent_st.st_ino), ready_to_remove=True,
    )
    child_frame = containment._WalkFrame(
        child_fd, None, 2, parent_fd=parent_fd, name=child.name,
        identity=(child_st.st_dev, child_st.st_ino), ready_to_remove=True,
    )
    cancellation = cancellation_type("cancel stacked ready condition")
    real_remove = containment._remove_authenticated_fenced
    real_close = containment.os.close
    real_frame_close = containment._WalkFrame.close
    events: list[str] = []
    child_parent_open: list[bool] = []
    fired = False
    previous_trace = sys.gettrace()
    condition_line = _source_line(
        containment._close_walk_frame_owned,
        "if (frame.ready_to_remove",
    )

    def recording_remove(*args, **kwargs) -> None:
        name = kwargs["name"]
        events.append(f"remove:{name}")
        if name == child.name:
            child_parent_open.append(
                kwargs["parent_fd"] == parent_fd
                and not _descriptor_is_closed(parent_fd)
            )
        real_remove(*args, **kwargs)

    def recording_frame_close(frame, *, strict: bool,
                              retain_fd: bool = False) -> None:
        if frame is child_frame and not retain_fd:
            events.append("close:child")
        elif frame is parent_frame and not retain_fd:
            events.append("close:parent")
        real_frame_close(frame, strict=strict, retain_fd=retain_fd)

    def interrupt_ready_condition(py_frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and py_frame.f_code is containment._close_walk_frame_owned.__code__
                and py_frame.f_lineno == condition_line
                and py_frame.f_locals.get("frame") is child_frame
                and child_frame.ready_to_remove is True
                and child_frame.remove_attempt.state == "not_started"
                and child_frame.parent_fd == parent_fd
                and not _descriptor_is_closed(parent_fd)):
            fired = True
            raise cancellation
        return interrupt_ready_condition

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", recording_remove,
    )
    monkeypatch.setattr(containment._WalkFrame, "close", recording_frame_close)
    try:
        sys.settrace(interrupt_ready_condition)
        caught = containment._close_walk_frames_guarded(
            (child_frame, parent_frame),
        )
        assert caught is cancellation
        assert fired is True
        assert events == [
            f"remove:{child.name}", "close:child",
            f"remove:{parent.name}", "close:parent",
        ]
        assert child_parent_open == [True]
        assert child_frame.remove_attempt.state == "removed"
        assert parent_frame.remove_attempt.state == "removed"
        assert child_frame.close_claim is not None
        assert parent_frame.close_claim is not None
        assert child_frame.close_claim.attempts == 1
        assert parent_frame.close_claim.attempts == 1
        assert child_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert parent_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert _descriptor_is_closed(child_fd)
        assert _descriptor_is_closed(parent_fd)
        assert not child.exists() and not parent.exists()
        os.fstat(root_fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, child_fd)
        _close_if_open(real_close, parent_fd)
        if child.exists():
            child.rmdir()
        if parent.exists():
            parent.rmdir()
        _close_if_open(real_close, root_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    ("seam", "try_occurrence"),
    [("outer", 1), ("recovery_remove", 2), ("recovery_close", 4)],
)
def test_stacked_frame_owner_try_header_cancellation_replays_child_first(
        monkeypatch, tmp_path, cancellation_type, seam, try_occurrence):
    root = tmp_path / f"stacked-owner-{seam}"
    parent = root / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    root_fd = os.open(root, containment._DIR_FLAGS)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    child_fd = os.open(child, containment._DIR_FLAGS)
    parent_st = os.fstat(parent_fd)
    child_st = os.fstat(child_fd)
    parent_frame = containment._WalkFrame(
        parent_fd, None, 1, parent_fd=root_fd, name=parent.name,
        identity=(parent_st.st_dev, parent_st.st_ino), ready_to_remove=True,
    )
    child_frame = containment._WalkFrame(
        child_fd, None, 2, parent_fd=parent_fd, name=child.name,
        identity=(child_st.st_dev, child_st.st_ino), ready_to_remove=True,
    )
    ordinary = RuntimeError(f"fixture {seam} frame-owner primary")
    cancellation = cancellation_type(f"cancel {seam} frame-owner try header")
    real_remove = containment._remove_authenticated_fenced
    real_close = containment.os.close
    real_frame_close = containment._WalkFrame.close
    events: list[str] = []
    child_parent_open: list[bool] = []
    remove_entries: list[str] = []
    ordinary_raised = False
    fired = False
    previous_trace = sys.gettrace()
    target_line = _source_line(
        containment._close_walk_frame_owned, "try:",
        occurrence=try_occurrence,
    )

    def scripted_remove(*args, **kwargs) -> None:
        nonlocal ordinary_raised
        name = kwargs["name"]
        remove_entries.append(name)
        if (seam == "recovery_remove" and name == child.name
                and not ordinary_raised):
            ordinary_raised = True
            raise ordinary
        events.append(f"remove:{name}")
        if name == child.name:
            child_parent_open.append(
                kwargs["parent_fd"] == parent_fd
                and not _descriptor_is_closed(parent_fd)
            )
        real_remove(*args, **kwargs)

    def scripted_frame_close(frame, *, strict: bool,
                             retain_fd: bool = False) -> None:
        nonlocal ordinary_raised
        if (seam == "recovery_close" and frame is child_frame
                and not retain_fd and not ordinary_raised):
            ordinary_raised = True
            raise ordinary
        if frame is child_frame and not retain_fd:
            events.append("close:child")
        elif frame is parent_frame and not retain_fd:
            events.append("close:parent")
        real_frame_close(frame, strict=strict, retain_fd=retain_fd)

    def interrupt_try_header(py_frame, event, _arg):
        nonlocal fired
        ready_for_seam = (
            seam == "outer" and not ordinary_raised
            or seam == "recovery_remove" and ordinary_raised
            and child_frame.remove_attempt.state == "not_started"
            or seam == "recovery_close" and ordinary_raised
            and child_frame.remove_attempt.state == "removed"
            and child_frame.close_claim is not None
            and child_frame.close_claim.disposition not in containment._CLOSE_TERMINAL
        )
        if (not fired and event == "line"
                and py_frame.f_code is containment._close_walk_frame_owned.__code__
                and py_frame.f_lineno == target_line
                and py_frame.f_locals.get("frame") is child_frame
                and ready_for_seam
                and not _descriptor_is_closed(parent_fd)):
            fired = True
            raise cancellation
        return interrupt_try_header

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", scripted_remove,
    )
    monkeypatch.setattr(containment._WalkFrame, "close", scripted_frame_close)
    try:
        sys.settrace(interrupt_try_header)
        caught = containment._close_walk_frames_guarded(
            (child_frame, parent_frame),
        )
        assert caught is cancellation
        assert fired is True
        assert ordinary_raised is (seam != "outer")
        assert events == [
            f"remove:{child.name}", "close:child",
            f"remove:{parent.name}", "close:parent",
        ]
        assert child_parent_open == [True]
        assert remove_entries.count(child.name) == (
            2 if seam == "recovery_remove" else 1
        )
        assert remove_entries.count(parent.name) == 1
        assert child_frame.remove_attempt.state == "removed"
        assert parent_frame.remove_attempt.state == "removed"
        assert child_frame.close_claim is not None
        assert parent_frame.close_claim is not None
        assert child_frame.close_claim.attempts == 1
        assert parent_frame.close_claim.attempts == 1
        assert child_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert parent_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert _descriptor_is_closed(child_fd)
        assert _descriptor_is_closed(parent_fd)
        assert not child.exists() and not parent.exists()
        os.fstat(root_fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, child_fd)
        _close_if_open(real_close, parent_fd)
        if child.exists():
            child.rmdir()
        if parent.exists():
            parent.rmdir()
        _close_if_open(real_close, root_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("seam", ["recovery_remove_call", "recovery_close_call"])
def test_stacked_frame_owner_recovery_call_cancellation_retries_immediately(
        monkeypatch, tmp_path, cancellation_type, seam):
    root = tmp_path / f"stacked-owner-{seam}"
    parent = root / "parent"
    child = parent / "child"
    child.mkdir(parents=True)
    root_fd = os.open(root, containment._DIR_FLAGS)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    child_fd = os.open(child, containment._DIR_FLAGS)
    parent_st = os.fstat(parent_fd)
    child_st = os.fstat(child_fd)
    parent_frame = containment._WalkFrame(
        parent_fd, None, 1, parent_fd=root_fd, name=parent.name,
        identity=(parent_st.st_dev, parent_st.st_ino), ready_to_remove=True,
    )
    child_frame = containment._WalkFrame(
        child_fd, None, 2, parent_fd=parent_fd, name=child.name,
        identity=(child_st.st_dev, child_st.st_ino), ready_to_remove=True,
    )
    ordinary = RuntimeError(f"fixture {seam} primary")
    cancellation = cancellation_type(f"cancel {seam}")
    real_remove = containment._remove_authenticated_fenced
    real_close = containment.os.close
    real_frame_close = containment._WalkFrame.close
    events: list[str] = []
    child_parent_open: list[bool] = []
    remove_entries: list[str] = []
    close_entries: list[str] = []
    ordinary_raised = False
    fired = False
    previous_trace = sys.gettrace()
    target_line = _source_line(
        containment._close_walk_frame_owned,
        ("_remove_authenticated_fenced("
         if seam == "recovery_remove_call" else "frame.close(strict=False)"),
        occurrence=2,
    )

    def scripted_remove(*args, **kwargs) -> None:
        nonlocal ordinary_raised
        name = kwargs["name"]
        remove_entries.append(name)
        if (seam == "recovery_remove_call" and name == child.name
                and not ordinary_raised):
            ordinary_raised = True
            raise ordinary
        events.append(f"remove:{name}")
        if name == child.name:
            child_parent_open.append(
                kwargs["parent_fd"] == parent_fd
                and not _descriptor_is_closed(parent_fd)
            )
        real_remove(*args, **kwargs)

    def scripted_frame_close(frame, *, strict: bool,
                             retain_fd: bool = False) -> None:
        nonlocal ordinary_raised
        role = "child" if frame is child_frame else "parent"
        if not retain_fd:
            close_entries.append(role)
        if (seam == "recovery_close_call" and frame is child_frame
                and not retain_fd and not ordinary_raised):
            ordinary_raised = True
            raise ordinary
        if not retain_fd:
            events.append(f"close:{role}")
        real_frame_close(frame, strict=strict, retain_fd=retain_fd)

    def interrupt_recovery_call(py_frame, event, _arg):
        nonlocal fired
        claim = child_frame.close_claim
        ready_for_seam = (
            seam == "recovery_remove_call"
            and ordinary_raised
            and child_frame.remove_attempt.state == "not_started"
            or seam == "recovery_close_call"
            and ordinary_raised
            and child_frame.remove_attempt.state == "removed"
            and claim is not None and claim.attempts == 0
            and claim.disposition not in containment._CLOSE_TERMINAL
        )
        if (not fired and event == "line"
                and py_frame.f_code is containment._close_walk_frame_owned.__code__
                and py_frame.f_lineno == target_line
                and py_frame.f_locals.get("frame") is child_frame
                and ready_for_seam
                and not _descriptor_is_closed(parent_fd)):
            fired = True
            raise cancellation
        return interrupt_recovery_call

    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", scripted_remove,
    )
    monkeypatch.setattr(containment._WalkFrame, "close", scripted_frame_close)
    try:
        sys.settrace(interrupt_recovery_call)
        caught = containment._close_walk_frames_guarded(
            (child_frame, parent_frame),
        )
        assert caught is cancellation
        assert fired is True and ordinary_raised is True
        assert events == [
            f"remove:{child.name}", "close:child",
            f"remove:{parent.name}", "close:parent",
        ]
        assert child_parent_open == [True]
        assert remove_entries.count(child.name) == (
            2 if seam == "recovery_remove_call" else 1
        )
        assert remove_entries.count(parent.name) == 1
        assert close_entries.count("child") == (
            2 if seam == "recovery_close_call" else 1
        )
        assert close_entries.count("parent") == 1
        assert child_frame.remove_attempt.state == "removed"
        assert parent_frame.remove_attempt.state == "removed"
        assert child_frame.close_claim is not None
        assert parent_frame.close_claim is not None
        assert child_frame.close_claim.attempts == 1
        assert parent_frame.close_claim.attempts == 1
        assert child_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert parent_frame.close_claim.disposition in containment._CLOSE_TERMINAL
        assert _descriptor_is_closed(child_fd)
        assert _descriptor_is_closed(parent_fd)
        assert not child.exists() and not parent.exists()
        os.fstat(root_fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, child_fd)
        _close_if_open(real_close, parent_fd)
        if child.exists():
            child.rmdir()
        if parent.exists():
            parent.rmdir()
        _close_if_open(real_close, root_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_walk_frame_iterator_close_cancellation_retries_and_closes_fd(
        tmp_path, cancellation_type):
    directory = tmp_path / "walk-frame"
    directory.mkdir()
    fd = os.open(directory, containment._DIR_FLAGS)
    real_iterator = os.scandir(fd)
    cancellation = cancellation_type("cancel iterator close")

    class InterruptingIterator:
        def __init__(self):
            self.close_calls = 0
            self.physically_closed = False

        def close(self):
            self.close_calls += 1
            if self.close_calls == 1:
                raise cancellation
            real_iterator.close()
            self.physically_closed = True

    iterator = InterruptingIterator()
    frame = containment._WalkFrame(fd, iterator, 0)
    try:
        with pytest.raises(cancellation_type) as caught:
            frame.close(strict=False)
        assert caught.value is cancellation
        assert iterator.close_calls == 2
        assert iterator.physically_closed is True
        assert _descriptor_is_closed(fd)
        assert frame.iterator is None
        assert frame.fd == -1
    finally:
        real_iterator.close()
        _close_if_open(os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_remove_descendants_cleanup_cancellation_drains_remaining_frames(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "child" / "grandchild").mkdir(parents=True)
    cancellation = cancellation_type("cancel first stacked frame close")
    real_close = containment._WalkFrame.close
    real_scandir = containment.os.scandir
    close_calls: list[int] = []
    interrupted = False
    ready = False
    captured_frames: list[containment._WalkFrame] = []
    iterators = []

    class RecordingIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.wrapped)

        def close(self):
            self.wrapped.close()
            self.closed = True

    def recording_scandir(fd: int):
        iterator = RecordingIterator(real_scandir(fd))
        iterators.append(iterator)
        return iterator

    def interrupt_first_frame_close(frame, *, strict):
        nonlocal interrupted
        close_calls.append(frame.fd)
        if not interrupted:
            interrupted = True
            raise cancellation
        return real_close(frame, strict=strict)

    def fault_after_all_frames_owned():
        if ready:
            raise RuntimeError("fixture traversal primary")
        return 10.0

    monkeypatch.setattr(containment.time, "monotonic", fault_after_all_frames_owned)
    monkeypatch.setattr(containment.os, "scandir", recording_scandir)
    monkeypatch.setattr(containment._WalkFrame, "close", interrupt_first_frame_close)
    real_append = containment._append_walk_frame

    def recording_append(stack, frame):
        nonlocal ready
        captured_frames.append(frame)
        real_append(stack, frame)
        if len(captured_frames) == 3:
            ready = True

    monkeypatch.setattr(containment, "_append_walk_frame", recording_append)
    try:
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, 11.0)
        assert caught.value is cancellation
        assert len(captured_frames) == 3
        assert len(iterators) == 3
        assert all(frame.fd == -1 or _descriptor_is_closed(frame.fd)
                   for frame in captured_frames)
        assert all(iterator.closed for iterator in iterators)
        assert len(close_calls) >= 4  # three-frame suffix plus interrupted retry
    finally:
        monkeypatch.setattr(containment._WalkFrame, "close", real_close)
        for frame in reversed(captured_frames):
            try:
                real_close(frame, strict=False)
            except BaseException:
                pass
        for iterator in iterators:
            iterator.wrapped.close()
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


def test_ordinary_close_fault_is_not_retried_or_reported_clean(monkeypatch, tmp_path):
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
    with pytest.raises(containment.ContainmentFailure) as first:
        handle.close()

    assert first.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
    assert first.value.os_errno == errno.EIO
    assert attempted == owned
    with pytest.raises(containment.ContainmentFailure) as replay:
        handle.close()
    assert replay.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
    assert replay.value.os_errno == errno.EIO
    assert attempted == owned
    for fd in owned[1:]:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    os.fstat(failed)
    real_close(failed)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_close_cancellation_never_retries_ambiguous_numeric_fd_after_suffix(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [handle._kill_fd, handle._events_fd, handle._procs_write_fd,
             handle._procs_read_fd, handle._leaf_fd, handle._parent_fd]
    target = owned[0]
    cancellation = cancellation_type("cancel before descriptor close")
    real_close = containment.os.close
    attempted: list[int] = []
    interrupted = False

    def interrupt_once_before_close(fd: int) -> None:
        nonlocal interrupted
        attempted.append(fd)
        if fd == target and not interrupted:
            interrupted = True
            raise cancellation
        real_close(fd)

    monkeypatch.setattr(containment.os, "close", interrupt_once_before_close)
    with pytest.raises(cancellation_type) as caught:
        handle.close()
    assert caught.value is cancellation
    assert attempted == owned
    os.fstat(target)
    for fd in owned[1:]:
        assert _descriptor_is_closed(fd)

    with pytest.raises(containment.ContainmentFailure) as replay:
        handle.close()
    assert replay.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
    assert attempted == owned
    real_close(target)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_close_after_physical_close_never_targets_reused_numeric_fd(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [handle._kill_fd, handle._events_fd, handle._procs_write_fd,
             handle._procs_read_fd, handle._leaf_fd, handle._parent_fd]
    target = owned[0]
    cancellation = cancellation_type("cancel after descriptor close")
    real_close = containment.os.close
    attempted: list[int] = []
    replacement = -1
    foreign = tmp_path / "foreign-control-file"
    foreign.write_bytes(b"foreign")

    def close_then_interrupt(fd: int) -> None:
        nonlocal replacement
        attempted.append(fd)
        if fd == target and replacement < 0:
            real_close(fd)
            replacement = os.open(foreign, os.O_WRONLY | containment._O_CLOEXEC)
            assert replacement == target
            raise cancellation
        real_close(fd)

    monkeypatch.setattr(containment.os, "close", close_then_interrupt)
    try:
        with pytest.raises(cancellation_type) as caught:
            handle.close()
        assert caught.value is cancellation
        assert attempted == owned
        os.fstat(replacement)

        with pytest.raises(containment.ContainmentFailure) as replay:
            handle.close()
        assert replay.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
        assert attempted == owned
        os.fstat(replacement)

        with pytest.raises(containment.ContainmentFailure):
            handle.close()
        assert attempted == owned
        os.fstat(replacement)
    finally:
        if replacement >= 0:
            real_close(replacement)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_read_bounded_path_ordinary_primary_recovery_boundary_drains_fd(
        monkeypatch, tmp_path, cancellation_type):
    source = tmp_path / "bounded-primary"
    source.write_text("fixture\n")
    ordinary = OSError(errno.EIO, "fixture read fault")
    cancellation = cancellation_type("cancel bounded-path recovery")
    real_open = containment.os.open
    real_close = containment.os.close
    real_read = containment._read_fd
    opened = -1
    read_failed = False
    fired = False
    previous_trace = sys.gettrace()

    def recording_open(path, flags, *args, **kwargs):
        nonlocal opened
        fd = real_open(path, flags, *args, **kwargs)
        if path == str(source):
            opened = fd
        return fd

    def fail_owned_read(fd: int, *args, **kwargs):
        nonlocal read_failed
        if fd == opened:
            read_failed = True
            raise ordinary
        return real_read(fd, *args, **kwargs)

    def interrupt_outer_recovery(frame, event, _arg):
        nonlocal fired
        claim = frame.f_locals.get("claim")
        primary = frame.f_locals.get("primary")
        if (not fired and event == "line"
                and frame.f_code is containment._read_bounded_path.__code__
                and read_failed
                and isinstance(primary, containment.ContainmentUnsupported)
                and type(claim) is containment._DescriptorCloseClaim
                and claim.fd == opened
                and claim.disposition not in containment._CLOSE_TERMINAL
                and not _descriptor_is_closed(opened)):
            fired = True
            raise cancellation
        return interrupt_outer_recovery

    monkeypatch.setattr(containment.os, "open", recording_open)
    monkeypatch.setattr(containment, "_read_fd", fail_owned_read)
    try:
        sys.settrace(interrupt_outer_recovery)
        with pytest.raises(cancellation_type) as caught:
            containment._read_bounded_path(str(source))
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
    finally:
        sys.settrace(previous_trace)
        if opened >= 0:
            _close_if_open(real_close, opened)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_walk_frame_iterator_ordinary_fault_then_cleanup_boundary_cancellation(
        tmp_path, cancellation_type):
    directory = tmp_path / "walk-frame-ordinary"
    directory.mkdir()
    fd = os.open(directory, containment._DIR_FLAGS)
    cancellation = cancellation_type("cancel iterator-to-fd cleanup")
    iterator_fault = OSError(errno.EIO, "fixture iterator close fault")
    fired = False
    previous_trace = sys.gettrace()

    class FaultingIterator:
        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1
            raise iterator_fault

    iterator = FaultingIterator()
    walk_frame = containment._WalkFrame(fd, iterator, 0)

    def interrupt_fd_cleanup_boundary(frame, event, _arg):
        nonlocal fired
        claim = walk_frame.close_claim
        if (not fired and event == "line"
                and frame.f_code is containment._WalkFrame.close.__code__
                and frame.f_locals.get("self") is walk_frame
                and frame.f_locals.get("iterator_attempted") is True
                and frame.f_locals.get("failure_errno") == errno.EIO
                and iterator.close_calls == 1
                and walk_frame.iterator is None
                and claim is not None and claim.fd == fd
                and claim.disposition not in containment._CLOSE_TERMINAL
                and not _descriptor_is_closed(fd)):
            fired = True
            raise cancellation
        return interrupt_fd_cleanup_boundary

    try:
        sys.settrace(interrupt_fd_cleanup_boundary)
        with pytest.raises(cancellation_type) as caught:
            walk_frame.close(strict=False)
        assert caught.value is cancellation
        assert fired is True
        assert iterator.close_calls == 1
        assert walk_frame.iterator is None
        assert _descriptor_is_closed(fd)
        assert walk_frame.close_claim is not None
        assert walk_frame.close_claim.disposition in containment._CLOSE_TERMINAL
    finally:
        sys.settrace(previous_trace)
        _close_if_open(os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_stacked_traversal_clock_primary_final_cleanup_boundary_drains_frames(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    (leaf / "child" / "grandchild").mkdir(parents=True)
    ordinary = RuntimeError("fixture traversal clock fault")
    cancellation = cancellation_type("cancel traversal final cleanup")
    real_append = containment._append_walk_frame
    real_scandir = containment.os.scandir
    real_close = containment.os.close
    frames: list[containment._WalkFrame] = []
    frame_fds: list[int] = []
    iterators = []
    ready = False
    clock_failed = False
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._remove_descendants_owned.__func__.__code__

    class RecordingIterator:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.wrapped)

        def close(self):
            self.wrapped.close()
            self.closed = True

    def recording_scandir(fd: int):
        iterator = RecordingIterator(real_scandir(fd))
        iterators.append(iterator)
        return iterator

    def recording_append(stack, frame):
        nonlocal ready
        frames.append(frame)
        frame_fds.append(frame.fd)
        real_append(stack, frame)
        if len(frames) == 3:
            ready = True

    def fail_clock_after_stack():
        nonlocal clock_failed
        if ready:
            clock_failed = True
            raise ordinary
        return 10.0

    def interrupt_final_cleanup(frame, event, _arg):
        nonlocal fired
        owned = frame.f_locals.get("owned_frames")
        if (not fired and event == "line" and frame.f_code is transaction_code
                and clock_failed
                and frame.f_locals.get("cleanup_cancellation") is None
                and isinstance(frame.f_locals.get("interrupted_frames"), list)
                and isinstance(owned, list) and len(frames) == 3
                and all(candidate in owned for candidate in frames)
                and all(not _descriptor_is_closed(fd) for fd in frame_fds)
                and all(not iterator.closed for iterator in iterators)):
            fired = True
            raise cancellation
        return interrupt_final_cleanup

    monkeypatch.setattr(containment.os, "scandir", recording_scandir)
    monkeypatch.setattr(containment, "_append_walk_frame", recording_append)
    monkeypatch.setattr(containment.time, "monotonic", fail_clock_after_stack)
    try:
        sys.settrace(interrupt_final_cleanup)
        with pytest.raises(cancellation_type) as caught:
            handle._remove_descendants(handle._leaf_fd, 11.0)
        assert caught.value is cancellation
        assert fired is True
        assert len(frames) == 3
        assert all(_descriptor_is_closed(fd) for fd in frame_fds)
        assert all(iterator.closed for iterator in iterators)
    finally:
        sys.settrace(previous_trace)
        for iterator in iterators:
            iterator.wrapped.close()
        for frame_fd in frame_fds:
            _close_if_open(real_close, frame_fd)
        handle.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_settlement_traversal_primary_close_cancellation_outranks_and_drains(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    ordinary = RuntimeError("fixture unexpected traversal fault")
    cancellation = cancellation_type("cancel settlement close")
    real_close = handle.close
    close_calls = 0

    def completed_kill_and_empty_sample(_sample=None):
        handle._kill_state = "write_complete"
        handle._kill_sent = True
        return None, False, None

    def fail_traversal(_directory_fd: int, _deadline: float) -> None:
        raise ordinary

    def interrupt_first_close() -> None:
        nonlocal close_calls
        close_calls += 1
        if close_calls == 1:
            raise cancellation
        real_close()

    monkeypatch.setattr(handle, "_request_kill_and_sample_once",
                        completed_kill_and_empty_sample)
    monkeypatch.setattr(handle, "_remove_descendants", fail_traversal)
    monkeypatch.setattr(handle, "close", interrupt_first_close)
    try:
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert caught.value is cancellation
        assert close_calls == 2
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)
        assert handle._closed is True
    finally:
        try:
            real_close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_discovery_ordinary_primary_recovery_boundary_drains_authorities(
        monkeypatch, tmp_path, cancellation_type):
    opened, _checked = _install_hermetic_discovery(monkeypatch, tmp_path)
    ordinary = RuntimeError("fixture discovery primary")
    cancellation = cancellation_type("cancel discovery recovery")
    fired = False
    ordinary_raised = False
    previous_trace = sys.gettrace()
    real_close = containment.os.close

    def fail_candidate(_fd: int) -> None:
        nonlocal ordinary_raised
        ordinary_raised = True
        raise ordinary

    def interrupt_recovery_call(frame, event, _arg):
        nonlocal fired
        claims = frame.f_locals.get("claims")
        if (not fired and event == "line"
                and frame.f_code is containment._discover_parent.__code__
                and ordinary_raised and frame.f_locals.get("primary") is ordinary
                and isinstance(claims, list) and len(claims) >= 2
                and all(claim.fd >= 0 for claim in claims[-2:])
                and opened["mount"] >= 0 and opened["parent"] >= 0
                and not _descriptor_is_closed(opened["mount"])
                and not _descriptor_is_closed(opened["parent"])):
            fired = True
            raise cancellation
        return interrupt_recovery_call

    monkeypatch.setattr(containment, "_check_parent_candidate", fail_candidate)
    try:
        sys.settrace(interrupt_recovery_call)
        with pytest.raises(cancellation_type) as caught:
            containment._discover_parent()
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened["mount"])
        assert _descriptor_is_closed(opened["parent"])
    finally:
        sys.settrace(previous_trace)
        for fd in opened.values():
            if fd >= 0:
                _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_discovered_parent_ordinary_primary_recovery_boundary_closes_fd(
        monkeypatch, tmp_path, cancellation_type):
    directory = tmp_path / "discovered-primary"
    directory.mkdir()
    fd = os.open(directory, containment._DIR_FLAGS)
    discovered = containment._DiscoveredParent(fd, "/delegated")
    ordinary = RuntimeError("fixture discovered-parent close primary")
    cancellation = cancellation_type("cancel discovered-parent recovery")
    real_close = containment.os.close
    real_close_claims = containment._close_claims_or_raise
    fired = False
    previous_trace = sys.gettrace()

    def fail_initial_close(claims, **kwargs):
        if claims == (discovered._close_claim,):
            raise ordinary
        return real_close_claims(claims, **kwargs)

    def interrupt_recovery_call(frame, event, _arg):
        nonlocal fired
        claim = discovered._close_claim
        if (not fired and event == "line"
                and frame.f_code is containment._DiscoveredParent.close.__code__
                and frame.f_locals.get("self") is discovered
                and frame.f_locals.get("primary") is ordinary
                and claim is not None and claim.fd == fd
                and claim.disposition not in containment._CLOSE_TERMINAL
                and not _descriptor_is_closed(fd)):
            fired = True
            raise cancellation
        return interrupt_recovery_call

    monkeypatch.setattr(containment, "_close_claims_or_raise", fail_initial_close)
    try:
        sys.settrace(interrupt_recovery_call)
        with pytest.raises(cancellation_type) as caught:
            discovered.close()
        assert caught.value is cancellation
        assert fired is True
        assert discovered.fd == -1
        assert _descriptor_is_closed(fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_parent_candidate_ordinary_primary_recovery_boundary_closes_control(
        monkeypatch, tmp_path, cancellation_type):
    parent = tmp_path / "candidate-primary"
    parent.mkdir()
    for name in ("cgroup.procs", "cgroup.threads", "cgroup.subtree_control"):
        _write_control(parent, name)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    ordinary = RuntimeError("fixture parent-candidate primary")
    cancellation = cancellation_type("cancel parent-candidate recovery")
    real_open_control = containment._open_control
    real_close = containment.os.close
    opened = -1
    ordinary_raised = False
    fired = False
    previous_trace = sys.gettrace()

    def open_then_fail(dir_fd: int, name: str, flags: int, **kwargs):
        nonlocal opened, ordinary_raised
        opened = real_open_control(dir_fd, name, flags, **kwargs)
        ordinary_raised = True
        raise ordinary

    def interrupt_recovery_call(frame, event, _arg):
        nonlocal fired
        claims = frame.f_locals.get("claims")
        if (not fired and event == "line"
                and frame.f_code is containment._check_parent_candidate.__code__
                and ordinary_raised and frame.f_locals.get("primary") is ordinary
                and isinstance(claims, list) and len(claims) == 1
                and claims[0].fd == opened
                and claims[0].disposition not in containment._CLOSE_TERMINAL
                and not _descriptor_is_closed(opened)):
            fired = True
            raise cancellation
        return interrupt_recovery_call

    monkeypatch.setattr(containment, "_fstatfs_type",
                        lambda _fd: containment._CGROUP2_SUPER_MAGIC)
    monkeypatch.setattr(containment.os, "access", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(containment, "_open_control", open_then_fail)
    try:
        sys.settrace(interrupt_recovery_call)
        with pytest.raises(cancellation_type) as caught:
            containment._check_parent_candidate(parent_fd)
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(opened)
        os.fstat(parent_fd)
    finally:
        sys.settrace(previous_trace)
        if opened >= 0:
            _close_if_open(real_close, opened)
        _close_if_open(real_close, parent_fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_acquisition_post_create_primary_cleanup_boundary_rolls_back(
        monkeypatch, tmp_path, cancellation_type):
    delegated = tmp_path / "acquisition-primary"
    delegated.mkdir()
    leaf_name = f"quarry-{REQUEST_ID}"
    leaf = delegated / leaf_name
    discovered = containment._DiscoveredParent(
        os.open(delegated, containment._DIR_FLAGS), "/delegated",
    )
    parent_fd = discovered.fd
    ordinary = RuntimeError("fixture post-create acquisition primary")
    cancellation = cancellation_type("cancel acquisition cleanup entry")
    real_open = containment.os.open
    real_close = containment.os.close
    opened: list[int] = []
    fired = False
    previous_trace = sys.gettrace()

    def create_leaf(name: str, dir_fd: int) -> None:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        _populate_leaf(delegated / name)

    def recording_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if path == leaf_name and kwargs.get("dir_fd") == parent_fd:
            opened.append(fd)
        return fd

    def fail_leaf_superblock(fd: int) -> int:
        if fd in opened:
            raise ordinary
        return containment._CGROUP2_SUPER_MAGIC

    def interrupt_cleanup_entry(frame, event, _arg):
        nonlocal fired
        claims = frame.f_locals.get("claims")
        if (not fired and event == "line"
                and frame.f_code is containment._acquire_from_parent.__code__
                and frame.f_locals.get("original") is ordinary
                and frame.f_locals.get("created") is True
                and isinstance(frame.f_locals.get("leaf_identity"), tuple)
                and isinstance(claims, tuple) and claims
                and any(claim.fd >= 0 for claim in claims)
                and leaf.is_dir()):
            fired = True
            raise cancellation
        return interrupt_cleanup_entry

    monkeypatch.setattr(containment, "_mkdir_leaf", create_leaf)
    monkeypatch.setattr(containment, "_rmdir_cgroup", _fake_cgroup_rmdir)
    monkeypatch.setattr(containment.os, "open", recording_open)
    monkeypatch.setattr(containment, "_fstatfs_type", fail_leaf_superblock)
    try:
        sys.settrace(interrupt_cleanup_entry)
        with pytest.raises(cancellation_type) as caught:
            containment._acquire_from_parent(REQUEST_ID, discovered)
        assert caught.value is cancellation
        assert fired is True
        assert opened and all(_descriptor_is_closed(fd) for fd in opened)
        assert not leaf.exists()
        assert discovered.fd == parent_fd
        os.fstat(parent_fd)
    finally:
        sys.settrace(previous_trace)
        for fd in opened:
            _close_if_open(real_close, fd)
        if leaf.exists():
            _fake_cgroup_rmdir(leaf_name, parent_fd)
        discovered.close()


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_direct_close_ordinary_preaction_then_retry_boundary_cancellation_drains(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    ordinary = RuntimeError("fixture close pre-action primary")
    cancellation = cancellation_type("cancel close retry boundary")
    real_transaction = handle._close_owned_transaction
    transaction_calls = 0

    def scripted_transaction() -> None:
        nonlocal transaction_calls
        transaction_calls += 1
        if transaction_calls == 1:
            raise ordinary
        if transaction_calls == 2:
            raise cancellation
        real_transaction()

    monkeypatch.setattr(handle, "_close_owned_transaction", scripted_transaction)
    try:
        with pytest.raises(cancellation_type) as caught:
            handle.close()
        assert caught.value is cancellation
        assert transaction_calls == 3
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)
        assert handle._closed is True
        with pytest.raises(containment.ContainmentFailure) as replay:
            handle.close()
        assert replay.value.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
        assert transaction_calls == 4
    finally:
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_finish_proc_claim_assignment_line_cancellation_recovers_claim(
        tmp_path, cancellation_type):
    fd = os.open(tmp_path, containment._DIR_FLAGS)
    claim = containment._new_close_claim("fixture_assignment_proc", fd)
    cancellation = cancellation_type("cancel proc claims assignment")
    result = containment.MembershipVerification(
        False, containment.ContainmentReason.PROCESS_CGROUP_MISMATCH,
    )
    empty_claim_events = 0
    fired = False
    previous_trace = sys.gettrace()

    def interrupt_assignment_line(frame, event, _arg):
        nonlocal empty_claim_events, fired
        if (event == "line" and frame.f_code is containment._finish_proc_claim.__code__
                and frame.f_locals.get("claim") is claim
                and frame.f_locals.get("claims") == ()
                and claim.fd == fd
                and claim.disposition not in containment._CLOSE_TERMINAL):
            empty_claim_events += 1
            if not fired and empty_claim_events == 2:
                fired = True
                raise cancellation
        return interrupt_assignment_line

    try:
        sys.settrace(interrupt_assignment_line)
        with pytest.raises(cancellation_type) as caught:
            containment._finish_proc_claim(
                claim, primary=None, result=result,
            )
        assert caught.value is cancellation
        assert fired is True
        assert _descriptor_is_closed(fd)
        assert claim.disposition in containment._CLOSE_TERMINAL
    finally:
        sys.settrace(previous_trace)
        _close_if_open(os.close, fd)


def test_failed_acquisition_pins_leaf_identity_through_authenticated_rmdir(
        monkeypatch, tmp_path):
    delegated = tmp_path / "failed-anchor"
    leaf = delegated / "pending-leaf"
    leaf.mkdir(parents=True)
    _populate_leaf(leaf)
    parent_fd = os.open(delegated, containment._DIR_FLAGS)
    leaf_fd = os.open(leaf, containment._DIR_FLAGS)
    observed = os.fstat(leaf_fd)
    identity = (observed.st_dev, observed.st_ino)
    claim = containment._new_close_claim("fixture_leaf", leaf_fd)
    preserve = RuntimeError("fixture failed acquisition")
    moved = delegated / "held-original"
    marker = leaf / "foreign-marker"
    real_close = containment.os.close
    real_stat = containment.os.stat
    events: list[str] = []
    swapped = False

    def close_and_replace(fd: int) -> None:
        nonlocal swapped
        if fd != leaf_fd or swapped:
            real_close(fd)
            return
        swapped = True
        events.append("leaf_close")
        real_close(fd)
        if leaf.exists():
            leaf.rename(moved)
        leaf.mkdir()
        marker.write_text("foreign")

    def spoof_replacement_identity(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if (swapped and path == leaf.name
                and kwargs.get("dir_fd") == parent_fd):
            values = list(result)
            values[1] = identity[1]
            values[2] = identity[0]
            return os.stat_result(values)
        return result

    def recording_rmdir(name: str, dir_fd: int) -> None:
        if name == leaf.name and dir_fd == parent_fd:
            events.append("rmdir")
        _fake_cgroup_rmdir(name, dir_fd)

    monkeypatch.setattr(containment.os, "close", close_and_replace)
    monkeypatch.setattr(containment.os, "stat", spoof_replacement_identity)
    monkeypatch.setattr(containment, "_rmdir_cgroup", recording_rmdir)
    try:
        containment._cleanup_failed_acquisition(
            claims=(claim,), created=True, leaf_name=leaf.name,
            parent_fd=parent_fd, preserve=preserve,
            leaf_identity=identity,
        )
        assert swapped is True
        assert events == ["rmdir", "leaf_close"]
        assert leaf.is_dir() and marker.read_text() == "foreign"
        assert not moved.exists()
        assert _descriptor_is_closed(leaf_fd)
        os.fstat(parent_fd)
    finally:
        _close_if_open(real_close, leaf_fd)
        for directory in (leaf, moved):
            if directory.exists():
                for child in directory.iterdir():
                    if child.is_file():
                        child.unlink()
                directory.rmdir()
        _close_if_open(real_close, parent_fd)


def test_authenticated_remove_detects_same_name_swap_between_stat_and_rmdir(
        monkeypatch, tmp_path):
    parent = tmp_path / "authenticated-swap"
    leaf = parent / "leaf"
    held = parent / "held-original"
    leaf.mkdir(parents=True)
    parent_fd = os.open(parent, containment._DIR_FLAGS)
    leaf_fd = os.open(leaf, containment._DIR_FLAGS)
    observed = os.fstat(leaf_fd)
    identity = (observed.st_dev, observed.st_ino)
    claim = containment._new_close_claim("fixture_leaf", leaf_fd)
    attempt = containment._RemoveAttempt()
    rmdir_calls = 0

    def swap_then_remove_foreign(name: str, dir_fd: int) -> None:
        nonlocal rmdir_calls
        assert name == leaf.name and dir_fd == parent_fd
        rmdir_calls += 1
        leaf.rename(held)
        leaf.mkdir()
        _fake_cgroup_rmdir(name, dir_fd)

    monkeypatch.setattr(containment, "_rmdir_cgroup", swap_then_remove_foreign)
    try:
        with pytest.raises(containment.ContainmentFailure) as caught:
            containment._remove_authenticated_once(
                attempt, name=leaf.name, parent_fd=parent_fd,
                identity=identity, anchor=claim,
                reason=containment.ContainmentReason.REMOVE_FAILED,
            )
        assert caught.value.reason is containment.ContainmentReason.REMOVE_FAILED
        assert rmdir_calls == 1
        assert attempt.state == "ambiguous"
        assert not leaf.exists()
        assert held.is_dir()
        anchored = os.fstat(leaf_fd)
        named = held.stat()
        assert (anchored.st_dev, anchored.st_ino) == identity
        assert (named.st_dev, named.st_ino) == identity
        assert anchored.st_nlink > 0
    finally:
        _close_if_open(os.close, leaf_fd)
        if leaf.exists():
            leaf.rmdir()
        if held.exists():
            held.rmdir()
        _close_if_open(os.close, parent_fd)


def test_settlement_same_name_swap_never_caches_settled_truth(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    held = leaf.parent / "held-settlement-original"
    identity = handle._leaf_identity
    rmdir_calls = 0

    def swap_then_remove_foreign(name: str, dir_fd: int) -> None:
        nonlocal rmdir_calls
        if name == leaf.name and dir_fd == handle._parent_fd:
            rmdir_calls += 1
            leaf.rename(held)
            leaf.mkdir()
            _populate_leaf(leaf)
        _fake_cgroup_rmdir(name, dir_fd)

    monkeypatch.setattr(containment, "_rmdir_cgroup", swap_then_remove_foreign)
    try:
        with pytest.raises(containment.ContainmentFailure) as caught:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert caught.value.reason is containment.ContainmentReason.REMOVE_FAILED
        assert rmdir_calls == 1
        assert not leaf.exists()
        assert held.is_dir()
        named = held.stat()
        assert (named.st_dev, named.st_ino) == identity
        assert named.st_nlink > 0
        assert handle._removed is False
        assert handle._closed is True
        assert handle._settlement_cache is None
        assert handle._settlement_failure is not None
        assert (handle._settlement_failure.reason
                is containment.ContainmentReason.REMOVE_FAILED)
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)

        with pytest.raises(containment.ContainmentFailure) as replay:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert replay.value.reason is containment.ContainmentReason.REMOVE_FAILED
        assert rmdir_calls == 1
    finally:
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for directory in (leaf, held):
            if directory.exists():
                cleanup_parent = os.open(directory.parent, containment._DIR_FLAGS)
                try:
                    _fake_cgroup_rmdir(directory.name, cleanup_parent)
                finally:
                    os.close(cleanup_parent)


def test_unpublished_rollback_pins_leaf_identity_through_rmdir(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    target_fd = handle._leaf_fd
    identity = handle._leaf_identity
    preserve = RuntimeError("fixture unpublished anchor")
    moved = leaf.parent / "held-unpublished-original"
    marker = leaf / "foreign-marker"
    real_close = containment.os.close
    real_stat = containment.os.stat
    events: list[str] = []
    swapped = False

    def close_and_replace(fd: int) -> None:
        nonlocal swapped
        if fd != target_fd or swapped:
            real_close(fd)
            return
        swapped = True
        events.append("leaf_close")
        real_close(fd)
        if leaf.exists():
            leaf.rename(moved)
        leaf.mkdir()
        marker.write_text("foreign")

    def spoof_replacement_identity(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if (swapped and path == leaf.name
                and kwargs.get("dir_fd") == handle._parent_fd):
            values = list(result)
            values[1] = identity[1]
            values[2] = identity[0]
            return os.stat_result(values)
        return result

    def recording_rmdir(name: str, parent_fd: int) -> None:
        if name == leaf.name:
            events.append("rmdir")
        _fake_cgroup_rmdir(name, parent_fd)

    monkeypatch.setattr(containment.os, "close", close_and_replace)
    monkeypatch.setattr(containment.os, "stat", spoof_replacement_identity)
    monkeypatch.setattr(containment, "_rmdir_cgroup", recording_rmdir)
    try:
        with pytest.raises(RuntimeError) as caught:
            containment._rollback_unpublished_handle(handle, preserve)
        assert caught.value is preserve
        assert swapped is True
        assert events == ["rmdir", "leaf_close"]
        assert leaf.is_dir() and marker.read_text() == "foreign"
        assert not moved.exists()
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert handle._removed is True and handle._closed is True
    finally:
        for fd in owned:
            _close_if_open(real_close, fd)
        for directory in (leaf, moved):
            if directory.exists():
                for child in directory.iterdir():
                    if child.is_file():
                        child.unlink()
                directory.rmdir()


def test_descendant_identity_fd_remains_pinned_through_named_rmdir(
        monkeypatch, tmp_path):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    child = leaf / "child"
    child.mkdir()
    held = leaf.parent / "held-child-original"
    marker = child / "foreign-marker"
    real_open = containment.os.open
    real_close = containment.os.close
    real_scandir = containment.os.scandir
    target_fd = -1
    swapped = False
    events: list[str] = []

    class SnapshotIterator:
        def __init__(self, fd: int):
            wrapped = real_scandir(fd)
            try:
                self.entries = list(wrapped)
            finally:
                wrapped.close()
            self.index = 0
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            if self.index >= len(self.entries):
                raise StopIteration
            entry = self.entries[self.index]
            self.index += 1
            return entry

        def close(self):
            self.closed = True

    def recording_open(path, flags, *args, **kwargs):
        nonlocal target_fd
        fd = real_open(path, flags, *args, **kwargs)
        if (target_fd < 0 and path == "child"
                and kwargs.get("dir_fd") is not None):
            target_fd = fd
        return fd

    def close_and_replace(fd: int) -> None:
        nonlocal swapped
        if fd != target_fd or swapped:
            real_close(fd)
            return
        swapped = True
        events.append("child_close")
        real_close(fd)
        if child.exists():
            child.rename(held)
        child.mkdir()
        marker.write_text("foreign")

    def recording_rmdir(name: str, parent_fd: int) -> None:
        if name == "child":
            events.append("child_rmdir")
        _fake_cgroup_rmdir(name, parent_fd)

    monkeypatch.setattr(containment.os, "open", recording_open)
    monkeypatch.setattr(containment.os, "close", close_and_replace)
    monkeypatch.setattr(containment.os, "scandir", SnapshotIterator)
    monkeypatch.setattr(containment, "_rmdir_cgroup", recording_rmdir)
    try:
        with pytest.raises(containment.ContainmentFailure) as caught:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert caught.value.reason is containment.ContainmentReason.REMOVE_FAILED
        assert target_fd >= 0 and swapped is True
        assert events.index("child_rmdir") < events.index("child_close")
        assert child.is_dir() and marker.read_text() == "foreign"
        assert not held.exists()
        assert handle._settlement_cache is None
        assert handle._settlement_failure is not None
        assert (handle._settlement_failure.reason
                is containment.ContainmentReason.REMOVE_FAILED)
        assert handle._closed is True
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)
    finally:
        monkeypatch.setattr(containment.os, "scandir", real_scandir)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        _close_if_open(real_close, target_fd)
        for directory in (child, held):
            if directory.exists():
                for entry in directory.iterdir():
                    if entry.is_file():
                        entry.unlink()
                directory.rmdir()
        if leaf.exists():
            cleanup_parent = os.open(leaf.parent, containment._DIR_FLAGS)
            try:
                _fake_cgroup_rmdir(leaf.name, cleanup_parent)
            finally:
                os.close(cleanup_parent)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_public_acquire_discovered_close_call_cancellation_drains_parent(
        monkeypatch, tmp_path, cancellation_type):
    directory = tmp_path / "public-acquire-parent"
    directory.mkdir()
    fd = os.open(directory, containment._DIR_FLAGS)
    discovered = containment._DiscoveredParent(fd, "/delegated")
    ordinary = RuntimeError("fixture public acquire primary")
    cancellation = cancellation_type("cancel public acquire discovery close")
    fired = False
    previous_trace = sys.gettrace()
    real_close = containment.os.close
    close_line = _source_line(
        containment.acquire_direct_cgroup_v2, "discovered.close()",
    )

    def fail_acquisition(*_args):
        raise ordinary

    def interrupt_discovery_close_call(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is containment.acquire_direct_cgroup_v2.__code__
                and frame.f_lineno == close_line
                and frame.f_locals.get("primary") is ordinary
                and frame.f_locals.get("discovered") is discovered
                and frame.f_locals.get("cleanup") is None
                and discovered.fd == fd and not _descriptor_is_closed(fd)):
            fired = True
            raise cancellation
        return interrupt_discovery_close_call

    monkeypatch.setattr(containment, "_discover_parent", lambda: discovered)
    monkeypatch.setattr(containment, "_acquire_from_parent", fail_acquisition)
    try:
        sys.settrace(interrupt_discovery_close_call)
        with pytest.raises(cancellation_type) as caught:
            containment.acquire_direct_cgroup_v2(REQUEST_ID)
        assert caught.value is cancellation
        assert fired is True
        assert discovered.fd == -1
        assert _descriptor_is_closed(fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_public_probe_second_discovered_close_call_cancellation_drains_parent(
        monkeypatch, tmp_path, cancellation_type):
    directory = tmp_path / "public-probe-parent"
    directory.mkdir()
    fd = os.open(directory, containment._DIR_FLAGS)
    discovered = containment._DiscoveredParent(fd, "/delegated")
    ordinary = RuntimeError("fixture first public probe close")
    cancellation = cancellation_type("cancel public probe discovery close")
    real_discovered_close = containment._DiscoveredParent.close
    real_os_close = containment.os.close
    close_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    close_line = _source_line(
        containment.probe_direct_cgroup_v2, "discovered.close()",
        occurrence=2,
    )

    def fail_first_close(owner) -> None:
        nonlocal close_calls
        assert owner is discovered
        close_calls += 1
        if close_calls == 1:
            raise ordinary
        real_discovered_close(owner)

    def interrupt_second_close_call(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is containment.probe_direct_cgroup_v2.__code__
                and frame.f_lineno == close_line
                and frame.f_locals.get("primary") is ordinary
                and frame.f_locals.get("cleanup") is None
                and frame.f_locals.get("discovered") is discovered
                and close_calls == 1 and discovered.fd == fd
                and not _descriptor_is_closed(fd)):
            fired = True
            raise cancellation
        return interrupt_second_close_call

    monkeypatch.setattr(containment, "_discover_parent", lambda: discovered)
    monkeypatch.setattr(containment._DiscoveredParent, "close", fail_first_close)
    try:
        sys.settrace(interrupt_second_close_call)
        with pytest.raises(cancellation_type) as caught:
            containment.probe_direct_cgroup_v2()
        assert caught.value is cancellation
        assert fired is True
        assert close_calls == 2
        assert discovered.fd == -1
        assert _descriptor_is_closed(fd)
    finally:
        sys.settrace(previous_trace)
        _close_if_open(real_os_close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_settlement_pre_remove_call_cancellation_reconciles_terminal_truth(
        monkeypatch, tmp_path, cancellation_type):
    handle, leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    cancellation = cancellation_type("cancel settlement before removal helper")
    real_identity = handle._leaf_identity_current
    real_descendants = handle._remove_descendants
    real_remove = containment._remove_authenticated_fenced
    identity_calls = 0
    descendants_complete = False
    remove_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    transaction_code = handle._kill_settle_remove_transaction.__func__.__code__

    def recording_identity() -> bool:
        nonlocal identity_calls
        identity_calls += 1
        return real_identity()

    def recording_descendants(directory_fd: int, deadline: float) -> None:
        nonlocal descendants_complete
        real_descendants(directory_fd, deadline)
        descendants_complete = True

    def recording_remove(*args, **kwargs) -> None:
        nonlocal remove_calls
        remove_calls += 1
        real_remove(*args, **kwargs)

    def interrupt_pre_remove_call(frame, event, _arg):
        nonlocal fired
        attempt = frame.f_locals.get("remove_attempt")
        if (not fired and event == "line" and frame.f_code is transaction_code
                and descendants_complete and identity_calls >= 2
                and type(attempt) is containment._RemoveAttempt
                and attempt.state == "not_started" and remove_calls == 0
                and handle._removed is False and leaf.is_dir()):
            fired = True
            raise cancellation
        return interrupt_pre_remove_call

    monkeypatch.setattr(handle, "_leaf_identity_current", recording_identity)
    monkeypatch.setattr(handle, "_remove_descendants", recording_descendants)
    monkeypatch.setattr(containment, "_remove_authenticated_fenced",
                        recording_remove)
    try:
        sys.settrace(interrupt_pre_remove_call)
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert remove_calls == 1
        assert not leaf.exists()
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)
        assert handle._closed is True and handle._removed is True

        try:
            replay = handle.kill_settle_remove(time.monotonic() + 1)
        except containment.ContainmentFailure as exc:
            assert exc.reason is containment.ContainmentReason.DESCRIPTOR_CLOSE_FAILED
        else:
            assert replay == containment.ContainmentSettlement(
                True, True, True, containment.ContainmentReason.SETTLED,
            )
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_settlement_post_handler_reconciliation_cancellation_terminalizes_once(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    ordinary = RuntimeError("fixture settlement traversal primary")
    cancellation = cancellation_type("cancel first post-handler line")
    real_remove = containment._remove_authenticated_fenced
    traversal_calls = 0
    remove_calls = 0
    fired = False
    previous_trace = sys.gettrace()
    transaction = containment.DirectCgroupV2._kill_settle_remove_transaction
    reconciliation_line = _source_line(transaction, "chosen = operation_error")

    def fail_traversal(_directory_fd: int, _deadline: float) -> None:
        nonlocal traversal_calls
        traversal_calls += 1
        raise ordinary

    def recording_remove(*args, **kwargs) -> None:
        nonlocal remove_calls
        remove_calls += 1
        real_remove(*args, **kwargs)

    def interrupt_reconciliation(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is transaction.__code__
                and frame.f_lineno == reconciliation_line
                and frame.f_locals.get("operation_error") is ordinary
                and frame.f_locals.get("handler_boundary") is None
                and "chosen" not in frame.f_locals):
            fired = True
            raise cancellation
        return interrupt_reconciliation

    monkeypatch.setattr(handle, "_remove_descendants", fail_traversal)
    monkeypatch.setattr(
        containment, "_remove_authenticated_fenced", recording_remove,
    )
    try:
        sys.settrace(interrupt_reconciliation)
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert traversal_calls == 1 and remove_calls == 0
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)
        assert handle._closed is True
        assert handle._settlement_cache is None
        assert handle._settlement_failure is not None
        assert (handle._settlement_failure.reason
                is containment.ContainmentReason.REMOVE_FAILED)

        mutations = traversal_calls, remove_calls
        with pytest.raises(containment.ContainmentFailure) as replay:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert replay.value.reason is containment.ContainmentReason.REMOVE_FAILED
        assert (traversal_calls, remove_calls) == mutations
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_public_settlement_first_handler_line_cancellation_drains_outer_owner(
        monkeypatch, tmp_path, cancellation_type):
    handle, _leaf = _acquire_fixture(monkeypatch, tmp_path)
    owned = [
        handle._kill_fd, handle._events_fd, handle._procs_write_fd,
        handle._procs_read_fd, handle._leaf_fd, handle._parent_fd,
    ]
    ordinary = RuntimeError("fixture public settlement transaction primary")
    cancellation = cancellation_type("cancel public settlement handler entry")
    real_transaction = handle._kill_settle_remove_transaction
    real_finish = handle._finish_settlement_teardown
    transaction_calls = 0
    finish_primaries: list[BaseException] = []
    fired = False
    previous_trace = sys.gettrace()
    public_method = containment.DirectCgroupV2.kill_settle_remove
    handler_line = _source_line(public_method, "primary = exc")

    def fail_transaction(_deadline: float):
        nonlocal transaction_calls
        transaction_calls += 1
        handle._settlement_teardown_started = True
        raise ordinary

    def recording_finish(primary: BaseException) -> None:
        finish_primaries.append(primary)
        real_finish(primary)

    def interrupt_first_handler_line(frame, event, _arg):
        nonlocal fired
        if (not fired and event == "line"
                and frame.f_code is public_method.__code__
                and frame.f_lineno == handler_line
                and frame.f_locals.get("exc") is ordinary
                and frame.f_locals.get("primary") is None
                and finish_primaries == []):
            fired = True
            raise cancellation
        return interrupt_first_handler_line

    monkeypatch.setattr(handle, "_kill_settle_remove_transaction", fail_transaction)
    monkeypatch.setattr(handle, "_finish_settlement_teardown", recording_finish)
    try:
        sys.settrace(interrupt_first_handler_line)
        with pytest.raises(cancellation_type) as caught:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert caught.value is cancellation
        assert fired is True
        assert transaction_calls == 1
        assert finish_primaries == [cancellation]
        assert all(_descriptor_is_closed(fd) for fd in owned)
        assert all(claim.disposition in containment._CLOSE_TERMINAL
                   for claim in handle._close_claims)
        assert handle._closed is True
        assert handle._settlement_cache is None
        assert handle._settlement_failure is not None
        assert (handle._settlement_failure.reason
                is containment.ContainmentReason.REMOVE_FAILED)

        terminal_snapshot = tuple(
            (claim.fd, claim.attempts, claim.disposition)
            for claim in handle._close_claims
        )
        failure_snapshot = (
            handle._settlement_failure.reason,
            handle._settlement_failure.os_errno,
        )
        monkeypatch.setattr(
            handle, "_kill_settle_remove_transaction", real_transaction,
        )
        with pytest.raises(containment.ContainmentFailure) as replay:
            handle.kill_settle_remove(time.monotonic() + 1)
        assert replay.value.reason is containment.ContainmentReason.REMOVE_FAILED
        assert transaction_calls == 1
        assert tuple(
            (claim.fd, claim.attempts, claim.disposition)
            for claim in handle._close_claims
        ) == terminal_snapshot
        assert handle._settlement_failure is not None
        assert (
            handle._settlement_failure.reason,
            handle._settlement_failure.os_errno,
        ) == failure_snapshot
        assert all(_descriptor_is_closed(fd) for fd in owned)
    finally:
        sys.settrace(previous_trace)
        try:
            handle.close()
        except containment.ContainmentError:
            pass
        for fd in owned:
            _close_if_open(containment.os.close, fd)


def test_pgid_fallback_can_never_claim_tree_proof():
    fallback = containment.PgidFallback(1234)
    assert fallback.kind is ContainmentKind.PGID
    assert (fallback.containment_assurance
            is ContainmentAssurance.PROCESS_GROUP)
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
