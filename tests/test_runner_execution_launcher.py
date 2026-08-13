"""Red contract for the private, release-gated execution launcher primitive.

The launcher is forked before any target-effective request is available.  Its
private release channel is the only exec authority: scheduling signals, EOF,
truncated bytes, and a naked request frame must all terminate without exec.
"""
from __future__ import annotations

import os
import select
import signal
import sys
import time

import pytest

from quarry_recon import runner_ipc
from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_worker


pytestmark = pytest.mark.integration


def _require_linux_procfs() -> None:
    if sys.platform != "linux" or not os.path.isdir("/proc/self/fd"):
        pytest.skip("release-gated launch identity requires Linux procfs")


def _read_to_eof(fd: int, *, timeout: float = 5.0) -> bytes:
    deadline = time.monotonic() + timeout
    chunks = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail("execution pipe did not reach EOF")
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            pytest.fail("execution pipe did not reach EOF")
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _close_launcher_fds(launcher) -> None:
    for name in ("stdin_write_fd", "stdout_read_fd", "stderr_read_fd"):
        fd = getattr(launcher, name, -1)
        if type(fd) is int and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _spawn_launcher():
    """Supply the two distinct worker-channel identities required at fork."""
    request_read, request_write = os.pipe()
    control_read, control_write = os.pipe()
    try:
        return runner_worker._spawn_execution_launcher(
            inherited_fds=(request_read, control_write),
        )
    finally:
        for fd in (request_read, request_write, control_read, control_write):
            try:
                os.close(fd)
            except OSError:
                pass


def _settle_launcher(launcher) -> None:
    try:
        launcher.abort_and_reap()
    finally:
        _close_launcher_fds(launcher)


def _request(*, request_id: str, argv, environment=None, cwd=None):
    return protocol.normalize_invocation(
        request_id=request_id,
        tool="fixture",
        cmd=argv,
        timeout=30,
        env=environment or {},
        base_environment={},
        cwd=cwd,
    ).worker


def _proc_bytes(pid: int, name: str) -> bytes:
    with open(f"/proc/{pid}/{name}", "rb") as source:
        return source.read()


def test_authenticated_release_execs_exact_request_and_exposes_binary_pipes(
        tmp_path):
    _require_linux_procfs()
    launcher = _spawn_launcher()
    try:
        assert launcher.prove_stopped() is True

        # These values are created only after fork.  They cannot have entered the
        # child through argv, environment, or the launcher's fork snapshot.
        argv_secret = f"argv-{os.urandom(12).hex()}"
        env_secret = f"env-{os.urandom(12).hex()}"
        work = tmp_path / "exact-cwd"
        work.mkdir()
        script = (
            "import os,sys;"
            "os.write(1,b'\\x00\\xffstdout\\n'+sys.argv[1].encode()"
            "+b'\\x00'+os.environb[b'TOKEN']+b'\\x00'+os.getcwd().encode());"
            "os.write(2,b'\\x80stderr\\x00')"
        )
        request = _request(
            request_id="b1" * 16,
            argv=(sys.executable, "-c", script, argv_secret),
            environment={"TOKEN": env_secret},
            cwd=str(work),
        )

        parked_cmdline = _proc_bytes(launcher.pid, "cmdline")
        parked_environment = _proc_bytes(launcher.pid, "environ")
        assert argv_secret.encode() not in parked_cmdline
        assert env_secret.encode() not in parked_environment

        assert launcher.release_for_exec(request) is True
        os.close(launcher.stdin_write_fd)
        launcher.stdin_write_fd = -1
        stdout = _read_to_eof(launcher.stdout_read_fd)
        stderr = _read_to_eof(launcher.stderr_read_fd)
        assert stdout == (
            b"\x00\xffstdout\n" + argv_secret.encode()
            + b"\x00" + env_secret.encode()
            + b"\x00" + os.fsencode(work)
        )
        assert stderr == b"\x80stderr\x00"
        assert launcher.abort_and_reap() == 0
    finally:
        _settle_launcher(launcher)


def test_sigcont_is_scheduling_only_and_cannot_release_exec(tmp_path):
    _require_linux_procfs()
    marker = tmp_path / "stray-sigcont-exec"
    launcher = _spawn_launcher()
    try:
        assert launcher.prove_stopped() is True
        executable = os.stat(f"/proc/{launcher.pid}/exe")
        executable_identity = (executable.st_dev, executable.st_ino)
        os.kill(launcher.pid, signal.SIGCONT)
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            if marker.exists():
                break
            time.sleep(0.01)
        assert not marker.exists()
        assert os.path.isdir(f"/proc/{launcher.pid}")
        executable = os.stat(f"/proc/{launcher.pid}/exe")
        assert (executable.st_dev, executable.st_ino) == executable_identity
    finally:
        _settle_launcher(launcher)


def test_release_refuses_a_non_request_without_resuming_launcher():
    _require_linux_procfs()
    launcher = _spawn_launcher()
    try:
        assert launcher.prove_stopped() is True
        assert launcher.release_for_exec(object()) is False
        with open(f"/proc/{launcher.pid}/stat", "rb") as source:
            state = source.read().split(b") ", 1)[1].split(None, 1)[0]
        assert state in (b"T", b"t")
    finally:
        _settle_launcher(launcher)


@pytest.mark.parametrize("wire", ["eof", "truncated", "trailing"])
def test_unauthenticated_release_channel_input_never_execs(tmp_path, wire):
    _require_linux_procfs()
    marker = tmp_path / f"{wire}-exec"
    request = _request(
        request_id="b2" * 16,
        argv=(
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).write_bytes(b'exec')",
        ),
    )
    launcher = _spawn_launcher()
    try:
        assert launcher.prove_stopped() is True
        release_write = launcher._release_write
        if wire == "truncated":
            runner_ipc.write_all(release_write, b"\x00\x00\x00\x20{")
        elif wire == "trailing":
            # A complete request with unauthenticated trailing data is not the
            # exact one-message release accepted by the launcher.
            runner_ipc.write_all(
                release_write, protocol.encode_request(request) + b"x",
            )
        os.close(release_write)
        launcher._release_write = -1
        os.kill(launcher.pid, signal.SIGCONT)
        assert type(launcher.abort_and_reap()) is int
        assert not marker.exists()
    finally:
        _settle_launcher(launcher)


def test_execution_launcher_is_additive_to_abort_only_launcher():
    assert runner_worker._spawn_execution_launcher \
        is not runner_worker._spawn_parked_launcher
