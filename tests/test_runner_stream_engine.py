"""Real-process contract for the worker-owned binary stream engine.

These cases deliberately stop at the worker/stage boundary: the engine owns the
tool pipes and records exact stream testimony, while the caller retains ownership
of the already-open stage descriptors.  Durable publication is a later Phase-1
step.
"""
from __future__ import annotations

import hashlib
import os
import sys
import time

import pytest

from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_streams
from quarry_recon import runner_worker


pytestmark = [pytest.mark.offline, pytest.mark.synthetic_process]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _spawn_launcher():
    """Fork the target-blind launcher with two distinct worker-channel FDs."""
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


def _close_launcher_fds(launcher) -> None:
    for name in ("stdin_write_fd", "stdout_read_fd", "stderr_read_fd"):
        fd = getattr(launcher, name, -1)
        if type(fd) is int and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
            setattr(launcher, name, -1)


def _stage_bytes(fd: int) -> bytes:
    size = os.fstat(fd).st_size
    return os.pread(fd, size, 0)


def _stream(settlement, role: protocol.StreamRole):
    return next(stream for stream in settlement.streams if stream.role is role)


def _execute(
    tmp_path,
    script: str,
    *,
    stdin_text: str | None = None,
    cap: int | None = None,
    timeout: int | float = 5,
    execution_window: float | None = None,
    settlement_window: float = 8,
):
    invocation = protocol.normalize_invocation(
        request_id=os.urandom(16).hex(),
        tool="stream-fixture",
        cmd=(sys.executable, "-c", script),
        timeout=timeout,
        stdin_data=stdin_text,
        env={},
        base_environment={},
        raw_path=tmp_path / f"{os.urandom(8).hex()}.stdout",
        stderr_path=tmp_path / f"{os.urandom(8).hex()}.stderr",
        max_output_bytes=cap,
    )
    stdout_stage = os.open(
        tmp_path / f"{os.urandom(8).hex()}.stdout.stage",
        os.O_RDWR | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    stderr_stage = os.open(
        tmp_path / f"{os.urandom(8).hex()}.stderr.stage",
        os.O_RDWR | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    launcher = _spawn_launcher()
    try:
        assert launcher.prove_stopped() is True
        started = time.monotonic()
        if execution_window is None:
            execution_deadline = None if timeout == 0 else started + float(timeout)
        else:
            execution_deadline = started + execution_window
        settlement = runner_streams._run_stream_engine(
            invocation.worker,
            launcher,
            stdin_data=invocation.stdin_data,
            stdout_stage_fd=stdout_stage,
            stderr_stage_fd=stderr_stage,
            execution_deadline=execution_deadline,
            settlement_deadline=started + settlement_window,
        )
        # Stage authority stays with the caller after the engine returns.
        os.fstat(stdout_stage)
        os.fstat(stderr_stage)
        return settlement, _stage_bytes(stdout_stage), _stage_bytes(stderr_stage)
    finally:
        try:
            launcher.abort_and_reap()
        finally:
            _close_launcher_fds(launcher)
            os.close(stdout_stage)
            os.close(stderr_stage)


@pytest.mark.parametrize(
    "stdout,stderr",
    [
        (b"", b""),
        (b"\x00\xffstdout\n", b"\x80stderr\x00"),
    ],
)
def test_binary_non_utf8_and_empty_streams_settle_exactly(
    tmp_path, stdout, stderr,
):
    script = (
        "import os;"
        f"os.write(1,bytes.fromhex({stdout.hex()!r}));"
        f"os.write(2,bytes.fromhex({stderr.hex()!r}))"
    )
    settlement, staged_stdout, staged_stderr = _execute(tmp_path, script)

    assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert settlement.exit_code == 0
    assert staged_stdout == stdout
    assert staged_stderr == stderr
    stdin_stream = _stream(settlement, protocol.StreamRole.STDIN)
    stdout_stream = _stream(settlement, protocol.StreamRole.STDOUT)
    stderr_stream = _stream(settlement, protocol.StreamRole.STDERR)
    assert stdin_stream.terminal is protocol.StreamTerminal.COMPLETE
    assert stdin_stream.observed_bytes == 0
    assert stdin_stream.observed_sha256 == _digest(b"")
    for stream, expected in ((stdout_stream, stdout), (stderr_stream, stderr)):
        assert stream.terminal is protocol.StreamTerminal.EOF
        assert stream.observed_bytes == len(expected)
        assert stream.retained_bytes == len(expected)
        assert stream.observed_sha256 == _digest(expected)
        assert stream.retained_sha256 == _digest(expected)
        assert stream.lines == expected.count(b"\n")


@pytest.mark.parametrize(
    "cap,retained,terminal",
    [
        (None, b"a\nbc", protocol.StreamTerminal.EOF),
        (0, b"", protocol.StreamTerminal.CAPPED),
        (2, b"a\n", protocol.StreamTerminal.CAPPED),
        (4, b"a\nbc", protocol.StreamTerminal.EOF),
    ],
)
def test_stdout_cap_retains_exact_prefix_but_observes_complete_stream(
    tmp_path, cap, retained, terminal,
):
    observed = b"a\nbc"
    settlement, staged_stdout, _staged_stderr = _execute(
        tmp_path, "import os; os.write(1,b'a\\nbc')", cap=cap,
    )

    stream = _stream(settlement, protocol.StreamRole.STDOUT)
    assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert staged_stdout == retained
    assert stream.terminal is terminal
    assert stream.observed_bytes == len(observed)
    assert stream.observed_sha256 == _digest(observed)
    assert stream.retained_bytes == len(retained)
    assert stream.retained_sha256 == _digest(retained)
    assert stream.lines == retained.count(b"\n")


def test_large_data_stdin_and_simultaneous_outputs_do_not_deadlock(tmp_path):
    stdin = "i" * (512 * 1024)
    script = """
import os
while True:
    block = os.read(0, 4096)
    if not block:
        break
    os.write(1, b'o' * len(block))
    os.write(2, b'e' * len(block))
"""
    settlement, staged_stdout, staged_stderr = _execute(
        tmp_path, script, stdin_text=stdin, settlement_window=12,
    )

    expected_stdout = b"o" * len(stdin)
    expected_stderr = b"e" * len(stdin)
    assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert staged_stdout == expected_stdout
    assert staged_stderr == expected_stderr
    stdin_stream = _stream(settlement, protocol.StreamRole.STDIN)
    assert stdin_stream.terminal is protocol.StreamTerminal.COMPLETE
    assert stdin_stream.observed_bytes == len(stdin)
    assert stdin_stream.observed_sha256 == _digest(stdin.encode())
    assert _stream(settlement, protocol.StreamRole.STDOUT).observed_sha256 \
        == _digest(expected_stdout)
    assert _stream(settlement, protocol.StreamRole.STDERR).observed_sha256 \
        == _digest(expected_stderr)


def test_empty_data_stdin_is_distinct_from_null_but_both_complete(tmp_path):
    script = "import os; data=os.read(0,1); os.write(1,b'eof' if not data else b'data')"
    null_settlement, null_stdout, _ = _execute(tmp_path, script)
    data_settlement, data_stdout, _ = _execute(tmp_path, script, stdin_text="")

    assert null_stdout == data_stdout == b"eof"
    for settlement in (null_settlement, data_settlement):
        stdin_stream = _stream(settlement, protocol.StreamRole.STDIN)
        assert stdin_stream.terminal is protocol.StreamTerminal.COMPLETE
        assert stdin_stream.observed_bytes == 0
        assert stdin_stream.observed_sha256 == _digest(b"")


def test_early_stdin_close_is_bounded_and_preserves_output(tmp_path):
    stdin = "i" * (2 * 1024 * 1024)
    settlement, staged_stdout, _ = _execute(
        tmp_path,
        "import os; os.close(0); os.write(1,b'done')",
        stdin_text=stdin,
    )

    stdin_stream = _stream(settlement, protocol.StreamRole.STDIN)
    assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert stdin_stream.terminal is protocol.StreamTerminal.PEER_CLOSED
    assert stdin_stream.observed_bytes < len(stdin)
    assert staged_stdout == b"done"


def test_finite_execution_deadline_times_out_once_and_retains_prefix(tmp_path):
    started = time.monotonic()
    settlement, staged_stdout, _ = _execute(
        tmp_path,
        "import os,time; os.write(1,b'prefix'); time.sleep(30)",
        timeout=30,
        execution_window=0.25,
        settlement_window=2,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 3
    assert settlement.terminal is protocol.ExecutionTerminal.TIMED_OUT
    assert staged_stdout == b"prefix"
    assert _stream(settlement, protocol.StreamRole.STDOUT).terminal \
        is protocol.StreamTerminal.DEADLINE


def test_timeout_zero_has_no_execution_cutoff_for_natural_exit(tmp_path):
    settlement, staged_stdout, staged_stderr = _execute(
        tmp_path,
        "import os; os.write(1,b'natural'); os.write(2,b'exit')",
        timeout=0,
        settlement_window=3,
    )

    assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    assert settlement.exit_code == 0
    assert staged_stdout == b"natural"
    assert staged_stderr == b"exit"


def test_timeout_zero_accepts_no_preexisting_settlement_deadline(tmp_path):
    invocation = protocol.normalize_invocation(
        request_id=os.urandom(16).hex(),
        tool="stream-fixture",
        cmd=(sys.executable, "-c", "import os; os.write(1,b'unbounded')"),
        timeout=0,
        env={},
        base_environment={},
        raw_path=tmp_path / "unbounded.stdout",
        stderr_path=tmp_path / "unbounded.stderr",
    )
    stdout_stage = os.open(
        tmp_path / "unbounded.stdout.stage",
        os.O_RDWR | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    stderr_stage = os.open(
        tmp_path / "unbounded.stderr.stage",
        os.O_RDWR | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    launcher = _spawn_launcher()
    try:
        assert launcher.prove_stopped() is True
        settlement = runner_streams._run_stream_engine(
            invocation.worker,
            launcher,
            stdout_stage_fd=stdout_stage,
            stderr_stage_fd=stderr_stage,
            execution_deadline=None,
            settlement_deadline=None,
        )
        assert settlement.terminal is protocol.ExecutionTerminal.COMPLETE
        assert _stage_bytes(stdout_stage) == b"unbounded"
    finally:
        try:
            launcher.abort_and_reap()
        finally:
            _close_launcher_fds(launcher)
            os.close(stdout_stage)
            os.close(stderr_stage)
