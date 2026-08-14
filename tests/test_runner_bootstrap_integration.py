"""Real-process smoke test for the fixed non-launching worker module."""
from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from quarry_recon import runner_protocol as protocol
from quarry_recon import runner_supervisor as supervisor


pytestmark = [pytest.mark.offline, pytest.mark.synthetic_process]


@pytest.fixture(autouse=True)
def _acquire_fake_direct_containment(fake_direct_containment):
    """Use a fake cgroup handle while retaining the real worker/launcher pair."""
    return fake_direct_containment


def test_real_fixed_worker_completes_authenticated_prelaunch_abort(monkeypatch):
    request = protocol.normalize_invocation(
        request_id="91" * 16,
        tool="fixture",
        cmd=["tool-sentinel-must-not-launch", "target-sentinel"],
        timeout=30,
        env={"TOKEN": "environment-sentinel"},
        base_environment={"PATH": "/usr/bin"},
    ).worker
    # H0 runs under an installed project interpreter; using that exact executable
    # keeps ``-I`` meaningful and avoids PYTHONPATH-based imports.
    monkeypatch.setattr(supervisor.sys, "executable", sys.executable)
    outcome = supervisor.bootstrap_worker(
        request, deadline=time.monotonic() + 5,
    )
    assert outcome.reason is supervisor.BootstrapReason.ABORTED
    assert outcome.transaction_complete
    assert outcome.worker_reaped and outcome.worker_returncode == 0
    assert outcome.control_eof and outcome.observed_trailing_control_bytes == 0
    assert outcome.abort_command_sent is True
    assert outcome.parent_pipes_closed is True
    assert outcome.kill_requested is False
    assert outcome.settlement is not None
    assert outcome.settlement.terminal is protocol.ExecutionTerminal.CANCELLED
    assert outcome.settlement.launched is False
    assert outcome.settlement.process_group_settled is True
    assert outcome.settlement.process_tree_settled is False
    assert all(
        stream.terminal is protocol.StreamTerminal.NOT_STARTED
        for stream in outcome.settlement.streams
    )
    rendered = repr(outcome)
    assert "tool-sentinel-must-not-launch" not in rendered
    assert "target-sentinel" not in rendered
    assert "environment-sentinel" not in rendered


def test_default_popen_constructor_cancellation_reaps_spawned_child(
    monkeypatch, fake_direct_containment,
):
    if sys.platform != "linux":
        pytest.skip("fixed worker bootstrap is Linux-only")

    request = protocol.normalize_invocation(
        request_id="92" * 16,
        tool="fixture",
        cmd=["tool-sentinel-must-not-launch"],
        timeout=30,
        env={},
        base_environment={"PATH": "/usr/bin"},
    ).worker
    original_execute_child = subprocess.Popen._execute_child
    captured = []
    cancellation = KeyboardInterrupt("cancel after child creation")

    def interrupt_after_exec(child, *args, **kwargs):
        original_execute_child(child, *args, **kwargs)
        captured.append(child)
        raise cancellation

    monkeypatch.setattr(subprocess.Popen, "_execute_child", interrupt_after_exec)
    monkeypatch.setattr(supervisor.sys, "executable", sys.executable)

    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            supervisor.bootstrap_worker(
                request, deadline=time.monotonic() + 5,
            )
        assert caught.value is cancellation
        assert len(captured) == 1
        child = captured[0]
        assert type(child.pid) is int and child.pid > 0
        assert child.stdin is not None and child.stdin.closed
        assert child.stdout is not None and child.stdout.closed
        assert child.returncode is not None
        assert len(fake_direct_containment.handle.settlement_deadlines) == 1
        assert fake_direct_containment.handle.terminal is True
        if os.path.isdir("/proc"):
            assert not os.path.exists(f"/proc/{child.pid}")
    finally:
        if captured and captured[0].returncode is None:
            child = captured[0]
            try:
                child.kill()
            except ProcessLookupError:
                pass
            child.wait(timeout=2)


def test_real_execution_timeout_zero_has_no_execution_cutoff(monkeypatch):
    if sys.platform != "linux":
        pytest.skip("fixed worker execution is Linux-only")
    invocation = protocol.normalize_invocation(
        request_id="93" * 16,
        tool="fixture",
        cmd=(
            sys.executable,
            "-c",
            "import os,time; time.sleep(0.15); os.write(1,b'natural-exit')",
        ),
        timeout=0,
        env={},
        base_environment={"PATH": os.environ.get("PATH", "")},
    )
    monkeypatch.setattr(supervisor.sys, "executable", sys.executable)

    outcome = supervisor.supervise_execution(
        invocation,
        stage_batch=None,
        deadline=(1 << 52),
    )

    assert outcome.reason is supervisor.ExecutionReason.COMPLETE
    assert outcome.transaction_complete is True
    assert outcome.worker_reaped and outcome.worker_returncode == 0
    assert outcome.settlement is not None
    assert outcome.settlement.terminal is protocol.ExecutionTerminal.COMPLETE
    stdout = next(
        stream for stream in outcome.settlement.streams
        if stream.role is protocol.StreamRole.STDOUT
    )
    assert stdout.observed_bytes == len(b"natural-exit")
    assert stdout.retained_bytes == 0
