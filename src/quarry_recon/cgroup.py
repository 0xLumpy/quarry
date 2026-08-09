"""Transient-unit containment: start work inside a cgroup and be able to stop it.

A phase must not hide a subprocess — every tool a phase runs goes through the runner, and `verify-quarry`
check 106 enforces that no raw `subprocess` is left in a phase module (the long-lived oob callback server
in `oob.py`, outside the phases, is the one deliberate exception). When `available()`, this is the
machinery that puts a tool inside a memory boundary and takes it out again; otherwise the tool still runs,
uncontained.

`MemoryMax` bounds memory actually used (not `RLIMIT_AS` address space, which can run far above it);
`MemorySwapMax=0` is load-bearing — with swap available an allocation can survive its cap.
"""
from __future__ import annotations

import shutil
import subprocess
import time

#: per-bus-call ceiling; whole-stop-sequence ceiling
BUS_S = 10.0
STOP_S = 30.0
#: minimum window for a final attempt when the budget is spent (outer bound = budget + 2×FLOOR_S)
FLOOR_S = 1.0


def available() -> bool:
    """Whether a per-invocation cgroup can be created at all."""
    return bool(shutil.which("systemd-run") and shutil.which("systemctl"))


def wrap(unit: str, cmd: list, *, memory_max_mb: int, swap_max: int = 0) -> list:
    """`cmd` inside a transient unit with a memory bound. The unit name is the caller's — a timeout
    kills the systemd-run client, not the service."""
    return ["systemd-run", "--user", f"--unit={unit}", "--pipe", "--wait", "-q",
            "-p", f"MemoryMax={memory_max_mb}M", "-p", f"MemorySwapMax={swap_max}", *cmd]


def _sysctl(args: list, timeout: float = BUS_S):
    """`systemctl --user …`, always bounded so a stalled bus can't hang cleanup."""
    if timeout <= 0:
        return None
    try:
        return subprocess.run(["systemctl", "--user"] + args, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None


def _state(unit: str, timeout: float) -> dict:
    r = _sysctl(["show", unit, "-p", "ActiveState", "-p", "LoadState"], timeout=timeout)
    return dict(line.split("=", 1) for line in (r.stdout.splitlines() if r else []) if "=" in line)


def stop(unit: str, budget_s: float = STOP_S) -> bool:
    """Stop the unit and confirm it stopped, under one absolute deadline; `True` only when confirmed.
    An unreadable state is never evidence it stopped. Sequence: `--no-block`, poll, SIGKILL, poll."""
    end = time.perf_counter() + budget_s
    left = lambda: max(0.0, end - time.perf_counter())                        # noqa: E731
    #: grace window reserved for the polite stop, so escalation always has budget left for SIGKILL
    grace_end = time.perf_counter() + budget_s / 2
    _sysctl(["stop", "--no-block", unit], timeout=min(BUS_S, left()))

    def _settled(deadline: float) -> bool:
        while time.perf_counter() < deadline and left() > 0:
            props = _state(unit, timeout=min(BUS_S, max(0.0, deadline - time.perf_counter()), left()))
            if props.get("LoadState") == "not-found" or \
                    props.get("ActiveState") in ("inactive", "failed"):
                return True
            time.sleep(min(0.05, left()))
        return False

    if _settled(grace_end):
        _sysctl(["reset-failed", unit], timeout=min(BUS_S, max(FLOOR_S, left())))
        return True
    # ignored the stop; budget remains by construction
    _sysctl(["kill", "--signal=SIGKILL", unit], timeout=min(BUS_S, max(FLOOR_S, left())))
    if _settled(end):
        _sysctl(["reset-failed", unit], timeout=min(BUS_S, max(FLOOR_S, left())))
        return True
    # bounded by remaining time with a small floor, so a spent budget still gets one attempt
    _sysctl(["reset-failed", unit], timeout=min(BUS_S, max(FLOOR_S, left())))
    return False


def clear(unit: str) -> None:
    """Drop a stale unit of this name before starting, so systemd-run won't refuse and a prior run's
    result can't be read as this run's."""
    _sysctl(["reset-failed", unit], timeout=BUS_S)
