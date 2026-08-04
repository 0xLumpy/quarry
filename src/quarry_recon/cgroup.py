"""Transient-unit containment: start work inside a cgroup, and be able to STOP it.

A phase must not hide a subprocess — every tool goes through the runner, and `verify-quarry` check 106
enforces that there is no raw `subprocess` left in a phase module. This is not a tool: it is the
machinery that puts a tool inside a memory boundary and takes it out again, so it lives here rather than
beside the lane that uses it.

Why a cgroup at all: `RLIMIT_AS` bounds ADDRESS SPACE, which for some workloads is an order of magnitude
above the physical memory they actually touch (measured: an analyzer using 5.3 GB needed 32 GB of address
space to run at all). A bound that kills ordinary input is not containment. `MemoryMax` bounds what is
really used, and `MemorySwapMax=0` is load-bearing — with swap available a 900 MB allocation survived a
512 MB cap.
"""
from __future__ import annotations

import shutil
import subprocess
import time

#: one bus call's ceiling, and the whole stop sequence's ceiling. They compose: a poll loop whose
#: per-call timeout is not capped by its own remaining time is not bounded by the number in its signature.
BUS_S = 10.0
STOP_S = 30.0
#: the smallest window a final attempt gets when the budget is already spent — so a stop still ASKS once
#: on a stalled bus. It is why the outer bound is `budget + 2 x FLOOR_S`, not `budget`.
FLOOR_S = 1.0


def available() -> bool:
    """Whether a per-invocation cgroup can be created at all."""
    return bool(shutil.which("systemd-run") and shutil.which("systemctl"))


def wrap(unit: str, cmd: list, *, memory_max_mb: int, swap_max: int = 0) -> list:
    """`cmd` inside a transient unit with a MEMORY bound. The unit NAME is the caller's, because the
    caller is what has to stop it: a timeout kills the systemd-run client, never the service."""
    return ["systemd-run", "--user", f"--unit={unit}", "--pipe", "--wait", "-q",
            "-p", f"MemoryMax={memory_max_mb}M", "-p", f"MemorySwapMax={swap_max}", *cmd]


def _sysctl(args: list, timeout: float = BUS_S):
    """`systemctl --user …`, always BOUNDED: a stalled bus must not hang the cleanup that exists to keep
    a lane inside its own budget."""
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
    """Stop the unit and CONFIRM it stopped, under one absolute deadline. `True` only when confirmed.

    Asking systemd to stop something is not the same as it having stopped, and an unreadable state is
    never evidence that it did — that is exactly what a hung bus produces. `--no-block` first, because a
    synchronous stop has no timeout of its own and would hang before the deadline below started counting;
    then poll; then SIGKILL; then poll again.
    """
    end = time.perf_counter() + budget_s
    left = lambda: max(0.0, end - time.perf_counter())                        # noqa: E731
    #: the polite window. It is RESERVED, not "whatever is left": letting the first poll consume the whole
    #: budget left zero time for the escalation, so `_sysctl` short-circuited on a zero timeout and no
    #: SIGKILL was ever sent — the kill path existed and could not run.
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
    # it ignored the stop, and there is budget left BY CONSTRUCTION
    _sysctl(["kill", "--signal=SIGKILL", unit], timeout=min(BUS_S, max(FLOOR_S, left())))
    if _settled(end):
        _sysctl(["reset-failed", unit], timeout=min(BUS_S, max(FLOOR_S, left())))
        return True
    # bounded by what is LEFT, with a small floor so a spent budget still gets one attempt: the full
    # BUS_S here made a 2 s stop take 12 s against a bus where every call blocks.
    _sysctl(["reset-failed", unit], timeout=min(BUS_S, max(FLOOR_S, left())))
    return False


def clear(unit: str) -> None:
    """Drop a stale unit of this name before starting, so a previous interrupted run cannot make
    `systemd-run` refuse — and cannot leave its result to be read as this run's."""
    _sysctl(["reset-failed", unit], timeout=BUS_S)
