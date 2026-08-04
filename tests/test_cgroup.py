"""`cgroup` — start work inside a memory boundary, and be able to STOP it.

The unit is transient and the client that started it is not the thing holding the memory: a timeout kills
`systemd-run`, never the service. So the only property worth testing here is that a stop is CONFIRMED,
and that an unreadable bus is never mistaken for a stopped one — that is exactly what a hung bus looks
like from the outside.
"""
from __future__ import annotations

import time

import pytest

from quarry_recon import cgroup


class _Reply:
    def __init__(self, text):
        self.stdout = text


def test_the_wrapper_carries_the_memory_bound_and_the_callers_unit_name():
    cmd = cgroup.wrap("quarry-test-1", ["/bin/true"], memory_max_mb=2048)
    assert "--unit=quarry-test-1" in cmd, "the caller must be able to stop what it started"
    assert "MemoryMax=2048M" in cmd and "MemorySwapMax=0" in cmd, \
        "swap is load-bearing: with it, a 900 MB allocation survived a 512 MB cap"
    assert cmd[-1] == "/bin/true"


def test_a_gone_or_inactive_unit_settles(monkeypatch):
    for text in ("LoadState=not-found\nActiveState=inactive\n",
                 "LoadState=loaded\nActiveState=failed\n",
                 "LoadState=loaded\nActiveState=inactive\n"):
        monkeypatch.setattr(cgroup, "_sysctl", lambda args, timeout=cgroup.BUS_S, t=text: _Reply(t))
        assert cgroup.stop("quarry-test-2", budget_s=5.0) is True


def test_an_unreadable_bus_never_counts_as_settled(monkeypatch):
    monkeypatch.setattr(cgroup, "_sysctl", lambda args, timeout=cgroup.BUS_S: None)
    assert cgroup.stop("quarry-test-3", budget_s=1.0) is False


def test_the_kill_is_REACHABLE_when_the_grace_window_expires(monkeypatch):  # noqa: D401
    """The escalation must be reserved, not left to whatever the polite window did not use: consuming
    the whole deadline in the first poll made `_sysctl` short-circuit on a zero timeout, so the SIGKILL
    existed and could never be sent."""
    sent = []

    def fake(args, timeout=cgroup.BUS_S):
        if timeout <= 0:
            return None
        sent.append((args[0], round(timeout, 2), time.perf_counter()))
        return _Reply("LoadState=loaded\nActiveState=active\n")
    monkeypatch.setattr(cgroup, "_sysctl", fake)
    t0 = time.perf_counter()
    assert cgroup.stop("quarry-test-6", budget_s=2.0) is False
    kills = [when for name, _t, when in sent if name == "kill"]
    assert kills, "SIGKILL was never actually issued"
    # and it was issued WHILE the deadline still had time: a kill that only fires after the budget is
    # spent leaves no window to confirm it worked, which is the whole point of escalating.
    assert kills[0] - t0 < 2.0 * 0.75, f"the kill waited for the whole budget ({kills[0] - t0:.2f}s)"


def test_a_unit_that_stays_active_is_killed_and_still_reported_honestly(monkeypatch):
    calls = []

    def fake(args, timeout=cgroup.BUS_S):
        # the REAL `_sysctl` refuses a zero/negative timeout without running anything; a fake that
        # ignores that made an unreachable SIGKILL look like a sent one
        if timeout <= 0:
            return None
        calls.append(args[0])
        return _Reply("LoadState=loaded\nActiveState=active\n")
    monkeypatch.setattr(cgroup, "_sysctl", fake)
    assert cgroup.stop("quarry-test-4", budget_s=1.0) is False, \
        "still active at the deadline is not settled, whatever we asked it to do"
    assert "kill" in calls, "a unit that ignores stop gets SIGKILL before the verdict"


def test_the_stop_respects_its_deadline_even_when_every_call_blocks(monkeypatch):
    tried = []

    def blocking(args, timeout=cgroup.BUS_S):
        if timeout <= 0:
            return None                       # the real one refuses without running anything
        tried.append(args[0])
        time.sleep(max(0.0, timeout))
        return None
    monkeypatch.setattr(cgroup, "_sysctl", blocking)
    t0 = time.perf_counter()
    assert cgroup.stop("quarry-test-5", budget_s=2.0) is False
    # the second window after SIGKILL is bounded too; what must not happen is per-call timeouts stacking
    # the composed bound: the budget, plus the two floor-sized attempts that still fire when the budget
    # is spent (the SIGKILL and the final reset). What must not happen is per-call timeouts stacking
    # without limit — an earlier version took 12 s for a 2 s budget.
    assert time.perf_counter() - t0 < 2.0 + 2 * cgroup.FLOOR_S + 0.5, \
        "the deadline was advisory, not a bound"
    # …and it still ASKED. A budget spent inside the polite window must not silently skip the escalation:
    # that is precisely when a unit is least likely to have stopped on its own.
    assert "kill" in tried, "a stalled bus swallowed the SIGKILL entirely"
