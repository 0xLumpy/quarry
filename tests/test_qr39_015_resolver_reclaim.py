"""QR39-015: a DNS timeout must reclaim a worker, never orphan one.

The resolver runs in forkserver workers; a test injects behaviour via the picklable `netguard._STUB` passed
to each worker (a safe process model does not inherit a parent monkeypatch). The invariant is resource
reclamation: after a corpus of hanging hosts, the live resolver-worker count returns to baseline with no
leaked thread, and every host is still accounted for as indeterminate.
"""
import threading
import time

import pytest

from quarry_recon import netguard

pytestmark = pytest.mark.offline

_HANG = {"mode": "hang"}
_OK = {"all": ["1.2.3.4"]}


def _leaked_resolver_threads():
    return [t for t in threading.enumerate() if "netguard" in t.name.lower()]


def test_large_failing_corpus_reclaims_every_worker(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", _HANG)
    base_workers = netguard.active_worker_count()
    hosts = [f"h{i}.invalid" for i in range(64)]

    res = netguard.resolve_many(hosts, timeout=0.1)

    assert set(res) == set(hosts)                                   # nothing dropped
    assert all(v == ([], "indeterminate") for v in res.values())   # honest queue: timed-out == indeterminate
    assert netguard.active_worker_count() == base_workers          # stuck-worker gate back to baseline
    assert _leaked_resolver_threads() == []


def test_outstanding_queries_are_bounded(monkeypatch):
    cap = 4
    monkeypatch.setattr(netguard, "_MAX_WORKERS", cap)
    cur = netguard._MP.Value("i", 0)     # workers currently in the resolver, shared with the forkserver children
    gate = netguard._MP.Event()
    monkeypatch.setattr(netguard, "_STUB", {"gate": (cur, gate)})
    base_workers = netguard.active_worker_count()
    hosts = [f"h{i}.invalid" for i in range(4 * cap)]
    done: dict = {}

    th = threading.Thread(target=lambda: done.__setitem__("res", netguard.resolve_many(hosts, timeout=30.0)))
    th.start()
    try:
        deadline = time.monotonic() + 5
        while cur.value < cap and time.monotonic() < deadline:
            time.sleep(0.01)
        observed = 0
        for _ in range(30):
            observed = max(observed, cur.value)
            time.sleep(0.005)
        assert observed == cap           # saturates at the cap while the rest wait — outstanding is bounded
    finally:
        gate.set()                       # release the workers even if the assert failed, so nothing leaks
        th.join(30)
    assert not th.is_alive()
    assert set(done["res"]) == set(hosts)
    assert all(v == (["1.2.3.4"], "ok") for v in done["res"].values())
    assert netguard.active_worker_count() == base_workers


def test_budget_leaves_remainder_indeterminate_without_leaking(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", _HANG)
    base_workers = netguard.active_worker_count()
    hosts = [f"h{i}.invalid" for i in range(200)]

    t0 = time.monotonic()
    res = netguard._resolve_batch(hosts, timeout=0.1, max_outstanding=8, budget_s=0.3)
    elapsed = time.monotonic() - t0

    assert set(res) == set(hosts)                                   # unreached hosts remain, not dropped
    assert all(v == ([], "indeterminate") for v in res.values())
    assert elapsed < 5.0                                            # corpus work is bounded, not run to the end
    assert netguard.active_worker_count() == base_workers
    assert _leaked_resolver_threads() == []


def test_single_resolve_hang_is_killed(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", _HANG)
    base_workers = netguard.active_worker_count()

    assert netguard.resolve("stuck.invalid", timeout=0.1) == ([], "indeterminate")
    assert netguard.active_worker_count() == base_workers
    assert _leaked_resolver_threads() == []


def test_late_completion_is_discarded(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", {"mode": "slow", "delay": 2.0})   # answers long after the deadline
    base_workers = netguard.active_worker_count()

    assert netguard.resolve("slow.invalid", timeout=0.1) == ([], "indeterminate")
    assert netguard.active_worker_count() == base_workers
    assert _leaked_resolver_threads() == []


def test_a_recv_failure_still_reclaims_the_worker(monkeypatch):
    import multiprocessing.connection as _mpc_mod
    monkeypatch.setattr(netguard, "_STUB", _OK)
    base = netguard.active_worker_count()
    real_recv = _mpc_mod.Connection.recv
    state = {"boom": True}

    def recv(self):
        if state["boom"]:
            state["boom"] = False
            raise RuntimeError("pipe boom")      # the parent's first recv fails mid-batch
        return real_recv(self)

    monkeypatch.setattr(_mpc_mod.Connection, "recv", recv)
    res = netguard.resolve_many(["a.invalid"], timeout=5.0)
    assert res["a.invalid"] == ([], "indeterminate")   # a recv failure is not a crash
    deadline = time.monotonic() + 3
    while netguard.active_worker_count() > base and time.monotonic() < deadline:
        time.sleep(0.02)
    assert netguard.active_worker_count() == base       # ...and the worker is reclaimed, never orphaned


def test_a_none_timeout_does_not_orphan_a_worker(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", _OK)
    base = netguard.active_worker_count()
    res = netguard.resolve_many(["a.invalid"], timeout=None)   # None coerces to a finite deadline, never raises
    assert res["a.invalid"][1] in ("ok", "nxdomain", "indeterminate")
    deadline = time.monotonic() + 3
    while netguard.active_worker_count() > base and time.monotonic() < deadline:
        time.sleep(0.02)
    assert netguard.active_worker_count() == base


def test_a_start_that_forks_then_raises_is_reclaimed(monkeypatch):
    monkeypatch.setattr(netguard, "_STUB", _OK)
    base = netguard.active_worker_count()
    ctx = netguard._spawn_context()          # single-threaded test -> fork context
    monkeypatch.setattr(netguard, "_spawn_context", lambda: ctx)
    real_start = ctx.Process.start
    state = {"boom": True}

    def flaky(self):
        real_start(self)                     # child really starts...
        if state["boom"]:
            state["boom"] = False
            raise RuntimeError("post-start boom")   # ...then start() raises, before the ownership guard registers it
    monkeypatch.setattr(ctx.Process, "start", flaky)
    with pytest.raises(RuntimeError):
        netguard.resolve_many(["a.invalid"])
    monkeypatch.undo()
    deadline = time.monotonic() + 3
    while netguard.active_worker_count() > base and time.monotonic() < deadline:
        time.sleep(0.02)
    assert netguard.active_worker_count() == base   # reclaimed, never orphaned
