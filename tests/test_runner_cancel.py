"""runner cancellation + CPU-token accounting under CONCURRENT execution (A2 review r2).

`KeyboardInterrupt` reaches the MAIN thread only, so a tool running inside a worker thread never runs
runner.run()'s own interrupt branch. Without a reachable registry of live process groups, the subprocess
survives and ThreadPoolExecutor.__exit__ waits for it — unbounded when the caller passes `timeout 0`.

These use REAL children (`sleep 8`), so they prove termination rather than asserting on a mock. The
child lifetime is BOUNDED so a regression FAILS on the elapsed assert instead of hanging the suite.
Marked `integration` because they spawn processes.
"""
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from quarry_recon import runner
from quarry_recon.runner import Status

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _clean_cancel_latch():
    runner.reset_cancel()
    yield
    runner.reset_cancel()
    runner._CPU_INFLIGHT.clear()


def _declared_path(kwargs, policy_name):
    policy = kwargs.get(policy_name)
    disposition = getattr(getattr(policy, "disposition", None), "value", None)
    repository = kwargs.get("repository")
    if repository is None or disposition != "publish":
        return None
    return repository.dir.joinpath(*policy.components)


def test_cancel_all_terminates_a_running_child_within_a_bound():
    """The core guarantee: a tool with NO timeout still dies promptly when the operator cancels."""
    started = threading.Event()

    def work():
        started.set()
        return runner.run("sleep", ["sleep", "8"], timeout=0)      # no wall-clock kill of its own

    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(work)
        assert started.wait(5)
        time.sleep(0.4)                                              # let Popen actually start
        t0 = time.monotonic()
        killed = runner.cancel_all()
        r = fut.result(timeout=20)
        elapsed = time.monotonic() - t0
    assert killed == 1
    assert elapsed < 4, f"cancellation took {elapsed:.1f}s — not bounded"
    assert r.status != Status.SUCCESS


def test_cancel_all_terminates_every_concurrent_child():
    n = 4
    started = threading.Barrier(n + 1, timeout=10)

    def work(i):
        started.wait()
        return runner.run("sleep", ["sleep", "8"], timeout=0)

    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(work, i) for i in range(n)]
        started.wait()
        time.sleep(0.6)
        killed = runner.cancel_all()
        results = [f.result(timeout=20) for f in futs]
    assert killed == n
    assert all(r.status != Status.SUCCESS for r in results)


def test_no_process_survives_cancellation():
    """A terminated GROUP must leave nothing behind — the reason start_new_session exists."""
    started = threading.Event()
    pids = []

    real_popen = subprocess.Popen

    def spy(*a, **kw):
        p = real_popen(*a, **kw)
        pids.append(p.pid)
        return p

    with ThreadPoolExecutor(max_workers=1) as pool:
        import unittest.mock as mock
        with mock.patch.object(subprocess, "Popen", spy):
            fut = pool.submit(lambda: (started.set(), runner.run("sleep", ["sleep", "8"], timeout=0))[1])
            assert started.wait(5)
            time.sleep(0.4)
            runner.cancel_all()
            fut.result(timeout=20)
    time.sleep(0.3)
    for pid in pids:
        alive = subprocess.run([sys.executable, "-c",
                                f"import os,sys;\nsys.exit(0 if os.path.exists('/proc/{pid}') else 1)"],
                               capture_output=True).returncode == 0
        assert not alive, f"pid {pid} survived cancellation"


def test_a_failed_launch_does_not_poison_later_cpu_measurement():
    """review#3: _cpu_start() ran before Popen but _cpu_finish() only after a successful completion, so a
    launch failure left the token in _CPU_INFLIGHT forever and EVERY later tool reported CPU unmeasured.
    QR39-001: a failed launch is now a typed machinery fault, not an escaping exception."""
    import unittest.mock as mock
    runner._CPU_INFLIGHT.clear()
    with mock.patch.object(subprocess, "Popen", side_effect=OSError("EMFILE")):
        r = runner.run("sleep", ["sleep", "0"], timeout=5)
    assert r.status == Status.FAILED and r.started is False
    assert any(f["kind"] == "machinery" for f in r.meta.get("faults", []))
    assert runner._CPU_INFLIGHT == {}, "token leaked after a failed launch"
    r = runner.run("sleep", ["sleep", "0"], timeout=10)
    assert runner.cpu_measured(r), "a later sequential run was wrongly reported unmeasured"


def test_an_unexpected_exception_never_orphans_a_running_child():
    """review#1 (r4): an exception out of wait() runs NEITHER the timeout nor the interrupt branch, so
    nothing killed the child — and the finally then dropped it from the registry, leaving a process alive
    that cancel_all() can no longer even see.

    The raise must happen while the child is STILL RUNNING: a test that lets `sleep 0` finish first proves
    nothing, because the process is already dead by the time the exception is raised."""
    import unittest.mock as mock
    real_popen = subprocess.Popen
    seen = {}

    class RaiseWhileAlive:
        def __init__(self, *a, **kw):
            self._p = real_popen(*a, **kw)
            self.pid = self._p.pid
            seen["proc"] = self._p

        def wait(self, timeout=None):
            assert self._p.poll() is None, "child already exited — the test proves nothing"
            raise RuntimeError("boom while alive")

        def __getattr__(self, n):
            return getattr(self._p, n)

    runner._CPU_INFLIGHT.clear()
    with mock.patch.object(subprocess, "Popen", RaiseWhileAlive):
        with pytest.raises(RuntimeError):
            runner.run("sleep", ["sleep", "8"], timeout=0)
    p = seen["proc"]
    for _ in range(60):                                  # the kill is best-effort + asynchronous
        if p.poll() is not None:
            break
        time.sleep(0.05)
    assert p.poll() is not None, "child survived an unexpected exception — orphaned and unreachable"
    assert runner._LIVE_PROCS == {}, "registry leaked"
    assert runner._CPU_INFLIGHT == {}, "cpu token leaked"


def test_an_exited_leader_does_not_leave_its_process_group_alive(tmp_path):
    """review#1 (r5): `poll() is None` answers only for the process LEADER. A leader can exit while its
    children keep the group alive — exactly what terminate_group() exists for (it signals the PGID, which
    stays valid while any member lives). Here the leader spawns `sleep`, exits, and only THEN does wait()
    raise: poll() reports 0, so a leader-gated cleanup skips the still-running group."""
    import unittest.mock as mock
    pidfile = tmp_path / "grandchild.pid"
    leader_src = (
        "import subprocess, sys\n"
        "p = subprocess.Popen(['sleep', '8'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
        # exit immediately, leaving the child running in the SAME process group
    )
    real_popen = subprocess.Popen
    seen = {}

    class RaiseAfterLeaderExits:
        def __init__(self, *a, **kw):
            self._p = real_popen(*a, **kw)
            self.pid = self._p.pid
            seen["proc"] = self._p

        def wait(self, timeout=None):
            for _ in range(200):                             # wait for the leader to hand off and exit
                if pidfile.exists() and self._p.poll() is not None:
                    break
                time.sleep(0.05)
            assert self._p.poll() is not None, "leader still alive — the test would not exercise the gap"
            raise RuntimeError("boom after leader exit")

        def __getattr__(self, n):
            return getattr(self._p, n)

    runner._CPU_INFLIGHT.clear()
    with mock.patch.object(subprocess, "Popen", RaiseAfterLeaderExits):
        with pytest.raises(RuntimeError):
            runner.run("python", [sys.executable, "-c", leader_src], timeout=0)
    grandchild = int(pidfile.read_text().strip())
    for _ in range(60):
        if not __import__("os").path.exists(f"/proc/{grandchild}"):
            break
        time.sleep(0.05)
    alive = __import__("os").path.exists(f"/proc/{grandchild}")
    if alive:                                                # never leave a real orphan behind
        try:
            __import__("os").kill(grandchild, 9)
        except OSError:
            pass
    assert not alive, "the leader exited but its process GROUP survived — unreachable by cancel_all()"
    assert runner._LIVE_PROCS == {} and runner._CPU_INFLIGHT == {}
    seen["proc"].wait(timeout=5)


def test_cleanup_never_masks_the_exception_in_flight():
    """The teardown runs in a `finally`, so anything IT raises REPLACES the exception actually propagating
    — the caller would see a cleanup failure instead of the real cause.

    Targets the path where the guard genuinely bites: an unexpected exception (group not settled) whose
    teardown then fails. NB an earlier version of this test used a KeyboardInterrupt and proved nothing:
    the KI branch's own drain re-raises, `except Exception` does not catch it, so `group_settled` stays
    False and the condition short-circuits before ever touching the guarded call."""
    import unittest.mock as mock
    real_popen = subprocess.Popen

    class RaisesInFlight:
        def __init__(self, *a, **kw):
            self._p = real_popen(*a, **kw)
            self.pid = self._p.pid

        def wait(self, timeout=None):
            raise ValueError("the real cause")

        def __getattr__(self, n):
            return getattr(self._p, n)

    def exploding_teardown(p, grace=None):
        try:
            runner.terminate_group.__wrapped__(p)        # still actually kill it, then fail
        except Exception:
            pass
        raise RuntimeError("teardown blew up")

    real_tg = runner.terminate_group
    exploding_teardown.__wrapped__ = real_tg
    with mock.patch.object(subprocess, "Popen", RaisesInFlight):
        with mock.patch.object(runner, "terminate_group", exploding_teardown):
            with pytest.raises(ValueError, match="the real cause"):   # NOT RuntimeError
                runner.run("sleep", ["sleep", "8"], timeout=0)
    assert runner._CPU_INFLIGHT == {} and runner._LIVE_PROCS == {}


def test_group_teardown_happens_exactly_once_per_path():
    """Ctrl-C already tears the group down in its own branch; the outer guard must not repeat it. A second
    terminate_group is not harmless — it pays another grace window on every cancelled tool."""
    import unittest.mock as mock
    calls = []

    class Fake:
        def __init__(self, *a, **kw):
            import io
            self.pid = 999998
            self.returncode = None
            self.n = 0
            self.stdout, self.stderr, self.stdin = io.BytesIO(), io.BytesIO(), io.BytesIO()

        def wait(self, timeout=None):
            self.n += 1
            if self.n == 1:
                raise KeyboardInterrupt
            return 0

        def poll(self):
            return 0                                     # leader gone after the branch's own teardown

    with mock.patch.object(subprocess, "Popen", Fake):
        with mock.patch.object(runner, "terminate_group", lambda p, grace=None: calls.append(1)):
            with pytest.raises(KeyboardInterrupt):
                runner.run("t", ["true"], timeout=5)
    assert calls == [1], f"terminate_group ran {len(calls)}x on the Ctrl-C path"


def test_group_teardown_is_scoped_to_exceptional_exits(tmp_path):
    """The guard's SCOPE, pinned in the other direction: a run that completed normally is NOT group-killed.

    This is deliberate and narrow — the r5 fix targets exceptional exits, where nothing else will ever
    reach the process. NB it also documents a real remaining gap: a tool that exits cleanly while leaving
    a child behind still leaves that child running. No current tool does, and widening the teardown to the
    success path would silently change semantics for anything that intentionally detaches, so it is called
    out rather than changed here."""
    pidfile = tmp_path / "survivor.pid"
    leader_src = (
        "import subprocess, sys\n"
        "p = subprocess.Popen(['sleep', '5'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
    )
    r = runner.run("python", [sys.executable, "-c", leader_src], timeout=20)
    assert r.exit_code == 0
    survivor = int(pidfile.read_text().strip())
    import os as _os
    alive = _os.path.exists(f"/proc/{survivor}")
    try:
        _os.kill(survivor, 9)                    # never leave it behind, whatever the assertion says
    except OSError:
        pass
    assert alive, "a CLEAN run group-killed its children — the teardown is no longer scoped"


def test_an_in_flight_exception_does_not_poison_later_cpu_measurement():
    """An exception raised after the child has already exited must still reclaim the CPU token (QR39-001
    removed the decode-crash path — binary capture never decodes — so any in-flight exception stands in)."""
    import unittest.mock as mock
    runner._CPU_INFLIGHT.clear()
    real_popen = subprocess.Popen

    class Boom:
        def __init__(self, *a, **kw):
            self._p = real_popen(*a, **kw)
            self.pid = self._p.pid

        def wait(self, timeout=None):
            self._p.wait()
            raise RuntimeError("boom")

        def __getattr__(self, n):
            return getattr(self._p, n)

    with mock.patch.object(subprocess, "Popen", Boom):
        with pytest.raises(RuntimeError):
            runner.run("sleep", ["sleep", "0"], timeout=10)
    assert runner._CPU_INFLIGHT == {}, "token leaked after an in-flight exception"
    r = runner.run("sleep", ["sleep", "0"], timeout=10)
    assert runner.cpu_measured(r)


def test_arjun_lane_cancellation_is_bounded(tmp_path, monkeypatch):
    """Lane-level: Ctrl-C arrives in the MAIN thread while workers are blocked on a child with no
    timeout. Without the registry the pool's __exit__ would wait for all of them."""
    from quarry_recon import budget
    from quarry_recon.phases import params

    class _Run:
        def __init__(self, d):
            self.dir = d
            self.added = []
            self.recorded = []

        def raw_path(self, ph, tl, nm):
            p = self.dir / "raw" / ph / tl / nm
            p.parent.mkdir(parents=True, exist_ok=True)
            return p

        def add(self, k, e):
            self.added.append((k, e))
            return True

        def record(self, ph, r):
            self.recorded.append(r)

    class _Ctx:
        def __init__(self, d):
            self.run = _Run(d)
            self.http_timeout = 0            # NO wall-clock kill: the worst case for cancellation
            self.echoed = []
            self.profile = type("P", (), {"http_rl": 0})()

        def echo(self, m):
            self.echoed.append(m)

    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    monkeypatch.setattr(params.settings, "concurrency", lambda k, d: 3 if k == "ARJUN_TARGETS" else d)
    running = threading.Semaphore(0)

    def slow(tool, cmd, **kw):
        running.release()
        return runner.run("sleep", ["sleep", "8"], timeout=0)

    monkeypatch.setattr(params, "exec_tool", slow)
    real_wait = params.wait
    fired = []

    def interrupt_once(fs, **kw):
        # the handler ALSO calls wait() to drain the killed futures — only the first call interrupts,
        # everything after delegates, or the test deadlocks on its own semaphore.
        if fired:
            return real_wait(fs, **kw)
        for _ in range(3):                   # only interrupt once every worker is actually in flight
            assert running.acquire(timeout=10)
        fired.append(True)
        raise KeyboardInterrupt

    monkeypatch.setattr(params, "wait", interrupt_once)
    ctx = _Ctx(tmp_path / "run")
    ctx.run.dir.mkdir(parents=True, exist_ok=True)
    urls = [f"https://h{i}.ex.com/api/x" for i in range(3)]
    t0 = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        params._arjun_lane(ctx, ctx.profile, urls)
    elapsed = time.monotonic() - t0
    assert elapsed < 4, f"lane cancellation took {elapsed:.1f}s — the pool blocked on the children"
    assert any("cancelled" in m for m in ctx.echoed)
    monkeypatch.setattr(params, "wait", real_wait)


def test_stubborn_children_share_one_grace_deadline():
    """review#1 (r3): terminating groups in a LOOP gave every SIGTERM-ignoring child its own full grace,
    so N stubborn children cost N x grace before the first SIGKILL. One shared deadline keeps
    cancellation bounded regardless of how many are running."""
    n = 5
    ignore_term = ("import signal, time\n"
                   "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                   "time.sleep(30)\n")
    started = threading.Barrier(n + 1, timeout=15)

    def work(_i):
        started.wait()
        return runner.run("python", [sys.executable, "-c", ignore_term], timeout=0)

    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(work, i) for i in range(n)]
        started.wait()
        time.sleep(1.0)                                  # let every child install its handler
        t0 = time.monotonic()
        killed = runner.cancel_all(grace=1.0)
        results = [f.result(timeout=25) for f in futs]
        elapsed = time.monotonic() - t0
    assert killed == n
    # one shared 1s deadline, not 5 x 1s. Generous bound so this cannot flake on a loaded box, but far
    # below the ~5s a sequential loop takes and far below the children's own 30s sleep.
    assert elapsed < 3.5, f"{n} stubborn children took {elapsed:.1f}s — grace is not shared"
    assert all(r.status != Status.SUCCESS for r in results)


def test_completed_work_is_harvested_before_the_kill(tmp_path, monkeypatch):
    """'Ctrl-C costs nothing already earned': a target that finished just before the interrupt must keep
    its completion, so the resume does NOT rerun it while its sleeping siblings are retried."""
    from quarry_recon import budget
    from quarry_recon.phases import params

    class _Run:
        def __init__(self, d):
            self.dir = d
            self.added = []
            self.recorded = []

        def raw_path(self, ph, tl, nm):
            p = self.dir / "raw" / ph / tl / nm
            p.parent.mkdir(parents=True, exist_ok=True)
            return p

        def add(self, k, e):
            self.added.append((k, e))
            return True

        def record(self, ph, r):
            self.recorded.append(r)

    class _Ctx:
        def __init__(self, d):
            self.run = _Run(d)
            self.http_timeout = 0
            self.echoed = []
            self.profile = type("P", (), {"http_rl": 0})()

        def echo(self, m):
            self.echoed.append(m)

    QUICK = "https://quick.ex.com/api/x"
    SLOW = [f"https://slow{i}.ex.com/api/x" for i in range(2)]
    SCAN = "[*] Scanning 0/1: {u}"
    NONE = "[!] No parameters were discovered."
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    monkeypatch.setattr(params.settings, "concurrency", lambda k, d: 3 if k == "ARJUN_TARGETS" else d)
    quick_done = threading.Event()

    def mixed(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        raw_path = raw_path or _declared_path(kw, "stdout")
        stderr_path = stderr_path or _declared_path(kw, "stderr")
        u = cmd[cmd.index("-u") + 1]
        if u == QUICK:
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text("\n".join([SCAN.format(u=u), NONE]))
            stderr_path.write_text("")
            quick_done.set()
            return Status and runner.RunResult(tool, cmd, Status.EMPTY, 0, 0.1, raw_path, 0)
        return runner.run("sleep", ["sleep", "8"], timeout=0)

    monkeypatch.setattr(params, "exec_tool", mixed)
    real_wait = params.wait
    fired = []

    def interrupt_after_quick(fs, **kw):
        if fired:
            return real_wait(fs, **kw)
        assert quick_done.wait(10)
        time.sleep(0.5)                                  # let the quick future settle to done()
        fired.append(True)
        raise KeyboardInterrupt

    monkeypatch.setattr(params, "wait", interrupt_after_quick)
    ctx = _Ctx(run_dir)
    with pytest.raises(KeyboardInterrupt):
        params._arjun_lane(ctx, ctx.profile, [QUICK] + SLOW)
    assert any("arjun[empty]" in (r.note or "") for r in ctx.run.recorded), \
        "the quick target was never harvested — its verdict is missing from the run record"

    # RESUME: the harvested target must not run again; the cancelled ones must.
    monkeypatch.setattr(params, "wait", real_wait)
    launched = []

    def all_quick(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        raw_path = raw_path or _declared_path(kw, "stdout")
        stderr_path = stderr_path or _declared_path(kw, "stderr")
        u = cmd[cmd.index("-u") + 1]
        launched.append(u)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text("\n".join([SCAN.format(u=u), NONE]))
        stderr_path.write_text("")
        return runner.RunResult(tool, cmd, Status.EMPTY, 0, 0.1, raw_path, 0)

    monkeypatch.setattr(params, "exec_tool", all_quick)
    ctx2 = _Ctx(run_dir)
    params._arjun_lane(ctx2, ctx2.profile, [QUICK] + SLOW)
    assert QUICK not in launched, "the harvested completion was lost and the target was rerun"
    assert set(launched) == set(SLOW)


def test_post_kill_reaping_uses_one_shared_deadline():
    """review#3 (r4): a sequential `p.wait(timeout=2)` after SIGKILL reintroduced the linear blow-up the
    shared TERM deadline removed. Real children exit instantly on SIGKILL, so the bound is tested with
    stubs that never reap — the behaviour has to be structural, not incidental."""
    class NeverReaps:
        def __init__(self, pid):
            self.pid = pid

        def poll(self):
            return None                                  # never exits, however hard we signal

        def wait(self, timeout=None):
            time.sleep(timeout or 0)
            raise subprocess.TimeoutExpired("stub", timeout or 0)

    import unittest.mock as mock
    stubs = [NeverReaps(900000 + i) for i in range(5)]
    with runner._LIVE_LOCK:
        runner._LIVE_PROCS.clear()
        for i, s in enumerate(stubs):
            runner._LIVE_PROCS[i] = s
    try:
        with mock.patch.object(runner.os, "killpg", lambda *a: None):     # never signal a real pid
            t0 = time.monotonic()
            killed = runner.cancel_all(grace=0.5)
            elapsed = time.monotonic() - t0
    finally:
        with runner._LIVE_LOCK:
            runner._LIVE_PROCS.clear()
    assert killed == 5
    # one 0.5s TERM window + one shared reap window. Sequential reaping would cost 5 x 2s = 10s.
    assert elapsed < 4, f"cancellation of 5 unreapable processes took {elapsed:.1f}s — reap not shared"


def test_work_finishing_during_the_kill_race_is_still_harvested(tmp_path, monkeypatch):
    """review#2 (r4): the first harvest is a SNAPSHOT. A target that completed naturally between that
    snapshot and process termination was declared unmeasured, discarding a verdict actually reached.

    The previous test deliberately settled the quick future BEFORE interrupting, so it could not see this.
    Here the quick worker is released only once cancel_all() has been called — squarely inside the race."""
    from quarry_recon import budget
    from quarry_recon.phases import params

    class _Run:
        def __init__(self, d):
            self.dir = d
            self.added = []
            self.recorded = []

        def raw_path(self, ph, tl, nm):
            p = self.dir / "raw" / ph / tl / nm
            p.parent.mkdir(parents=True, exist_ok=True)
            return p

        def add(self, k, e):
            self.added.append((k, e))
            return True

        def record(self, ph, r):
            self.recorded.append(r)

    class _Ctx:
        def __init__(self, d):
            self.run = _Run(d)
            self.http_timeout = 0
            self.echoed = []
            self.profile = type("P", (), {"http_rl": 0})()

        def echo(self, m):
            self.echoed.append(m)

    RACER = "https://racer.ex.com/api/x"
    SLOW = "https://slow.ex.com/api/x"
    SCAN = "[*] Scanning 0/1: {u}"
    NONE = "[!] No parameters were discovered."
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    monkeypatch.setattr(params.settings, "concurrency", lambda k, d: 2 if k == "ARJUN_TARGETS" else d)
    both_started = threading.Barrier(3, timeout=15)
    kill_called = threading.Event()

    def racy(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        raw_path = raw_path or _declared_path(kw, "stdout")
        stderr_path = stderr_path or _declared_path(kw, "stderr")
        u = cmd[cmd.index("-u") + 1]
        both_started.wait()
        if u == RACER:
            assert kill_called.wait(10)                  # complete only AFTER termination was requested
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text("\n".join([SCAN.format(u=u), NONE]))
            stderr_path.write_text("")
            return runner.RunResult(tool, cmd, Status.EMPTY, 0, 0.1, raw_path, 0)
        return runner.run("sleep", ["sleep", "8"], timeout=0)

    real_cancel = params.runner_cancel_all

    def cancel_then_release():
        n = real_cancel()
        kill_called.set()
        return n

    monkeypatch.setattr(params, "exec_tool", racy)
    monkeypatch.setattr(params, "runner_cancel_all", cancel_then_release)
    real_wait = params.wait
    fired = []

    def interrupt_once(fs, **kw):
        if fired:
            return real_wait(fs, **kw)
        both_started.wait()
        fired.append(True)
        raise KeyboardInterrupt

    monkeypatch.setattr(params, "wait", interrupt_once)
    ctx = _Ctx(run_dir)
    with pytest.raises(KeyboardInterrupt):
        params._arjun_lane(ctx, ctx.profile, [RACER, SLOW])
    monkeypatch.setattr(params, "wait", real_wait)
    assert any("arjun[empty]" in (r.note or "") for r in ctx.run.recorded), \
        "the racing target's verdict was discarded as unmeasured"

    # and it must not be rerun on resume — the completion was genuinely earned
    launched = []

    def all_quick(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        raw_path = raw_path or _declared_path(kw, "stdout")
        stderr_path = stderr_path or _declared_path(kw, "stderr")
        u = cmd[cmd.index("-u") + 1]
        launched.append(u)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text("\n".join([SCAN.format(u=u), NONE]))
        stderr_path.write_text("")
        return runner.RunResult(tool, cmd, Status.EMPTY, 0, 0.1, raw_path, 0)

    monkeypatch.setattr(params, "exec_tool", all_quick)
    ctx2 = _Ctx(run_dir)
    params._arjun_lane(ctx2, ctx2.profile, [RACER, SLOW])
    assert RACER not in launched, "a target harvested from the race was rerun anyway"
    assert launched == [SLOW]


def test_lane_returns_even_when_termination_fails(tmp_path, monkeypatch):
    """The reason shutdown must not wait: if termination FAILS (privileges, an unkillable state, a bug),
    `with ThreadPoolExecutor(...)` re-blocks on __exit__ = shutdown(wait=True) and Ctrl-C hangs anyway.
    Simulated by neutering cancel_all so the children genuinely keep running."""
    from quarry_recon import budget
    from quarry_recon.phases import params

    class _Run:
        def __init__(self, d):
            self.dir = d
            self.added = []
            self.recorded = []

        def raw_path(self, ph, tl, nm):
            p = self.dir / "raw" / ph / tl / nm
            p.parent.mkdir(parents=True, exist_ok=True)
            return p

        def add(self, k, e):
            self.added.append((k, e))
            return True

        def record(self, ph, r):
            self.recorded.append(r)

    class _Ctx:
        def __init__(self, d):
            self.run = _Run(d)
            self.http_timeout = 0
            self.echoed = []
            self.profile = type("P", (), {"http_rl": 0})()

        def echo(self, m):
            self.echoed.append(m)

    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    monkeypatch.setattr(params.settings, "concurrency", lambda k, d: 2 if k == "ARJUN_TARGETS" else d)
    monkeypatch.setattr(params, "runner_cancel_all", lambda: 0)      # termination FAILS to stop anything
    running = threading.Semaphore(0)

    def slow(tool, cmd, **kw):
        running.release()
        return runner.run("sleep", ["sleep", "6"], timeout=0)

    monkeypatch.setattr(params, "exec_tool", slow)
    real_wait = params.wait
    fired = []

    def interrupt_once(fs, **kw):
        if fired:
            return real_wait(fs, timeout=0.1)        # do not let the drain wait become the hang
        for _ in range(2):
            assert running.acquire(timeout=10)
        fired.append(True)
        raise KeyboardInterrupt

    monkeypatch.setattr(params, "wait", interrupt_once)
    ctx = _Ctx(tmp_path / "run")
    ctx.run.dir.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        params._arjun_lane(ctx, ctx.profile, [f"https://h{i}.ex.com/api/x" for i in range(2)])
    elapsed = time.monotonic() - t0
    monkeypatch.setattr(params, "wait", real_wait)
    assert elapsed < 3, f"lane blocked {elapsed:.1f}s on workers it could not kill"
    runner.cancel_all()                                              # clean up the survivors


def test_concurrent_runs_report_cpu_unmeasured_not_fabricated():
    """getrusage(RUSAGE_CHILDREN) is process-GLOBAL: overlapping deltas each absorb the others' CPU."""
    runner._CPU_INFLIGHT.clear()
    gate = threading.Barrier(3, timeout=10)

    def work():
        gate.wait()
        return runner.run("sleep", ["sleep", "0.5"], timeout=10)

    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = [pool.submit(work) for _ in range(3)]
        results = [f.result(timeout=20) for f in futs]
    assert all(not runner.cpu_measured(r) for r in results)
    assert runner._CPU_INFLIGHT == {}
    solo = runner.run("sleep", ["sleep", "0"], timeout=10)
    assert runner.cpu_measured(solo)
