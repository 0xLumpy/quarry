"""B1.6b — the Whoxy lifecycle lock, proven with genuinely OVERLAPPING PROCESSES.

Marked `integration` rather than `offline`: these spawn a real second process, which the offline guard
forbids — and a same-process check would only demonstrate flock's per-fd behaviour, not that two
`quarry osint` runs actually contend.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import time

import pytest

from quarry_recon import whoxy_page as wp

pytestmark = pytest.mark.integration

#: captured at IMPORT, before the autouse redirect below. `importlib.reload` would rebind the module's
#: CLASSES, so `Anchor` in an already-imported test module would stop comparing equal to the reloaded
#: one — which broke 25 unrelated tests in the same session the first time this was written.
_DEFAULT_SPEND_LOCK = wp.SPEND_LOCK


@pytest.fixture(autouse=True)
def _never_touch_the_real_spend_lock(tmp_path, monkeypatch):
    """The spend lock is installation-wide, which means the operator's own `~/.config/quarry` — a test
    must never create or contend for it."""
    monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "install-spend.lock")


def _holder(project, ready, hold=6.0, schema=None, spend=None, full=False, spend_only=False):
    """A genuinely SEPARATE process holding a lock.

    `full=True` holds `open_state`, i.e. the PROJECT lock and the ledger — which is all a lifecycle
    holds outside its paid phase. `spend_only=True` holds the ACCOUNT lock, which is what a lifecycle
    holds while it is actually buying pages."""
    bump = f"wp.WHOXY_WORK_SCHEMA = {schema}" if schema is not None else ""
    if spend_only:
        inner = f"wp.spend_lock(pathlib.Path({str(spend)!r}))"
    elif full:
        inner = f"wp.open_state(pathlib.Path({str(project)!r}))"
    else:
        inner = f"wp.lifecycle_lock(pathlib.Path({str(project)!r}))"
    code = textwrap.dedent(f"""
        import pathlib, time
        import quarry_recon.whoxy_page as wp
        {bump}
        with {inner}:
            pathlib.Path({str(ready)!r}).write_text("held")
            time.sleep({hold})
    """)
    return subprocess.Popen([sys.executable, "-c", code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def _await(ready, proc):
    for _ in range(200):
        if ready.exists():
            return
        if proc.poll() is not None:
            pytest.fail(f"holder died: {proc.stderr.read().decode()[:400]}")
        time.sleep(0.05)
    pytest.fail("the holder process never acquired the lock")


def test_a_CONCURRENT_lifecycle_is_refused(tmp_path):
    """review-B1.6b#1: two runs could load the same snapshot, buy the same pages, and race while
    compacting the ledger and unlinking the journal it supersedes."""
    proj, ready = tmp_path / "proj", tmp_path / "ready"
    proc = _holder(proj, ready)
    try:
        _await(ready, proc)
        with pytest.raises(wp.LockBusy):
            with wp.lifecycle_lock(proj):
                pass
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_a_BLOCKED_lifecycle_issues_NO_paid_request(tmp_path):
    """Contention is refused BEFORE the balance read or any purchase, so a blocked run spends nothing."""
    proj, ready = tmp_path / "proj", tmp_path / "ready"
    calls = []
    proc = _holder(proj, ready)
    try:
        _await(ready, proc)
        try:
            with wp.lifecycle_lock(proj):
                calls.append("would have fetched")
        except wp.LockBusy:
            pass
    finally:
        proc.kill()
        proc.wait(timeout=10)
    assert calls == []


def test_the_lock_is_released_when_the_HOLDER_DIES(tmp_path):
    """OS-released, not lockfile EXISTENCE: a stale file from a killed run would wedge the project
    forever, while the kernel drops an flock with the process however it dies."""
    proj, ready = tmp_path / "proj", tmp_path / "ready"
    proc = _holder(proj, ready, hold=30.0)
    try:
        _await(ready, proc)
    finally:
        proc.kill()
        proc.wait(timeout=10)
    for _ in range(100):
        try:
            with wp.lifecycle_lock(proj):
                break
        except wp.LockBusy:
            time.sleep(0.05)
    else:
        pytest.fail("the lock outlived its holder")
    assert (wp.provider_dir(proj) / ".lock").exists(), "the lock FILE must not be removed"


def test_a_DIFFERENT_SCHEMA_still_contends(tmp_path, monkeypatch):
    """review-B1.6b2#1: the lock lived inside the schema directory, so a v1 process and a v2 process took
    DIFFERENT locks and could spend against the same account at once. Two builds share one Whoxy
    account; concurrency is a property of the PROVIDER and the project, not of the schema."""
    proj, ready = tmp_path / "proj", tmp_path / "ready"
    proc = _holder(proj, ready, schema=wp.WHOXY_WORK_SCHEMA)      # holder on the CURRENT schema
    try:
        _await(ready, proc)
        before = wp.state_dir(proj)
        monkeypatch.setattr(wp, "WHOXY_WORK_SCHEMA", wp.WHOXY_WORK_SCHEMA + 1)
        assert wp.state_dir(proj) != before                       # a genuinely different generation
        assert wp.provider_dir(proj) == before.parent             # ...sharing one lock level
        with pytest.raises(wp.LockBusy):                          # ...and still refused
            with wp.lifecycle_lock(proj):
                pass
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_opening_STATE_takes_the_lock(tmp_path):
    """review-B1.6b2#2: the safe path is the structural one — there is no way to load the ledger, or get
    as far as a balance read, without the provider lock already held."""
    proj, ready = tmp_path / "proj", tmp_path / "ready"
    proc = _holder(proj, ready)
    try:
        _await(ready, proc)
        with pytest.raises(wp.LockBusy):
            with wp.open_state(proj):
                pytest.fail("state was opened while another lifecycle held the lock")
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_a_NON_CONTENTION_OSError_is_not_reported_as_contention(tmp_path, monkeypatch):
    """review-B1.6b2#3: catching every OSError meant a read-only filesystem or a filesystem with no lock
    support was reported as "another run is active" — sending an operator to look for a process that
    does not exist."""
    import errno
    import fcntl as _f
    proj = tmp_path / "proj"

    def broken(fd, op):
        raise OSError(errno.EROFS, "read-only file system")

    monkeypatch.setattr(_f, "flock", broken)
    with pytest.raises(OSError) as e:
        with wp.lifecycle_lock(proj):
            pass
    assert not isinstance(e.value, wp.LockBusy) and e.value.errno == errno.EROFS


@pytest.mark.parametrize("code", ["EACCES", "EAGAIN"])
def test_the_contention_errnos_ARE_reported_as_contention(tmp_path, monkeypatch, code):
    import errno
    import fcntl as _f
    proj = tmp_path / "proj"

    def busy(fd, op):
        raise OSError(getattr(errno, code), "locked")

    monkeypatch.setattr(_f, "flock", busy)
    with pytest.raises(wp.LockBusy):
        with wp.lifecycle_lock(proj):
            pass


def _paid(spend_path, allowance, seen):
    import contextlib

    @contextlib.contextmanager
    def phase():
        with wp.spend_lock(spend_path):
            seen.append("balance read")          # a real lifecycle reads the balance HERE
            yield allowance

    return phase


def _page(param, value, page, total):
    import json
    n = min(100, max(0, total - (page - 1) * 100))
    return json.dumps({"status": 1, "api_query": "reverse_whois",
                       "search_identifier": {param: value}, "total_results": str(total),
                       "total_pages": max(1, -(-total // 100)), "current_page": page,
                       "search_result": [{"domain_name": f"p{page}d{i}.example.com"}
                                         for i in range(n)]}).encode()


def _lifecycle(project, spend_path, *, total=250, allowance=None, seen=None, calls=None):
    """A whole Whoxy lifecycle: project lock, replay, and the paid phase only if work remains."""
    seen = seen if seen is not None else []
    calls = calls if calls is not None else []
    anchor = wp.Anchor("company", "a")

    def fetch(a, page):
        calls.append(page)
        return _page(a.param, a.value, page, total), None

    with wp.open_state(project) as (led, pages):
        d = pages / f"attempt-{len(list(pages.iterdir()))}"
        d.mkdir(parents=True, exist_ok=True)
        out = wp.run_pages([wp.AnchorState(anchor)], paid=_paid(spend_path, allowance, seen),
                           fetch=fetch, ingest=lambda a, pg, doc, art: len(doc.get("rows") or []),
                           read=wp.read_page, ledger=led, attempt_dir=d)
    return out, seen, calls


def test_a_FULLY_OWNED_project_replays_while_another_SPENDS(tmp_path, monkeypatch):
    """review-B1.6b4: the account lock was taken before the ledger, so a project that owned everything
    it needed was blocked by another project's purchasing — a gap for access it never wanted."""
    spend = tmp_path / "spend.lock"
    # point the module DEFAULT at the very lock the holder takes, so an `open_state` that wrongly
    # acquired the account would contend and be caught. Without this the mutation is invisible: the
    # autouse redirect gives each test its own path, which nothing else is holding.
    monkeypatch.setattr(wp, "SPEND_LOCK", spend)
    a, b = tmp_path / "acme", tmp_path / "other"
    out1, _, calls1 = _lifecycle(b, spend)                      # b buys its pages first
    assert out1.pages_bought == 3

    ready = tmp_path / "ready"
    proc = _holder(a, ready, spend=spend, full=True, hold=8.0, spend_only=True)
    try:
        _await(ready, proc)
        out2, seen2, calls2 = _lifecycle(b, spend)              # ...now replays while a holds the account
        assert out2.pages_replayed == 3 and out2.pages_bought == 0
        assert calls2 == [] and seen2 == [], "a fully owned replay touched the account"
        assert out2.stop_cause == "", out2.stop_cause
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_a_project_with_PENDING_pages_is_blocked_without_touching_the_account(tmp_path):
    """Contention on the paid phase keeps what was replayed and reports only the unpaid remainder."""
    spend = tmp_path / "spend.lock"
    a, b = tmp_path / "acme", tmp_path / "other"
    first, _s, _c = _lifecycle(b, spend, total=1000, allowance=3)   # b owns 3 pages of a 10-page anchor
    assert first.pages_bought == 3 and first.pages_left_known == 7
    ready = tmp_path / "ready"
    proc = _holder(a, ready, spend=spend, full=True, hold=8.0, spend_only=True)
    try:
        _await(ready, proc)
        out, seen, calls = _lifecycle(b, spend, total=1000)
        assert out.pages_replayed == 3, out
        assert calls == [] and seen == [], "a blocked lifecycle read the balance or fetched a page"
        assert out.stop_cause == "account_busy", out.stop_cause
        assert out.pages_left_known == 7
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_TWO_PROJECTS_cannot_spend_the_same_ACCOUNT_at_once(tmp_path):
    """review-B1.6b3: the project lock protects one project's ledger and nothing else. The Whoxy KEY is
    global, so two runs in DIFFERENT projects take different project locks, read the SAME balance, and
    can each spend down to the reserve — together crossing or exhausting it."""
    spend = tmp_path / "spend.lock"
    a, b = tmp_path / "acme", tmp_path / "other"
    ready = tmp_path / "ready"
    calls = []
    # the ACCOUNT lock, not project a's state lock: `open_state` no longer holds the account at all.
    proc = _holder(a, ready, spend=spend, spend_only=True)
    try:
        _await(ready, proc)
        out, seen, fetched = _lifecycle(b, spend, total=250)
        assert out.stop_cause == "account_busy", out.stop_cause
        assert seen == [] and fetched == [], "the contender got as far as a balance read"
    finally:
        proc.kill()
        proc.wait(timeout=10)
    # ...and once the holder is gone the second project runs, with its OWN ledger
    out, seen, fetched = _lifecycle(b, spend, total=250)
    assert out.pages_bought == 3 and seen == ["balance read"], (out, seen)
    with wp.open_state(b) as (led, _pages):
        assert led.path == wp.state_dir(b) / "ledger.json"
        assert wp.state_dir(b) != wp.state_dir(a)


def test_the_spend_lock_is_OUTSIDE_any_project():
    """It is installation-wide by construction: a per-project path could never see another project."""
    default = _DEFAULT_SPEND_LOCK
    assert default.parent.name == "quarry" and default.parent.parent.name == ".config"
    assert "osint" not in default.parts and "state" not in default.parts


def test_the_lock_is_released_after_a_BaseException(tmp_path):
    proj = tmp_path / "proj"
    with pytest.raises(KeyboardInterrupt):
        with wp.lifecycle_lock(proj):
            raise KeyboardInterrupt("cancelled mid-lifecycle")
    with wp.lifecycle_lock(proj):
        pass                                     # acquirable again -> the finally ran


def test_the_WIRED_LANE_blocked_on_the_account_reads_no_balance_and_fetches_no_page(tmp_path,
                                                                                    monkeypatch):
    """The end-to-end form promised earlier: with another project holding the ACCOUNT lock, the real
    `_whoxy` must issue neither a balance read nor a page fetch — the earlier proxy could only show that
    the block happened, not that nothing downstream ran."""
    import json
    from quarry_recon import osint, secrets, settings
    from quarry_recon.runner import Status

    spend = tmp_path / "spend.lock"
    monkeypatch.setattr(wp, "SPEND_LOCK", spend)
    calls = []

    def get(url, timeout=None):
        calls.append(url)
        return json.dumps({"status": 1, "reverse_whois_balance": 200}).encode(), None

    monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
    monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
    monkeypatch.setattr(osint, "_whoxy_get", get)
    monkeypatch.setattr(settings, "performance", dict)

    class _Sess:
        def __init__(self):
            self.dir = tmp_path / "session"
            self.project_dir = tmp_path / "project"
            self.dir.mkdir(parents=True, exist_ok=True)
            self.recorded = []

        def raw_path(self, source, name):
            return self.dir / name

        def candidate(self, *a, **k):
            pass

        def record(self, r):
            self.recorded.append(r)

    ready = tmp_path / "ready"
    proc = _holder(tmp_path / "other", ready, spend=spend, spend_only=True, hold=8.0)
    try:
        _await(ready, proc)
        s = _Sess()
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
        assert calls == [], f"a blocked lifecycle still talked to Whoxy: {calls}"
        r = s.recorded[0]
        # review-B1.6b16#4: this fixture replays NOTHING, so PARTIAL would be a weaker claim than the
        # facts support — nothing was collected at all.
        assert r.status is Status.FAILED, r.status
        assert r.meta["gap_reason"] and "account" in r.meta["gap_reason"], r.meta
        assert r.meta["provider_limit"] is False and r.meta["operator_limit"] is False
        # ...and the SESSION says so: a blocked lane is a gap, never a soft limit.
        sess = osint.OsintSession(tmp_path / "project", "acme.com")
        sess.record(r)
        v = sess.outcome()
        assert v["verdict"] == "complete_with_gaps", v
        assert v["gaps"] and not v["provider_limits"] and not v["operator_limits"], v
    finally:
        proc.kill()
        proc.wait(timeout=10)
