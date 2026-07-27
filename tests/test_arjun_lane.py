"""params.arjun — the A2 lane migrated off ARJUN_CAP onto per-target execution.

The contract these encode was PROBED against arjun 2.2.7 (source read + executed), not inferred:
exit 0 is not an execution oracle, a missing -oT is usually a legitimate clean-empty, and an unhandled
`.status_code` crash on a 400/413/418/429/503 target aborts every REMAINING target of a batched run.
Pure/offline — arjun is faked, no subprocess, no network.
"""
import hashlib
import json
import time

import pytest

from quarry_recon import budget, events
from quarry_recon.phases import params
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline

SUCC = "https://a.ex.com/api/x"
NONE = "https://a.ex.com/api/y"
SKIP = "https://b.ex.com/api/z"
CRASH = "https://b.ex.com/api/w"

_SCAN = "\x1b[1;97m[*]\x1b[0m Scanning 0/1: {u}"
_FOUND = "\x1b[1;32m[+]\x1b[0m Parameters found: foo"
_NONE = "\x1b[1;93m[!]\x1b[0m No parameters were discovered."
_SKIPPED = "\x1b[1;91m[-]\x1b[0m Skipped {u} due to errors"
_UNSTABLE = "\x1b[1;91m[-]\x1b[0m Webpage is returning different content on each request. Skipping."


class _Run:
    def __init__(self, d):
        self.dir = d
        self.added = []
        self.recorded = []

    def raw_path(self, ph, tl, nm):
        p = self.dir / "raw" / ph / tl / nm
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def add(self, kind, e):
        self.added.append((kind, e))
        return True

    def record(self, ph, r):
        self.recorded.append(r)


class _Ctx:
    def __init__(self, d):
        self.run = _Run(d)
        self.http_timeout = 60
        self.echoed = []
        self.profile = type("P", (), {"http_rl": 0})()

    def echo(self, m):
        self.echoed.append(m)


def _fake_arjun(behaviour):
    """Replace exec_tool with a fake arjun honouring `behaviour[url] -> (exit, stdout, params_rows)`.

    It writes the SAME channels a real arjun run leaves behind, so the lane's evidence binding is
    exercised for real: stdout always, stderr always, and -oT only when rows are exported (arjun calls
    exporter() solely inside `elif these_params:`)."""
    launched = []

    def fake(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        if tool != "arjun":
            return RunResult(tool, cmd, Status.SKIPPED, None, 0.0, None, 0)
        url = cmd[cmd.index("-u") + 1]
        launched.append(url)
        code, out, rows = behaviour[url]
        if raw_path is not None:
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(out, encoding="utf-8")
        if stderr_path is not None:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_text("traceback\n" if code else "", encoding="utf-8")
        if rows:
            o = cmd[cmd.index("-oT") + 1]
            with open(o, "a", encoding="utf-8") as fh:      # real arjun APPENDS (text_export 'a+')
                fh.write("".join(r + "\n" for r in rows))
        st = Status.PARTIAL if code else Status.EMPTY
        return RunResult(tool, cmd, st, code, 0.1, raw_path, 0)

    return fake, launched


def _behaviour():
    return {
        SUCC: (0, "\n".join([_SCAN.format(u=SUCC), _FOUND]), [f"{SUCC}?foo=7101"]),
        NONE: (0, "\n".join([_SCAN.format(u=NONE), _NONE]), []),
        SKIP: (0, "\n".join([_SCAN.format(u=SKIP), _SKIPPED.format(u=SKIP)]), []),
        CRASH: (1, _SCAN.format(u=CRASH), []),
    }


@pytest.fixture
def drive(tmp_path, monkeypatch):
    """Run the lane over a corpus, returning (ctx, launched_urls). The run dir PERSISTS across calls so
    resume is exercised the way a real rerun exercises it."""
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    state = {}
    _orig_exhausted = budget.Budget.exhausted

    def _go(corpus, behaviour=None, exhaust_after=None, targets=1):
        fake, launched = _fake_arjun(behaviour or _behaviour())
        monkeypatch.setattr(params, "exec_tool", fake)
        monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
        # default the pool to 1 so SUBMISSION order is observable; concurrency has its own tests.
        _real_conc = params.settings.concurrency
        monkeypatch.setattr(params.settings, "concurrency",
                            lambda k, d: targets if k == "ARJUN_TARGETS" else _real_conc(k, d))
        # the gate must be RESTORED between calls: monkeypatch only unwinds at test teardown, so a
        # bounded first run otherwise leaves its exhausted-counter armed and the "resume" run launches
        # nothing — a green test proving the opposite of what it claims.
        if exhaust_after is None:
            monkeypatch.setattr(budget.Budget, "exhausted", _orig_exhausted)
        else:
            # exercise the REAL between-items gate rather than sleeping out a wall-clock budget. A
            # negative/zero budget would not do it: Budget clamps to 0, which means UNBOUNDED.
            seen_items = {"n": 0}

            def _exhausted(self):
                seen_items["n"] += 1
                return seen_items["n"] > exhaust_after

            monkeypatch.setattr(budget.Budget, "exhausted", _exhausted)
        d = state.setdefault("dir", tmp_path / "run")
        d.mkdir(parents=True, exist_ok=True)
        ctx = _Ctx(d)
        params._arjun_lane(ctx, ctx.profile, list(corpus))
        return ctx, launched

    return _go


# ── the measured contract matrix ──────────────────────────────────────────────────────────────────
_S = _SCAN.format(u=SUCC)
_K = _SKIPPED.format(u=SUCC)
_ROW = [f"{SUCC}?a=1"]


def _verdict(exit_ok, text, urls, *, target=SUCC, malformed=0):
    return params._arjun_verdict(exit_ok, params._arjun_signals(text), urls,
                                 target=target, malformed=malformed)[0]


@pytest.mark.parametrize("exit_ok,text,urls,want", [
    (True, f"{_S}\n{_NONE}", None, "empty"),
    (True, f"{_S}\n{_FOUND}", _ROW, "success"),
    (True, f"{_S}\n{_K}", None, "skipped"),
    (False, f"{_S}", None, "failed"),
    (True, f"{_S}\n{_NONE}", _ROW, "unknown"),              # says none, artifact exists
    (True, f"{_S}\n{_FOUND}", None, "unknown"),             # says found, no artifact
    (True, f"{_S}\n{_FOUND}", [], "unknown"),               # says found, empty artifact
    (True, f"{_S}\n{_UNSTABLE}\n{_NONE}", None, "skipped"),      # terminal line LIES
    (True, f"{_S}", None, "unknown"),                       # no terminal line
    (True, f"{_S}\n{_NONE}\n{_K}", None, "unknown"),        # duplicate terminal
    (True, _NONE, None, "unknown"),                         # no attempt line
    (True, "", None, "unknown"),                            # nothing at all
])
def test_verdict_matrix(exit_ok, text, urls, want):
    assert _verdict(exit_ok, text, urls) == want


def test_exit_zero_alone_never_means_complete():
    """`main()` returns None on every ordinary path, so a target arjun SKIPPED still exits 0. A verdict
    keyed on the exit code alone would journal it as done and never look at that endpoint again."""
    assert _verdict(True, f"{_S}\n{_K}", None) == "skipped"


def test_progress_lines_do_not_hide_the_terminal_line():
    """arjun prints progress with end='\\r'. Splitting on '\\n' only would swallow the terminal line that
    follows the last chunk update — and the verdict would read as 'no terminal line' = unknown."""
    text = f"{_S}\n\x1b[1;93m[!]\x1b[0m Processing chunks: 2/2     \r{_FOUND}"
    assert _verdict(True, text, _ROW) == "success"


# ── the output/target binding (review#2) ──────────────────────────────────────────────────────────
def test_stdout_about_another_target_is_never_attributed_here():
    """arjun prints the URL it was given, so a mismatch means this output is not about this target.
    Accepting it would attribute another host's parameters to the endpoint we asked about."""
    other = _SCAN.format(u="https://other.ex/api")
    assert _verdict(True, f"{other}\n{_FOUND}", _ROW) == "unknown"
    assert _verdict(True, f"{_S}\n" + _SKIPPED.format(u="https://other.ex/api"), None) == "unknown"


@pytest.mark.parametrize("row", [
    "garbage?x=1",                       # not a URL at all — the old `"?" in line` accepted this
    "ftp://a.ex.com/api/x?a=1",          # not HTTP(S)
    "https://other.ex/api/x?a=1",        # right shape, WRONG target
    "https://a.ex.com/api/x",            # no query -> not a parameter finding
    "//a.ex.com/api/x?a=1",              # scheme-relative, no absolute identity
])
def test_malformed_or_off_target_rows_are_rejected(tmp_path, row):
    art = tmp_path / "o.txt"
    art.write_text(f"{SUCC}?good=1\n{row}\n")
    rows, malformed = params._arjun_rows(art, SUCC)
    assert rows == [f"{SUCC}?good=1"]                        # the trustworthy sibling is RETAINED
    assert malformed == 1
    assert _verdict(True, f"{_S}\n{_FOUND}", rows, malformed=malformed) == "unknown"   # not completable


def test_blank_lines_are_not_corruption(tmp_path):
    art = tmp_path / "o.txt"
    art.write_text(f"{SUCC}?a=1\n\n  \n")
    assert params._arjun_rows(art, SUCC) == ([f"{SUCC}?a=1"], 0)


def test_post_rows_keep_their_url_identity(tmp_path):
    """arjun writes POST/JSON results as `<url>\\t<params>`; the URL half is still the identity."""
    art = tmp_path / "o.txt"
    art.write_text(f"{SUCC}?a=1\tb=2\n")
    assert params._arjun_rows(art, SUCC) == ([f"{SUCC}?a=1"], 0)


# ── lifecycle ─────────────────────────────────────────────────────────────────────────────────────
def test_one_crashing_target_does_not_lose_the_others(drive):
    """The batched `-i` failure mode: measured 3 targets with a 429 second -> exit 1 and target 3 never
    scanned. Per-target isolation must attempt every endpoint regardless."""
    ctx, launched = drive([SUCC, NONE, SKIP, CRASH])
    assert set(launched) == {SUCC, NONE, SKIP, CRASH}


def test_each_verdict_is_recorded_with_an_honest_status(drive):
    ctx, _ = drive([SUCC, NONE, SKIP, CRASH])
    by = {r.note.split()[0]: r.status for r in ctx.run.recorded}
    assert by["arjun[success]"] == Status.SUCCESS
    assert by["arjun[empty]"] == Status.EMPTY
    assert by["arjun[skipped]"] == Status.PARTIAL
    assert by["arjun[failed]"] == Status.FAILED       # a nonzero exit is never merely PARTIAL


def test_findings_reach_the_store(drive):
    ctx, _ = drive([SUCC, NONE, SKIP, CRASH])
    assert any(k == "url" and e["url"] == f"{SUCC}?foo=7101" for k, e in ctx.run.added)
    assert any(k == "parameter" and e["value"] == f"{SUCC}?foo=" for k, e in ctx.run.added)
    assert any(k == "review" and e["klass"] == "xss" for k, e in ctx.run.added)


def test_every_entity_carries_raw_provenance(drive):
    """Quarry's traceability contract: a finding whose proof cannot be located is not reviewable."""
    ctx, _ = drive([SUCC, NONE])
    ingested = [e for k, e in ctx.run.added if k in ("url", "parameter", "review")]
    assert ingested and all(e.get("raw_ref") for e in ingested)
    assert all(e["raw_ref"].endswith(".txt") for e in ingested)      # the validated -oT artifact


def test_review_ids_do_not_collide_on_long_urls(drive):
    """A 100-char prefix identity collapsed two distinct long URLs into one review, discarding a finding."""
    long_a = "https://a.ex.com/api/" + "x" * 120 + "/one"
    long_b = "https://a.ex.com/api/" + "x" * 120 + "/two"
    b = {u: (0, "\n".join([_SCAN.format(u=u), _FOUND]), [f"{u}?p=1"]) for u in (long_a, long_b)}
    ctx, _ = drive([long_a, long_b], behaviour=b)
    ids = {e["id"] for k, e in ctx.run.added if k == "review"}
    assert len(ids) == 2


def test_only_agreeing_targets_resume_degraded_ones_retry(drive):
    """Completion needs exit code, terminal line and artifact to AGREE. success/empty are done; skipped
    and crashed are retried, because a transient error must not be remembered as answered."""
    drive([SUCC, NONE, SKIP, CRASH])
    _ctx, again = drive([SUCC, NONE, SKIP, CRASH])
    assert set(again) == {SKIP, CRASH}


def test_a_resumed_target_still_feeds_this_run(drive):
    """The store is per-run: a target skipped by the LEDGER must still re-ingest its retained findings,
    or a resumed run silently reports fewer parameters than the run that discovered them."""
    drive([SUCC, NONE])
    ctx, again = drive([SUCC, NONE])
    assert again == []                                        # nothing relaunched
    assert any(k == "url" and e["url"] == f"{SUCC}?foo=7101" for k, e in ctx.run.added)


def test_never_attempted_targets_run_before_previous_skips(drive):
    """Retry starvation: a permanently-skipped endpoint must never consume a finite budget ahead of an
    endpoint nothing has looked at yet, or the untouched remainder stays invisible run after run.

    Driven with a pool of 1 and a budget that stops after two launches, which is the only situation where
    the ordering actually decides coverage."""
    drive([SKIP, CRASH])
    fresh = ["https://c.ex.com/api/new1", "https://c.ex.com/api/new2"]
    b = _behaviour()
    for u in fresh:
        b[u] = (0, "\n".join([_SCAN.format(u=u), _NONE]), [])
    _ctx, order = drive([SKIP, CRASH] + fresh, behaviour=b, exhaust_after=2, targets=1)
    assert set(order) == set(fresh)          # the budget went to UNTOUCHED work, not to prior skips


@pytest.mark.parametrize("ext", [".out", ".err", ".txt"])
def test_tampering_any_bound_channel_withdraws_the_completion(drive, ext):
    """Both evidence channels are bound, not just the one carrying results. Remembering a verdict whose
    stdout proof (or traceback, or -oT) has since changed would resume on evidence we never re-verified."""
    ctx, _ = drive([SUCC, NONE])
    uid = hashlib.sha256(SUCC.encode()).hexdigest()
    hit = next((ctx.run.dir / "raw" / "params" / "arjun").rglob(f"{uid}{ext}"))
    hit.write_text("TAMPERED")
    _ctx2, again = drive([SUCC, NONE])
    assert SUCC in again


def test_an_untouched_completion_is_not_redone(drive):
    """The control for the tamper tests — without it they would pass even if EVERY resume were redone."""
    drive([SUCC, NONE])
    _ctx, again = drive([SUCC, NONE])
    assert SUCC not in again


def test_manifest_binds_every_channel_that_existed(drive):
    ctx, _ = drive([SUCC, NONE])
    uid = hashlib.sha256(SUCC.encode()).hexdigest()
    man = next((ctx.run.dir / "raw" / "params" / "arjun").rglob(f"{uid}.attempt.json"))
    data = json.loads(man.read_text())
    assert data["url"] == SUCC and data["verdict"] == "success"
    assert set(data["channels"]) == {"stdout", "stderr", "params"}
    # the clean-empty target has NO -oT channel: arjun writes no file when it finds nothing
    uid2 = hashlib.sha256(NONE.encode()).hexdigest()
    man2 = next((ctx.run.dir / "raw" / "params" / "arjun").rglob(f"{uid2}.attempt.json"))
    assert set(json.loads(man2.read_text())["channels"]) == {"stdout", "stderr"}


# ── bounded concurrency (review#1) ────────────────────────────────────────────────────────────────
def test_targets_actually_run_concurrently(tmp_path, monkeypatch):
    """Per-target isolation is one PROCESS per target; it never implied one AT A TIME. With a pool of 4,
    four targets on different hosts must overlap — otherwise hundreds of remote scans are needlessly
    serialized and the lane's wall-clock is the sum of every target."""
    import threading
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    monkeypatch.setattr(params.settings, "concurrency", lambda k, d: 4 if k == "ARJUN_TARGETS" else d)
    urls = [f"https://h{i}.ex.com/api/x" for i in range(4)]
    gate = threading.Barrier(4, timeout=5)         # only passes if 4 workers are in flight together

    def fake(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        u = cmd[cmd.index("-u") + 1]
        gate.wait()                                 # raises BrokenBarrierError if they are serialized
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text("\n".join([_SCAN.format(u=u), _NONE]))
        stderr_path.write_text("")
        return RunResult(tool, cmd, Status.EMPTY, 0, 0.1, raw_path, 0)

    monkeypatch.setattr(params, "exec_tool", fake)
    ctx = _Ctx(tmp_path / "run")
    ctx.run.dir.mkdir(parents=True, exist_ok=True)
    params._arjun_lane(ctx, ctx.profile, urls)
    assert sum(1 for r in ctx.run.recorded if r.status == Status.EMPTY) == 4


def test_one_active_target_per_host(tmp_path, monkeypatch):
    """Several endpoints on ONE host must not get several concurrent arjun processes pointed at it —
    that would multiply pressure on a single host regardless of the pool size."""
    import threading
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    monkeypatch.setattr(params.settings, "concurrency", lambda k, d: 5 if k == "ARJUN_TARGETS" else d)
    urls = [f"https://one.ex.com/api/{i}" for i in range(5)]
    live, peak, lock = {"n": 0}, {"n": 0}, threading.Lock()

    def fake(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        u = cmd[cmd.index("-u") + 1]
        with lock:
            live["n"] += 1
            peak["n"] = max(peak["n"], live["n"])
        time.sleep(0.02)
        with lock:
            live["n"] -= 1
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text("\n".join([_SCAN.format(u=u), _NONE]))
        stderr_path.write_text("")
        return RunResult(tool, cmd, Status.EMPTY, 0, 0.1, raw_path, 0)

    monkeypatch.setattr(params, "exec_tool", fake)
    ctx = _Ctx(tmp_path / "run")
    ctx.run.dir.mkdir(parents=True, exist_ok=True)
    params._arjun_lane(ctx, ctx.profile, urls)
    assert peak["n"] == 1                            # same host -> strictly one at a time
    assert sum(1 for r in ctx.run.recorded if r.status == Status.EMPTY) == 5   # all still processed


def test_the_global_rate_is_split_between_workers_not_handed_to_each(tmp_path, monkeypatch):
    """RATELIMIT.HTTP is a GLOBAL lane cap. Passing it to every process would multiply the real rate at
    the target by the worker count — an RoE breach wearing a rate cap's name."""
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    monkeypatch.setattr(params.settings, "concurrency", lambda k, d: 4 if k == "ARJUN_TARGETS" else d)
    rates = []

    def fake(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        u = cmd[cmd.index("-u") + 1]
        rates.append(int(cmd[cmd.index("--rate-limit") + 1]) if "--rate-limit" in cmd else None)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text("\n".join([_SCAN.format(u=u), _NONE]))
        stderr_path.write_text("")
        return RunResult(tool, cmd, Status.EMPTY, 0, 0.1, raw_path, 0)

    monkeypatch.setattr(params, "exec_tool", fake)
    ctx = _Ctx(tmp_path / "run")
    ctx.run.dir.mkdir(parents=True, exist_ok=True)
    ctx.profile = type("P", (), {"http_rl": 10})()
    params._arjun_lane(ctx, ctx.profile, [f"https://h{i}.ex.com/api/x" for i in range(4)])
    assert rates and all(r is not None for r in rates)      # a configured rate is always applied
    assert all(r < 10 for r in rates)                       # nobody gets the whole budget
    assert sum(set(rates)) <= 10 and sum(sorted(rates)[:4]) <= 10


def test_unverified_engine_is_not_resumable(monkeypatch):
    """A shadowed/drifted/unidentifiable arjun must not inherit another binary's completion state. A
    stable '' sentinel silently did exactly that; a per-run nonce makes the run non-resumable instead."""
    from quarry_recon import registry
    monkeypatch.setattr(registry, "health", lambda t: {"ok": False, "identity": ""})
    a, b = params._arjun_engine(), params._arjun_engine()
    assert a.startswith("unverified-") and b.startswith("unverified-") and a != b

    monkeypatch.setattr(registry, "health", lambda t: {"ok": True, "identity": "2.2.7"})
    assert params._arjun_engine() == "2.2.7"


def test_no_eligible_input_opens_a_zero_generation(tmp_path, monkeypatch):
    """A bare `return` left a PRIOR run's arjun counters standing as current after the corpus stopped
    yielding endpoints — the same defect the content/vhost lanes route every exit through a lifecycle to
    avoid."""
    seen = _coverage(monkeypatch)
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    ctx = _Ctx(tmp_path / "run")
    ctx.run.dir.mkdir(parents=True, exist_ok=True)
    params._arjun_lane(ctx, ctx.profile, [])
    measures = {kw.get("measure") for _s, kw in seen}
    assert {"api_endpoints", "endpoints_tested", "state_persisted"} <= measures
    assert all(kw["eligible"] == 0 and kw["omitted"] == 0 for _s, kw in seen if kw.get("measure"))
    assert ctx.run.recorded and ctx.run.recorded[0].status == Status.SKIPPED


def test_a_worker_crash_is_reported_not_swallowed(tmp_path, monkeypatch):
    """An exception inside a worker is OUR failure, not a verdict about the target: it must surface as a
    coverage gap rather than vanish and leave the endpoint looking unexamined-but-fine."""
    seen = _coverage(monkeypatch)

    def boom(tool, cmd, **kw):
        raise RuntimeError("worker exploded")

    monkeypatch.setattr(params, "exec_tool", boom)
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    ctx = _Ctx(tmp_path / "run")
    ctx.run.dir.mkdir(parents=True, exist_ok=True)
    params._arjun_lane(ctx, ctx.profile, [SUCC])
    unk = [kw for _s, kw in seen if kw.get("kind") == events.COVERAGE_UNKNOWN]
    assert unk and "worker failed" in unk[0]["reason"]


def test_pool_is_sized_from_distinct_hosts_before_the_rate_is_split():
    """The bug: rate 7 / pool 5 on ONE host produced [2,2,1,1,1], ran serially (one target per host) and
    used 1 req/s of the 7 permitted. Size the pool by work that can actually run, THEN partition."""
    assert params._arjun_pool(5, 1, 7) == 1                  # one host -> one slot -> the whole rate
    assert params._arjun_rate_shares(7, params._arjun_pool(5, 1, 7)) == [7]
    assert params._arjun_pool(5, 3, 7) == 3                  # three hosts -> three slots
    assert sum(params._arjun_rate_shares(7, params._arjun_pool(5, 3, 7))) == 7
    assert params._arjun_pool(5, 9, 0) == 5                  # no rate -> bounded by config only
    assert params._arjun_pool(5, 9, 2) == 2                  # rate still shrinks the pool


def test_largest_share_is_used_first():
    """Shares are largest-first and the lowest free slot is taken first, so a partly-filled pool never
    strands the operator's rate on an unused slot."""
    shares = params._arjun_rate_shares(7, 5)
    assert shares == sorted(shares, reverse=True)
    src = __import__("inspect").getsource(params._arjun_lane)
    assert "free.pop(0)" in src and "insort(free, slot)" in src


def test_single_host_scope_uses_the_whole_rate(tmp_path, monkeypatch):
    """End-to-end version of the same defect: every target on one host must run at the full permitted
    rate, since only one of them is ever in flight."""
    monkeypatch.setattr(params.netguard, "guard_urls", lambda ctx, urls, phase=None: list(urls))
    monkeypatch.setattr(params, "have", lambda b: True)
    monkeypatch.setattr(params, "_arjun_engine", lambda: "2.2.7")
    monkeypatch.setattr(budget, "budget_seconds", lambda k: 0)
    monkeypatch.setattr(params.settings, "concurrency", lambda k, d: 5 if k == "ARJUN_TARGETS" else d)
    rates = []

    def fake(tool, cmd, *, raw_path=None, stderr_path=None, timeout=None, **kw):
        u = cmd[cmd.index("-u") + 1]
        rates.append(int(cmd[cmd.index("--rate-limit") + 1]))
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text("\n".join([_SCAN.format(u=u), _NONE]))
        stderr_path.write_text("")
        return RunResult(tool, cmd, Status.EMPTY, 0, 0.1, raw_path, 0)

    monkeypatch.setattr(params, "exec_tool", fake)
    ctx = _Ctx(tmp_path / "run")
    ctx.run.dir.mkdir(parents=True, exist_ok=True)
    ctx.profile = type("P", (), {"http_rl": 7})()
    params._arjun_lane(ctx, ctx.profile, [f"https://one.ex.com/api/{i}" for i in range(4)])
    assert rates == [7, 7, 7, 7]                             # not [1, 1, 1, 1]


def test_unpublishable_completion_fails_the_persistence_measure(drive, monkeypatch):
    """A completion whose manifest could not be written is NOT durable. ledger.save() knows nothing about
    that, so without tracking it the lane reported state_persisted 1/1 and promised a resume that will
    silently repeat the work."""
    seen = _coverage(monkeypatch)
    monkeypatch.setattr(params, "_arjun_manifest", lambda *a, **k: (None, None))
    ctx, _ = drive([SUCC, NONE])
    sp = [kw for _s, kw in seen if kw.get("measure") == "state_persisted"]
    assert sp and sp[0]["tested"] == 0 and sp[0]["omitted"] == 1
    assert "could not publish" in sp[0]["reason"]
    assert any("could not publish evidence" in m for m in ctx.echoed)


def test_unhashable_channel_blocks_the_completion_and_the_persistence_claim(drive, monkeypatch):
    """review#2 (r3): `events.file_digest` returns "" for an unreadable file instead of raising, so a
    channel was bound with an EMPTY digest, the manifest still named it, and state_persisted read 1/1 —
    while the next ledger load rejected the unhashed channel and silently redid the target."""
    seen = _coverage(monkeypatch)
    real_digest = events.file_digest
    monkeypatch.setattr(events, "file_digest",
                        lambda p: "" if str(p).endswith(".err") else real_digest(p))
    ctx, _ = drive([SUCC, NONE])
    sp = [kw for _s, kw in seen if kw.get("measure") == "state_persisted"]
    assert sp and sp[0]["tested"] == 0 and sp[0]["omitted"] == 1


def test_an_unhashable_channel_target_is_retried_not_skipped(drive, monkeypatch):
    """The consequence that matters: the target must actually be rerun, not silently treated as done."""
    real_digest = events.file_digest
    monkeypatch.setattr(events, "file_digest",
                        lambda p: "" if str(p).endswith(".err") else real_digest(p))
    drive([SUCC, NONE])
    monkeypatch.setattr(events, "file_digest", real_digest)
    _ctx, again = drive([SUCC, NONE])
    assert SUCC in again and NONE in again


def test_the_dead_fail_open_parser_is_gone():
    """`_arjun_urls` accepted any line containing '?'. Leaving it importable invites a future caller to
    reintroduce the hole the target-bound parser closed."""
    assert not hasattr(params, "_arjun_urls")


# ── coverage truth ────────────────────────────────────────────────────────────────────────────────
def _coverage(monkeypatch):
    seen = []
    real = events.coverage_partial
    monkeypatch.setattr(events, "coverage_partial",
                        lambda src, **kw: (seen.append((src, kw)), real(src, **kw))[1])
    return seen


def test_budget_leaves_a_counted_resumable_remainder(drive, monkeypatch):
    seen = _coverage(monkeypatch)
    _ctx, launched = drive([SUCC, NONE, SKIP, CRASH], exhaust_after=1)
    assert len(launched) == 1                                 # the budget stopped LAUNCHING after one
    sel = [kw for _s, kw in seen if kw.get("measure") == "api_endpoints"]
    assert sel and sel[0]["eligible"] == 4 and sel[0]["tested"] == 1 and sel[0]["omitted"] == 3
    assert "RESUMABLE remainder" in sel[0]["reason"]


def test_the_remainder_is_picked_up_not_restarted(drive):
    """A bounded run's value is only real if the next run continues it: the one completed target must not
    be redone, and the three the budget never reached must all run."""
    _ctx, first = drive([SUCC, NONE, SKIP, CRASH], exhaust_after=1)
    _ctx2, second = drive([SUCC, NONE, SKIP, CRASH])
    assert len(first) == 1
    assert set(second) == {SUCC, NONE, SKIP, CRASH} - set(first)


def test_the_full_eligible_set_is_the_membership(drive, monkeypatch):
    """ARJUN_CAP 40 is gone: an unbounded run must report the whole set as processed, with no omission."""
    seen = _coverage(monkeypatch)
    drive([SUCC, NONE, SKIP, CRASH])
    sel = [kw for _s, kw in seen if kw.get("measure") == "api_endpoints"]
    assert sel and sel[0]["eligible"] == 4 and sel[0]["tested"] == 4 and sel[0]["omitted"] == 0


def test_unknown_verdicts_are_coverage_unknown_never_a_clean_zero(drive, monkeypatch):
    seen = _coverage(monkeypatch)
    contradictory = {SUCC: (0, "\n".join([_SCAN.format(u=SUCC), _FOUND]), [])}   # claims params, writes none
    drive([SUCC], behaviour=contradictory)
    unk = [kw for _s, kw in seen if kw.get("kind") == events.COVERAGE_UNKNOWN]
    assert unk and unk[0]["omitted"] == 1


def test_missing_tool_is_unknown_not_an_empty_result(drive, monkeypatch):
    """We could not look, so 0/0 would assert these endpoints have no hidden parameters."""
    monkeypatch.setattr(params, "have", lambda b: False)
    seen = _coverage(monkeypatch)
    ctx, launched = drive([SUCC, NONE])
    assert launched == []
    unk = [kw for _s, kw in seen if kw.get("kind") == events.COVERAGE_UNKNOWN]
    assert unk and unk[0]["eligible"] == 2 and unk[0]["tested"] == 0


def test_outcome_counts_only_trusted_terminal_states(drive, monkeypatch):
    seen = _coverage(monkeypatch)
    drive([SUCC, NONE, SKIP, CRASH])
    out = [kw for _s, kw in seen if kw.get("measure") == "endpoints_tested"]
    assert out and out[0]["tested"] == 2 and out[0]["omitted"] == 2      # success+empty vs skipped+crashed


def test_engine_upgrade_starts_a_clean_generation(drive, monkeypatch):
    """The resume key folds arjun's installed identity: a tool upgrade must not resume work its
    predecessor produced under different detection behaviour."""
    drive([SUCC, NONE])
    monkeypatch.setattr(params, "_arjun_engine", lambda: "3.0.0")
    _ctx, again = drive([SUCC, NONE])
    assert set(again) == {SUCC, NONE}


def test_parser_schema_change_starts_a_clean_generation(drive, monkeypatch):
    drive([SUCC, NONE])
    monkeypatch.setattr(params, "_ARJUN_SCHEMA", params._ARJUN_SCHEMA + 1)
    _ctx, again = drive([SUCC, NONE])
    assert set(again) == {SUCC, NONE}
