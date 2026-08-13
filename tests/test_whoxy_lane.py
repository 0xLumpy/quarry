"""B1.6b — the wired `_whoxy` lane, driven end to end with a scripted provider.

Covers what only the REAL lane can show: the spending controls as an operator writes them, the exact
bytes of a failing response, and a lifecycle blocked on the account lock.
"""

from __future__ import annotations

import json
import urllib.error

import pytest

from quarry_recon import osint, secrets, settings, whoxy_page as wp
from quarry_recon.runner import Status

pytestmark = pytest.mark.offline

BAL = json.dumps({"status": 1, "reverse_whois_balance": 200}).encode()


def _page(param, value, page, total):
    n = min(100, max(0, total - (page - 1) * 100))
    return json.dumps({"status": 1, "api_query": "reverse_whois",
                       "search_identifier": {param: value}, "total_results": str(total),
                       "total_pages": max(1, -(-total // 100)), "current_page": page,
                       "search_result": [{"domain_name": f"p{page}d{i}.example.com"}
                                         for i in range(n)]}).encode()


class _Sess:
    def __init__(self, tmp_path):
        self.dir = tmp_path / "session"
        self.project_dir = tmp_path / "project"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.recorded, self.cands = [], []

    def raw_path(self, source, name):
        p = self.dir / "raw" / source
        p.mkdir(parents=True, exist_ok=True)
        return p / name

    def candidate(self, value, *a, **k):
        self.cands.append(value)

    def record(self, result):
        self.recorded.append(result)


def _drive(tmp_path, monkeypatch, *, perf=None, total=250, err=None, spend_lock=None):
    calls = []

    def get(url, timeout=None):
        calls.append(url)
        if "account=balance" in url:
            return BAL, None
        if err is not None:
            return err()
        param = "email" if "email=" in url else "company"
        value = url.split(f"{param}=")[1].split("&")[0].replace("%40", "@").replace("%20", " ")
        page = int(url.split("page=")[1])
        return _page(param, value, page, total), None

    monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
    monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
    monkeypatch.setattr(osint, "_whoxy_get", get)
    monkeypatch.setattr(settings, "performance", lambda: dict(perf or {}))
    monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock" if spend_lock is None else spend_lock)
    s = _Sess(tmp_path)
    osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
    return s, calls


def _paid(calls):
    return [c for c in calls if "account=balance" not in c]


class TestSpendingControlsAsWritten:
    """review-B1.6b15: nothing referenced `settings.raw()`. `concurrency()` would have turned an explicit
    0 into 1, a negative typo into 1, and a malformed value into a permissive default."""

    def test_an_explicit_ZERO_reserve_stays_zero(self, tmp_path, monkeypatch):
        s, calls = _drive(tmp_path, monkeypatch, perf={"WHOXY_CREDIT_RESERVE": 0})
        assert len(_paid(calls)) == 3 and s.recorded[0].status is Status.SUCCESS

    def test_an_explicit_ZERO_page_budget_is_UNBOUNDED_not_one_page(self, tmp_path, monkeypatch):
        s, calls = _drive(tmp_path, monkeypatch, perf={"WHOXY_PAGE_BUDGET": 0})
        assert len(_paid(calls)) == 3, _paid(calls)

    def test_a_POSITIVE_page_budget_bounds_the_run(self, tmp_path, monkeypatch):
        s, calls = _drive(tmp_path, monkeypatch, perf={"WHOXY_PAGE_BUDGET": 2})
        assert len(_paid(calls)) == 2
        r = s.recorded[0]
        assert r.status is Status.LIMITED and r.meta["operator_limit"] is True
        assert r.meta["spend_stop_kind"] == "run_budget"

    @pytest.mark.parametrize("perf", [
        {"WHOXY_CREDIT_RESERVE": -5}, {"WHOXY_PAGE_BUDGET": -1},
        {"WHOXY_CREDIT_RESERVE": "lots"}, {"WHOXY_PAGE_BUDGET": "3 pages"},
        {"WHOXY_CREDIT_RESERVE": True},
    ])
    def test_a_MALFORMED_control_issues_NO_paid_request(self, tmp_path, monkeypatch, perf):
        """A cost guard that fails open is worse than none: a typo must not become permission."""
        s, calls = _drive(tmp_path, monkeypatch, perf=perf)
        assert _paid(calls) == [], _paid(calls)
        r = s.recorded[0]
        assert r.status is Status.FAILED and r.meta["config_invalid"], r.meta

    def test_a_RESERVE_withholds_and_reports_itself_as_OURS(self, tmp_path, monkeypatch):
        s, calls = _drive(tmp_path, monkeypatch, perf={"WHOXY_CREDIT_RESERVE": 199}, total=1000)
        assert len(_paid(calls)) == 1, _paid(calls)
        r = s.recorded[0]
        assert r.status is Status.LIMITED and r.meta["operator_limit"] is True
        assert r.meta["provider_limit"] is False and r.meta["spend_stop_kind"] == "operator_reserve"


class TestFailureEvidenceIsExact:
    def test_NON_UTF8_error_bytes_survive_the_REAL_whoxy_get(self, monkeypatch):
        """review-B1.6b16#2: the earlier version called `capture_error_body` itself and returned
        `body_bytes`, so reverting `_whoxy_get` to the lossy `body_text.encode()` would have survived
        it. The real function is called, with a real raising `urlopen` behind it."""
        import io
        body = b'{"status": 0, "status_reason": "\xff\xfe bad bytes"}'
        assert body.decode("utf-8", "replace").encode() != body, "fixture is not actually non-UTF-8"

        def raising(req, timeout=None):
            raise urllib.error.HTTPError("http://x", 500, "err", {}, io.BytesIO(body))

        monkeypatch.setattr(osint.urllib.request, "urlopen", raising)
        raw, err = osint._whoxy_get("https://api.whoxy.com/?key=K&account=balance", 5)
        assert raw == body, raw
        assert err is not None and getattr(err, "error_class", None)

    def test_the_non_utf8_body_is_PERSISTED_verbatim(self, tmp_path, monkeypatch):
        """...and reaches disk unchanged, through the paginator's evidence path."""
        import io
        body = b'{"status": 0, "status_reason": "\xff\xfe bad bytes"}'

        def raiser():
            e = urllib.error.HTTPError("http://x", 500, "err", {}, io.BytesIO(body))
            from quarry_recon.contract import capture_error_body, provider_error_class
            capture_error_body(e, provider="whoxy")
            e.error_class = provider_error_class(e)
            return getattr(e, "body_bytes", b""), e

        s, _calls = _drive(tmp_path, monkeypatch, err=raiser)
        kept = [q.read_bytes() for q in (wp.state_dir(s.project_dir) / "pages").rglob("*.json")
                if q.name != ".quarry-write-probe"]
        assert kept == [body], kept

    @pytest.mark.parametrize("cls", sorted(__import__("quarry_recon.contract",
                                                      fromlist=["x"]).PROVIDER_CLASSES))
    def test_EVERY_error_class_builds_a_VALID_balance_outcome(self, cls):
        """review-B1.6b15#2: the rule said `refused=False` unconditionally, so a class the type requires
        to be refused built an INVALID `BalanceRead` and raised `ValueError` out of the lane. The RULE is
        tested rather than one path through it — Whoxy reports quota inside a 200 today, so no transport
        error currently produces a limit class, and "unlikely" is not a contract."""
        from quarry_recon.contract import PROVIDER_LIMITS
        for err in (RuntimeError("boom"),
                    urllib.error.HTTPError("http://x", 500, "err", {}, None)):
            err.error_class = cls
            bal = osint._balance_from_error(err)      # must not raise for ANY class, from ANY origin
            assert bal.error_class == cls and bal.remaining is None
            if cls in PROVIDER_LIMITS:
                assert bal.refused is True, "a proven limit that is not refused cannot be constructed"

    @pytest.mark.parametrize("cls", ["error", "auth", "forbidden", "server", "rate_limit", "http"])
    def test_a_LOCAL_exception_is_not_the_provider_REFUSING_us(self, cls):
        """review-B1.6b16#1: refusal was inferred from the CLASS alone, so an unclassified LOCAL
        exception — which maps to `error` — claimed the provider had refused us. That is a statement
        about a conversation that may never have happened."""
        err = RuntimeError("a bug in our own code")
        err.error_class = cls
        assert osint._balance_from_error(err).refused is False, cls

    @pytest.mark.parametrize("cls", ["auth", "forbidden", "server", "rate_limit", "http", "error"])
    def test_an_HTTP_ERROR_is_the_provider_having_ANSWERED(self, cls):
        err = urllib.error.HTTPError("http://x", 500, "err", {}, None)
        err.error_class = cls
        assert osint._balance_from_error(err).refused is True, cls

    def test_a_PARSE_failure_is_never_a_refusal_from_either_origin(self):
        for err in (RuntimeError("x"), urllib.error.HTTPError("http://x", 500, "e", {}, None)):
            err.error_class = "parse"
            assert osint._balance_from_error(err).refused is False

    @pytest.mark.parametrize("code,body,cls", [
        (401, b"<html>401 Unauthorized</html>", "auth"),
        (429, b"slow down", "rate_limit"),
        (500, b"upstream exploded", "server"),
    ])
    def test_a_BALANCE_endpoint_ERROR_never_raises_out_of_the_lane(self, tmp_path, monkeypatch,
                                                                   code, body, cls):
        import io
        calls = []

        def get(url, timeout=None):
            calls.append(url)
            if "account=balance" in url:
                e = urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(body))
                from quarry_recon.contract import capture_error_body, provider_error_class
                capture_error_body(e, provider="whoxy")
                e.error_class = provider_error_class(e)
                return getattr(e, "body_bytes", b""), e
            return _page("email", "a@x.com", 1, 250), None

        monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint, "_whoxy_get", get)
        monkeypatch.setattr(settings, "performance", dict)
        monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock")
        s = _Sess(tmp_path)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)     # must not raise
        assert _paid(calls) == [], "a refused balance still bought a page"
        r = s.recorded[0]
        # the TAXONOMY, pinned: none of these is a boundary, so none may read as a provider limit.
        assert r.status is Status.FAILED, (code, r.status)
        # the CLASS itself, not "the class appears somewhere in the prose": the disjunction this
        # replaced was satisfied by `gap_reason` alone, so removing `SpendPolicy.error_class`
        # survived it entirely.
        assert r.meta["error_class"] == cls, r.meta
        assert cls in (r.meta.get("gap_reason") or ""), r.meta["gap_reason"]
        assert r.meta["provider_limit"] is False and r.meta["operator_limit"] is False


class TestMachineryFailuresStayBestEffort:
    """review-B1.6b21: only `LockBusy` was caught, so a machinery failure the lock deliberately
    PROPAGATES — a read-only filesystem, one without lock support — aborted the entire OSINT run with no
    Whoxy terminal at all. Best-effort is the provider contract: one lane failing must not take the
    session with it."""

    def _flock_raises(self, monkeypatch, errno_code):
        import errno as _e
        import fcntl as _f

        def broken(fd, op):
            raise OSError(getattr(_e, errno_code), errno_code)

        monkeypatch.setattr(_f, "flock", broken)

    @pytest.mark.parametrize("code", ["EROFS", "ENOLCK", "ENOSYS", "EPERM"])
    def test_a_NON_CONTENTION_lock_error_becomes_a_lane_FAILURE(self, tmp_path, monkeypatch, code):
        calls = []

        def get(url, timeout=None):
            calls.append(url)
            return BAL, None

        monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint, "_whoxy_get", get)
        monkeypatch.setattr(settings, "performance", dict)
        monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock")
        self._flock_raises(monkeypatch, code)

        s = _Sess(tmp_path)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)      # must NOT raise
        assert calls == [], f"a broken lock still talked to Whoxy: {calls}"
        assert len(s.recorded) == 1, s.recorded
        r = s.recorded[0]
        assert r.status is Status.FAILED, r.status
        assert r.meta["gap_reason"] and r.meta["coverage_incomplete"]
        assert r.meta["provider_limit"] is False and r.meta["operator_limit"] is False

    def test_a_BODY_raised_StateBusy_is_NOT_this_lock_s_contention(self, tmp_path, monkeypatch):
        """review-B-audit-7#7: the wrapper translated `StateBusy` around the whole `with` body, so a
        DIFFERENT lock's contention (an inner lifecycle, a nested state lock) came back out as this lock
        reporting itself busy. Only the acquisition may be translated."""
        from quarry_recon import budget as _b

        with pytest.raises(_b.StateBusy) as ei:
            with wp._flock(tmp_path / "x.lock"):
                raise _b.StateBusy("a DIFFERENT lock is held")
        assert "a DIFFERENT lock" in str(ei.value)

        # ...and real contention on THIS lock is still `LockBusy`
        with wp._flock(tmp_path / "y.lock"):
            with pytest.raises(wp.LockBusy):
                with wp._flock(tmp_path / "y.lock"):
                    pass                                   # pragma: no cover

    def test_the_SESSION_verdict_reports_the_gap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint, "_whoxy_get", lambda url, timeout=None: (BAL, None))
        monkeypatch.setattr(settings, "performance", dict)
        monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock")
        # Establish the session authority before faulting the process-wide flock
        # primitive: this test is about a Whoxy lane lock failure, not failure to
        # acquire the OSINT repository's own mandatory mutation lock.
        sess = osint.OsintSession(tmp_path / "project", "acme.com")
        self._flock_raises(monkeypatch, "EROFS")

        osint._whoxy(sess, {"a@x.com"}, [], lambda m: None, 30)
        v = sess.outcome()
        assert v["verdict"] == "complete_with_gaps", v
        assert v["gaps"] and not v["provider_limits"] and not v["operator_limits"], v

    def test_CANCELLATION_still_ends_the_run(self, tmp_path, monkeypatch):
        """`KeyboardInterrupt` is not an `Exception` — a cancelled run must not be swallowed into a
        lane terminal and reported as merely degraded."""
        import fcntl as _f
        monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint, "_whoxy_get", lambda url, timeout=None: (BAL, None))
        monkeypatch.setattr(settings, "performance", dict)
        monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock")
        monkeypatch.setattr(_f, "flock",
                            lambda fd, op: (_ for _ in ()).throw(KeyboardInterrupt("ctrl-c")))
        s = _Sess(tmp_path)
        with pytest.raises(KeyboardInterrupt):
            osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
        assert s.recorded == []

    def _own_three_pages(self, tmp_path, monkeypatch):
        """One lifecycle that buys three pages, so the NEXT one has real evidence to replay."""
        def get(url, timeout=None):
            if "account=balance" in url:
                return BAL, None
            return _page("email", "a@x.com", int(url.split("page=")[1]), 1000), None

        monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint, "_whoxy_get", get)
        # a budget of 3 against a TEN-page anchor, so the second lifecycle has real pending work and
        # therefore actually enters the paid phase.
        monkeypatch.setattr(settings, "performance", lambda: {"WHOXY_PAGE_BUDGET": 3})
        monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock")
        s = _Sess(tmp_path)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)
        assert s.recorded[0].meta["pages_bought"] == 3
        return s

    def test_a_REPLAY_failure_keeps_the_pages_replayed_before_it(self, tmp_path, monkeypatch):
        """review-B1.6b22: `_replay` sat OUTSIDE the paid-phase handler, so an ingest that raised on
        page 2 — after page 1 had already yielded 100 candidates — escaped `run_pages` entirely and the
        lane fabricated `attempted=0, completed=0, not_sent=1` over evidence it was holding."""
        s = self._own_three_pages(tmp_path, monkeypatch)

        s2 = _Sess(tmp_path)
        s2.project_dir = s.project_dir
        real_candidate = s2.candidate

        def exploding(value, *a, **k):
            if str(value).startswith("p2d"):          # page 2, first row
                raise RuntimeError("ingest exploded during replay")
            return real_candidate(value, *a, **k)

        s2.candidate = exploding
        osint._whoxy(s2, {"a@x.com"}, [], lambda m: None, 30)

        assert len(s2.recorded) == 1, s2.recorded
        r = s2.recorded[0]
        # both pages were read back out of the store, and page 2 STAYS owned — dropping it would have
        # the scheduler sell it to us again. review-B1.6b23#1: its rows never landed, and that shortfall
        # gets its own unit rather than silently leaving the page remainder.
        assert r.meta["pages_replayed"] == 2, "pages replayed BEFORE the failure were discarded"
        assert r.meta["pages_unconsumed"] == 1, "a page read but NOT ingested vanished from the terminal"
        assert r.meta["failed"] >= 1, "an unconsumed page did not reach the coverage counters"
        assert "not ingested" in r.meta["gap_reason"], r.meta["gap_reason"]
        assert r.meta["domains"] == 100, r.meta["domains"]
        assert s2.cands and len(s2.cands) == 100, "page 1's candidates never reached the session"
        assert r.meta["completed"] == 1, "an anchor we ingested a page for was reported untouched"
        assert r.meta["not_sent"] == 0, "an OPENED anchor was reported as never opened"
        assert r.status is Status.PARTIAL, r.status         # real evidence + an unfinished lifecycle
        assert "machinery" in (r.meta["gap_reason"] or ""), r.meta["gap_reason"]
        assert r.meta["coverage_incomplete"] is True
        assert r.meta["provider_limit"] is False and r.meta["operator_limit"] is False

    def test_a_REMAINDER_failure_keeps_the_completed_lifecycle(self, tmp_path, monkeypatch):
        """`_remainder` is accounting, and its failure must not delete the pages the run actually got."""
        s = self._own_three_pages(tmp_path, monkeypatch)
        monkeypatch.setattr(wp, "_remainder",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("accounting exploded")))
        s2 = _Sess(tmp_path)
        s2.project_dir = s.project_dir
        osint._whoxy(s2, {"a@x.com"}, [], lambda m: None, 30)

        r = s2.recorded[0]
        assert r.meta["pages_replayed"] == 3 and r.meta["domains"] >= 300, r.meta
        assert r.status is Status.PARTIAL and "machinery" in (r.meta["gap_reason"] or "")

    def test_BOTH_a_provider_failure_and_a_later_machinery_failure_reach_the_terminal(
            self, tmp_path, monkeypatch):
        """review-B1.6b23#3: the machinery reason was added only when no gap reason existed, so a
        provider failure followed by our own accounting blowing up reported only the provider."""
        def get(url, timeout=None):
            if "account=balance" in url:
                return BAL, None
            if "page=2" in url:
                err = RuntimeError("connection died")
                err.error_class = "transport"
                return b"", err
            return _page("email", "a@x.com", int(url.split("page=")[1]), 1000), None

        monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint, "_whoxy_get", get)
        monkeypatch.setattr(settings, "performance", dict)
        monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock")
        monkeypatch.setattr(wp, "_remainder",
                            lambda *a, **k: (_ for _ in ()).throw(ValueError("accounting exploded")))
        s = _Sess(tmp_path)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)

        gap = s.recorded[0].meta["gap_reason"]
        assert "transport" in gap, gap                       # the first cause still leads
        assert "accounting exploded" in gap, gap             # and the later one is no longer hidden
        assert s.recorded[0].meta["machinery"] == ["ValueError: accounting exploded"]

    def test_the_REMAINDER_is_a_snapshot_not_an_accumulator(self, tmp_path, monkeypatch):
        """It is reachable twice — once normally, once after a machinery failure — so `+=` over the
        first pass would report a remainder twice the size of the real one."""
        st = wp.AnchorState(wp.Anchor("email", "a@x.com"))
        st.total_pages, st.pages_done = 4, {1}
        o = wp.Outcome(anchors=1)
        wp._remainder([st], o)
        first = (o.pages_left_known, list(o.unopened))
        wp._remainder([st], o)
        assert (o.pages_left_known, list(o.unopened)) == first, "remainder accumulated across calls"

    def test_a_PAID_PHASE_failure_keeps_what_was_already_collected(self, tmp_path, monkeypatch):
        """If it blows up after replay or purchase, those pages are real and stay counted."""
        led_pages = []

        def get(url, timeout=None):
            if "account=balance" in url:
                return BAL, None
            led_pages.append(url)
            # honour the page ASKED FOR: the page binding rejects a body that names a different one,
            # so a fixture answering page 1 to every request tests the binding, not the lane.
            return _page("email", "a@x.com", int(url.split("page=")[1]), 1000), None

        monkeypatch.setattr(secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint.secrets, "whoxy", lambda: "KEY")
        monkeypatch.setattr(osint, "_whoxy_get", get)
        # a budget of 3 against a TEN-page anchor, so the second lifecycle has real pending work and
        # therefore actually enters the paid phase.
        monkeypatch.setattr(settings, "performance", lambda: {"WHOXY_PAGE_BUDGET": 3})
        monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock")
        s = _Sess(tmp_path)
        osint._whoxy(s, {"a@x.com"}, [], lambda m: None, 30)      # first run buys three of ten
        assert s.recorded[0].meta["pages_bought"] == 3

        real_buy = wp._buy

        def exploding(*a, **k):
            real_buy(*a, **k)
            raise RuntimeError("machinery exploded after buying")

        monkeypatch.setattr(wp, "_buy", exploding)
        s2 = _Sess(tmp_path)
        s2.project_dir = s.project_dir                            # same project -> replays its pages
        osint._whoxy(s2, {"a@x.com"}, [], lambda m: None, 30)
        r = s2.recorded[0]
        assert r.meta["pages_replayed"] == 3, "replayed pages were discarded with the exception"
        assert r.meta["pages_bought"] == 3, "pages PAID FOR before the failure were discarded"
        assert r.meta["domains"] == 600 and r.status is not Status.SUCCESS
        assert "machinery" in (r.meta["gap_reason"] or ""), r.meta["gap_reason"]


class TestStructuredOutcomeIsRedacted:
    """review-B1.6b24#1: `record()` redacted `note` and `cmd` and copied `meta` verbatim. r23 put
    arbitrary exception strings into `machinery` and `gap_reason`, so a configured key inside an
    exception reached the manifest beside a redacted `note: ***`. One unredacted sink is the leak."""

    def test_a_KEY_inside_a_machinery_reason_never_reaches_the_manifest(self, tmp_path, monkeypatch):
        key = "TEST-SECRET-abc123"
        monkeypatch.setattr(secrets, "whoxy", lambda: key)
        monkeypatch.setattr(osint.secrets, "whoxy", lambda: key)
        monkeypatch.setattr(secrets, "values", lambda: [key])
        monkeypatch.setattr(osint.secrets, "values", lambda: [key])
        monkeypatch.setattr(osint, "_whoxy_get", lambda url, timeout=None: (BAL, None))
        monkeypatch.setattr(settings, "performance", dict)
        monkeypatch.setattr(wp, "SPEND_LOCK", tmp_path / "spend.lock")
        monkeypatch.setattr(wp, "_remainder",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError(f"boom {key}")))

        sess = osint.OsintSession(tmp_path / "project", "acme.com")
        osint._whoxy(sess, {"a@x.com"}, [], lambda m: None, 30)
        blob = json.dumps(sess._tool_runs)
        assert key not in blob, blob
        assert "***" in blob, blob

    def test_EVERY_string_leaf_is_reached_however_deeply_it_is_nested(self):
        key = "TEST-SECRET-abc123"
        import quarry_recon.secrets as sec
        old = sec.values
        sec.values = lambda: [key]
        try:
            got = sec.redact_deep({"a": [{"b": (f"x{key}", {f"k{key}"})}, f"plain {key}"],
                                   f"key-{key}": f"v{key}", "n": 1, "none": None})
        finally:
            sec.values = old
        blob = repr(got)
        assert key not in blob, blob
        assert got["n"] == 1 and got["none"] is None, got     # non-strings pass through untouched
        assert "key-***" in got and got["key-***"] == "v***", got

    def test_the_ORIGINAL_metadata_object_is_not_edited(self, tmp_path, monkeypatch):
        """The caller's `meta` is evidence, not ours to rewrite in place."""
        key = "TEST-SECRET-abc123"
        monkeypatch.setattr(secrets, "values", lambda: [key])
        monkeypatch.setattr(osint.secrets, "values", lambda: [key])
        meta = {"gap_reason": f"boom {key}", "machinery": [f"RuntimeError: {key}"]}
        sess = osint.OsintSession(tmp_path / "project", "acme.com")
        sess.record(osint.RunResult("whoxy", ["whoxy"], Status.FAILED, None, 0.0, None, 0,
                                    note="", meta=meta))
        assert meta["gap_reason"] == f"boom {key}", "the caller's own object was rewritten"
        assert key not in json.dumps(sess._tool_runs)
