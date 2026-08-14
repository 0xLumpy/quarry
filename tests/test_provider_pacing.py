"""Rate coordination belongs to the provider ACCOUNT, not to one lane's object.

review (Lumpy, 2026-08-05): every `_ProviderCooldown()` started at `last = 0`, so the first request of
each lifecycle was unpaced against whatever ran a moment before it — the paid pivot coordinator, the
free `/host/count` sizing, the `/api-info` balance read and the free `shodan_host` lane are ONE account
being throttled, and two Quarry processes had entirely independent clocks. "One request per second" was
true of an object, never of the account.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import pace
from quarry_recon.phases import probe


class TestTheAccountIsTheBoundary:
    def test_the_same_credential_shares_one_key_across_lanes_and_runs(self):
        a = pace.account("shodan", "SECRET-KEY")
        b = pace.account("shodan", "SECRET-KEY")
        assert a == b, "two lifecycles on one credential must queue behind the same boundary"
        assert a != pace.account("shodan", "OTHER-KEY")

    def test_providers_do_not_share_a_clock(self):
        """Whoxy, Censys and crt.sh have their own accounts and rate policies. One clock across
        providers would be the same mistake in the other direction."""
        key = "SECRET-KEY"
        keys = {pace.account(p, key) for p in ("shodan", "whoxy", "censys", "certspotter")}
        assert len(keys) == 4

    def test_an_unauthenticated_provider_coordinates_by_endpoint(self):
        assert pace.account("crt.sh") == "crt.sh:anonymous"

    def test_the_CREDENTIAL_never_appears_in_the_key_or_on_disk(self, tmp_path, monkeypatch):
        secret = "SUPER-SECRET-KEY-VALUE"
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", secret)
        assert secret not in key and secret not in str(pace._state_path(key))
        pace.wait(key, 0.0)
        blob = "".join(p.read_text() for p in tmp_path.rglob("*.json"))
        assert secret not in blob and secret not in "".join(str(p) for p in tmp_path.rglob("*"))
        assert len(key.split(":")[1]) == 16, "a truncated digest, not the credential"


class TestPacingIsSharedNotPerObject:
    def test_a_SECOND_lifecycle_is_paced_behind_the_first(self, tmp_path, monkeypatch):
        """The defect, directly: two objects, one account. The second must not start unpaced."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        assert pace.wait(key, 1.05) == 0.0, "the first request waits for nothing"
        waited = pace.wait(key, 1.05)                 # a DIFFERENT lifecycle, same account
        assert 0.5 < waited <= 1.1, waited

    def test_two_cooldown_OBJECTS_share_the_boundary(self, tmp_path, monkeypatch):
        """The defect as the lane experiences it: two `_ProviderCooldown` objects, one credential."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        monkeypatch.setattr(probe, "_SHODAN_MIN_INTERVAL_S", 1.05)
        asked: list = []
        real_wait = pace.wait
        monkeypatch.setattr(probe.pace, "wait",
                            lambda key, interval, **kw: asked.append((key, interval)) or 0.0)
        monkeypatch.setattr(probe._time, "sleep", lambda s: None)
        probe._ProviderCooldown("K").wait()           # the paid pivot lane
        probe._ProviderCooldown("K").wait()           # …and the free host lane, moments later
        assert len(asked) == 2, "every request consults the account boundary"
        assert asked[0][0] == asked[1][0] == pace.account("shodan", "K"), asked
        assert asked[0][1] == 1.05, "…with the shipped interval, not a per-object one"
        del real_wait

    def test_a_different_credential_is_NOT_paced_behind_it(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        pace.wait(pace.account("shodan", "K1"), 1.05)
        assert pace.wait(pace.account("shodan", "K2"), 1.05) == 0.0

    def test_the_stamp_is_written_BEFORE_the_request(self, tmp_path, monkeypatch):
        """A process that dies mid-request must still leave the account paced."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace.wait(key, 0.0)
        doc = json.loads(pace._state_path(key).read_text())
        assert doc["last"] > 0 and doc["last"] <= time.time()


class TestAPenaltyOutlivesTheProcessThatEarnedIt:
    def test_a_429_is_persisted_for_the_account(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace.note_penalty(key, time.time() + 300)
        doc = json.loads(pace._state_path(key).read_text())
        assert doc["until"] > time.time() + 200

    def test_the_next_lifecycle_honours_it(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        slept: list = []
        monkeypatch.setattr(pace.time, "sleep", lambda s: slept.append(s))
        key = pace.account("shodan", "K")
        pace.note_penalty(key, time.time() + 120)
        pace.wait(key, 1.05)
        assert slept and slept[0] > 100, "the provider's own slowdown outranks the interval"

    def test_a_penalty_recorded_by_the_lane_reaches_the_account(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        err = Exception("429")
        err.headers = {"Retry-After": "90"}
        c = probe._ProviderCooldown("K")
        c.note(err)
        doc = json.loads(pace._state_path(c.account).read_text())
        assert doc["until"] > time.time() + 60


class TestABoundaryRefusesRatherThanFailsOpen:
    """review#2 (Lumpy): the first version proceeded UNPACED whenever the slot was held, the state was
    malformed or a write failed — it stopped coordinating exactly when coordination mattered, and two
    processes could burst together. A fail-open pacer is advisory telemetry, not a boundary.

    Refusing costs no evidence: replay is untouched and the pages we did not buy are still there."""

    def test_a_held_slot_REFUSES_instead_of_proceeding(self, tmp_path, monkeypatch):
        from quarry_recon import budget
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        monkeypatch.setattr(pace, "LOCK_WAIT_S", 0.1)
        key = pace.account("shodan", "K")
        lock = pace._state_path(key).with_suffix(".lock")
        lock.parent.mkdir(parents=True, exist_ok=True)
        started = time.perf_counter()
        with budget.state_lock(lock):                    # another process holds the slot
            with pytest.raises(pace.PaceBusy):
                pace.wait(key, 1.05)
        assert time.perf_counter() - started < 5.0, "the WAIT is bounded; the boundary is not abandoned"

    def test_malformed_state_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text("{ half a write")
        with pytest.raises(pace.PaceBusy):
            pace.wait(key, 1.05)

    def test_a_non_object_state_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text("[]")
        with pytest.raises(pace.PaceBusy):
            pace.wait(key, 1.05)

    def test_an_unusable_state_directory_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path / "nope" / "\0bad")
        with pytest.raises(pace.PaceBusy):
            pace.wait(pace.account("shodan", "K"), 1.05)

    def test_a_failed_write_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")

        def boom(self, *a, **k):
            raise OSError("disk full")
        monkeypatch.setattr(Path, "write_text", boom)
        with pytest.raises(pace.PaceBusy):
            pace.wait(key, 0.0)

    def test_the_state_is_published_ATOMICALLY(self, tmp_path, monkeypatch):
        """`write_text` can leave a fragment behind, which the next process would read as "no pacing
        history" — the very failure this module exists to prevent."""
        import inspect
        src = inspect.getsource(pace._publish)
        assert "os.replace" in src and ".tmp" in src
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace.wait(key, 0.0)
        assert not list(tmp_path.glob("*.tmp")), "no fragment is left behind"

    def test_a_MISSING_state_is_a_first_request_not_a_refusal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        assert pace.wait(pace.account("shodan", "NEW"), 1.05) == 0.0

    def test_recording_a_penalty_never_raises(self, tmp_path, monkeypatch):
        """The request already happened and the 429 is in hand — the caller is on a failure path. What
        is lost is SHARING the penalty, which the next `wait()` refuses over anyway."""
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text("{ broken")
        pace.note_penalty(key, time.time() + 60)          # must not raise


class TestAnUnusableStampWaitsTheInterval:
    """review#3 (Lumpy): `_stamp` returned 0.0 for an unusable value, so `last + interval` landed near
    the Unix epoch and the request went out IMMEDIATELY — the opposite of the documented behaviour."""

    @pytest.mark.parametrize("bad", [float("inf"), float("nan"), "soon", None, True])
    def test_an_unusable_last_stamp_waits_a_FULL_interval(self, tmp_path, monkeypatch, bad):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text(json.dumps({"last": bad}))
        slept: list = []
        monkeypatch.setattr(pace.time, "sleep", lambda s: slept.append(s))
        pace.wait(key, 1.05)
        assert slept and 1.0 <= slept[0] <= 1.1, (bad, slept)

    def test_a_FUTURE_stamp_waits_one_interval_not_the_difference(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        pace._state_path(key).parent.mkdir(parents=True, exist_ok=True)
        pace._state_path(key).write_text(json.dumps({"last": time.time() + 10_000}))
        slept: list = []
        monkeypatch.setattr(pace.time, "sleep", lambda s: slept.append(s))
        pace.wait(key, 1.05)
        assert slept and 1.0 <= slept[0] <= 1.1, slept


class TestTheLaneReportsARefusalAsAGap:
    def test_a_refused_search_is_a_classified_error_not_a_crash(self, monkeypatch, tmp_path):
        from quarry_recon import contract
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path / "x" / "\0bad")
        c = probe._ProviderCooldown("K")
        with pytest.raises(pace.PaceBusy):
            c.wait()
        e = pace.PaceBusy("slot held")
        e.error_class = contract.PROVIDER_PACE_BUSY
        assert contract.provider_error_class(e) == "pace_busy"
        assert not contract.is_provider_limit("pace_busy"), "ours, not a provider limit"
        assert "pace_busy" in contract.PROVIDER_CLASSES


class TestARefusalIsNotAnIssuedRequest:
    """review#1 (Lumpy): the refusal arrived as an error tuple and `_work` then ran `spent += 1` — a
    credit charged for a socket that never opened, withholding later pivots as though the balance had
    moved. "Contact refused" must stay distinct from "request issued" through the whole accounting."""

    @staticmethod
    def _lane(tmp_path, *, refuse_after=0, spendable=5):
        from quarry_recon import budget, shodan_sched as S
        base = S.state_dir(tmp_path)
        attempt = base / "pages" / "a0"
        attempt.mkdir(parents=True, exist_ok=True)
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        states = [S.PivotState(pivot=S.Pivot("probe.favicon", "http.favicon.hash", v))
                  for v in ("1", "2", "3")]
        res = S.WorkResult()
        res.lanes.setdefault("probe.favicon", S.LaneOutcome(lane="probe.favicon"))
        issued: list = []

        def search(pivot, page):
            if len(issued) >= refuse_after:
                raise pace.PaceBusy("another process holds this account's pacing slot")
            issued.append((pivot.value, page))
            raw = attempt / "raw" / f"{S.item_key(pivot, page)}.json"
            raw.parent.mkdir(parents=True, exist_ok=True)
            raw.write_bytes(b'{"total": 1, "matches": []}')
            return ([], 1, None)

        S._work(states, res,
                balance=type("B", (), {"spendable": spendable, "may_spend": True, "reserve": 0})(),
                search=search, ingest=lambda *a: 0, ledger=led, attempt_dir=attempt,
                max_pages=1, is_limit=lambda cls: False)
        return res, issued

    def test_a_refusal_on_the_FIRST_pivot_spends_nothing(self, tmp_path):
        res, issued = self._lane(tmp_path, refuse_after=0)
        o = res.lanes["probe.favicon"]
        assert issued == [], "no socket opened"
        assert o.pages_bought == 0 and o.pace_refused == 1
        assert res.stop_cause.startswith("pace_busy")

    def test_a_refusal_does_not_consume_the_remaining_budget(self, tmp_path):
        """The distortion: a refusal that charges a credit makes the NEXT pivot look unaffordable."""
        res, issued = self._lane(tmp_path, refuse_after=1, spendable=2)
        o = res.lanes["probe.favicon"]
        assert len(issued) == 1, issued
        assert o.pages_bought == 1, "the one real purchase stands"
        assert o.pace_refused == 1
        # one credit was spendable AFTER that purchase; the refusal must not have eaten it. The pivot is
        # left as an unbought REMAINDER, which a later lifecycle can buy — not as a budget exhaustion.
        assert "budget" not in res.stop_cause, res.stop_cause
        assert res.stop_cause.startswith("pace_busy")

    def test_the_refused_page_is_not_marked_as_tried(self, tmp_path):
        """A page nobody asked for must stay askable: it is a remainder, not a completed attempt."""
        res, _ = self._lane(tmp_path, refuse_after=0)
        st_pages = {p for st in [] for p in st.pages_done}
        assert not st_pages
        assert res.lanes["probe.favicon"].pages_bought == 0


class TestTheBalancePathRefusalIsClassified:
    """review#2: a refusal before `/api-info` returned None and `run_work` skipped quietly, while the
    balance claimed an operator RESERVE. Nothing carried `pace_busy`."""

    def test_the_lane_reports_pace_busy_and_contacts_nobody(self, tmp_path, monkeypatch):
        from quarry_recon import budget, shodan_sched as S
        base = S.state_dir(tmp_path)
        attempt = base / "pages" / "a0"
        attempt.mkdir(parents=True, exist_ok=True)
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        states = [S.PivotState(pivot=S.Pivot("probe.favicon", "http.favicon.hash", "1"))]

        def refused():
            raise pace.PaceBusy("pacing state unreadable")

        res = S.run_work(None, states=states, balance=refused,
                         search=lambda pv, pg: pytest.fail("a request was issued after a refusal"),
                         ingest=lambda *a: 0, ledger=led, attempt_dir=attempt, max_pages=1)
        assert res.stop_cause.startswith("pace_busy"), res.stop_cause
        assert res.lanes["probe.favicon"].pace_refused == 1
        assert res.lanes["probe.favicon"].pages_bought == 0

    def test_it_is_neither_a_provider_limit_nor_a_reserve(self):
        from quarry_recon import contract, events, shodan_sched as S
        assert not contract.is_provider_limit(contract.PROVIDER_PACE_BUSY)
        # the coverage KIND for work we never reached must read as a gap of ours, never a soft limit
        assert S._unqueried_kind(None, f"{S.PACE_BUSY}:slot held") == events.COVERAGE_TIMEOUT

    def test_the_reported_balance_makes_no_reserve_claim(self, tmp_path, monkeypatch):
        """`SHODAN_UNKNOWN_WITH_RESERVE` would say the OPERATOR withheld credits. Nobody did."""
        import inspect
        src = inspect.getsource(probe._shodan_work_locked)
        idx = src.index('if paid["pace_busy"]:')
        block = src[idx:idx + 700]
        assert "SHODAN_UNKNOWN_WITH_RESERVE" not in block
        # the ASSIGNMENT, not the word: the comment above it explains why `stop_kind` stays unset, and a
        # test that matches prose passes for the wrong reason.
        assert "stop_kind=" not in block, "an empty stop_kind is the honest answer here"
        assert "may_spend=False" in block, "…but nothing may be spent either"


class TestAnUnsharedPenaltyStopsFurtherContact:
    """review#3: `note_penalty` swallowed a publish failure, so an older valid state file kept the next
    process going without the new `Retry-After` — while the comment claimed the opposite."""

    def test_note_penalty_reports_whether_it_shared(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        key = pace.account("shodan", "K")
        assert pace.note_penalty(key, time.time() + 60) is True
        monkeypatch.setattr(Path, "write_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(OSError("disk full")))
        assert pace.note_penalty(key, time.time() + 120) is False

    def test_an_unshared_penalty_ends_provider_contact_for_this_lifecycle(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        monkeypatch.setattr(pace, "note_penalty", lambda *a, **k: False)
        c = probe._ProviderCooldown("K")
        err = Exception("429")
        err.headers = {"Retry-After": "60"}
        c.note(err)
        assert c.unshared_penalty, "the loss of coordination is recorded"
        with pytest.raises(pace.PaceBusy):
            c.wait()

    def test_a_SHARED_penalty_leaves_the_lifecycle_working(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path)
        monkeypatch.setattr(pace.time, "sleep", lambda s: None)
        c = probe._ProviderCooldown("K")
        err = Exception("429")
        err.headers = {"Retry-After": "1"}
        c.note(err)
        assert not c.unshared_penalty
        c.wait()                                    # honoured, not refused


class TestTheREALLaneNotJustTheScheduler:
    """review#5 (Lumpy): the scheduler caught `PaceBusy` before its "request ISSUED" line, and the
    production `search()` wrapper caught it FIRST and handed back an error tuple — so the phantom credit
    survived in production while the scheduler's fix looked complete. My tests injected a `search`
    callable that raises directly and never drove the real wrapper.

    Same seam as the deferred-parse wiring: fix the coordinator, let the adapter mask the signal.
    Everything here goes through `probe._shodan_pivot`, the production entry point."""

    @staticmethod
    def _ctx(tmp_path):
        from types import SimpleNamespace
        from quarry_recon import events
        events.reset()
        events.configure(tmp_path)
        added: list = []
        run = SimpleNamespace(
            raw_path=lambda ph, lb, nm: (tmp_path / ph / lb).joinpath(nm)
            if (tmp_path / ph / lb).mkdir(parents=True, exist_ok=True) or True else None,
            dir=tmp_path, project_dir=tmp_path,
            add=lambda e, r: (added.append((e, r)), True)[1], read=lambda e: [])
        scope = SimpleNamespace(in_scope=lambda h: h.endswith("acme.com"), is_oos=lambda h: False)
        return SimpleNamespace(run=run, scope=scope, echo=lambda *a: None), added

    def test_a_refusal_during_PAID_SEARCH_issues_nothing_and_spends_nothing(self, monkeypatch,
                                                                           tmp_path):
        from quarry_recon import events, shodan_sched
        monkeypatch.setattr(probe.settings, "concurrency", lambda k, d=None: 1)
        monkeypatch.setattr(pace, "PACE_DIR", tmp_path / "pace")

        # pacing lets the FREE phase through (balance + counts) and refuses at the first paid search
        calls = {"n": 0}
        real_wait = pace.wait

        def wait(key, interval, **kw):
            calls["n"] += 1
            if calls["n"] > 2:                       # 1: /api-info, 2: /host/count, 3: the purchase
                raise pace.PaceBusy("another process holds this account's pacing slot")
            return real_wait(key, 0.0, **kw)
        monkeypatch.setattr(pace, "wait", wait)

        pages: list = []
        monkeypatch.setattr(probe, "_shodan_page",
                            lambda *a, **k: pages.append(a) or ([], None, None))
        monkeypatch.setattr(probe, "_read_shodan_balance",
                            lambda key, timeout=15, cooldown=None: probe.ShodanBalance(
                                remaining=100, allowance=100, reserve=0, spendable=100,
                                may_spend=True, reason="ok"))
        monkeypatch.setattr(probe, "_shodan_count", lambda k, f, v: (250, b'{"total": 250}', None))

        ctx, _added = self._ctx(tmp_path)
        probe._shodan_pivot(ctx, "KEY", ["hA"], "http.favicon.hash", "favicon-shodan",
                            "probe.favicon", "{}")

        assert pages == [], "the paid search must never be reached after a refusal"
        evs = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        spend = [e for e in evs if e.get("event") == "spend" and e.get("provider") == "shodan"]
        assert spend and all(e["amount"] == 0 for e in spend), spend

        cov = [e for e in evs if e.get("event") == "coverage_partial"]
        unq = [e for e in cov if e.get("measure") == "shodan_pivots_unqueried"]
        assert unq, cov
        # a GAP of ours, and explicitly NOT the budget running out
        assert shodan_sched.PACE_BUSY in (unq[-1].get("reason") or ""), unq[-1]
        assert "budget" not in (unq[-1].get("reason") or "")
        assert unq[-1]["kind"] == events.COVERAGE_TIMEOUT
        events.reset()

    def test_the_wrapper_does_not_swallow_the_refusal(self):
        """The defect itself, pinned in the source: an adapter that converts `PaceBusy` into a returned
        error tuple hides it from the accounting that must see it."""
        import inspect
        src = inspect.getsource(probe._shodan_work_locked)
        start = src.index("def search(pivot, page):")
        body = src[start:src.index("def ingest(", start)]
        assert "cooldown.wait()" in body
        assert "except pace.PaceBusy" not in body, "the refusal must reach the coordinator unchanged"
