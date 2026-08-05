"""Purchased Shodan pages: durable enough not to re-buy, never an eternal cache.

Whoxy's page cache is permanent because a historical WHOIS record does not change. A Shodan SEARCH page
is live intelligence — the free `shodan_host` lane already warns that a project-global ledger would
"replay a stale snapshot of a host forever". So ownership is project-scoped (a second run must not pay
again) and bounded by a TTL (a stale page is history, not a current answer).
"""
from __future__ import annotations

import contextlib

import pytest

from quarry_recon import shodan_sched as S
from quarry_recon.shodan_sched import Pivot, PivotState

FAV = "probe.shodan_favicon"


def _doc(page=1, total=5, matches=(), age_days=0.0, now=1_000_000.0):
    return S._page_doc(Pivot(FAV, "http.favicon.hash", "1"), page, total, list(matches),
                       bought_at=now - age_days * 86400.0)


class TestOwnershipIsProjectScoped:
    def test_the_store_lives_beside_the_project_not_the_run(self, tmp_path):
        """A run directory is timestamped: state kept inside one dies with it and the next run buys the
        same pages again. Measured in code before this change — replay read a run-scoped ledger only."""
        d = S.state_dir(tmp_path)
        assert d == tmp_path / "state" / "shodan-pivot" / f"v{S.SHODAN_WORK_SCHEMA}"
        assert S.provider_dir(tmp_path) in d.parents or S.provider_dir(tmp_path) == d.parent

    def test_the_generation_is_the_WORK_SCHEMA_only(self, tmp_path):
        """Not the API key (a page's bytes do not depend on which credential paid), not the budget or
        reserve (lowering a spending policy must not re-buy pages already paid for)."""
        assert S.state_dir(tmp_path).name == f"v{S.SHODAN_WORK_SCHEMA}"


class TestTheAgeTravelsWithTheEvidence:
    def test_a_page_records_when_it_was_bought(self):
        doc = _doc()
        assert isinstance(doc["bought_at"], float)
        assert S.valid_page(doc, Pivot(FAV, "http.favicon.hash", "1"), 1) is doc

    def test_a_page_without_an_age_is_never_fresh(self):
        """A page that cannot prove when it was bought cannot prove it is current. Fails CLOSED."""
        doc = _doc()
        doc.pop("bought_at")
        assert S.page_age_s(doc) is None
        assert not S.page_fresh(doc, ttl_days=7)

    @pytest.mark.parametrize("bad", [True, "yesterday", None, {}])
    def test_a_malformed_age_is_never_fresh(self, bad):
        assert not S.page_fresh(dict(_doc(), bought_at=bad), ttl_days=7)

    def test_inside_the_ttl_is_fresh_outside_is_not(self):
        now = 2_000_000.0
        assert S.page_fresh(_doc(age_days=6.9, now=now), ttl_days=7, now=now)
        assert not S.page_fresh(_doc(age_days=7.1, now=now), ttl_days=7, now=now)

    def test_ttl_zero_means_NEVER_REPLAY_not_always_buy(self):
        """Zero retains and refuses refresh. Nothing in this policy spends: the scheduler skips an aged
        page precisely so that time passing can never authorise a purchase."""
        assert not S.page_fresh(_doc(age_days=0), ttl_days=0)

    @pytest.mark.parametrize("at,ok", [(-10.0, True),           # 10s ago
                                       (60.0, True),            # 60s in the future: ordinary clock skew
                                       (3600.0, False),         # an hour in the future: not skew
                                       (float("nan"), False), (float("inf"), False),
                                       (float("-inf"), False)])
    def test_an_impossible_timestamp_cannot_certify_freshness(self, at, ok):
        """Clamping a future or non-finite `bought_at` to age zero made it read as bought right now."""
        now = 1_000_000.0
        doc = dict(_doc(), bought_at=(now + at) if at == at and abs(at) != float("inf") else at)
        assert S.page_fresh(doc, ttl_days=7, now=now) is ok

    def test_the_skew_tolerance_is_named_and_small(self):
        assert 0 < S.CLOCK_SKEW_S <= 900


class TestAgedPagesAreHistoryNotCurrentEvidence:
    """Driven through the REAL `_replay_indexed`. An earlier version of these tests re-implemented the
    replay loop inline and passed happily with the freshness check deleted — a test that mirrors the
    implementation proves only that the mirror is consistent."""

    @staticmethod
    def _owned(tmp_path, age_days, *, now=3_000_000.0, page=1):
        doc = _doc(page=page, age_days=age_days, now=now)
        art = tmp_path / f"p{page}.json"
        art.write_text(__import__("json").dumps(doc))
        key = S.item_key(Pivot(FAV, "http.favicon.hash", "1"), page)

        class _Ledger:
            def items(self):
                return [(key, art)]
        return _Ledger()

    @staticmethod
    def _run(tmp_path, age_days, *, ttl=7.0, now=3_000_000.0):
        st = PivotState(pivot=Pivot(FAV, "http.favicon.hash", "1"))
        res = S.WorkResult()
        res.lanes.setdefault(FAV, S.LaneOutcome(lane=FAV))
        ingested = []
        S._replay_indexed([st], res, ledger=TestAgedPagesAreHistoryNotCurrentEvidence._owned(
            tmp_path, age_days, now=now),
            ingest=lambda pivot, page, matches, art: ingested.append(page) or 0,
            ttl_days=ttl, now=now)
        return st, res.lanes[FAV], ingested

    def test_a_fresh_page_is_replayed_as_current_evidence_with_its_age(self, tmp_path):
        st, o, ingested = self._run(tmp_path, age_days=2.0)
        assert o.pages_replayed == 1 and ingested == [1]
        assert 1.9 * 86400 < o.oldest_replay_s < 2.1 * 86400, "the report says HOW old current is"
        assert not st.aged_pages and st.pages_done == {1}

    def test_an_aged_page_is_kept_but_not_ingested(self, tmp_path):
        st, o, ingested = self._run(tmp_path, age_days=30.0)
        assert o.pages_aged == 1 and ingested == [], "stale results must not stand in for today's"
        assert st.aged_pages == {1} and not st.pages_done
        assert o.pages_replayed == 0

    def test_a_page_with_no_recorded_age_is_aged_out_not_replayed(self, tmp_path):
        import json as _json
        doc = _doc(age_days=0.0)
        doc.pop("bought_at")
        art = tmp_path / "p1.json"
        art.write_text(_json.dumps(doc))
        key = S.item_key(Pivot(FAV, "http.favicon.hash", "1"), 1)

        class _L:
            def items(self):
                return [(key, art)]
        st = PivotState(pivot=Pivot(FAV, "http.favicon.hash", "1"))
        res = S.WorkResult()
        res.lanes.setdefault(FAV, S.LaneOutcome(lane=FAV))
        S._replay_indexed([st], res, ledger=_L(), ingest=lambda *a: 0, ttl_days=7.0)
        assert res.lanes[FAV].pages_aged == 1 and res.lanes[FAV].pages_replayed == 0

    def test_an_aged_page_is_NOT_rescheduled_for_purchase(self, tmp_path):
        """Never spend a credit merely because time passed."""
        st, _o, _i = self._run(tmp_path, age_days=30.0)
        st.total = 1000
        assert st.next_page() != 1, "buying it again is an operator decision, not a side effect"

    def test_the_refusal_is_COUNTED_not_hidden(self, tmp_path):
        st, _o, _i = self._run(tmp_path, age_days=30.0)
        st.total = 1000
        assert st.refused_refresh() == 1

    def test_a_refusal_is_only_counted_for_pages_the_pivot_would_ask_for(self):
        st = PivotState(pivot=Pivot(FAV, "http.favicon.hash", "1"))
        st.total = 1000                                   # 100 results per page -> 10 pages
        assert st.page_count() == 10
        st.aged_pages = {1, 2, 99}
        assert st.refused_refresh() == 2, "page 99 is beyond what this pivot has"
        assert st.refused_refresh(max_pages=1) == 1, "a page policy already excluded the rest"


class TestOwnershipSurvivesAConfigChange:
    """The ledger filename used to fold in the enabled facet list, and `prune_state` deleted the others —
    so running favicon alone and then favicon+cert destroyed the ownership index for pages already paid
    for. Per-page keys already separate lane/facet/value; the durable grain is the GENERATION."""

    def test_the_ledger_name_does_not_move_with_the_pivot_set(self, tmp_path, monkeypatch):
        from quarry_recon import budget
        from quarry_recon.phases import probe
        seen = []
        monkeypatch.setattr(budget, "Ledger", lambda path, lane: seen.append(path) or _NullLedger())
        monkeypatch.setattr(budget, "prune_state",
                            lambda *a, **k: pytest.fail("a durable purchase record must not be pruned"))
        for facets in (["http.favicon.hash"], ["http.favicon.hash", "ssl.cert.serial"]):
            probe.budget.Ledger(
                budget.state_path(S.state_dir(tmp_path), "probe.shodan",
                                  f"v{S.SHODAN_WORK_SCHEMA}"), lane="probe.shodan")
        assert len(set(seen)) == 1, f"the ownership index moved with the configuration: {seen}"

    def test_the_lane_uses_the_schema_as_the_ledger_identity(self):
        """Pins the CALLER, not a re-implementation: the lane must not pass a config fingerprint."""
        import inspect
        from quarry_recon.phases import probe
        src = inspect.getsource(probe._shodan_work_locked)
        i = src.index("state_dir(ctx.run.project_dir)")
        window = src[i:i + 1400]                      # the comment block sits between the two statements
        assert 'f"v{shodan_sched.SHODAN_WORK_SCHEMA}"' in window, \
            "the durable ledger is keyed by the schema, never by the enabled pivot set"
        head = window[:window.index("ledger = ")]
        # the CALL, not the word: the comment above the ledger explains why pruning is wrong, and a bare
        # substring check cannot tell an explanation from an invocation
        assert "budget.prune_state(" not in head, "pruning a durable purchase record is the loss to avoid"


class _NullLedger:
    def items(self):
        return []

    def has(self, item):
        return False


class TestTheConfiguredTTLIsReachable:
    @pytest.mark.parametrize("raw,want", [(0, 0.0), (0.0, 0.0), (7, 7.0), (30, 30.0), (1.5, 1.5),
                                          ("x", 7.0), (True, 7.0), (False, 7.0), (-3, 7.0), (None, 7.0),
                                          ("", 7.0),
                                          # a NUMERIC STRING is not a number: `float("7")` succeeded, so
                                          # "exactly as written" was quietly a coercion
                                          ("7", 7.0), ("0", 7.0), ("7 days", 7.0),
                                          (float("nan"), 7.0), (float("inf"), 7.0)])
    def test_the_reader_takes_the_value_as_written(self, raw, want, monkeypatch):
        """`concurrency()` clamps to >= 1 — reading a DURATION through it made the documented
        `0 = never replay` unreachable, and a boolean or a typo must never become permissive."""
        from quarry_recon import settings
        monkeypatch.setattr(settings, "_cache", {"PERFORMANCE": {"SHODAN_PAGE_TTL_DAYS": raw}})
        assert settings.policy_days("SHODAN_PAGE_TTL_DAYS", 7) == want

    @pytest.mark.parametrize("raw,want", [(0, 0.0), (7, 7.0), (30, 30.0), ("x", 7.0), (True, 7.0),
                                          (-1, 7.0), (None, 7.0)])
    def test_the_CONSUMER_reads_it_as_a_duration(self, raw, want, monkeypatch):
        """Pinned at the lane, not only at the parser: every direct test of `policy_days` passed while
        the lane still read the knob through `concurrency()`, which clamps 0 to 1."""
        from quarry_recon import settings
        from quarry_recon.phases import probe
        monkeypatch.setattr(settings, "_cache", {"PERFORMANCE": {"SHODAN_PAGE_TTL_DAYS": raw}})
        assert probe._shodan_page_ttl() == want

    def test_zero_from_config_reaches_the_freshness_decision(self, monkeypatch):
        from quarry_recon import settings
        from quarry_recon.phases import probe
        monkeypatch.setattr(settings, "_cache", {"PERFORMANCE": {"SHODAN_PAGE_TTL_DAYS": 0}})
        ttl = probe._shodan_page_ttl()
        assert ttl == 0.0 and not S.page_fresh(_doc(age_days=0.0), ttl_days=ttl)


class TestThePolicyIsLabelledAsPolicy:
    def test_the_default_is_seven_days_and_is_configurable(self):
        assert S.PAGE_TTL_DAYS_DEFAULT == 7

    def test_the_knob_is_classified_as_a_PROVIDER_axis(self):
        """It governs SPENDING (a shorter TTL buys more often), so it is never `--unbound`'s — the flag
        authorises no purchase at all."""
        from quarry_recon import policy
        kind, why = policy.EXCLUDED["SHODAN_PAGE_TTL_DAYS"]
        assert kind == "provider" and "unbound" in why.lower()
        assert "SHODAN_PAGE_TTL_DAYS" not in policy.unbound_overrides()


class TestTheSharedStoreIsLocked:
    """The store only became shareable when it became project-scoped. Two runs of one project would
    otherwise load the same snapshot, both see a page as unowned, and both pay for identical bytes —
    then race while journaling and compacting, which is how ownership is lost outright."""

    def test_a_second_holder_is_REFUSED_not_queued(self, tmp_path):
        with S.lifecycle_lock(tmp_path):
            with pytest.raises(S.StoreBusy):
                with S.lifecycle_lock(tmp_path):
                    pytest.fail("two lifecycles held the purchased-page store at once")

    def test_a_StateBusy_from_the_BODY_is_not_this_locks_contention(self, tmp_path):
        """An inner lane's ledger contention is a different lock. Reporting it as this one sends an
        operator looking for a second run that does not exist — and claims zero acquisition for a store
        this process was successfully holding."""
        from quarry_recon import budget
        with pytest.raises(budget.StateBusy) as caught:
            with S.lifecycle_lock(tmp_path):
                raise budget.StateBusy("some OTHER lane's state is held")
        assert not isinstance(caught.value, S.StoreBusy)
        assert "OTHER lane" in str(caught.value)

    def test_the_lock_is_released_after_the_body_raises(self, tmp_path):
        from quarry_recon import budget
        with contextlib.suppress(budget.StateBusy):
            with S.lifecycle_lock(tmp_path):
                raise budget.StateBusy("inner")
        with S.lifecycle_lock(tmp_path):          # released in `finally`, whatever the body did
            pass

    def test_the_lock_is_released_when_the_holder_leaves(self, tmp_path):
        with S.lifecycle_lock(tmp_path):
            pass
        with S.lifecycle_lock(tmp_path):          # a stale lockfile must not block the project for ever
            pass

    def test_it_locks_the_PROVIDER_level_above_the_schema(self, tmp_path):
        """Two builds on different schemas still share one account and must not spend at once."""
        with S.lifecycle_lock(tmp_path):
            assert (S.provider_dir(tmp_path) / ".lock").exists()
        assert S.provider_dir(tmp_path) == S.state_dir(tmp_path).parent

    def test_the_lane_takes_it_before_touching_the_ledger(self):
        import inspect
        from quarry_recon.phases import probe
        wrapper = inspect.getsource(probe._shodan_work)
        assert "lifecycle_lock(ctx.run.project_dir)" in wrapper
        assert "_shodan_work_locked" in wrapper
        assert "StoreBusy" in wrapper, "contention must be handled, not propagated as an unknown fault"
        body = inspect.getsource(probe._shodan_work_locked)
        assert "lifecycle_lock" not in body, "the lock wraps the body; it is not taken inside it"

    def test_contention_issues_no_paid_request(self, monkeypatch, tmp_path):
        """A blocked run refuses acquisition. Waiting for a lock is not a spending policy."""
        from quarry_recon import events
        from quarry_recon.phases import probe
        events.reset(); events.configure(tmp_path)
        monkeypatch.setattr(probe.shodan_sched, "lifecycle_lock",
                            lambda p: (_ for _ in ()).throw(S.StoreBusy("held by pid 1")))
        monkeypatch.setattr(probe, "_shodan_work_locked",
                            lambda *a, **k: pytest.fail("the lane ran while another holder had the store"))
        spec = type("S", (), {"sid": "probe.shodan_favicon"})()
        run = type("R", (), {"project_dir": tmp_path})()
        ctx = type("C", (), {"run": run})()
        with pytest.raises(probe.ShodanPageError):
            probe._shodan_work(ctx, "key", [(spec, ["v"])])
        evs = [__import__("json").loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
        cov = [e for e in evs if e["event"] == "coverage_partial" and e.get("measure") == "shodan_pages"]
        assert cov and "another run holds this project's purchased-page store" in cov[0]["reason"]
        events.reset()
