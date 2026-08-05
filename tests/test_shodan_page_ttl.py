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


class TestLostEvidenceIsNotASpendingPermission:
    """`Ledger` drops an unverifiable completion silently ("unverifiable -> redo", `budget.py`). Redo is
    free for an unpaid lane and a CHARGE here.

    review#1 (Lumpy): counting the charge afterwards does not authorise it. A lost page is refused on the
    same terms as an AGED one — the loss is admitted, the page is never scheduled again, and repair waits
    for an explicit operator policy. An earlier version of this class asserted the opposite (it pinned
    the automatic repurchase as correct), which is why the tests below assert `search` is never called."""

    @staticmethod
    def _buy(tmp_path, *, values=("1",), pages=1, issued=None):
        """Drive the REAL purchase path against a real Ledger, and return (ledger, outcome).

        `issued` collects every page the lane actually ASKED the provider for — the only evidence that
        distinguishes "refused" from "reported"."""
        import json as _json
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        base.mkdir(parents=True, exist_ok=True)
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        states = [PivotState(pivot=Pivot(FAV, "http.favicon.hash", v)) for v in values]
        res = S.WorkResult()
        res.lanes.setdefault(FAV, S.LaneOutcome(lane=FAV))
        bal = type("B", (), {"spendable": 10, "may_spend": True, "reserve": 0})()
        def _search(pivot, page):
            if issued is not None:
                issued.append((pivot.value, page))
            return ([{"ip_str": "203.0.113.1"}], pages, None)
        S._work(states, res, balance=bal, search=_search,
                ingest=lambda *a: 0, ledger=led, attempt_dir=base / "pages",
                max_pages=pages, is_limit=lambda cls: False)
        del _json
        return led, res.lanes[FAV]

    def test_a_first_purchase_is_not_a_loss(self, tmp_path):
        _led, o = self._buy(tmp_path)
        assert o.pages_bought == 1 and o.pages_lost == 0 and o.repair_refused == 0

    def test_an_altered_artifact_is_admitted_as_lost_and_NOT_re_bought(self, tmp_path):
        import json as _json
        led, first = self._buy(tmp_path)
        assert first.pages_bought == 1
        art = next(iter(dict(led.items()).values()))
        doc = _json.loads(art.read_text())
        doc["matches"] = []                                  # same identity, different bytes
        art.write_text(_json.dumps(doc))
        issued = []
        _led2, o = self._buy(tmp_path, issued=issued)
        assert issued == [], "no request may be issued to repair evidence this run cannot authorise"
        assert o.pages_bought == 0
        assert o.pages_lost == 1 and o.repair_refused == 1

    def test_a_vanished_artifact_is_admitted_as_lost_and_NOT_re_bought(self, tmp_path):
        led, _first = self._buy(tmp_path)
        next(iter(dict(led.items()).values())).unlink()
        issued = []
        _led2, o = self._buy(tmp_path, issued=issued)
        assert issued == [] and o.pages_bought == 0
        assert o.pages_lost == 1 and o.repair_refused == 1

    def test_every_lost_page_is_refused_not_just_the_first(self, tmp_path):
        import json as _json
        led, _ = self._buy(tmp_path, values=("1", "2"))
        for art in dict(led.items()).values():
            doc = _json.loads(art.read_text()); doc["matches"] = []
            art.write_text(_json.dumps(doc))
        issued = []
        _led2, o = self._buy(tmp_path, values=("1", "2"), issued=issued)
        assert issued == [] and o.pages_bought == 0
        assert o.pages_lost == 2 and o.repair_refused == 2

    def test_a_lost_page_is_never_scheduled_again_inside_the_run(self, tmp_path):
        """Refusing without removing the page from selection would loop the scheduler over it."""
        st = PivotState(pivot=Pivot(FAV, "http.favicon.hash", "1"), total=250)
        st.lost_pages.add(1)
        assert st.next_page(max_pages=0) == 2, "a lost page is skipped, like an aged one"

    def test_a_healthy_neighbour_still_buys(self, tmp_path):
        """The refusal is per PAGE. A loss must not stop the pivot beside it from working."""
        import json as _json
        led, _ = self._buy(tmp_path, values=("1", "2"))
        art = dict(led.items())[S.item_key(Pivot(FAV, "http.favicon.hash", "1"), 1)]
        doc = _json.loads(art.read_text()); doc["matches"] = []
        art.write_text(_json.dumps(doc))
        art.with_name(art.name)                              # only pivot "1" is damaged
        (led.path.parent / "pages").mkdir(exist_ok=True)
        issued = []
        _led2, o = self._buy(tmp_path, values=("1", "2"), issued=issued)
        assert o.pages_lost == 1 and o.repair_refused == 1
        assert issued == [], "pivot 2 still OWNS its page, so it replays rather than buying"
        assert o.pages_replayed == 1

    def test_the_ledger_records_which_items_it_could_not_verify(self, tmp_path):
        import json as _json
        from quarry_recon import budget
        led, _ = self._buy(tmp_path)
        item, art = next(iter(led.items()))
        doc = _json.loads(art.read_text()); doc["total"] = 999
        art.write_text(_json.dumps(doc))
        reopened = budget.Ledger(led.path, lane="probe.shodan")
        assert item in reopened.lost, "a dropped completion must leave a trace, not vanish"
        assert not reopened.has(item), "…and it must still fail CLOSED, i.e. be redone"

    def test_a_clean_store_loses_nothing(self, tmp_path):
        from quarry_recon import budget
        led, _ = self._buy(tmp_path)
        reopened = budget.Ledger(led.path, lane="probe.shodan")
        assert reopened.lost == {}, "an intact store must never accuse itself of a loss"

    def test_a_completion_filed_without_a_digest_counts_as_lost_too(self, tmp_path):
        """The other unverifiable shape: `done` names an artifact the snapshot never hashed. It is redone
        for the same reason, so it is the same kind of spend."""
        import json as _json
        from quarry_recon import budget
        led, _ = self._buy(tmp_path)
        led.save()                                           # the snapshot, not just the journal
        snap = _json.loads(led.path.read_text())
        snap["digests"] = {}                                 # recorded as done, never hashed
        led.path.write_text(_json.dumps(snap))
        led.journal.unlink(missing_ok=True)                  # replay would re-add the digest
        reopened = budget.Ledger(led.path, lane="probe.shodan")
        assert list(reopened.lost) == list(snap["done"]) and not reopened.done


class TestAnUnreadableOwnershipStoreIsNotAnEmptyOne:
    """review#1 (Lumpy): `_read_snapshot()` returned `{}, {}` for a file that could not be parsed, was
    the wrong shape, or was unreadable — indistinguishable from "no store yet". A PAID lane then saw a
    clean slate and could buy every page again. `Ledger.lost` only ever covered item-level artifact
    failures; this is the same laundering route one level up."""

    @staticmethod
    def _seed(tmp_path):
        return TestLostEvidenceIsNotASpendingPermission._buy(tmp_path)

    @pytest.mark.parametrize("corrupt,why", [
        (lambda p: p.write_text("{not json"), "not valid JSON"),
        (lambda p: p.write_text("[]"), "root is a list"),
        (lambda p: p.write_text('{"lane": "probe.shodan", "done": "nope", "digests": {}}'),
         "done is not an index"),
        (lambda p: p.write_text('{"lane": "probe.shodan", "done": {}, "digests": 7}'),
         "digests is not an index"),
    ])
    def test_a_corrupt_state_file_is_reported_not_treated_as_empty(self, tmp_path, corrupt, why):
        from quarry_recon import budget
        led, _ = self._seed(tmp_path)
        led.save()
        led.journal.unlink(missing_ok=True)
        corrupt(led.path)
        reopened = budget.Ledger(led.path, lane="probe.shodan")
        assert reopened.unreadable, f"{why}: an existing store that cannot be read must say so"
        assert not reopened.done

    def test_a_store_that_was_never_written_is_simply_absent(self, tmp_path):
        from quarry_recon import budget
        led = budget.Ledger(tmp_path / "never-written.json", lane="probe.shodan")
        assert led.unreadable == "", "absent is not corrupt; a first run must not be blocked"

    def test_a_clean_store_is_not_accused(self, tmp_path):
        from quarry_recon import budget
        led, _ = self._seed(tmp_path)
        led.save()
        assert budget.Ledger(led.path, lane="probe.shodan").unreadable == ""

    def test_a_torn_journal_TAIL_is_not_corruption(self, tmp_path):
        """A crash mid-append is expected and costs nothing: the record was never complete."""
        from quarry_recon import budget
        led, _ = self._seed(tmp_path)
        with led.journal.open("a") as fh:
            fh.write('{"v": 1, "l": "probe.shodan", "i": "x"')      # no terminator
        assert budget.Ledger(led.path, lane="probe.shodan").unreadable == ""

    def test_a_garbled_journal_record_BEFORE_the_end_is_corruption(self, tmp_path):
        """Intact records behind a bad one mean a completion was destroyed, not merely half-written."""
        from quarry_recon import budget
        led, _ = self._seed(tmp_path)
        lines = led.journal.read_text().splitlines()
        led.journal.write_text("\n".join(["{garbled", *lines]) + "\n")
        assert budget.Ledger(led.path, lane="probe.shodan").unreadable

    def test_the_paid_lane_BUYS_NOTHING_against_an_untrusted_store(self, tmp_path):
        """The whole point: refusal happens before the provider call, not in the report afterwards."""
        from quarry_recon import budget
        led, first = self._seed(tmp_path)
        assert first.pages_bought == 1
        led.save()
        led.journal.unlink(missing_ok=True)
        led.path.write_text("{ this is not a ledger")
        issued = []
        _led2, o = TestLostEvidenceIsNotASpendingPermission._buy(tmp_path, issued=issued)
        assert issued == [], "a corrupt index must never authorise a purchase"
        assert o.pages_bought == 0

    def test_the_refusal_names_itself_in_the_run(self, tmp_path):
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        base.mkdir(parents=True, exist_ok=True)
        path = budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}")
        path.write_text("{ nope")
        led = budget.Ledger(path, lane="probe.shodan")
        st = PivotState(pivot=Pivot(FAV, "http.favicon.hash", "1"))
        res = S.WorkResult()
        res.lanes.setdefault(FAV, S.LaneOutcome(lane=FAV))
        bal = type("B", (), {"spendable": 10, "may_spend": True, "reserve": 0})()
        S._work([st], res, balance=bal,
                search=lambda pivot, page: pytest.fail("a purchase was attempted"),
                ingest=lambda *a: 0, ledger=led, attempt_dir=base / "pages",
                max_pages=1, is_limit=lambda cls: False)
        assert res.stop_cause.startswith("ownership_unreadable:")


class TestAnUntrustedStoreIsREADONLY:
    """review#1 (Lumpy): both lanes refused to BUY against an unreadable store and then called
    `ledger.save()` in their `finally`, which compacted this run's empty maps over the corrupt snapshot.
    The next run opened a healthy, empty ownership index and could buy everything — the original
    repurchase route one lifecycle later, with the evidence that should have blocked it destroyed on the
    way. A refusal that the next write launders is not a refusal."""

    @staticmethod
    def _corrupt(tmp_path, *, kind="snapshot"):
        """A store with one page really bought, then damaged. Returns (ledger_path, bytes-before)."""
        from quarry_recon import budget
        led, o = TestLostEvidenceIsNotASpendingPermission._buy(tmp_path)
        assert o.pages_bought == 1
        led.save()
        if kind == "snapshot":
            led.journal.unlink(missing_ok=True)
            led.path.write_text('{"lane": "probe.shodan", "done": "not an index", "digests": {}}')
            target = led.path
        else:                                            # a garbled record BEFORE the end of the journal
            lines = led.journal.read_text().splitlines() if led.journal.exists() else []
            led.journal.write_text("\n".join(["{garbled", *lines]) + "\n")
            target = led.journal
        return led.path, target, target.read_bytes()

    @pytest.mark.parametrize("kind", ["snapshot", "journal"])
    def test_a_refused_run_leaves_the_STORE_BYTE_IDENTICAL(self, tmp_path, kind):
        from quarry_recon import budget
        path, target, before = self._corrupt(tmp_path, kind=kind)
        led = budget.Ledger(path, lane="probe.shodan")
        assert led.unreadable
        assert led.save() is False, "compaction would overwrite the corrupt state with an empty one"
        assert led.checkpoint() is False and led.record.__name__ == "record"
        assert target.read_bytes() == before, "an untrusted store must not be modified at all"

    @pytest.mark.parametrize("kind", ["snapshot", "journal"])
    def test_the_refusal_SURVIVES_a_second_lifecycle(self, tmp_path, kind):
        """The end-to-end shape: refuse, change nothing, and still refuse when reopened."""
        from quarry_recon import budget
        path, target, before = self._corrupt(tmp_path, kind=kind)
        for cycle in (1, 2):
            issued = []
            _led, o = TestLostEvidenceIsNotASpendingPermission._buy(tmp_path, issued=issued)
            assert issued == [], f"cycle {cycle}: a corrupt store authorised a purchase"
            assert o.pages_bought == 0
            assert budget.Ledger(path, lane="probe.shodan").unreadable, \
                f"cycle {cycle}: the store healed itself instead of staying refused"
            assert target.read_bytes() == before, f"cycle {cycle}: the store was rewritten"

    def test_a_garbled_journal_record_is_NOT_repaired_away(self, tmp_path):
        """review#2: the repair path rewrote the journal from `kept`, deleting the damaged record — the
        one piece of evidence that proved the history is incomplete."""
        from quarry_recon import budget
        path, journal, before = self._corrupt(tmp_path, kind="journal")
        led = budget.Ledger(path, lane="probe.shodan")
        assert led.unreadable and journal.read_bytes() == before
        assert b"{garbled" in journal.read_bytes()

    def test_a_torn_TAIL_is_still_repaired(self, tmp_path):
        """The benign case keeps its automatic repair: a crash mid-append destroyed nothing."""
        from quarry_recon import budget
        led, _ = TestLostEvidenceIsNotASpendingPermission._buy(tmp_path)
        with led.journal.open("a") as fh:
            fh.write('{"v": 1, "l": "probe.shodan", "i": "half-written"')
        reopened = budget.Ledger(led.path, lane="probe.shodan")
        assert reopened.unreadable == ""
        assert reopened.journal.read_text().endswith("\n"), "the intact prefix is restored"
        assert reopened.save() is True

    def test_an_unreadable_PATH_is_not_read_as_absent(self, tmp_path):
        """review#3: `Path.exists()` returns False for a path we may not inspect, so using it as the
        discriminator cleared `unreadable` on exactly the permission failure it exists to catch."""
        import os
        from quarry_recon import budget
        led, _ = TestLostEvidenceIsNotASpendingPermission._buy(tmp_path)
        led.save()
        led.journal.unlink(missing_ok=True)
        d = led.path.parent
        mode = d.stat().st_mode
        os.chmod(d, 0o000)
        try:
            if os.access(led.path, os.R_OK):
                pytest.skip("running as root: an unreadable path cannot be simulated")
            reopened = budget.Ledger(led.path, lane="probe.shodan")
            assert reopened.unreadable, "a path we cannot inspect is UNKNOWN, never empty"
            assert reopened.save() is False
        finally:
            os.chmod(d, mode)


class TestAPaidResponseWeRefuseIsStillEvidence:
    """Measured 2026-08-05: Shodan billed two credits, one page was accepted and the other was rejected
    as `parse`. The run kept the accepted page and, for the rejected one, a single counter reading
    `{'parse': 1}` — no bytes, no objection, no artifact. Provider drift and a wrong contract of ours were
    equally unprovable, and only one of those two is something we can fix."""

    @staticmethod
    def _run(tmp_path, *, matches, total, err=None):
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        base.mkdir(parents=True, exist_ok=True)
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        st = PivotState(pivot=Pivot(FAV, "http.favicon.hash", "1"))
        res = S.WorkResult()
        res.lanes.setdefault(FAV, S.LaneOutcome(lane=FAV))
        bal = type("B", (), {"spendable": 5, "may_spend": True, "reserve": 0})()
        attempt = base / "pages" / "a0"
        attempt.mkdir(parents=True, exist_ok=True)
        S._work([st], res, balance=bal, search=lambda pivot, page: (matches, total, err),
                ingest=lambda *a: 0, ledger=led, attempt_dir=attempt,
                max_pages=1, is_limit=lambda cls: False)
        return res.lanes[FAV], attempt

    def test_the_objection_is_NAMED_not_just_classified(self, tmp_path):
        o, _ = self._run(tmp_path, matches=[{"hostnames": [None]}], total=5)
        assert o.fail_classes.get("parse") == 1
        assert o.pages_rejected == 1
        assert o.reject_reasons and "hostname" in o.reject_reasons[0], o.reject_reasons

    @pytest.mark.parametrize("matches,total,want", [
        ([], "many", "total"),
        ("not a list", 5, "matches is str"),
        ([42], 5, "match row 0"),
        ([{"hostnames": "a.example"}], 5, "hostnames is str"),
        ([{"hostnames": ["ok.example", 7]}], 5, "int hostname"),
    ])
    def test_every_rejection_says_which_check_failed(self, matches, total, want):
        why = S.reject_reason(matches, total)
        assert why and want in why, why

    def test_a_valid_page_has_no_objection(self):
        assert S.reject_reason([{"ip_str": "203.0.113.1", "hostnames": ["a.example"]}], 5) is None
        assert S.valid_fresh([{"hostnames": ["a.example"]}], 5) is True

    def test_the_BYTES_are_kept_outside_the_ledger(self, tmp_path):
        import json as _json
        o, attempt = self._run(tmp_path, matches=[{"hostnames": [None]}], total=5)
        arts = list((attempt / "rejected").glob("*.rejected.json"))
        assert len(arts) == 1, "a paid response must survive our refusal of it"
        doc = _json.loads(arts[0].read_text())
        assert doc["owned"] is False and doc["page"] == 1 and doc["value"] == "1"
        assert "hostname" in doc["reason"]
        assert doc["payload"]["total"] == 5, "what we were handed is inspectable"
        assert o.pages_bought == 0

    def test_a_provider_ERROR_body_is_kept_without_claiming_WE_rejected_it(self, tmp_path):
        """An auth or quota refusal is the provider's decision, already counted by its class. Keep the
        bytes — that is how a Cloudflare interstitial stays inspectable — but do not call it ours."""
        import json as _json
        err = RuntimeError("HTTP Error 401: Unauthorized")
        err.error_class = "quota"
        err.body_bytes = b'{"error": "Zero Account Balance"}'
        o, attempt = self._run(tmp_path, matches=[], total=None, err=err)
        assert o.pages_rejected == 0 and not o.reject_reasons
        arts = list((attempt / "rejected").glob("*.rejected.json"))
        assert len(arts) == 1
        doc = _json.loads(arts[0].read_text())
        import base64
        assert base64.b64decode(doc["body_b64"]) == err.body_bytes, "the EXACT bytes, not our reading"

    def test_the_rejection_reaches_telemetry_on_its_own_measure(self, tmp_path):
        import json as _json
        from quarry_recon import events
        events.reset(); events.configure(tmp_path)
        o, _ = self._run(tmp_path, matches=[{"hostnames": [None]}], total=5)
        S.report(FAV, o, balance=type("B", (), {"reason": "ok", "stop_kind": ""})(), max_pages=1)
        evs = [_json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        rej = [e for e in evs if e.get("measure") == "shodan_pages_rejected"]
        assert rej and rej[-1]["omitted"] == 1
        assert "hostname" in rej[-1]["reason"]
        # the POSITION measures stay clean: a page's shape is not a pivot's position
        pos = [e for e in evs if e.get("measure") == "shodan_pivots"]
        assert pos and "hostname" not in (pos[-1]["reason"] or "")
        events.reset()
