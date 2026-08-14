"""Purchased Shodan pages: durable enough not to re-buy, never an eternal cache.

Whoxy's page cache is permanent because a historical WHOIS record does not change. A Shodan SEARCH page
is live intelligence — the free `shodan_host` lane already warns that a project-global ledger would
"replay a stale snapshot of a host forever". So ownership is project-scoped (a second run must not pay
again) and bounded by a TTL (a stale page is history, not a current answer).
"""
from __future__ import annotations

import contextlib
from pathlib import Path

import pytest

pytestmark = pytest.mark.offline

from quarry_recon import shodan_sched as S
from quarry_recon.shodan_sched import Pivot, PivotState

FAV = "probe.shodan_favicon"


def _json_load(path):
    import json
    return json.loads(Path(path).read_text())


def _json_dump(path, doc):
    import json
    Path(path).write_text(json.dumps(doc))


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
        art = next(a for i, a in led.items() if not i.startswith(S.ACQ_PREFIX))
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
        next(a for i, a in led.items() if not i.startswith(S.ACQ_PREFIX)).unlink()
        issued = []
        _led2, o = self._buy(tmp_path, issued=issued)
        assert issued == [] and o.pages_bought == 0
        assert o.pages_lost == 1 and o.repair_refused == 1

    def test_every_lost_page_is_refused_not_just_the_first(self, tmp_path):
        import json as _json
        led, _ = self._buy(tmp_path, values=("1", "2"))
        # PAGE documents only: the ledger also holds acquisition receipts, and damaging those is a
        # different scenario (an orphaned purchase, pinned separately).
        for item, art in led.items():
            if item.startswith(S.ACQ_PREFIX):
                continue
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


class TestWePayForBytesSoWeKeepThem:
    """Lumpy, 2026-08-05, after a 4 MiB cap truncated two paid pages and a 64 MiB one replaced it:

        "if we are already paying, i want to get EVERYTHING i pay for … Stream provider responses to
        disk … Preserve the complete raw response atomically … Bound memory and execution time, not
        evidence membership or response bytes."

    A cap on a bought response is not a safety guard: the credit is gone before it can help, so it only
    converts money into incomplete evidence and invites a second purchase."""

    def test_a_rejected_page_POINTS_at_the_whole_response(self, tmp_path):
        import json as _json
        pivot = Pivot(FAV, "http.favicon.hash", "1")
        raw = tmp_path / "raw" / f"{S.item_key(pivot, 1)}.json"
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_bytes(b'{"total": 1, "matches": [{"hostnames": [null]}]}')
        art = S.publish_rejected(tmp_path, pivot, 1, reason="parse: bad row", raw_path=raw)
        doc = _json.loads(art.read_text())
        assert doc["raw_ref"] == str(raw) and doc["raw_bytes"] == raw.stat().st_size
        assert doc["raw_digest"], "the pointer is digest-bound"
        assert "body_b64" not in doc, "a truncated second copy would be the worse artifact"

    def test_it_still_keeps_bytes_when_there_is_no_artifact(self, tmp_path):
        import base64, json as _json
        pivot = Pivot(FAV, "http.favicon.hash", "1")
        art = S.publish_rejected(tmp_path, pivot, 1, reason="quota", body=b'{"error": "no balance"}')
        doc = _json.loads(art.read_text())
        assert base64.b64decode(doc["body_b64"]) == b'{"error": "no balance"}'

    def test_the_page_doc_NAMES_the_raw_response(self, tmp_path):
        """Ownership and the provider's exact bytes are bound by the same digest."""
        doc = S._page_doc(Pivot(FAV, "http.favicon.hash", "1"), 1, 5, [],
                          raw={"raw_ref": "abc.json", "raw_bytes": 123, "raw_digest": "d" * 64})
        assert doc["raw_ref"] == "abc.json" and doc["raw_bytes"] == 123
        assert S.valid_page(doc, Pivot(FAV, "http.favicon.hash", "1"), 1) is not None, \
            "the extra fields must not make a valid page unreadable"


class TestAcquisitionIsCommittedBeforeInterpretation:
    """review#1 (Lumpy, 2026-08-05, P0): "bytes landing on disk is not ownership".

    A response we paid for and could not parse was published as a rejection and never RECORDED, so the
    next run saw the page as unowned and bought it again — the double spend this store exists to prevent,
    reintroduced by the streaming repair itself. Acquisition is now committed independently of parse
    success, in three states:

        complete_parsed     the page is ours and readable
        complete_unparsed   the whole response is ours; this box would not parse it. Parsed later FROM
                            THE ARTIFACT, never re-bought.
        incomplete_paid     the body did not arrive whole. Automatic retry refused.
    """

    @staticmethod
    def _lane(tmp_path, *, response, parse=None, parse_ok=True, err=None):
        """One paid lifecycle over one pivot, through the REAL scheduler."""
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        attempt = base / "pages" / "a0"
        (attempt / "raw").mkdir(parents=True, exist_ok=True)
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        pivot = Pivot(FAV, "http.favicon.hash", "1")
        st = PivotState(pivot=pivot)
        res = S.WorkResult()
        res.lanes.setdefault(FAV, S.LaneOutcome(lane=FAV))
        issued = []

        def search(pv, page):
            issued.append(page)
            raw = attempt / "raw" / f"{S.item_key(pv, page)}.json"
            raw.write_bytes(response)
            if err is not None:
                e = RuntimeError(err[1])
                e.error_class = err[0]
                e.raw_path = raw
                return ([], None, e)
            return ([{"ip_str": "203.0.113.1", "hostnames": ["a.example"]}], 3, None)

        ingested = []
        S._work([st], res, balance=type("B", (), {"spendable": 5, "may_spend": True, "reserve": 0})(),
                search=search, ingest=lambda pv, pg, ms, art: ingested.append(pg) or len(ms),
                ledger=led, attempt_dir=attempt, max_pages=1, is_limit=lambda cls: False,
                parse=parse)
        led.save()
        return {"outcome": res.lanes[FAV], "issued": issued, "ingested": ingested, "ledger": led,
                "attempt": attempt, "pivot": pivot, "base": base}

    @staticmethod
    def _fresh_ledger(run):
        from quarry_recon import budget
        return budget.Ledger(run["ledger"].path, lane="probe.shodan")

    def test_an_UNPARSED_purchase_is_owned_and_never_re_bought(self, tmp_path):
        """buy once -> parse deferred -> fresh run -> ZERO provider calls -> bytes still addressable."""
        body = b'{"total": 3, "matches": [{"hostnames": ["a.example"]}]}'
        first = self._lane(tmp_path, response=body, err=("oversize", "too large to parse here"))
        assert first["issued"] == [1], "the page was bought exactly once"
        assert first["outcome"].pages_unparsed == 1 and first["outcome"].pages_bought == 0

        acq = S.read_acquisition(self._fresh_ledger(first), first["pivot"], 1)
        assert acq and acq["state"] == S.ACQ_UNPARSED, acq
        raw = Path(acq["raw_ref"])
        assert raw.is_file() and raw.read_bytes() == body, "the bytes we paid for are addressable"
        assert acq["raw_digest"] == __import__("hashlib").sha256(body).hexdigest()

        # a FRESH lifecycle over the same project, with no ability to parse: it must still not buy
        second = self._lane(tmp_path, response=b"unused", parse=lambda p: None)
        assert second["issued"] == [], "a page this project already paid for must never be re-bought"
        assert second["outcome"].acquisition_refused == 1
        assert second["outcome"].pages_unparsed == 1 and second["outcome"].pages_bought == 0

    def test_deferred_bytes_are_PARSED_later_for_no_credit(self, tmp_path):
        body = b'{"total": 3, "matches": [{"hostnames": ["a.example"]}]}'
        first = self._lane(tmp_path, response=body, err=("oversize", "too large to parse here"))
        assert first["issued"] == [1]

        import json as _json

        def parse(path):
            doc = _json.loads(Path(path).read_text())
            return doc["matches"], doc["total"]

        second = self._lane(tmp_path, response=b"unused", parse=parse)
        assert second["issued"] == [], "interpretation must not contact the provider"
        assert second["outcome"].pages_parsed_late == 1
        assert second["ingested"] == [1], "the rows finally reach the store"
        assert second["outcome"].pages_bought == 0, "a late parse is not a purchase"

        # …and now it is an ordinary owned page: a third run replays it
        third = self._lane(tmp_path, response=b"unused", parse=parse)
        assert third["issued"] == [] and third["outcome"].pages_replayed == 1

    def test_an_INCOMPLETE_paid_response_refuses_an_automatic_retry(self, tmp_path):
        partial = b'{"total": 3, "matches": [{"hostna'
        first = self._lane(tmp_path, response=partial,
                           err=("incomplete", "response incomplete after 33 byte(s)"))
        assert first["issued"] == [1] and first["outcome"].pages_incomplete == 1

        acq = S.read_acquisition(self._fresh_ledger(first), first["pivot"], 1)
        assert acq and acq["state"] == S.ACQ_INCOMPLETE
        assert Path(acq["raw_ref"]).read_bytes() == partial, "what DID arrive is kept and addressable"

        second = self._lane(tmp_path, response=b"unused", parse=lambda p: None)
        assert second["issued"] == [], "nothing retries a paid, incomplete acquisition automatically"
        assert second["outcome"].pages_incomplete == 1 and second["outcome"].acquisition_refused == 1

    def test_a_receipt_must_match_the_identity_it_claims(self, tmp_path):
        """A transplanted receipt cannot donate ownership to a different pivot or page."""
        body = b'{"total": 3, "matches": []}'
        run = self._lane(tmp_path, response=body, err=("oversize", "deferred"))
        led = self._fresh_ledger(run)
        assert S.read_acquisition(led, run["pivot"], 2) is None, "another PAGE is not covered"
        assert S.read_acquisition(led, Pivot(FAV, "http.favicon.hash", "other"), 1) is None

    def test_a_PARSED_purchase_also_leaves_a_receipt(self, tmp_path):
        run = self._lane(tmp_path, response=b'{"total": 3, "matches": []}')
        assert run["outcome"].pages_bought == 1
        acq = S.read_acquisition(self._fresh_ledger(run), run["pivot"], 1)
        assert acq and acq["state"] == S.ACQ_PARSED

    def test_the_page_doc_points_at_the_RESPONSE_not_at_itself(self, tmp_path):
        """review#2: `raw_ref` stored only the basename, which resolved to the page document's own
        sibling — the doc claimed its own completion artifact was the provider's answer."""
        import json as _json
        body = b'{"total": 3, "matches": [{"hostnames": ["a.example"]}]}'
        run = self._lane(tmp_path, response=body)
        page = run["attempt"] / f"{S.item_key(run['pivot'], 1)}.json"
        doc = _json.loads(page.read_text())
        resolved = page.parent / doc["raw_ref"]
        assert resolved.resolve() != page.resolve(), "it must not point at the page document"
        assert resolved.read_bytes() == body and doc["raw_bytes"] == len(body)

    def test_a_receipt_whose_CONTENTS_name_another_page_is_refused(self, tmp_path):
        """Defence against our own writer: a document filed under this page's key that describes a
        different one proves nothing about this page, and must not read as a purchase.

        Driven through a stub store because a real `Ledger` is digest-bound — this is the case where the
        bytes are intact and the CLAIM is wrong."""
        import json as _json
        pivot = Pivot(FAV, "http.favicon.hash", "1")
        art = tmp_path / "receipt.json"
        art.write_text(_json.dumps({"schema": S.SHODAN_WORK_SCHEMA, "kind": "acquisition",
                                    "state": S.ACQ_UNPARSED, "lane": FAV,
                                    "facet": "http.favicon.hash", "value": "SOMEONE_ELSE",
                                    "page": 1, "at": 0.0}))

        class _Stub:
            def artifact(self, item):
                return art
        assert S.read_acquisition(_Stub(), pivot, 1) is None, "a receipt for another pivot is not ours"

        art.write_text(_json.dumps({"schema": S.SHODAN_WORK_SCHEMA, "kind": "acquisition",
                                    "state": S.ACQ_UNPARSED, "lane": FAV,
                                    "facet": "http.favicon.hash", "value": "1", "page": 7, "at": 0.0}))
        assert S.read_acquisition(_Stub(), pivot, 1) is None, "a receipt for another PAGE is not ours"

        art.write_text(_json.dumps({"schema": S.SHODAN_WORK_SCHEMA, "kind": "acquisition",
                                    "state": "invented", "lane": FAV, "facet": "http.favicon.hash",
                                    "value": "1", "page": 1, "at": 0.0}))
        assert S.read_acquisition(_Stub(), pivot, 1) is None, "an unknown state is not a purchase"

        art.write_text(_json.dumps({"schema": S.SHODAN_WORK_SCHEMA, "kind": "acquisition",
                                    "state": S.ACQ_UNPARSED, "lane": FAV, "facet": "http.favicon.hash",
                                    "value": "1", "page": 1, "at": 0.0}))
        assert S.read_acquisition(_Stub(), pivot, 1) is not None, "…and a matching one IS"

    def test_the_acquisition_states_reach_telemetry(self, tmp_path):
        import json as _json
        from quarry_recon import events
        run = self._lane(tmp_path, response=b'{"total": 3, "matches": []}',
                         err=("oversize", "deferred"))
        events.reset(); events.configure(tmp_path)
        S.report(FAV, run["outcome"], balance=type("B", (), {"reason": "ok", "stop_kind": ""})(),
                 max_pages=1)
        evs = [_json.loads(x) for x in (tmp_path / "events.jsonl").read_text().splitlines()]
        acq = [e for e in evs if e.get("measure") == "shodan_pages_acquired"]
        assert acq, "a purchase we could not interpret must still be reported as a purchase"
        assert acq[-1]["eligible"] == 1 and acq[-1]["tested"] == 0 and acq[-1]["omitted"] == 1
        assert "complete_unparsed=1" in acq[-1]["reason"] and "never re-bought" in acq[-1]["reason"]
        events.reset()

    def test_a_PARSED_receipt_blocks_purchase_even_with_the_page_gone(self, tmp_path):
        """review#1: the receipt check skipped `complete_parsed`, so a page whose completion document
        had vanished while its receipt survived could still reach the purchase path."""
        run = self._lane(tmp_path, response=b'{"total": 3, "matches": []}')
        assert run["outcome"].pages_bought == 1
        page = run["attempt"] / f"{S.item_key(run['pivot'], 1)}.json"
        page.unlink()                                    # the PAGE is gone; the receipt is not

        second = self._lane(tmp_path, response=b"unused", parse=lambda p: None)
        assert second["issued"] == [], "a receipt is a receipt whatever state it carries"
        assert second["outcome"].pages_bought == 0
        assert second["outcome"].pages_lost == 1 and second["outcome"].repair_refused == 1

    def test_TAMPERED_purchased_bytes_are_never_parsed_into_evidence(self, tmp_path):
        """review#2: the receipt carries a digest and a byte count, and nothing checked either — a
        substituted artifact would have become normalized evidence on the deferred-parse path."""
        import json as _json
        body = b'{"total": 3, "matches": [{"hostnames": ["a.example"]}]}'
        run = self._lane(tmp_path, response=body, err=("oversize", "deferred"))
        acq = S.read_acquisition(self._fresh_ledger(run), run["pivot"], 1)
        raw = Path(acq["raw_ref"])
        raw.write_bytes(_json.dumps({"total": 3, "matches": [{"hostnames": ["attacker.example"]}]},
                                    separators=(",", ":")).encode())

        ingested = []
        second = self._lane(tmp_path, response=b"unused",
                            parse=lambda p: (_json.loads(Path(p).read_text())["matches"], 3))
        assert second["ingested"] == [], "substituted bytes must never reach the store"
        assert second["issued"] == [], "…and must not be re-bought either"
        assert second["outcome"].pages_lost == 1 and second["outcome"].repair_refused == 1
        assert ingested == []

    def test_a_SAME_LENGTH_substitution_is_caught_by_the_digest(self, tmp_path):
        """The byte count alone would pass this: only the digest can tell two same-sized responses
        apart, which is why the receipt carries one."""
        body = b'{"total": 3, "matches": [{"hostnames": ["aaa.example"]}]}'
        run = self._lane(tmp_path, response=body, err=("oversize", "deferred"))
        acq = S.read_acquisition(self._fresh_ledger(run), run["pivot"], 1)
        raw = Path(acq["raw_ref"])
        swapped = b'{"total": 3, "matches": [{"hostnames": ["bbb.example"]}]}'
        assert len(swapped) == len(body), "the fixture must keep the length identical"
        raw.write_bytes(swapped)
        assert acq["raw_bytes"] == raw.stat().st_size, "the byte count still agrees…"
        assert S.verified_raw(acq, base=run["base"]) is None, "…and the digest does not"

    def test_a_TRUNCATED_purchased_artifact_fails_its_byte_count(self, tmp_path):
        body = b'{"total": 3, "matches": [{"hostnames": ["a.example"]}]}'
        run = self._lane(tmp_path, response=body, err=("oversize", "deferred"))
        acq = S.read_acquisition(self._fresh_ledger(run), run["pivot"], 1)
        assert S.verified_raw(acq, base=run["base"]) is not None, "the untouched artifact verifies"
        Path(acq["raw_ref"]).write_bytes(body[:-1])
        assert S.verified_raw(acq, base=run["base"]) is None, "one byte short is not what we bought"

    def test_a_raw_pointer_may_not_ESCAPE_the_paid_store(self, tmp_path):
        """A confined path is checked before the digest: a link out of the store is refused on sight."""
        import hashlib as _h
        outside = tmp_path / "elsewhere.json"
        outside.write_bytes(b"{}")
        acq = {"raw_ref": str(outside), "raw_bytes": 2,
               "raw_digest": _h.sha256(b"{}").hexdigest()}
        assert S.verified_raw(acq, base=S.state_dir(tmp_path)) is None
        link = S.state_dir(tmp_path) / "linked.json"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside)
        acq["raw_ref"] = str(link)
        assert S.verified_raw(acq, base=S.state_dir(tmp_path)) is None, "a symlink is not a regular file"

    def test_an_ORPHANED_purchase_is_refused_not_bought_again(self, tmp_path):
        """review#3: publish lands, journal fails. The next run indexes only ledger items, sees nothing,
        and would buy the page again while the receipt and the paid bytes sit right there."""
        run = self._lane(tmp_path, response=b'{"total": 3, "matches": []}',
                         err=("oversize", "deferred"))
        led = self._fresh_ledger(run)
        acq_art = led.artifact(S.acq_key(run["pivot"], 1))
        assert acq_art is not None and acq_art.is_file()

        # simulate the lost ownership entry: the ledger forgets, the artifacts survive
        state = _json_load(led.path)
        state["done"] = {k: v for k, v in state["done"].items() if not k.startswith(S.ACQ_PREFIX)}
        _json_dump(led.path, state)
        led.journal.unlink(missing_ok=True)

        second = self._lane(tmp_path, response=b"unused", parse=lambda p: None)
        assert second["issued"] == [], "a surviving receipt is not evidence that nothing was bought"
        assert second["outcome"].acquisition_orphans == 1
        assert second["outcome"].acquisition_refused == 1
        assert acq_art.is_file(), "the orphan is PRESERVED for an operator, not cleaned up"

    def test_an_orphaned_RAW_response_alone_is_also_refused(self, tmp_path):
        """The raw bytes can survive without a receipt at all — same rule."""
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        attempt = base / "pages" / "a0"
        (attempt / "raw").mkdir(parents=True, exist_ok=True)
        pivot = Pivot(FAV, "http.favicon.hash", "1")
        (attempt / "raw" / f"{S.item_key(pivot, 1)}.json").write_bytes(b'{"total": 1, "matches": []}')
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        assert S.ownership_view(base, led).orphans, \
            "a paid response with no ownership entry is an orphan"

        run = self._lane(tmp_path, response=b"unused", parse=lambda p: None)
        assert run["issued"] == [] and run["outcome"].acquisition_orphans == 1

    def test_an_UNINSPECTABLE_store_stops_acquisition_globally(self, tmp_path):
        """review#1: `orphan_index` was best-effort, so a failed walk or a ledger that would not
        enumerate returned an EMPTY index — and empty read as "no prior purchase". For a paid store,
        unknown is not empty."""
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        base.mkdir(parents=True, exist_ok=True)

        class _Blind(budget.Ledger):
            def items(self):
                raise OSError("the ownership store cannot be enumerated")

        led = _Blind(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                     lane="probe.shodan")
        view = S.ownership_view(base, led)
        assert view.error and "enumerated" in view.error
        assert view.by_page == {} and view.orphans == {}, "and it says nothing else, either"

        st = PivotState(pivot=Pivot(FAV, "http.favicon.hash", "1"))
        res = S.WorkResult()
        res.lanes.setdefault(FAV, S.LaneOutcome(lane=FAV))
        S._work([st], res, balance=type("B", (), {"spendable": 5, "may_spend": True, "reserve": 0})(),
                search=lambda pv, pg: pytest.fail("a purchase was attempted against an unreadable store"),
                ingest=lambda *a: 0, ledger=led, attempt_dir=base / "pages" / "a0",
                max_pages=1, is_limit=lambda cls: False)
        assert res.stop_cause.startswith("ownership_uninspectable:")

    def test_a_REAL_unreadable_subtree_stops_acquisition(self, tmp_path):
        """review#1 (Lumpy, measured; reproduced here): `Path.rglob` SILENTLY OMITS a subtree it cannot
        read — a directory at mode 000 yields nothing and raises nothing, so the scan looks clean and an
        orphaned purchase inside it is invisible. This is pinned against the real filesystem, not a
        monkeypatched traversal: the previous version faked the exception that never happens."""
        import os
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        attempt = base / "pages" / "a0"
        (attempt / "raw").mkdir(parents=True, exist_ok=True)
        pivot = Pivot(FAV, "http.favicon.hash", "1")
        # an ORPHANED paid response, hidden inside a directory we cannot enter
        (attempt / "raw" / f"{S.item_key(pivot, 1)}.json").write_bytes(b'{"total": 1, "matches": []}')
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        assert S.item_key(pivot, 1) in S.ownership_view(base, led).orphans, "visible while readable"

        mode = (attempt / "raw").stat().st_mode
        os.chmod(attempt / "raw", 0o000)
        try:
            if os.access(attempt / "raw", os.R_OK):
                pytest.skip("running as root: an unreadable subtree cannot be simulated")
            # the artifact is now unreachable — and the walk must SAY SO rather than report a clean store
            view = S.ownership_view(base, led)
            assert view.error and "could not be fully inspected" in view.error, view
            assert not view.orphans, "it must not report a partial picture as the whole one"

            st = PivotState(pivot=pivot)
            res = S.WorkResult()
            res.lanes.setdefault(FAV, S.LaneOutcome(lane=FAV))
            S._work([st], res,
                    balance=type("B", (), {"spendable": 5, "may_spend": True, "reserve": 0})(),
                    search=lambda pv, pg: pytest.fail("bought a page we could not rule out owning"),
                    ingest=lambda *a: 0, ledger=led, attempt_dir=attempt, max_pages=1,
                    is_limit=lambda cls: False)
            assert res.stop_cause.startswith("ownership_uninspectable:")
        finally:
            os.chmod(attempt / "raw", mode)

    def test_a_receipt_from_another_SCHEMA_blocks_but_is_not_interpreted(self, tmp_path):
        """review#2: `schema` was never checked, so a receipt from a generation we do not speak could
        enter `by_page` and reach deferred parsing. It still proves a PURCHASE — it just may not be
        read — so it belongs in `invalid`."""
        import json as _json
        run = self._lane(tmp_path, response=b'{"total": 3, "matches": []}',
                         err=("oversize", "deferred"))
        led = self._fresh_ledger(run)
        art = led.artifact(S.acq_key(run["pivot"], 1))
        doc = _json.loads(art.read_text())
        doc["schema"] = S.SHODAN_WORK_SCHEMA + 1
        art.write_text(_json.dumps(doc))
        led.record(S.acq_key(run["pivot"], 1), art)
        led.save()

        view = S.ownership_view(S.state_dir(tmp_path), self._fresh_ledger(run))
        assert S.item_key(run["pivot"], 1) in view.invalid
        assert not view.by_page, "a receipt we cannot read must never feed deferred parsing"

        parsed = []
        second = self._lane(tmp_path, response=b"unused",
                            parse=lambda p: parsed.append(p) or ([], 0))
        assert second["issued"] == [] and second["outcome"].acquisition_invalid == 1
        assert parsed == [], "…and its bytes are not interpreted either"

    def test_an_orphaned_PARTIAL_response_is_seen_and_refused(self, tmp_path):
        """review#2: a broken stream leaves `<key>.json.part`. The scan matched only `raw/*.json`, so a
        partial whose receipt never published was invisible and the page could be bought again."""
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        attempt = base / "pages" / "a0"
        (attempt / "raw").mkdir(parents=True, exist_ok=True)
        pivot = Pivot(FAV, "http.favicon.hash", "1")
        partial = attempt / "raw" / f"{S.item_key(pivot, 1)}.json.part"
        partial.write_bytes(b'{"total": 3, "matches": [{"hostna')      # the stream died here
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        view = S.ownership_view(base, led)
        assert S.item_key(pivot, 1) in view.orphans
        assert "PARTIAL" in view.orphans[S.item_key(pivot, 1)]

        run = self._lane(tmp_path, response=b"unused", parse=lambda p: None)
        assert run["issued"] == [], "a partial we paid for is not evidence that nothing was bought"
        assert run["outcome"].acquisition_orphans == 1
        assert partial.read_bytes().startswith(b'{"total"'), "the partial is PRESERVED"

    def test_an_OWNED_but_invalid_receipt_blocks_the_purchase(self, tmp_path):
        """review#3: a receipt that would not validate was silently skipped, while its `acq:` key stayed
        owned — so the orphan scan did not see it either and the scheduler reached the purchase path.
        Driven end to end through `_work`, not through `read_acquisition` against a stub."""
        import json as _json
        run = self._lane(tmp_path, response=b'{"total": 3, "matches": []}',
                         err=("oversize", "deferred"))
        led = self._fresh_ledger(run)
        art = led.artifact(S.acq_key(run["pivot"], 1))
        doc = _json.loads(art.read_text())
        doc["state"] = "something we never issue"
        art.write_text(_json.dumps(doc))
        # re-own it: the ledger's digest binding would otherwise drop it and make it a LOST item
        led.record(S.acq_key(run["pivot"], 1), art)
        led.save()

        view = S.ownership_view(S.state_dir(tmp_path), self._fresh_ledger(run))
        assert S.item_key(run["pivot"], 1) in view.invalid

        second = self._lane(tmp_path, response=b"unused", parse=lambda p: None)
        assert second["issued"] == [], "untrusted ownership evidence is not an absence"
        assert second["outcome"].acquisition_invalid == 1
        assert second["outcome"].acquisition_refused == 1
        assert second["outcome"].pages_bought == 0

    def test_an_unreadable_owned_receipt_blocks_the_purchase_too(self, tmp_path):
        run = self._lane(tmp_path, response=b'{"total": 3, "matches": []}',
                         err=("oversize", "deferred"))
        led = self._fresh_ledger(run)
        art = led.artifact(S.acq_key(run["pivot"], 1))
        art.write_bytes(b"{ not json at all")
        led.record(S.acq_key(run["pivot"], 1), art)
        led.save()
        second = self._lane(tmp_path, response=b"unused", parse=lambda p: None)
        assert second["issued"] == [] and second["outcome"].acquisition_invalid == 1


class TestCooldownGovernsProviderContactOnly:
    """Lumpy, 2026-08-05, from the §5 measurement: run B slept 301 s honouring a 429 raised by the FREE
    sizing pass and only then replayed two pages it already owned (`oldest_replay_s: 302.3` — they aged
    by exactly the sleep).

    Replay is LOCAL. It happens whenever a project owns pages — a resumed run, a new run over the same
    project, a campaign child, another lane's lifecycle — and a penalty recorded seconds earlier can
    still be in force. None of that is a reason to delay reading a file we already paid for."""

    @staticmethod
    def _owned(tmp_path):
        """A project that already owns page 1 of one pivot."""
        from quarry_recon import budget
        base = S.state_dir(tmp_path)
        attempt = base / "pages" / "a0"
        attempt.mkdir(parents=True, exist_ok=True)
        pivot = Pivot(FAV, "http.favicon.hash", "1")
        doc = S._page_doc(pivot, 1, 3, [{"ip_str": "203.0.113.1", "hostnames": ["a.example"]}])
        art = attempt / f"{S.item_key(pivot, 1)}.json"
        art.write_text(__import__("json").dumps(doc))
        led = budget.Ledger(budget.state_path(base, "probe.shodan", f"v{S.SHODAN_WORK_SCHEMA}"),
                            lane="probe.shodan")
        led.record(S.item_key(pivot, 1), art)
        led.save()
        return led, attempt, pivot

    def test_owned_pages_replay_BEFORE_the_provider_is_consulted(self, tmp_path):
        """The ordering, asserted as an ORDER: every replay happens before the balance is read."""
        led, attempt, pivot = self._owned(tmp_path)
        order = []

        def balance():
            order.append("provider")
            return type("B", (), {"spendable": 0, "may_spend": False, "reserve": 0})()

        res = S.run_work(None, states=[PivotState(pivot=pivot)], balance=balance,
                         search=lambda pv, pg: pytest.fail("no purchase was needed"),
                         ingest=lambda pv, pg, ms, art: order.append("replay") or len(ms),
                         ledger=led, attempt_dir=attempt, max_pages=1)
        assert order and order[0] == "replay", order
        assert res.lanes[FAV].pages_replayed == 1

    def test_a_LIVE_penalty_does_not_delay_replay(self, tmp_path, monkeypatch):
        """A resume may start seconds after the failure that earned a 300 s penalty. The owned page must
        come back instantly anyway — it costs no request and no credit."""
        import time as _t
        from quarry_recon.phases import probe
        led, attempt, pivot = self._owned(tmp_path)
        cooldown = probe._ProviderCooldown()
        cooldown.until = _t.monotonic() + 300.0          # a penalty recorded moments ago
        slept: list = []
        monkeypatch.setattr(probe._time, "sleep", lambda s: slept.append(s))

        events: list = []

        def balance():
            # the provider phase still runs — the free count is how GROWTH beyond a completed
            # pagination is found — and it honours the penalty. It simply no longer runs FIRST.
            events.append(("provider", list(slept)))
            cooldown.wait()
            return type("B", (), {"spendable": 0, "may_spend": False, "reserve": 0})()

        started = _t.perf_counter()
        res = S.run_work(None, states=[PivotState(pivot=pivot)], balance=balance,
                         search=lambda pv, pg: pytest.fail("a request was issued"),
                         ingest=lambda pv, pg, ms, art: events.append(("replay", list(slept))) or len(ms),
                         ledger=led, attempt_dir=attempt, max_pages=1)
        assert res.lanes[FAV].pages_replayed == 1
        assert [k for k, _ in events][:2] == ["replay", "provider"], events
        assert events[0][1] == [], "replay must not wait on a provider slowdown"
        assert slept and slept[0] > 200, "…and the penalty is still honoured for provider contact"
        assert _t.perf_counter() - started < 5.0, "the wait was recorded, not actually slept in the test"

    def test_the_cooldown_paces_requests_it_does_not_only_react(self, monkeypatch):
        """review (Lumpy): with no minimum interval we generated the 429 ourselves — four requests in
        ~3 s — and then honoured a penalty of up to 300 s for it. Pacing is the control."""
        import time as _t
        from quarry_recon.phases import probe
        slept: list = []
        monkeypatch.setattr(probe._time, "sleep", lambda s: slept.append(s))
        monkeypatch.setattr(probe, "_SHODAN_MIN_INTERVAL_S", 1.05)   # offline runs disable pacing
        c = probe._ProviderCooldown()
        c.wait()                                          # the first request waits for nothing
        assert slept == []
        c.wait()                                          # the second is paced behind it
        assert slept and slept[0] > 0.5, slept

    def test_the_shipped_interval_matches_the_providers_own_rule(self):
        """Asserted against the SOURCE, because the offline suite deliberately zeroes the live value."""
        import inspect
        from quarry_recon.phases import probe
        src = inspect.getsource(probe)
        line = next(ln for ln in src.splitlines() if ln.startswith("_SHODAN_MIN_INTERVAL_S ="))
        assert float(line.split("=")[1].strip()) >= 1.0, "Shodan documents about one request per second"

    def test_a_provider_penalty_still_outranks_the_pacing_interval(self, monkeypatch):
        import time as _t
        from quarry_recon.phases import probe
        slept: list = []
        monkeypatch.setattr(probe._time, "sleep", lambda s: slept.append(s))
        c = probe._ProviderCooldown()
        c.until = _t.monotonic() + 42.0
        c.wait()
        assert slept and slept[0] > 40, "the provider's own slowdown is the longer of the two"
