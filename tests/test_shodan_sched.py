"""B1.3 — the Shodan work coordinator: hermetic lifecycle.

No network and no credits: `search` and `ingest` are injected, so every case below is the REAL scheduler
against a scripted provider. The eight properties this increment must prove are one class each.
"""
import json
import os
import pathlib

import pytest

from quarry_recon import budget, events
from quarry_recon.shodan_sched import (SHODAN_PAGE_SIZE, LaneOutcome, Pivot, PivotState,
                                       dedupe, item_key, report, run_work, schedule,
                                       valid_page)

pytestmark = pytest.mark.offline

FAV, CERT = "probe.favicon", "probe.cert"


class _Bal:
    """The B1.2 contract's shape, only the fields the coordinator consumes."""

    def __init__(self, spendable=None, may_spend=True, reason="test", stop_kind="", read_error=None,
                 reserve=0):
        self.spendable = spendable
        self.may_spend = may_spend
        self.reason = reason
        self.stop_kind = stop_kind
        self.read_error = read_error
        self.reserve = reserve


class _Provider:
    """A scripted Shodan. Records every purchase, so 'was this credit spent?' is directly observable."""

    def __init__(self, totals=None, errors=None, page_size=SHODAN_PAGE_SIZE):
        self.totals = totals or {}
        self.errors = errors or {}
        self.calls = []
        self.page_size = page_size

    def search(self, pivot, page):
        self.calls.append((pivot.lane, pivot.value, page))
        err = self.errors.get((pivot.value, page)) or self.errors.get(pivot.value)
        if err is not None:
            return [], None, err
        total = self.totals.get((pivot.value, page), self.totals.get(pivot.value, 1))
        start = (page - 1) * self.page_size
        n = max(0, min(self.page_size, total - start))
        return [{"hostnames": [f"h{start + i}.{pivot.value}.acme.com"]} for i in range(n)], total, None


def _err(cls):
    e = RuntimeError(f"simulated {cls}")
    e.error_class = cls
    return e


def _states(*specs):
    return [PivotState(Pivot(lane, "facet", value)) for lane, value in specs]


def _ledger(tmp_path, lane="shodan.work"):
    return budget.Ledger(budget.state_path(tmp_path, lane, "fp0"), lane=lane)


def _run(tmp_path, states, provider, balance=None, max_pages=0, ledger=None, ingested=None):
    d = tmp_path / "attempts"
    d.mkdir(parents=True, exist_ok=True)
    led = ledger if ledger is not None else _ledger(tmp_path)

    def ingest(pivot, page, matches, raw):
        if ingested is not None:
            ingested.append((pivot.value, page, len(matches)))
        return len(matches)

    res = run_work(None, states=states, balance=balance or _Bal(), search=provider.search,
                   ingest=ingest, ledger=led, attempt_dir=d, max_pages=max_pages)
    return res.lanes, led


# ── 1. both lanes are collected before spending ───────────────────────────────────────────────────
class TestBothLanesCollectedFirst:
    def test_no_lane_can_drain_the_balance_before_the_other_is_seen(self, tmp_path):
        """A shared counter is not fairness: two sequential provider calls would let favicon spend
        everything while cert never ran. With only 2 credits, each lane must get one."""
        states = _states((FAV, "a"), (FAV, "b"), (CERT, "x"), (CERT, "y"))
        p = _Provider()
        _run(tmp_path, states, p, balance=_Bal(spendable=2))
        lanes = {lane for lane, _v, _pg in p.calls}
        assert len(p.calls) == 2 and lanes == {FAV, CERT}

    def test_a_single_credit_is_still_deterministic(self, tmp_path):
        states = _states((FAV, "a"), (CERT, "x"))
        p = _Provider()
        _run(tmp_path, states, p, balance=_Bal(spendable=1))
        assert len(p.calls) == 1

    def test_every_lane_appears_in_the_outcome_even_with_no_budget(self, tmp_path):
        states = _states((FAV, "a"), (CERT, "x"))
        out, _ = _run(tmp_path, states, _Provider(), balance=_Bal(spendable=0))
        assert set(out) == {FAV, CERT} and all(o.pivots == 1 for o in out.values())


# ── 2. page-one work is fair across lanes AND pivots ──────────────────────────────────────────────
class TestPageOneFairness:
    def test_lanes_alternate(self, tmp_path):
        states = _states((FAV, "a"), (FAV, "b"), (FAV, "c"), (CERT, "x"))
        p = _Provider()
        _run(tmp_path, states, p, balance=_Bal(spendable=2))
        assert {lane for lane, _v, _pg in p.calls} == {FAV, CERT}

    def test_one_lane_with_many_pivots_cannot_starve_the_other(self, tmp_path):
        states = _states(*[(FAV, f"f{i}") for i in range(20)], (CERT, "x"))
        p = _Provider()
        _run(tmp_path, states, p, balance=_Bal(spendable=4))
        assert any(lane == CERT for lane, _v, _pg in p.calls)

    def test_the_order_is_deterministic(self, tmp_path):
        first = None
        for _ in range(3):
            states = _states((FAV, "a"), (FAV, "b"), (CERT, "x"), (CERT, "y"))
            p = _Provider()
            _run(tmp_path / str(_), states, p, balance=_Bal(spendable=3))
            if first is None:
                first = list(p.calls)
            assert p.calls == first


# ── 3. later pages are lazy AND breadth-first ─────────────────────────────────────────────────────
class TestBreadthFirstPages:
    def test_page_two_never_precedes_another_pivots_page_one(self, tmp_path):
        """A pivot matching millions must not eat the balance on its own later pages."""
        states = _states((FAV, "huge"), (CERT, "small"))
        p = _Provider(totals={"huge": 10_000_000, "small": 1})
        _run(tmp_path, states, p, balance=_Bal(spendable=4))
        pages_before_small = [pg for lane, v, pg in p.calls[:p.calls.index((CERT, "small", 1))]]
        assert all(pg == 1 for pg in pages_before_small)

    def test_pages_are_generated_lazily_not_materialised(self, tmp_path):
        """10.9M matches = 109_238 pages. The scheduler must never build that list."""
        st = PivotState(Pivot(FAV, "f", "huge"))
        assert st.page_count() is None                       # nothing known before page 1
        st.total = 10_923_823
        st.pages_done.add(1)
        assert st.page_count() == 109_239
        assert schedule([st])[0][1] == 2                      # only the NEXT page is produced

    def test_a_full_round_of_page_ones_comes_first(self, tmp_path):
        states = _states((FAV, "a"), (FAV, "b"), (CERT, "x"))
        p = _Provider(totals={"a": 500, "b": 500, "x": 500})
        _run(tmp_path, states, p, balance=_Bal(spendable=3))
        assert [pg for _l, _v, pg in p.calls] == [1, 1, 1]

    def test_the_second_round_only_starts_after_the_first(self, tmp_path):
        states = _states((FAV, "a"), (CERT, "x"))
        p = _Provider(totals={"a": 500, "x": 500})
        _run(tmp_path, states, p, balance=_Bal(spendable=4))
        assert [pg for _l, _v, pg in p.calls] == [1, 1, 2, 2]

    def test_a_single_page_pivot_is_not_revisited(self, tmp_path):
        states = _states((FAV, "a"))
        p = _Provider(totals={"a": 3})
        _run(tmp_path, states, p, balance=_Bal(spendable=10))
        assert p.calls == [(FAV, "a", 1)]

    def test_max_pages_is_an_operator_depth_policy(self, tmp_path):
        states = _states((FAV, "a"))
        p = _Provider(totals={"a": 500})
        _run(tmp_path, states, p, balance=_Bal(spendable=10), max_pages=2)
        assert [pg for _l, _v, pg in p.calls] == [1, 2]


# ── 4. the B1.2 balance actually stops scheduling ─────────────────────────────────────────────────
class TestTheBalanceStops:
    def test_spendable_is_the_hard_stop(self, tmp_path):
        states = _states(*[(FAV, f"f{i}") for i in range(10)])
        p = _Provider()
        _run(tmp_path, states, p, balance=_Bal(spendable=3))
        assert len(p.calls) == 3

    def test_may_spend_false_buys_nothing(self, tmp_path):
        """The reserve/refusal cases from B1.2 must reach ZERO purchases, not merely fewer."""
        states = _states((FAV, "a"), (CERT, "x"))
        p = _Provider()
        _run(tmp_path, states, p, balance=_Bal(spendable=None, may_spend=False))
        assert p.calls == []

    def test_an_unknown_balance_with_no_reserve_runs_the_whole_set(self, tmp_path):
        states = _states(*[(FAV, f"f{i}") for i in range(5)])
        p = _Provider()
        _run(tmp_path, states, p, balance=_Bal(spendable=None, may_spend=True))
        assert len(p.calls) == 5

    def test_a_provider_limit_mid_flight_degrades_rather_than_disabling(self, tmp_path):
        """Stop buying, keep what was earned, leave the rest as a counted remainder.

        The limit is placed on the FIRST scheduled item so there IS work after it — asserting on a limit
        that happens to land last proves nothing about stopping."""
        states = _states((FAV, "a"), (FAV, "b"), (CERT, "x"))
        order = [(s.pivot.lane, s.pivot.value) for s, _pg in schedule(states)]
        first_value = order[0][1]
        p = _Provider(errors={first_value: _err("quota")})
        out, _ = _run(tmp_path, states, p, balance=_Bal(spendable=None))
        assert len(p.calls) == 1, p.calls                         # purchasing stopped immediately
        limited = [o for o in out.values() if o.limit_classes]
        assert limited and limited[0].limit_classes.get("quota") == 1

    def test_evidence_bought_BEFORE_a_limit_is_kept(self, tmp_path):
        """Degrade, don't discard: pages already paid for stay ingested and recorded."""
        states = _states((FAV, "a"), (FAV, "b"), (CERT, "x"))
        order = [(s.pivot.lane, s.pivot.value) for s, _pg in schedule(states)]
        p = _Provider(totals={order[0][1]: 5}, errors={order[1][1]: _err("quota")})
        seen = []
        out, led = _run(tmp_path, states, p, balance=_Bal(spendable=None), ingested=seen)
        assert seen and seen[0][2] == 5                           # the first page was ingested
        assert sum(o.pages_bought for o in out.values()) == 1     # and recorded as bought
        assert led.has(item_key(Pivot(order[0][0], "facet", order[0][1]), 1))

    def test_the_remainder_after_a_limit_is_still_named(self, tmp_path):
        states = _states((FAV, "a"), (FAV, "b"), (CERT, "x"))
        order = [(s.pivot.lane, s.pivot.value) for s, _pg in schedule(states)]
        p = _Provider(errors={order[0][1]: _err("quota")})
        out, _ = _run(tmp_path, states, p, balance=_Bal(spendable=None))
        named = sorted(v for o in out.values() for v in o.unqueried)
        # the refused pivot is NOT in the remainder: it was asked and a credit was spent on it.
        assert named == sorted(v for _l, v in order[1:])
        assert order[0][1] not in named

    def test_a_plain_failure_does_not_stop_the_whole_run(self, tmp_path):
        states = _states((FAV, "a"), (FAV, "b"), (CERT, "x"))
        p = _Provider(errors={"a": _err("transport")})
        out, _ = _run(tmp_path, states, p, balance=_Bal(spendable=None))
        assert out[FAV].fail_classes.get("transport") == 1
        assert len(p.calls) == 3                                  # the others still ran


# ── 5. reserve is excluded from completion identity ───────────────────────────────────────────────
class TestReserveIsNotIdentity:
    def test_the_key_ignores_the_reserve(self):
        """A page bought under reserve 10 is byte-identical to one bought under reserve 0. Folding the
        reserve into identity would make LOWERING it re-pay for pages already purchased."""
        pv = Pivot(FAV, "facet", "a")
        assert item_key(pv, 1) == item_key(pv, 1)

    def test_lowering_the_reserve_resumes_instead_of_repurchasing(self, tmp_path):
        states = _states((FAV, "a"), (FAV, "b"))
        led = _ledger(tmp_path)
        p1 = _Provider()
        _run(tmp_path, states, p1, balance=_Bal(spendable=1), ledger=led)
        bought_first = list(p1.calls)
        # a SECOND run with a bigger allowance (reserve lowered) must not re-buy the first page
        states2 = _states((FAV, "a"), (FAV, "b"))
        p2 = _Provider()
        _run(tmp_path, states2, p2, balance=_Bal(spendable=5), ledger=led)
        assert bought_first[0] not in p2.calls

    def test_identity_changes_with_page_lane_facet_and_value(self):
        base = Pivot(FAV, "f", "a")
        assert item_key(base, 1) != item_key(base, 2)
        assert item_key(base, 1) != item_key(Pivot(CERT, "f", "a"), 1)
        assert item_key(base, 1) != item_key(Pivot(FAV, "g", "a"), 1)
        assert item_key(base, 1) != item_key(Pivot(FAV, "f", "b"), 1)


# ── 6. completed evidence replays without repurchase ──────────────────────────────────────────────
class TestReplayWithoutRepurchase:
    def test_a_second_run_buys_nothing_new(self, tmp_path):
        states = _states((FAV, "a"), (CERT, "x"))
        led = _ledger(tmp_path)
        _run(tmp_path, states, _Provider(), balance=_Bal(spendable=None), ledger=led)
        p2 = _Provider()
        out, _ = _run(tmp_path, _states((FAV, "a"), (CERT, "x")), p2,
                      balance=_Bal(spendable=None), ledger=led)
        assert p2.calls == []
        assert out[FAV].pages_replayed == 1 and out[CERT].pages_replayed == 1

    def test_replayed_evidence_is_re_ingested(self, tmp_path):
        """The store is per-run: a replayed page must still feed this run's entities."""
        states = _states((FAV, "a"))
        led = _ledger(tmp_path)
        _run(tmp_path, states, _Provider(totals={"a": 5}), balance=_Bal(spendable=None), ledger=led)
        seen = []
        _run(tmp_path, _states((FAV, "a")), _Provider(), balance=_Bal(spendable=None),
             ledger=led, ingested=seen)
        assert seen and seen[0][2] == 5

    def test_replay_happens_even_when_spending_is_forbidden(self, tmp_path):
        """Evidence costs nothing. A refused balance must not also lose what we already own."""
        states = _states((FAV, "a"))
        led = _ledger(tmp_path)
        _run(tmp_path, states, _Provider(totals={"a": 4}), balance=_Bal(spendable=None), ledger=led)
        seen = []
        out, _ = _run(tmp_path, _states((FAV, "a")), _Provider(),
                      balance=_Bal(spendable=0, may_spend=False), ledger=led, ingested=seen)
        assert seen and out[FAV].pages_replayed == 1

    def test_a_partially_bought_pivot_resumes_at_the_next_page(self, tmp_path):
        states = _states((FAV, "a"))
        led = _ledger(tmp_path)
        _run(tmp_path, states, _Provider(totals={"a": 500}), balance=_Bal(spendable=2), ledger=led)
        p2 = _Provider(totals={"a": 500})
        _run(tmp_path, _states((FAV, "a")), p2, balance=_Bal(spendable=2), ledger=led)
        assert [pg for _l, _v, pg in p2.calls] == [3, 4]


# ── 7. unknown page totals never invent denominators ──────────────────────────────────────────────
class TestNoInventedDenominators:
    def test_an_unqueried_pivot_has_no_page_count(self):
        assert PivotState(Pivot(FAV, "f", "never")).page_count() is None

    def test_an_ATTEMPTED_pivot_is_not_in_the_unqueried_remainder(self, tmp_path):
        """A credit was spent on it. Counting it as never-reached would overstate the remainder and hide
        that the attempt happened at all."""
        states = _states((FAV, "boom"))
        out, _ = _run(tmp_path, states, _Provider(errors={"boom": _err("transport")}),
                      balance=_Bal(spendable=None))
        assert out[FAV].unqueried == [] and out[FAV].fail_classes.get("transport") == 1

    def test_unqueried_pivots_are_reported_by_IDENTITY(self, tmp_path):
        states = _states((FAV, "a"), (FAV, "b"), (FAV, "c"))
        out, _ = _run(tmp_path, states, _Provider(), balance=_Bal(spendable=1))
        assert len(out[FAV].unqueried) == 2 and set(out[FAV].unqueried) <= {"a", "b", "c"}

    def test_page_remainder_counts_only_KNOWN_totals(self, tmp_path):
        states = _states((FAV, "known"), (FAV, "never"))
        p = _Provider(totals={"known": 500})
        out, _ = _run(tmp_path, states, p, balance=_Bal(spendable=1))
        assert out[FAV].pages_left_known == 4                 # 500 -> 5 pages, 1 bought
        assert "never" in out[FAV].unqueried
        assert out[FAV].pages_left_unknown_pivots == 0        # untouched pivots are NOT page-counted

    def test_the_coverage_event_never_sums_an_unknown_page_count(self, tmp_path):
        states = _states((FAV, "known"), (FAV, "never"))
        out, _ = _run(tmp_path, states, _Provider(totals={"known": 500}), balance=_Bal(spendable=1))
        events.reset()
        events.configure(tmp_path)
        try:
            report(FAV, out[FAV], balance=_Bal())
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        pages = [r for r in recs if r["measure"] == "shodan_pages_left"][0]
        assert pages["eligible"] == 5 and pages["omitted"] == 4      # the UNKNOWN pivot is absent
        unq = [r for r in recs if r["measure"] == "shodan_pivots_unqueried"][0]
        assert unq["eligible"] == 2 and unq["omitted"] == 1


# ── 8. a read gap plus an operator limit: gaps dominate ───────────────────────────────────────────
class TestGapsDominateOverLimits:
    def test_a_failure_and_a_limit_are_counted_separately(self, tmp_path):
        states = _states((FAV, "boom"), (FAV, "spent"), (CERT, "x"))
        p = _Provider(errors={"boom": _err("transport"), "spent": _err("quota")})
        out, _ = _run(tmp_path, states, p, balance=_Bal(spendable=None))
        assert out[FAV].fail_classes.get("transport") == 1
        assert out[FAV].limit_classes.get("quota") == 1

    def test_a_limit_never_absorbs_a_failure_class(self, tmp_path):
        states = _states((FAV, "boom"), (FAV, "spent"))
        p = _Provider(errors={"boom": _err("server"), "spent": _err("quota")})
        out, _ = _run(tmp_path, states, p, balance=_Bal(spendable=None))
        assert "quota" not in out[FAV].fail_classes and "server" not in out[FAV].limit_classes

    def test_an_operator_limit_still_reports_the_unqueried_remainder(self, tmp_path):
        """The B1.2 reserve case: nothing is bought, and every pivot is named as remaining."""
        states = _states((FAV, "a"), (CERT, "x"))
        out, _ = _run(tmp_path, states, _Provider(),
                      balance=_Bal(spendable=0, may_spend=False, reason="operator reserve"))
        assert out[FAV].unqueried == ["a"] and out[CERT].unqueried == ["x"]

    def test_the_balance_reason_reaches_the_coverage_event(self, tmp_path):
        states = _states((FAV, "a"))
        bal = _Bal(spendable=0, may_spend=False, reason="balance UNKNOWN and a reserve is set")
        out, _ = _run(tmp_path, states, _Provider(), balance=bal)
        events.reset()
        events.configure(tmp_path)
        try:
            report(FAV, out[FAV], balance=bal)
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        unq = [r for r in recs if r["measure"] == "shodan_pivots_unqueried"][0]
        assert "reserve is set" in unq["reason"]


# ── review r1: failures and balance classes must reach RECONCILIATION, not just dictionaries ──────
class TestFoldedVerdict:
    """The earlier "gaps dominate" tests inspected LaneOutcome dicts — the event stream read clean while
    the dictionaries looked right. These drive a REAL ShodanBalance and assert the folded verdict."""

    def _fold(self, tmp_path, states, provider, balance, max_pages=0):
        from quarry_recon import contract
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        try:
            out, _led = _run(tmp_path, states, provider, balance=balance, max_pages=max_pages)
            for lane, o in out.items():
                contract.run_provider(lane, lambda: set(), work_unit=f"wu-{lane}")
                report(lane, o, balance=balance, max_pages=max_pages)
            run.write_manifest({}, ["probe"])
            return json.loads(run.manifest_path.read_text())["summary"], out
        finally:
            events.reset()

    def _bal(self, **kw):
        from quarry_recon.phases.probe import shodan_balance
        return shodan_balance(kw.pop("doc", {"query_credits": 50}), **kw)

    def test_a_transport_failure_is_a_GAP_in_the_folded_output(self, tmp_path):
        """The reproduction: fail_classes={'transport': 1} while every emitted counter read 0 omitted."""
        s, out = self._fold(tmp_path, _states((FAV, "boom")),
                            _Provider(errors={"boom": _err("transport")}), self._bal())
        assert out[FAV].fail_classes.get("transport") == 1
        assert s["verdict"] == "complete_with_gaps", (s["gaps"], s["coverage"])

    def test_quota_ALONE_is_a_limit(self, tmp_path):
        s, _out = self._fold(tmp_path, _states((FAV, "spent")),
                             _Provider(errors={"spent": _err("quota")}), self._bal())
        assert s["verdict"] == "complete_with_limits", (s["gaps"], s["failures"])

    def test_a_read_gap_PLUS_an_operator_limit_still_reads_as_a_gap(self, tmp_path):
        """THE regression carried from B1.2: an unreadable /api-info with a reserve set stops us for an
        operator reason, but the failed read is real and must dominate."""
        from quarry_recon.phases.probe import SHODAN_UNKNOWN_WITH_RESERVE
        import dataclasses
        bal = dataclasses.replace(self._bal(doc=None, reserve=10), read_error="transport")
        assert bal.stop_kind == SHODAN_UNKNOWN_WITH_RESERVE and bal.may_spend is False
        s, _out = self._fold(tmp_path, _states((FAV, "a"), (CERT, "x")), _Provider(), bal)
        assert s["verdict"] == "complete_with_gaps", (s["gaps"], s["coverage"])

    def test_an_operator_reserve_ALONE_is_a_limit_not_a_gap(self, tmp_path):
        """The control for the case above: the same stop WITHOUT a failed read is a soft limit."""
        bal = self._bal(doc={"query_credits": 5}, reserve=10)
        s, _out = self._fold(tmp_path, _states((FAV, "a")), _Provider(), bal)
        assert s["verdict"] == "complete_with_limits", (s["gaps"], s["failures"])

    def test_a_bad_key_is_a_gap_not_a_limit(self, tmp_path):
        import dataclasses
        from quarry_recon.phases.probe import SHODAN_AUTH_REFUSED
        bal = dataclasses.replace(self._bal(doc=None), read_error="auth", may_spend=False,
                                  spendable=0, stop_kind=SHODAN_AUTH_REFUSED)
        s, _out = self._fold(tmp_path, _states((FAV, "a")), _Provider(), bal)
        assert s["verdict"] == "complete_with_gaps"

    def test_an_operator_page_policy_is_OUR_CAP(self, tmp_path):
        """review-B1 (Lumpy): "SHODAN_MAX_PAGES=1 is still a cap". It was emitted as a soft SAMPLE, which
        let a run that never looked past its page policy fold as `complete_with_limits` — a hard ceiling
        WE imposed, reported as somebody else's boundary."""
        s, out = self._fold(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                            self._bal(), max_pages=2)
        assert out[FAV].pages_withheld == 3
        assert s["verdict"] == "complete_with_gaps", (s["gaps"], s["failures"])

    def test_unpersisted_state_is_a_gap(self, tmp_path):
        from quarry_recon import contract
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.reset()
        events.configure(run.dir)
        try:
            contract.run_provider(FAV, lambda: set(), work_unit="wu")
            report(FAV, LaneOutcome(lane=FAV, pivots=1), balance=self._bal(), persisted=False)
            run.write_manifest({}, ["probe"])
            s = json.loads(run.manifest_path.read_text())["summary"]
        finally:
            events.reset()
        assert s["verdict"] == "complete_with_gaps"


# ── review r2: a malformed recorded page is not a completion ──────────────────────────────────────
class TestGhostCompletions:
    @pytest.mark.parametrize("doc", [
        {}, {"schema": 1}, {"schema": 2, "lane": FAV, "facet": "facet", "value": "a", "page": 1,
                            "matches": []},
        {"schema": 1, "lane": CERT, "facet": "facet", "value": "a", "page": 1, "matches": []},
        {"schema": 1, "lane": FAV, "facet": "other", "value": "a", "page": 1, "matches": []},
        {"schema": 1, "lane": FAV, "facet": "facet", "value": "b", "page": 1, "matches": []},
        {"schema": 1, "lane": FAV, "facet": "facet", "value": "a", "page": 2, "matches": []},
        {"schema": 1, "lane": FAV, "facet": "facet", "value": "a", "page": True, "matches": []},
        {"schema": 1, "lane": FAV, "facet": "facet", "value": "a", "page": 1, "matches": "nope"},
        {"schema": 1, "lane": FAV, "facet": "facet", "value": "a", "page": 1, "matches": [],
         "total": -1},
        {"schema": 1, "lane": FAV, "facet": "facet", "value": "a", "page": 1, "matches": [],
         "total": True},
    ])
    def test_an_artifact_that_does_not_identify_itself_is_rejected(self, doc):
        assert valid_page(doc, Pivot(FAV, "facet", "a"), 1) is None

    def test_a_valid_page_is_accepted(self):
        from quarry_recon.shodan_sched import SHODAN_WORK_SCHEMA
        doc = {"schema": SHODAN_WORK_SCHEMA, "lane": FAV, "facet": "facet", "value": "a", "page": 1,
               "total": 5, "matches": [], "bought_at": 1.0}
        assert valid_page(doc, Pivot(FAV, "facet", "a"), 1) is doc

    def test_a_PREVIOUS_generation_page_is_not_accepted(self):
        """A schema bump ISOLATES the older generation rather than deleting it: paid evidence is never
        pruned automatically, but it also cannot answer for a schema it was not written under."""
        from quarry_recon.shodan_sched import SHODAN_WORK_SCHEMA
        doc = {"schema": SHODAN_WORK_SCHEMA - 1, "lane": FAV, "facet": "facet", "value": "a", "page": 1,
               "total": 5, "matches": []}
        assert valid_page(doc, Pivot(FAV, "facet", "a"), 1) is None

    def test_a_DIGEST_VALID_ghost_page_is_rejected_and_re_bought(self, tmp_path):
        """A digest-bound `{}` was replayed forever: never re-bought, contributing nothing.

        NB the artifact must be digest-VALID, or the Ledger rejects it at load and the coordinator's own
        validation is never reached — an earlier version of this test corrupted the file and so proved
        only that the digest binding works (it does; that is a different guard)."""
        import hashlib as _h
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        key = item_key(Pivot(FAV, "facet", "a"), 1)
        ghost = d / f"{key}.json"
        body = b"{}"                                          # well-formed JSON, identifies NOTHING
        ghost.write_bytes(body)
        led.record(key, ghost, digest=_h.sha256(body).hexdigest())
        led.save()

        led2 = _ledger(tmp_path)
        assert led2.has(key), "the ghost must survive the digest check — that is the point"
        p2 = _Provider(totals={"a": 3})
        out, _ = _run(tmp_path, _states((FAV, "a")), p2, balance=_Bal(spendable=None), ledger=led2)
        assert out[FAV].pages_replayed == 0                   # NOT a completion
        assert out[FAV].evidence_invalid == 1                 # counted as unusable evidence
        assert p2.calls == [(FAV, "a", 1)]                    # and bought again

    def test_a_corrupted_artifact_is_caught_by_the_digest_binding(self, tmp_path):
        """The other guard, kept distinct: a MODIFIED file never even reaches valid_page."""
        led = _ledger(tmp_path)
        _run(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 3}),
             balance=_Bal(spendable=None), ledger=led)
        led.artifact(item_key(Pivot(FAV, "facet", "a"), 1)).write_text("{}")
        led2 = _ledger(tmp_path)
        assert not led2.has(item_key(Pivot(FAV, "facet", "a"), 1))


# ── review r3: paid completion must be durable ────────────────────────────────────────────────────
class TestDurability:
    def test_persistence_result_is_reported(self, tmp_path):
        """Both facts must fail before the run is unresumable: a failed snapshot ALONE is survivable,
        because the journal is replayed at load. (The earlier version asserted `persisted is False` on a
        failed save alone — the FALSE gap review-r4#1 identified.)"""
        from quarry_recon.shodan_sched import run_work
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        led.save = lambda: False
        led._journal_lost = True                              # neither snapshot nor journal survives
        res = run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=None),
                       search=_Provider().search, ingest=lambda *a: 0, ledger=led, attempt_dir=d)
        assert res.persisted is False

    def test_persistence_runs_even_when_the_body_raises(self, tmp_path):
        """review-B1.7a: this used to assert the exception PROPAGATES. It does not any more — the caller
        then fabricated `attempted=0` over pages the run had already bought. Persistence still runs, and
        now the outcome survives with the failure named."""
        from quarry_recon.shodan_sched import run_work
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        saved = []
        real = led.save
        led.save = lambda: (saved.append(1), real())[1]

        def boom(pivot, page):
            raise RuntimeError("search exploded")

        res = run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=None), search=boom,
                       ingest=lambda *a: 0, ledger=led, attempt_dir=d)
        assert saved, "completion state was not persisted on the failure path"
        assert res.stop_cause == "machinery:RuntimeError", res.stop_cause
        assert res.machinery == ["RuntimeError: search exploded"], res.machinery
        assert res.lanes[FAV].unqueried == ["a"], "the remainder was lost with the exception"

    def test_a_failed_publish_is_not_recorded_as_bought(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        from quarry_recon.shodan_sched import run_work
        monkeypatch.setattr(_b, "publish_bytes", _publish_pages_fail(_b))
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        res = run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=3),
                       search=_Provider().search, ingest=lambda *a: 0, ledger=led, attempt_dir=d)
        o = res.lanes[FAV]
        assert o.pages_bought == 0 and o.publish_failed >= 1
        assert not led.has(item_key(Pivot(FAV, "facet", "a"), 1))


# ── review r4: breadth-first must survive RESUME ──────────────────────────────────────────────────
class TestBreadthFirstOnResume:
    def test_an_untouched_pivot_outranks_a_resumed_pivots_later_page(self):
        """The reproduction: `a` holding pages 1-2 took page 3 before untouched `b` got page 1."""
        a = PivotState(Pivot(FAV, "facet", "a"), total=500)
        a.pages_done.update({1, 2})
        b = PivotState(Pivot(FAV, "facet", "b"))
        order = [(st.pivot.value, pg) for st, pg in schedule([a, b])]
        assert order[0] == ("b", 1), order

    def test_page_tier_outranks_lane_fairness(self):
        a = PivotState(Pivot(FAV, "facet", "a"), total=500)
        a.pages_done.add(1)
        x = PivotState(Pivot(CERT, "facet", "x"))
        order = [(st.pivot.value, pg) for st, pg in schedule([a, x])]
        assert [pg for _v, pg in order] == [1, 2]

    def test_within_a_page_tier_lanes_still_alternate(self):
        sts = [PivotState(Pivot(FAV, "f", "a")), PivotState(Pivot(FAV, "f", "b")),
               PivotState(Pivot(CERT, "f", "x"))]
        lanes = [st.pivot.lane for st, _pg in schedule(sts)]
        assert lanes[0] != lanes[1]

    def test_a_resumed_run_buys_page_ones_first(self, tmp_path):
        led = _ledger(tmp_path)
        _run(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
             balance=_Bal(spendable=2), ledger=led)
        p2 = _Provider(totals={"a": 500, "fresh": 50})
        _run(tmp_path, _states((FAV, "a"), (FAV, "fresh")), p2, balance=_Bal(spendable=2), ledger=led)
        assert p2.calls[0] == (FAV, "fresh", 1), p2.calls


# ── review r5: max_pages is an operator policy, never a silent cap ─────────────────────────────────
class TestWithheldPagesAreVisible:
    def test_withheld_pages_are_counted(self, tmp_path):
        out, _ = _run(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=None), max_pages=2)
        o = out[FAV]
        assert o.pages_bought == 2 and o.pages_withheld == 3 and o.pages_left_known == 0

    def test_no_policy_withholds_nothing(self, tmp_path):
        out, _ = _run(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=None))
        assert out[FAV].pages_withheld == 0 and out[FAV].pages_bought == 5

    def test_withheld_pages_are_emitted_as_OUR_CAP(self, tmp_path):
        out, _ = _run(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=None), max_pages=2)
        events.reset()
        events.configure(tmp_path)
        try:
            report(FAV, out[FAV], balance=_Bal(), max_pages=2)
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        w = [r for r in recs if r["measure"] == "shodan_pages_withheld"][0]
        assert w["omitted"] == 3 and w["kind"] == "cap"


# ── review r6/r7: cursor + duplicate identities ───────────────────────────────────────────────────
class TestCursorAndDuplicates:
    def test_next_page_does_not_rescan_the_completed_prefix(self):
        st = PivotState(Pivot(FAV, "f", "huge"), total=10_000_000)
        st.pages_done.update(range(1, 50_001))
        seen = []
        real = st.pages_done.__contains__

        class _Counting(set):
            def __contains__(self, x):
                seen.append(x)
                return real(x)

        st.pages_done = _Counting(st.pages_done)
        st.next_page()                                # the prefix is walked ONCE, ever
        seen.clear()
        for _ in range(5):
            st.next_page()
        # the cursor is monotonic: subsequent calls must not re-walk the 50k prefix
        assert len(seen) < 20, len(seen)

    def test_duplicate_pivots_are_bought_once(self, tmp_path):
        states = _states((FAV, "a"), (FAV, "a"), (FAV, "a"))
        p = _Provider()
        out, _ = _run(tmp_path, states, p, balance=_Bal(spendable=None))
        assert p.calls == [(FAV, "a", 1)]
        assert out[FAV].pivots == 1

    def test_dedupe_keeps_distinct_identities(self):
        sts = [PivotState(Pivot(FAV, "f", "a")), PivotState(Pivot(CERT, "f", "a")),
               PivotState(Pivot(FAV, "g", "a")), PivotState(Pivot(FAV, "f", "b")),
               PivotState(Pivot(FAV, "f", "a"))]
        assert len(dedupe(sts)) == 4


# ── review r2: the paid-work transitions ──────────────────────────────────────────────────────────
def _res(tmp_path, states, provider, balance=None, max_pages=0, ledger=None, ingested=None):
    """Like _run but hands back the WHOLE WorkResult (stop_cause included)."""
    from quarry_recon.shodan_sched import run_work
    d = tmp_path / "attempts"
    d.mkdir(parents=True, exist_ok=True)
    led = ledger if ledger is not None else _ledger(tmp_path)

    def ingest(pivot, page, matches, raw):
        if ingested is not None:
            ingested.append((pivot.value, page, len(matches)))
        return len(matches)

    return run_work(None, states=states, balance=balance or _Bal(), search=provider.search,
                    ingest=ingest, ledger=led, attempt_dir=d, max_pages=max_pages), led


class TestPublishFailureStopsPaying:
    """review-r2#1: a failed publish left the page PENDING, so the next round scheduled it again — the
    same page bought over and over, unbounded when the balance is unknown."""

    def test_a_page_is_not_bought_twice_after_a_publish_failure(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b, "publish_bytes", _publish_pages_fail(_b))
        p = _Provider()
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=3))
        assert p.calls == [(FAV, "a", 1)], p.calls
        assert res.lanes[FAV].publish_failed == 1 and res.lanes[FAV].pages_bought == 0

    def test_an_unbounded_balance_does_not_loop_forever(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b, "publish_bytes", _publish_pages_fail(_b))
        p = _Provider()
        res, _ = _res(tmp_path, _states((FAV, "a"), (FAV, "b")), p, balance=_Bal(spendable=None))
        assert len(p.calls) == 1                     # an unwritable store is a GLOBAL stop
        assert res.stop_cause == "publish_failed"

    def test_a_publish_failure_is_a_GAP_not_a_limit(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b, "publish_bytes", _publish_pages_fail(_b))
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(), balance=_Bal(spendable=None))
        events.reset()
        events.configure(tmp_path)
        try:
            report(FAV, res.lanes[FAV], balance=_Bal(), stop_cause=res.stop_cause)
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        assert [r for r in recs if r["measure"] == "shodan_pivots_unqueried"][0]["kind"] == "timeout"


class TestFreshOutputIsValidatedToo:
    """review-r2#2: replayed evidence was validated and FRESH output was not — the coordinator trusted
    the network more than its own disk."""

    def test_a_missing_total_is_a_failure_not_a_completed_page(self, tmp_path):
        class _Bad:
            calls = []

            def search(self, pivot, page):
                self.calls.append((pivot.lane, pivot.value, page))
                return [], None, None                # answered, but not with a page

        b = _Bad()
        res, led = _res(tmp_path, _states((FAV, "a")), b, balance=_Bal(spendable=2))
        o = res.lanes[FAV]
        assert o.pages_bought == 0 and o.fail_classes.get("parse") == 1
        assert not led.has(item_key(Pivot(FAV, "facet", "a"), 1))

    @pytest.mark.parametrize("matches,total", [([], None), ([], -1), ([], True), ([], "5"),
                                               ("nope", 5), (None, 5)])
    def test_invalid_fresh_output_is_rejected(self, matches, total):
        from quarry_recon.shodan_sched import valid_fresh
        assert valid_fresh(matches, total) is False

    def test_valid_fresh_output_is_accepted(self):
        from quarry_recon.shodan_sched import valid_fresh
        assert valid_fresh([], 0) is True and valid_fresh([{"hostnames": []}], 1) is True

    def test_a_rejected_page_leaves_no_ghost_completion(self, tmp_path):
        class _Bad:
            def search(self, pivot, page):
                return [], None, None

        res, _ = _res(tmp_path, _states((FAV, "a")), _Bad(), balance=_Bal(spendable=1))
        assert res.lanes[FAV].pages_left_unknown_pivots == 0     # nothing was marked owned


class TestReplayHoles:
    """review-r2#3: replay stopped at the first hole, so a damaged page 1 with a good page 2 behind it
    caused BOTH to be bought again."""

    def _own(self, led, tmp_path, value, page, total, matches):
        import hashlib as _h
        from quarry_recon.shodan_sched import _page_doc
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        pv = Pivot(FAV, "facet", value)
        raw = d / f"{item_key(pv, page)}.json"
        body = json.dumps(_page_doc(pv, page, total, matches)).encode()
        raw.write_bytes(body)
        led.record(item_key(pv, page), raw, digest=_h.sha256(body).hexdigest())

    def test_a_valid_later_page_is_replayed_not_repurchased(self, tmp_path):
        led = _ledger(tmp_path)
        self._own(led, tmp_path, "a", 2, 500, [{"hostnames": ["x.acme.com"]}])   # page 2 only
        led.save()
        led2 = _ledger(tmp_path)
        p = _Provider(totals={"a": 500})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=None), ledger=led2)
        bought = [pg for _l, _v, pg in p.calls]
        assert 2 not in bought, f"page 2 was owned and should not be bought again: {p.calls}"
        assert res.lanes[FAV].pages_replayed >= 1

    def test_the_hole_itself_is_still_bought(self, tmp_path):
        led = _ledger(tmp_path)
        self._own(led, tmp_path, "a", 2, 500, [])
        led.save()
        p = _Provider(totals={"a": 500})
        _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=None), ledger=_ledger(tmp_path))
        assert (FAV, "a", 1) in p.calls


class TestStopCauseAttribution:
    """review-r2#4: attribution consulted only the BALANCE, which cannot know how the run ended."""

    def test_a_positive_reserve_reached_is_an_OPERATOR_sample(self, tmp_path):
        res, _ = _res(tmp_path, _states((FAV, "a"), (FAV, "b"), (FAV, "c")), _Provider(),
                      balance=_Bal(spendable=2, reserve=1))
        assert res.stop_cause == "budget_reserve"
        events.reset()
        events.configure(tmp_path)
        try:
            report(FAV, res.lanes[FAV], balance=_Bal(reserve=1), stop_cause=res.stop_cause)
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        assert [r for r in recs if r["measure"] == "shodan_pivots_unqueried"][0]["kind"] == "sample"

    def test_a_zero_reserve_exhaustion_is_the_PROVIDER_boundary(self, tmp_path):
        res, _ = _res(tmp_path, _states((FAV, "a"), (FAV, "b")), _Provider(),
                      balance=_Bal(spendable=1, reserve=0))
        assert res.stop_cause == "budget_provider"

    def test_a_mid_flight_quota_is_a_provider_limit(self, tmp_path):
        states = _states((FAV, "a"), (FAV, "b"))
        first = schedule(states)[0][0].pivot.value
        res, _ = _res(tmp_path, states, _Provider(errors={first: _err("quota")}),
                      balance=_Bal(spendable=None))
        assert res.stop_cause == "provider_limit:quota"

    def test_pages_left_after_a_FAILURE_are_a_gap_not_a_provider_limit(self, tmp_path):
        """The aggregate kind used to label known pages left after a transport failure as
        provider-limited — blaming the balance for something that broke."""
        p = _Provider(totals={"a": 500}, errors={("a", 2): _err("transport")})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=None))
        events.reset()
        events.configure(tmp_path)
        try:
            report(FAV, res.lanes[FAV], balance=_Bal(), stop_cause=res.stop_cause)
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        assert [r for r in recs if r["measure"] == "shodan_pages_left"][0]["kind"] == "timeout"

    def test_nothing_stopped_us_leaves_no_cause(self, tmp_path):
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(), balance=_Bal(spendable=None))
        assert res.stop_cause == ""


class TestWithheldExcludesOwnedPages:
    """review-r2#5: `withheld_pages` ignored what we already own, so lowering max_pages reported COMPLETE
    coverage as withheld and produced complete_with_limits."""

    def test_lowering_max_pages_does_not_invent_a_limit(self, tmp_path):
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
             balance=_Bal(spendable=None), ledger=led)
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=None), ledger=_ledger(tmp_path), max_pages=2)
        o = res.lanes[FAV]
        assert o.pages_replayed == 5 and o.pages_withheld == 0, (o.pages_replayed, o.pages_withheld)

    def test_partially_owned_pages_are_counted_correctly(self, tmp_path):
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
             balance=_Bal(spendable=3), ledger=led)                 # own pages 1-3
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=None), ledger=_ledger(tmp_path), max_pages=2)
        assert res.lanes[FAV].pages_withheld == 2                   # pages 4-5 only

    def test_unowned_policy_pages_are_still_withheld(self, tmp_path):
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=None), max_pages=2)
        assert res.lanes[FAV].pages_withheld == 3


class TestAPageIsNeverPaidForTwice:
    """A structural guard, not an optimisation: any bug leaving a page pending after purchase turns the
    round loop into an unbounded spend. It also keeps such a bug FAILING rather than HANGING — the
    publish-failure regression looped forever before this existed, and a hang is worse than a failure."""

    def test_the_same_page_is_requested_at_most_once_per_run(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b, "publish_bytes", _publish_pages_fail(_b))
        p = _Provider()
        _res(tmp_path, _states((FAV, "a"), (FAV, "b")), p, balance=_Bal(spendable=None))
        assert len(p.calls) == len(set(p.calls)), p.calls

    def test_the_loop_terminates_even_when_nothing_can_be_recorded(self, tmp_path, monkeypatch):
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b, "publish_bytes", _publish_pages_fail(_b))
        p = _Provider()
        res, _ = _res(tmp_path, _states(*[(FAV, f"f{i}") for i in range(5)]), p,
                      balance=_Bal(spendable=None))
        assert len(p.calls) <= 5 and res.stop_cause


# ── review r3: durability, ghost totals, orphaned evidence, window counting, a loud guard ─────────
class TestLedgerWritabilityIsAPrecondition:
    """review-r3#1: writability was checked only AFTER every purchase, so a foreign ledger let a run buy
    15 pages and report `persisted=False` — and the next lifecycle bought all 15 again."""

    def _foreign(self, tmp_path):
        """A state file belonging to ANOTHER lane: Ledger refuses to write it."""
        other = budget.state_path(tmp_path, "someone.else", "fp0")
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_text(json.dumps({"lane": "someone.else", "done": {}, "digests": {}}))
        led = budget.Ledger(other, lane="shodan.work")
        assert led.foreign, "fixture must produce a foreign ledger"
        return led

    def test_no_credit_is_spent_on_an_unwritable_ledger(self, tmp_path):
        p = _Provider()
        res, _ = _res(tmp_path, _states(*[(FAV, f"f{i}") for i in range(5)]), p,
                      balance=_Bal(spendable=None), ledger=self._foreign(tmp_path))
        assert p.calls == [], "paid for work that could never be recorded"
        assert res.stop_cause == "ledger_unwritable" and res.persisted is False

    def test_replay_still_happens_on_an_unwritable_ledger(self, tmp_path):
        """Reading costs nothing — a broken store must not also lose what we already own."""
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 5}),
             balance=_Bal(spendable=None), ledger=led)
        seen = []
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(), balance=_Bal(spendable=0),
                      ledger=_ledger(tmp_path), ingested=seen)
        assert seen and res.lanes[FAV].pages_replayed == 1

    def test_a_journal_that_dies_MID_RUN_stops_further_purchases(self, tmp_path):
        """The precondition only covers a ledger that was broken from the start. A journal can also go
        unusable partway — and every page bought after that point is money spent on a record that will
        not survive the run."""
        led = _ledger(tmp_path)
        real_record = led.record

        def record_then_break(key, art, digest=None):
            real_record(key, art, digest=digest)
            led._journal_unsafe = True                   # the append path is gone from here on

        led.record = record_then_break
        p = _Provider()
        res, _ = _res(tmp_path, _states(*[(FAV, f"f{i}") for i in range(5)]), p,
                      balance=_Bal(spendable=None), ledger=led)
        assert len(p.calls) == 1, f"kept buying after the journal died: {p.calls}"
        assert res.stop_cause == "ledger_unwritable"

    def test_an_unwritable_ledger_is_a_GAP(self, tmp_path):
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(), balance=_Bal(spendable=None),
                      ledger=self._foreign(tmp_path))
        events.reset()
        events.configure(tmp_path)
        try:
            report(FAV, res.lanes[FAV], balance=_Bal(), persisted=res.persisted,
                   stop_cause=res.stop_cause)
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        assert [r for r in recs if r["measure"] == "shodan_pivots_unqueried"][0]["kind"] == "timeout"


class TestReplayTotalContract:
    """review-r3#2: `total: null` was accepted on replay while fresh output required an exact int — the
    ghost completion, recreated one layer over."""

    def test_a_null_total_page_is_not_a_completion(self, tmp_path):
        import hashlib as _h
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        pv = Pivot(FAV, "facet", "a")
        body = json.dumps({"schema": 1, "lane": FAV, "facet": "facet", "value": "a", "page": 1,
                           "total": None, "matches": []}).encode()
        raw = d / f"{item_key(pv, 1)}.json"
        raw.write_bytes(body)
        led.record(item_key(pv, 1), raw, digest=_h.sha256(body).hexdigest())
        led.save()
        p = _Provider(totals={"a": 3})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=None),
                      ledger=_ledger(tmp_path))
        assert res.lanes[FAV].pages_replayed == 0
        assert res.lanes[FAV].evidence_invalid == 1
        assert p.calls == [(FAV, "a", 1)]                 # bought again, with a real total
        assert res.lanes[FAV].pages_left_unknown_pivots == 0

    @pytest.mark.parametrize("total", [None, -1, True, "5", 1.5])
    def test_replay_and_fresh_share_the_total_contract(self, total):
        from quarry_recon.shodan_sched import valid_fresh
        doc = {"schema": 1, "lane": FAV, "facet": "facet", "value": "a", "page": 1,
               "total": total, "matches": []}
        assert valid_page(doc, Pivot(FAV, "facet", "a"), 1) is None
        assert valid_fresh([], total) is False


class TestOwnedEvidenceSurvivesAFailedRepair:
    """review-r3#3: a failed page-1 repair set `stopped`, which removed the pivot from scheduling, which
    hid an owned page 2 that had ALREADY BEEN PAID FOR."""

    def test_page_two_is_replayed_even_when_page_one_fails(self, tmp_path):
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
             balance=_Bal(spendable=3), ledger=led)                  # own pages 1-3
        # destroy page 1 only; pages 2-3 stay owned and valid
        led2 = _ledger(tmp_path)
        led2.artifact(item_key(Pivot(FAV, "facet", "a"), 1)).write_text("{}")
        seen = []
        p = _Provider(totals={"a": 500}, errors={("a", 1): _err("transport")})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=None),
                      ledger=_ledger(tmp_path), ingested=seen)
        assert res.lanes[FAV].pages_replayed >= 2, "paid-for pages 2-3 were lost"
        assert seen, "retained findings were never ingested"

    def test_the_LEDGER_itself_reports_what_is_owned(self, tmp_path):
        """review-r4#2/#3/#4: the separate index snapshot is gone. It was quadratic, published a MUTABLE
        artifact through a content-addressed primitive (a failed update deleted the last good copy), and
        was a second source of truth that could go stale or fail open. The ledger already is an
        append-only, digest-bound, per-page ownership record."""
        from quarry_recon.shodan_sched import owned_index
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
             balance=_Bal(spendable=3), ledger=led)
        idx = owned_index(_ledger(tmp_path))
        assert _pages(idx) == {(FAV, "facet", "a"): [1, 2, 3]}
        # the validated DOCUMENT rides along, so replay never re-reads the artifact (review-r6#2)
        assert [d["page"] for _pg, _art, d in idx[(FAV, "facet", "a")]] == [1, 2, 3]

    def test_an_unowned_pivot_reports_nothing(self, tmp_path):
        from quarry_recon.shodan_sched import owned_index
        assert owned_index(_ledger(tmp_path)).get((FAV, "facet", "nope")) is None

    def test_a_hole_of_ANY_width_still_yields_the_page_above_it(self, tmp_path):
        """review-r5#1, the reviewer's own reproduction: own pages 1-6, damage 1-5. Page 6 is still valid
        in the ledger, so it must still be owned. A probe that walks up from page 1 and gives up after a
        fixed run of misses reported NOTHING here — paid evidence made invisible by a recovery cap."""
        from quarry_recon.shodan_sched import owned_index
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 600}),
             balance=_Bal(spendable=6), ledger=led)
        led2 = _ledger(tmp_path)
        for page in range(1, 6):
            led2.artifact(item_key(Pivot(FAV, "facet", "a"), page)).write_text("{}")
        assert _pages(owned_index(_ledger(tmp_path))) == {(FAV, "facet", "a"): [6]}

    def test_a_wide_hole_is_REPLAYED_not_repurchased(self, tmp_path):
        """Discovery is only worth anything if the run acts on it: page 6 must replay for free."""
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 600}),
             balance=_Bal(spendable=6), ledger=led)
        led2 = _ledger(tmp_path)
        for page in range(1, 6):
            led2.artifact(item_key(Pivot(FAV, "facet", "a"), page)).write_text("{}")
        seen = []
        p = _Provider(totals={"a": 600})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=None),
                      ledger=_ledger(tmp_path), ingested=seen)
        assert res.lanes[FAV].pages_replayed == 1, "the paid page above the hole was lost"
        assert ("a", 6) not in p.calls, f"re-bought a page we already owned: {p.calls}"

    def test_a_document_cannot_donate_ownership_to_a_key_it_was_not_filed_under(self, tmp_path):
        """The item key is recomputed from the document and must match the key it is stored under, so a
        transplanted artifact cannot make one pivot look like it owns another's page."""
        from quarry_recon.shodan_sched import owned_index
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 100}),
             balance=_Bal(spendable=1), ledger=led)
        art = led.artifact(item_key(Pivot(FAV, "facet", "a"), 1))
        led2 = _ledger(tmp_path)
        led2.record(item_key(Pivot(FAV, "facet", "b"), 1), art)   # same bytes, different identity
        led2.save()
        assert _pages(owned_index(_ledger(tmp_path))) == {(FAV, "facet", "a"): [1]}


class TestWindowCounting:
    """review-r3#4: `len(pages_done)` counted replayed pages from ABOVE the policy window, so a real hole
    inside it vanished."""

    def test_a_hole_inside_the_window_is_not_erased_by_pages_above_it(self, tmp_path):
        import hashlib as _h
        from quarry_recon.shodan_sched import _page_doc
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        pv = Pivot(FAV, "facet", "a")
        for page in (1, 3):                                          # page 2 deliberately missing
            body = json.dumps(_page_doc(pv, page, 500, [])).encode()
            raw = d / f"{item_key(pv, page)}.json"
            raw.write_bytes(body)
            led.record(item_key(pv, page), raw, digest=_h.sha256(body).hexdigest())
        led.save()
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=0, may_spend=False), ledger=_ledger(tmp_path),
                      max_pages=2)
        o = res.lanes[FAV]
        assert o.pages_replayed == 2
        assert o.pages_left_known == 1, "page 2 is missing inside the policy window"


class TestTheGuardIsLoud:
    """review-r3#5: the guard prevented a duplicate purchase but said nothing, so the loop ended with no
    cause and an unknown balance labelled the remainder a provider limit."""

    def test_hitting_the_guard_sets_a_defect_cause(self, tmp_path):
        from quarry_recon.shodan_sched import LaneOutcome, WorkResult, _work
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        # bypass dedupe deliberately: two states for ONE identity is exactly the invariant break
        pv = Pivot(FAV, "facet", "a")
        states = [PivotState(pv), PivotState(pv)]
        res = WorkResult()
        res.lanes[FAV] = LaneOutcome(lane=FAV, pivots=2)
        p = _Provider()

        # record SUCCEEDS (so durability does not stop us first); the duplicate state is what causes
        # the same page to be offered twice — the invariant break the guard exists for.
        led.record = lambda *a, **k: True
        _work(states, res, balance=_Bal(spendable=None), search=p.search, ingest=lambda *a: 0,
              ledger=led, attempt_dir=d, max_pages=0, is_limit=lambda c: False)
        assert res.stop_cause == "scheduler_invariant", res.stop_cause

    def test_the_invariant_cause_reads_as_a_GAP(self, tmp_path):
        events.reset()
        events.configure(tmp_path)
        try:
            report(FAV, LaneOutcome(lane=FAV, pivots=1), balance=_Bal(),
                   stop_cause="scheduler_invariant")
            recs = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        assert [r for r in recs if r["measure"] == "shodan_pivots_unqueried"][0]["kind"] == "timeout"


def _publish_pages_fail(mod):
    """Fail publishing PAGES while leaving the pre-flight write probe working — these tests are about a
    store that breaks mid-run, not one that was already unwritable (review-r7#2)."""
    real = mod.publish_bytes
    return lambda dest, data, digest: (False if str(dest).endswith(".json")
                                       else real(dest, data, digest=digest))


def _pages(index: dict) -> dict:
    """Just the page numbers — `owned_index` also carries each page's artifact and validated document."""
    return {k: [pg for pg, _art, _doc in v] for k, v in index.items()}


class TestRowContractOnReplay:
    """review-B1.5br3#1: the adapter learned to reject a non-string hostname member, but a page PAID FOR
    and RECORDED before that contract existed replayed straight past it. `valid_fresh` is the one gate
    both paths use, so the contract lives there — NOT in a schema bump, which would invalidate every
    page already bought, including the valid ones."""

    def test_a_malformed_recorded_page_is_NOT_owned(self, tmp_path):
        from quarry_recon.shodan_sched import owned_index, valid_fresh
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 100}), balance=_Bal(spendable=1),
             ledger=led)
        art = led.artifact(item_key(Pivot(FAV, "facet", "a"), 1))
        doc = json.loads(art.read_text())
        doc["matches"] = [{"hostnames": [None]}]              # what an OLD page could hold
        body = json.dumps(doc).encode()
        art.write_bytes(body)
        led2 = _ledger(tmp_path)
        led2.record(item_key(Pivot(FAV, "facet", "a"), 1), art)   # re-bind: digest-VALID, row-invalid
        led2.save()
        assert valid_fresh(doc["matches"], doc["total"]) is False
        assert owned_index(_ledger(tmp_path)) == {}, "a malformed page was still owned"

    def test_a_malformed_recorded_page_is_REFUSED_not_repurchased(self, tmp_path):
        """DOCTRINE CHANGE (Lumpy, review#1, 2026-08-05). This test previously asserted the opposite:
        a recorded page whose rows are malformed was BOUGHT AGAIN. Acquisition is now committed
        separately from interpretation, so the receipt for that purchase survives the page's contents —
        and a receipt without a usable page is evidence loss plus a refused repair, never permission to
        spend. The page stays unusable; what changed is who pays for that."""
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 100}), balance=_Bal(spendable=1),
             ledger=led)
        art = led.artifact(item_key(Pivot(FAV, "facet", "a"), 1))
        doc = json.loads(art.read_text())
        doc["matches"] = [{"hostnames": [None]}]
        art.write_bytes(json.dumps(doc).encode())
        led2 = _ledger(tmp_path)
        led2.record(item_key(Pivot(FAV, "facet", "a"), 1), art)
        led2.save()
        p = _Provider(totals={"a": 100})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=None),
                      ledger=_ledger(tmp_path))
        assert p.calls == [], "a page this project already paid for must never be re-bought"
        o = res.lanes[FAV]
        assert o.pages_bought == 0
        assert o.pages_lost == 1 and o.repair_refused == 1 and o.acquisition_refused == 1

    def test_a_VALID_recorded_page_still_replays_FREE(self, tmp_path):
        """The control that keeps the fix from being a schema bump in disguise."""
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 100}), balance=_Bal(spendable=1),
             ledger=led)
        p = _Provider(totals={"a": 100})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=None),
                      ledger=_ledger(tmp_path))
        assert p.calls == [], f"a valid paid page was re-bought: {p.calls}"
        assert res.lanes[FAV].pages_replayed == 1

    def test_a_non_dict_row_is_rejected_on_BOTH_paths(self):
        from quarry_recon.shodan_sched import valid_fresh
        assert valid_fresh([None], 1) is False
        assert valid_fresh([{"hostnames": "oops"}], 1) is False
        assert valid_fresh([{"hostnames": [1]}], 1) is False
        assert valid_fresh([{"hostnames": ["ok.acme.com"]}], 1) is True
        assert valid_fresh([{"hostnames": None}], 1) is True      # absent is fine
        assert valid_fresh([{}], 1) is True


class TestCardinalityOrdering:
    """B1.5: /host/count sizes pivots. Cardinality orders work and NEVER removes, caps, or completes it."""

    def _sched(self, states, **kw):
        from quarry_recon.shodan_sched import schedule
        return [(st.pivot.lane, st.pivot.value, pg) for st, pg in schedule(states, **kw)]

    def _st(self, lane, value, card=None, total=None, done=()):
        s = PivotState(Pivot(lane, "facet", value), total=total)
        s.cardinality = card
        for pg in done:
            s.pages_done.add(pg)
        return s

    def test_rare_pivots_run_before_generic_ones(self, tmp_path):
        got = self._sched([self._st(FAV, "generic", 500000), self._st(FAV, "rare", 12),
                           self._st(FAV, "mid", 900)])
        assert [v for _l, v, _p in got] == ["rare", "mid", "generic"]

    def test_ordering_never_changes_MEMBERSHIP(self, tmp_path):
        states = [self._st(FAV, "generic", 5000000), self._st(FAV, "rare", 1)]
        assert len(self._sched(states)) == 2, "a pivot was dropped by ranking"

    def test_PAGE_TIER_still_outranks_cardinality(self, tmp_path):
        """Breadth before depth: every pivot's page 1 precedes any pivot's page 2, however rare."""
        rare_deep = self._st(FAV, "rare", 1, total=500, done=(1,))
        generic_shallow = self._st(FAV, "generic", 500000)
        got = self._sched([rare_deep, generic_shallow])
        assert got == [(FAV, "generic", 1), (FAV, "rare", 2)], got

    def test_lanes_still_alternate_within_a_page_tier(self, tmp_path):
        """review-B1.5: cardinality must not enter the rank TIER — that would bucket almost every pivot
        alone and collapse cross-lane fairness into a global cardinality sort."""
        got = self._sched([self._st(FAV, "f1", 10), self._st(FAV, "f2", 20),
                           self._st(CERT, "c1", 15), self._st(CERT, "c2", 25)])
        assert [l for l, _v, _p in got] == [CERT, FAV, CERT, FAV], got
        assert [v for _l, v, _p in got] == ["c1", "f1", "c2", "f2"], got

    def test_an_UNSIZED_pivot_is_ordered_last_but_never_dropped(self, tmp_path):
        got = self._sched([self._st(FAV, "unknown", None), self._st(FAV, "generic", 999999)])
        assert [v for _l, v, _p in got] == ["generic", "unknown"], got

    def test_unsized_pivots_are_ordered_DETERMINISTICALLY(self, tmp_path):
        a = self._sched([self._st(FAV, "b", None), self._st(FAV, "a", None)])
        b = self._sched([self._st(FAV, "a", None), self._st(FAV, "b", None)])
        assert a == b == [(FAV, "a", 1), (FAV, "b", 1)]


class TestCardinalityFold:
    def _fold(self, st):
        from quarry_recon.shodan_sched import LaneOutcome, WorkResult, _apply_cardinality
        res = WorkResult()
        res.lanes[st.pivot.lane] = LaneOutcome(lane=st.pivot.lane, pivots=1)
        _apply_cardinality([st], res)
        return st, res.lanes[st.pivot.lane]

    def test_an_UNQUERIED_pivot_gets_no_phantom_remainder(self):
        """The boundary: a count may order a pivot we have never bought, and may NOT give it a page
        count — it would report as `unqueried` AND as "N pages left" over a denominator no page proved."""
        st = PivotState(Pivot(FAV, "facet", "a"))
        st.cardinality = 500
        st, o = self._fold(st)
        assert st.total is None and st.effective_total() is None and st.page_count() is None
        assert o.count_compared == 0 and o.count_drift == 0

    def test_a_HIGHER_count_EXPANDS_a_known_remainder(self):
        """Growth beyond a completed pagination: yesterday's total is not permanent. The PAGE total is
        left intact — only the EFFECTIVE total grows (review-B1.5r1#1)."""
        st = PivotState(Pivot(FAV, "facet", "a"), total=100)
        st.pages_done.add(1)
        st.cardinality = 500
        st, o = self._fold(st)
        assert st.total == 100, "the count contaminated the page-derived total"
        assert st.effective_total() == 500 and st.page_count() == 5
        assert st.next_page() == 2, "the newly known pages are not schedulable"
        assert o.count_drift == 1 and o.count_compared == 1

    def test_a_LOWER_count_keeps_the_MAXIMUM(self):
        st = PivotState(Pivot(FAV, "facet", "a"), total=500)
        st.pages_done.add(1)
        st.cardinality = 100
        st, o = self._fold(st)
        assert st.total == 500 and st.effective_total() == 500 and o.count_drift == 1

    def test_an_AGREEING_count_is_not_drift(self):
        st = PivotState(Pivot(FAV, "facet", "a"), total=300)
        st.cardinality = 300
        st, o = self._fold(st)
        assert st.total == 300 and o.count_drift == 0 and o.count_compared == 1

    def test_a_count_does_NOT_make_two_agreeing_pages_look_like_DRIFT(self, tmp_path):
        """review-B1.5r1#1, reproduction one: page 1 says 100, the count says 500, page 2 says 100. The
        pages agree with each other; only the COUNT disagrees, and each fact must be reported as itself."""
        led = _ledger(tmp_path)
        states = _states((FAV, "a"))
        states[0].cardinality = 500
        p = _Provider(totals={"a": 100})
        res, _ = _res(tmp_path, states, p, balance=_Bal(spendable=None), ledger=led)
        o = res.lanes[FAV]
        assert o.total_drift == 0, "two agreeing pages were reported as drifting"
        assert o.count_drift == 1 and o.count_compared == 1

    def test_a_count_IS_compared_against_a_RETAINED_page_total(self, tmp_path):
        """The replay half: a pivot bought in an earlier lifecycle has its total on disk, so a count is
        measured against THAT with nothing fresh bought at all."""
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 100}), balance=_Bal(spendable=1),
             ledger=led)
        states = _states((FAV, "a"))
        states[0].cardinality = 500
        p = _Provider(totals={"a": 100})
        res, _ = _res(tmp_path, states, p, balance=_Bal(spendable=0), ledger=_ledger(tmp_path))
        o = res.lanes[FAV]
        assert p.calls == [], "the fixture bought a fresh page; this tests the RETAINED path"
        assert o.pages_replayed == 1 and o.count_compared == 1 and o.count_drift == 1

    def test_a_count_IS_compared_against_a_FRESH_page_total(self, tmp_path):
        """Reproduction two: nothing retained, count 100, the first search returns 500. Comparing only
        at fold time reported no drift because no page total existed yet."""
        led = _ledger(tmp_path)
        states = _states((FAV, "a"))
        states[0].cardinality = 100
        res, _ = _res(tmp_path, states, _Provider(totals={"a": 500}), balance=_Bal(spendable=1),
                      ledger=led)
        o = res.lanes[FAV]
        assert o.count_compared == 1 and o.count_drift == 1

    def test_drift_is_measured_against_the_FINAL_reconciled_total(self, tmp_path):
        """review-B1.5r2#2: retained totals 150 then 500, count 500. Freezing the verdict on page 1
        called that drift; the total it actually ended up with is 500, so it AGREES."""
        led = _ledger(tmp_path)
        p = _Provider(totals={("a", 1): 150, ("a", 2): 500, "a": 500})
        _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=2), ledger=led)
        states = _states((FAV, "a"))
        states[0].cardinality = 500
        res, _ = _res(tmp_path, states, _Provider(totals={"a": 500}), balance=_Bal(spendable=0),
                      ledger=_ledger(tmp_path))
        o = res.lanes[FAV]
        assert o.pages_replayed == 2 and o.count_compared == 1
        assert o.count_drift == 0, "a count matching the reconciled total was reported as drift"

    def test_a_count_matching_only_the_FIRST_page_is_drift(self, tmp_path):
        """The mirror: count 150 agrees with page 1 and disagrees with the reconciled 500."""
        led = _ledger(tmp_path)
        p = _Provider(totals={("a", 1): 150, ("a", 2): 500, "a": 500})
        _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=2), ledger=led)
        states = _states((FAV, "a"))
        states[0].cardinality = 150
        res, _ = _res(tmp_path, states, _Provider(totals={"a": 500}), balance=_Bal(spendable=0),
                      ledger=_ledger(tmp_path))
        o = res.lanes[FAV]
        assert o.pages_replayed == 2 and o.count_compared == 1 and o.count_drift == 1

    def test_a_count_is_compared_ONCE_per_pivot(self, tmp_path):
        led = _ledger(tmp_path)
        states = _states((FAV, "a"))
        states[0].cardinality = 100
        res, _ = _res(tmp_path, states, _Provider(totals={"a": 500}), balance=_Bal(spendable=None),
                      ledger=led)
        o = res.lanes[FAV]
        assert o.count_compared == 1, "the same pivot was compared on every page"

    def test_an_UNKNOWN_count_is_never_read_as_zero(self):
        st = PivotState(Pivot(FAV, "facet", "a"), total=300)
        st.cardinality = None
        st, o = self._fold(st)
        assert st.total == 300 and st.effective_total() == 300
        assert o.count_compared == 0 and o.count_drift == 0

    def test_a_MALFORMED_total_fails_closed_as_unknown(self):
        from quarry_recon.shodan_sched import valid_total
        for bad in (True, False, -1, 1.0, "5", None, [], {}):
            assert valid_total(bad) is False, bad
        assert valid_total(0) is True and valid_total(500) is True


class TestDriftTelemetry:
    def test_drift_is_REPORTED_not_just_counted(self, tmp_path):
        """The user's integration requirement: `total_drift` must reach telemetry. It is a soft PROVIDER
        limit — the index moved under us — and never a gap, because keeping the maximum omits nothing."""
        from quarry_recon.shodan_sched import report
        led = _ledger(tmp_path)
        p = _Provider(totals={("a", 1): 200, ("a", 2): 500, "a": 500})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=2), ledger=led)
        ev = tmp_path / "ev"
        ev.mkdir(parents=True, exist_ok=True)
        events.reset()
        events.configure(ev)
        try:
            report(FAV, res.lanes[FAV], balance=_Bal(spendable=2), persisted=True)
            recs = [json.loads(l) for l in (ev / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        rec = [r for r in recs if r["measure"] == "shodan_total_drift"]
        assert rec, f"drift never reached telemetry: {[r['measure'] for r in recs]}"
        # review-B1.4r2#4: VISIBLE but never a coverage boundary — keeping the maximum omits nothing, so
        # a single drifting total must not fold an otherwise complete scan into complete_with_limits.
        assert rec[0]["omitted"] == 0
        assert "1 of 2 page(s)" in rec[0]["reason"], rec[0]["reason"]

    def test_no_drift_still_reports_a_clean_measure(self, tmp_path):
        """Emitted every run, so a later clean run CLEARS a prior drift record."""
        from quarry_recon.shodan_sched import report
        led = _ledger(tmp_path)
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=2), ledger=led)
        ev = tmp_path / "ev"
        ev.mkdir(parents=True, exist_ok=True)
        events.reset()
        events.configure(ev)
        try:
            report(FAV, res.lanes[FAV], balance=_Bal(spendable=2), persisted=True)
            recs = [json.loads(l) for l in (ev / "events.jsonl").read_text().splitlines()
                    if '"coverage_partial"' in l]
        finally:
            events.reset()
        rec = [r for r in recs if r["measure"] == "shodan_total_drift"]
        assert rec and rec[0]["omitted"] == 0


class TestTotalReconciliation:
    """review-r7#1: fresh pages OVERWROTE the total, replayed pages kept only the FIRST. One body of
    evidence, two policies — and the quieter one won on resume."""

    def test_a_LATER_pages_larger_total_survives_a_resume(self, tmp_path):
        """The reviewer's two-lifecycle reproduction. Page 1 says 200, page 2 says 500; on resume the
        pivot must still owe pages 3-5 rather than reporting itself complete."""
        led = _ledger(tmp_path)
        p1 = _Provider(totals={("a", 1): 200, ("a", 2): 500, "a": 500})
        res1, _ = _res(tmp_path, _states((FAV, "a")), p1, balance=_Bal(spendable=2), ledger=led)
        assert res1.lanes[FAV].pages_left_known == 3

        p2 = _Provider(totals={("a", 1): 200, ("a", 2): 500, "a": 500})
        res2, _ = _res(tmp_path, _states((FAV, "a")), p2, balance=_Bal(spendable=0),
                       ledger=_ledger(tmp_path))
        assert res2.lanes[FAV].pages_replayed == 2
        assert res2.lanes[FAV].pages_left_known == 3, "a resumed pivot silently declared itself complete"

    def test_a_smaller_later_total_never_shrinks_the_remainder(self, tmp_path):
        """Drift runs both ways: the index is live, so page 2 may report FEWER results than page 1.
        Breadth-first means the remainder is never understated."""
        led = _ledger(tmp_path)
        p = _Provider(totals={("a", 1): 500, ("a", 2): 200, "a": 500})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=2), ledger=led)
        assert res.lanes[FAV].pages_left_known == 3

    def test_the_artifact_stores_what_SHODAN_said_not_what_we_derived(self, tmp_path):
        """review-r8#1: the page artifact serialized the reconciled maximum, so the evidence reported a
        total the provider never gave for that page — and because every stored page then agreed, the
        drift fact vanished on resume (stored 500/500 for a measured 500/200; drift 1 fresh, 0 resumed).
        Evidence records the ANSWER; reconciliation is a derived view."""
        led = _ledger(tmp_path)
        p = _Provider(totals={("a", 1): 500, ("a", 2): 200, "a": 500})
        res1, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=2), ledger=led)
        assert res1.lanes[FAV].total_drift == 1
        from quarry_recon.shodan_sched import owned_index
        stored = [d["total"] for _pg, _art, d
                  in owned_index(_ledger(tmp_path))[(FAV, "facet", "a")]]
        assert stored == [500, 200], f"the artifact was rewritten with a derived total: {stored}"
        res2, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                       balance=_Bal(spendable=0), ledger=_ledger(tmp_path))
        assert res2.lanes[FAV].total_drift == 1, "the drift fact did not survive a restart"
        assert res2.lanes[FAV].pages_left_known == 3, "reconciliation was lost with it"

    def test_disagreeing_totals_are_COUNTED_not_hidden(self, tmp_path):
        led = _ledger(tmp_path)
        p = _Provider(totals={("a", 1): 200, ("a", 2): 500, "a": 500})
        res, _ = _res(tmp_path, _states((FAV, "a")), p, balance=_Bal(spendable=2), ledger=led)
        assert res.lanes[FAV].total_drift == 1
        other = tmp_path / "stable"
        other.mkdir(parents=True, exist_ok=True)
        clean = _Provider(totals={"b": 500})
        res2, _ = _res(other, _states((FAV, "b")), clean, balance=_Bal(spendable=2),
                       ledger=_ledger(other))
        assert res2.lanes[FAV].total_drift == 0, "a stable total was reported as drift"


class TestBothSinksProvenBeforeSpending:
    """review-r7#2: only the ledger was probed. A page needs the artifact store too."""

    def test_an_unwritable_artifact_store_costs_NOTHING(self, tmp_path):
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o500)                                     # readable, not writable
        try:
            p = _Provider()
            res = run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=None),
                           search=p.search, ingest=lambda *a: 0, ledger=_ledger(tmp_path),
                           attempt_dir=d)
        finally:
            d.chmod(0o700)
        assert p.calls == [], f"paid for a page the store could not hold: {p.calls}"
        assert res.stop_cause == "publish_failed"

    def test_the_probe_removes_itself(self, tmp_path):
        """An artifact tree's contract is that every file in it is validated evidence, so the probe must
        leave nothing behind for a miner or an orphan sweep to find."""
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=1),
                 search=_Provider().search, ingest=lambda *a: 0, ledger=_ledger(tmp_path),
                 attempt_dir=d)
        leftovers = [q.name for q in d.iterdir() if "probe" in q.name or q.name.startswith(".")]
        assert leftovers == [], f"the write probe left files behind: {leftovers}"

    def test_a_store_that_cannot_be_cleaned_up_is_not_writable(self, tmp_path, monkeypatch):
        """Publishing is only half of it: a probe we cannot remove would become a permanent orphan."""
        from quarry_recon.shodan_sched import store_writable
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(pathlib.Path, "unlink", lambda self, **k: None)   # removal silently no-ops
        assert store_writable(d) is False
        monkeypatch.undo()
        for q in d.iterdir():
            q.unlink()

    def test_a_failed_atomic_publish_leaves_NOTHING_behind(self, tmp_path, monkeypatch):
        """review-r8#2: `publish_bytes` cleaned up its temp on a digest mismatch but not on an OSError,
        so a failing `os.replace` left `<name>.part-<pid>` in the artifact tree. Fixed in the shared
        primitive, so every publisher inherits it."""
        import quarry_recon.budget as _b
        from quarry_recon.shodan_sched import store_writable
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(_b.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
        assert store_writable(d) is False
        monkeypatch.undo()
        assert list(d.iterdir()) == [], f"a failed publish left a temp behind: {list(d.iterdir())}"

    def test_a_healthy_store_passes(self, tmp_path):
        from quarry_recon.shodan_sched import store_writable
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        assert store_writable(d) is True


class TestProbesOnlyWhenBuying:
    """review-r8#1: the probes ran at entry, so a run that purchases NOTHING was still judged on sinks it
    never needed — a free, fully-replayed run over a read-only store reported `publish_failed` with zero
    publications attempted."""

    @staticmethod
    def _spy(monkeypatch):
        """Count sink probes without changing their answers."""
        import quarry_recon.shodan_sched as ss
        seen = {"store": 0, "ledger": 0}
        real = ss.store_writable
        monkeypatch.setattr(ss, "store_writable",
                            lambda d: (seen.__setitem__("store", seen["store"] + 1), real(d))[1])
        real_w = ss.ledger_writable
        monkeypatch.setattr(ss, "ledger_writable",
                            lambda l: (seen.__setitem__("ledger", seen["ledger"] + 1), real_w(l))[1])
        return seen

    def test_a_fully_replayed_run_probes_NEITHER_sink(self, tmp_path, monkeypatch):
        """The reviewer's reproduction: buy page 1, then resume with the store read-only. The replay is
        free and complete, so nothing may be published and nothing may be claimed broken."""
        led = _ledger(tmp_path)
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        p1 = _Provider(totals={"a": 3})
        run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=None), search=p1.search,
                 ingest=lambda *a: 0, ledger=led, attempt_dir=d)
        seen = self._spy(monkeypatch)
        d.chmod(0o500)
        try:
            p2 = _Provider(totals={"a": 3})
            res = run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=None),
                           search=p2.search, ingest=lambda *a: 0, ledger=_ledger(tmp_path),
                           attempt_dir=d)
        finally:
            d.chmod(0o700)
        assert p2.calls == [] and res.lanes[FAV].pages_replayed == 1
        assert res.stop_cause == "", f"a free complete replay reported a failure: {res.stop_cause}"
        assert res.lanes[FAV].publish_failed == 0
        assert seen == {"store": 0, "ledger": 0}, f"probed sinks it never needed: {seen}"

    def test_a_run_with_no_work_probes_nothing(self, tmp_path, monkeypatch):
        seen = self._spy(monkeypatch)
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        res = run_work(None, states=[], balance=_Bal(spendable=None), search=_Provider().search,
                       ingest=lambda *a: 0, ledger=_ledger(tmp_path), attempt_dir=d)
        assert res.stop_cause == "" and seen == {"store": 0, "ledger": 0}

    def test_a_policy_withheld_run_probes_nothing(self, tmp_path, monkeypatch):
        """Every page the operator allows is already owned: the remainder is withheld, not unbuyable."""
        led = _ledger(tmp_path)
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=1),
                 search=_Provider(totals={"a": 500}).search, ingest=lambda *a: 0, ledger=led,
                 attempt_dir=d, max_pages=1)
        seen = self._spy(monkeypatch)
        p = _Provider(totals={"a": 500})
        res = run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=None), search=p.search,
                       ingest=lambda *a: 0, ledger=_ledger(tmp_path), attempt_dir=d, max_pages=1)
        assert p.calls == [] and res.lanes[FAV].pages_withheld == 4
        assert seen == {"store": 0, "ledger": 0}, f"probed with nothing to buy: {seen}"

    def test_pending_paid_work_probes_BOTH_sinks_before_the_first_call(self, tmp_path, monkeypatch):
        seen = self._spy(monkeypatch)
        d = tmp_path / "att"
        d.mkdir(parents=True, exist_ok=True)
        order: list = []
        import quarry_recon.shodan_sched as ss
        real = ss.store_writable
        monkeypatch.setattr(ss, "store_writable", lambda x: (order.append("probe"), real(x))[1])
        p = _Provider(totals={"a": 300})          # three pages, so "once" is distinguishable from "each"

        def watched(pivot, page):
            order.append("search")
            return p.search(pivot, page)

        run_work(None, states=_states((FAV, "a")), balance=_Bal(spendable=None), search=watched,
                 ingest=lambda *a: 0, ledger=_ledger(tmp_path), attempt_dir=d)
        assert order.count("search") == 3, f"fixture bought {order.count('search')} pages"
        assert seen["store"] == 1 and seen["ledger"] >= 1, f"sinks not proven: {seen}"
        assert order[0] == "probe", f"spent before proving the sinks: {order}"
        # ONCE per run, not once per purchase: each probe writes a journal record and republishes a file,
        # so repeating it would grow the journal and touch the artifact tree on every page.
        assert order.count("probe") == 1, f"re-probed on every purchase: {order}"

class TestReadsPerResumedPage:
    def test_a_resumed_page_is_read_from_disk_exactly_once(self, tmp_path, monkeypatch):
        """review-r6#2: the artifact was parsed in `owned_index`, again in `_read_page`, and a third time
        in `_replay_one` — on top of the digest `Ledger._load` already computed."""
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 300}),
             balance=_Bal(spendable=3), ledger=led)
        reads: list = []
        real = pathlib.Path.read_text

        def counted(self, *a, **k):
            if self.suffix == ".json" and "attempt" in str(self):
                reads.append(str(self))
            return real(self, *a, **k)

        monkeypatch.setattr(pathlib.Path, "read_text", counted)
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 300}),
                      balance=_Bal(spendable=None), ledger=_ledger(tmp_path))
        assert res.lanes[FAV].pages_replayed == 3
        # ONE read per ARTIFACT. A resumed page's bytes were read three times (here, in `_read_page`
        # and again in `_replay_one`) — that is the defect this pins. Acquisition receipts are separate,
        # much smaller artifacts and are likewise read once each, so the property is "nothing is read
        # twice", not "only pages exist".
        assert len(reads) == len(set(reads)), f"an artifact was read more than once: {reads}"
        pages = [r for r in reads if "/acq/" not in r]
        assert len(pages) == 3, f"{len(pages)} page reads for 3 resumed pages: {pages}"


class TestDurabilityHandshake:
    """review-r4#1: `ledger_writable` read two flags that `_append` never set, so a real OSError on the
    journal was invisible; and `save() == False` alone was treated as "not resumable" even when every
    completion had been journaled."""

    def test_a_failed_journal_append_stops_purchasing(self, tmp_path):
        """The PRODUCTION path — no flag is set by hand. A real OSError on the append is what `_append`
        used to swallow, leaving both safety flags clear and the caller unable to tell a durable
        completion from an in-memory one.

        The journal path is occupied by a DIRECTORY, so `open('a')` raises IsADirectoryError while the
        artifact write itself is untouched (patching `Path.open` would break `publish_bytes` too, and the
        first attempt at this test did exactly that — it failed on publish, not on the journal).

        review-r5#3: this cost ONE credit to discover, because nothing set the flags until a write had
        already failed. The precondition now performs a real (state-free) write, so NOTHING is spent."""
        led = _ledger(tmp_path)
        led.journal.parent.mkdir(parents=True, exist_ok=True)
        led.journal.mkdir()                                   # appending here can only raise
        p = _Provider()
        res, _ = _res(tmp_path, _states(*[(FAV, f"f{i}") for i in range(5)]), p,
                      balance=_Bal(spendable=None), ledger=led)
        assert p.calls == [], f"spent credits on a ledger that could not be written: {p.calls}"
        assert res.stop_cause == "ledger_unwritable"
        assert led.durable is False

    def test_a_journaled_run_is_resumable_even_if_compaction_fails(self, tmp_path):
        """The inverse FALSE gap: the journal is replayed at load, so these completions survive."""
        led = _ledger(tmp_path)
        led.save = lambda: False                          # snapshot write fails, journal is fine
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 3}),
                      balance=_Bal(spendable=None), ledger=led)
        assert res.lanes[FAV].pages_bought == 1
        assert res.persisted is True, "a journaled completion was reported as lost"
        # and it really does survive a reopen
        assert _ledger(tmp_path).has(item_key(Pivot(FAV, "facet", "a"), 1))

    def test_the_write_probe_leaves_the_journal_replayable(self, tmp_path):
        """The probe is only free if it costs nothing on the way back in: its record carries no state and
        must not look like damage, or every load would rewrite the journal to repair it."""
        led = _ledger(tmp_path)
        art = tmp_path / "x.json"
        art.write_text("{}")
        assert led.checkpoint() is True
        assert led.record("k", art) is True
        before = led.journal.read_text()
        re = _ledger(tmp_path)
        assert re.has("k"), "the completion did not survive a journal carrying a probe record"
        assert re.journal.read_text() == before, "the probe record was treated as damage and repaired"
        assert re._journal_unsafe is False and re.durable is True

    def test_a_failed_RECORD_plus_a_failed_SNAPSHOT_is_not_persisted(self, tmp_path, monkeypatch):
        """review-r6#1, the combined failure — NEITHER half reproduces it alone. The checkpoint journals
        fine, so the journal is readable and `durable` is True; the paid page's `record()` fails, so the
        page is only in memory; compaction then fails too. Every signal looked survivable while the page
        reached no destination at all."""
        import quarry_recon.budget as _b
        led = _ledger(tmp_path)
        real_append, real_replace = led._append, os.replace
        # the COMPLETION record fails to journal; the checkpoint before it did not. Flags stay clear,
        # because a refused append leaves the existing journal perfectly readable — that is the trap.
        led._append = lambda rec: False if "i" in rec else real_append(rec)

        def fail(src, dst, *a, **k):
            if str(dst).endswith(led.path.name):
                raise OSError("no space left on device")
            return real_replace(src, dst, *a, **k)

        monkeypatch.setattr(_b.os, "replace", fail)
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 3}),
                      balance=_Bal(spendable=None), ledger=led)
        monkeypatch.undo()
        assert res.lanes[FAV].pages_bought == 1 and res.stop_cause == "ledger_unwritable"
        assert led.durable is True, "precondition: the OLD journal is readable, which is the trap"
        assert res.persisted is False, "a page that reached neither journal nor snapshot read as durable"
        assert not _ledger(tmp_path).has(item_key(Pivot(FAV, "facet", "a"), 1)), \
            "fixture is wrong: the page must NOT survive a reopen"

    def test_a_foreign_ledger_is_not_resumable(self, tmp_path):
        other = budget.state_path(tmp_path, "someone.else", "fp0")
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_text(json.dumps({"lane": "someone.else", "done": {}, "digests": {}}))
        led = budget.Ledger(other, lane="shodan.work")
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(), balance=_Bal(spendable=None),
                      ledger=led)
        assert res.persisted is False and res.stop_cause == "ledger_unwritable"

    def test_a_record_that_REPORTS_failure_stops_purchasing(self, tmp_path):
        """`record()` returning False is the DIRECT signal; `ledger_writable` is derived from flags. A
        ledger that reports failure without setting a flag must still stop the run — otherwise the
        coordinator trusts a derived state over the primary one."""
        led = _ledger(tmp_path)
        led.record = lambda *a, **k: False                # reports failure, flags stay clean
        p = _Provider()
        res, _ = _res(tmp_path, _states(*[(FAV, f"f{i}") for i in range(4)]), p,
                      balance=_Bal(spendable=None), ledger=led)
        assert len(p.calls) == 1, f"kept buying after record() reported failure: {p.calls}"
        assert res.stop_cause == "ledger_unwritable"

    def test_record_reports_whether_it_journaled(self, tmp_path):
        led = _ledger(tmp_path)
        art = tmp_path / "x.json"
        art.write_text("{}")
        assert led.record("k", art) is True and led.durable is True
        led._journal_lost = True
        assert led.durable is False

    def test_a_blocked_append_does_not_mean_a_LOST_journal(self, tmp_path):
        """review-r5#2: `_journal_unsafe` answers "may I append?", `durable` answers "will the next run
        see this?". Conflating them turned every refusal-to-append into a claim that earlier journaled
        completions were gone."""
        led = _ledger(tmp_path)
        art = tmp_path / "x.json"
        art.write_text("{}")
        assert led.record("k", art) is True
        led._journal_unsafe = True                        # appends refused; the journal is untouched
        assert led.record("k2", art) is False
        assert led.durable is True, "a refused append was reported as a lost journal"
        assert _ledger(tmp_path).has("k"), "the journaled completion did not survive a reopen"

    def test_a_REAL_snapshot_failure_keeps_the_run_resumable(self, tmp_path, monkeypatch):
        """review-r5#2, the production path: `Ledger.save()` sets a flag when `os.replace` fails, keeping
        the journal deliberately. Measured: save=False, journal present, completion survives reopen — so
        reporting `persisted=False` was a false gap on genuinely resumable work. The earlier test stubbed
        `save` to return False, which never exercised that flag at all."""
        import quarry_recon.budget as _b
        led = _ledger(tmp_path)
        real = os.replace

        def fail(src, dst, *a, **k):
            if str(dst).endswith(led.path.name):
                raise OSError("no space left on device")
            return real(src, dst, *a, **k)

        monkeypatch.setattr(_b.os, "replace", fail)
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 3}),
                      balance=_Bal(spendable=None), ledger=led)
        monkeypatch.undo()
        assert res.lanes[FAV].pages_bought == 1
        assert res.persisted is True, "a journaled completion was reported as lost"
        assert _ledger(tmp_path).has(item_key(Pivot(FAV, "facet", "a"), 1))


class TestPivotsTouched:
    """review-r4#5: it claimed "at least one page bought or replayed" but counted only page 1, so
    replaying pages 2-3 while page 1 failed left it at zero."""

    def test_touching_a_pivot_via_a_later_page_counts(self, tmp_path):
        led = _ledger(tmp_path)
        _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
             balance=_Bal(spendable=3), ledger=led)
        led2 = _ledger(tmp_path)
        led2.artifact(item_key(Pivot(FAV, "facet", "a"), 1)).write_text("{}")   # break page 1
        res, _ = _res(tmp_path, _states((FAV, "a")),
                      _Provider(totals={"a": 500}, errors={("a", 1): _err("transport")}),
                      balance=_Bal(spendable=None), ledger=_ledger(tmp_path))
        assert res.lanes[FAV].pages_replayed >= 2
        assert res.lanes[FAV].pivots_touched == 1, "pages 2-3 replayed but the pivot read as untouched"

    def test_an_untouched_pivot_stays_zero(self, tmp_path):
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(),
                      balance=_Bal(spendable=0, may_spend=False))
        assert res.lanes[FAV].pivots_touched == 0

    def test_a_pivot_is_counted_once(self, tmp_path):
        res, _ = _res(tmp_path, _states((FAV, "a")), _Provider(totals={"a": 500}),
                      balance=_Bal(spendable=None))
        assert res.lanes[FAV].pivots_touched == 1 and res.lanes[FAV].pages_bought == 5


# ── B1.7a: the machinery boundary, ported from `whoxy_page` ────────────────────────────────────────
class TestMachineryFailuresPreserveTheWorkResult:
    """review-B1.7a: `run_work` had no boundary at all, so an exception in replay, scheduling, sweeping,
    remainder accounting or the ledger save escaped the coordinator and the caller fabricated zero
    accounting over pages the run had already replayed and bought. Best effort is the contract; only
    cancellation ends the run."""

    def _work(self, tmp_path, provider, *, states=None, ledger=None, balance=None, ingest=None):
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        return run_work(None, states=states or _states((FAV, "a")), balance=balance or _Bal(),
                        search=provider.search, ingest=ingest or (lambda p, pg, m, r: len(m)),
                        ledger=ledger if ledger is not None else _ledger(tmp_path), attempt_dir=d)

    def test_a_REPLAY_failure_keeps_the_pages_already_ingested(self, tmp_path):
        prov = _Provider(totals={"a": 3 * SHODAN_PAGE_SIZE})
        led = _ledger(tmp_path)
        first = self._work(tmp_path, prov, ledger=led)
        assert first.lanes[FAV].pages_bought == 3, first.lanes[FAV].pages_bought

        seen = []

        def ingest(pivot, page, matches, raw):
            if len(seen) >= 1:
                raise RuntimeError("ingest exploded during replay")
            seen.append(page)
            return len(matches)

        res = self._work(tmp_path, prov, ledger=_ledger(tmp_path), ingest=ingest)
        o = res.lanes[FAV]
        assert o.pages_replayed >= 1, "replayed pages died with the exception"
        assert o.pages_unconsumed == 1, o.pages_unconsumed
        assert res.stop_cause == "machinery:RuntimeError", res.stop_cause
        # review-B1.7a#2: an INGEST failure is the lane's own, not the run's — filing it globally turned
        # completed sibling lanes partial. The stop is still global; the fault is lane-scoped.
        assert o.machinery == ["RuntimeError: ingest exploded during replay"], o.machinery
        assert res.machinery == [], res.machinery

    def test_a_PAID_page_we_could_not_ingest_is_counted_as_unconsumed(self, tmp_path):
        """The credit is spent and the page is journaled — it stays owned, or the scheduler sells it to
        us again — but its matches are not in the store, and the page remainder cannot say so."""
        def boom(pivot, page, matches, raw):
            raise RuntimeError("ingest exploded on a bought page")

        res = self._work(tmp_path, _Provider(totals={"a": SHODAN_PAGE_SIZE}), ingest=boom)
        o = res.lanes[FAV]
        assert o.pages_bought == 1, o.pages_bought
        assert o.pages_unconsumed == 1, o.pages_unconsumed
        assert o.matches == 0 and res.stop_cause == "machinery:RuntimeError", (o.matches,
                                                                              res.stop_cause)
        assert o.machinery == ["RuntimeError: ingest exploded on a bought page"], o.machinery
        assert res.machinery == [], res.machinery

    def test_a_REMAINDER_failure_keeps_the_run(self, tmp_path, monkeypatch):
        import quarry_recon.shodan_sched as ss
        prov = _Provider(totals={"a": SHODAN_PAGE_SIZE})
        monkeypatch.setattr(ss, "_remainder",
                            lambda *a, **k: (_ for _ in ()).throw(ValueError("accounting exploded")))
        res = self._work(tmp_path, prov)
        assert res.lanes[FAV].pages_bought == 1
        assert res.machinery == ["ValueError: accounting exploded"], res.machinery

    def test_the_REMAINDER_is_a_snapshot_not_an_accumulator(self, tmp_path):
        import quarry_recon.shodan_sched as ss
        states = _states((FAV, "a"))
        res = ss.WorkResult()
        res.lanes[FAV] = LaneOutcome(lane=FAV, pivots=1)
        ss._remainder(states, res, max_pages=0)
        first = (list(res.lanes[FAV].unqueried), res.lanes[FAV].pages_left_known)
        ss._remainder(states, res, max_pages=0)
        assert (list(res.lanes[FAV].unqueried), res.lanes[FAV].pages_left_known) == first

    def test_a_SAVE_that_raises_keeps_the_pages_it_bought(self, tmp_path):
        prov = _Provider(totals={"a": 2 * SHODAN_PAGE_SIZE})
        led = _ledger(tmp_path)
        led.save = lambda *a, **k: (_ for _ in ()).throw(OSError("store exploded"))
        led._journal_lost = True                       # neither snapshot nor journal survives
        res = self._work(tmp_path, prov, ledger=led)
        assert res.lanes[FAV].pages_bought == 2, res.lanes[FAV].pages_bought
        assert res.persisted is False
        assert res.machinery == ["OSError: store exploded"], res.machinery

    def test_a_SUCCESSFUL_save_never_consults_the_fallback(self, tmp_path):
        touched = []
        led = _ledger(tmp_path)

        class _Loud(type(led)):
            @property
            def durable(self):
                touched.append(1)
                raise OSError("fallback exploded")

        led.__class__ = _Loud
        led.save = lambda *a, **k: True
        res = self._work(tmp_path, _Provider(totals={"a": SHODAN_PAGE_SIZE}), ledger=led)
        assert touched == [], "the fallback was consulted although the snapshot landed"
        assert res.persisted is True and res.machinery == [] and res.stop_cause == ""

    def test_CANCELLATION_still_ends_the_run(self, tmp_path):
        def boom(pivot, page):
            raise KeyboardInterrupt("ctrl-c")

        prov = _Provider()
        prov.search = boom
        with pytest.raises(KeyboardInterrupt):
            self._work(tmp_path, prov)

    def test_the_FIRST_cause_names_the_stop(self, tmp_path, monkeypatch):
        """A page we could not publish is why this run ended; a later accounting failure is a
        consequence of it, and renaming the stop would report the symptom."""
        import quarry_recon.shodan_sched as ss
        from quarry_recon import budget as _b
        monkeypatch.setattr(_b, "publish_bytes", lambda *a, **k: False)
        monkeypatch.setattr(ss, "_remainder",
                            lambda *a, **k: (_ for _ in ()).throw(ValueError("accounting exploded")))
        res = self._work(tmp_path, _Provider(totals={"a": SHODAN_PAGE_SIZE}))
        assert res.stop_cause == "publish_failed", res.stop_cause
        assert res.machinery == ["ValueError: accounting exploded"], res.machinery


    def test_a_LANE_LOCAL_ingest_failure_does_not_contaminate_a_COMPLETED_sibling(self, tmp_path):
        """review-B1.7a#2: reproduced — cert completed with every page bought and stored, favicon's
        ingest then raised, and BOTH terminals read degraded. A completed lane owes nothing to another
        lane's ingestion defect."""
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)

        def ingest(pivot, page, matches, raw):
            if pivot.lane == FAV:
                raise RuntimeError("favicon ingest exploded")
            return len(matches)

        res = run_work(None, states=_states((CERT, "x"), (FAV, "a")), balance=_Bal(),
                       search=_Provider(totals={"x": SHODAN_PAGE_SIZE,
                                                "a": SHODAN_PAGE_SIZE}).search,
                       ingest=ingest, ledger=_ledger(tmp_path), attempt_dir=d)
        assert res.lanes[FAV].machinery, "the failing lane lost its own fact"
        assert res.lanes[CERT].machinery == [], "a completed lane inherited another lane's failure"
        assert res.lanes[CERT].pages_unconsumed == 0 and res.lanes[CERT].matches > 0
        assert res.machinery == [], "a lane-local failure was filed as everyone's"


    def test_lane_scope_survives_an_exception_that_REJECTS_ATTRIBUTES(self, tmp_path):
        """review-B1.7a#5: attribution used to be a flag set ON the raised exception, so a class with
        `__slots__` or an overridden `__setattr__` silently fell back to being filed against every lane —
        a completed sibling went partial again and the failing lane's reason said it twice. Scope is now
        carried by the exception TYPE the boundary receives, which the callback cannot influence."""
        class _Immutable(Exception):
            __slots__ = ()

            def __setattr__(self, k, v):
                raise AttributeError("this exception refuses attributes")

        def ingest(pivot, page, matches, raw):
            if pivot.lane == FAV:
                raise _Immutable("favicon ingest exploded")
            return len(matches)

        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        res = run_work(None, states=_states((CERT, "x"), (FAV, "a")), balance=_Bal(),
                       search=_Provider(totals={"x": SHODAN_PAGE_SIZE,
                                                "a": SHODAN_PAGE_SIZE}).search,
                       ingest=ingest, ledger=_ledger(tmp_path), attempt_dir=d)
        assert res.machinery == [], "a lane-local fault was filed as everyone's"
        assert res.lanes[CERT].machinery == [], "a completed lane inherited another lane's failure"
        assert res.lanes[FAV].machinery == ["_Immutable: favicon ingest exploded"], res.lanes[FAV].machinery
        # the STOP still names what actually broke, not the carrier we wrapped it in
        assert res.stop_cause == "machinery:_Immutable", res.stop_cause


    def test_a_REPLAY_failure_in_ONE_lane_does_not_stop_the_SIBLING_replaying(self, tmp_path):
        """review-B1.7a#6: the carrier propagated out of the WHOLE replay pass, so a favicon store
        failure on resume meant an already-owned cert page was never replayed and cert reported FAILED
        with its ingest never called. Replay is free and per-lane."""
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        prov = _Provider(totals={"a": SHODAN_PAGE_SIZE, "x": SHODAN_PAGE_SIZE})
        first = run_work(None, states=_states((FAV, "a"), (CERT, "x")), balance=_Bal(),
                         search=prov.search, ingest=lambda *a: 1, ledger=led, attempt_dir=d)
        assert first.lanes[FAV].pages_bought == 1 and first.lanes[CERT].pages_bought == 1

        seen = []

        def ingest(pivot, page, matches, raw):
            if pivot.lane == FAV:
                raise RuntimeError("favicon store exploded")
            seen.append((pivot.lane, page))
            return len(matches)

        calls = len(prov.calls)
        res = run_work(None, states=_states((FAV, "a"), (CERT, "x")), balance=_Bal(),
                       search=prov.search, ingest=ingest, ledger=_ledger(tmp_path), attempt_dir=d)
        assert len(prov.calls) == calls, "a resumed run bought pages it already owned"
        assert seen == [(CERT, 1)], f"the sibling lane never re-ingested its owned page: {seen}"
        assert res.lanes[CERT].pages_replayed == 1 and res.lanes[CERT].machinery == []
        assert res.lanes[CERT].pages_unconsumed == 0
        assert res.lanes[FAV].pages_unconsumed == 1
        assert res.lanes[FAV].machinery == ["RuntimeError: favicon store exploded"]

    def test_a_PURCHASE_ingest_failure_does_not_skip_the_owned_page_SWEEP(self, tmp_path):
        """The same rule on the paid path: a page one lane could not ingest ends PURCHASING, not the free
        sweep of pages another lane already paid for."""
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        prov = _Provider(totals={"x": 3 * SHODAN_PAGE_SIZE, "a": SHODAN_PAGE_SIZE})
        # lifecycle 1: cert owns all three of its pages
        run_work(None, states=_states((CERT, "x")), balance=_Bal(), search=prov.search,
                 ingest=lambda *a: 1, ledger=led, attempt_dir=d)

        swept = []

        def ingest(pivot, page, matches, raw):
            if pivot.lane == FAV:
                raise RuntimeError("favicon store exploded")
            swept.append(page)
            return len(matches)

        # max_pages=1 excludes cert pages 2-3 from PURCHASING; the sweep must still replay them
        res = run_work(None, states=_states((FAV, "a"), (CERT, "x")), balance=_Bal(),
                       search=prov.search, ingest=ingest, ledger=_ledger(tmp_path), attempt_dir=d,
                       max_pages=1)
        assert sorted(swept) == [1, 2, 3], f"the owned-page sweep was skipped: {swept}"
        assert res.lanes[CERT].pages_replayed == 3, res.lanes[CERT].pages_replayed
        assert res.lanes[FAV].machinery and res.lanes[CERT].machinery == []


    def test_a_BROKEN_SINK_stops_that_lane_rather_than_repeating_the_failure(self, tmp_path):
        """Its sink is broken: the next pivot of the same lane would fail identically, so the lane stops
        after the first failure. Other lanes are unaffected (see the sibling test)."""
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        prov = _Provider(totals={"a": SHODAN_PAGE_SIZE, "b": SHODAN_PAGE_SIZE, "x": SHODAN_PAGE_SIZE})
        run_work(None, states=_states((FAV, "a"), (FAV, "b"), (CERT, "x")), balance=_Bal(),
                 search=prov.search, ingest=lambda *a: 1, ledger=led, attempt_dir=d)

        tried = []

        def ingest(pivot, page, matches, raw):
            tried.append(pivot.value)
            if pivot.lane == FAV:
                raise RuntimeError("favicon store exploded")
            return len(matches)

        res = run_work(None, states=_states((FAV, "a"), (FAV, "b"), (CERT, "x")), balance=_Bal(),
                       search=prov.search, ingest=ingest, ledger=_ledger(tmp_path), attempt_dir=d)
        assert tried.count("a") + tried.count("b") == 1, f"the broken lane kept being retried: {tried}"
        assert res.lanes[FAV].pages_unconsumed == 1, res.lanes[FAV].pages_unconsumed
        assert len(res.lanes[FAV].machinery) == 1, res.lanes[FAV].machinery
        assert "x" in tried and res.lanes[CERT].pages_replayed == 1

    def test_a_PURCHASE_failure_does_not_skip_the_MAX_PAGES_sweep(self, tmp_path, monkeypatch):
        """`_sweep_owned` is the seam under test: with the owned-page INDEX empty, it is the only path
        that replays pages an operator page policy excluded from purchasing. A purchase-path ingest
        failure in another lane must not skip it (review-B1.7a#6)."""
        import quarry_recon.shodan_sched as ss
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        prov = _Provider(totals={"x": 3 * SHODAN_PAGE_SIZE, "a": SHODAN_PAGE_SIZE})
        run_work(None, states=_states((CERT, "x")), balance=_Bal(), search=prov.search,
                 ingest=lambda *a: 1, ledger=led, attempt_dir=d)

        swept = []

        def ingest(pivot, page, matches, raw):
            if pivot.lane == FAV:
                raise RuntimeError("favicon store exploded")
            swept.append(page)
            return len(matches)

        monkeypatch.setattr(ss, "owned_index", lambda ledger: {})   # only the SWEEP can replay now
        states = _states((FAV, "a"), (CERT, "x"))
        for st in states:
            if st.pivot.lane == CERT:
                st.total = 3 * SHODAN_PAGE_SIZE     # the page count the sweep walks
        res = run_work(None, states=states, balance=_Bal(), search=prov.search, ingest=ingest,
                       ledger=_ledger(tmp_path), attempt_dir=d, max_pages=1)
        # page 1 is bought (the index is empty, so it reads as pending under max_pages=1); pages 2-3 can
        # only come from the sweep.
        assert sorted(swept) == [1, 2, 3], f"the owned-page sweep was skipped: {swept}"
        assert res.lanes[CERT].machinery == [] and res.lanes[FAV].machinery


    def test_a_BROKEN_SINK_stays_broken_ACROSS_passes(self, tmp_path):
        """review-B1.7a#8: `broken` was per-PASS, so indexed replay and the max-pages sweep forgot each
        other's failures — ingestion was called for pages 1 AND 2, `pages_unconsumed=2`, and the machinery
        reason appeared twice for one broken sink."""
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        prov = _Provider(totals={"a": 3 * SHODAN_PAGE_SIZE})
        run_work(None, states=_states((FAV, "a")), balance=_Bal(), search=prov.search,
                 ingest=lambda *a: 1, ledger=led, attempt_dir=d)
        assert prov.calls, "the first lifecycle bought nothing to replay"

        tried = []

        def ingest(pivot, page, matches, raw):
            tried.append(page)
            raise RuntimeError("store exploded")

        res = run_work(None, states=_states((FAV, "a")), balance=_Bal(), search=prov.search,
                       ingest=ingest, ledger=_ledger(tmp_path), attempt_dir=d, max_pages=1)
        assert tried == [1], f"the broken sink was tried again in a later pass: {tried}"
        assert res.lanes[FAV].pages_unconsumed == 1, res.lanes[FAV].pages_unconsumed
        assert res.lanes[FAV].machinery == ["RuntimeError: store exploded"], res.lanes[FAV].machinery

    def test_a_PAID_PATH_fault_also_stops_the_later_sweep(self, tmp_path, monkeypatch):
        """The same rule seeded from the OTHER direction: the fault is recorded while buying, and the
        sweep that follows must not try the same broken sink."""
        import quarry_recon.shodan_sched as ss
        d = tmp_path / "attempts"
        d.mkdir(parents=True, exist_ok=True)
        led = _ledger(tmp_path)
        prov = _Provider(totals={"a": 3 * SHODAN_PAGE_SIZE})
        run_work(None, states=_states((FAV, "a")), balance=_Bal(), search=prov.search,
                 ingest=lambda *a: 1, ledger=led, attempt_dir=d)

        tried = []

        def ingest(pivot, page, matches, raw):
            tried.append(page)
            raise RuntimeError("store exploded")

        monkeypatch.setattr(ss, "owned_index", lambda ledger: {})   # nothing to replay; page 1 is BOUGHT
        st = _states((FAV, "a"))[0]
        st.total = 3 * SHODAN_PAGE_SIZE
        res = run_work(None, states=[st], balance=_Bal(), search=prov.search, ingest=ingest,
                       ledger=_ledger(tmp_path), attempt_dir=d, max_pages=1)
        assert tried == [1], f"the sweep retried a sink that failed while buying: {tried}"
        assert len(res.lanes[FAV].machinery) == 1, res.lanes[FAV].machinery
