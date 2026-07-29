"""B1.6b — the Whoxy lane's TERMINAL MAPPER, driven directly from paginator outcomes.

Every state a lifecycle can end in, mapped to a status and to the metadata `OsintSession.outcome()`
folds into the session verdict. Driven at the mapper rather than through HTTP, because these are
decisions about facts, not about transport — and because several of them were silently reporting
SUCCESS while the lane had failed.
"""

from __future__ import annotations

import pytest

from quarry_recon import osint, whoxy_page as wp
from quarry_recon.runner import Status

pytestmark = pytest.mark.offline


def _term(pol=None, **kw):
    out = wp.Outcome(anchors=kw.pop("anchors", 1), **kw)
    rec: list = []

    class _S:
        def record(self, r):
            rec.append(r)

    osint._whoxy_record(_S(), out, pol if pol is not None else wp.SpendPolicy(), [], lambda m: None)
    return rec[0]


class TestMachineryFailuresAreNeverSuccess:
    """review-B1.6b14#2: status was chosen from the balance/provider reason alone, so a lane could
    publish nothing, journal nothing, or reject every page and still report SUCCESS."""

    @pytest.mark.parametrize("kw,why", [
        ({"publish_failed": 1}, "a page we could not store"),
        ({"fail_classes": {"parse": 1}, "evidence_invalid": 1}, "a page we could not use"),
        ({"stop_cause": "scheduler_invariant"}, "our own scheduler"),
        ({"stop_cause": "ledger_unwritable"}, "our own ledger"),
        ({"stop_cause": "publish_failed"}, "our own artifact store"),
    ])
    def test_a_real_failure_reaches_the_terminal(self, kw, why):
        r = _term(**kw)
        assert r.status is Status.FAILED, (why, r.status)
        assert r.meta["coverage_incomplete"] and r.meta["gap_reason"], r.meta

    def test_a_failure_with_evidence_is_PARTIAL_not_failed(self):
        r = _term(fail_classes={"transport": 1}, fail_reason="transport: boom", domains=5,
                  pages_bought=1)
        assert r.status is Status.PARTIAL and r.meta["gap_reason"]

    def test_an_unusable_page_is_counted_ONCE(self):
        """`fail_classes["parse"]` and `evidence_invalid` describe the SAME malformed response."""
        r = _term(fail_classes={"parse": 1}, evidence_invalid=1)
        assert r.meta["failed"] == 1, r.meta


class TestRemainderActivatesTheBoundary:
    """review-B1.6b14#1: only a KNOWN page remainder activated `stop_kind`, so anchors we never opened
    at all — the larger loss — reported SUCCESS."""

    @pytest.mark.parametrize("kind,origin", [("provider_balance", "provider"),
                                             ("operator_reserve", "operator"),
                                             ("run_budget", "operator")])
    def test_an_UNOPENED_anchor_is_a_remainder(self, kind, origin):
        # the allowance must actually have been SPENT for a policy boundary to explain the remainder
        # (review-B1.6b20) — `pages=0` means it was exhausted before the first request.
        r = _term(allowance_exhausted=True, unopened=["email=a@x.com"],
                  pol=wp.SpendPolicy(pages=0, stop_kind=kind))
        assert r.status is Status.LIMITED, r.status
        assert r.meta["limit_origin"] == origin, r.meta
        assert r.meta["unopened_anchors"] == 1 and r.meta["pages_left"] == 0

    def test_pages_and_anchors_are_reported_in_their_OWN_units(self):
        """review-B1.6b14#8 (earlier round): adding known pages to anchor identities and calling the
        result "pages" invents a denominator for anchors that have no knowable page count."""
        r = _term(allowance_exhausted=True, pages_left_known=7,
                  unopened=["email=a", "company=b"], pol=wp.SpendPolicy(pages=3, stop_kind="run_budget"))
        assert r.meta["pages_left"] == 7 and r.meta["unopened_anchors"] == 2
        assert "7 page(s) and 2 anchor(s)" in r.note, r.note


class TestLimitsAndGapsAreIndEPENDENT:
    """review-B1.6b14#3: `provider_limit` was set only inside the limit-ONLY branch, so a failure and a
    limit together reported the gap and lost the limit entirely."""

    def test_a_failure_AND_a_limit_keep_both_facts(self):
        r = _term(fail_classes={"transport": 1}, limit_classes={"quota": 1},
                  fail_reason="transport: boom", limit_reason="quota: Zero Account Balance",
                  domains=5, pages_bought=1)
        assert r.status is Status.PARTIAL, "gaps dominate"
        assert r.meta["provider_limit"] is True, "the limit vanished behind the gap"
        assert r.meta["limit_reason"] == "quota: Zero Account Balance"
        assert r.meta["gap_reason"] == "transport: boom"

    def test_account_busy_is_a_GAP_not_a_limit(self):
        """The agreed contract: another project holding the account leaves pages simply missing."""
        r = _term(stop_cause="account_busy", pages_replayed=2, domains=3)
        assert r.status is Status.PARTIAL and r.meta["gap_reason"]
        assert r.meta["provider_limit"] is False and r.meta["operator_limit"] is False

    @pytest.mark.parametrize("kind", ["provider_balance", "operator_reserve", "run_budget"])
    def test_MACHINERY_failure_with_an_UNUSED_allowance_is_a_gap_ONLY(self, kind):
        """review-B1.6b20: a remainder alone activated the policy's boundary, so a run OUR machinery
        stopped reported a provider or operator limit it never reached. `stop_kind` says what the policy
        WOULD bound; only the scheduler knows whether the allowance was actually spent."""
        r = _term(stop_cause="publish_failed", publish_failed=1, unopened=["email=a"],
                  pol=wp.SpendPolicy(pages=5, stop_kind=kind))
        assert r.status is Status.FAILED, r.status
        assert r.meta["gap_reason"] and not r.meta["provider_limit"] and not r.meta["operator_limit"]
        assert r.meta["limit_origin"] is None, r.meta

    @pytest.mark.parametrize("kind,provider,operator", [("provider_balance", True, False),
                                                        ("operator_reserve", False, True),
                                                        ("run_budget", False, True)])
    def test_an_EXHAUSTED_allowance_with_a_remainder_is_a_soft_limit(self, kind, provider, operator):
        r = _term(allowance_exhausted=True, pages_left_known=7,
                  pol=wp.SpendPolicy(pages=3, stop_kind=kind))
        assert r.status is Status.LIMITED
        assert r.meta["provider_limit"] is provider and r.meta["operator_limit"] is operator

    def test_a_PAGE_QUOTA_survives_alongside_an_exhausted_operator_allowance(self):
        """A page-proven limit is independent of the allowance: both really happened."""
        r = _term(allowance_exhausted=True, limit_classes={"quota": 1}, limit_reason="quota: spent",
                  pages_left_known=7, pol=wp.SpendPolicy(pages=3, stop_kind="operator_reserve"))
        assert r.meta["provider_limit"] is True and r.meta["operator_limit"] is True
        assert r.meta["limit_origin"] == "provider+operator"

    def test_a_PAGE_QUOTA_needs_no_allowance_to_be_reported(self):
        """...and it stands on its own when the allowance was never touched."""
        r = _term(limit_classes={"quota": 1}, limit_reason="quota: spent", pages_bought=1, domains=5)
        assert r.status is Status.LIMITED and r.meta["provider_limit"] is True
        assert r.meta["operator_limit"] is False

    def test_a_PROVIDER_and_an_OPERATOR_limit_can_BOTH_be_true(self):
        """review-B1.6b19: `limit_origin` was a single value and provider won first, so a quota AND a
        reserve together reported `operator_limit=False` beside `spend_stop_kind="operator_reserve"` —
        metadata contradicting itself, with our own boundary dropped. One run can hit both."""
        r = _term(allowance_exhausted=True, limit_classes={"quota": 1},
                  limit_reason="quota: Zero Account Balance", pages_left_known=7,
                  pol=wp.SpendPolicy(pages=3, stop_kind="operator_reserve"))
        m = r.meta
        assert r.status is Status.LIMITED
        assert m["provider_limit"] is True and m["operator_limit"] is True
        assert m["limit_origin"] == "provider+operator", m["limit_origin"]
        assert m["provider_limit_reason"] == "quota: Zero Account Balance"
        assert "withheld by the operator" in m["operator_limit_reason"]
        assert m["spend_stop_kind"] == "operator_reserve"

    def test_BOTH_limit_kinds_reach_BOTH_session_lists(self, tmp_path):
        r = _term(allowance_exhausted=True, limit_classes={"quota": 1}, limit_reason="quota: spent",
                  pages_left_known=7, pol=wp.SpendPolicy(pages=3, stop_kind="run_budget"))
        s = osint.OsintSession(tmp_path, "acme.com")
        s.record(r)
        v = s.outcome()
        assert v["verdict"] == "complete_with_limits", v
        assert v["provider_limits"] and v["operator_limits"], v

    def test_an_invalid_control_does_not_erase_a_provider_refusal(self):
        pol = wp.SpendPolicy(pages=0, invalid="WHOXY_CREDIT_RESERVE",
                             limit="quota: Zero Account Balance")
        r = _term(pol=pol)
        assert r.status is Status.FAILED and r.meta["config_invalid"]
        assert r.meta["limit_reason"] == "quota: Zero Account Balance"


class TestTheSessionVerdictSeesBoth:
    """review-B1.6b14#4: an OPERATOR boundary was invisible to `OsintSession.outcome()`, so a
    deliberately withheld remainder folded as `complete`."""

    def _verdict(self, tmp_path, meta, status):
        s = osint.OsintSession(tmp_path, "acme.com")
        s.record(osint.RunResult("whoxy", ["whoxy"], status, None, 0.0, None, 0,
                                 note="n", meta=meta))
        return s.outcome()

    def test_an_OPERATOR_limit_lifts_the_session_to_limits_as_OURS(self, tmp_path):
        """review-B1.6b15#1: this asserted `v["provider_limits"]` for an operator reserve — pinning the
        blame-shift instead of catching it. Both kinds lift the verdict; they are reported apart."""
        r = _term(allowance_exhausted=True, unopened=["email=a"],
                  pol=wp.SpendPolicy(pages=0, stop_kind="operator_reserve"))
        v = self._verdict(tmp_path, r.meta, r.status)
        assert v["verdict"] == "complete_with_limits", v
        assert v["operator_limits"] and not v["provider_limits"], v
        assert not v["gaps"]

    def test_a_PROVIDER_limit_lifts_the_session_to_limits(self, tmp_path):
        r = _term(allowance_exhausted=True, unopened=["email=a"],
                  pol=wp.SpendPolicy(pages=0, stop_kind="provider_balance"))
        v = self._verdict(tmp_path, r.meta, r.status)
        assert v["verdict"] == "complete_with_limits", v
        assert v["provider_limits"] and not v["operator_limits"], v

    def test_a_clean_lane_is_complete(self, tmp_path):
        r = _term(pages_bought=1, domains=2, requested={("email", "a")})
        assert r.status is Status.SUCCESS
        assert self._verdict(tmp_path, r.meta, r.status)["verdict"] == "complete"

    def test_a_gap_beats_a_simultaneous_limit(self, tmp_path):
        r = _term(fail_classes={"transport": 1}, limit_classes={"quota": 1},
                  fail_reason="transport: boom", limit_reason="quota: spent", domains=1,
                  pages_bought=1)
        v = self._verdict(tmp_path, r.meta, r.status)
        assert v["verdict"] == "complete_with_gaps" and v["provider_limits"], v


class TestAttemptedCountsRequests:
    """review-B1.6b14#6: `anchors - unopened` counted a replay-only lifecycle as having attempted every
    anchor while issuing zero requests."""

    def test_a_REPLAY_ONLY_lifecycle_attempted_nothing(self):
        r = _term(pages_replayed=3, domains=250, anchors_touched=1)
        assert r.meta["attempted"] == 0 and r.meta["requests_issued"] == 0
        assert r.meta["completed"] == 1 and r.meta["pages_replayed"] == 3

    def test_a_REJECTED_page_one_still_counts_as_attempted(self):
        r = _term(fail_classes={"transport": 1}, fail_reason="transport: boom",
                  requested={("email", "a@x.com")}, requests_issued=1)
        assert r.meta["attempted"] == 1 and r.meta["completed"] == 0


class TestACleanLifecycleStaysClean:
    """review-B1.6b25: a fabricated machinery fact reaches the operator as a gap on a run that lost
    nothing. The terminal is where that lie would land, so it is asserted here too."""

    def test_a_fully_persisted_run_reports_SUCCESS_with_no_machinery(self):
        r = _term(anchors=1, anchors_touched=1, pages_bought=3, domains=250, persisted=True)
        assert r.status is Status.SUCCESS, r.status
        assert r.meta["gap_reason"] is None and r.meta["machinery"] == []
        assert not r.meta.get("coverage_incomplete")
        assert r.meta["provider_limit"] is False and r.meta["operator_limit"] is False

    def test_a_RETAINED_machinery_fact_always_reaches_the_terminal(self):
        r = _term(anchors=1, anchors_touched=1, pages_bought=3, domains=250, persisted=True,
                  machinery=["OSError: fallback exploded"])
        assert r.status is not Status.SUCCESS, "a machinery failure reported as a clean run"
        assert "fallback exploded" in r.meta["gap_reason"], r.meta["gap_reason"]


class TestMachineryReasonsAreSaidOnce:
    """review-B1.6b26: the first reason is already carried by `fail_reason`, and the appendix repeated
    it verbatim as soon as a second failure existed."""

    def test_TWO_machinery_failures_each_appear_exactly_once(self):
        r = _term(anchors=1, anchors_touched=1, pages_replayed=1, domains=100,
                  fail_reason="page state machinery failed (ValueError: first)",
                  stop_cause="machinery:ValueError",
                  machinery=["ValueError: first", "OSError: second"])
        gap = r.meta["gap_reason"]
        assert gap.count("ValueError: first") == 1, gap
        assert gap.count("OSError: second") == 1, gap
        assert r.meta["machinery"] == ["ValueError: first", "OSError: second"]

    def test_a_PROVIDER_reason_keeps_the_lead_and_both_machinery_facts_follow(self):
        r = _term(anchors=1, anchors_touched=1, pages_bought=1, domains=100,
                  fail_reason="transport: connection died", fail_classes={"transport": 1},
                  machinery=["ValueError: first", "OSError: second"])
        gap = r.meta["gap_reason"]
        assert gap.startswith("transport: connection died"), gap
        assert gap.count("ValueError: first") == 1 and gap.count("OSError: second") == 1, gap

    def test_a_SINGLE_machinery_failure_is_not_repeated(self):
        r = _term(anchors=1, anchors_touched=1, pages_replayed=1, domains=100,
                  fail_reason="page state machinery failed (ValueError: only)",
                  machinery=["ValueError: only"])
        assert r.meta["gap_reason"].count("ValueError: only") == 1, r.meta["gap_reason"]
