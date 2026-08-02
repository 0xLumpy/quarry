"""The campaign supervisor's LEDGER and STOP RULES — settle, the supervisor step.

It creates no runs here: what is pinned is what makes repeating them safe. One project may have one
campaign at a time; every child is recorded BEFORE it launches, so a crash leaves an interrupted child
rather than an orphan run directory; and every ending is a NAMED outcome, because a supervisor that runs
out of reasons and simply stops has told the operator nothing.
"""
from __future__ import annotations

import json

import pytest

from quarry_recon import budget, campaign


def _summary(*, remainders=(), faults=(), verdict="complete", spend=()):
    return {"verdict": verdict, "faults": list(faults), "remainders": list(remainders),
            "provider_spend": list(spend)}


def _rem(lane="enrich.a1d_brute", *, now=0, cooldown=0, terminal=None, model="project_progress"):
    return {"lane": lane, "unit": f"{lane}:targets", "measure": "targets", "model": model,
            "retriable": {"now": now, "cooldown": cooldown},
            "terminal": terminal or {"unschedulable": 0, "entitlement": 0, "dependency": 0,
                                     "machinery": 0}}


def _absorbed(new=0, enriched=0, unusable=None):
    out = campaign.AbsorbResult(new=new, enriched=enriched, unusable=dict(unusable or {}))
    out.absorbed = True
    return out


class TestTheStopRules:
    def test_a_FIXED_POINT_needs_known_zeroes_and_nothing_new(self):
        d = campaign.decide(_summary(remainders=[_rem()]), _absorbed(),
                            expected_lanes=["enrich.a1d_brute"])
        assert (d.stop, d.success) == ("fixed_point", True), d

    def test_RETRIABLE_work_keeps_the_campaign_alive(self):
        d = campaign.decide(_summary(remainders=[_rem(now=3)]), _absorbed(new=1),
                            expected_lanes=["enrich.a1d_brute"])
        assert d.stop is None and d.retriable == 3 and d.progressed, d

    def test_a_COOLDOWN_blocks_success_without_keeping_the_loop_running(self):
        """It is retriable, so it is not a fixed point — and the no-progress rule still ends the campaign
        rather than spinning children to burn generations."""
        cooling = _summary(remainders=[_rem(cooldown=2)])
        assert campaign.decide(cooling, _absorbed(), expected_lanes=["enrich.a1d_brute"]).stop is None
        stopped = campaign.decide(cooling, _absorbed(), expected_lanes=["enrich.a1d_brute"],
                                  idle_children=1)
        assert stopped.stop == "no_progress" and "stayed owed" in stopped.detail, stopped

    def test_a_RERUN_SAME_WORK_remainder_never_keeps_it_alive(self):
        """Repetition cannot reach it — that remainder is `--unbound`'s business."""
        d = campaign.decide(_summary(remainders=[_rem("vertical.alterx_permute", now=5,
                                                      model="rerun_same_work")]),
                            _absorbed(), expected_lanes=["vertical.alterx_permute"])
        assert d.stop == "fixed_point" and d.retriable == 0, d

    def test_TERMINAL_work_is_a_distinct_non_success(self):
        d = campaign.decide(_summary(remainders=[_rem(terminal={"unschedulable": 4})]), _absorbed(),
                            expected_lanes=["enrich.a1d_brute"])
        assert (d.stop, d.success) == ("terminal", False), d
        assert "unschedulable: 4" in d.detail, d

    def test_a_SILENT_lane_is_unknown_not_zero(self):
        d = campaign.decide(_summary(remainders=[_rem()]), _absorbed(),
                            expected_lanes=["enrich.a1d_brute", "vertical.wildcard_http"])
        assert d.stop == "unknown" and "vertical.wildcard_http" in d.detail, d

    def test_an_UNREADABLE_remainder_is_unknown(self):
        d = campaign.decide(_summary(remainders=[{"lane": "enrich.a1d_brute", "invalid": "bad"}]),
                            _absorbed(), expected_lanes=["enrich.a1d_brute"])
        assert d.stop == "unknown" and "unreadable" in d.detail, d

    def test_UNREADABLE_evidence_stops_the_campaign(self):
        d = campaign.decide(_summary(remainders=[_rem()]), _absorbed(unusable={"subdomain": "unusable"}),
                            expected_lanes=["enrich.a1d_brute"])
        assert d.stop == "unknown" and "subdomain" in d.detail, d

    @pytest.mark.parametrize("kind", ["machinery", "phase_exception", "required_tool_missing"])
    def test_a_BROKEN_child_ends_it_first(self, kind):
        """Repeating a run that broke is not continuation — and it is asked BEFORE anything else, so one
        child can never be classified two ways."""
        d = campaign.decide(_summary(faults=[{"kind": kind, "where": "httpx"}],
                                     remainders=[_rem(now=9)]), _absorbed(new=5),
                            expected_lanes=["enrich.a1d_brute"])
        assert d.stop == "child_fault" and kind in d.detail, d

    def test_an_OPTIONAL_tool_failure_is_not_a_child_fault(self):
        d = campaign.decide(_summary(faults=[{"kind": "optional_tool_failed", "where": "gowitness"}],
                                     remainders=[_rem()]), _absorbed(),
                            expected_lanes=["enrich.a1d_brute"])
        assert d.stop == "fixed_point", d

    def test_the_MAX_CHILDREN_bound_is_a_named_stop(self):
        d = campaign.decide(_summary(remainders=[_rem(now=1)]), _absorbed(new=1),
                            expected_lanes=["enrich.a1d_brute"], children=10)
        assert d.stop == "max_runs" and "10 child" in d.detail, d

    def test_progress_with_nothing_owed_still_runs_another_child(self):
        """It learned something and reports no remainder — the next child is what proves the fixed point."""
        d = campaign.decide(_summary(remainders=[_rem()]), _absorbed(enriched=1),
                            expected_lanes=["enrich.a1d_brute"])
        assert d.stop is None and d.progressed, d


class TestTheLedger:
    def test_a_child_is_RESERVED_before_it_launches(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        assert child["state"] == "reserved" and child["run_id"] is None
        stored = json.loads(c.path.read_text())["children"]
        assert stored == [{"index": 1, "state": "reserved", "run_id": None}], stored

    def test_the_states_advance_and_are_DURABLE(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        c.started(child, "20260802-abc")
        c.manifested(child, summary=_summary(spend=[{"lane": "probe.cert", "amount": 2}]),
                     absorbed=_absorbed(new=3, enriched=1),
                     decision=campaign.Decision(retriable=4, progressed=True))
        c.finish(campaign.Decision(stop="fixed_point", detail="done"))
        reopened = campaign.Campaign(tmp_path, "c1")
        kid = reopened.children[0]
        assert (kid["state"], kid["run_id"], kid["new_identities"]) == ("manifested", "20260802-abc", 3)
        assert kid["provider_spend"] == [{"lane": "probe.cert", "amount": 2}], kid
        assert reopened.stop == {"cause": "fixed_point", "detail": "done", "success": True}

    def test_an_INTERRUPTED_child_is_visible(self, tmp_path):
        """A crash between reserving and manifesting leaves a child in its last known state — never an
        orphan run directory nobody can account for."""
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        c.started(child, "20260802-abc")
        reopened = campaign.Campaign(tmp_path, "c1")
        assert [k["state"] for k in reopened.interrupted] == ["started"], reopened.children

    def test_the_lock_is_PROJECT_scoped(self, tmp_path):
        """Two supervisors that minted different ids would otherwise take different locks and both spawn
        children against the same rotation."""
        first = campaign.Campaign(tmp_path, "c1")
        with first.acquire():
            other = campaign.Campaign(tmp_path, "c2")          # a DIFFERENT campaign id, same project
            with pytest.raises(budget.StateBusy):
                with other.acquire():
                    pass

    def test_the_lock_is_released_afterwards(self, tmp_path):
        first = campaign.Campaign(tmp_path, "c1")
        with first.acquire():
            pass
        with campaign.Campaign(tmp_path, "c2").acquire():
            pass

    def test_a_corrupt_ledger_does_not_crash_the_supervisor(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text("{not json")
        assert campaign.Campaign(tmp_path, "c1").children == []
