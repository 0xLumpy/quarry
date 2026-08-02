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


class TestProgressIncludesReducingTheRemainder:
    def test_taking_owed_work_forward_is_PROGRESS(self):
        """A child that discovered no identity but reduced what is owed from 10 to 5 is not idle, and
        stopping it would abandon work the campaign was measurably completing."""
        d = campaign.decide(_summary(remainders=[_rem(now=5)]), _absorbed(),
                            expected_lanes=["enrich.a1d_brute"], idle_children=1,
                            previous_retriable=10)
        assert d.stop is None and d.progressed and d.retriable == 5, d

    def test_an_UNCHANGED_remainder_with_no_discovery_is_idle(self):
        d = campaign.decide(_summary(remainders=[_rem(now=10)]), _absorbed(),
                            expected_lanes=["enrich.a1d_brute"], idle_children=1,
                            previous_retriable=10)
        assert d.stop == "no_progress" and "reduced nothing" in d.detail, d

    def test_a_GROWING_remainder_is_not_progress_either(self):
        """More work appearing is not the same as work being done."""
        d = campaign.decide(_summary(remainders=[_rem(now=12)]), _absorbed(),
                            expected_lanes=["enrich.a1d_brute"], idle_children=1,
                            previous_retriable=10)
        assert d.stop == "no_progress", d


class TestEveryRemainderUNITCounts:
    def test_units_of_one_lane_are_AGGREGATED(self):
        rows = [_rem(now=3), {**_rem(now=4), "unit": "enrich.a1d_brute:candidate_pairs",
                              "measure": "candidate_pairs"}]
        d = campaign.decide(_summary(remainders=rows), _absorbed(new=1),
                            expected_lanes=["enrich.a1d_brute"])
        assert d.retriable == 7, d          # one row per lane dropped the other unit entirely

    def test_an_INVALID_unit_is_not_hidden_by_a_valid_sibling(self):
        rows = [_rem(now=3), {"lane": "enrich.a1d_brute", "unit": "enrich.a1d_brute:pairs",
                              "invalid": "unreadable"}]
        d = campaign.decide(_summary(remainders=rows), _absorbed(),
                            expected_lanes=["enrich.a1d_brute"])
        assert d.stop == "unknown" and "could not measure its remainder" in d.detail, d

    @pytest.mark.parametrize("row", [
        {"model": "invented"}, {"retriable": {"now": -1, "cooldown": 0}},
        {"retriable": {"now": True, "cooldown": 0}}, {"retriable": "five"},
        {"terminal": {"invented": 1}}, {"unit": 7}])
    def test_a_malformed_unit_is_UNKNOWN(self, row):
        d = campaign.decide(_summary(remainders=[{**_rem(), **row}]), _absorbed(),
                            expected_lanes=["enrich.a1d_brute"])
        assert d.stop == "unknown", (row, d)


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
        d = campaign.decide(_summary(remainders=[{"lane": "enrich.a1d_brute", "model": "nonsense"}]),
                            _absorbed(), expected_lanes=["enrich.a1d_brute"])
        assert d.stop == "unknown" and "unreadable remainder" in d.detail, d

    def test_a_lane_that_COULD_NOT_MEASURE_says_that_not_merely_unreadable(self):
        """The manifest already flagged this row: the lane RAN and could not measure. An operator should
        not have to guess whether the record was corrupt or the measurement never happened."""
        d = campaign.decide(_summary(remainders=[{"lane": "enrich.a1d_brute", "invalid": "bad"}]),
                            _absorbed(), expected_lanes=["enrich.a1d_brute"])
        assert d.stop == "unknown" and "could not measure its remainder" in d.detail, d

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

    @pytest.mark.parametrize("corruption", [
        "{not json", "[]", '{"children": "two"}',
        '{"children": [{"index": 2, "state": "reserved", "run_id": null}]}',      # index out of order
        '{"children": [{"index": 1, "state": "invented", "run_id": null}]}',      # unknown state
        '{"children": [{"index": 1, "state": "started", "run_id": 7}]}',          # run id is not an id
        '{"children": [null]}'])
    def test_a_CORRUPT_ledger_is_unusable_not_a_new_campaign(self, tmp_path, corruption):
        """Absence may create; corruption may not. Treating them alike let the next `reserve()` publish
        child 1 again and launder the whole campaign's history."""
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text(corruption)
        reopened = campaign.Campaign(tmp_path, "c1")
        assert (reopened.status, reopened.trustworthy) == ("unusable", False), (corruption, reopened.status)
        with pytest.raises(campaign.UnionUnusable):
            reopened.reserve()
        assert reopened.path.read_text() == corruption, "the evidence must not be overwritten"

    def test_an_ABSENT_ledger_is_a_new_campaign(self, tmp_path):
        fresh = campaign.Campaign(tmp_path, "c1")
        assert (fresh.status, fresh.trustworthy) == ("new", True)
        fresh.reserve()
        assert campaign.Campaign(tmp_path, "c1").status == "valid"

    def test_RECOVERY_is_explicit_and_states_the_loss(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text("{not json")
        broken = campaign.Campaign(tmp_path, "c1")
        with pytest.raises(ValueError):
            broken.recover("")
        broken.recover("ledger was unreadable")
        history = json.loads(c.path.read_text())["recoveries"]
        assert [(r["index"], r["reason"]) for r in history] == [(1, "ledger was unreadable")]
        assert "not JSON" in history[0]["cause"] and history[0]["at"].endswith("+00:00")
        assert campaign.Campaign(tmp_path, "c1").status == "valid"

    def test_recovery_ADMISSION_survives_every_later_publication(self, tmp_path):
        """The union already lost a recovery this way: an admission recorded only in the document that
        gets rewritten is an admission the next child deletes."""
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text("{not json")
        broken = campaign.Campaign(tmp_path, "c1")
        broken.recover("first loss")
        broken.started(broken.reserve(), "run-2")
        assert [r["reason"] for r in campaign.Campaign(tmp_path, "c1").recoveries] == ["first loss"]

    def test_a_SECOND_recovery_does_not_erase_the_first_confession(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text("{not json")
        again = campaign.Campaign(tmp_path, "c1")
        again.recover("first loss")
        doc = json.loads(again.path.read_text())
        doc["children"] = "wrecked"                       # corrupt again, history still readable
        again.path.write_text(json.dumps(doc))
        second = campaign.Campaign(tmp_path, "c1")
        second.recover("second loss")
        assert [(r["index"], r["reason"]) for r in second.recoveries] == [
            (1, "first loss"), (2, "second loss")]

    def test_a_HEALTHY_campaign_cannot_be_recovered(self, tmp_path):
        """Recovery erases every child. On a readable ledger that is not repair, it is the laundering
        `require()` exists to stop."""
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.reserve()
        for reopened in (c, campaign.Campaign(tmp_path, "c1")):
            with pytest.raises(ValueError, match="nothing to recover"):
                reopened.recover("i would rather start over")
        assert len(campaign.Campaign(tmp_path, "c1").children) == 2

    def test_an_UNREADABLE_recovery_history_makes_the_ledger_unusable(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        for history in ([{"index": 2, "reason": "x", "cause": "y", "at": "2026-08-02T00:00:00+00:00"}],
                        [{"index": 1, "reason": " ", "cause": "y", "at": "2026-08-02T00:00:00+00:00"}],
                        [{"index": 1, "reason": "x", "cause": "y", "at": "2026-08-02T00:00:00"}],
                        [{"index": 1, "reason": "x", "at": "2026-08-02T00:00:00+00:00"}],
                        "a recovery", [None]):
            doc = json.loads(c.path.read_text())
            doc["recoveries"] = history
            c.path.write_text(json.dumps(doc))
            assert campaign.Campaign(tmp_path, "c1").status == "unusable", history

    def test_a_ledger_from_ANOTHER_campaign_is_not_ours_to_rewrite(self, tmp_path):
        other = campaign.Campaign(tmp_path, "c2")
        other.reserve()
        mine = tmp_path / "recon" / "campaigns" / "c1"
        mine.mkdir(parents=True)
        (mine / "ledger.json").write_text(other.path.read_text())
        assert campaign.Campaign(tmp_path, "c1").status == "unusable"

    @pytest.mark.parametrize("child", [
        {"index": 1, "state": "reserved", "run_id": "r1"},                       # reserved, yet has a run
        {"index": 1, "state": "started", "run_id": " "},                         # started without one
        {"index": 1, "state": "manifested", "run_id": "r1"},                     # no deltas at all
        {"index": 1, "state": "manifested", "run_id": "r1", "new_identities": 1, "enriched": 0,
         "retriable": -1, "progressed": True, "provider_spend": [], "faults": [], "verdict": "success"},
        {"index": 1, "state": "manifested", "run_id": "r1", "new_identities": 1, "enriched": 0,
         "retriable": 0, "progressed": 1, "provider_spend": [], "faults": [], "verdict": "success"},
        {"index": 1, "state": "manifested", "run_id": "r1", "new_identities": 1, "enriched": 0,
         "retriable": 0, "progressed": True, "provider_spend": {}, "faults": [], "verdict": "success"},
        {"index": 1, "state": "manifested", "run_id": "r1", "new_identities": 1, "enriched": 0,
         "retriable": 0, "progressed": True, "provider_spend": [], "faults": [], "verdict": 7}])
    def test_a_child_that_CONTRADICTS_its_state_is_unusable(self, tmp_path, child):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text(json.dumps({"campaign_id": "c1", "children": [child], "stop": None,
                                      "recoveries": []}))
        assert campaign.Campaign(tmp_path, "c1").status == "unusable", child

    @pytest.mark.parametrize("stop", ["stopped", {"cause": "", "detail": "d", "success": True},
                                      {"cause": "no_progress", "detail": "d"},
                                      {"cause": "no_progress", "detail": "d", "success": "yes"},
                                      {"cause": "no_progress", "detail": "d", "success": True, "x": 1}])
    def test_an_arbitrary_STOP_object_is_unusable(self, tmp_path, stop):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text(json.dumps({"campaign_id": "c1", "children": c.children, "stop": stop,
                                      "recoveries": []}))
        assert campaign.Campaign(tmp_path, "c1").status == "unusable", stop


class TestEveryWriteIsFailClosed:
    def _wrecked(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        c.path.write_text("{not json")
        return campaign.Campaign(tmp_path, "c1"), child

    def test_STARTED_refuses_an_unusable_ledger(self, tmp_path):
        c, child = self._wrecked(tmp_path)
        with pytest.raises(campaign.UnionUnusable):
            c.started(child, "run-1")

    def test_MANIFESTED_refuses_an_unusable_ledger(self, tmp_path):
        c, child = self._wrecked(tmp_path)
        with pytest.raises(campaign.UnionUnusable):
            c.manifested(child, summary=_summary(), absorbed=_absorbed(), decision=campaign.decide(
                _summary(), _absorbed(new=1)))

    def test_FINISH_refuses_an_unusable_ledger(self, tmp_path):
        """The laundering door: `finish()` wrote the whole ledger back out with no trust check at all."""
        c, _ = self._wrecked(tmp_path)
        with pytest.raises(campaign.UnionUnusable):
            c.finish(campaign.decide(_summary(), _absorbed(new=1)))
        assert c.path.read_text() == "{not json"

    def test_a_child_from_ANOTHER_campaign_cannot_be_advanced(self, tmp_path):
        mine, theirs = campaign.Campaign(tmp_path, "c1"), campaign.Campaign(tmp_path, "c2")
        stolen = theirs.reserve()
        mine.reserve()
        with pytest.raises(ValueError, match="does not belong"):
            mine.started(stolen, "run-1")

    def test_a_COPY_of_our_own_child_is_not_the_record(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        copy = dict(c.reserve())
        with pytest.raises(ValueError, match="does not belong"):
            c.started(copy, "run-1")

    @pytest.mark.parametrize("path", [("manifested",), ("started", "started"),
                                      ("started", "manifested", "manifested")])
    def test_states_advance_in_ORDER_only(self, tmp_path, path):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        with pytest.raises(ValueError, match="not a transition"):
            for step in path:
                if step == "started":
                    c.started(child, f"run-{child['index']}")
                else:
                    c.manifested(child, summary=_summary(), absorbed=_absorbed(new=1),
                                 decision=campaign.decide(_summary(), _absorbed(new=1)))

    def test_a_started_child_must_NAME_its_run(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        with pytest.raises(ValueError, match="must name its run"):
            c.started(c.reserve(), "  ")

    def test_a_manifested_child_is_written_only_if_it_can_be_READ_back(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        c.started(child, "run-1")
        with pytest.raises(ValueError, match="provider_spend"):
            c.manifested(child, summary={"verdict": "success", "provider_spend": {}, "faults": []},
                         absorbed=_absorbed(new=1), decision=campaign.decide(_summary(), _absorbed(new=1)))
        assert campaign.Campaign(tmp_path, "c1").status == "valid"

    def test_a_REJECTED_manifestation_leaves_the_live_child_untouched(self, tmp_path):
        """Validating after mutating produced exactly the record it refused: the child stayed `manifested`
        and malformed in memory, and the next `finish()` published it."""
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        c.started(child, "run-1")
        before = dict(child)
        with pytest.raises(ValueError):
            c.manifested(child, summary={"verdict": "success", "provider_spend": {}, "faults": []},
                         absorbed=_absorbed(new=1), decision=campaign.decide(_summary(), _absorbed(new=1)))
        assert child == before, "the rejected candidate was written onto the owned record"
        c.finish(campaign.decide(_summary(), _absorbed(new=1)))
        assert campaign.Campaign(tmp_path, "c1").status == "valid"

    def test_a_child_rejected_once_can_still_be_manifested_PROPERLY(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        c.started(child, "run-1")
        with pytest.raises(ValueError):
            c.manifested(child, summary={"provider_spend": {}}, absorbed=_absorbed(new=1),
                         decision=campaign.decide(_summary(), _absorbed(new=1)))
        c.manifested(child, summary=_summary(), absorbed=_absorbed(new=1),
                     decision=campaign.decide(_summary(), _absorbed(new=1)))
        reopened = campaign.Campaign(tmp_path, "c1")
        assert (reopened.status, reopened.children[0]["state"]) == ("valid", "manifested")


class TestNoWriterCanPublishWhatLoadRefuses:
    """`reserve()` hands back the LIVE record. Validating only the child a transition touched left every
    other route open — the snapshot is what reaches disk, so the snapshot is what must be readable."""

    def test_a_hand_EDITED_child_cannot_be_published_by_finish(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        child["run_id"] = "run-that-never-started"        # contradicts `reserved`
        with pytest.raises(ValueError, match="already names a run"):
            c.finish(campaign.decide(_summary(), _absorbed(new=1)))
        reopened = campaign.Campaign(tmp_path, "c1")
        assert (reopened.status, reopened.stop) == ("valid", None)

    def test_a_hand_EDITED_child_cannot_ride_along_with_a_later_reserve(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        first = c.reserve()
        first["state"] = "manifested"                     # no run, no deltas
        with pytest.raises(ValueError, match="child 1"):
            c.reserve()
        assert len(campaign.Campaign(tmp_path, "c1").children) == 1

    def test_a_hand_EDITED_child_cannot_ride_along_with_a_TRANSITION(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        first, second = c.reserve(), c.reserve()
        first["index"] = 9
        with pytest.raises(ValueError, match="child 1"):
            c.started(second, "run-2")
        assert campaign.Campaign(tmp_path, "c1").status == "valid"

    def test_an_unpublishable_document_is_refused_BEFORE_the_disk_is_touched(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        before = c.path.read_text()
        child["state"] = "started"                        # started without a run id
        with pytest.raises(ValueError):
            c.finish(campaign.decide(_summary(), _absorbed(new=1)))
        assert c.path.read_text() == before and c.trustworthy

    def test_an_unreadable_RECOVERY_history_is_refused(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        c.recoveries = [{"index": 1, "reason": "x"}]
        with pytest.raises(ValueError, match="recovery history"):
            c.reserve()

    def test_an_unreadable_STOP_is_refused(self, tmp_path):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.stop = "stopped"
        with pytest.raises(ValueError, match="stop record"):
            c.reserve()


class TestAFailedPublicationSettles:
    """An atomic write either landed or it did not, and after an interruption this object cannot know
    which. Believing memory is how a campaign publishes children no disk ever held."""

    @staticmethod
    def _breaking(monkeypatch, *, land: bool):
        real = campaign.store._atomic_write

        def broken(path, body, *a, **kw):
            if land:
                real(path, body, *a, **kw)          # the write LANDED, then we were interrupted
            raise OSError("interrupted")
        monkeypatch.setattr(campaign.store, "_atomic_write", broken)
        return lambda: monkeypatch.setattr(campaign.store, "_atomic_write", real)

    def test_a_failed_first_reserve_leaves_NO_phantom_child(self, tmp_path, monkeypatch):
        c = campaign.Campaign(tmp_path, "c1")
        restore = self._breaking(monkeypatch, land=False)
        with pytest.raises(OSError):
            c.reserve()
        assert c.children == [] and c.status == "new"
        restore()
        assert c.reserve()["index"] == 1, "the next reserve published a phantom child 1 beside it"
        assert [k["index"] for k in campaign.Campaign(tmp_path, "c1").children] == [1]

    def test_a_LANDED_write_that_still_raised_is_adopted_not_discarded(self, tmp_path, monkeypatch):
        c = campaign.Campaign(tmp_path, "c1")
        restore = self._breaking(monkeypatch, land=True)
        with pytest.raises(OSError):
            c.reserve()
        restore()
        assert [k["index"] for k in c.children] == [1], "the landed child was thrown away"
        assert c.reserve()["index"] == 2
        assert [k["index"] for k in campaign.Campaign(tmp_path, "c1").children] == [1, 2]

    def test_a_failed_TRANSITION_does_not_advance_memory(self, tmp_path, monkeypatch):
        c = campaign.Campaign(tmp_path, "c1")
        child = c.reserve()
        restore = self._breaking(monkeypatch, land=False)
        with pytest.raises(OSError):
            c.started(child, "run-1")
        restore()
        assert child["state"] == "reserved" and child["run_id"] is None
        c.started(child, "run-1")                    # the transition is still available
        assert campaign.Campaign(tmp_path, "c1").children[0]["run_id"] == "run-1"

    def test_a_failed_FINISH_does_not_claim_a_stop(self, tmp_path, monkeypatch):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        restore = self._breaking(monkeypatch, land=False)
        with pytest.raises(OSError):
            c.finish(campaign.decide(_summary(), _absorbed(new=1)))
        restore()
        assert c.stop is None and campaign.Campaign(tmp_path, "c1").stop is None

    def test_a_failed_RECOVERY_does_not_erase_the_children(self, tmp_path, monkeypatch):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text("{not json")
        broken = campaign.Campaign(tmp_path, "c1")
        restore = self._breaking(monkeypatch, land=False)
        with pytest.raises(OSError):
            broken.recover("lost it")
        restore()
        assert broken.status == "unusable", "a failed recovery left the ledger trusted"
        assert broken.recoveries == [] and c.path.read_text() == "{not json"

    def test_a_ledger_found_CORRUPT_while_settling_is_unusable(self, tmp_path, monkeypatch):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text("{not json")               # what settling will find
        restore = self._breaking(monkeypatch, land=False)
        with pytest.raises(OSError):
            c.reserve()
        restore()
        assert c.status == "unusable"
        with pytest.raises(campaign.UnionUnusable):
            c.reserve()

    @staticmethod
    def _unsettleable(monkeypatch):
        """Nothing can be written and nothing can be re-read — the one case where ORDER is all that is
        left. Adopting before the write means the campaign now holds state no disk ever saw."""
        monkeypatch.setattr(campaign.store, "_atomic_write",
                            lambda *a, **kw: (_ for _ in ()).throw(OSError("interrupted")))
        monkeypatch.setattr(campaign.Campaign, "_load",
                            lambda self: (_ for _ in ()).throw(OSError("gone")))

    def test_settling_that_itself_fails_says_SO(self, tmp_path, monkeypatch):
        c = campaign.Campaign(tmp_path, "c1")
        self._unsettleable(monkeypatch)
        with pytest.raises(OSError, match="interrupted"):
            c.reserve()
        assert c.status == "unusable" and "could not be re-read" in c.reason
        assert c.children == [], "an unpublished child was adopted anyway"

    def test_an_unsettleable_RECOVERY_claims_nothing(self, tmp_path, monkeypatch):
        c = campaign.Campaign(tmp_path, "c1")
        c.reserve()
        c.path.write_text("{not json")
        broken = campaign.Campaign(tmp_path, "c1")
        self._unsettleable(monkeypatch)
        with pytest.raises(OSError, match="interrupted"):
            broken.recover("lost it")
        assert broken.recoveries == [], "a recovery nobody recorded was claimed in memory"
        assert not broken.trustworthy
