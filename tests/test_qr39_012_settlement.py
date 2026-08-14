"""QR39-012 — settlement proves convergence and resume, or names what it could not prove.

Three things are pinned here that the supervisor could not do before:

  * the obligation ROSTER exists before child one, so a lane that ran and never said what it owes is
    caught in the first child rather than from the second on;
  * silence is tracked by exact `(lane, unit, measure)`, so a lane that keeps reporting one unit and
    drops another cannot retire the dropped one by staying quiet about it;
  * convergence MEANING is read before the budget to continue, and a campaign killed at ANY transition
    resumes from its ledger instead of being refused.

The children are FAKE runs: what is real is everything the supervisor reads — a run directory, its
entity logs, its manifest and the events that carry remainders and coverage.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from quarry_recon import campaign, remainder, settle, store
from quarry_recon.state import ContractError

pytestmark = pytest.mark.offline

LANE = "enrich.a1d_brute"
OTHER = "vertical.wildcard_http"


def _rem(lane=LANE, *, unit=None, measure="targets", now=0, cooldown=0, terminal=None):
    return remainder.Remainder(lane=lane, unit=unit or f"{lane}:{measure}", measure=measure,
                               model="project_progress", now=now, cooldown=cooldown,
                               terminal=dict(terminal or {}))


class _Launcher:
    """Hands each child a run directory, lets the campaign seed it, then returns the finished run.

    A spec may make the child `die` at a named boundary, so a kill can be driven at every transition.
    """

    def __init__(self, project, plan, target="acme.com"):
        self.project, self.plan, self.target = project, list(plan), target
        self.calls: list = []
        self.acquisition: list = []

    def __call__(self, index, prepare):
        from quarry_recon import contract, events
        assert index <= len(self.plan), f"the campaign asked for child {index}; the plan has {len(self.plan)}"
        spec = self.plan[index - 1]
        if spec.get("die") == "before_run":
            raise RuntimeError("killed before a run directory existed")
        run = store.Run.create(self.project, self.target)
        prepare(run)
        self.acquisition.append(contract.acquisition_open("probe.favicon", announce=False))
        if spec.get("die") == "mid_phase":
            self.calls.append({"index": index, "run_id": run.run_id, "died": "mid_phase"})
            raise RuntimeError("killed mid-phase")
        events.configure(run.dir)
        try:
            for host in spec.get("hosts", ()):
                run.add("subdomain", {"host": host, "sources": ["crtsh"]})
            for lane in spec.get("ran", ()):
                # a lane that ran and covered its whole input: activity with no gap and no remainder
                events.coverage_partial(lane, eligible=1, tested=1, omitted=0, kind="cap",
                                        unit=f"{lane}:probe", measure="targets")
            if spec.get("gap"):
                # real lost coverage: the manifest folds it into summary.gaps and the run's verdict
                events.coverage_partial("probe.httpx", eligible=50, tested=10, omitted=40,
                                        kind="timeout", unit="probe.httpx:hosts", measure="hosts")
            for source in spec.get("covered", ()):
                # Explicit source/measure-matching positive evidence; unlike silence, this can discharge
                # the same source's historical coverage gap.
                events.coverage_partial(source, eligible=50, tested=50, omitted=0,
                                        kind="timeout", unit=f"{source}:hosts", measure="hosts")
            for rem in spec.get("remainders", ()):
                remainder.emit(rem)
            for lane in spec.get("unknown", ()):
                remainder.unknown(lane)
            if not spec.get("uncommitted"):
                run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        if spec.get("after_commit"):
            # cli._run_phases unseals the verdict for its derived views: anything that touches the run
            # after the base commit is visible to a RECOMPUTE and absent from what the child published
            run.unseal_verdict()
            spec["after_commit"](run)
        self.calls.append({"index": index, "run_id": run.run_id,
                           "inherited": sum(1 for r in run.read("subdomain") if r.get("_inherited"))})
        if spec.get("die") == "after_manifest":
            raise RuntimeError("killed after the child wrote its manifest")
        return run


def _settle(tmp_path, plan, **kw):
    launcher = _Launcher(tmp_path, plan)
    out = settle.settle(project_dir=tmp_path, target="acme.com", launch=launcher, **kw)
    return out, launcher


def _kill(tmp_path, plan, cid, **kw):
    launcher = _Launcher(tmp_path, plan)
    with pytest.raises(RuntimeError):
        settle.settle(project_dir=tmp_path, target="acme.com", launch=launcher, campaign_id=cid, **kw)
    return launcher


# ── the roster exists before child one ────────────────────────────────────────────────────────────
class TestTheObligationRosterExistsBeforeChildOne:
    def test_a_lane_that_RAN_and_never_reported_is_caught_in_child_one(self, tmp_path):
        """The roster was built from what the campaign had HEARD, so child one had no obligations at all
        and one quiet lane read as a fixed point."""
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "ran": [LANE]}])
        assert out.stop == "unknown" and LANE in out.detail, out
        assert not out.success and len(launcher.calls) == 1, "it took a second child to notice"

    def test_every_declared_lane_is_DISPOSED_of_by_every_child(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                    {"remainders": [_rem()]},
                                    {"remainders": [_rem()]}])
        assert out.stop == "fixed_point", out
        ledger = campaign.Campaign(tmp_path, out.campaign_id)
        for child in ledger.children:
            disposed = {(o["lane"], o["unit"], o["measure"]): o["disposition"]
                        for o in child["obligations"]}
            assert {lane for lane, _u, _m in disposed} >= set(remainder.LANE_MODEL), \
                "a declared lane with no disposition is an obligation nobody accounted for"
            assert all(d in remainder.DISPOSITIONS for d in disposed.values()), disposed
            assert disposed[(LANE, f"{LANE}:targets", "targets")] in ("remainder", "known_zero")
            assert disposed[(OTHER, "", "")] == "not_applicable", "a lane that never ran is not owed work"

    def test_a_lane_that_could_not_MEASURE_is_still_unknown(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"unknown": [LANE]}])
        assert out.stop == "unknown" and "could not measure" in out.detail, out


# ── silence is tracked by exact (lane, unit, measure) ──────────────────────────────────────────────
class TestSilenceCannotHideAnObligation:
    def test_a_lane_that_DROPS_one_of_its_units_is_unknown(self, tmp_path):
        """Both units are the same lane, so a per-lane roster saw the lane report and asked nothing about
        the unit that vanished — with 5 units still owed under it."""
        pairs = f"{LANE}:candidate_pairs"
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"],
                                     "remainders": [_rem(now=1),
                                                    _rem(unit=pairs, measure="candidate_pairs", now=5)]},
                                    {"remainders": [_rem()]}])
        assert out.stop == "unknown" and pairs in out.detail, out
        assert not out.success

    def test_the_same_unit_in_another_MEASURE_is_its_own_obligation(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"],
                                     "remainders": [_rem(now=1), _rem(measure="hosts", now=2)]},
                                    {"remainders": [_rem(), _rem(measure="hosts")]},
                                    {"remainders": [_rem()]}])
        assert out.stop == "unknown" and "hosts" in out.detail, out


# ── convergence meaning is read before the budget to continue ─────────────────────────────────────
class TestMeaningBeforeBudget:
    def test_a_fixed_point_ON_the_last_permitted_child_is_a_fixed_point(self, tmp_path):
        """`max_runs` was asked first, so a campaign that converged exactly as its budget ran out was
        reported as a bound it never actually hit."""
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                           {"remainders": [_rem()]}], max_runs=2)
        assert (out.stop, out.success, out.clean) == ("fixed_point", True, True), out
        assert len(launcher.calls) == 2

    def test_TERMINAL_work_on_the_last_child_is_named_terminal(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                    {"remainders": [_rem(terminal={"entitlement": 2})]}], max_runs=2)
        assert out.stop == "terminal" and "entitlement: 2" in out.detail, out

    def test_owed_work_on_the_last_child_is_still_MAX_RUNS(self, tmp_path):
        """The bound is real when the campaign genuinely had somewhere to go."""
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=9)]},
                                    {"hosts": ["b.acme.com"], "remainders": [_rem(now=9)]}], max_runs=2)
        assert (out.stop, out.detail, out.success) == ("max_runs", "2 child run(s)", False), out


# ── resume at every boundary ──────────────────────────────────────────────────────────────────────
class TestResumeAtEveryBoundary:
    def test_a_child_killed_BEFORE_its_run_existed_is_relaunched(self, tmp_path):
        _kill(tmp_path, [{"die": "before_run"}], "c-1")
        assert [c["state"] for c in campaign.Campaign(tmp_path, "c-1").children] == ["reserved"]
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                           {"remainders": [_rem()]}], campaign_id="c-1")
        assert out.stop == "fixed_point" and out.resumed, out
        assert [c["index"] for c in campaign.Campaign(tmp_path, "c-1").children] == [1, 2]
        assert launcher.acquisition[0] is True, "nothing was ever acquired, so child one still may"

    def test_a_child_killed_MID_PHASE_is_abandoned_and_the_campaign_goes_on(self, tmp_path):
        """Its run has no manifest, so nothing about it can be measured — the campaign says so instead of
        folding an unmeasured child in or refusing to continue at all."""
        _kill(tmp_path, [{"die": "mid_phase"}], "c-2")
        out, launcher = _settle(tmp_path, [{}, {"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                           {"remainders": [_rem()]}], campaign_id="c-2")
        children = campaign.Campaign(tmp_path, "c-2").children
        assert children[0]["state"] == "abandoned" and children[0]["run_id"], children[0]
        assert [c["index"] for c in children] == [1, 2, 3]
        assert out.stop == "fixed_point" and out.abandoned == 1
        assert not out.clean, "a campaign that could not measure one of its children is not clean"
        assert launcher.acquisition == [False, False], "child one already had a run: it may have acquired"

    def test_a_child_killed_AFTER_its_manifest_is_adopted_not_rerun(self, tmp_path):
        """The evidence is complete and paid for; re-running it would spend again and lose the child."""
        killed = _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()], "die": "after_manifest"}],
                       "c-3")
        run_id = killed.calls[0]["run_id"]
        out, launcher = _settle(tmp_path, [{}, {"remainders": [_rem()]}], campaign_id="c-3")
        children = campaign.Campaign(tmp_path, "c-3").children
        assert children[0] == {**children[0], "state": "manifested", "run_id": run_id}
        assert children[0]["new_identities"] == 1, "the adopted child's own discovery was recounted as zero"
        assert out.stop == "fixed_point" and out.resumed, out
        assert [c["index"] for c in launcher.calls] == [2], "the finished child was launched again"

    def test_a_kill_between_ABSORBING_and_recording_replays_the_same_deltas(self, tmp_path, monkeypatch):
        """The union already holds this child's entities, so a second absorb finds nothing new. Reading
        that as `no progress` is the false fixed point a resume must not invent."""
        real = campaign.Campaign.manifested

        def once(self, child, **kw):
            if child["index"] == 1:
                raise RuntimeError("killed after the union was published")
            return real(self, child, **kw)

        monkeypatch.setattr(campaign.Campaign, "manifested", once)
        _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]}], "c-4")
        monkeypatch.setattr(campaign.Campaign, "manifested", real)
        out, _ = _settle(tmp_path, [{}, {"remainders": [_rem()]}], campaign_id="c-4")
        children = campaign.Campaign(tmp_path, "c-4").children
        assert children[0]["state"] == "manifested" and children[0]["new_identities"] == 1, children[0]
        assert (out.stop, out.success) == ("fixed_point", True), out

    def test_a_kill_between_children_resumes_at_the_next_one(self, tmp_path, monkeypatch):
        real = campaign.Campaign.reserve
        seen: list = []

        def once(self):
            seen.append(1)
            if len(seen) == 2:
                raise RuntimeError("killed before child 2 was reserved")
            return real(self)

        monkeypatch.setattr(campaign.Campaign, "reserve", once)
        _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]}], "c-5")
        monkeypatch.setattr(campaign.Campaign, "reserve", real)
        ledger = campaign.Campaign(tmp_path, "c-5")
        assert [c["state"] for c in ledger.children] == ["manifested"] and ledger.stop is None
        out, _ = _settle(tmp_path, [{}, {"remainders": [_rem()]}, {"remainders": [_rem()]}],
                         campaign_id="c-5")
        assert out.stop == "fixed_point" and out.resumed, out
        assert [c["index"] for c in campaign.Campaign(tmp_path, "c-5").children] == [1, 2, 3]

    def test_what_the_killed_children_LEARNED_reaches_the_next_one(self, tmp_path):
        _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()], "die": "after_manifest"}], "c-6")
        _out, launcher = _settle(tmp_path, [{}, {"remainders": [_rem()]}], campaign_id="c-6")
        assert launcher.calls[0]["inherited"] == 1, "the resumed child started blind"

    def test_a_resumed_campaign_keeps_its_OBLIGATIONS(self, tmp_path):
        """A roster rebuilt from nothing would forget that this lane owes anything, and the first quiet
        child after the kill would read as a fixed point."""
        pairs = f"{LANE}:candidate_pairs"
        _kill(tmp_path, [{"hosts": ["a.acme.com"],
                          "remainders": [_rem(now=1), _rem(unit=pairs, measure="candidate_pairs", now=5)],
                          "die": "after_manifest"}], "c-7")
        out, _ = _settle(tmp_path, [{}, {"remainders": [_rem()]}], campaign_id="c-7")
        assert out.stop == "unknown" and pairs in out.detail, out

    def test_a_kill_between_DECIDING_and_recording_the_stop_runs_no_further_child(self, tmp_path):
        """Every child is a whole run: re-deciding one the campaign already measured is free, launching
        another is not."""
        def never(self, decision):
            raise RuntimeError("killed before the stop was recorded")

        launcher = _Launcher(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                        {"remainders": [_rem()]}])
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(campaign.Campaign, "finish", never)
            with pytest.raises(RuntimeError):
                settle.settle(project_dir=tmp_path, target="acme.com", launch=launcher,
                              campaign_id="c-11")
        assert campaign.Campaign(tmp_path, "c-11").stop is None
        out, resumed = _settle(tmp_path, [{}, {}], campaign_id="c-11")
        assert (out.stop, out.success) == ("fixed_point", True), out
        assert resumed.calls == [], "the campaign had already measured its fixed point"
        assert [c.index for c in out.children] == [1, 2]

    def test_a_persisted_max_runs_decision_is_not_reinterpreted_under_a_larger_resume_bound(
        self, tmp_path,
    ):
        """The manifested decision is authority once written; changing the next invocation's bound cannot
        turn it into a continuation that the ledger itself correctly refuses after a terminal child."""
        first = _Launcher(tmp_path, [{"hosts": ["a.acme.com"],
                                      "remainders": [_rem(now=1)]}])

        def killed_before_stop(self, decision):
            raise RuntimeError("killed after the child decision, before the campaign stop")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(campaign.Campaign, "finish", killed_before_stop)
            with pytest.raises(RuntimeError, match="before the campaign stop"):
                settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-max-resume",
                              max_runs=1, launch=first)

        interrupted = campaign.Campaign(tmp_path, "c-max-resume")
        assert interrupted.status == "valid" and interrupted.stop is None
        assert interrupted.children[-1]["decision"]["cause"] == "max_runs"

        resumed = _Launcher(tmp_path, [{"remainders": [_rem()]}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-max-resume",
                            max_runs=2, launch=resumed)
        assert (out.stop, out.success) == ("max_runs", False)
        assert resumed.calls == [], "a persisted terminal child decision launched another child"

    def test_an_abandoned_child_is_a_TERMINAL_ledger_state(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-12")
        settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-12", max_runs=1,
                      launch=_Launcher(tmp_path, [{}, {"remainders": [_rem()]}]))
        reopened = campaign.Campaign(tmp_path, "c-12")
        assert reopened.status == "valid" and reopened.children[0]["state"] == "abandoned"
        assert reopened.interrupted == [], "an abandoned child is accounted for, not still in flight"
        with pytest.raises(ValueError, match="not a transition"):
            reopened.started(reopened.children[0], "run-x")
        with pytest.raises(ValueError, match="not a transition"):
            reopened.abandoned(reopened.children[0], "again")
        assert "ABANDONED" in "\n".join(settle.report_lines(reopened))

    def test_a_child_RESERVED_when_the_campaign_stops_is_not_left_dangling(self, tmp_path):
        """A budget that expires on a resumed campaign must still leave a ledger that accounts for every
        child it recorded."""
        _kill(tmp_path, [{"die": "before_run"}], "c-13")
        spent = [0.0, 99.0]                       # the budget is gone by the first check after t0
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-13", budget_s=10,
                            launch=_Launcher(tmp_path, []),
                            _now=lambda: spent.pop(0) if len(spent) > 1 else spent[0])
        ledger = campaign.Campaign(tmp_path, "c-13")
        assert out.stop == "budget" and out.abandoned == 1, out
        assert ledger.interrupted == [] and ledger.stop["cause"] == "budget"

    def test_a_FINISHED_campaign_is_still_refused(self, tmp_path):
        """Resuming is for a campaign that was interrupted. One that stopped has said its outcome."""
        _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                           {"remainders": [_rem()]}], campaign_id="c-8")
        with pytest.raises(settle.AlreadyRun, match="stopped: fixed_point"):
            _settle(tmp_path, [{"remainders": [_rem()]}], campaign_id="c-8")
        assert len(campaign.Campaign(tmp_path, "c-8").children) == 2

    def test_a_CORRUPT_ledger_is_never_resumed(self, tmp_path):
        _kill(tmp_path, [{"die": "before_run"}], "c-9")
        ledger = campaign.Campaign(tmp_path, "c-9")
        ledger.path.write_text("{not json")
        launched: list = []
        with pytest.raises(campaign.UnionUnusable):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-9",
                          launch=lambda index, prepare: launched.append(index))
        assert launched == [] and ledger.path.read_text() == "{not json"

    def test_a_resume_takes_the_project_LEASE_like_any_campaign(self, tmp_path):
        from quarry_recon import budget
        _kill(tmp_path, [{"die": "before_run"}], "c-10")
        held = campaign.Campaign(tmp_path, "other")
        with held.acquire():
            with pytest.raises(budget.StateBusy):
                _settle(tmp_path, [{"remainders": [_rem()]}], campaign_id="c-10")


class TestAbsorbingIsIdempotent:
    def test_absorbing_one_run_TWICE_reports_the_deltas_once(self, tmp_path):
        run = store.Run.create(tmp_path, "acme.com")
        run.add("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]})
        run.write_manifest(profile_summary={}, phases_run=["vertical"])
        union = campaign.Union.for_campaign(tmp_path, "c-abs", create=True)
        first = union.absorb(run.dir)
        again = union.absorb(run.dir)
        assert (first.new, first.enriched) == (1, 0)
        assert (again.new, again.enriched, again.absorbed) == (1, 0, True), \
            "a replayed absorb reported the run as having added nothing"

    def test_a_replayed_absorb_survives_a_REOPEN(self, tmp_path):
        run = store.Run.create(tmp_path, "acme.com")
        run.add("subdomain", {"host": "a.acme.com", "sources": ["crtsh"]})
        run.write_manifest(profile_summary={}, phases_run=["vertical"])
        campaign.Union.for_campaign(tmp_path, "c-abs2", create=True).absorb(run.dir)
        reopened = campaign.Union.for_campaign(tmp_path, "c-abs2")
        assert reopened.trustworthy
        assert (reopened.absorb(run.dir).new, len(reopened.records)) == (1, 1)

    def test_an_UNREADABLE_absorption_record_is_not_believed(self, tmp_path):
        run = store.Run.create(tmp_path, "acme.com")
        run.write_manifest(profile_summary={}, phases_run=["vertical"])
        union = campaign.Union.for_campaign(tmp_path, "c-abs3", create=True)
        union.absorb(run.dir)
        pointer = json.loads(union.path.read_text())
        pointer["absorbed"][run.run_id] = {"new": -1}
        union.path.write_text(json.dumps(pointer))
        assert campaign.Union.for_campaign(tmp_path, "c-abs3").status == "unusable"


# ── the child's verdict is the one it COMMITTED ───────────────────────────────────────────────────
class TestTheCommittedManifestIsTheVerdict:
    def test_a_verdict_RECOMPUTED_after_the_commit_is_never_the_campaign_s(self, tmp_path):
        """A run is unsealed again for its derived views, so recomputing after it returns can invent a
        verdict the child never published — and one a resume, which has only the manifest, cannot see."""
        def scribble(run):
            run.notes.append("vertical: EXCEPTION a derived view scribbled after the commit")

        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()],
                                            "after_commit": scribble},
                                           {"remainders": [_rem()]}])
        committed = json.loads(
            (tmp_path / "recon" / launcher.calls[0]["run_id"] / "manifest.json").read_text())["summary"]
        assert (committed["verdict"], committed["faults"]) == ("complete", [])
        assert (out.stop, out.success) == ("fixed_point", True), out
        assert [c["verdict"] for c in campaign.Campaign(tmp_path, out.campaign_id).children] == \
            ["complete", "complete"], "the ledger recorded a verdict the child never published"

    def test_the_campaign_and_a_RESUME_read_one_child_the_same_way(self, tmp_path):
        def scribble(run):
            run.notes.append("vertical: EXCEPTION a derived view scribbled after the commit")

        _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()], "after_commit": scribble,
                          "die": "after_manifest"}], "c-14")
        out, _ = _settle(tmp_path, [{}, {"remainders": [_rem()]}], campaign_id="c-14")
        adopted = campaign.Campaign(tmp_path, "c-14").children[0]
        assert (adopted["state"], adopted["verdict"]) == ("manifested", "complete"), adopted
        assert out.stop == "fixed_point", out

    def test_a_child_that_committed_NOTHING_is_refused_not_summarised(self, tmp_path):
        """Its evidence was never published, so there is no verdict to decide on and none may be made up."""
        with pytest.raises(RuntimeError, match="without a committed manifest"):
            _settle(tmp_path, [{"hosts": ["a.acme.com"], "uncommitted": True}])
        ledger = campaign.Campaign(tmp_path, settle.campaigns(tmp_path)[-1].parent.name)
        assert [c["state"] for c in ledger.children] == ["started"] and ledger.stop is None


# ── the terminal taxonomy a caller states an outcome from ─────────────────────────────────────────
class TestTerminalCausesAreClassified:
    def test_every_declared_cause_has_a_CLASS(self):
        assert set(remainder.TERMINAL_DISPOSITIONS) == set(remainder.TERMINAL_CAUSES)
        assert set(remainder.TERMINAL_DISPOSITIONS.values()) <= set(remainder.TERMINAL_CLASSES)

    @pytest.mark.parametrize("cause,expected", [("entitlement", "bounded"), ("unschedulable", "gap"),
                                                ("dependency", "gap"), ("machinery", "fault")])
    def test_a_cause_reads_as_what_it_IS(self, cause, expected):
        assert remainder.terminal_disposition(cause) == expected

    def test_an_UNDECLARED_cause_is_a_fault_never_a_bound(self):
        assert remainder.terminal_disposition("invented") == "fault"

    @pytest.mark.parametrize("causes,expected", [
        ({"entitlement": 2}, "bounded"),
        ({"entitlement": 2, "dependency": 1}, "gap"),
        ({"entitlement": 2, "dependency": 1, "machinery": 1}, "fault"),
        ({"machinery": 0, "entitlement": 3}, "bounded"),          # a zero count names nothing
        ({}, "gap"), (["dependency"], "gap")])
    def test_the_MOST_SERIOUS_cause_classifies_a_mixed_terminal(self, causes, expected):
        assert remainder.terminal_class(causes) == expected

    def test_a_terminal_stop_carries_its_CAUSES_not_just_a_word(self, tmp_path):
        """`terminal` alone cannot be mapped to an outcome: an entitlement bound and a machinery terminal
        are not the same answer."""
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                    {"remainders": [_rem(terminal={"machinery": 2, "entitlement": 1})]}])
        assert out.stop == "terminal" and out.terminal == {"entitlement": 1, "machinery": 2}, out
        assert remainder.terminal_class(out.terminal) == "fault"

    def test_the_LEDGER_carries_the_same_breakdown_the_outcome_did(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                    {"remainders": [_rem(terminal={"entitlement": 3})]}])
        stop = campaign.Campaign(tmp_path, out.campaign_id).stop
        assert stop["cause"] == "terminal" and stop["terminal"] == {"entitlement": 3}, stop
        assert remainder.terminal_class(stop["terminal"]) == remainder.terminal_class(out.terminal)

    def test_a_stop_that_named_no_terminal_work_carries_NO_breakdown(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}])
        assert campaign.Campaign(tmp_path, out.campaign_id).stop == {
            "cause": "fixed_point", "detail": "no retriable work and nothing new", "success": True,
            "clean": True, "recovered": False}
        assert out.terminal == {}

    @pytest.mark.parametrize("terminal", [{}, {"invented": 1}, {"machinery": -1}, {"machinery": True},
                                          "machinery", ["machinery"], None])
    def test_an_UNREADABLE_breakdown_makes_the_ledger_unusable(self, tmp_path, terminal):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}])
        ledger = campaign.Campaign(tmp_path, out.campaign_id)
        doc = json.loads(ledger.path.read_text())
        doc["stop"]["terminal"] = terminal
        ledger.path.write_text(json.dumps(doc))
        assert campaign.Campaign(tmp_path, out.campaign_id).status == "unusable", terminal

    def test_a_terminal_ledger_without_its_breakdown_is_unusable(self, tmp_path):
        """The breakdown is the evidence that distinguishes a bound, gap and fault; absence is not a
        legacy terminal truth the strict v1 ledger can classify."""
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                    {"remainders": [_rem(terminal={"entitlement": 3})]}])
        ledger = campaign.Campaign(tmp_path, out.campaign_id)
        doc = json.loads(ledger.path.read_text())
        del doc["stop"]["terminal"]
        ledger.path.write_text(json.dumps(doc))
        reopened = campaign.Campaign(tmp_path, out.campaign_id)
        assert reopened.status == "unusable" and "terminal breakdown" in reopened.reason


# ── which campaign a caller may resume ─────────────────────────────────────────────────────────────
class TestFindingAResumableCampaign:
    def test_an_interrupted_campaign_is_OFFERED(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-15")
        assert settle.resumable_campaigns(tmp_path) == ["c-15"]
        assert settle.resumable(tmp_path) == "c-15"

    def test_a_FINISHED_campaign_is_not(self, tmp_path):
        _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                           {"remainders": [_rem()]}], campaign_id="c-16")
        assert settle.resumable_campaigns(tmp_path) == [] and settle.resumable(tmp_path) is None

    def test_a_project_that_never_settled_offers_NOTHING(self, tmp_path):
        assert settle.resumable_campaigns(tmp_path) == [] and settle.resumable(tmp_path) is None
        assert not (tmp_path / "recon" / "campaigns" / ".campaign.lock").exists(), \
            "a lookup took the project lease for a project with no campaign"

    def test_an_UNREADABLE_ledger_is_never_offered(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-17")
        campaign.Campaign(tmp_path, "c-17").path.write_text("{not json")
        assert settle.resumable_campaigns(tmp_path) == []

    def test_an_unusable_UNION_is_never_offered(self, tmp_path):
        _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()], "die": "after_manifest"}],
              "c-18")
        union = campaign.Union.for_campaign(tmp_path, "c-18")
        union.path.write_text("{not json")                     # the generations survive it
        assert settle.resumable_campaigns(tmp_path) == [], "a campaign settle would refuse was offered"

    def test_TWO_candidates_are_a_choice_the_lookup_never_makes(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-19")
        _kill(tmp_path, [{"die": "mid_phase"}], "c-20")
        assert settle.resumable_campaigns(tmp_path) == ["c-19", "c-20"]
        assert settle.resumable(tmp_path) is None, "one of two campaigns was picked for the operator"

    def test_a_campaign_a_LIVE_supervisor_holds_is_not_offered(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-21")
        with campaign.Campaign(tmp_path, "c-21").acquire():
            assert settle.resumable(tmp_path) is None, "auto-resume would have raced a live campaign"
            assert settle.resumable_campaigns(tmp_path) == ["c-21"], "it is still the resumable one"

    def test_what_the_lookup_offers_is_what_settle_ACCEPTS(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-22")
        cid = settle.resumable(tmp_path)
        out, _ = _settle(tmp_path, [{}, {"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}], campaign_id=cid)
        assert (out.resumed, out.stop) == (True, "fixed_point"), out
        assert settle.resumable(tmp_path) is None, "a campaign that stopped is still offered"


# ── a campaign belongs to the target it ran against ───────────────────────────────────────────────
class TestACampaignIsOneTargetsCorpus:
    @staticmethod
    def _kill_for(tmp_path, cid, target):
        launcher = _Launcher(tmp_path, [{"die": "mid_phase"}], target=target)
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target=target, launch=launcher, campaign_id=cid)
        return launcher

    def test_a_campaign_names_the_target_its_children_RAN_against(self, tmp_path):
        """The ledger records no target, so it is read from the children's own creation record."""
        self._kill_for(tmp_path, "c-t1", "other.com")
        assert settle.campaign_target(tmp_path, "c-t1") == ("other.com", "")

    def test_a_campaign_whose_child_never_LAUNCHED_names_none(self, tmp_path):
        """Nothing ran under it, so it names nothing — and hides nothing either."""
        _kill(tmp_path, [{"die": "before_run"}], "c-t2")
        assert settle.campaign_target(tmp_path, "c-t2") == (None, "")

    def test_a_creation_record_from_ANOTHER_run_CONFIRMS_nothing(self, tmp_path):
        """`store._run_identity`'s rule: a record that does not name the run it sits in is not that run's,
        and a target nobody can confirm is not a campaign anyone may adopt."""
        launcher = self._kill_for(tmp_path, "c-t3", "other.com")
        meta = tmp_path / "recon" / launcher.calls[0]["run_id"] / "run.json"
        doc = json.loads(meta.read_text())
        meta.write_text(json.dumps({**doc, "run_id": "20260101-000000-ffff"}))
        assert settle.campaign_target(tmp_path, "c-t3") == (None, "child 1 (%s) has no readable creation "
                                                            "record" % launcher.calls[0]["run_id"])

    def test_a_symlinked_creation_record_cannot_answer_for_a_campaign_child(self, tmp_path):
        launcher = self._kill_for(tmp_path, "c-t-symlink", "other.com")
        meta = tmp_path / "recon" / launcher.calls[0]["run_id"] / "run.json"
        external = tmp_path / "external-run.json"
        external.write_bytes(meta.read_bytes())
        meta.unlink()
        meta.symlink_to(external)

        target, why = settle.campaign_target(tmp_path, "c-t-symlink")
        assert target is None and "no readable creation record" in why

    @pytest.mark.parametrize("wreck", ["{not json", '{"run_id": "x", "target": "other.com"}',
                                       '{"target": ""}'])
    def test_an_UNREADABLE_child_refuses_the_campaign_it_cannot_speak_for(self, tmp_path, wreck):
        """Fail CLOSED. Reading "cannot confirm" as "names no target" let a campaign started for one
        target be resumed under another — the union is one target's corpus."""
        launcher = self._kill_for(tmp_path, "c-t4", "other.com")
        meta = tmp_path / "recon" / launcher.calls[0]["run_id"] / "run.json"
        meta.write_text(wreck if "run_id" not in wreck else
                        json.dumps({**json.loads(meta.read_text()), **json.loads(wreck)}))
        target, why = settle.campaign_target(tmp_path, "c-t4")
        assert target is None and why, "an unreadable child answered for the campaign"
        launched: list = []
        with pytest.raises(settle.WrongTarget, match="cannot be confirmed"):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-t4",
                          launch=lambda index, prepare: launched.append(index))
        assert launched == []
        assert settle.resumable_campaigns(tmp_path) == [], "settle refuses it, so nothing may offer it"

    def test_a_LATER_child_cannot_speak_over_an_unreadable_earlier_one(self, tmp_path):
        """One child the campaign cannot account for is enough: its evidence is in the union too."""
        launcher = _Launcher(tmp_path, [{"hosts": ["a.other.com"], "remainders": [_rem()],
                                         "die": "after_manifest"}], target="other.com")
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="other.com", launch=launcher, campaign_id="c-t5")
        (tmp_path / "recon" / launcher.calls[0]["run_id"] / "run.json").write_text("{not json")
        second = _Launcher(tmp_path, [{}, {"die": "mid_phase"}], target="other.com")
        with pytest.raises(settle.WrongTarget, match="child 1"):
            settle.settle(project_dir=tmp_path, target="other.com", launch=second, campaign_id="c-t5")
        assert second.calls == [], "child 2 ran for a campaign nobody could account for"

    def test_children_that_DISAGREE_confirm_nothing(self, tmp_path):
        """Two targets under one campaign is not a target; adopting either would pick one for the operator."""
        self._kill_for(tmp_path, "c-t6", "other.com")
        ledger = campaign.Campaign(tmp_path, "c-t6")
        ledger.abandoned(ledger.children[0], "the first supervisor was interrupted")
        strayed = store.Run.create(tmp_path, "acme.com")
        second = ledger.reserve()
        ledger.started(second, strayed.run_id)
        target, why = settle.campaign_target(tmp_path, "c-t6")
        assert target is None and "'acme.com', 'other.com'" in why, why
        for asked in ("acme.com", "other.com"):
            with pytest.raises(settle.WrongTarget, match="cannot be confirmed"):
                settle.settle(project_dir=tmp_path, target=asked, campaign_id="c-t6",
                              launch=lambda index, prepare: None)

    def test_resuming_under_ANOTHER_target_is_refused(self, tmp_path):
        """The union is one target's corpus: a child seeded from it would file one target's evidence
        under another's."""
        self._kill_for(tmp_path, "c-t5", "other.com")
        launched: list = []
        with pytest.raises(settle.WrongTarget, match="ran against 'other.com'"):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-t5",
                          launch=lambda index, prepare: launched.append(index))
        assert launched == [], "a child ran for the wrong target"
        assert len(campaign.Campaign(tmp_path, "c-t5").children) == 1

    def test_the_refusal_happens_BEFORE_the_lease_is_taken(self, tmp_path):
        """Refusing after taking it would leave a campaign that cannot be resumed while this one sulks."""
        self._kill_for(tmp_path, "c-t6", "other.com")
        with pytest.raises(settle.WrongTarget):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-t6",
                          launch=lambda index, prepare: None)
        with campaign.Campaign(tmp_path, "c-t6").acquire():
            pass                                  # free: the refusal never held it

    def test_the_RIGHT_target_resumes(self, tmp_path):
        self._kill_for(tmp_path, "c-t7", "other.com")
        launcher = _Launcher(tmp_path, [{}, {"hosts": ["a.other.com"], "remainders": [_rem()]},
                                        {"remainders": [_rem()]}], target="other.com")
        out = settle.settle(project_dir=tmp_path, target="other.com", launch=launcher,
                            campaign_id="c-t7")
        assert (out.resumed, out.stop) == (True, "fixed_point"), out

    def test_a_lookup_for_one_target_never_offers_ANOTHER_S(self, tmp_path):
        self._kill_for(tmp_path, "c-t8", "other.com")
        assert settle.resumable_campaigns(tmp_path, "other.com") == ["c-t8"]
        assert settle.resumable(tmp_path, "other.com") == "c-t8"
        assert settle.resumable_campaigns(tmp_path, "acme.com") == []
        assert settle.resumable(tmp_path, "acme.com") is None
        assert settle.resumable_campaigns(tmp_path) == ["c-t8"], "no target asked, no target filtered"

    def test_a_campaign_that_named_no_target_is_offered_to_ANY(self, tmp_path):
        """Nothing has run under it, so no evidence can be misfiled — and `settle()` accepts it too."""
        _kill(tmp_path, [{"die": "before_run"}], "c-t9")
        assert settle.resumable_campaigns(tmp_path, "acme.com") == ["c-t9"]
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}], campaign_id="c-t9")
        assert out.stop == "fixed_point" and settle.campaign_target(tmp_path, "c-t9") == ("acme.com", "")

    @pytest.mark.parametrize("refusal", ["already_run", "wrong_target"])
    def test_every_refusal_is_one_EXCEPTION_a_caller_can_catch(self, tmp_path, refusal):
        """A caller that means "this campaign is not mine to continue" catches one type, not a list that
        grows behind its back."""
        if refusal == "already_run":
            _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                               {"remainders": [_rem()]}], campaign_id="c-t10")
            call = lambda: _settle(tmp_path, [{}], campaign_id="c-t10")            # noqa: E731
        else:
            self._kill_for(tmp_path, "c-t10", "other.com")
            call = lambda: _settle(tmp_path, [{}], campaign_id="c-t10")            # noqa: E731
        with pytest.raises(settle.CampaignRefused):
            call()
        assert issubclass(settle.AlreadyRun, settle.CampaignRefused)
        assert issubclass(settle.WrongTarget, settle.CampaignRefused)


# ── a campaign id is a directory name, never a route out of the campaigns directory ───────────────
class TestACampaignIdCannotLeaveItsDirectory:
    @pytest.mark.parametrize("bad", ["../../escape", "../sibling", "a/b", "/etc/passwd", "..", ".",
                                     ".hidden", "", "  ", "x" * 65, None, 7, "c\x00null", "c\nnl"])
    def test_an_id_that_is_not_ONE_segment_is_refused(self, tmp_path, bad):
        """`--settle-resume` is operator input, and everything a campaign owns is derived from its id."""
        with pytest.raises(campaign.InvalidCampaignId):
            campaign.Campaign(tmp_path, bad)
        with pytest.raises(campaign.InvalidCampaignId):
            campaign.Union.for_campaign(tmp_path, bad)

    def test_nothing_is_TOUCHED_outside_the_campaigns_directory(self, tmp_path):
        outside = tmp_path / "escape"
        with pytest.raises(campaign.InvalidCampaignId):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="../escape",
                          launch=lambda index, prepare: None)
        assert not outside.exists(), "a path outside recon/campaigns was created"
        assert not (tmp_path / "recon").exists()

    @pytest.mark.parametrize("bad", ["", 0, False])
    def test_falsey_explicit_ids_are_invalid_not_requests_to_mint(self, tmp_path, bad):
        with pytest.raises(campaign.InvalidCampaignId):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id=bad,
                          launch=lambda index, prepare: pytest.fail("invalid campaign launched"))
        assert not (tmp_path / "recon").exists()

    def test_a_bad_minted_id_is_validated_before_the_campaign_root_is_created(self, tmp_path, monkeypatch):
        monkeypatch.setattr(settle, "new_campaign_id", lambda: "../escape")
        with pytest.raises(campaign.InvalidCampaignId):
            settle._claim(tmp_path)
        assert not (tmp_path / "recon").exists()

    @pytest.mark.parametrize("bad", [None, 0, "", "   "])
    def test_invalid_target_is_refused_before_a_campaign_is_claimed(self, tmp_path, bad):
        with pytest.raises(ContractError):
            settle.settle(project_dir=tmp_path, target=bad,
                          launch=lambda index, prepare: pytest.fail("invalid target launched"))
        assert not (tmp_path / "recon").exists()

    @pytest.mark.parametrize("good", ["c20260811-085256-af1a507d", "c1", "c-fixed", "a.b_c-1", "Z9"])
    def test_a_MINTED_or_deliberately_named_id_still_works(self, tmp_path, good):
        assert campaign.Campaign(tmp_path, good).campaign_id == good
        assert campaign.valid_campaign_id(settle.new_campaign_id())

    def test_a_directory_nobody_could_have_MINTED_is_never_offered(self, tmp_path):
        """`resumable_campaigns` reads directory names off the disk: one that is not an id is not ours."""
        _kill(tmp_path, [{"die": "mid_phase"}], "c-ok")
        stray = tmp_path / "recon" / "campaigns" / ".sneaky"
        stray.mkdir()
        (stray / "ledger.json").write_text(json.dumps(
            {"campaign_id": ".sneaky", "children": [], "stop": None, "recoveries": []}))
        assert settle.resumable_campaigns(tmp_path) == ["c-ok"]


# ── the child cap counts every child the ledger recorded ──────────────────────────────────────────
class TestTheChildCapIsCheckedBeforeLaunch:
    def test_an_ABANDONED_child_still_counts_against_max_runs(self, tmp_path):
        """The cap was only asked after a child ran, so a campaign that abandoned one ran an extra."""
        _kill(tmp_path, [{"die": "mid_phase"}], "c-cap1")
        launcher = _Launcher(tmp_path, [{}, {"hosts": ["a.acme.com"], "remainders": [_rem()]}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", launch=launcher,
                            campaign_id="c-cap1", max_runs=1)
        assert (out.stop, out.detail) == ("max_runs", "1 child run(s)"), out
        assert launcher.calls == [], "the cap was already spent"
        assert [c["index"] for c in campaign.Campaign(tmp_path, "c-cap1").children] == [1]

    def test_a_RESERVED_child_left_by_a_kill_is_relaunched_within_the_cap(self, tmp_path):
        _kill(tmp_path, [{"die": "before_run"}], "c-cap2")
        launcher = _Launcher(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", launch=launcher,
                            campaign_id="c-cap2", max_runs=1)
        assert [c["index"] for c in launcher.calls] == [1], "the child nobody launched was not relaunched"
        assert out.stop == "max_runs" and len(campaign.Campaign(tmp_path, "c-cap2").children) == 1

    def test_the_cap_still_reads_the_SAME_however_it_was_reached(self, tmp_path):
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=9)]},
                                           {"hosts": ["b.acme.com"], "remainders": [_rem(now=9)]}],
                                max_runs=2)
        assert (out.stop, out.detail) == ("max_runs", "2 child run(s)"), out
        assert len(launcher.calls) == 2


# ── coverage the last child never got is not a clean fixed point ──────────────────────────────────
class TestAFixedPointOverGapsIsNotClean:
    @staticmethod
    def _gapped(**over):
        return {"verdict": "complete_with_gaps", "faults": [], "remainders": [],
                "gaps": [{"phase": "probe", "tool": "probe.httpx", "kind": "timeout",
                          "status": "coverage:timeout", "why": "timed out", "omitted": 40}], **over}

    @staticmethod
    def _absorbed():
        out = campaign.AbsorbResult()
        out.absorbed = True
        return out

    def test_an_unresolved_child_gap_PREVENTS_a_clean_fixed_point(self):
        d = campaign.decide(self._gapped(), self._absorbed())
        assert (d.stop, d.success) == ("fixed_point_with_gaps", False), d
        assert "probe.httpx" in d.detail

    def test_a_verdict_that_claims_less_than_covered_with_NO_gap_named_is_gapped_too(self):
        d = campaign.decide(self._gapped(gaps=[]), self._absorbed())
        assert d.stop == "fixed_point_with_gaps" and "no gap named" in d.detail, d

    @pytest.mark.parametrize("verdict", ["complete", "complete_with_limits"])
    def test_covered_and_intentionally_BOUNDED_children_still_converge_cleanly(self, verdict):
        d = campaign.decide({"verdict": verdict, "faults": [], "remainders": [], "gaps": []},
                            self._absorbed())
        assert (d.stop, d.success) == ("fixed_point", True), d

    def test_a_campaign_over_a_gapped_child_says_so_and_is_NOT_clean(self, tmp_path):
        """Driven through a real run: the child's own manifest carries the timeout gap and the verdict."""
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()], "gap": True},
                                           {"remainders": [_rem()], "gap": True}])
        committed = json.loads(
            (tmp_path / "recon" / launcher.calls[-1]["run_id"] / "manifest.json").read_text())["summary"]
        assert committed["verdict"] == "complete_with_gaps" and committed["gaps"]
        assert (out.stop, out.success, out.clean) == ("fixed_point_with_gaps", False, False), out
        assert campaign.Campaign(tmp_path, out.campaign_id).stop["cause"] == "fixed_point_with_gaps"

    def test_a_gapped_child_does_not_stop_a_campaign_that_can_still_ADVANCE(self, tmp_path):
        """The gap decides a verdict only at the fixed point: owed work still gets its children, and a
        child that closes the gap converges cleanly."""
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=2)],
                                            "gap": True},
                                           {"hosts": ["b.acme.com"], "remainders": [_rem(now=1)],
                                            "gap": True},
                                           {"remainders": [_rem()], "covered": ["probe.httpx"]},
                                           {"remainders": [_rem()]}])
        assert (out.stop, out.clean) == ("fixed_point", True), out
        assert len(launcher.calls) == 4


def _sticky(*ticks):
    """A clock that reads each tick once and then holds the last — a campaign's reading count is not a
    contract, so a test that pins one breaks on every honest change."""
    seq = list(ticks)
    return lambda: seq.pop(0) if len(seq) > 1 else seq[0]


# ── an interrupted campaign is never passed over in silence ───────────────────────────────────────
class TestWhatIsSkippedIsNamed:
    def test_an_unconfirmable_campaign_is_SKIPPED_with_its_reason(self, tmp_path):
        """It used to vanish from the lookup, so a caller minted a new campaign over it and paid for
        child one's acquisition again."""
        launcher = _Launcher(tmp_path, [{"die": "mid_phase"}], target="other.com")
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="other.com", launch=launcher,
                          campaign_id="c-s1")
        (tmp_path / "recon" / launcher.calls[0]["run_id"] / "run.json").write_text("{not json")
        assert settle.resumable_campaigns(tmp_path) == []
        [(cid, why)] = settle.skipped_resumable(tmp_path)
        assert cid == "c-s1" and "no readable creation record" in why, why

    def test_an_unusable_UNION_is_skipped_with_its_reason(self, tmp_path):
        _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)],
                          "die": "after_manifest"}], "c-s2")
        settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-s2", max_runs=1,
                      launch=_Launcher(tmp_path, [{}]))
        ledger = campaign.Campaign(tmp_path, "c-s2")
        doc = json.loads(ledger.path.read_text())
        doc["stop"] = None                                   # as a kill between children would leave it
        ledger.path.write_text(json.dumps(doc))
        for artifact in (tmp_path / "recon" / "campaigns" / "c-s2").glob("union*"):
            artifact.unlink()
        assert settle.resumable_campaigns(tmp_path) == []
        [(cid, why)] = settle.skipped_resumable(tmp_path)
        assert cid == "c-s2" and "union is unusable" in why, why

    def test_an_unreadable_LEDGER_is_skipped_with_its_reason(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-s3")
        campaign.Campaign(tmp_path, "c-s3").path.write_text("{not json")
        assert [cid for cid, _why in settle.skipped_resumable(tmp_path)] == ["c-s3"]

    def test_ANOTHER_target_s_campaign_is_skipped_only_when_a_target_is_asked(self, tmp_path):
        launcher = _Launcher(tmp_path, [{"die": "mid_phase"}], target="other.com")
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="other.com", launch=launcher, campaign_id="c-s4")
        assert settle.skipped_resumable(tmp_path, "acme.com") == [("c-s4", "it ran against 'other.com'")]
        assert settle.skipped_resumable(tmp_path, "other.com") == []
        assert settle.resumable_campaigns(tmp_path, "other.com") == ["c-s4"]

    def test_a_FINISHED_campaign_is_neither_offered_nor_skipped(self, tmp_path):
        """It is not interrupted, so there is nothing to pass over and nothing to say about it."""
        _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                           {"remainders": [_rem()]}], campaign_id="c-s5")
        assert settle.resumable_campaigns(tmp_path) == [] and settle.skipped_resumable(tmp_path) == []

    def test_offered_and_skipped_never_name_the_SAME_campaign(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-s6")
        bad = _Launcher(tmp_path, [{"die": "mid_phase"}], target="other.com")
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="other.com", launch=bad, campaign_id="c-s7")
        (tmp_path / "recon" / bad.calls[0]["run_id"] / "run.json").write_text("{not json")
        offered = settle.resumable_campaigns(tmp_path)
        skipped = [cid for cid, _why in settle.skipped_resumable(tmp_path)]
        assert offered == ["c-s6"] and skipped == ["c-s7"]
        assert not set(offered) & set(skipped)


# ── losing the union is evidence loss, not a fresh start ──────────────────────────────────────────
class TestAnAbsentUnionIsReadAgainstTheLedger:
    @staticmethod
    def _campaign_with_a_manifested_child(tmp_path, cid):
        _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)],
                          "die": "after_manifest"}], cid)
        settle.settle(project_dir=tmp_path, target="acme.com", campaign_id=cid, max_runs=1,
                      launch=_Launcher(tmp_path, [{}]))
        ledger = campaign.Campaign(tmp_path, cid)
        assert [c["state"] for c in ledger.children] == ["manifested"]
        return ledger

    def test_a_union_lost_after_a_manifested_child_is_DAMAGE(self, tmp_path):
        """Absence read as "new" republished an empty corpus as authoritative — the campaign then had no
        idea what it had already found, and every later child re-discovered it as new."""
        self._campaign_with_a_manifested_child(tmp_path, "c-u1")
        for artifact in (tmp_path / "recon" / "campaigns" / "c-u1").glob("union*"):
            artifact.unlink()
        union = campaign.Union.for_campaign(tmp_path, "c-u1", create=True)
        assert (union.status, union.trustworthy) == ("unusable", False)
        assert "1 manifested child run(s)" in union.reason and not union.records

    def test_a_campaign_whose_union_was_lost_REFUSES_to_continue(self, tmp_path):
        ledger = self._campaign_with_a_manifested_child(tmp_path, "c-u2")
        doc = json.loads(ledger.path.read_text())
        doc["stop"] = None
        ledger.path.write_text(json.dumps(doc))
        for artifact in (tmp_path / "recon" / "campaigns" / "c-u2").glob("union*"):
            artifact.unlink()
        launched: list = []
        with pytest.raises(campaign.UnionUnusable, match="manifested child run"):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-u2",
                          launch=lambda index, prepare: launched.append(index))
        assert launched == []

    def test_a_campaign_that_manifested_NOTHING_may_still_start_empty(self, tmp_path):
        """A kill before any child finished lost no corpus: there was none to lose."""
        _kill(tmp_path, [{"die": "mid_phase"}], "c-u3")
        assert not list((tmp_path / "recon" / "campaigns" / "c-u3").glob("union*"))
        union = campaign.Union.for_campaign(tmp_path, "c-u3", create=True)
        assert (union.status, union.trustworthy) == ("new", True)
        out, _ = _settle(tmp_path, [{}, {"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}], campaign_id="c-u3")
        assert out.stop == "fixed_point", out

    def test_a_surviving_GENERATION_beside_a_lost_pointer_is_still_refused(self, tmp_path):
        self._campaign_with_a_manifested_child(tmp_path, "c-u4")
        (tmp_path / "recon" / "campaigns" / "c-u4" / "union.json").unlink()
        union = campaign.Union.for_campaign(tmp_path, "c-u4", create=True)
        assert (union.status, union.trustworthy) == ("unusable", False)


# ── the budget bounds the campaign, not one invocation of it ──────────────────────────────────────
class TestTheBudgetIsCumulativeAcrossResumes:
    @staticmethod
    def _spend(tmp_path, cid, seconds, budget_s=10):
        """One child that costs the campaign `seconds`, recorded and left resumable."""
        launcher = _Launcher(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=5)]}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id=cid, max_runs=1,
                            budget_s=budget_s, launch=launcher, _now=_sticky(0.0, 0.0, seconds))
        ledger = campaign.Campaign(tmp_path, cid)
        doc = json.loads(ledger.path.read_text())
        doc["stop"] = None                                   # as a kill between children would leave it
        doc["children"][-1]["decision"] = {"cause": None, "detail": "", "success": False}
        ledger.path.write_text(json.dumps(doc))
        return out, launcher

    def test_what_a_child_COST_the_campaign_is_recorded(self, tmp_path):
        out, _ = self._spend(tmp_path, "c-b1", 12.0)
        [child] = campaign.Campaign(tmp_path, "c-b1").children
        assert child["elapsed_s"] == 12.0 and out.spent_s == 12.0, child

    def test_a_resume_spends_what_is_LEFT_of_the_budget(self, tmp_path):
        """A fresh timer per invocation made `--settle-budget` a per-restart allowance: a campaign that
        had already spent 12s of 10s launched another child after a kill."""
        self._spend(tmp_path, "c-b2", 12.0)
        launcher = _Launcher(tmp_path, [{}, {}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-b2", budget_s=10,
                            launch=launcher, _now=_sticky(0.0, 0.0))
        assert (out.stop, out.spent_s) == ("budget", 12.0), out
        assert "12s of a 10s budget" in out.detail
        assert launcher.calls == [], "the campaign spent a budget it had already exhausted"
        assert len(campaign.Campaign(tmp_path, "c-b2").children) == 1

    def test_a_resume_INSIDE_the_budget_still_runs(self, tmp_path):
        self._spend(tmp_path, "c-b3", 2.0)
        launcher = _Launcher(tmp_path, [{}, {"remainders": [_rem()]}, {"remainders": [_rem()]}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-b3", budget_s=10,
                            launch=launcher, _now=_sticky(0.0, 0.0))
        assert out.stop == "fixed_point" and [c["index"] for c in launcher.calls] == [2, 3], out

    def test_a_ledger_written_before_elapsed_was_recorded_still_reads(self, tmp_path):
        out, _ = self._spend(tmp_path, "c-b4", 2.0)
        ledger = campaign.Campaign(tmp_path, "c-b4")
        doc = json.loads(ledger.path.read_text())
        del doc["children"][0]["elapsed_s"]
        ledger.path.write_text(json.dumps(doc))
        assert campaign.Campaign(tmp_path, "c-b4").status == "valid"

    @pytest.mark.parametrize("bad", [-1, "12", True, None])
    def test_an_unreadable_elapsed_time_makes_the_ledger_unusable(self, tmp_path, bad):
        self._spend(tmp_path, "c-b5", 2.0)
        ledger = campaign.Campaign(tmp_path, "c-b5")
        doc = json.loads(ledger.path.read_text())
        doc["children"][0]["elapsed_s"] = bad
        ledger.path.write_text(json.dumps(doc))
        assert campaign.Campaign(tmp_path, "c-b5").status == "unusable", bad


# ── a child's run id is joined to reach its evidence ──────────────────────────────────────────────
class TestAChildRunIdCannotLeaveTheProject:
    @staticmethod
    def _ledger_naming(tmp_path, run_id):
        cdir = tmp_path / "recon" / "campaigns" / "c-evil"
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "ledger.json").write_text(json.dumps(
            {"campaign_id": "c-evil", "recoveries": [], "stop": None,
             "children": [{"index": 1, "state": "started", "run_id": run_id}]}))
        return campaign.Campaign(tmp_path, "c-evil")

    def test_a_ledger_naming_a_run_OUTSIDE_the_project_is_unusable(self, tmp_path):
        """It was read as valid, and the run.json it pointed at — a file no project owns — then supplied
        the campaign's target."""
        assert self._ledger_naming(tmp_path, "../../outside-run").status == "unusable"

    @pytest.mark.parametrize("bad", ["../sibling", "a/b", "/etc", "..", ".hidden", "x" * 65, "r\x00"])
    def test_no_traversal_shape_survives_the_LOADER(self, tmp_path, bad):
        assert self._ledger_naming(tmp_path, bad).status == "unusable", bad

    def test_nothing_outside_the_project_is_READ_for_such_a_ledger(self, tmp_path):
        outside = tmp_path.parent / "outside-run-012"
        outside.mkdir(exist_ok=True)
        (outside / "run.json").write_text(json.dumps(
            {"run_id": "../../outside-run-012", "target": "attacker.example",
             "started": "2026-01-01T00:00:00+00:00"}))
        self._ledger_naming(tmp_path, "../../outside-run-012")
        target, why = settle.campaign_target(tmp_path, "c-evil")
        assert target is None and "unusable" in why, (target, why)
        with pytest.raises(campaign.UnionUnusable):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-evil",
                          launch=lambda index, prepare: None)

    def test_a_child_cannot_be_STARTED_under_such_an_id(self, tmp_path):
        ledger = campaign.Campaign(tmp_path, "c-ok")
        child = ledger.reserve()
        with pytest.raises(campaign.InvalidRunId):
            ledger.started(child, "../../outside-run")
        assert campaign.Campaign(tmp_path, "c-ok").children[0]["state"] == "reserved"

    def test_a_MINTED_run_id_is_accepted(self, tmp_path):
        run = store.Run.create(tmp_path, "acme.com")
        assert campaign.valid_segment(run.run_id)
        ledger = campaign.Campaign(tmp_path, "c-ok2")
        ledger.started(ledger.reserve(), run.run_id)
        assert campaign.Campaign(tmp_path, "c-ok2").status == "valid"


# ── a child the campaign never saw finish still cost it ───────────────────────────────────────────
class TestAnInterruptedChildIsChargedToTheBudget:
    @staticmethod
    def _interrupted(tmp_path, cid, *, seconds, budget_s=10, forget_started_at=False, started=None):
        """A campaign whose child one ran for `seconds` and was killed before its manifest."""
        launcher = _Launcher(tmp_path, [{"die": "mid_phase"}])
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id=cid, budget_s=budget_s,
                          launch=launcher, _now=_sticky(0.0))
        began = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        ledger = campaign.Campaign(tmp_path, cid)
        doc = json.loads(ledger.path.read_text())
        child = doc["children"][0]
        if forget_started_at:
            del child["started_at"]         # a ledger written before a campaign timed its children
        else:
            child["started_at"] = began.isoformat()
        ledger.path.write_text(json.dumps(doc))
        run_json = tmp_path / "recon" / child["run_id"] / "run.json"
        meta = json.loads(run_json.read_text())
        meta["started"] = began.isoformat() if started is None else started
        run_json.write_text(json.dumps(meta))
        return campaign.Campaign(tmp_path, cid)

    def test_the_ledger_records_WHEN_a_child_started(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-i0")
        [child] = campaign.Campaign(tmp_path, "c-i0").children
        assert child["state"] == "started" and campaign._aware_stamp(child["started_at"]), child

    def test_time_spent_in_an_INTERRUPTED_child_is_charged(self, tmp_path):
        """Restoring only manifested children let a killed child's time vanish: 12s of a 10s budget was
        spent, and the resume launched again as if the campaign had spent nothing."""
        self._interrupted(tmp_path, "c-i1", seconds=12)
        launcher = _Launcher(tmp_path, [{}, {"hosts": ["a.acme.com"], "remainders": [_rem()]}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-i1", budget_s=10,
                            launch=launcher, _now=_sticky(0.0))
        assert (out.stop, out.spent_s) == ("budget", 12.0), out
        assert launcher.calls == [], "a new child ran on a budget the campaign had already spent"
        assert [c["elapsed_s"] for c in campaign.Campaign(tmp_path, "c-i1").children] == [12.0]

    def test_an_interrupted_child_INSIDE_the_budget_still_leaves_room(self, tmp_path):
        self._interrupted(tmp_path, "c-i2", seconds=2)
        launcher = _Launcher(tmp_path, [{}, {"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                        {"remainders": [_rem()]}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-i2", budget_s=10,
                            launch=launcher, _now=_sticky(0.0))
        assert out.stop == "fixed_point" and [c["index"] for c in launcher.calls] == [2, 3], out
        assert campaign.Campaign(tmp_path, "c-i2").children[0]["elapsed_s"] == 2.0

    def test_a_ledger_that_never_TIMED_its_children_falls_back_to_the_run(self, tmp_path):
        """The run's own creation record says when it began, so an older ledger is still chargeable."""
        self._interrupted(tmp_path, "c-i3", seconds=12, forget_started_at=True)
        launcher = _Launcher(tmp_path, [{}, {}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-i3", budget_s=10,
                            launch=launcher, _now=_sticky(0.0))
        assert (out.stop, launcher.calls) == ("budget", []), out

    def test_a_spend_nobody_can_measure_FAILS_CLOSED(self, tmp_path):
        """Neither end can be established, so the campaign cannot show it is inside its budget — and a
        bound it cannot prove is not a bound it may keep spending against."""
        self._interrupted(tmp_path, "c-i4", seconds=12, forget_started_at=True,
                          started="2026-08-11 14:00:00")          # naive: it names no instant
        launcher = _Launcher(tmp_path, [{}, {}])
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-i4", budget_s=10,
                            launch=launcher, _now=_sticky(0.0))
        assert (out.stop, out.success) == ("unknown", False), out
        assert "no measurable spend" in out.detail and launcher.calls == []
        assert "elapsed_s" not in campaign.Campaign(tmp_path, "c-i4").children[0]

    def test_an_unmeasurable_child_stops_NOTHING_when_no_budget_was_asked_for(self, tmp_path):
        """There is no bound to prove, so unmeasured time bounds nothing."""
        self._interrupted(tmp_path, "c-i5", seconds=12, budget_s=0, forget_started_at=True,
                          started="2026-08-11 14:00:00")
        out, launcher = _settle(tmp_path, [{}, {"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                           {"remainders": [_rem()]}], campaign_id="c-i5")
        assert out.stop == "fixed_point" and [c["index"] for c in launcher.calls] == [2, 3], out

    def test_an_ADOPTED_child_is_charged_what_it_really_took(self, tmp_path):
        """It wrote its manifest before the kill, so its own record says when it finished."""
        launcher = _Launcher(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()],
                                         "die": "after_manifest"}])
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-i6", budget_s=10,
                          launch=launcher, _now=_sticky(0.0))
        ledger = campaign.Campaign(tmp_path, "c-i6")
        doc = json.loads(ledger.path.read_text())
        doc["children"][0]["started_at"] = (datetime.now(timezone.utc)
                                            - timedelta(seconds=30)).isoformat()
        ledger.path.write_text(json.dumps(doc))
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-i6", budget_s=10,
                            launch=_Launcher(tmp_path, [{}, {}]), _now=_sticky(0.0))
        [child] = campaign.Campaign(tmp_path, "c-i6").children
        assert child["state"] == "manifested" and child["elapsed_s"] >= 29.0, child
        assert out.stop == "budget", out

    @pytest.mark.parametrize("bad", ["not a stamp", "2026-08-11 14:00:00", 7, None])
    def test_an_unreadable_START_time_makes_the_ledger_unusable(self, tmp_path, bad):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-i7")
        ledger = campaign.Campaign(tmp_path, "c-i7")
        doc = json.loads(ledger.path.read_text())
        doc["children"][0]["started_at"] = bad
        ledger.path.write_text(json.dumps(doc))
        assert campaign.Campaign(tmp_path, "c-i7").status == "unusable", bad

    def test_an_abandoned_child_carries_its_COST_across_a_second_resume(self, tmp_path):
        """Charged once, recorded, and never re-measured from a run directory that may be gone."""
        self._interrupted(tmp_path, "c-i8", seconds=4)
        settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-i8", budget_s=10,
                      max_runs=2, launch=_Launcher(tmp_path, [{}, {"remainders": [_rem(now=1)]}]),
                      _now=_sticky(0.0))
        ledger = campaign.Campaign(tmp_path, "c-i8")
        doc = json.loads(ledger.path.read_text())
        doc["stop"] = None
        doc["children"][-1]["decision"] = {"cause": None, "detail": "", "success": False}
        ledger.path.write_text(json.dumps(doc))
        out = settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-i8", budget_s=10,
                            max_runs=9, launch=_Launcher(tmp_path, [{}, {}, {"remainders": [_rem()]},
                                                                    {"remainders": [_rem()]}]),
                            _now=_sticky(0.0))
        assert out.spent_s == 4.0, "the abandoned child's cost was recounted or forgotten"


# ── which skipped campaigns might still be ours ───────────────────────────────────────────────────
class TestUnconfirmableIsNotTheSameAsSomeoneElses:
    def test_a_campaign_confirmed_for_another_TARGET_is_not_unconfirmable(self, tmp_path):
        launcher = _Launcher(tmp_path, [{"die": "mid_phase"}], target="other.com")
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="other.com", launch=launcher, campaign_id="c-n1")
        assert settle.skipped_resumable(tmp_path, "acme.com") == [("c-n1", "it ran against 'other.com'")]
        assert settle.unconfirmable_resumable(tmp_path, "acme.com") == [], \
            "a campaign we know belongs to another target is not one we failed to identify"

    @pytest.mark.parametrize("damage", ["ledger", "union", "target"])
    def test_DAMAGE_of_any_kind_is_unconfirmable(self, tmp_path, damage):
        if damage == "union":
            _kill(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)],
                              "die": "after_manifest"}], "c-n2")
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c-n2", max_runs=1,
                          launch=_Launcher(tmp_path, [{}]))
            ledger = campaign.Campaign(tmp_path, "c-n2")
            doc = json.loads(ledger.path.read_text())
            doc["stop"] = None
            ledger.path.write_text(json.dumps(doc))
            for artifact in (tmp_path / "recon" / "campaigns" / "c-n2").glob("union*"):
                artifact.unlink()
        else:
            launcher = _kill(tmp_path, [{"die": "mid_phase"}], "c-n2")
            if damage == "ledger":
                campaign.Campaign(tmp_path, "c-n2").path.write_text("{not json")
            else:
                (tmp_path / "recon" / launcher.calls[0]["run_id"] / "run.json").write_text("{not json")
        assert settle.unconfirmable_resumable(tmp_path) == ["c-n2"], damage
        assert [cid for cid, _why in settle.skipped_resumable(tmp_path)] == ["c-n2"]
        assert settle.resumable_campaigns(tmp_path) == []

    def test_a_resumable_campaign_is_neither_skipped_nor_UNCONFIRMABLE(self, tmp_path):
        _kill(tmp_path, [{"die": "mid_phase"}], "c-n3")
        assert settle.resumable_campaigns(tmp_path, "acme.com") == ["c-n3"]
        assert settle.skipped_resumable(tmp_path, "acme.com") == []
        assert settle.unconfirmable_resumable(tmp_path, "acme.com") == []

    def test_unconfirmable_is_a_SUBSET_of_skipped(self, tmp_path):
        other = _Launcher(tmp_path, [{"die": "mid_phase"}], target="other.com")
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="other.com", launch=other, campaign_id="c-n4")
        broken = _kill(tmp_path, [{"die": "mid_phase"}], "c-n5")
        (tmp_path / "recon" / broken.calls[0]["run_id"] / "run.json").write_text("{not json")
        skipped = {cid for cid, _why in settle.skipped_resumable(tmp_path, "acme.com")}
        unconfirmable = set(settle.unconfirmable_resumable(tmp_path, "acme.com"))
        assert skipped == {"c-n4", "c-n5"} and unconfirmable == {"c-n5"}
        assert unconfirmable <= skipped
