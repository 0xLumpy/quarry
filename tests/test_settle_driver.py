"""`--settle` — the CONTINUATION loop over ordinary runs (settle step 7).

The supervisor's rules and ledger are pinned in `test_campaign_supervisor.py`; what is pinned HERE is the
loop that drives them: that every child is an ordinary run with its own evidence, that what one child
learned reaches the next, that acquisition is closed from child 2 on, that both bounds are named outcomes,
and that a campaign never edits a child.

The children are FAKE runs — real phases would make these tests a scan, not a pin. What is real is
everything the supervisor actually reads: a run directory, its entity logs, its manifest and the events
that carry remainders.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon import budget, campaign, remainder, settle, store


def _rem(lane="enrich.a1d_brute", *, now=0, cooldown=0):
    return remainder.Remainder(lane=lane, unit=f"{lane}:targets", measure="targets",
                               model="project_progress", now=now, cooldown=cooldown)


class _Launcher:
    """Stands in for `_run_phases`: hands each child a run directory, lets the campaign seed it, then
    returns the finished run. Records what the campaign did around each child."""

    def __init__(self, project, plan):
        self.project, self.plan = project, list(plan)
        self.calls: list = []
        self.acquisition: list = []

    def __call__(self, index, prepare):
        from quarry_recon import contract
        run = store.Run.create(self.project, "acme.com")
        prepare(run)                                   # exactly where the CLI calls it: before any phase
        self.acquisition.append(contract.acquisition_open("probe.favicon", announce=False))
        # a plan that runs out is a FAILED expectation, never a repeat: how many children a campaign
        # creates is exactly what these tests are pinning
        assert index <= len(self.plan), f"the campaign asked for child {index}; the plan has {len(self.plan)}"
        spec = self.plan[index - 1]
        from quarry_recon import events
        events.configure(run.dir)
        try:
            for host in spec.get("hosts", ()):
                run.add("subdomain", {"host": host, "sources": ["crtsh"]})
            for rem in spec.get("remainders", ()):
                remainder.emit(rem)
            for why in spec.get("unknown", ()):
                remainder.unknown(why)
            for note in spec.get("faults", ()):
                run.notes.append(f"vertical: EXCEPTION {note}")
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        self.calls.append({"index": index, "run_id": run.run_id,
                           "inherited": sum(1 for r in run.read("subdomain") if r.get("_inherited"))})
        return run


def _settle(tmp_path, plan, **kw):
    launcher = _Launcher(tmp_path, plan)
    out = settle.settle(project_dir=tmp_path, target="acme.com", launch=launcher, **kw)
    return out, launcher


class TestTheLoopStops:
    def test_a_FIXED_POINT_ends_the_campaign_successfully(self, tmp_path):
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                           {"remainders": [_rem()]}])
        assert (out.stop, out.success, out.clean) == ("fixed_point", True, True), out
        assert len(launcher.calls) == 2, "a child that added nothing over a known zero ends it"

    def test_owed_work_keeps_it_RUNNING(self, tmp_path):
        # child 3 owes nothing but still REDUCED the remainder 2 -> 0, which is progress; the campaign
        # confirms with one more child that nothing is left rather than stopping on the reduction itself
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=3)]},
                                           {"hosts": ["b.acme.com"], "remainders": [_rem(now=2)]},
                                           {"remainders": [_rem()]},
                                           {"remainders": [_rem()]}])
        assert (out.stop, len(launcher.calls)) == ("fixed_point", 4), out

    def test_NO_PROGRESS_stops_and_says_what_is_owed(self, tmp_path):
        # NO_PROGRESS_LIMIT is 2 CONSECUTIVE idle children — one quiet child is not a fixed point
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=5)]},
                                           {"remainders": [_rem(now=5)]},
                                           {"remainders": [_rem(now=5)]}])
        assert out.stop == "no_progress" and "5 unit(s) stayed owed" in out.detail, out
        assert len(launcher.calls) == 3 and not out.success

    def test_a_CHILD_FAULT_stops_immediately(self, tmp_path):
        out, launcher = _settle(tmp_path, [{"faults": ["boom"], "remainders": [_rem(now=5)]}])
        assert out.stop == "child_fault" and len(launcher.calls) == 1, out

    def test_a_lane_that_could_not_MEASURE_is_unknown_not_a_fixed_point(self, tmp_path):
        """A lane that ran and cannot say what it owes must not be read as a zero — nor be invisible
        because it stayed silent."""
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"unknown": ["enrich.a1d_brute"]}])
        assert out.stop == "unknown" and "could not measure" in out.detail, out

    def test_a_lane_that_reported_once_and_goes_SILENT_is_unknown(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                    {"remainders": []}])
        assert out.stop == "unknown" and "reported nothing" in out.detail, out


class TestTheBounds:
    def test_MAX_RUNS_is_a_named_outcome(self, tmp_path):
        plan = [{"hosts": [f"h{i}.acme.com"], "remainders": [_rem(now=9)]} for i in range(5)]
        out, launcher = _settle(tmp_path, plan, max_runs=3)
        assert (out.stop, out.detail) == ("max_runs", "3 child run(s)"), out
        assert len(launcher.calls) == 3 and not out.success

    def test_the_BUDGET_stops_before_the_next_child_never_during_one(self, tmp_path):
        """A wall clock bounds CONTINUATION. Killing a running child is `--timeout`'s axis, and a
        supervisor that did it would destroy the evidence the child was producing."""
        plan = [{"hosts": [f"h{i}.acme.com"], "remainders": [_rem(now=9)]} for i in range(4)]
        launcher = _Launcher(tmp_path, plan)
        # a clock the loop cannot outrun: inside the budget until two children have run, past it after —
        # so the only place the stop can land is BETWEEN children, whatever the loop reads it
        out = settle.settle(project_dir=tmp_path, target="acme.com", launch=launcher, budget_s=10,
                            _now=lambda: 0.0 if len(launcher.calls) < 2 else 99.0)
        assert out.stop == "budget" and "10s budget" in out.detail, out
        assert len(launcher.calls) == 2, "a child already running is never cut short by the budget"
        assert all(c["state"] == "manifested" for c in
                   campaign.Campaign(tmp_path, out.campaign_id).children)


class TestWhatOneChildLEARNSReachesTheNext:
    def test_child_2_is_SEEDED_from_the_union(self, tmp_path):
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com", "b.acme.com"],
                                            "remainders": [_rem(now=1)]},
                                           {"remainders": [_rem()]},
                                           {"remainders": [_rem()]}])
        assert launcher.calls[0]["inherited"] == 0
        assert launcher.calls[1]["inherited"] == 2, "child 2 started empty — its emptiness is not a fixed point"
        assert out.stop == "fixed_point"

    def test_an_inherited_entity_is_not_counted_as_the_child_s_DISCOVERY(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                    {"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"hosts": ["a.acme.com"], "remainders": [_rem()]}])
        ledger = campaign.Campaign(tmp_path, out.campaign_id)
        assert [c["new_identities"] for c in ledger.children] == [1, 0, 0], \
            "re-seeing what it was handed is not discovery"

    def test_the_union_SURVIVES_the_campaign(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}])
        union = campaign.Union.for_campaign(tmp_path, out.campaign_id)
        assert union.trustworthy and ("subdomain", "a.acme.com") in union.records


class TestAcquisitionIsChildOneOnly:
    def test_a_provider_lane_is_OPEN_for_child_1_and_closed_after(self, tmp_path):
        _out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                            {"remainders": [_rem()]},
                                            {"remainders": [_rem()]}])
        assert launcher.acquisition == [True, False, False], \
            "a continuation flag may not authorise more provider spending"

    def test_the_closure_is_RESTORED_after_the_campaign(self, tmp_path):
        from quarry_recon import contract
        _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                           {"remainders": [_rem()]},
                           {"remainders": [_rem()]}])
        assert contract.acquisition_open("probe.favicon", announce=False) is True


class TestTheLedgerIsTheRecord:
    def test_every_child_is_recorded_BEFORE_it_launches(self, tmp_path):
        seen: list = []

        def launch(index, prepare):
            seen.append([dict(c) for c in campaign.Campaign(tmp_path, cid).children])
            run = store.Run.create(tmp_path, "acme.com")
            prepare(run)
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
            return run

        cid = settle.new_campaign_id()
        settle.settle(project_dir=tmp_path, target="acme.com", launch=launch, campaign_id=cid)
        assert seen[0] == [{"index": 1, "state": "reserved", "run_id": None}]

    def test_a_child_that_RAISES_leaves_an_interrupted_record(self, tmp_path):
        def launch(index, prepare):
            raise RuntimeError("the run died")

        cid = settle.new_campaign_id()
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="acme.com", launch=launch, campaign_id=cid)
        ledger = campaign.Campaign(tmp_path, cid)
        assert [c["state"] for c in ledger.interrupted] == ["reserved"], \
            "an orphan run directory nobody recorded is what this prevents"

    def test_the_campaign_never_edits_a_CHILD(self, tmp_path):
        out, launcher = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=1)]},
                                           {"remainders": [_rem()]},
                                           {"remainders": [_rem()]}])
        first = tmp_path / "recon" / launcher.calls[0]["run_id"]
        after = json.loads((first / "manifest.json").read_text())
        assert "campaign" not in json.dumps(after), "a child's evidence is its own"
        assert out.campaign_id not in json.dumps(after)

    def test_two_supervisors_cannot_share_a_PROJECT(self, tmp_path):
        held = campaign.Campaign(tmp_path, "other")
        with held.acquire():
            with pytest.raises(budget.StateBusy):
                _settle(tmp_path, [{"remainders": [_rem()]}])

    def test_a_child_that_dies_MID_PHASE_is_recorded_as_started(self, tmp_path):
        """The run directory exists and phases have touched it. A ledger still calling that child "not
        launched" describes a run directory nobody accounts for — exactly what reserving early prevents."""
        def launch(index, prepare):
            run = store.Run.create(tmp_path, "acme.com")
            prepare(run)                                # the campaign records it HERE, then seeds it
            raise RuntimeError("the phase died")

        cid = settle.new_campaign_id()
        with pytest.raises(RuntimeError, match="the phase died"):
            settle.settle(project_dir=tmp_path, target="acme.com", launch=launch, campaign_id=cid)
        [child] = campaign.Campaign(tmp_path, cid).children
        assert child["state"] == "started" and child["run_id"], child
        assert (tmp_path / "recon" / child["run_id"]).is_dir()

    def test_a_child_that_dies_BEFORE_its_run_exists_stays_reserved(self, tmp_path):
        def launch(index, prepare):
            raise RuntimeError("no run directory was ever created")

        cid = settle.new_campaign_id()
        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="acme.com", launch=launch, campaign_id=cid)
        [child] = campaign.Campaign(tmp_path, cid).children
        assert (child["state"], child["run_id"]) == ("reserved", None)

    def test_the_ledger_records_the_run_that_was_actually_RETURNED(self, tmp_path):
        """A launcher that runs a second run would otherwise file one run's evidence under another's id."""
        def launch(index, prepare):
            prepare(store.Run.create(tmp_path, "acme.com"))
            other = store.Run.create(tmp_path, "acme.com")
            other.write_manifest(profile_summary={}, phases_run=["vertical"])
            return other

        with pytest.raises(RuntimeError, match="was returned"):
            settle.settle(project_dir=tmp_path, target="acme.com", launch=launch)

    def test_a_CORRUPT_ledger_is_refused_before_anything_is_taken_or_created(self, tmp_path):
        """Fail closed at the DOOR: `reserve()` would refuse it too, but only after the project lock was
        taken and the campaign's union created for a campaign that may not continue."""
        campaigns = tmp_path / "recon" / "campaigns" / "c1"
        campaigns.mkdir(parents=True)
        (campaigns / "ledger.json").write_text("{not json")
        launched: list = []
        with pytest.raises(campaign.UnionUnusable):
            settle.settle(project_dir=tmp_path, target="acme.com", campaign_id="c1",
                          launch=lambda index, prepare: launched.append(index))
        assert launched == []
        assert not (tmp_path / "recon" / "campaigns" / ".campaign.lock").exists(), \
            "the project lock was taken for a campaign that may not continue"
        assert not (campaigns / "union.json").exists()
        assert (campaigns / "ledger.json").read_text() == "{not json"

    def test_a_campaign_can_be_READ_back_from_its_ledger(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem(now=5)]},
                                    {"remainders": [_rem(now=5)]},
                                    {"remainders": [_rem(now=5)]}])
        lines = "\n".join(settle.report_lines(campaign.Campaign(tmp_path, out.campaign_id)))
        assert "3 child run(s)" in lines and "stopped: no_progress" in lines
        assert "+1 new" in lines and "no progress" in lines

    def test_an_UNREADABLE_ledger_reads_as_unusable_not_as_empty(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}])
        ledger = campaign.Campaign(tmp_path, out.campaign_id)
        ledger.path.write_text("{not json")
        lines = "\n".join(settle.report_lines(campaign.Campaign(tmp_path, out.campaign_id)))
        assert "unusable" in lines and "recover it deliberately" in lines

    def test_campaigns_are_listed_NEWEST_last(self, tmp_path):
        first, _ = _settle(tmp_path, [{"remainders": [_rem()]}], campaign_id="c20260101-000000")
        second, _ = _settle(tmp_path, [{"remainders": [_rem()]}], campaign_id="c20260102-000000")
        assert first.stop == second.stop == "fixed_point"
        assert [p.parent.name for p in settle.campaigns(tmp_path)] == [first.campaign_id,
                                                                       second.campaign_id]


class TestACampaignIsNotResumedByACCIDENT:
    def test_ids_do_not_collide_within_one_SECOND(self):
        minted = {settle.new_campaign_id() for _ in range(200)}
        assert len(minted) == 200, "second precision alone reuses an id — and an id here is a campaign"

    def test_a_minted_id_CLAIMS_its_directory(self, tmp_path):
        out, _ = _settle(tmp_path, [{"remainders": [_rem()]}])
        assert (tmp_path / "recon" / "campaigns" / out.campaign_id).is_dir()

    def test_a_colliding_MINT_never_adopts_a_directory_that_exists(self, tmp_path, monkeypatch):
        """The suffix makes a clash negligible; the atomic claim makes it impossible. Adopting an existing
        directory would hand a fresh campaign another campaign's union and child numbering."""
        _settle(tmp_path, [{"remainders": [_rem()]}])
        taken = settle.campaigns(tmp_path)[-1].parent.name
        monkeypatch.setattr(settle, "new_campaign_id", lambda *a, **kw: taken)
        with pytest.raises(RuntimeError, match="could not mint a unique campaign id"):
            _settle(tmp_path, [{"remainders": [_rem()]}])

    def test_running_the_same_id_twice_REFUSES(self, tmp_path):
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}], campaign_id="c-fixed")
        with pytest.raises(settle.AlreadyRun, match="already has 2 child run"):
            _settle(tmp_path, [{"remainders": [_rem()]}], campaign_id="c-fixed")
        assert len(campaign.Campaign(tmp_path, "c-fixed").children) == 2, \
            "a second invocation continued a finished campaign as its child 3"
        assert out.stop == "fixed_point"

    def test_a_STOPPED_campaign_names_its_stop_when_it_refuses(self, tmp_path):
        _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                           {"remainders": [_rem()]}], campaign_id="c-fixed")
        with pytest.raises(settle.AlreadyRun, match="stopped: fixed_point"):
            _settle(tmp_path, [{"remainders": [_rem()]}], campaign_id="c-fixed")

    @pytest.mark.parametrize("make_run", [False, True])
    def test_an_INTERRUPTED_campaign_is_RESUMED_not_refused(self, tmp_path, make_run):
        """What may not happen by accident is continuing a campaign that already stated an outcome.
        Refusing an interrupted one instead stranded it: its children were recorded and no invocation
        could ever finish or close them. The kill boundaries are pinned in `test_qr39_012_settlement`."""
        def dies(index, prepare):
            if make_run:
                prepare(store.Run.create(tmp_path, "acme.com"))
            raise RuntimeError("killed")

        with pytest.raises(RuntimeError):
            settle.settle(project_dir=tmp_path, target="acme.com", launch=dies, campaign_id="c-fixed")
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"hosts": ["b.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}], campaign_id="c-fixed")
        ledger = campaign.Campaign(tmp_path, "c-fixed")
        assert (out.resumed, out.stop, out.abandoned) == (True, "fixed_point", int(make_run)), out
        assert ledger.interrupted == [] and ledger.stop["cause"] == "fixed_point"


class TestTheFlagsThatDriveIt:
    """A help string that changes nothing is exactly the failure these are for."""

    @staticmethod
    def _invoke(argv, monkeypatch, **stubs):
        from click.testing import CliRunner
        from quarry_recon import cli as cli_mod
        for name, value in stubs.items():
            monkeypatch.setattr(cli_mod, name, value)
        return CliRunner().invoke(cli_mod.cli, argv)

    def test_the_bounds_REFUSE_to_exist_without_the_axis_they_bound(self, monkeypatch):
        for argv in (["run", "-t", "acme", "--settle-max-runs", "3"],
                     ["run", "-t", "acme", "--settle-budget", "60"]):
            res = self._invoke(argv, monkeypatch)
            assert res.exit_code != 0 and "need --settle" in res.output, argv

    def test_the_flag_reaches_the_SUPERVISOR_with_its_bounds(self, monkeypatch):
        from quarry_recon import cli as cli_mod, settle as _settle
        seen: dict = {}

        def _fake(**kw):
            seen.update(kw)
            return _settle.Outcome(campaign_id="c1", stop="fixed_point", success=True)

        monkeypatch.setattr(_settle, "settle", _fake)
        monkeypatch.setattr(cli_mod, "_resolve_profile", lambda v: v)
        monkeypatch.setattr(cli_mod.TargetProfile, "load", staticmethod(
            lambda _v: type("P", (), {"target": "acme.com", "modes": {}})()))
        monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: pathlib.Path("/nowhere"))
        res = self._invoke(["run", "-t", "acme", "--settle", "--settle-max-runs", "3",
                            "--settle-budget", "90"], monkeypatch)
        assert res.exit_code == 0, res.output
        assert (seen["max_runs"], seen["budget_s"]) == (3, 90), seen
        assert "fixed point" in res.output

    def test_a_plain_run_never_becomes_a_CAMPAIGN(self, monkeypatch):
        from quarry_recon import cli as cli_mod, settle as _settle
        called: list = []
        # the stand-in returns what the real `_run_phases` returns — a finished run the exit contract reads
        finished = type("R", (), {"run_id": "r1", "summary": lambda self: {"verdict": "complete"}})()

        def _ran(*a, **kw):
            called.append("run")
            return finished

        monkeypatch.setattr(_settle, "settle", lambda **kw: called.append(kw))
        monkeypatch.setattr(cli_mod, "_run_phases", _ran)
        res = self._invoke(["run", "-t", "acme"], monkeypatch)
        assert called == ["run"] and res.exit_code == 0

    def test_status_reads_a_CAMPAIGN_back(self, tmp_path, monkeypatch):
        from quarry_recon import cli as cli_mod
        out, _ = _settle(tmp_path, [{"hosts": ["a.acme.com"], "remainders": [_rem()]},
                                    {"remainders": [_rem()]}])
        monkeypatch.setattr(cli_mod, "_resolve_profile", lambda v: v)
        monkeypatch.setattr(cli_mod.TargetProfile, "load", staticmethod(
            lambda _v: type("P", (), {"target": "acme.com", "modes": {}})()))
        monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
        res = self._invoke(["status", "-t", "acme", "--campaign"], monkeypatch)
        assert res.exit_code == 0 and out.campaign_id in res.output
        assert "stopped: fixed_point" in res.output and "✔ success" in res.output

    def test_status_refuses_to_show_a_run_AND_a_campaign(self, tmp_path, monkeypatch):
        from quarry_recon import cli as cli_mod
        monkeypatch.setattr(cli_mod, "_resolve_profile", lambda v: v)
        monkeypatch.setattr(cli_mod.TargetProfile, "load", staticmethod(
            lambda _v: type("P", (), {"target": "acme.com", "modes": {}})()))
        monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
        res = self._invoke(["status", "-t", "acme", "--campaign", "--run", "20260101-000000-aaaa"],
                           monkeypatch)
        assert res.exit_code != 0 and "one of them" in res.output

    def test_status_says_so_when_a_project_never_SETTLED(self, tmp_path, monkeypatch):
        from quarry_recon import cli as cli_mod
        monkeypatch.setattr(cli_mod, "_resolve_profile", lambda v: v)
        monkeypatch.setattr(cli_mod.TargetProfile, "load", staticmethod(
            lambda _v: type("P", (), {"target": "acme.com", "modes": {}})()))
        monkeypatch.setattr(cli_mod, "_project_dir", lambda _p: tmp_path)
        res = self._invoke(["status", "-t", "acme", "--campaign"], monkeypatch)
        assert res.exit_code != 0 and "no campaigns found" in res.output
