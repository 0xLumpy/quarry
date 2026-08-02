"""What a lane still OWES — settle prerequisite B.

`--settle` may only keep a campaign alive for work another child would actually ADVANCE. That needs the
lane's cross-run MODEL and this remainder's DISPOSITION as separate facts, in a stated MEASURE, and a lane
that reports nothing must read as UNKNOWN rather than zero.
"""
from __future__ import annotations

import json
import time

import pytest

from quarry_recon import events, remainder, sources, store, sweep


def _swept(**kw):
    out = sweep.SweepResult()
    for key, value in kw.items():
        setattr(out, key, value)
    return out


class TestTheModelIsDeclared:
    def test_every_declared_lane_is_a_REGISTERED_source(self):
        known = set(sources.all_sources())
        assert set(remainder.LANE_MODEL) <= known, set(remainder.LANE_MODEL) - known

    def test_every_SWEEP_lane_declares_a_model(self):
        """A lane that reports a remainder without declaring how it behaves across runs is a lane whose
        remainder nobody can interpret."""
        for lane in ("enrich.a1d_brute", "enrich.wildcard_a1d", "vertical.wildcard_http"):
            assert remainder.LANE_MODEL[lane] == "project_progress", lane

    def test_the_permutation_loop_is_RERUN_SAME_WORK(self):
        """Entities are run-scoped, so a later run replays its rounds from an empty frontier — its
        remainder is `--unbound`'s business, never `--settle`'s."""
        assert remainder.LANE_MODEL["vertical.alterx_permute"] == "rerun_same_work"

    def test_a_rerun_same_work_remainder_is_NOT_retriable(self):
        rec = remainder.Remainder(lane="vertical.alterx_permute", unit="u", measure="rounds",
                                  model="rerun_same_work", now=5)
        assert rec.retriable == 0, rec
        progress = remainder.Remainder(lane="enrich.a1d_brute", unit="u", measure="candidate_pairs",
                                       model="project_progress", now=5, cooldown=2)
        assert progress.retriable == 7, progress

    @pytest.mark.parametrize("kwargs,why", [
        ({"model": "invented"}, "unknown model"),
        ({"model": "rerun_same_work"}, "contradicts the declared model"),
        ({"unit": ""}, "needs a unit"),
        ({"measure": ""}, "needs a measure"),
        ({"now": -1}, "negative"),
        ({"now": True}, "a bool is not a count"),
        ({"terminal": {"invented": 1}}, "unknown cause"),
        ({"terminal": {"machinery": -1}}, "negative cause"),
    ])
    def test_a_malformed_remainder_is_REFUSED(self, kwargs, why):
        base = {"lane": "enrich.a1d_brute", "unit": "u", "measure": "candidate_pairs",
                "model": "project_progress"}
        with pytest.raises(ValueError):
            remainder.Remainder(**{**base, **kwargs}).validate()


class TestTheSweepMapsOntoDispositions:
    def test_LIVENESS_comes_from_the_DURABLE_rotation(self):
        """The defect the continuation report already had: the pair partition describes ONE lifecycle, so
        a deferred-but-since-finished target stayed counted. After the pinned eight-zone trace the rotation
        owes nothing, and the remainder must say so however many pairs this run left behind."""
        finished = _swept(eligible_pairs=16, attempted_pairs=10, deferred_pairs=6,
                          targets_eligible=8, targets_complete=8, targets_remaining=0,
                          remaining_now=0)
        rec = remainder.from_sweep("vertical.wildcard_http", finished)
        assert (rec.now, rec.cooldown, rec.terminal) == (0, 0, {}), rec.as_record()
        assert rec.detail["candidate_pairs"]["deferred"] == 6, rec.detail     # kept, never summed
        owing = _swept(eligible_pairs=16, attempted_pairs=10, deferred_pairs=6,
                       targets_eligible=8, targets_complete=5, targets_remaining=3, remaining_now=3)
        assert remainder.from_sweep("vertical.wildcard_http", owing).now == 3

    def test_a_REFUSAL_is_retriable_with_a_COOLDOWN(self):
        """`budget.ADMISSION_COOLDOWN_GENS` asks a refused target again — a transient refusal must not
        become a permanent exclusion, so it is not terminal."""
        out = _swept(eligible_pairs=5, attempted_pairs=0, refused_pairs=5, targets_eligible=2,
                     targets_remaining=2, targets_refused=2, remaining_cooldown=2)
        rec = remainder.from_sweep("vertical.wildcard_http", out)
        assert (rec.now, rec.cooldown) == (0, 2), rec.as_record()
        assert rec.terminal == {}, rec.terminal

    def test_only_UNSCHEDULABLE_work_left_is_terminal(self):
        out = _swept(eligible_pairs=5, attempted_pairs=3, unselectable_pairs=2, targets_eligible=2,
                     targets_remaining=1, remaining_terminal={"unschedulable": 1})
        rec = remainder.from_sweep("vertical.wildcard_http", out)
        assert rec.terminal == {"unschedulable": 1}, rec.terminal
        assert (rec.now, rec.cooldown) == (0, 0), rec.as_record()

    @pytest.mark.parametrize("kind", ["machinery", "dependency"])
    def test_a_MACHINERY_or_DEPENDENCY_stop_is_terminal(self, kind):
        out = _swept(eligible_pairs=10, attempted_pairs=6, stop_kind=kind, stop="x",
                     targets_eligible=3, targets_remaining=2, remaining_terminal={kind: 2})
        rec = remainder.from_sweep("enrich.a1d_brute", out)
        assert rec.terminal == {kind: 2} and rec.now == 0, rec.as_record()

    def test_a_CLOCK_stop_is_retriable(self):
        """A budget stopped this child; the next one simply continues."""
        out = _swept(eligible_pairs=10, attempted_pairs=6, stop_kind="budget", stop="budget exhausted",
                     targets_eligible=3, targets_remaining=2, remaining_now=2)
        rec = remainder.from_sweep("enrich.a1d_brute", out)
        assert (rec.now, rec.terminal) == (2, {}), rec.as_record()

    def test_the_measure_and_unit_are_STATED(self):
        rec = remainder.from_sweep("vertical.wildcard_http",
                                   _swept(eligible_pairs=1, attempted_pairs=0, targets_eligible=1,
                                          targets_remaining=1, remaining_now=1))
        record = rec.as_record()
        assert record["measure"] == "targets"
        assert record["unit"] == "vertical.wildcard_http:targets"
        assert set(record["terminal"]) == set(remainder.TERMINAL_CAUSES)
        assert "candidate_pairs" in record["detail"], record


class TestTheLoopReportsToo:
    """`vertical.alterx_permute` declares a model, so it must REPORT — a lane that never does reads as
    unknown for ever, and the supervisor learns nothing about a loop it was told to expect."""

    def test_a_bound_that_cut_a_producing_loop_short_owes_a_round(self):
        rec = remainder.for_rounds("vertical.alterx_permute", stop="bound", rounds=3, ran=3, made=True)
        assert rec.now == 1 and rec.model == "rerun_same_work", rec.as_record()
        assert rec.retriable == 0, "repetition still cannot reach it"
        assert rec.detail == {"rounds_ran": 3, "bound": 3, "exit": "bound"}, rec.detail

    @pytest.mark.parametrize("stop", ["converged", "no_candidates", "passive"])
    def test_a_finished_loop_owes_nothing(self, stop):
        rec = remainder.for_rounds("vertical.alterx_permute", stop=stop, rounds=3, ran=2, made=False)
        assert (rec.now, rec.terminal) == (0, {}), rec.as_record()

    def test_a_DEGRADED_stall_is_terminal_not_a_fixed_point(self):
        rec = remainder.for_rounds("vertical.alterx_permute", stop="no_progress", rounds=0, ran=2,
                                   made=False)
        assert rec.terminal == {"machinery": 1} and rec.now == 0, rec.as_record()


class TestTheManifestCarriesIt:
    def test_the_LATEST_record_per_unit_reaches_the_manifest(self, tmp_path):
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            remainder.emit(remainder.from_sweep("vertical.wildcard_http",
                                                _swept(eligible_pairs=10, attempted_pairs=3,
                                                       bound_pairs=7, targets_eligible=4,
                                                       targets_remaining=3, remaining_now=3)))
            time.sleep(0.005)                              # a DIFFERENT timestamp, same unit
            remainder.emit(remainder.from_sweep("vertical.wildcard_http",      # a later, smaller remainder
                                                _swept(eligible_pairs=10, attempted_pairs=9,
                                                       bound_pairs=1, targets_eligible=4,
                                                       targets_remaining=1, remaining_now=1)))
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        rows = json.loads(run.manifest_path.read_text())["summary"]["remainders"]
        assert len(rows) == 1, rows                       # latest-per-unit, so a finished rotation CLEARS
        assert rows[0]["retriable"] == {"now": 1, "cooldown": 0}, rows[0]
        assert rows[0]["model"] == "project_progress" and rows[0]["measure"] == "targets"

    @pytest.mark.parametrize("payload,why", [
        ({"model": "invented"}, "unknown model"),
        ({"retriable": {"now": -1, "cooldown": 0}}, "negative"),
        ({"retriable": {"now": True, "cooldown": 0}}, "a bool is not a count"),
        ({"retriable": "five"}, "not a mapping"),
        ({"terminal": {"invented": 2}}, "unknown cause"),
        ({"measure": ""}, "no measure"),
    ])
    def test_a_MALFORMED_record_arrives_as_INVALID_not_as_numbers(self, tmp_path, payload, why):
        """This feeds a supervisor's arithmetic. A payload nobody validated must not reach it as data."""
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        base = {"unit": "vertical.wildcard_http:targets", "measure": "targets",
                "model": "project_progress", "retriable": {"now": 1, "cooldown": 0},
                "terminal": {c: 0 for c in remainder.TERMINAL_CAUSES}}
        try:
            events.emit("remainder", "vertical.wildcard_http", **{**base, **payload})
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        row = json.loads(run.manifest_path.read_text())["summary"]["remainders"][0]
        assert "retriable" not in row and row["invalid"], (why, row)

    def test_a_lane_that_said_NOTHING_is_absent_not_zero(self, tmp_path):
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        assert json.loads(run.manifest_path.read_text())["summary"]["remainders"] == []

    def test_the_real_PERMUTATION_LOOP_reports_its_remainder(self, tmp_path, monkeypatch):
        """A lane that declares a model must actually report, or the supervisor's roster reads it as
        unknown for ever."""
        from test_a1d_vocabulary import TestTheRecursionRoundsPolicy as L
        chain = {1: ["a1.acme.com"], 2: ["a2.acme.com"], 3: ["a3.acme.com"], 4: ["a4.acme.com"]}
        L._drive(L(), tmp_path, monkeypatch, growth=lambda i: chain.get(i, []))
        log = next((tmp_path / "recon").glob("*/events.jsonl"))
        rows = [json.loads(l) for l in log.read_text().splitlines()
                if json.loads(l).get("event") == "remainder"]
        assert rows and rows[-1]["source_id"] == "vertical.alterx_permute", rows
        assert rows[-1]["model"] == "rerun_same_work", rows[-1]
        assert rows[-1]["retriable"]["now"] == 1, rows[-1]      # the 3-round bound cut a producing loop

    def test_the_real_DIFFER_reports_its_remainder(self, tmp_path, monkeypatch):
        from test_a1d_vocabulary import TestTheWildcardDifferHasItsOwnLifecycle as L
        st: dict = {}
        L._differ(L(), tmp_path, monkeypatch, zones=tuple(f"z{i}.acme.com" for i in range(8)),
                  words=("api", "admin"), rows=[], st=st, spend=1)
        log = next((tmp_path / "recon").glob("*/events.jsonl"))
        rows = [json.loads(l) for l in log.read_text().splitlines()
                if json.loads(l).get("event") == "remainder"]
        assert rows and rows[-1]["source_id"] == "enrich.wildcard_a1d", rows
        assert rows[-1]["model"] == "project_progress"
        assert rows[-1]["retriable"]["now"] > 0, rows[-1]      # a spend of 1 over 8 zones owes plenty

    def test_an_UNKNOWN_remainder_is_reported_AS_UNKNOWN(self, tmp_path, monkeypatch):
        """A lane whose eligible set was never established must read as unknown, not as a clean zero —
        and SAYING so is what distinguishes it from a lane that never ran at all. Staying silent made the
        two indistinguishable, so a supervisor's roster simply dropped it (settle step 7)."""
        from quarry_recon import sweep as _sweep
        from test_a1d_vocabulary import TestTheWildcardDifferHasItsOwnLifecycle as L
        real = _sweep.run_sweep

        def unknown(**kw):
            out = real(**kw)
            out.remainder_known = False                  # as an unestablished corpus would leave it
            return out

        monkeypatch.setattr(_sweep, "run_sweep", unknown)
        st: dict = {}
        L._differ(L(), tmp_path, monkeypatch, zones=("z.acme.com",), words=("api",), rows=[], st=st)
        log = next((tmp_path / "recon").glob("*/events.jsonl"))
        rows = [json.loads(l) for l in log.read_text().splitlines()
                if json.loads(l).get("event") == "remainder"]
        assert len(rows) == 1 and rows[0]["model"] == "unknown", rows
        assert "retriable" not in rows[0] and "terminal" not in rows[0], "unknown carries NO counts"
        assert rows[0]["detail"]["why"], "an unknown says why nobody could measure it"
