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
    def test_a_BOUND_and_a_DEFERRAL_are_retriable_now(self):
        out = _swept(eligible_pairs=10, attempted_pairs=3, bound_pairs=4, deferred_pairs=3,
                     targets_eligible=2, stop_kind="bound")
        rec = remainder.from_sweep("vertical.wildcard_http", out)
        assert (rec.now, rec.cooldown) == (7, 0), rec.as_record()
        assert rec.terminal == {}, rec.terminal

    def test_a_REFUSAL_is_retriable_with_a_COOLDOWN(self):
        """`budget.ADMISSION_COOLDOWN_GENS` asks a refused target again — a transient refusal must not
        become a permanent exclusion, so it is not terminal."""
        out = _swept(eligible_pairs=5, attempted_pairs=0, refused_pairs=5)
        rec = remainder.from_sweep("vertical.wildcard_http", out)
        assert (rec.now, rec.cooldown) == (0, 5), rec.as_record()
        assert rec.terminal == {}, rec.terminal

    def test_UNSCHEDULABLE_work_is_terminal(self):
        out = _swept(eligible_pairs=5, attempted_pairs=3, unselectable_pairs=2)
        rec = remainder.from_sweep("vertical.wildcard_http", out)
        assert rec.terminal == {"unschedulable": 2}, rec.terminal
        assert (rec.now, rec.cooldown) == (0, 0), rec.as_record()

    @pytest.mark.parametrize("kind,expect", [("machinery", {"machinery": 4}),
                                             ("dependency", {"dependency": 4})])
    def test_a_MACHINERY_or_DEPENDENCY_stop_is_terminal(self, kind, expect):
        out = _swept(eligible_pairs=10, attempted_pairs=6, stop_kind=kind, stop="x")
        rec = remainder.from_sweep("enrich.a1d_brute", out)
        assert rec.terminal == expect and rec.now == 0, rec.as_record()

    def test_a_CLOCK_stop_is_retriable(self):
        """A budget stopped this child; the next one simply continues."""
        out = _swept(eligible_pairs=10, attempted_pairs=6, stop_kind="budget", stop="budget exhausted")
        rec = remainder.from_sweep("enrich.a1d_brute", out)
        assert (rec.now, rec.terminal) == (4, {}), rec.as_record()

    def test_the_measure_and_unit_are_STATED(self):
        rec = remainder.from_sweep("vertical.wildcard_http", _swept(eligible_pairs=1, attempted_pairs=0))
        record = rec.as_record()
        assert record["measure"] == "candidate_pairs"
        assert record["unit"] == "vertical.wildcard_http:candidate_pairs"
        assert set(record["terminal"]) == set(remainder.TERMINAL_CAUSES)


class TestTheManifestCarriesIt:
    def test_the_LATEST_record_per_unit_reaches_the_manifest(self, tmp_path):
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            remainder.emit(remainder.from_sweep("vertical.wildcard_http",
                                                _swept(eligible_pairs=10, attempted_pairs=3,
                                                       bound_pairs=7)))
            time.sleep(0.005)                              # a DIFFERENT timestamp, same unit
            remainder.emit(remainder.from_sweep("vertical.wildcard_http",      # a later, smaller remainder
                                                _swept(eligible_pairs=10, attempted_pairs=9,
                                                       bound_pairs=1)))
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        rows = json.loads(run.manifest_path.read_text())["summary"]["remainders"]
        assert len(rows) == 1, rows                       # latest-per-unit, so a finished rotation CLEARS
        assert rows[0]["retriable"] == {"now": 1, "cooldown": 0}, rows[0]
        assert rows[0]["model"] == "project_progress" and rows[0]["measure"] == "candidate_pairs"

    def test_a_lane_that_said_NOTHING_is_absent_not_zero(self, tmp_path):
        run = store.Run.create(tmp_path, "t")
        events.reset(); events.configure(run.dir)
        try:
            run.write_manifest(profile_summary={}, phases_run=["vertical"])
        finally:
            events.reset()
        assert json.loads(run.manifest_path.read_text())["summary"]["remainders"] == []

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
