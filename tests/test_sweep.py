"""The SWEEP DRIVER — `sweep.run_sweep` (step-4 design v10).

Every case here is one of the ten review rounds' conclusions, driven through the real driver and the real
`budget.RotationProgress`: only the tool invocation is a double.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon import budget, events, sweep
from quarry_recon.runner import RunResult, Status

pytestmark = pytest.mark.offline

LANE = "a1d"
COV = "enrich.wildcard_a1d"          # any registered source: the driver only emits coverage under it


def _result(status=Status.SUCCESS):
    return RunResult("puredns", ["puredns"], status, 0, 0.1, None, 0)


class _Tool:
    """Records what was submitted, and can be told to fail."""

    def __init__(self, statuses=None, raises=None, max_calls=200):
        self.calls = []
        self.statuses = list(statuses or [])
        self.raises = raises
        self.max_calls = max_calls          # a WATCHDOG: a sweep that never terminates must FAIL, not hang

    def __call__(self, target, bucket, words):
        assert len(self.calls) < self.max_calls, "the sweep did not terminate"
        self.calls.append((target, bucket, tuple(words)))
        if self.raises and len(self.calls) == self.raises[0]:
            raise self.raises[1]
        status = self.statuses.pop(0) if self.statuses else Status.SUCCESS
        return _result(status)


def _run(tmp_path, *, targets=("acme.com",), words=None, tool=None, budget_s=0, **kw):
    words = words or [f"w{i:03d}" for i in range(20)]
    tool = tool or _Tool()
    out = sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=list(targets),
                          vocabulary=lambda t: list(words), execute=tool,
                          budget_s=budget_s, coverage_lane=COV, **kw)
    return out, tool


def _events(tmp_path):
    log = tmp_path / "events.jsonl"
    return [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []


@pytest.fixture(autouse=True)
def _log(tmp_path):
    events.reset()
    events.configure(tmp_path)
    yield
    events.reset()


class TestTerminationAndOnceness:
    def test_an_UNBOUNDED_sweep_runs_every_slot_exactly_once(self, tmp_path):
        """v6#1: without a run-local exclusion, ranking re-selects the oldest CLEAN slot forever — a
        `budget=0` lane would never terminate."""
        out, tool = _run(tmp_path, tool=_Tool(max_calls=25))     # 20 words -> at most 20 slots
        submitted = [c[1] for c in tool.calls]
        assert len(submitted) == len(set(submitted)), submitted
        assert sum(len(c[2]) for c in tool.calls) == 20 == out.eligible_pairs == out.attempted_pairs

    def test_a_SECOND_sweep_re_runs_the_same_slots_in_rotation(self, tmp_path):
        first, tool1 = _run(tmp_path)
        second, tool2 = _run(tmp_path)
        assert {c[1] for c in tool1.calls} == {c[1] for c in tool2.calls}
        assert second.eligible_pairs == 20

    def test_a_BUDGET_stops_the_sweep_and_the_REMAINDER_goes_first_next_time(self, tmp_path, monkeypatch):
        """A bounded run advances; the next run continues instead of repeating the prefix. The clock is a
        FAKE that only moves when a slot runs, so the test is deterministic."""
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 4.0                       # each invocation costs 4s of the 10s budget
                return super().__call__(target, bucket, words)

        first, tool1 = _run(tmp_path, tool=_Slow(), budget_s=10)
        done_first = {c[1] for c in tool1.calls}
        assert 0 < len(done_first) < 20, done_first
        assert first.stop is None or "budget" in (first.stop or "")
        ticks["t"] = 0.0
        second, tool2 = _run(tmp_path, tool=_Slow(), budget_s=10)
        assert not ({c[1] for c in tool2.calls} & done_first), "the bounded run repeated its own prefix"


class TestOrdering:
    def test_TIER_dominates_target_fairness(self, tmp_path):
        """v5#1: a target holding only CLEAN work must not run while another has dirty/never-run work —
        even when the clean target is the one that was selected longest ago."""
        words = ["alpha", "beta"]
        _run(tmp_path, targets=("a.com",), words=words)               # a.com swept first (older cursor)
        _run(tmp_path, targets=("b.com",), words=words)               # b.com swept second (newer cursor)
        # b.com now has NEW vocabulary (dirty); a.com is clean and its cursor is older
        def vocab(target):
            return words + (["gamma-new"] if target == "b.com" else [])

        tool = _Tool()
        out = sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=["a.com", "b.com"],
                              vocabulary=vocab, execute=tool, budget_s=0, coverage_lane=COV)
        assert tool.calls[0][0] == "b.com", [c[0] for c in tool.calls]
        assert tool.calls[0][1] == sweep.bucket_of("gamma-new"), tool.calls[0]

    def test_targets_ALTERNATE_inside_a_tier(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com", "b.com"),
                         words=[f"w{i:03d}" for i in range(6)])
        seen = [c[0] for c in tool.calls]
        assert seen[0] != seen[1], seen                               # A,B,A,B rather than A,A,…,B,B
        assert seen.count("a.com") == seen.count("b.com")

    def test_the_STALEST_slot_goes_first_within_a_target(self, tmp_path):
        """Clean slots are ordered by when they were last SELECTED, not by bucket name."""
        words = [f"w{i:03d}" for i in range(6)]
        _run(tmp_path, words=words)                                   # everything clean, seq ascends
        # make one LATE bucket the stalest by hand: the state is the scheduler's input
        doc = json.loads((tmp_path / f"{LANE}.json").read_text())
        slots = doc["targets"]["acme.com"]["slots"]
        late = sorted(slots)[-1]
        slots[late]["res"]["gen"] = 1                                 # oldest reservation
        slots[late]["done"]["gen"] = 1
        for other in sorted(slots)[:-1]:
            slots[other]["res"]["gen"] = 50
            slots[other]["done"]["gen"] = 50
        doc["gen"] = 60
        doc["targets"]["acme.com"]["seq"] = 60
        (tmp_path / f"{LANE}.json").write_text(json.dumps(doc))
        out, tool = _run(tmp_path, words=words)
        assert tool.calls[0][1] == late, [c[1] for c in tool.calls]

    def test_a_DIRTY_slot_outranks_a_clean_one(self, tmp_path):
        words = [f"w{i:03d}" for i in range(4)]
        _run(tmp_path, words=words)                                   # everything clean
        grown = words + ["brand-new-word"]
        out, tool = _run(tmp_path, words=grown)
        changed = sweep.bucket_of("brand-new-word")
        assert tool.calls[0][1] == changed, [c[1] for c in tool.calls]


class TestTheFourDispositions:
    def test_a_MISSING_dependency_reserves_nothing(self, tmp_path):
        out, tool = _run(tmp_path, dependency_ok=lambda: False)
        assert tool.calls == [] and out.reservations_persisted == 0
        assert out.stop == "the tool is not installed"
        assert not (tmp_path / f"{LANE}.json").exists()

    def test_a_SKIPPED_result_stops_the_lane(self, tmp_path):
        """v7#2: reserving every remaining slot against a tool that vanished burns the whole rotation."""
        tool = _Tool(statuses=[Status.SUCCESS, Status.SKIPPED, Status.SUCCESS])
        out, _t = _run(tmp_path, tool=tool)
        assert len(tool.calls) == 2 and out.stop == "the tool did not run"
        assert out.slots_attempted == 1                                # SKIPPED never enters the denominator

    def test_a_RAISING_invocation_keeps_what_was_already_earned(self, tmp_path):
        tool = _Tool(raises=(2, RuntimeError("popen exploded")))
        out, _t = _run(tmp_path, tool=tool)
        assert out.slots_attempted == 1 and out.attempted_pairs > 0
        assert "popen exploded" in " ".join(out.machinery)
        assert out.stop == "machinery: the invocation raised"
        assert out.reservations_persisted == 2                        # the raising slot WAS reserved

    def test_a_failed_RESERVATION_submits_nothing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(budget.RotationProgress, "save", lambda self: False)
        out, tool = _run(tmp_path)
        assert tool.calls == [], tool.calls                            # FAIL CLOSED
        assert out.stop == "machinery: the reservation could not be persisted"
        assert out.stop_kind == "machinery" and out.durable is False    # nothing persisted at all

    def test_an_unpublishable_COMPLETION_keeps_the_evidence(self, tmp_path, monkeypatch):
        saves = {"n": 0}

        real = budget.RotationProgress.save

        def flaky(self):
            saves["n"] += 1
            return real(self) if saves["n"] % 2 else False     # reservations save, completions do not

        monkeypatch.setattr(budget.RotationProgress, "save", flaky)
        out, tool = _run(tmp_path, words=["one", "two", "three"])
        assert tool.calls, "the sweep stopped instead of running"
        # v14#1: a completion whose own save failed is PENDING, and a later successful reservation save
        # carries it to disk — so it is reclassified as published rather than reported lost.
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA)
        durable_done = sum(1 for t in reopened.targets.values()
                           for sl in t["slots"].values() if "done" in sl)
        assert out.completions_published == durable_done, (out.completions_published, durable_done)
        assert out.completion_unpersisted == 0 or durable_done < len(tool.calls)
        assert out.slots_attempted == len(tool.calls)                  # the evidence still counts


class TestContentionAndCoverage:
    def test_a_CONTENDER_submits_nothing_and_reports_the_exact_denominator(self, tmp_path):
        with budget.rotation_session(tmp_path, LANE, schema=sweep.SCHEMA):
            out, tool = _run(tmp_path)
        assert tool.calls == [] and out.contended is True
        assert out.eligible_pairs == 20 and out.attempted_pairs == 0
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (20, 0, 20), sel
        assert "another lifecycle" in sel["reason"] and sel["kind"] == "timeout", sel

    def test_a_body_StateBusy_is_MACHINERY_not_contention(self, tmp_path, monkeypatch):
        """v10#2: only failing to ENTER the lane lock is contention."""
        def boom(self, *a, **k):
            raise budget.StateBusy("something inside the sweep")

        monkeypatch.setattr(budget.RotationProgress, "reserve", boom)
        with pytest.raises(budget.StateBusy):
            _run(tmp_path)                     # it is NOT swallowed into a contention gap

    def test_a_NON_CONTENTION_acquisition_error_is_not_reported_as_contention(self, tmp_path,
                                                                              monkeypatch):
        """Only `StateBusy` means another lifecycle. A read-only filesystem is machinery and must not be
        laundered into "somebody else owns this"."""
        import contextlib as _c

        @_c.contextmanager
        def broken(*a, **k):
            raise OSError("read-only filesystem")
            yield  # pragma: no cover

        monkeypatch.setattr(budget, "rotation_session", broken)
        with pytest.raises(OSError):
            _run(tmp_path)

    def test_SELECTION_and_OUTCOME_are_separate_denominators(self, tmp_path):
        tool = _Tool(statuses=[Status.SUCCESS, Status.FAILED] + [Status.EMPTY] * 30)
        out, _t = _run(tmp_path, tool=tool, words=[f"w{i:03d}" for i in range(6)])
        evs = _events(tmp_path)
        sel = [e for e in evs if e.get("measure") == "candidate_pairs"][-1]
        outc = [e for e in evs if e.get("measure") == "slot_outcomes"][-1]
        assert sel["eligible"] == 6 and sel["tested"] == 6, sel
        assert outc["eligible"] == out.slots_attempted, outc
        assert outc["omitted"] == 1 and "failed" in outc["reason"], outc   # the FAILED slot is a loss

    def test_a_CLEAN_sweep_reports_no_omission(self, tmp_path):
        _run(tmp_path)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert sel["omitted"] == 0 and sel["kind"] == "cap", sel


class TestStableIdentityAndAttribution:
    def test_inserting_a_word_never_MOVES_another(self, tmp_path):
        before = {w: sweep.bucket_of(w) for w in ("alpha", "beta", "gamma")}
        assert sweep.bucket_of("aaaa-inserted-first") is not None
        after = {w: sweep.bucket_of(w) for w in ("alpha", "beta", "gamma")}
        assert before == after

    def test_attribution_ranges_only_over_PRODUCERS(self, tmp_path):
        assert sweep.owner_of("word", ["js"]) == "js"
        assert sweep.owner_of("word", ["js", "katana"]) in ("js", "katana")

    def test_attribution_is_STABLE_and_SPREAD(self, tmp_path):
        srcs = ["js", "katana", "sourcemap"]
        owners = [sweep.owner_of(f"w{i:04d}", srcs) for i in range(300)]
        assert set(owners) == set(srcs), set(owners)               # nobody takes them all
        assert owners == [sweep.owner_of(f"w{i:04d}", srcs) for i in range(300)]

    def test_per_source_ACCOUNTING_is_reported(self, tmp_path):
        out, _t = _run(tmp_path, attribution=lambda w: "js" if w.endswith(("0", "2", "4")) else "katana")
        assert sum(out.per_source_eligible.values()) == 20
        assert sum(out.per_source_attempted.values()) == 20             # an unbounded sweep ran them all
        attr = [e for e in _events(tmp_path) if e.get("unit") == "attribution"][-1]["selection_attribution"]
        assert attr["per_source_scheduled"] == attr["per_source_eligible"], attr   # an unbounded sweep
        assert set(attr["per_source_eligible"]) == {"js", "katana"}, attr


class TestStateHonesty:
    def test_a_DEGRADED_rotation_is_named(self, tmp_path):
        (tmp_path / f"{LANE}.json").write_text(json.dumps(
            {"lane": LANE, "schema": sweep.SCHEMA, "gen": 3,
             "targets": {"acme.com": {"seq": 3, "slots": {"001": {"res": {"gen": 99, "at": 1.0}}}}}}))
        out, _t = _run(tmp_path)
        assert out.state_status == "degraded"
        assert any("degraded" in m for m in out.machinery), out.machinery

    def test_an_UNUSABLE_rotation_submits_NOTHING_and_says_why(self, tmp_path):
        """Composition of two rules: a document we cannot read is never overwritten (it may be another
        lifecycle's), and a slot whose reservation cannot be persisted is never submitted. So a corrupt
        lane file costs this run its work — loudly — and recovery is the operator removing it."""
        (tmp_path / f"{LANE}.json").write_text("not json")
        out, tool = _run(tmp_path)
        assert out.state_status == "unusable"
        assert tool.calls == [], tool.calls
        assert out.stop == "machinery: the reservation could not be persisted"
        assert out.durable is False                                      # no reservation ever landed
        assert (tmp_path / f"{LANE}.json").read_text() == "not json"     # nothing was destroyed
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert (sel["tested"], sel["omitted"]) == (0, 20), sel


class TestReviewV14:
    """Five accounting contracts the v14 review reproduced against 940ee2d."""

    def test_a_completion_RESCUED_by_a_later_save_is_counted_as_published(self, tmp_path):
        """The `done` tuple stays in the in-memory map, so the next successful save carries it to disk.
        Reporting it as unpersisted while the disk holds it is the counters lying about the state."""
        saves = {"n": 0}
        real = budget.RotationProgress.save

        def flaky(self):
            saves["n"] += 1
            return False if saves["n"] == 2 else real(self)     # only the FIRST completion save fails

        import unittest.mock as _m
        with _m.patch.object(budget.RotationProgress, "save", flaky):
            out, tool = _run(tmp_path, words=["one", "two", "three"])
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA)
        durable_done = sum(1 for t in reopened.targets.values()
                           for sl in t["slots"].values() if "done" in sl)
        assert out.completions_published == durable_done, (out.completions_published, durable_done)
        assert out.completion_unpersisted == len(tool.calls) - durable_done

    def test_PARTIAL_progress_is_not_reported_as_a_full_restart(self, tmp_path):
        """v14#2: a reservation failure after real progress used to claim the lane RESTARTS."""
        saves = {"n": 0}
        real = budget.RotationProgress.save

        def fail_third(self):
            saves["n"] += 1
            return False if saves["n"] >= 3 else real(self)

        import unittest.mock as _m
        with _m.patch.object(budget.RotationProgress, "save", fail_third):
            out, tool = _run(tmp_path, words=["one", "two", "three"])
        assert out.reservations_persisted >= 1 and out.stop_kind == "machinery"
        assert out.durable is True, out
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "RESTARTS" not in sel["reason"], sel["reason"]
        assert "RESUMABLE" in sel["reason"], sel["reason"]

    def test_CONTENTION_never_claims_completion_state_was_lost(self, tmp_path):
        with budget.rotation_session(tmp_path, LANE, schema=sweep.SCHEMA):
            out, _tool = _run(tmp_path)
        assert out.durable is True and out.stop_kind == "contention"
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "RESTARTS" not in sel["reason"], sel["reason"]

    def test_ATTRIBUTION_measures_the_SCHEDULED_PREFIX(self, tmp_path, monkeypatch):
        """v14#3: it summed the whole eligible corpus and reported no omission, so the timing pass could
        not see the first-k distribution it exists to measure."""
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 20.0
                return super().__call__(target, bucket, words)

        out, tool = _run(tmp_path, tool=_Slow(), budget_s=10,
                         attribution=lambda w: "js" if w < "w010" else "katana")
        assert len(tool.calls) == 1, tool.calls
        assert sum(out.per_source_eligible.values()) == 20
        assert sum(out.per_source_attempted.values()) == out.attempted_pairs < 20
        ev = [e for e in _events(tmp_path) if e.get("unit") == "attribution"][-1]
        attr = ev["selection_attribution"]
        assert ev.get("produced") is None, ev          # `produced` is for real entity counts only
        assert attr["scheduled"] == out.attempted_pairs, attr
        assert attr["eligible"] == 20 > attr["scheduled"], attr
        assert sum(attr["per_source_scheduled"].values()) == out.attempted_pairs, attr

    def test_BUDGET_EXHAUSTION_is_a_named_stop(self, tmp_path, monkeypatch):
        """v14#4: `stop` stayed None, which the dataclass defines as "the whole eligible set ran"."""
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 20.0
                return super().__call__(target, bucket, words)

        out, _tool = _run(tmp_path, tool=_Slow(), budget_s=10)
        assert out.stop_kind == "budget" and "budget exhausted" in (out.stop or ""), out.stop
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert sel["kind"] == "cap", sel          # a budget is still a CAP we chose
        assert "budget exhausted" in sel["reason"], sel

    def test_a_COMPLETE_sweep_has_no_stop_at_all(self, tmp_path):
        out, _tool = _run(tmp_path)
        assert out.stop is None and out.stop_kind is None

    def test_DUPLICATE_input_is_ONE_submission(self, tmp_path):
        """v14#5: `['alpha', 'alpha']` produced eligible=2 and submitted the word twice."""
        out, tool = _run(tmp_path, targets=("acme.com", "acme.com"), words=["alpha", "alpha", "beta"])
        assert out.eligible_pairs == 2, out.eligible_pairs
        submitted = [w for c in tool.calls for w in c[2]]
        assert sorted(submitted) == ["alpha", "beta"], submitted
        assert len({c[0] for c in tool.calls}) == 1, tool.calls


class TestReviewV15:
    """First-cause and reporting contracts the v15 review reproduced against cd1882f."""

    def test_a_MACHINERY_stop_is_not_relabelled_as_a_budget_cap(self, tmp_path, monkeypatch):
        """An invocation that crosses the bound AND raises was reported as an operator cap — a failure
        laundered into a choice."""
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _SlowBoom(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 20.0                       # past the 10s bound
                raise RuntimeError("popen exploded")

        out, _t = _run(tmp_path, tool=_SlowBoom(), budget_s=10)
        assert out.stop_kind == "machinery", out
        assert "popen exploded" in " ".join(out.machinery)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert sel["kind"] == "timeout" and "invocation raised" in sel["reason"], sel

    def test_an_UNPUBLISHED_completion_reaches_the_reported_facts(self, tmp_path, monkeypatch):
        """v15#2: a counter no emitted fact consumes is still silent loss."""
        real = budget.RotationProgress.save
        calls = {"n": 0}

        def last_completion_fails(self):
            calls["n"] += 1
            return False if calls["n"] == 2 else real(self)      # the ONLY completion save fails

        monkeypatch.setattr(budget.RotationProgress, "save", last_completion_fails)
        out, tool = _run(tmp_path, words=["only-one"])
        assert len(tool.calls) == 1 and out.completion_unpersisted == 1
        assert any("may be selected again" in m for m in out.machinery), out.machinery

    def test_ATTRIBUTION_carries_the_stop_it_actually_had(self, tmp_path):
        """v15#3: it is metadata on the same selection, not a second denominator with an invented kind."""
        out, _t = _run(tmp_path, dependency_ok=lambda: False, attribution=lambda w: "js")
        evs = _events(tmp_path)
        assert not [e for e in evs if e.get("measure") == "vocabulary_attribution"], "a third denominator"
        sel = [e for e in evs if e.get("measure") == "candidate_pairs"][-1]
        assert sel["kind"] == "timeout" and "not installed" in sel["reason"], sel
        ev = [e for e in evs if e.get("unit") == "attribution"][-1]
        assert ev.get("produced") is None, ev
        assert ev["selection_attribution"]["eligible"] == 20, ev
        assert ev["selection_attribution"]["scheduled"] == 0, ev

    def test_the_two_ATTEMPTED_totals_agree_even_on_the_invariant_path(self, tmp_path, monkeypatch):
        """v15#4: `attempted_pairs` counted on return, the per-source split only after publication — so a
        `SchedulerInvariant` between them left the two disagreeing."""
        def boom(self, *a, **k):
            raise budget.SchedulerInvariant("moved under the holder")

        monkeypatch.setattr(budget.RotationProgress, "complete", boom)
        out, tool = _run(tmp_path, attribution=lambda w: "js")
        assert out.stop_kind == "machinery" and out.slots_attempted == 1
        assert sum(out.per_source_attempted.values()) == out.attempted_pairs, out

    def test_attribution_NEVER_touches_the_reserved_produced_namespace(self, tmp_path):
        """v16#1: `produced` is real parser/store entity counts, and a status view folds it as such — a
        two-word sweep reporting `produced={'eligible': 2, 'scheduled': 2}` presents selection counters as
        output this lane created."""
        out, _t = _run(tmp_path, words=["alpha", "beta"], attribution=lambda w: "js")
        ev = [e for e in _events(tmp_path) if e.get("unit") == "attribution"][-1]
        assert ev.get("produced") is None, ev
        assert ev["selection_attribution"] == {"eligible": 2, "scheduled": 2,
                                               "per_source_eligible": {"js": 2},
                                               "per_source_scheduled": {"js": 2}}, ev


class TestTheAdaptiveSlotSpace:
    """Schema 2 (timing pass, finding 2): a slot bigger than the per-target bound was never selectable, so
    those pairs stayed unreachable FOREVER — 87% of them at 525,000 words, with every later lifecycle
    re-running the same reachable minority."""

    def test_the_SCHEMA_records_that_the_slot_space_changed_meaning(self):
        assert sweep.SCHEMA == 2

    def test_DEPTH_ZERO_is_the_historical_bucket_byte_for_byte(self):
        for word in ("api", "internal", "portal", "w000000xq"):
            assert sweep.slot_of(word, 0) == sweep.bucket_of(word)

    def test_the_slot_ids_are_PINNED(self):
        """The same fixtures the cost model asserts. A flipped bit order or a different digest slice would
        silently re-partition every lane's vocabulary."""
        assert [sweep.slot_of("api", d) for d in (0, 1, 2)] == ["158", "158.1", "158.10"]
        assert [sweep.slot_of("internal", d) for d in (0, 1, 2)] == ["179", "179.1", "179.10"]
        assert [sweep.slot_of("portal", d) for d in (0, 1, 2)] == ["001", "001.1", "001.11"]
        assert [sweep.slot_of("w000000xq", d) for d in (0, 1, 2)] == ["177", "177.0", "177.00"]

    def test_a_DEEPER_slot_is_CONTAINED_in_the_shallower_one(self):
        for word in ("api", "internal", "w000000xq"):
            deep = sweep.slot_of(word, 3)
            assert budget.RotationProgress._contains(sweep.slot_of(word, 2), deep)
            assert budget.RotationProgress._contains(sweep.slot_of(word, 0), deep)

    def test_every_ALLOCATED_slot_fits_the_cap_and_nothing_is_lost(self):
        vocab = [f"w{i:07d}" for i in range(30000)]
        alloc = sweep.allocate(vocab, cap=50)
        assert max(len(v) for v in alloc.values()) <= 50
        assert sorted(w for group in alloc.values() for w in group) == sorted(vocab)
        assert all(sweep.slot_id_ok(s) for s in alloc)

    def test_an_UNBOUNDED_lane_keeps_the_flat_roots(self):
        vocab = [f"w{i:05d}" for i in range(2000)]
        assert sweep.allocate(vocab, cap=0) == sweep.allocate(vocab, cap=-1)
        assert all("." not in s for s in sweep.allocate(vocab, cap=0))

    def test_allocation_is_DETERMINISTIC_and_never_moves_a_word_sideways(self):
        vocab = [f"w{i:05d}" for i in range(4000)]
        first = sweep.allocate(vocab, cap=25)
        backwards = sweep.allocate(list(reversed(vocab)), cap=25)
        assert {s: sorted(g) for s, g in first.items()} == {s: sorted(g) for s, g in backwards.items()}
        # a word's slot at the depth it landed on is the same id `slot_of` computes
        for slot, group in first.items():
            depth = len(slot.split(".")[1]) if "." in slot else 0
            assert all(sweep.slot_of(w, depth) == slot for w in group)

    def test_an_EMPTY_child_is_never_a_slot(self):
        alloc = sweep.allocate(["x25", "x38"], cap=1)      # both share the root AND the next bit
        assert len(alloc) == 2 and sorted(w for g in alloc.values() for w in g) == ["x25", "x38"]
        assert all(len(g) == 1 for g in alloc.values()), alloc
        assert len({len(s.split(".")[1]) for s in alloc}) == 1, "both children sit at the same depth"

    def test_a_corpus_that_used_to_STARVE_now_advances_every_lifecycle(self, tmp_path):
        """Reproduction of the measured defect: 30,000 words, bound 50, smallest root 92 members. Before
        schema 2 this submitted ZERO, run after run, while reporting the ordinary cap sentence."""
        vocab = [f"w{i:07d}" for i in range(30000)]
        seen, spent, invocations = set(), 0, 0
        for _ in range(4):
            out, tool = _run(tmp_path, words=vocab, max_pairs_per_target=50,
                             tool=_Tool(max_calls=40))
            assert out.attempted_pairs > 0, out.stop
            assert out.attempted_pairs <= 50, "the per-target bound still holds"
            seen |= {b for _t, b, _w in tool.calls}
            invocations += len(tool.calls)
            spent += out.attempted_pairs
        assert len(seen) == invocations >= 6, (seen, invocations)   # never the same slot twice
        assert spent >= 180

    def test_the_bound_is_still_never_EXCEEDED(self, tmp_path):
        vocab = [f"w{i:07d}" for i in range(5000)]
        out, tool = _run(tmp_path, words=vocab, max_pairs_per_target=100, tool=_Tool(max_calls=40))
        assert sum(len(w) for _t, _b, w in tool.calls) <= 100
        assert out.attempted_pairs <= 100


class TestTheSlotGrammarGuard:
    """v25: rank inheritance walks ids structurally, so a document holding arbitrary dotted strings could
    make unrelated slots each other's ancestors."""

    def test_a_FOREIGN_id_is_dropped_from_the_rotation_and_SAID_so(self, tmp_path):
        (tmp_path / f"{LANE}.json").write_text(json.dumps({
            "lane": LANE, "schema": sweep.SCHEMA, "gen": 4,
            "targets": {"acme.com": {"seq": 4, "slots": {
                "158": {"res": {"gen": 1, "at": 1.0}},
                "158.2": {"res": {"gen": 2, "at": 2.0}},          # 2 is not a bit
                "abc.01": {"res": {"gen": 3, "at": 3.0}},         # not a root
                "158.": {"res": {"gen": 4, "at": 4.0}},           # no bits at all
            }}}}))
        p = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                    slot_grammar=sweep.slot_id_ok)
        assert list(p.targets["acme.com"]["slots"]) == ["158"]
        assert p.state_status == "degraded" and "dropped" in p.state_reason

    def test_a_MUTATION_under_a_foreign_id_is_refused(self, tmp_path):
        p = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                    slot_grammar=sweep.slot_id_ok)
        for bad in ("158.2", "abc", "158.", "158.0.1", "1580", "158.” "):
            with pytest.raises(ValueError):
                p.reserve("acme.com", bad, at=1.0)
        assert p.reserve("acme.com", "158.01", at=1.0) == 1

    def test_a_lane_with_NO_grammar_is_unconstrained(self, tmp_path):
        p = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA)
        assert p.reserve("acme.com", "anything-at-all", at=1.0) == 1

    def test_the_grammar_bounds_the_DEPTH(self):
        assert sweep.slot_id_ok("158." + "0" * sweep.EXT_BITS)
        assert not sweep.slot_id_ok("158." + "0" * (sweep.EXT_BITS + 1))
