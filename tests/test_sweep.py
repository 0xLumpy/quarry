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
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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

    def test_the_STALEST_slot_goes_first_within_a_target(self, tmp_path, monkeypatch):
        """Clean slots are ordered by when they were last SELECTED, not by bucket name."""
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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

    def test_a_SKIPPED_result_stops_the_lane(self, tmp_path, monkeypatch):
        """v7#2: reserving every remaining slot against a tool that vanished burns the whole rotation."""
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        tool = _Tool(statuses=[Status.SUCCESS, Status.SKIPPED, Status.SUCCESS])
        out, _t = _run(tmp_path, tool=tool)
        assert len(tool.calls) == 2 and out.stop == "the tool did not run"
        assert out.slots_attempted == 1                                # SKIPPED never enters the denominator

    def test_a_RAISING_invocation_keeps_what_was_already_earned(self, tmp_path, monkeypatch):
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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

        monkeypatch.setattr(budget.RotationProgress, "reserve_batch", boom)
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

    def test_SELECTION_and_OUTCOME_are_separate_denominators(self, tmp_path, monkeypatch):
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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

    def test_a_completion_RESCUED_by_a_later_save_is_counted_as_published(self, tmp_path, monkeypatch):
        """The `done` tuple stays in the in-memory map, so the next successful save carries it to disk.
        Reporting it as unpersisted while the disk holds it is the counters lying about the state."""
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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

    def test_PARTIAL_progress_is_not_reported_as_a_full_restart(self, tmp_path, monkeypatch):
        """v14#2: a reservation failure after real progress used to claim the lane RESTARTS."""
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
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
        # v31: this case is about PER-SLOT behaviour, so it drives the driver one slot per
        # invocation. Batching is exercised by `TestExecutorBatching`.
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        def boom(self, *a, **k):
            raise budget.SchedulerInvariant("moved under the holder")

        monkeypatch.setattr(budget.RotationProgress, "complete_batch", boom)
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
        assert all("." not in s for s in sweep.allocate(vocab, cap=0))

    def test_the_BOUND_must_be_an_exact_non_negative_int(self, tmp_path):
        """v26#4: `-1` meant "unbounded" to the allocator and "a bound nothing satisfies" to the driver,
        and `True` silently became a bound of one."""
        for bad in (-1, True, 1.0, "50", None):
            with pytest.raises(ValueError):
                sweep.allocate(["a", "b"], cap=bad)
        out, tool = _run(tmp_path, max_pairs_per_target=-1)
        assert tool.calls == [] and out.stop_kind == "machinery" and "non-negative" in out.stop
        out, tool = _run(tmp_path, max_pairs_per_target=True)
        assert tool.calls == [] and out.stop_kind == "machinery"

    def test_an_INVALID_bound_still_reports_the_REAL_denominator_under_the_REGISTERED_source(
            self, tmp_path):
        """v27: the machinery stop was filed under the scheduler's private lane name, with `0/0` — a lane
        that had four unsubmitted candidate-target pairs reporting no omission at all."""
        out, tool = _run(tmp_path, targets=("acme.com", "acme.net"), words=["api", "internal"],
                         max_pairs_per_target=-1)
        assert tool.calls == [] and out.eligible_pairs == 4 and out.attempted_pairs == 0
        cov = [e for e in _events(tmp_path) if str(e.get("event", "")).startswith("coverage")]
        assert cov and {e["source_id"] for e in cov} == {COV}, cov
        sel = [e for e in cov if e.get("measure") == "candidate_pairs"]
        assert sel and sel[0]["eligible"] == 4 and sel[0]["omitted"] == 4, sel

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
        seen, spent, invocations, slots = set(), 0, 0, 0
        for _ in range(4):
            out, tool = _run(tmp_path, words=vocab, max_pairs_per_target=50,
                             tool=_Tool(max_calls=40))
            assert out.attempted_pairs > 0, out.stop
            assert out.attempted_pairs <= 50, "the per-target bound still holds"
            seen |= {u for _t, u, _w in tool.calls}
            invocations += len(tool.calls)
            slots += out.slots_attempted
            spent += out.attempted_pairs
        assert len(seen) == invocations == 4, (seen, invocations)   # one batched call a lifecycle
        assert slots >= 7, slots                                    # never the same slot twice
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

    def test_a_PARTITION_that_loses_a_candidate_is_a_machinery_stop(self, tmp_path, monkeypatch):
        """v28: the denominator made the loss visible, but it was classed as a resumable remainder — a
        pair in no slot is in no rotation, so nothing can resume it."""
        real = sweep.allocate
        monkeypatch.setattr(sweep, "allocate",
                            lambda words, *, cap: real(list(words)[:-1], cap=cap))
        out, tool = _run(tmp_path, words=["api", "internal"], max_pairs_per_target=10)
        assert tool.calls == [] and out.stop_kind == "machinery" and "does not cover" in out.stop
        assert out.eligible_pairs == 2 and out.attempted_pairs == 0
        sel = [e for e in _events(tmp_path)
               if str(e.get("event", "")).startswith("coverage") and e.get("measure") == "candidate_pairs"]
        assert sel and sel[0]["source_id"] == COV and sel[0]["omitted"] == 2, sel

    def test_a_PARTITION_that_SUBMITS_a_candidate_TWICE_is_caught_too(self, tmp_path, monkeypatch):
        """Membership alone is not enough either: a partition covering every word but placing one of them
        in two slots would submit that pair twice and inflate the attempted count."""
        def twice(words, *, cap):
            kept = list(words)
            return {"000": kept, "001": kept[:1]}
        monkeypatch.setattr(sweep, "allocate", twice)
        out, tool = _run(tmp_path, words=["api", "internal"], max_pairs_per_target=10)
        assert tool.calls == [] and out.stop_kind == "machinery" and "does not cover" in out.stop
        assert "3 placed, 2 distinct, of 2" in out.stop

    def test_the_grammar_rejects_a_ROOT_outside_the_space_and_a_trailing_newline(self):
        """v26#2: `$` matches before a final newline, and three digits are not automatically a bucket."""
        assert sweep.slot_id_ok("255") and not sweep.slot_id_ok("256")
        assert not sweep.slot_id_ok("999")
        assert not sweep.slot_id_ok("158.0\n")
        assert not sweep.slot_id_ok("158\n")
        assert sweep.slot_id_ok("099", buckets=100) and not sweep.slot_id_ok("100", buckets=100)

    def test_a_FOREIGN_id_cannot_return_through_the_MERGE(self, tmp_path):
        """v26#1: the id was dropped on load and then republished by `save()`, to disk AND to live state,
        where it could rank again in the same sweep."""
        doc = {"lane": LANE, "schema": sweep.SCHEMA, "gen": 2,
               "targets": {"acme.com": {"seq": 2, "slots": {
                   "158.2": {"res": {"gen": 1, "at": 1.0}},
                   "158": {"res": {"gen": 2, "at": 2.0}}}}}}
        path = tmp_path / f"{LANE}.json"
        path.write_text(json.dumps(doc))
        p = budget.RotationProgress(path, lane=LANE, schema=sweep.SCHEMA, slot_grammar=sweep.slot_id_ok)
        assert list(p.targets["acme.com"]["slots"]) == ["158"]
        p.reserve("acme.com", "158.01", at=3.0)
        assert p.save()
        assert "158.2" not in json.loads(path.read_text())["targets"]["acme.com"]["slots"]
        assert "158.2" not in p.targets["acme.com"]["slots"]

    def test_a_RAISING_grammar_leaves_the_rotation_unusable_not_the_read(self, tmp_path):
        path = tmp_path / f"{LANE}.json"
        path.write_text(json.dumps({"lane": LANE, "schema": sweep.SCHEMA, "gen": 1,
                                    "targets": {"acme.com": {"seq": 1, "slots": {
                                        "158": {"res": {"gen": 1, "at": 1.0}}}}}}))
        def boom(_slot):
            raise RuntimeError("predicate exploded")
        p = budget.RotationProgress(path, lane=LANE, schema=sweep.SCHEMA, slot_grammar=boom)
        assert p.state_status == "unusable" and "grammar raised" in p.state_reason
        assert p.targets == {}

    def test_a_grammar_that_is_not_CALLABLE_is_refused(self, tmp_path):
        with pytest.raises(ValueError):
            budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                    slot_grammar="^[0-9]{3}$")

    def test_the_grammar_bounds_the_DEPTH(self):
        assert sweep.slot_id_ok("158." + "0" * sweep.EXT_BITS)
        assert not sweep.slot_id_ok("158." + "0" * (sweep.EXT_BITS + 1))


class TestExecutorBatching:
    """The pinned batch protocol (design v22#3). One invocation may carry several slots — measured: a
    puredns call costs ~1.04 s before it resolves anything, which the old one-slot-per-call driver paid
    once per slot (3.8x on the OTC corpus, 94x on a small one)."""

    def test_ONE_invocation_carries_the_whole_eligible_prefix(self, tmp_path):
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(20)])
        assert len(tool.calls) == 1 and out.invocations == 1
        assert out.slots_attempted == 20 and out.attempted_pairs == 20
        assert len(tool.calls[0][2]) == 20

    def test_a_batch_NEVER_crosses_a_TARGET(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=[f"w{i:03d}" for i in range(6)])
        assert len(tool.calls) == 2 and {c[0] for c in tool.calls} == {"a.com", "b.com"}
        assert out.invocations == 2 and out.slots_attempted == 12

    def test_a_batch_NEVER_crosses_a_TIER(self, tmp_path):
        words = [f"w{i:03d}" for i in range(4)]
        _run(tmp_path, words=words)                                    # everything clean now
        out, tool = _run(tmp_path, words=words + ["brand-new-word"])   # one DIRTY slot joins
        assert len(tool.calls) == 2, tool.calls
        assert tool.calls[0][2] == ("brand-new-word",), tool.calls[0]  # the dirty tier goes alone, first
        assert len(tool.calls[1][2]) == 4

    def test_the_batch_is_bounded_by_the_REMAINING_allowance(self, tmp_path):
        vocab = [f"w{i:07d}" for i in range(30000)]
        out, tool = _run(tmp_path, words=vocab, max_pairs_per_target=50, tool=_Tool(max_calls=10))
        assert len(tool.calls) == 1, tool.calls          # ONE call, several slots
        assert out.slots_attempted >= 2 and out.attempted_pairs <= 50
        assert len(tool.calls[0][2]) == out.attempted_pairs

    def test_the_INVOCATION_MAXIMUM_bounds_the_SLOT_not_just_the_batch(self, tmp_path, monkeypatch):
        """v32#1: applied only after a slot was chosen it was no maximum at all — a lone oversized slot
        walked straight past it. The allocator now splits against the smaller of the two bounds."""
        monkeypatch.setattr(sweep, "BUCKETS", 1)              # every word would land in ONE root slot
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"])
        assert out.attempted_pairs == 3 and out.slots_attempted == 3
        assert all(len(c[2]) <= 1 for c in tool.calls), tool.calls

    def test_the_SMALLER_of_the_two_bounds_shapes_the_slots(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "BUCKETS", 1)
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 100)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(8)], max_pairs_per_target=2)
        assert all(len(c[2]) <= 2 for c in tool.calls) and out.attempted_pairs == 2

    def _residual(self, monkeypatch, keep=3):
        """Force what a 64-bit collision class would do: a slot the allocator cannot split below the
        bound."""
        real = sweep.allocate
        monkeypatch.setattr(sweep, "allocate",
                            lambda words, *, cap: {"000": list(words)[:keep], **{
                                s: g for s, g in real(list(words)[keep:], cap=cap).items()
                                if s != "000"}})

    def test_an_UNSPLITTABLE_residual_is_never_submitted_and_never_called_RESUMABLE(self, tmp_path,
                                                                                    monkeypatch):
        """v33: it was appended to machinery and then reported as "budget exhausted … RESUMABLE" — but no
        later lifecycle can reach it, so neither "resumable" nor "restarts" is true."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        self._residual(monkeypatch)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)])
        assert all(len(c[2]) <= 2 for c in tool.calls), tool.calls
        assert out.unselectable_slots == 1 and out.unselectable_pairs == 3
        assert any("can never be scheduled" in m for m in out.machinery), out.machinery
        assert out.stop_kind is None, "nothing STOPPED the run — the work simply cannot be scheduled"
        assert out.attempted_pairs == 3 and out.eligible_pairs == 6
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "UNSCHEDULABLE" in sel["reason"] and "RESUMABLE" not in sel["reason"], sel
        assert "budget exhausted" not in sel["reason"], sel      # no clock fired
        assert sel["kind"] == "timeout", sel                     # a GAP, never a clean cap

    def test_the_REAL_stop_keeps_the_sentence_while_the_residual_keeps_its_count(self, tmp_path,
                                                                                 monkeypatch):
        """v34#1: `unselectable` used to be assigned as the stop, hiding a clock that really did fire."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        self._residual(monkeypatch)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)], budget_s=0,
                         max_pairs_per_target=1)
        assert out.stop_kind == "bound" and out.unselectable_pairs == 3
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "bound" in sel["reason"] and "UNSCHEDULABLE" in sel["reason"], sel
        assert sel["kind"] == "timeout", sel      # an operator cap that ALSO left unschedulable work

    def test_a_residual_under_a_SPEND_CAP_is_not_laundered_into_an_ordinary_bound(self, tmp_path,
                                                                                  monkeypatch):
        """The cap check used to run first, so the same residual read as a routine cap with no machinery
        note at all."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 100)
        self._residual(monkeypatch)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)], max_pairs_per_target=2)
        assert out.unselectable_slots == 1 and out.unselectable_pairs == 3
        assert any("can never be scheduled" in m for m in out.machinery), out.machinery
        assert all(len(c[2]) <= 2 for c in tool.calls), tool.calls

    def test_a_REAL_stop_still_wins_over_the_residual_sentence(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        self._residual(monkeypatch)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)],
                         tool=_Tool(raises=(1, RuntimeError("popen exploded"))))
        assert out.stop_kind == "machinery" and out.unselectable_pairs == 3
        assert any("can never be scheduled" in m for m in out.machinery), out.machinery

    def test_the_batch_policy_still_STOPS_a_batch_from_growing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)])
        assert len(tool.calls) == 3 and all(len(c[2]) == 2 for c in tool.calls), tool.calls

    def test_the_UNIT_id_keeps_a_lone_slot_s_own_name(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        out, tool = _run(tmp_path, words=["alpha"])
        assert tool.calls[0][1] == sweep.bucket_of("alpha")

    def test_a_BATCHED_unit_names_its_first_slot_and_its_size(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"])
        unit = tool.calls[0][1]
        assert unit.endswith("+2") and sweep.slot_id_ok(unit.split("+")[0]), unit

    def test_EVERY_reservation_is_persisted_BEFORE_contact(self, tmp_path, monkeypatch):
        monkeypatch.setattr(budget.RotationProgress, "save", lambda self: False)
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"])
        assert tool.calls == [] and out.reservations_persisted == 0
        assert out.stop == "machinery: the reservation could not be persisted"

    def test_a_RAISING_invocation_completes_NO_slot_of_its_batch(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"],
                         tool=_Tool(raises=(1, RuntimeError("popen exploded"))))
        assert out.reservations_persisted == 3 and out.slots_attempted == 0
        assert out.completions_published == 0 and out.stop_kind == "machinery"
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA)
        assert all("done" not in sl for t in reopened.targets.values() for sl in t["slots"].values())

    def test_a_SKIPPED_invocation_completes_NO_slot_of_its_batch(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"],
                         tool=_Tool(statuses=[Status.SKIPPED]))
        assert out.slots_attempted == 0 and out.invocations == 0
        assert out.stop == "the tool did not run" and out.stop_kind == "dependency"

    def test_ONE_status_applies_to_EVERY_slot_of_the_batch(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"],
                         tool=_Tool(statuses=[Status.FAILED]))
        assert out.slots_attempted == 3 and out.slots_obtained == 0
        assert out.classes == {"failed": 3}, out.classes
        assert out.invocations == 1 and out.invocations_obtained == 0

    def test_the_WHOLE_batch_is_completed_in_ONE_save(self, tmp_path, monkeypatch):
        saves = {"n": 0}
        real = budget.RotationProgress.save

        def flaky(self):
            saves["n"] += 1
            return real(self) if saves["n"] == 1 else False     # the reservation lands, the completion not

        monkeypatch.setattr(budget.RotationProgress, "save", flaky)
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"])
        assert len(tool.calls) == 1
        assert out.completion_unpersisted == 3, out          # the batch is pending WHOLE, never partly

    def test_INVOCATIONS_are_reported_as_their_own_measure(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=[f"w{i:03d}" for i in range(6)])
        cov = [e for e in _events(tmp_path) if e.get("measure") == "tool_invocations"]
        slots = [e for e in _events(tmp_path) if e.get("measure") == "slot_outcomes"]
        assert cov and cov[-1]["tested"] == 2 and cov[-1]["eligible"] == 2, cov
        assert slots and slots[-1]["tested"] == 12, slots     # never read off one another

    def test_a_lane_that_ran_NOTHING_reports_no_invocation_measure(self, tmp_path):
        _run(tmp_path, dependency_ok=lambda: False)
        assert [e for e in _events(tmp_path) if e.get("measure") == "tool_invocations"] == []

    def test_TARGET_FAIRNESS_survives_batching(self, tmp_path):
        """Clause 7: ranking is global and re-evaluated for every member, so the batch stops at the first
        slot of another target and the next batch is chosen globally again."""
        out, tool = _run(tmp_path, targets=("a.com", "b.com", "c.com"),
                         words=[f"w{i:03d}" for i in range(4)])
        assert [c[0] for c in tool.calls] == ["a.com", "b.com", "c.com"], tool.calls
        assert all(len(c[2]) == 4 for c in tool.calls)

    def test_INVOCATION_classes_are_counted_ONCE_per_call(self, tmp_path, monkeypatch):
        """v32#2: with batches of different sizes the slot-weighted map cannot say how many CALLS failed.
        Here a 4-slot batch times out and a 1-slot batch fails: slots say 4 and 1, calls say 1 and 1."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 4)
        tool = _Tool(statuses=[Status.TIMED_OUT, Status.FAILED])
        out, _t = _run(tmp_path, words=[f"w{i:03d}" for i in range(5)], tool=tool)
        assert out.classes == {"timed_out": 4, "failed": 1}, out.classes
        assert out.invocation_classes == {"timed_out": 1, "failed": 1}, out.invocation_classes
        inv = [e for e in _events(tmp_path) if e.get("measure") == "tool_invocations"][-1]
        assert "{'failed': 1, 'timed_out': 1}" in inv["reason"], inv        # calls, not slots
        assert (inv["eligible"], inv["tested"]) == (2, 0), inv

    def test_a_CLEAN_run_reports_no_invocation_classes(self, tmp_path):
        out, _t = _run(tmp_path, words=["alpha", "beta"])
        assert out.invocation_classes == {}
        inv = [e for e in _events(tmp_path) if e.get("measure") == "tool_invocations"][-1]
        assert "{" not in inv["reason"], inv        # no class map at all when every call was obtained

    def test_a_MIXED_remainder_names_both_parts(self, tmp_path, monkeypatch):
        """Some pairs wait for the next lifecycle, some never come back at all — one sentence, both."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 100)
        self._residual(monkeypatch)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)], max_pairs_per_target=1)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "RESUMABLE" in sel["reason"] and "UNSCHEDULABLE" in sel["reason"], sel
        assert sel["omitted"] == 5 and out.unselectable_pairs == 3, (sel, out)

    def test_a_BUDGET_that_really_fired_is_not_hidden_by_the_residual(self, tmp_path, monkeypatch):
        """The clock stop and the unschedulable count are different facts and both must survive."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        self._residual(monkeypatch)
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, unit, words):
                ticks["t"] += 20.0
                return super().__call__(target, unit, words)

        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)], budget_s=10, tool=_Slow())
        assert out.stop_kind == "budget" and out.unselectable_pairs == 3
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "budget exhausted" in sel["reason"], sel
        assert "RESUMABLE" in sel["reason"] and "UNSCHEDULABLE" in sel["reason"], sel
