"""The SWEEP DRIVER — `sweep.run_sweep` (step-4 design v10).

Every case here is one of the ten review rounds' conclusions, driven through the real driver and the real
`budget.RotationProgress`: only the tool invocation is a double.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import types

import pytest

from quarry_recon import budget, events, sweep
from quarry_recon.runner import RunResult, Status


def _tracer_lines(names):
    """A context manager factory that raises `KeyboardInterrupt` at the Nth traced line of `names`."""
    import contextlib
    import sys

    @contextlib.contextmanager
    def at(stop_at: int):
        seen = [0]

        def tracer(frame, event, arg):
            if frame.f_code.co_name not in names:
                return None
            if event == "line":
                seen[0] += 1
                if seen[0] == stop_at:
                    raise KeyboardInterrupt("cancelled mid-transition")
            return tracer

        sys.settrace(tracer)
        try:
            yield
        finally:
            sys.settrace(None)

    return at

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
        """v10#2: only failing to ENTER the lane lock is contention. v71#2: and a body-raised StateBusy
        is CONTAINED machinery — escaping broke the driver's raises-nothing-but-cancellation contract
        and took the accounting with it."""
        def boom(self, *a, **k):
            raise budget.StateBusy("something inside the sweep")

        monkeypatch.setattr(budget.RotationProgress, "reserve_batch", boom)
        out, tool = _run(tmp_path)
        assert out.contended is False, out              # NOT laundered into a contention gap
        assert out.stop_kind == "machinery" and tool.calls == []
        assert "StateBusy" in " ".join(out.machinery), out.machinery
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"]
        assert sel, "the accounting still reaches the log"

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
        # v73#2: and it is CONTAINED — escaping contradicted the driver's contract and threw away a
        # denominator the run already knew.
        out, tool = _run(tmp_path)
        assert out.contended is False and out.stop_kind == "machinery", out
        assert "rotation could not be acquired (OSError: read-only filesystem)" in " ".join(out.machinery)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (20, 0, 20), sel

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
        # v38: STRUCTURED, never a sentence in `machinery` a consumer has to recognise
        assert out.machinery == [], out.machinery
        assert out.unselectable == [{"target": "acme.com", "slot": "000", "members": 3, "bound": 2}]
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
        assert out.machinery == [] and out.unselectable[0]["members"] == 3, out
        assert all(len(c[2]) <= 2 for c in tool.calls), tool.calls

    def test_a_REAL_stop_still_wins_over_the_residual_sentence(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        self._residual(monkeypatch)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)],
                         tool=_Tool(raises=(1, RuntimeError("popen exploded"))))
        assert out.stop_kind == "machinery" and out.unselectable_pairs == 3
        # the ordinary machinery note is the RAISE; the refused slot is its own structured fact
        assert any("popen exploded" in m for m in out.machinery), out.machinery
        assert not any("scheduled" in m for m in out.machinery), out.machinery
        assert out.unselectable[0]["slot"] == "000", out.unselectable

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

    def test_ATTRIBUTION_counts_the_WHOLE_eligible_corpus(self, tmp_path, monkeypatch):
        """v35#1: eligible attribution was taken after unschedulable slots had been removed, so it
        disagreed with the selection record it describes."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        self._residual(monkeypatch)
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)], attribution=lambda w: "js")
        assert out.eligible_pairs == 6 and out.unselectable_pairs == 3
        assert sum(out.per_source_eligible.values()) == 6, out.per_source_eligible
        assert sum(out.per_source_attempted.values()) == out.attempted_pairs == 3
        ev = [e for e in _events(tmp_path) if e.get("unit") == "attribution"][-1]
        assert ev["selection_attribution"]["eligible"] == 6, ev
        assert ev["selection_attribution"]["scheduled"] == 3, ev

    def test_an_ENTIRELY_unschedulable_workload_blames_no_dependency(self, tmp_path, monkeypatch):
        """v35#2: with nothing schedulable, the dependency gate still reported "the tool is not
        installed" — for a tool no slot could ever have invoked."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        monkeypatch.setattr(sweep, "allocate", lambda words, *, cap: {"000": list(words)})
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"], dependency_ok=lambda: False)
        assert tool.calls == [] and out.stop_kind is None and out.unselectable_pairs == 3
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "not installed" not in sel["reason"] and "UNSCHEDULABLE" in sel["reason"], sel

    def test_an_ENTIRELY_unschedulable_workload_takes_no_rotation_lock(self, tmp_path, monkeypatch):
        """Contention is likewise not the reason: the lane never needed the state at all."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        monkeypatch.setattr(sweep, "allocate", lambda words, *, cap: {"000": list(words)})
        with budget.rotation_session(tmp_path, LANE, schema=sweep.SCHEMA):
            out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"])
        assert out.contended is False and out.stop_kind is None
        assert out.unselectable_pairs == 3 and tool.calls == []

    def test_the_DETAIL_bound_is_GLOBAL_not_per_target(self, tmp_path, monkeypatch):
        """v39#3: the slice sat inside the target loop, so two targets produced twice the allowance."""
        monkeypatch.setattr(sweep, "_UNSELECTABLE_DETAIL", 1)
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        monkeypatch.setattr(sweep, "allocate", lambda words, *, cap: {"000": list(words)})
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha", "beta", "gamma"])
        assert len(out.unselectable) == 1, out.unselectable
        assert out.unselectable_slots == 2 and out.unselectable_pairs == 6

    def test_the_UNSCHEDULABLE_detail_is_EMITTED_not_only_returned(self, tmp_path, monkeypatch):
        """v39#2: a field on a value that dies with the process is not detail an operator retains."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        monkeypatch.setattr(sweep, "allocate", lambda words, *, cap: {"000": list(words)})
        out, tool = _run(tmp_path, words=["alpha", "beta", "gamma"])
        ev = [e for e in _events(tmp_path) if e.get("unit") == "unschedulable"]
        assert len(ev) == 1, ev
        got = ev[0]["unschedulable"]
        assert got["slots"] == 1 and got["pairs"] == 3 and got["truncated"] is False, got
        assert got["detail"] == [{"target": "acme.com", "slot": "000", "members": 3, "bound": 2}], got
        assert ev[0].get("produced") is None, ev        # `produced` stays reserved for entity counts

    def test_a_TRUNCATED_detail_says_so(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "_UNSELECTABLE_DETAIL", 1)
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        monkeypatch.setattr(sweep, "allocate", lambda words, *, cap: {"000": list(words)[:3],
                                                                      "001": list(words)[3:]})
        out, tool = _run(tmp_path, words=[f"w{i:03d}" for i in range(6)])
        got = [e for e in _events(tmp_path) if e.get("unit") == "unschedulable"][0]["unschedulable"]
        assert got["slots"] == 2 and len(got["detail"]) == 1 and got["truncated"] is True, got

    def test_a_CLEAN_run_emits_no_unschedulable_record(self, tmp_path):
        _run(tmp_path, words=["alpha", "beta"])
        assert [e for e in _events(tmp_path) if e.get("unit") == "unschedulable"] == []


class TestThePerRunTargetAllowance:
    """A THROUGHPUT bound on how many targets one lifecycle contacts. It never decides WHICH: the
    rotation does, so every target is eventually covered — the difference between bounding throughput
    and capping membership, where a fixed "first N by name" cut contacts the same N for ever."""

    def test_ONE_run_contacts_at_most_the_allowance(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com", "b.com", "c.com", "d.com"),
                         words=["alpha", "beta"], max_targets_per_run=2)
        assert {c[0] for c in tool.calls} == {"a.com", "b.com"}, tool.calls
        assert out.targets_eligible == 4 and out.targets_admitted == 2
        assert out.targets_contacted == 2 and out.deferred_targets == 2
        # v59#1: a CAP we chose ends the run only when nothing else did
        assert out.stop_kind == "bound" and "allowance (2)" in out.stop

    def test_the_ROTATION_chooses_and_LATER_runs_continue(self, tmp_path):
        seen = set()
        for _ in range(2):
            out, tool = _run(tmp_path, targets=("a.com", "b.com", "c.com", "d.com"),
                             words=["alpha", "beta"], max_targets_per_run=2)
            seen |= {c[0] for c in tool.calls}
        assert seen == {"a.com", "b.com", "c.com", "d.com"}, seen   # membership is NOT capped

    def test_ZERO_is_unbounded(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com", "b.com", "c.com"), words=["alpha"],
                         max_targets_per_run=0)
        assert {c[0] for c in tool.calls} == {"a.com", "b.com", "c.com"}
        assert out.stop_kind is None and out.targets_admitted == out.targets_contacted == 3

    def test_the_allowance_is_an_exact_non_negative_int(self, tmp_path):
        for bad in (-1, True, 1.0, "2"):
            out, tool = _run(tmp_path, max_targets_per_run=bad)
            assert tool.calls == [] and out.stop_kind == "machinery", (bad, out)

    def test_the_REMAINDER_is_reported_as_a_CAP_not_a_failure(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha", "beta"],
                         max_targets_per_run=1)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert sel["kind"] == "cap", sel                     # a bound we chose, never a gap
        assert "allowance (1)" in sel["reason"] and "RESUMABLE" in sel["reason"], sel
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (4, 2, 2), sel

    def test_a_target_ALREADY_contacted_keeps_its_remaining_slots(self, tmp_path, monkeypatch):
        """The allowance counts TARGETS, not batches: once a target is in, its own spend bound governs."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha", "beta", "gamma"],
                         max_targets_per_run=1)
        assert {c[0] for c in tool.calls} == {"a.com"} and len(tool.calls) == 3, tool.calls
        assert out.attempted_pairs == 3 and out.targets_admitted == out.targets_contacted == 1

    def test_a_CLOCK_that_fired_is_not_blamed_on_the_allowance(self, tmp_path, monkeypatch):
        """v59#1: the allowance set a scalar stop while the run carried on, so a budget that really
        expired was reported as an allowance cap."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, unit, words):
                ticks["t"] += 4.0            # the clock fires only after the allowance has deferred
                return super().__call__(target, unit, words)

        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=[f"w{i:03d}" for i in range(5)],
                         max_targets_per_run=1, budget_s=10, tool=_Slow())
        assert out.stop_kind == "budget" and "budget exhausted" in out.stop, out
        assert out.deferred_targets == 1 and out.deferred_pairs == 5, out
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "budget exhausted" in sel["reason"], sel
        assert "also: the per-run target allowance (1) was reached" in sel["reason"], sel

    def test_BOTH_caps_are_named_when_both_applied(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=[f"w{i:03d}" for i in range(6)],
                         max_targets_per_run=1, max_pairs_per_target=3)
        assert out.stop_kind == "bound", out
        assert "candidate bound (3)" in out.stop and "allowance (1)" in out.stop, out.stop
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert sel["kind"] == "cap" and "candidate bound (3)" in sel["reason"], sel
        assert "allowance (1)" in sel["reason"], sel

    def test_ADMITTED_is_not_CONTACTED(self, tmp_path, monkeypatch):
        """v59#2: the counter advanced before the reservation was persisted and before the tool ran."""
        monkeypatch.setattr(budget.RotationProgress, "save", lambda self: False)
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha"], max_targets_per_run=1)
        assert tool.calls == [] and out.targets_contacted == 0, out
        assert out.targets_admitted == 1, out                 # the allowance DID admit it
        assert out.stop_kind == "machinery", out

    def test_an_INVALID_allowance_names_ITS_OWN_bound(self, tmp_path):
        """v59#3: both bounds shared one message, so an invalid allowance diagnosed the candidate cap —
        and the exit lost the target denominator it already knew."""
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha", "beta"],
                         max_targets_per_run=-1)
        assert tool.calls == [] and out.stop_kind == "machinery"
        assert "the per-run target allowance must be an exact non-negative int" in out.stop, out.stop
        assert out.targets_eligible == 2 and out.eligible_pairs == 4, out

    def test_the_DEFERRAL_is_reconciled_even_when_ranking_never_reached_it(self, tmp_path, monkeypatch):
        """v60#1: the disposition was counted only when ranking happened to REACH a disallowed target, so
        a clock firing right after the last admitted one left the allowance invisible."""
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, unit, words):
                ticks["t"] += 20.0
                return super().__call__(target, unit, words)

        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha"],
                         max_targets_per_run=1, budget_s=10, tool=_Slow())
        assert len(tool.calls) == 1 and out.targets_contacted == 1, tool.calls
        assert out.deferred_targets == 1 and out.deferred_pairs == 1, out
        # v61: the clock elapsed but took NOTHING — the only omitted pair is the allowance's
        assert out.stop_kind == "bound" and "allowance (1)" in out.stop, out
        assert "budget" not in out.stop, out.stop
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "the per-run target allowance (1) was reached" in sel["reason"], sel
        assert "budget exhausted" not in sel["reason"], sel

    def test_an_ELAPSED_clock_that_stopped_NOTHING_is_not_the_cause(self, tmp_path, monkeypatch):
        """v60#2: the last permitted call crossed the deadline, but every omitted pair had already been
        classified by the candidate bound — the clock took nothing."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, unit, words):
                ticks["t"] += 20.0
                return super().__call__(target, unit, words)

        out, tool = _run(tmp_path, words=["alpha", "beta"], max_pairs_per_target=1, budget_s=10,
                         tool=_Slow())
        assert out.attempted_pairs == 1 and out.stop_kind == "bound", out
        assert "candidate bound (1)" in out.stop and "budget" not in out.stop, out.stop
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "budget exhausted" not in sel["reason"], sel
        assert sel["kind"] == "cap" and "candidate bound (1)" in sel["reason"], sel


class TestTheAdmissionHook:
    """v64: work that is itself ACTIVE — a contact guard's live resolution — may not run for every
    eligible target before the allowance and the clock apply. The scheduler asks once, per admitted
    target, after the reservation is durable."""

    def test_the_HOOK_runs_after_the_reservation_is_persisted(self, tmp_path, monkeypatch):
        order = []
        real = budget.RotationProgress.save
        monkeypatch.setattr(budget.RotationProgress, "save",
                            lambda self: (order.append("save"), real(self))[1])
        out, tool = _run(tmp_path, words=["alpha"], admit=lambda t: order.append("admit") or True)
        assert order[:2] == ["save", "admit"], order        # reservation first, then anything active
        assert tool.calls and out.targets_refused == 0

    def test_it_is_asked_ONCE_per_target(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        asked = []
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha", "beta", "gamma"],
                         admit=lambda t: asked.append(t) or True)
        assert sorted(asked) == ["a.com", "b.com"], asked   # not once per batch
        assert len(tool.calls) > 2, tool.calls

    def test_a_REFUSAL_excludes_the_target_and_submits_nothing_for_it(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha", "beta", "gamma"],
                         admit=lambda t: t != "a.com")
        assert {c[0] for c in tool.calls} == {"b.com"}, tool.calls
        assert out.targets_refused == 1 and out.refused == ["a.com"]
        assert out.refused_pairs == 3 and out.attempted_pairs == 3
        assert out.targets_contacted == 1                    # a refusal is NOT a contact

    def test_a_REFUSAL_consumes_the_ALLOWANCE_and_never_backfills(self, tmp_path):
        """Clause 3: otherwise many refusals recreate exactly the traffic the allowance bounds."""
        out, tool = _run(tmp_path, targets=("a.com", "b.com", "c.com"), words=["alpha"],
                         max_targets_per_run=1, admit=lambda t: t != "a.com")
        assert tool.calls == [], tool.calls
        assert out.targets_admitted == 1 and out.targets_refused == 1

    def test_a_refused_target_moves_to_the_BACK_of_its_tier(self, tmp_path):
        """Clause 4: the reservation advanced its cursor, so a permanently refused target cannot
        monopolise the front of the rotation."""
        seen = []
        for _ in range(3):
            out, tool = _run(tmp_path, targets=("a.com", "b.com", "c.com"), words=["alpha"],
                             max_targets_per_run=1, admit=lambda t: t != "a.com")
            seen.append({c[0] for c in tool.calls})
        assert seen[0] == set() and seen[1] and seen[2], seen
        assert seen[1] | seen[2] == {"b.com", "c.com"}, seen

    def test_a_RAISING_hook_is_machinery_and_submits_nothing_further(self, tmp_path):
        def boom(target):
            raise OSError("resolver exploded")

        out, tool = _run(tmp_path, words=["alpha"], admit=boom)
        assert tool.calls == [] and out.stop_kind == "machinery"
        assert "admission check raised" in " ".join(out.machinery)

    def test_NO_hook_is_the_unchanged_path(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha", "beta"])
        assert tool.calls and out.targets_refused == 0 and out.refused == []

    @pytest.mark.parametrize("answer", ["private_blocked", 1, 0, None, ("self", True), [], object()])
    def test_only_TRUE_or_FALSE_is_an_admission_answer(self, tmp_path, answer):
        """v65#1: a SAFETY boundary ran on truthiness, so a callback returning a contact-state string
        authorised traffic."""
        out, tool = _run(tmp_path, words=["alpha"], admit=lambda _t: answer)
        assert tool.calls == [], (answer, tool.calls)
        assert out.stop_kind == "machinery" and "not True or False" in " ".join(out.machinery)
        assert out.targets_refused == 0, out

    def test_an_EXACT_False_is_still_a_refusal(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha"], admit=lambda _t: False)
        assert tool.calls == [] and out.targets_refused == 1 and out.stop_kind != "machinery"

    def test_the_REFUSAL_detail_is_EMITTED_not_only_returned(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=["alpha", "beta"],
                         admit=lambda t: t != "a.com")
        ev = [e for e in _events(tmp_path) if e.get("unit") == "admission"]
        assert len(ev) == 1, ev
        got = ev[0]["admission"]
        assert got == {"targets": 1, "pairs": 2, "detail": ["a.com"], "unpersisted": 0,
                       "unknown": 0, "truncated": False}, got
        assert ev[0].get("produced") is None, ev

    def test_a_run_with_NO_refusal_emits_no_admission_record(self, tmp_path):
        _run(tmp_path, words=["alpha"], admit=lambda _t: True)
        assert [e for e in _events(tmp_path) if e.get("unit") == "admission"] == []

    def test_a_TRUNCATED_refusal_list_says_so(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "_UNSELECTABLE_DETAIL", 1)
        out, tool = _run(tmp_path, targets=("a.com", "b.com", "c.com"), words=["alpha"],
                         admit=lambda t: t == "c.com")
        got = [e for e in _events(tmp_path) if e.get("unit") == "admission"][-1]["admission"]
        assert got["targets"] == 2 and len(got["detail"]) == 1 and got["truncated"] is True, got

    def test_an_UNREPRESENTABLE_answer_is_still_contained(self, tmp_path):
        """v66#1: rendering the returned value's repr outside the protected call let a raising
        `__repr__` escape the driver at the very boundary that exists to fail closed."""
        class Hostile:
            def __repr__(self):
                raise RuntimeError("repr exploded")

        out, tool = _run(tmp_path, words=["alpha"], admit=lambda _t: Hostile())
        assert tool.calls == [] and out.stop_kind == "machinery"
        assert "<unrepresentable>" in " ".join(out.machinery), out.machinery

    def test_a_CANCELLATION_still_flushes_the_refusals_before_it(self, tmp_path):
        """v66#2: cancellation propagated before the report, so refusals the lifecycle had already made
        left no record at all."""
        def admit(target):
            if target == "a.com":
                return False
            raise KeyboardInterrupt("ctrl-c")

        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, targets=("a.com", "b.com"), words=["alpha"], admit=admit)
        ev = [e for e in _events(tmp_path) if e.get("unit") == "admission"]
        assert len(ev) == 1 and ev[0]["admission"]["detail"] == ["a.com"], ev
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"]
        assert sel, "the selection record is flushed too"

    def test_a_REPORTING_failure_never_masks_the_cancellation(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "_report",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("event log gone")))

        def admit(_target):
            raise KeyboardInterrupt("ctrl-c")

        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha"], admit=admit)

    def test_a_CANCELLED_run_is_reported_as_cancelled_not_as_a_cap(self, tmp_path):
        """v67#1: the flush ran before any disposition was settled, so the record said "candidate budget
        exhausted after 0.0s of 0s" — a CAP — for a run a Ctrl-C ended."""
        def admit(_target):
            raise KeyboardInterrupt("ctrl-c")

        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha", "beta"], admit=admit)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert "CANCELLED mid-sweep" in sel["reason"], sel
        assert "budget exhausted" not in sel["reason"], sel
        assert sel["kind"] == "timeout", sel                  # a gap, never a cap we chose

    def test_a_HOSTILE_repr_raising_a_BaseException_is_contained(self, tmp_path):
        """v67#2: catching `Exception` alone let `GeneratorExit` through the fail-closed boundary."""
        class Hostile:
            def __repr__(self):
                raise GeneratorExit("not an Exception")

        out, tool = _run(tmp_path, words=["alpha"], admit=lambda _t: Hostile())
        assert tool.calls == [] and out.stop_kind == "machinery"
        assert "<unrepresentable>" in " ".join(out.machinery), out.machinery

    def test_CANCELLATION_from_a_repr_still_propagates(self, tmp_path):
        class Interrupting:
            def __repr__(self):
                raise KeyboardInterrupt("ctrl-c")

        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha"], admit=lambda _t: Interrupting())

    def test_a_REPORTING_BaseException_never_replaces_the_cancellation(self, tmp_path, monkeypatch):
        """v68#1: catching `Exception` alone let a reporting `GeneratorExit` become the exception that
        left the driver, in place of the Ctrl-C being handled."""
        monkeypatch.setattr(sweep, "_report",
                            lambda *a, **k: (_ for _ in ()).throw(GeneratorExit("log gone")))

        def admit(_target):
            raise KeyboardInterrupt("ctrl-c")

        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha"], admit=admit)

    def test_a_HOSTILE_TYPE_NAME_is_contained_too(self, tmp_path):
        """v68#2: `_safe_repr` protected the value, but `type(value).__name__` went through a metaclass
        that can raise just as easily."""
        class Meta(type):
            @property
            def __name__(cls):
                raise RuntimeError("name exploded")

        class Hostile(metaclass=Meta):
            def __repr__(self):
                return "<hostile>"

        out, tool = _run(tmp_path, words=["alpha"], admit=lambda _t: Hostile())
        assert tool.calls == [] and out.stop_kind == "machinery"
        assert "<unrepresentable> <hostile>" in " ".join(out.machinery), out.machinery

    def test_a_HOSTILE_exception_STR_is_contained(self, tmp_path):
        class Hostile(Exception):
            def __str__(self):
                raise RuntimeError("str exploded")

        def admit(_target):
            raise Hostile()

        out, tool = _run(tmp_path, words=["alpha"], admit=admit)
        assert tool.calls == [] and out.stop_kind == "machinery"
        assert "Hostile: <unrepresentable>" in " ".join(out.machinery), out.machinery


class TestPublicationIsSettledOnEveryExit:
    """v69: the tool result is counted BEFORE the completion is durable. A run that ends in between
    leaves the disk holding only the reservation — the slot will run again, and nothing said so."""

    def _cancel_on_save(self, monkeypatch, nth: int):
        real = budget.RotationProgress.save
        calls = {"n": 0}

        def save(self):
            calls["n"] += 1
            if calls["n"] == nth:
                raise KeyboardInterrupt("ctrl-c")
            return real(self)

        monkeypatch.setattr(budget.RotationProgress, "save", save)

    def test_a_CANCELLATION_mid_publication_says_the_slot_may_RUN_AGAIN(self, tmp_path, monkeypatch):
        self._cancel_on_save(monkeypatch, 2)          # 1 = the reservation, 2 = the completion
        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha"])
        ev = [e for e in _events(tmp_path) if e.get("unit") == "completion"]
        assert len(ev) == 1, ev
        assert ev[0]["completion"] == {"pending": 0, "unknown": 1, "unstaged": 0,
                                       "unpersisted": 1}, ev
        assert ev[0].get("produced") is None, ev
        # ...and the disk really does hold only the reservation
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        slots = [s for t in reopened.targets.values() for s in t["slots"].values()]
        assert slots and all("done" not in s for s in slots), slots

    def test_a_CANCELLATION_before_any_publication_reports_none(self, tmp_path, monkeypatch):
        self._cancel_on_save(monkeypatch, 1)          # dies on the RESERVATION save
        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha"])
        assert [e for e in _events(tmp_path) if e.get("unit") == "completion"] == []

    def test_an_ORDINARY_pending_completion_is_still_PENDING_not_unknown(self, tmp_path, monkeypatch):
        saves = {"n": 0}
        real = budget.RotationProgress.save

        def flaky(self):
            saves["n"] += 1
            return real(self) if saves["n"] == 1 else False

        monkeypatch.setattr(budget.RotationProgress, "save", flaky)
        out, tool = _run(tmp_path, words=["alpha", "beta"])
        assert out.completion_unknown == 0 and out.pending_completions == out.completion_unpersisted
        ev = [e for e in _events(tmp_path) if e.get("unit") == "completion"][-1]
        assert ev["completion"]["unknown"] == 0 and ev["completion"]["pending"] > 0, ev

    def test_a_CLEAN_run_emits_no_completion_record(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha"])
        assert out.completion_unpersisted == 0
        assert [e for e in _events(tmp_path) if e.get("unit") == "completion"] == []

    def test_a_RESOLVED_publication_is_not_still_in_flight(self, tmp_path, monkeypatch):
        """The flag has to be CLEARED once the save resolves: a cancellation in a later batch must not
        report an earlier, safely published completion as unknown."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)

        class _Cancel(_Tool):
            def __call__(self, target, unit, words):
                if self.calls:                      # the FIRST batch publishes cleanly
                    raise KeyboardInterrupt("ctrl-c")
                return super().__call__(target, unit, words)

        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha", "beta"], tool=_Cancel())
        assert [e for e in _events(tmp_path) if e.get("unit") == "completion"] == []

    def test_an_UNSTAGED_completion_is_never_rescued_as_published(self, tmp_path, monkeypatch):
        """v70: `complete_batch` and the save shared one branch, so a failure BEFORE any `done` tuple
        existed was called pending — and a later reservation save then `_rescue`d a completion that was
        never written, leaving the counters disagreeing with the disk."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        clock = {"n": 0}

        def now():
            clock["n"] += 1
            if clock["n"] == 2:                 # 1 = the reservation, 2 = the completion's reading
                raise OSError("clock exploded")
            return float(clock["n"])

        out, tool = _run(tmp_path, words=["alpha", "beta"], now=now)
        assert out.stop_kind == "machinery" and "not staged" in " ".join(out.machinery), out
        assert out.completions_published == 0 and out.pending_completions == 0, out
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        done = [s for t in reopened.targets.values() for s in t["slots"].values() if "done" in s]
        assert done == [], done                  # nothing completed on disk, and none claimed

    def test_a_PUBLICATION_failure_after_staging_is_still_PENDING(self, tmp_path, monkeypatch):
        """The other half of the split: the tuples EXIST, so a later save really can carry them."""
        saves = {"n": 0}
        real = budget.RotationProgress.save

        def flaky(self):
            saves["n"] += 1
            return real(self) if saves["n"] != 2 else False

        monkeypatch.setattr(budget.RotationProgress, "save", flaky)
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        out, tool = _run(tmp_path, words=["alpha", "beta"])
        assert out.stop_kind is None and out.completions_published >= 1, out
        assert out.completion_unpersisted == 0, out      # the later save carried it

    def test_a_CANCELLATION_before_STAGING_is_not_UNKNOWN(self, tmp_path, monkeypatch):
        clock = {"n": 0}

        def now():
            clock["n"] += 1
            if clock["n"] == 2:                 # cancelled at the completion's clock reading
                raise KeyboardInterrupt("ctrl-c")
            return float(clock["n"])

        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha"], now=now)
        ev = [e for e in _events(tmp_path) if e.get("unit") == "completion"][-1]["completion"]
        # v71#3: never STAGED is its own disposition — not pending, which implies a rescuable tuple
        assert ev == {"pending": 0, "unknown": 0, "unstaged": 1, "unpersisted": 1}, ev

    def test_a_CLOCK_that_fails_at_RESERVATION_is_machinery_not_an_escape(self, tmp_path):
        """v70: the reservation guarded only the scheduler's own refusals, so an `OSError` from the
        caller's `now()` escaped the driver instead of becoming a machinery stop."""
        def now():
            raise OSError("clock exploded")

        out, tool = _run(tmp_path, words=["alpha"], now=now)
        assert tool.calls == [] and out.stop_kind == "machinery", out
        assert "reservation refused (OSError: clock exploded)" in " ".join(out.machinery), out.machinery


class TestThePreflightCallbacksAreContained:
    """v71#1: `vocabulary`, `attribution` and `dependency_ok` are the CALLER's callables and ran outside
    every boundary — a failure left the driver by the back door, and the dependency gate authorised
    active work on truthiness."""

    @pytest.mark.parametrize("answer", ["missing", 1, 0, None, [], ("ok",)])
    def test_only_TRUE_or_FALSE_gates_the_dependency(self, tmp_path, answer):
        out, tool = _run(tmp_path, words=["alpha"], dependency_ok=lambda: answer)
        assert tool.calls == [], (answer, tool.calls)
        assert out.stop_kind == "machinery" and "not True or False" in " ".join(out.machinery)

    def test_an_EXACT_False_is_still_the_dependency_stop(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha"], dependency_ok=lambda: False)
        assert tool.calls == [] and out.stop_kind == "dependency"
        assert out.stop == "the tool is not installed"

    def test_a_RAISING_dependency_check_is_machinery(self, tmp_path):
        def boom():
            raise OSError("which() exploded")

        out, tool = _run(tmp_path, words=["alpha"], dependency_ok=boom)
        assert tool.calls == [] and out.stop_kind == "machinery"
        assert "dependency check raised (OSError: which() exploded)" in " ".join(out.machinery)

    def test_a_RAISING_vocabulary_leaves_eligibility_UNKNOWN(self, tmp_path):
        out = sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=["acme.com"],
                              vocabulary=lambda t: (_ for _ in ()).throw(OSError("corpus gone")),
                              execute=_Tool(), budget_s=0, coverage_lane=COV)
        assert out.stop_kind == "machinery" and out.eligibility_known is False
        assert "corpus could not be built (OSError: corpus gone)" in " ".join(out.machinery)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert sel["kind"] == "unknown" and sel.get("eligible") is None, sel
        assert "no candidate denominator exists" in sel["reason"], sel

    def test_a_RAISING_attribution_is_machinery_with_a_KNOWN_denominator(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha", "beta"],
                         attribution=lambda w: (_ for _ in ()).throw(OSError("owner lookup gone")))
        assert tool.calls == [] and out.stop_kind == "machinery"
        assert "attribution failed (OSError: owner lookup gone)" in " ".join(out.machinery)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert (sel["eligible"], sel["tested"], sel["omitted"]) == (2, 0, 2), sel

    def test_a_HOSTILE_dependency_answer_is_rendered_safely(self, tmp_path):
        class Hostile:
            def __repr__(self):
                raise RuntimeError("repr exploded")

        out, tool = _run(tmp_path, words=["alpha"], dependency_ok=lambda: Hostile())
        assert tool.calls == [] and "<unrepresentable>" in " ".join(out.machinery), out.machinery

    @pytest.mark.parametrize("boom", [budget.StateBusy("held elsewhere"), OSError("disk gone")])
    def test_a_RESERVATION_SAVE_failure_is_contained(self, tmp_path, monkeypatch, boom):
        """v72#1: the save sat outside the reservation's boundary, so a body-raised StateBusy or OSError
        escaped the driver with no accounting at all."""
        def save(self):
            raise boom

        monkeypatch.setattr(budget.RotationProgress, "save", save)
        out, tool = _run(tmp_path, words=["alpha"])
        assert tool.calls == [] and out.stop_kind == "machinery", out
        assert out.contended is False and "reservation refused" in " ".join(out.machinery)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"]
        assert sel, "the accounting still reaches the log"

    def test_a_PARTIAL_attribution_publishes_NOTHING(self, tmp_path):
        """v72#2: a failure on the second word left a one-entry map presented as the complete attribution
        of a two-pair corpus."""
        seen = {"n": 0}

        def attribution(word):
            seen["n"] += 1
            if seen["n"] > 1:
                raise OSError("owner lookup gone")
            return "js"

        out, tool = _run(tmp_path, words=["alpha", "beta"], attribution=attribution)
        assert out.stop_kind == "machinery" and out.per_source_eligible == {}, out
        assert [e for e in _events(tmp_path) if e.get("unit") == "attribution"] == []

    def test_an_ORDINARY_unstaged_failure_is_COUNTED(self, tmp_path, monkeypatch):
        """v72#3: `inflight` was cleared and the batch forgotten, so the result claimed nothing was
        unpersisted even though the tool ran and only the reservation exists."""
        def boom(self, *a, **k):
            raise OSError("staging gone")

        monkeypatch.setattr(budget.RotationProgress, "complete_batch", boom)
        out, tool = _run(tmp_path, words=["alpha"])
        assert tool.calls and out.stop_kind == "machinery", out
        assert out.completion_unstaged == 1 and out.completion_unpersisted == 1, out
        ev = [e for e in _events(tmp_path) if e.get("unit") == "completion"][-1]["completion"]
        assert ev["unstaged"] == 1 and ev["pending"] == 0, ev

    @pytest.mark.parametrize("where", ["vocabulary", "attribution", "dependency", "admit", "execute",
                                       "clock"])
    def test_a_GENERATOR_EXIT_from_any_callback_is_contained(self, tmp_path, where):
        """v73#1: only `KeyboardInterrupt` and `SystemExit` are cancellation. Every other
        `BaseException` from a caller's callable is machinery, not an escape."""
        def boom(*_a, **_k):
            raise GeneratorExit("not cancellation")

        kw = {}
        if where == "vocabulary":
            out = sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=["acme.com"],
                                  vocabulary=boom, execute=_Tool(), budget_s=0, coverage_lane=COV)
            assert out.stop_kind == "machinery" and out.eligibility_known is False
            return
        if where == "attribution":
            kw["attribution"] = boom
        elif where == "dependency":
            kw["dependency_ok"] = boom
        elif where == "admit":
            kw["admit"] = boom
        elif where == "clock":
            kw["now"] = boom
        tool = boom if where == "execute" else None
        out, _t = _run(tmp_path, words=["alpha"], tool=tool, **kw)
        assert out.stop_kind == "machinery", (where, out)
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"]
        assert sel, where

    def test_a_GENERATOR_EXIT_from_the_ACQUISITION_is_contained(self, tmp_path, monkeypatch):
        import contextlib as _c

        @_c.contextmanager
        def broken(*a, **k):
            raise GeneratorExit("not cancellation")
            yield  # pragma: no cover

        monkeypatch.setattr(budget, "rotation_session", broken)
        out, tool = _run(tmp_path, words=["alpha"])
        assert out.stop_kind == "machinery" and out.contended is False, out
        assert "rotation could not be acquired" in " ".join(out.machinery), out.machinery

    def test_a_GENERATOR_EXIT_from_STAGING_is_contained(self, tmp_path, monkeypatch):
        def boom(self, *a, **k):
            raise GeneratorExit("not cancellation")

        monkeypatch.setattr(budget.RotationProgress, "complete_batch", boom)
        out, tool = _run(tmp_path, words=["alpha"])
        assert tool.calls and out.stop_kind == "machinery", out
        assert out.completion_unstaged == 1, out

    @pytest.mark.parametrize("boom", [OSError("event log gone"), GeneratorExit("not cancellation")])
    def test_a_REPORTING_failure_on_the_NORMAL_path_is_contained(self, tmp_path, monkeypatch, boom):
        """v74#1: every ordinary and early-return report call sat outside the containment, so an event
        sink that failed escaped a driver promising to raise nothing but cancellation."""
        monkeypatch.setattr(sweep, "_report", lambda *a, **k: (_ for _ in ()).throw(boom))
        out, tool = _run(tmp_path, words=["alpha"])
        assert tool.calls, "the work still happened"
        assert out.stop_kind == "machinery", out
        assert "coverage could not be reported" in " ".join(out.machinery), out.machinery

    def test_a_REPORTING_failure_on_an_EARLY_return_is_contained(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "_report",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("event log gone")))
        out, tool = _run(tmp_path, words=["alpha"], dependency_ok=lambda: False)
        assert tool.calls == [] and "coverage could not be reported" in " ".join(out.machinery)
        assert out.stop_kind == "dependency", out      # the FIRST cause keeps the stop

    def test_a_REPORTING_CANCELLATION_never_replaces_the_original(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "_report",
                            lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt("from the sink")))

        class _Cancel(_Tool):
            def __call__(self, target, unit, words):
                raise SystemExit("the original")

        with pytest.raises(SystemExit, match="the original"):
            _run(tmp_path, words=["alpha"], tool=_Cancel())

    @pytest.mark.parametrize("word", [1, None, b"alpha", True, "", ("alpha",)])
    def test_a_NON_STRING_candidate_is_refused_inside_the_boundary(self, tmp_path, word):
        """v75#1: containing the CALL is not enough — a hashable non-string candidate survived corpus
        building and then crashed the allocator outside every boundary."""
        out = sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=["acme.com"],
                              vocabulary=lambda t: ["alpha", word], execute=_Tool(), budget_s=0,
                              coverage_lane=COV)
        assert out.stop_kind == "machinery" and out.eligibility_known is False, (word, out)
        assert "not a non-empty str" in " ".join(out.machinery), out.machinery
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert sel["kind"] == "unknown", sel

    @pytest.mark.parametrize("bad", [None, "success", object(),
                                     types.SimpleNamespace(status="success"),   # duck-typed status
                                     types.SimpleNamespace(status=None)])
    def test_an_INVOCATION_that_returns_nothing_usable_is_contained(self, tmp_path, bad):
        """v75#1: the call was guarded, its RESULT was not — `result.status` escaped after active work
        had already happened, leaving only a reservation and no coverage."""
        out, _t = _run(tmp_path, words=["alpha"], tool=lambda *a: bad)
        assert out.stop_kind == "machinery", (bad, out)
        assert "no usable status" in " ".join(out.machinery), out.machinery
        # v76#1: the call RETURNED, so the payload went out — the accounting says so, and the
        # completion nobody staged is counted
        assert out.reservations_persisted == 1 and out.slots_attempted == 1, out
        assert out.attempted_pairs == 1 and out.invocations == 1, out
        assert out.classes == {"invalid_result": 1} and out.completion_unstaged == 1, out
        sel = [e for e in _events(tmp_path) if e.get("measure") == "candidate_pairs"][-1]
        assert (sel["eligible"], sel["tested"]) == (1, 1), sel

    def test_a_VALID_RunResult_is_still_accepted(self, tmp_path):
        out, tool = _run(tmp_path, words=["alpha"])
        assert out.stop_kind is None and out.slots_attempted == 1 and tool.calls

    def test_a_STATEFUL_status_property_is_read_only_ONCE(self, tmp_path):
        """v76#2: the guard validated one read and the loop re-read it, so a property could pass and then
        raise on its second access, escaping the driver."""
        class Once:
            def __init__(self):
                self.n = 0

            @property
            def status(self):
                self.n += 1
                if self.n > 1:
                    raise GeneratorExit("second read explodes")
                return Status.SUCCESS

        out, _t = _run(tmp_path, words=["alpha"], tool=lambda *a: Once())
        assert out.stop_kind is None and out.slots_attempted == 1, out
        assert out.slots_obtained == 1, out

    def test_a_BARE_STRING_vocabulary_is_not_four_candidates(self, tmp_path):
        """v76#3: `"alpha"` is iterable — it became a, l, p, h and was actively submitted."""
        out = sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=["acme.com"],
                              vocabulary=lambda t: "alpha", execute=_Tool(), budget_s=0,
                              coverage_lane=COV)
        assert out.stop_kind == "machinery" and out.eligibility_known is False, out
        assert "not a collection of words" in " ".join(out.machinery), out.machinery

    def test_a_STR_SUBCLASS_is_not_an_exact_string(self, tmp_path):
        """A subclass can override `encode` and escape from the allocator."""
        class Hostile(str):
            def encode(self, *a, **k):
                raise GeneratorExit("encode explodes")

        out = sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=["acme.com"],
                              vocabulary=lambda t: ["alpha", Hostile("beta")], execute=_Tool(),
                              budget_s=0, coverage_lane=COV)
        assert out.stop_kind == "machinery" and "not a non-empty str" in " ".join(out.machinery)

    def test_a_REFUSED_target_stops_starving_DIRTY_work(self, tmp_path, monkeypatch):
        """v78: a refusal left the slot at tier 0, and tier dominates fairness globally — so a
        permanently refused target won every lifecycle while contactable dirty work waited for ever."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        seen = []

        def sweep_once(words_for_b):
            def vocab(target):
                return ["alpha"] if target == "a.com" else words_for_b

            tool = _Tool()
            out = sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=["a.com", "b.com"],
                                  vocabulary=vocab, execute=tool, budget_s=0, coverage_lane=COV,
                                  max_targets_per_run=1, admit=lambda t: t != "a.com")
            seen.append({c[0] for c in tool.calls})
            return out

        sweep_once(["beta"])                      # a.com refused; b.com runs next lifecycle
        sweep_once(["beta"])
        for _ in range(4):                        # b.com is DIRTY from here on
            sweep_once(["beta", "gamma"])
        assert seen[0] == set() and seen[1] == {"b.com"}, seen
        # the refused target does not starve the dirty one across the cooldown window...
        assert all(s == {"b.com"} for s in seen[2:]), seen

    def test_a_REFUSAL_never_claims_the_slot_RAN(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        slots = [s for t in reopened.targets.values() for s in t["slots"].values()]
        assert slots and all("done" not in s for s in slots), slots     # nothing completed
        assert reopened.targets["a.com"].get("adm"), reopened.targets
        assert reopened.tier("a.com", sweep.bucket_of("alpha"), "whatever") == 3

    def test_a_CRASH_before_admission_stays_NEVER_RUN(self, tmp_path):
        def boom(_target):
            raise OSError("resolver exploded")

        out, tool = _run(tmp_path, words=["alpha"], admit=boom)
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert "adm" not in reopened.targets.get("acme.com", {}), reopened.targets
        assert reopened.tier("acme.com", sweep.bucket_of("alpha"), "whatever") == 0

    def test_a_target_that_RUNS_after_a_refusal_leaves_tier_3(self, tmp_path):
        _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: True)
        assert tool.calls, "the retry still happens — a refusal orders, it does not exclude"
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        content = sweep.content_digest(["alpha"])
        assert reopened.tier("a.com", sweep.bucket_of("alpha"), content) == 2

    def test_a_SUCCESSFUL_retry_supersedes_the_refusal_for_NEW_slots_too(self, tmp_path):
        """v79#1: the refusal was compared only against each slot's own completion, so a slot that did
        not exist when the target was refused still inherited tier 3 after a successful retry."""
        _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: True)
        assert tool.calls, "the retry ran"
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        fresh = sweep.bucket_of("beta")                    # a slot that did not exist before
        assert reopened.tier("a.com", fresh, sweep.content_digest(["beta"])) == 0, reopened.targets
        old = sweep.bucket_of("alpha")
        assert reopened.tier("a.com", old, sweep.content_digest(["alpha"])) == 2

    def test_a_LATER_refusal_still_outranks_an_older_admission(self, tmp_path):
        _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: True)
        _run(tmp_path, targets=("a.com",), words=["alpha", "beta"], admit=lambda t: False)
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert reopened.tier("a.com", sweep.bucket_of("beta"), sweep.content_digest(["beta"])) == 3

    def test_a_refused_target_is_ASKED_AGAIN_within_bounded_lifecycles(self, tmp_path, monkeypatch):
        """v80#1: tier 3 alone is permanent EXCLUSION — clean work is eligible again every lifecycle and
        fills a finite allowance for ever, so a transient refusal became a membership cap."""
        monkeypatch.setattr(budget, "ADMISSION_COOLDOWN_GENS", 4)
        asked, ran = [], []
        allowed = {"a.com": False}

        def admit(target):
            asked.append(target)
            return allowed.get(target, True)

        for _ in range(8):
            tool = _Tool()
            sweep.run_sweep(lane=LANE, state_dir=tmp_path, targets=["a.com", "b.com"],
                            vocabulary=lambda t: ["alpha"], execute=tool, budget_s=0,
                            coverage_lane=COV, max_targets_per_run=1, admit=admit)
            ran.append({c[0] for c in tool.calls})
            allowed["a.com"] = True               # it becomes contactable after the first refusal

        assert asked.count("a.com") >= 2, asked   # asked again, not frozen out
        assert any(s == {"a.com"} for s in ran), ran
        assert any(s == {"b.com"} for s in ran), ran

    def test_the_COOLDOWN_holds_while_it_lasts(self, tmp_path, monkeypatch):
        monkeypatch.setattr(budget, "ADMISSION_COOLDOWN_GENS", 1000)
        _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert reopened.tier("a.com", sweep.bucket_of("alpha"), "members") == 3

    @pytest.mark.parametrize("mode", ["raises", "skipped"])
    def test_an_ADMISSION_survives_an_invocation_that_never_completed(self, tmp_path, mode):
        """v80#2: `adm_ok` lived only in memory, so a raised or skipped invocation left the older refusal
        authoritative on disk while the guard had just said yes."""
        _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        tool = (_Tool(raises=(1, RuntimeError("popen exploded"))) if mode == "raises"
                else _Tool(statuses=[Status.SKIPPED]))
        _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: True, tool=tool)
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert reopened.targets["a.com"].get("adm_ok"), reopened.targets
        assert reopened.tier("a.com", sweep.bucket_of("alpha"), "members") == 0, reopened.targets

    @pytest.mark.parametrize("what", ["admission", "refusal"])
    def test_an_admission_answer_that_did_NOT_persist_says_so(self, tmp_path, monkeypatch, what):
        """v81: `save()` reports durability through its RESULT. Ignoring it let the run claim the answer
        had landed while the older record stood on disk."""
        real = budget.RotationProgress.save
        calls = {"n": 0}

        def flaky(self):
            calls["n"] += 1
            # 1 = the reservation save, 2 = the admission answer's own save
            return False if calls["n"] == 2 else real(self)

        if what == "admission":
            _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        monkeypatch.setattr(budget.RotationProgress, "save", flaky)
        allow = what == "admission"
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: allow,
                         tool=_Tool(raises=(1, RuntimeError("popen exploded"))))
        assert out.admission_unpersisted == 1, out
        # v82: the sentence is written from the SETTLED state, not from the first failed write
        assert "1 admission answer(s) not persisted" in " ".join(out.machinery), out.machinery
        ev = [e for e in _events(tmp_path) if e.get("unit") == "admission"][-1]["admission"]
        assert ev["unpersisted"] == 1, ev

    def test_an_admission_RESCUED_by_a_later_save_is_not_reported_unpersisted(self, tmp_path,
                                                                             monkeypatch):
        """v82: the counter recorded the first failed save. A later successful save writes the WHOLE map
        and carries the tuple, so the claim contradicted the disk."""
        _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        real = budget.RotationProgress.save
        calls = {"n": 0}

        def flaky(self):
            calls["n"] += 1
            return False if calls["n"] == 2 else real(self)   # only the admission's own save fails

        monkeypatch.setattr(budget.RotationProgress, "save", flaky)
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: True)
        assert tool.calls and out.admission_unpersisted == 0, out
        assert "not persisted" not in " ".join(out.machinery), out.machinery
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert reopened.targets["a.com"].get("adm_ok"), reopened.targets   # the disk agrees

    def test_a_RAISED_admission_write_leaves_nothing_to_rescue(self, tmp_path, monkeypatch):
        """The inverse: no tuple was written at all, so it is machinery — never a pending answer."""
        def boom(self, target, *, at):
            raise OSError("state gone")

        monkeypatch.setattr(budget.RotationProgress, "admit_target", boom)
        # ...even when no later save can rescue anything: there is nothing to rescue
        real = budget.RotationProgress.save
        calls = {"n": 0}
        monkeypatch.setattr(budget.RotationProgress, "save",
                            lambda self: real(self) if (calls.update(n=calls["n"] + 1) or calls["n"]) == 1
                            else False)
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: True)
        assert out.admission_pending == 0 and out.admission_unpersisted == 0, out
        assert "the admission could not be recorded (OSError: state gone)" in " ".join(out.machinery)
        assert "admission answer(s) not persisted" not in " ".join(out.machinery), out.machinery

    def test_a_CANCELLED_admission_save_is_UNKNOWN_not_lost(self, tmp_path, monkeypatch):
        """v83#1: `os.replace` is atomic, so a cancellation arriving after it landed but before the call
        returned leaves the tuple ON DISK — claiming it was definitely not persisted contradicted the
        state file."""
        real = budget.RotationProgress.save
        calls = {"n": 0}

        def interrupted(self):
            calls["n"] += 1
            if calls["n"] == 2:                 # 1 = the reservation, 2 = the admission answer
                real(self)                      # the write LANDS...
                raise KeyboardInterrupt("ctrl-c")   # ...and then we are interrupted
            return real(self)

        monkeypatch.setattr(budget.RotationProgress, "save", interrupted)
        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        ev = [e for e in _events(tmp_path) if e.get("unit") == "admission"][-1]["admission"]
        assert ev["unknown"] == 1 and ev["unpersisted"] == 1, ev
        # the REFUSAL itself is measured, not lost to the interrupted write (v83#2)
        assert ev["targets"] == 1 and ev["pairs"] == 1 and ev["detail"] == ["a.com"], ev
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert reopened.targets["a.com"].get("adm"), reopened.targets   # it really is on disk

    def test_an_ORDINARY_failed_admission_save_is_still_PENDING_not_unknown(self, tmp_path, monkeypatch):
        real = budget.RotationProgress.save
        calls = {"n": 0}
        monkeypatch.setattr(budget.RotationProgress, "save",
                            lambda self: False if (calls.update(n=calls["n"] + 1) or calls["n"]) == 2
                            else real(self))
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: False)
        assert out.admission_unknown == 0 and out.admission_unpersisted == 1, out
        assert "not persisted" in " ".join(out.machinery), out.machinery

    def test_a_LATER_save_that_was_interrupted_makes_an_older_ANSWER_unknown(self, tmp_path,
                                                                            monkeypatch):
        """v84: every save writes the WHOLE map, so a later one can carry an older pending answer. An
        interrupted completion save therefore cannot say that answer definitely did not land."""
        real = budget.RotationProgress.save
        calls = {"n": 0}

        def flaky(self):
            calls["n"] += 1
            if calls["n"] == 2:                 # the admission answer's own save fails outright
                return False
            if calls["n"] == 3:                 # the COMPLETION save lands, then we are interrupted
                real(self)
                raise KeyboardInterrupt("ctrl-c")
            return real(self)

        monkeypatch.setattr(budget.RotationProgress, "save", flaky)
        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: True)
        ev = [e for e in _events(tmp_path) if e.get("unit") == "admission"][-1]["admission"]
        assert ev["unknown"] == 1 and ev["unpersisted"] == 1, ev
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert reopened.targets["a.com"].get("adm_ok"), reopened.targets   # it really did land

    def test_a_LATER_save_that_was_interrupted_makes_an_older_COMPLETION_unknown(self, tmp_path,
                                                                                monkeypatch):
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        real = budget.RotationProgress.save
        calls = {"n": 0}

        def flaky(self):
            calls["n"] += 1
            if calls["n"] == 2:                 # the first completion save fails outright
                return False
            if calls["n"] == 3:                 # the NEXT reservation save lands, then interrupted
                real(self)
                raise KeyboardInterrupt("ctrl-c")
            return real(self)

        monkeypatch.setattr(budget.RotationProgress, "save", flaky)
        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, words=["alpha", "beta"])
        ev = [e for e in _events(tmp_path) if e.get("unit") == "completion"][-1]["completion"]
        assert ev["unknown"] >= 1 and ev["pending"] == 0, ev
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        done = [s for t in reopened.targets.values() for s in t["slots"].values() if "done" in s]
        assert done, reopened.targets                                     # it really did land

    def test_a_CONFIRMED_save_still_rescues_everything_it_carried(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)
        real = budget.RotationProgress.save
        calls = {"n": 0}
        monkeypatch.setattr(budget.RotationProgress, "save",
                            lambda self: False if (calls.update(n=calls["n"] + 1) or calls["n"]) == 2
                            else real(self))
        out, tool = _run(tmp_path, words=["alpha", "beta"])
        assert out.completion_unpersisted == 0 and out.completions_published == 2, out

    def test_a_CANCELLATION_between_the_save_and_the_rescue_is_UNKNOWN(self, tmp_path, monkeypatch):
        """v85: the in-flight markers were cleared before the confirmed-success accounting, so a
        cancellation in that window reached settlement with pending state and no uncertainty — a definite
        "not persisted" claim for tuples already on disk."""
        real = budget.RotationProgress.save
        calls = {"n": 0}
        monkeypatch.setattr(budget.RotationProgress, "save",
                            lambda self: False if (calls.update(n=calls["n"] + 1) or calls["n"]) == 2
                            else real(self))
        real_rescue = sweep._rescue
        seen = {"n": 0}

        def rescue(out):
            seen["n"] += 1
            if seen["n"] == 2:                  # the save that would carry the pending answer
                raise KeyboardInterrupt("ctrl-c")
            return real_rescue(out)

        monkeypatch.setattr(sweep, "_rescue", rescue)
        with pytest.raises(KeyboardInterrupt):
            _run(tmp_path, targets=("a.com",), words=["alpha"], admit=lambda t: True)
        ev = [e for e in _events(tmp_path) if e.get("unit") == "admission"][-1]["admission"]
        assert ev["unknown"] == 1 and ev["unpersisted"] == 1, ev
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert reopened.targets["a.com"].get("adm_ok"), reopened.targets   # it really is on disk

    def test_the_RESCUE_never_counts_a_completion_twice(self, tmp_path):
        out = sweep.SweepResult()
        out.pending_completions = 3
        sweep._rescue(out)
        sweep._rescue(out)
        assert out.completions_published == 3 and out.pending_completions == 0, out

    def test_the_BOOKS_are_a_RECORD_a_transition_replaces(self):
        """v86: the atomicity rests on the record being immutable and swapped, not edited in place."""
        out = sweep.SweepResult()
        out.pending_completions = 3
        snapshot = out.books
        out.pending_completions = 4
        assert snapshot.pending == 3 and out.books is not snapshot, (snapshot, out.books)
        with pytest.raises(dataclasses.FrozenInstanceError):
            snapshot.pending = 9

    @pytest.mark.parametrize("saved", [True, False])
    def test_an_INTERRUPTION_ANYWHERE_in_the_transition_leaves_ONE_disposition(self, saved):
        """v86: a clean double call does not exercise interruption BETWEEN the assignments.

        `published += pending` then `pending = 0` is two stores, and a cancellation lands between any two:
        three tuples were credited as published AND, through the in-flight snapshot, settled as unknown.
        This raises at every executable line of the publication transition and demands that each tuple end
        in exactly one disposition — the books either describe the state before it or the state after."""
        line = _tracer_lines(("_persist", "_rescue", "_land"))
        outcomes = set()
        for stop_at in range(1, 40):
            out = sweep.SweepResult()
            out.completions_published, out.pending_completions, out.admission_pending = 5, 3, 2
            with line(stop_at):
                try:
                    sweep._persist(out, types.SimpleNamespace(save=lambda: saved))
                except KeyboardInterrupt:
                    pass
            sweep._settle_completions(out)
            assert out.completions_published + out.pending_completions + out.completion_unknown == 8, (
                stop_at, out.books, out.completion_unknown)
            # the SAME transition credits the admission answers, so the two move together or not at all
            rescued = out.completions_published == 8
            assert out.admission_pending + out.admission_unknown == (0 if rescued else 2), (
                stop_at, out.books, out.admission_unknown)
            assert out.inflight_completions == out.admission_inflight == 0, (stop_at, out.books)
            # one save, one answer: the snapshot is taken for BOTH kinds at once, so an interruption
            # cannot leave the completions of that save unknown while its admission answers read pending
            assert (out.completion_unknown == 3) == (out.admission_unknown == 2), (stop_at, out.books)
            outcomes.add((out.completions_published, out.pending_completions, out.completion_unknown))
        # not vacuous: the sweep must really cut the transition both before and after it applied
        assert (5, 0, 3) in outcomes and ((8, 0, 0) in outcomes) == saved, outcomes

    def test_a_CLOCK_stop_does_not_absorb_the_BOUND_s_pairs(self, tmp_path, monkeypatch):
        """v65: two five-word targets, a three-per-target bound, and a clock that expires after the first
        call. Two pairs are the BOUND's (that target may spend no more) and five are the clock's — the
        either/or that inferred the split from `eligible - attempted` called all seven the clock's,
        omitting a cap that fired and overstating what the stop prevented."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 3)
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 9.0                       # the first call alone exhausts the 5s budget
                return super().__call__(target, bucket, words)

        out, tool = _run(tmp_path, targets=("a.com", "b.com"), words=[f"w{i}" for i in range(5)],
                         tool=_Slow(), budget_s=5, max_pairs_per_target=3)
        assert out.stop_kind == "budget", (out.stop, out.stop_kind)
        assert out.attempted_pairs == 3 and out.eligible_pairs == 10, out
        parts = out.pair_remainder()
        assert parts["bound"] == 2 and parts["stopped"] == 5, parts
        assert sum(parts[k] for k in ("refused", "unselectable", "deferred", "stopped", "bound")) == 7
        assert parts["total"] == 7, parts

    def test_the_PARTITION_holds_for_ANY_counters(self, tmp_path):
        """v65: `pair_remainder()` is a PARTITION — the parts sum to the total, none is negative, and no
        pair is counted twice however the counters were reached. Recorded dispositions can overlap (a
        target whose slots the bound excluded can then be refused), and a residual with no stop belongs to
        the bound: the last batch simply left the allowance short of another slot, which nothing marks."""
        out = sweep.SweepResult()
        out.eligible_pairs, out.attempted_pairs = 10, 3
        out.stop_kind = None                             # nothing stopped this run
        parts = out.pair_remainder()
        assert parts["bound"] == 7 and parts["stopped"] == 0, parts     # the residual is the BOUND's
        out.refused_pairs, out.bound_pairs, out.deferred_pairs = 9, 9, 9     # deliberately overlapping
        parts = out.pair_remainder()
        assert parts["total"] == 7, parts
        assert sum(parts[k] for k in ("refused", "unselectable", "deferred", "stopped", "bound")) == 7
        assert all(parts[k] >= 0 for k in parts), parts

    def test_a_TIER_boundary_does_not_hide_the_BOUND_s_pairs(self, tmp_path, monkeypatch):
        """v66: `_next_batch` returns at a tier boundary BEFORE the next slot ever reaches the cap check,
        so counting only what the scan excluded left work no remaining allowance could admit looking like
        the clock's. One target, one dirty word and one clean one, a one-per-target bound, and a clock that
        expires after the dirty invocation: the clean pair is the BOUND's, not the stop's."""
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])
        _run(tmp_path, words=["clean-word"])                    # ...now clean, and its slot is tier 2

        class _Slow(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 9.0                               # the first call exhausts the 5s budget
                return super().__call__(target, bucket, words)

        out, tool = _run(tmp_path, words=["clean-word", "brand-new-word"], tool=_Slow(),
                         budget_s=5, max_pairs_per_target=1)
        assert [c[2] for c in tool.calls] == [("brand-new-word",)], tool.calls   # the dirty tier, alone
        parts = out.pair_remainder()
        assert parts["bound"] == 1 and parts["stopped"] == 0, (parts, out.stop, out.stop_kind)
        # ...and with nothing left for the clock to take, the CAP is what ended the run (v60#2)
        assert out.stop_kind == "bound", (out.stop, out.stop_kind)

    def test_the_REMAINING_capacity_is_consumed_CUMULATIVELY(self, tmp_path, monkeypatch):
        """v67: four one-word slots, two words per call, a three-per-target bound, and a clock that expires
        after the first call. Two candidates remain and only ONE of them fits the remaining allowance, so
        the clock stopped one pair and the cap withheld the other. Testing each remaining slot against the
        same final `spent` let both "fit" and reported `bound=0, stopped=2`."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])

        class _Slow(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 9.0
                return super().__call__(target, bucket, words)

        out, tool = _run(tmp_path, words=[f"w{i}" for i in range(4)], tool=_Slow(),
                         budget_s=5, max_pairs_per_target=3)
        assert out.eligible_pairs == 4 and out.attempted_pairs == 2, out
        parts = out.pair_remainder()
        assert parts["bound"] == 1 and parts["stopped"] == 1, parts
        # ...and the unbounded-clock run proves the split: the scheduler submits one more, excludes one
        ticks["t"] = 0.0
        again, tool2 = _run(tmp_path / "b", words=[f"w{i}" for i in range(4)], max_pairs_per_target=3)
        assert again.attempted_pairs == 3 and again.pair_remainder()["bound"] == 1, again.pair_remainder()

    def test_the_dry_run_walks_the_SCHEDULER_s_order(self, tmp_path, monkeypatch):
        """v67, the other half: WHICH remaining slot the allowance admits depends on the ORDER the
        selection would have used, not on any walk over the same slots. Two candidates remain — a two-word
        slot the scheduler reaches first and a one-word slot behind it — and two candidates of room. In the
        scheduler's order the pair fits and the single is the bound's; in any other order the single fits
        first and the PAIR is withheld, which is not what the next run will do."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])
        # bucket ids: w0001 -> 030, w0003 -> 091 (the first call), w0831 + w1263 -> 101 (ONE slot, two
        # words), w0000 -> 171. The scheduler takes the lowest slot id inside the tier, so it meets the
        # two-word slot before the one-word one.
        words = ["w0001", "w0003", "w0831", "w1263", "w0000"]
        assert sweep.bucket_of("w0831") == sweep.bucket_of("w1263") == "101", "fixture drifted"
        assert [sweep.bucket_of(w) for w in ("w0001", "w0003", "w0000")] == ["030", "091", "171"]

        class _Slow(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 9.0                              # one call, then the 5s clock is gone
                return super().__call__(target, bucket, words)

        out, tool = _run(tmp_path, words=words, tool=_Slow(), budget_s=5, max_pairs_per_target=4)
        assert out.attempted_pairs == 2, tool.calls
        parts = out.pair_remainder()
        assert parts["bound"] == 1 and parts["stopped"] == 2, parts

    def test_the_dry_run_respects_TIER_before_slot_order(self, tmp_path, monkeypatch):
        """v67: the order is the SCHEDULER's, which is tier first — not the slot set's own order. A clean
        slot with a low id is met AFTER the dirty work whatever the slot list says, so the dirty two-word
        slot takes the remaining allowance and the clean single is the bound's."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 2)
        ticks = {"t": 0.0}
        monkeypatch.setattr(budget.time, "monotonic", lambda: ticks["t"])
        assert sweep.bucket_of("w0001") == "030", "fixture drifted"          # the CLEAN slot, lowest id
        assert [sweep.bucket_of(w) for w in ("w3761", "w3345")] == ["000", "001"]
        assert sweep.bucket_of("w0831") == sweep.bucket_of("w1263") == "101"
        _run(tmp_path, words=["w0001"])                                       # ...now clean (tier 2)

        class _Slow(_Tool):
            def __call__(self, target, bucket, words):
                ticks["t"] += 9.0
                return super().__call__(target, bucket, words)

        out, tool = _run(tmp_path, words=["w0001", "w3761", "w3345", "w0831", "w1263"], tool=_Slow(),
                         budget_s=5, max_pairs_per_target=4)
        assert [c[2] for c in tool.calls] == [("w3761", "w3345")], tool.calls   # the dirty tier, first
        parts = out.pair_remainder()
        assert parts["bound"] == 1 and parts["stopped"] == 2, parts

    def test_a_REFUSED_target_owns_every_pair_it_holds(self, tmp_path):
        """v68: the refusal loop skipped slots already in `picked` — which includes the ones the candidate
        bound excluded on the way in. A target the guard turned away without a single call reported part of
        its work as withheld by the spend bound, and the terminal named a bound that decided nothing.
        Admission is target-wide: nothing was contacted, so every schedulable pair is the refusal's."""
        # five one-word slots and a three-per-target bound: the batch scan fills the allowance and
        # EXCLUDES the last two before the admission hook is ever asked
        out, tool = _run(tmp_path, words=[f"w{i}" for i in range(5)], max_pairs_per_target=3,
                         admit=lambda t: False)
        assert tool.calls == [], tool.calls
        assert out.targets_refused == 1 and out.refused_pairs == 5, out
        parts = out.pair_remainder()
        assert parts["refused"] == 5 and parts["bound"] == 0 and parts["stopped"] == 0, parts
        assert "candidate bound" not in (out.stop or ""), out.stop        # it withheld nothing

    def test_an_UNPUBLISHED_completion_leaves_its_target_OWED(self, tmp_path, monkeypatch):
        """v-review: `progress` holds `done` tuples staged in MEMORY. When the save that would make one
        durable did not confirm, the next lifecycle reopens a ledger showing tier 0 and selects the slot
        again — so a target whose completion nobody published is NOT complete, whatever the map says."""
        real = budget.RotationProgress.save
        calls = {"n": 0}
        monkeypatch.setattr(budget.RotationProgress, "save",
                            lambda self: real(self) if (calls.update(n=calls["n"] + 1) or calls["n"]) < 2
                            else False)
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"])
        assert tool.calls and out.pending_completions, out
        assert out.targets_complete == 0 and out.targets_remaining == 1, out
        # ...and the ledger really does still owe it
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        assert reopened.tier("a.com", sweep.bucket_of("alpha"), sweep.content_digest(["alpha"])) != 2

    def test_a_PUBLISHED_completion_does_count_as_done(self, tmp_path):
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"])
        assert out.pending_completions == 0 and out.targets_complete == 1, out
        assert out.targets_remaining == 0, out

    def test_an_UNSTAGED_completion_leaves_its_target_OWED_too(self, tmp_path):
        """The other unsettled shape: the invocation returned something that is not a status, so no `done`
        tuple was ever staged. The slots RAN and nobody holds their completion — the target still owes."""
        class _Bad(_Tool):
            def __call__(self, target, bucket, words):
                super().__call__(target, bucket, words)
                return "not a status"

        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha"], tool=_Bad())
        assert out.completion_unstaged and out.stop_kind == "machinery", out
        assert out.targets_complete == 0 and out.targets_remaining == 1, out

    def test_a_RESCUED_completion_stops_owing_its_target(self, tmp_path, monkeypatch):
        """v-review: the unsettled set only grew. A later successful save writes the WHOLE map and rescues
        every pending tuple, so a target excluded when its own save failed stayed excluded for the rest of
        the lifecycle — and the hint kept asking for work the disk already held."""
        monkeypatch.setattr(sweep, "MAX_BATCH_WORDS", 1)          # two batches, two saves
        real = budget.RotationProgress.save
        calls = {"n": 0}
        monkeypatch.setattr(budget.RotationProgress, "save",
                            lambda self: False if (calls.update(n=calls["n"] + 1) or calls["n"]) == 2
                            else real(self))
        out, tool = _run(tmp_path, targets=("a.com",), words=["alpha", "bravo"])
        assert len(tool.calls) == 2, tool.calls
        assert out.pending_completions == 0 and out.completions_published == 2, out
        assert out.targets_complete == 1 and out.targets_remaining == 0, out
        reopened = budget.RotationProgress(tmp_path / f"{LANE}.json", lane=LANE, schema=sweep.SCHEMA,
                                           slot_grammar=sweep.slot_id_ok)
        for word in ("alpha", "bravo"):
            assert reopened.tier("a.com", sweep.bucket_of(word), sweep.content_digest([word])) == 2
