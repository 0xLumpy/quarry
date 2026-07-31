"""`budget.RotationProgress` / `rotation_session` — the shared scheduling primitive (step 4 design v10).

It ORDERS and nothing else: no outcome, no completion claim, and losing it costs ordering quality rather
than coverage. These tests pin the parts the design argued about for nine review rounds — the held-lock
contract, the two independently ordered tuples, the tier rule, the fairness cursor, and fail-closed parsing.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from quarry_recon import budget

pytestmark = pytest.mark.offline

SCHEMA = 1


def _progress(tmp_path, lane="a1d", schema=SCHEMA):
    return budget.RotationProgress(tmp_path / f"{lane}.json", lane=lane, schema=schema)


class TestHeldLockIsStructural:
    """v8#1/v9#2: `state_lock` is flock-based, so a nested acquisition in the same process is `StateBusy`.
    A `save()` that re-locked inside a session would report every write as contended."""

    def test_a_SESSION_save_never_acquires_the_lock_again(self, tmp_path):
        with budget.rotation_session(tmp_path, "a1d", schema=SCHEMA) as progress:
            assert progress.held is True
            progress.reserve("acme.com", "07", at=1000.0)
            assert progress.save() is True                # would be False if it re-locked against itself

    def test_the_nested_acquisition_it_protects_against_is_REAL(self, tmp_path):
        with budget.rotation_session(tmp_path, "a1d", schema=SCHEMA):
            with pytest.raises(budget.StateBusy):
                with budget.rotation_session(tmp_path, "a1d", schema=SCHEMA):
                    pass                                  # pragma: no cover

    def test_a_save_OUTSIDE_a_session_takes_the_lock_itself(self, tmp_path):
        p = _progress(tmp_path)
        assert p.held is False
        p.reserve("acme.com", "07", at=1000.0)
        assert p.save() is True
        assert json.loads((tmp_path / "a1d.json").read_text())["targets"]["acme.com"]["slots"]["07"]["res"]

    def test_LANES_do_not_contend_with_each_other(self, tmp_path):
        """a1d and wildcard share no state; one must not make the other report contention (v3#6)."""
        with budget.rotation_session(tmp_path, "a1d", schema=SCHEMA):
            with budget.rotation_session(tmp_path, "wildcard", schema=SCHEMA) as other:
                assert other.save() is True


class TestTheTwoTuples:
    def test_a_completion_needs_ITS_OWN_reservation(self, tmp_path):
        p = _progress(tmp_path)
        gen = p.reserve("acme.com", "07", at=1.0)
        p.complete("acme.com", "07", gen, at=2.0, content="abc", members=195)
        assert p.tier("acme.com", "07", "abc") == 2

    def test_a_moved_reservation_is_an_INVARIANT_not_a_disposition(self, tmp_path):
        """v9#1: one sweeper owns the lane, so this cannot happen — if it does, it is a bug."""
        p = _progress(tmp_path)
        p.reserve("acme.com", "06", at=0.5)                  # push the lane generation past 1
        gen = p.reserve("acme.com", "07", at=1.0)
        with pytest.raises(budget.SchedulerInvariant):
            p.complete("acme.com", "07", gen - 1, at=2.0, content="abc", members=1)

    def test_MERGE_replaces_each_tuple_by_ITS_OWN_generation(self, tmp_path):
        """v5#3: reservation gen 41 can sit beside completion gen 39; merging the slot by one of them
        would erase the other. Each tuple is atomic and ordered by its own gen."""
        first = _progress(tmp_path)
        gen1 = first.reserve("acme.com", "07", at=1.0)
        first.complete("acme.com", "07", gen1, at=2.0, content="OLD-RAN", members=10)
        assert first.save() is True

        second = _progress(tmp_path)                      # a later lifecycle re-reserves, never runs
        gen2 = second.reserve("acme.com", "07", at=3.0)
        assert gen2 > gen1 and second.save() is True

        on_disk = json.loads((tmp_path / "a1d.json").read_text())
        slot = on_disk["targets"]["acme.com"]["slots"]["07"]
        assert slot["res"]["gen"] == gen2, slot           # newer reservation wins
        assert slot["done"]["gen"] == gen1 and slot["done"]["c"] == "OLD-RAN", slot  # completion survives

    def test_an_OLDER_snapshot_cannot_erase_a_newer_completion(self, tmp_path):
        newer = _progress(tmp_path)
        for _ in range(8):
            newer.next_gen()                              # push the lane generation up to 8
        gen = newer.reserve("acme.com", "07", at=1.0)     # -> 9
        newer.complete("acme.com", "07", gen, at=2.0, content="NEW", members=2)
        assert newer.save() is True
        stale = budget.RotationProgress(tmp_path / "a1d.json", lane="a1d", schema=SCHEMA)
        stale.targets = {"acme.com": {"seq": 3, "slots": {"07": {"res": {"gen": 3, "at": 0.5},
                                                                 "done": {"gen": 3, "at": 0.6,
                                                                          "c": "OLD", "n": 1}}}}}
        assert stale.save() is True
        slot = json.loads((tmp_path / "a1d.json").read_text())["targets"]["acme.com"]["slots"]["07"]
        assert slot["done"]["c"] == "NEW" and slot["res"]["gen"] == gen, slot

    def test_the_lane_generation_and_cursor_merge_by_MAX(self, tmp_path):
        a = _progress(tmp_path)
        for _ in range(4):
            a.next_gen()
        gen = a.reserve("acme.com", "01", at=1.0)         # -> 5
        assert a.save() is True
        b = _progress(tmp_path)
        assert b.gen == gen and b.target_seq("acme.com") == gen
        assert b.next_gen() == gen + 1


class TestTheTierRule:
    def test_a_NEVER_RUN_slot_outranks_everything(self, tmp_path):
        p = _progress(tmp_path)
        assert p.tier("acme.com", "07", "abc") == 0            # no record at all

    def test_a_RESERVED_then_CRASHED_slot_is_still_never_run(self, tmp_path):
        """v4#3: the content digest is written with the COMPLETION, never at reservation — otherwise a
        crash before the launch would leave the slot looking clean while nothing was submitted."""
        p = _progress(tmp_path)
        p.reserve("acme.com", "07", at=1.0)
        assert p.tier("acme.com", "07", "abc") == 0

    def test_MEMBERSHIP_CHANGE_since_the_slot_ran_is_DIRTY(self, tmp_path):
        p = _progress(tmp_path)
        gen = p.reserve("acme.com", "07", at=1.0)
        p.complete("acme.com", "07", gen, at=2.0, content="ran-over-these", members=3)
        assert p.tier("acme.com", "07", "ran-over-these") == 2
        assert p.tier("acme.com", "07", "new-members") == 1


class TestFailClosedParsing:
    """An unusable record reads as NEVER RUN, which puts the slot at the FRONT of the rotation — the safe
    direction for something that only orders."""

    @pytest.mark.parametrize("doc", [
        "not json at all",
        json.dumps({"lane": "other", "schema": SCHEMA, "gen": 3, "targets": {}}),
        json.dumps({"lane": "a1d", "schema": SCHEMA + 1, "gen": 3, "targets": {}}),
        json.dumps([1, 2, 3]),
    ])
    def test_an_untrusted_document_starts_a_FRESH_rotation(self, tmp_path, doc):
        (tmp_path / "a1d.json").write_text(doc)
        p = _progress(tmp_path)
        assert p.gen == 0 and p.targets == {}

    @pytest.mark.parametrize("done", [
        {"gen": 1, "at": float("nan"), "c": "x", "n": 1},
        {"gen": 1, "at": -5.0, "c": "x", "n": 1},
        {"gen": 1, "at": 1.0, "c": "", "n": 1},
        {"gen": 1, "at": 1.0, "c": "x"},
        {"gen": True, "at": 1.0, "c": "x", "n": 1},
        "not a dict",
    ])
    def test_an_unusable_completion_reads_as_NEVER_RUN(self, tmp_path, done):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": 2,
             "targets": {"acme.com": {"seq": 2, "slots": {"07": {"res": {"gen": 2, "at": 1.0},
                                                                 "done": done}}}}}))
        p = _progress(tmp_path)
        assert p.tier("acme.com", "07", "whatever") == 0

    def test_an_UNREADABLE_file_is_a_fresh_rotation_not_a_stop(self, tmp_path, monkeypatch):
        real = pathlib.Path.read_text
        monkeypatch.setattr(pathlib.Path, "read_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("denied"))
                            if self.name == "a1d.json" else real(self, *a, **k))
        p = _progress(tmp_path)
        assert p.gen == 0 and p.targets == {}

    def test_a_save_that_cannot_write_answers_FALSE(self, tmp_path, monkeypatch):
        p = _progress(tmp_path)
        p.reserve("acme.com", "07", at=1.0)
        monkeypatch.setattr(pathlib.Path, "write_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(OSError("full")))
        assert p.save() is False

    def test_a_partial_write_never_replaces_the_document(self, tmp_path, monkeypatch):
        p = _progress(tmp_path)
        gen = p.reserve("acme.com", "07", at=1.0)
        p.complete("acme.com", "07", gen, at=2.0, content="good", members=1)
        assert p.save() is True
        before = (tmp_path / "a1d.json").read_text()
        broken = _progress(tmp_path)
        broken.reserve("acme.com", "08", at=3.0)
        monkeypatch.setattr(pathlib.Path, "write_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(OSError("full")))
        assert broken.save() is False
        assert (tmp_path / "a1d.json").read_text() == before
        assert not list(tmp_path.glob("*.tmp")), list(tmp_path.iterdir())

    def test_a_save_that_cannot_SERIALISE_gives_up_instead_of_hanging(self, tmp_path, monkeypatch):
        """A `LOCK_EX` that blocks forever turns a best-effort write into a hang — the Shodan lesson. The
        wait is bounded; giving up answers False rather than writing unserialised."""
        import threading
        monkeypatch.setattr(budget, "_ROTATION_LOCK_WAIT_S", 0.05)
        p = _progress(tmp_path)
        p.reserve("acme.com", "07", at=1.0)
        answer = []
        with budget.state_lock(tmp_path / "a1d.lock"):          # somebody else holds it
            # a WATCHDOG, not a bare call: an unbounded `LOCK_EX` would block here forever, and a hanging
            # test proves nothing — it has to FAIL.
            worker = threading.Thread(target=lambda: answer.append(p.save()), daemon=True)
            worker.start()
            worker.join(timeout=5)
            assert not worker.is_alive(), "save() blocked on the lane lock instead of giving up"
        assert answer == [False], answer
        assert p.save() is True                                  # ...and it works once released

    def test_the_write_is_TEMP_THEN_REPLACE(self, tmp_path, monkeypatch):
        """A direct write would leave a torn document behind on failure; the replace is what makes the
        publication atomic."""
        import os as _os
        p = _progress(tmp_path)
        gen = p.reserve("acme.com", "07", at=1.0)
        p.complete("acme.com", "07", gen, at=2.0, content="good", members=1)
        assert p.save() is True
        before = (tmp_path / "a1d.json").read_text()

        later = _progress(tmp_path)
        later.reserve("acme.com", "08", at=3.0)
        monkeypatch.setattr(_os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("replace failed")))
        assert later.save() is False
        assert (tmp_path / "a1d.json").read_text() == before      # the old document is intact
        assert not list(tmp_path.glob("*.tmp")), list(tmp_path.iterdir())


class TestReviewV11:
    """The four defects the v11 review reproduced against the committed primitive."""

    # ── v11#1 fail-closed parsing must never RAISE ───────────────────────────────────────────────
    @pytest.mark.parametrize("doc", [
        {"lane": "a1d", "schema": SCHEMA, "gen": 2, "targets": ["bad"]},
        {"lane": "a1d", "schema": SCHEMA, "gen": "two", "targets": {}},
    ])
    def test_a_MALFORMED_HEADER_starts_a_fresh_rotation_instead_of_raising(self, tmp_path, doc):
        """`targets` that is not a mapping, or a generation that is not a count, makes the DOCUMENT
        untrustworthy — the whole rotation restarts. (Constructing it used to raise `AttributeError`.)"""
        (tmp_path / "a1d.json").write_text(json.dumps(doc))
        p = _progress(tmp_path)                            # must not raise
        assert p.gen == 0 and p.targets == {} and p.state_status == "unusable"

    def test_PARSE_ITSELF_never_raises_on_a_malformed_container(self, tmp_path):
        """The constructor's guard would hide this: `_parse` is also called by `save()` when the document
        changed on disk, so it has to be safe on its own."""
        for doc in ({"lane": "a1d", "schema": SCHEMA, "gen": 2, "targets": ["bad"]},
                    {"lane": "a1d", "schema": SCHEMA, "gen": 2, "targets": {"acme.com": {"slots": []}}}):
            gen, targets, status, _why = budget.RotationProgress._parse(
                json.dumps(doc), lane="a1d", schema=SCHEMA)
            assert targets == {}, (doc, targets)

    def test_the_constructor_CONTAINS_a_raising_parse(self, tmp_path, monkeypatch):
        """Defence in depth: even if a future `_parse` raises, a scheduling map must degrade to a fresh
        rotation and SAY so, never take the phase down."""
        monkeypatch.setattr(budget.RotationProgress, "_parse",
                            classmethod(lambda cls, *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))))
        (tmp_path / "a1d.json").write_text("{}")
        p = _progress(tmp_path)
        assert p.gen == 0 and p.targets == {}
        assert p.state_status == "unusable" and "unparseable" in p.state_reason

    @pytest.mark.parametrize("doc", [
        {"lane": "a1d", "schema": SCHEMA, "gen": 2, "targets": {"acme.com": ["bad"]}},
        {"lane": "a1d", "schema": SCHEMA, "gen": 2, "targets": {"acme.com": {"seq": 1, "slots": []}}},
        {"lane": "a1d", "schema": SCHEMA, "gen": 2, "targets": {"acme.com": {"seq": 1, "slots": "x"}}},
    ])
    def test_a_MALFORMED_TARGET_is_dropped_without_losing_the_document(self, tmp_path, doc):
        """A container we cannot read is not a target: it is skipped, its slots read as NEVER RUN (the
        front of the rotation), and the rest of the document still orders."""
        (tmp_path / "a1d.json").write_text(json.dumps(doc))
        p = _progress(tmp_path)                            # must not raise
        assert p.targets == {} and p.gen == 2
        assert p.tier("acme.com", "07", "whatever") == 0

    @pytest.mark.parametrize("bad", [True, 1.9, -1, "1"])
    def test_a_GENERATION_must_be_an_exact_non_negative_int(self, tmp_path, bad):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": bad, "targets": {}}))
        p = _progress(tmp_path)
        assert p.gen == 0 and p.state_status == "unusable", (p.gen, p.state_status)

    def test_schema_TRUE_is_not_schema_ONE(self, tmp_path):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": True, "gen": 1, "targets": {}}))
        p = _progress(tmp_path)
        assert p.state_status == "unusable", p.state_status

    @pytest.mark.parametrize("n", [True, 2.5, -1, "3"])
    def test_a_MEMBER_COUNT_must_be_an_exact_non_negative_int(self, tmp_path, n):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": 2,
             "targets": {"acme.com": {"seq": 2, "slots": {"07": {"res": {"gen": 2, "at": 1.0},
                                                                 "done": {"gen": 2, "at": 2.0,
                                                                          "c": "x", "n": n}}}}}}))
        assert _progress(tmp_path).tier("acme.com", "07", "x") == 0       # unusable -> never run

    # ── v11#2 the lane generation is the authority ───────────────────────────────────────────────
    def test_reserve_ALLOCATES_the_generation(self, tmp_path):
        p = _progress(tmp_path)
        first = p.reserve("acme.com", "07", at=1.0)
        second = p.reserve("acme.com", "08", at=2.0)
        assert (first, second) == (1, 2) and p.gen == 2
        assert p.save() is True
        reopened = _progress(tmp_path)
        assert reopened.gen == 2, reopened.gen             # the lane covers its own slots
        assert reopened.next_gen() == 3

    def test_a_slot_AHEAD_of_its_lane_generation_is_dropped(self, tmp_path):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": 5,
             "targets": {"acme.com": {"seq": 5, "slots": {"07": {"res": {"gen": 39, "at": 1.0}}}}}}))
        p = _progress(tmp_path)
        assert p.slot_seq("acme.com", "07") == 0, p.targets

    def test_a_COMPLETION_without_its_reservation_reads_as_never_run(self, tmp_path):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": 4,
             "targets": {"acme.com": {"seq": 4, "slots": {"07": {"done": {"gen": 4, "at": 2.0,
                                                                          "c": "x", "n": 1}}}}}}))
        assert _progress(tmp_path).tier("acme.com", "07", "x") == 0

    def test_a_COMPLETION_claiming_to_PRECEDE_its_reservation_reads_as_never_run(self, tmp_path):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": 9,
             "targets": {"acme.com": {"seq": 9, "slots": {"07": {"res": {"gen": 3, "at": 1.0},
                                                                 "done": {"gen": 7, "at": 2.0,
                                                                          "c": "x", "n": 1}}}}}}))
        assert _progress(tmp_path).tier("acme.com", "07", "x") == 0

    def test_the_target_cursor_covers_its_reservations(self, tmp_path):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": 9,
             "targets": {"acme.com": {"seq": 0, "slots": {"07": {"res": {"gen": 7, "at": 1.0}}}}}}))
        assert _progress(tmp_path).target_seq("acme.com") == 7

    # ── v11#3 held is not a public escape hatch ──────────────────────────────────────────────────
    def test_a_caller_CANNOT_declare_the_lock_held(self, tmp_path):
        p = budget.RotationProgress(tmp_path / "a1d.json", lane="a1d", schema=SCHEMA)
        assert p.held is False
        with pytest.raises(TypeError):
            budget.RotationProgress(tmp_path / "a1d.json", lane="a1d", schema=SCHEMA, held=True)
        assert budget.RotationProgress(tmp_path / "a1d.json", lane="a1d", schema=SCHEMA,
                                       _session=object()).held is False    # a foreign token proves nothing

    def test_only_the_SESSION_yields_a_held_map(self, tmp_path):
        with budget.rotation_session(tmp_path, "a1d", schema=SCHEMA) as progress:
            assert progress.held is True

    # ── v11#4 lost progress is distinguishable from a fresh one ──────────────────────────────────
    def test_MISSING_state_is_not_the_same_fact_as_UNUSABLE_state(self, tmp_path):
        fresh = _progress(tmp_path)
        assert fresh.state_status == "missing" and not fresh.state_reason
        (tmp_path / "a1d.json").write_text("not json")
        broken = _progress(tmp_path)
        assert broken.state_status == "unusable" and broken.state_reason, broken.state_reason
        # ...and an unusable document is NOT overwritten (v12#1): the rotation degrades, it does not
        # silently destroy state that might belong to another lifecycle.
        broken.reserve("acme.com", "07", at=1.0)
        assert broken.save() is False
        assert (tmp_path / "a1d.json").read_text() == "not json"
        (tmp_path / "a1d.json").unlink()                   # recovery is the operator's explicit act
        good = _progress(tmp_path)
        good.reserve("acme.com", "07", at=1.0)
        assert good.save() is True
        assert _progress(tmp_path).state_status == "valid"

    def test_an_UNREADABLE_file_is_reported_unusable_not_missing(self, tmp_path, monkeypatch):
        (tmp_path / "a1d.json").write_text("{}")
        real = pathlib.Path.read_text
        monkeypatch.setattr(pathlib.Path, "read_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("denied"))
                            if self.name == "a1d.json" else real(self, *a, **k))
        p = _progress(tmp_path)
        assert p.state_status == "unusable" and "unreadable" in p.state_reason


class TestReviewV12:
    """Four contract violations the v12 review reproduced against c6bccd0, each confirmed here first."""

    def test_a_save_NEVER_overwrites_state_it_could_not_read(self, tmp_path, monkeypatch):
        p = _progress(tmp_path)
        p.reserve("acme.com", "01", at=1.0)
        assert p.save() is True
        before = (tmp_path / "a1d.json").read_bytes()

        later = _progress(tmp_path)
        later.reserve("acme.com", "02", at=2.0)
        monkeypatch.setattr(budget.RotationProgress, "_parse",
                            classmethod(lambda cls, *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))))
        assert later.save() is False
        assert (tmp_path / "a1d.json").read_bytes() == before

    def test_an_UNREADABLE_document_is_not_overwritten_either(self, tmp_path, monkeypatch):
        p = _progress(tmp_path)
        p.reserve("acme.com", "01", at=1.0)
        assert p.save() is True
        before = (tmp_path / "a1d.json").read_bytes()
        later = _progress(tmp_path)
        later.reserve("acme.com", "02", at=2.0)
        real = pathlib.Path.read_text
        monkeypatch.setattr(pathlib.Path, "read_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("denied"))
                            if self.name == "a1d.json" else real(self, *a, **k))
        assert later.save() is False
        assert (tmp_path / "a1d.json").read_bytes() == before

    def test_ABSENCE_is_still_a_legitimate_empty_start(self, tmp_path):
        p = _progress(tmp_path)
        p.reserve("acme.com", "01", at=1.0)
        assert p.save() is True and (tmp_path / "a1d.json").exists()

    @pytest.mark.parametrize("kwargs", [
        {"at": float("nan")},
        {"at": float("inf")},
        {"at": -1.0},
        {"at": True},
        {"at": "1"},
    ])
    def test_reserve_REJECTS_a_timestamp_it_cannot_order_by(self, tmp_path, kwargs):
        p = _progress(tmp_path)
        with pytest.raises(ValueError):
            p.reserve("acme.com", "01", **kwargs)

    @pytest.mark.parametrize("bad", [{"members": 2.9}, {"members": True}, {"members": -1},
                                     {"content": None}, {"content": ""}, {"content": 7}])
    def test_complete_REJECTS_what_it_cannot_persist(self, tmp_path, bad):
        p = _progress(tmp_path)
        gen = p.reserve("acme.com", "01", at=1.0)
        kwargs = {"at": 2.0, "content": "digest", "members": 3}
        kwargs.update(bad)
        with pytest.raises(ValueError):
            p.complete("acme.com", "01", gen, **kwargs)

    def test_no_NON_STANDARD_json_token_can_reach_the_document(self, tmp_path):
        """`json.dumps(float('nan'))` emits a bare `NaN`, which is not JSON and nothing else reads back."""
        p = _progress(tmp_path)
        gen = p.reserve("acme.com", "01", at=1.0)
        p.complete("acme.com", "01", gen, at=2.0, content="d", members=1)
        assert p.save() is True
        raw = (tmp_path / "a1d.json").read_text()
        assert "NaN" not in raw and "Infinity" not in raw, raw
        json.loads(raw)                                     # strict: no non-standard tokens

    def test_a_CURSOR_ahead_of_the_lane_generation_is_clamped_and_reported(self, tmp_path):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": 5, "targets": {"t": {"seq": 99, "slots": {}}}}))
        p = _progress(tmp_path)
        assert p.target_seq("t") == 5, p.target_seq("t")     # not 99 for the next 94 lifecycles
        assert p.state_status == "degraded" and "clamped" in p.state_reason, p.state_reason

    @pytest.mark.parametrize("schema", [1.0, False, True, "1"])
    def test_a_STORED_schema_must_be_an_exact_int(self, tmp_path, schema):
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": schema, "gen": 1, "targets": {}}))
        assert _progress(tmp_path).state_status == "unusable"

    @pytest.mark.parametrize("schema", [True, 1.0, "1", -1])
    def test_a_CONFIGURED_schema_must_be_an_exact_int(self, tmp_path, schema):
        with pytest.raises(ValueError):
            budget.RotationProgress(tmp_path / "a1d.json", lane="a1d", schema=schema)

    def test_SALVAGED_records_are_reported_as_DEGRADED_not_valid(self, tmp_path):
        """Keeping the healthy records is right; presenting the result as an intact rotation is not."""
        (tmp_path / "a1d.json").write_text(json.dumps(
            {"lane": "a1d", "schema": SCHEMA, "gen": 4,
             "targets": {"good.com": {"seq": 4, "slots": {"01": {"res": {"gen": 4, "at": 1.0}}}},
                         "bad.com": ["not a target"]}}))
        p = _progress(tmp_path)
        assert p.slot_seq("good.com", "01") == 4            # the healthy record survives
        assert p.state_status == "degraded" and "dropped" in p.state_reason, p.state_reason

    def test_a_CLEAN_document_is_still_plain_valid(self, tmp_path):
        p = _progress(tmp_path)
        gen = p.reserve("acme.com", "01", at=1.0)
        p.complete("acme.com", "01", gen, at=2.0, content="d", members=1)
        assert p.save() is True
        assert _progress(tmp_path).state_status == "valid"


class TestReviewV13:
    """Identity and publication invariants the v13 review reproduced against b3abc39."""

    def test_completing_a_slot_that_was_NEVER_RESERVED_is_an_invariant(self, tmp_path):
        """`gen=0` matched the default of an absent reservation, so the call succeeded, wrote into a
        throwaway dict and `save()` answered True with nothing persisted."""
        p = _progress(tmp_path)
        with pytest.raises(ValueError):                      # 0 is not a generation at all
            p.complete("never", "07", 0, at=1.0, content="x", members=1)
        with pytest.raises(budget.SchedulerInvariant):       # ...and 1 has no reservation behind it
            p.complete("never", "07", 1, at=1.0, content="x", members=1)
        assert p.save() is True
        assert json.loads((tmp_path / "a1d.json").read_text())["targets"] == {}

    @pytest.mark.parametrize("target,bucket", [(7, "01"), ("acme.com", True), ("", "01"),
                                               ("acme.com", ""), (None, "01"), ("acme.com", 3)])
    def test_slot_identity_must_survive_PERSISTENCE(self, tmp_path, target, bucket):
        """JSON keys are strings: `reserve(7, True, …)` came back as target "7" and bucket "true", so the
        rotation history was orphaned under a key nothing looks up again."""
        p = _progress(tmp_path)
        with pytest.raises(ValueError):
            p.reserve(target, bucket, at=1.0)
        assert p.gen == 0, "the generation moved for a slot that was never valid"

    def test_a_rejected_identity_does_not_consume_a_generation(self, tmp_path):
        p = _progress(tmp_path)
        with pytest.raises(ValueError):
            p.reserve(7, "01", at=1.0)
        assert p.reserve("acme.com", "01", at=1.0) == 1

    def test_PARSE_survives_an_integer_too_large_for_a_float(self, tmp_path):
        """A 401-digit JSON integer makes `float()` raise OverflowError — the standalone never-raises
        contract has to hold, not just the constructor's guard."""
        doc = json.dumps({"lane": "a1d", "schema": SCHEMA, "gen": 1,
                          "targets": {"t": {"seq": 1, "slots": {"01": {"res": {"gen": 1,
                                                                               "at": int("9" * 401)}}}}}})
        gen, targets, status, _why = budget.RotationProgress._parse(doc, lane="a1d", schema=SCHEMA)
        assert targets["t"]["slots"] == {}, targets          # the unusable tuple is dropped, nothing raises
        (tmp_path / "a1d.json").write_text(doc)
        assert _progress(tmp_path).tier("t", "01", "x") == 0

    @pytest.mark.parametrize("schema", [True, False, 1.0, "1", -1])
    def test_PARSE_validates_its_own_schema_argument(self, tmp_path, schema):
        """`schema=True` compared equal to a stored 1 and read as valid."""
        doc = json.dumps({"lane": "a1d", "schema": 1, "gen": 0, "targets": {}})
        _gen, _targets, status, _why = budget.RotationProgress._parse(doc, lane="a1d", schema=schema)
        assert status == "unusable", (schema, status)

