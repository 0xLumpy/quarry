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
            progress.reserve("acme.com", "07", progress.next_gen(), at=1000.0)
            assert progress.save() is True                # would be False if it re-locked against itself

    def test_the_nested_acquisition_it_protects_against_is_REAL(self, tmp_path):
        with budget.rotation_session(tmp_path, "a1d", schema=SCHEMA):
            with pytest.raises(budget.StateBusy):
                with budget.rotation_session(tmp_path, "a1d", schema=SCHEMA):
                    pass                                  # pragma: no cover

    def test_a_save_OUTSIDE_a_session_takes_the_lock_itself(self, tmp_path):
        p = _progress(tmp_path)
        assert p.held is False
        p.reserve("acme.com", "07", p.next_gen(), at=1000.0)
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
        gen = p.next_gen()
        p.reserve("acme.com", "07", gen, at=1.0)
        p.complete("acme.com", "07", gen, at=2.0, content="abc", members=195)
        assert p.tier("acme.com", "07", "abc") == 2

    def test_a_moved_reservation_is_an_INVARIANT_not_a_disposition(self, tmp_path):
        """v9#1: one sweeper owns the lane, so this cannot happen — if it does, it is a bug."""
        p = _progress(tmp_path)
        p.reserve("acme.com", "07", 5, at=1.0)
        with pytest.raises(budget.SchedulerInvariant):
            p.complete("acme.com", "07", 4, at=2.0, content="abc", members=1)

    def test_MERGE_replaces_each_tuple_by_ITS_OWN_generation(self, tmp_path):
        """v5#3: reservation gen 41 can sit beside completion gen 39; merging the slot by one of them
        would erase the other. Each tuple is atomic and ordered by its own gen."""
        first = _progress(tmp_path)
        first.reserve("acme.com", "07", 39, at=1.0)
        first.complete("acme.com", "07", 39, at=2.0, content="OLD-RAN", members=10)
        assert first.save() is True

        second = _progress(tmp_path)                      # a later lifecycle re-reserves, never runs
        second.reserve("acme.com", "07", 41, at=3.0)
        assert second.save() is True

        on_disk = json.loads((tmp_path / "a1d.json").read_text())
        slot = on_disk["targets"]["acme.com"]["slots"]["07"]
        assert slot["res"]["gen"] == 41, slot             # newer reservation wins
        assert slot["done"]["gen"] == 39 and slot["done"]["c"] == "OLD-RAN", slot   # completion survives

    def test_an_OLDER_snapshot_cannot_erase_a_newer_completion(self, tmp_path):
        newer = _progress(tmp_path)
        newer.reserve("acme.com", "07", 9, at=1.0)
        newer.complete("acme.com", "07", 9, at=2.0, content="NEW", members=2)
        assert newer.save() is True
        stale = budget.RotationProgress(tmp_path / "a1d.json", lane="a1d", schema=SCHEMA)
        stale.targets = {"acme.com": {"seq": 3, "slots": {"07": {"res": {"gen": 3, "at": 0.5},
                                                                 "done": {"gen": 3, "at": 0.6,
                                                                          "c": "OLD", "n": 1}}}}}
        assert stale.save() is True
        slot = json.loads((tmp_path / "a1d.json").read_text())["targets"]["acme.com"]["slots"]["07"]
        assert slot["done"]["c"] == "NEW" and slot["res"]["gen"] == 9, slot

    def test_the_lane_generation_and_cursor_merge_by_MAX(self, tmp_path):
        a = _progress(tmp_path)
        for _ in range(5):
            a.next_gen()
        a.reserve("acme.com", "01", 5, at=1.0)
        assert a.save() is True
        b = _progress(tmp_path)
        assert b.gen == 5 and b.target_seq("acme.com") == 5
        assert b.next_gen() == 6


class TestTheTierRule:
    def test_a_NEVER_RUN_slot_outranks_everything(self, tmp_path):
        p = _progress(tmp_path)
        assert p.tier("acme.com", "07", "abc") == 0            # no record at all

    def test_a_RESERVED_then_CRASHED_slot_is_still_never_run(self, tmp_path):
        """v4#3: the content digest is written with the COMPLETION, never at reservation — otherwise a
        crash before the launch would leave the slot looking clean while nothing was submitted."""
        p = _progress(tmp_path)
        p.reserve("acme.com", "07", p.next_gen(), at=1.0)
        assert p.tier("acme.com", "07", "abc") == 0

    def test_MEMBERSHIP_CHANGE_since_the_slot_ran_is_DIRTY(self, tmp_path):
        p = _progress(tmp_path)
        gen = p.next_gen()
        p.reserve("acme.com", "07", gen, at=1.0)
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
        p.reserve("acme.com", "07", p.next_gen(), at=1.0)
        monkeypatch.setattr(pathlib.Path, "write_text",
                            lambda self, *a, **k: (_ for _ in ()).throw(OSError("full")))
        assert p.save() is False

    def test_a_partial_write_never_replaces_the_document(self, tmp_path, monkeypatch):
        p = _progress(tmp_path)
        gen = p.next_gen()
        p.reserve("acme.com", "07", gen, at=1.0)
        p.complete("acme.com", "07", gen, at=2.0, content="good", members=1)
        assert p.save() is True
        before = (tmp_path / "a1d.json").read_text()
        broken = _progress(tmp_path)
        broken.reserve("acme.com", "08", broken.next_gen(), at=3.0)
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
        p.reserve("acme.com", "07", p.next_gen(), at=1.0)
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
        gen = p.next_gen()
        p.reserve("acme.com", "07", gen, at=1.0)
        p.complete("acme.com", "07", gen, at=2.0, content="good", members=1)
        assert p.save() is True
        before = (tmp_path / "a1d.json").read_text()

        later = _progress(tmp_path)
        later.reserve("acme.com", "08", later.next_gen(), at=3.0)
        monkeypatch.setattr(_os, "replace",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("replace failed")))
        assert later.save() is False
        assert (tmp_path / "a1d.json").read_text() == before      # the old document is intact
        assert not list(tmp_path.glob("*.tmp")), list(tmp_path.iterdir())

