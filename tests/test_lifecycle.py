"""C10a run lifecycle primitives — collision-resistant ids, create vs open, atomic writes, no ghosts.

Guards: two runs started in the same second no longer collide into one directory; opening an existing run
does not fabricate a new start time or a ghost directory; manifest/state writes are atomic.
"""
import json

import pytest

from quarry_recon.store import Run, _atomic_write

pytestmark = pytest.mark.offline


class TestRunId:
    def test_ids_are_unique_within_same_second(self):
        ids = {Run._mint_run_id() for _ in range(200)}
        assert len(ids) == 200                              # random suffix → no same-second collision

    def test_id_is_timestamp_sortable_prefixed(self):
        rid = Run._mint_run_id()
        # timestamp prefix (YYYYmmdd) is digits → lexical sort orders by time; trailing hex suffix
        assert rid[:8].isdigit() and len(rid.rsplit("-", 1)[1]) == 8


class TestCreate:
    def test_create_makes_distinct_dirs_for_two_runs(self, tmp_path):
        a = Run.create(tmp_path, "t")
        b = Run.create(tmp_path, "t")
        assert a.run_id != b.run_id and a.dir != b.dir and a.dir.is_dir() and b.dir.is_dir()

    def test_create_claims_dir_atomically(self, tmp_path, monkeypatch):
        # force a minted-id clash once → create must retry, not reuse the occupied dir
        seq = iter(["dup-id", "dup-id", "fresh-id"])
        monkeypatch.setattr(Run, "_mint_run_id", staticmethod(lambda: next(seq)))
        (tmp_path / "recon" / "dup-id").mkdir(parents=True)   # pre-occupy the first id
        run = Run.create(tmp_path, "t")
        assert run.run_id == "fresh-id"

    def test_create_stamps_started_now(self, tmp_path):
        assert Run.create(tmp_path, "t").started is not None


class TestOpen:
    def test_open_missing_run_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            Run.open(tmp_path, "t", "no-such-run")

    def test_open_does_not_fabricate_started(self, tmp_path):
        r1 = Run.create(tmp_path, "t")
        r1.add("subdomain", {"host": "h.example.com"})
        r1.write_manifest({}, ["vertical"])
        recorded = json.loads(r1.manifest_path.read_text())["started"]
        r2 = Run.open(tmp_path, "t", r1.run_id)
        assert r2.started == recorded                       # reads the recorded start, no ghost timestamp

    def test_create_writes_immutable_run_meta(self, tmp_path):
        r = Run.create(tmp_path, "t")
        meta = json.loads(r.meta_path.read_text())
        assert meta["run_id"] == r.run_id and meta["started"] == r.started

    def test_open_crashed_run_recovers_started_from_meta_not_manifest(self, tmp_path):
        # review#7: a CRASHED run has run.json but NO final manifest -> open must recover the real start,
        # not fabricate a new one.
        r1 = Run.create(tmp_path, "t")
        assert r1.meta_path.exists() and not r1.manifest_path.exists()   # crash: no manifest written
        recorded = r1.started
        r2 = Run.open(tmp_path, "t", r1.run_id)
        assert r2.started == recorded                       # recovered from run.json, not a ghost

    def test_open_never_creates_ghost_dir(self, tmp_path):
        # a typo run id must not silently materialize a directory
        with pytest.raises(FileNotFoundError):
            Run.open(tmp_path, "t", "typo-run")
        assert not (tmp_path / "recon" / "typo-run").exists()

    def test_reopen_preserves_merged_entities(self, tmp_path):
        r1 = Run.create(tmp_path, "t")
        r1.add("subdomain", {"host": "h.example.com", "sources": ["a"]})
        r2 = Run.open(tmp_path, "t", r1.run_id)
        assert r2.count("subdomain") == 1

    def test_open_corrupt_metadata_raises_before_mutating(self, tmp_path):
        # review#5: a run dir with NEITHER a readable run.json NOR manifest is corrupt — open() must raise
        # (never fabricate a ghost start) and must not have materialized subdirs for it.
        d = tmp_path / "recon" / "corrupt-run"
        d.mkdir(parents=True)
        (d / "run.json").write_text("{not json")             # unreadable
        with pytest.raises(ValueError):
            Run.open(tmp_path, "t", "corrupt-run")
        assert not (d / "raw").exists()                      # constructor never ran -> no ghost subdirs

    def test_latest_recovers_target_from_run_json_when_no_manifest(self, tmp_path):
        # review#5: a CRASHED run has run.json but no manifest — latest() must recover the real target, not "unknown"
        r1 = Run.create(tmp_path, "acme.com")
        assert not r1.manifest_path.exists()
        latest = Run.latest(tmp_path)
        assert latest.run_id == r1.run_id and latest.target == "acme.com"


class TestAtomicWrite:
    def test_atomic_write_replaces_and_leaves_no_temp(self, tmp_path):
        p = tmp_path / "m.json"
        _atomic_write(p, "v1")
        _atomic_write(p, "v2")
        assert p.read_text() == "v2"
        assert not list(tmp_path.glob(".*.tmp"))            # no stray temp left behind

    def test_manifest_written_atomically(self, tmp_path):
        run = Run.create(tmp_path, "t")
        run.write_manifest({}, ["vertical"])
        assert run.manifest_path.exists()
        assert json.loads(run.manifest_path.read_text())["run_id"] == run.run_id
        # state pointers updated
        assert (tmp_path / "recon" / "state" / "history" / f"{run.run_id}.json").exists()


class TestLatest:
    def test_latest_opens_without_ghosting(self, tmp_path):
        r1 = Run.create(tmp_path, "t")
        r1.write_manifest({}, ["vertical"])
        recorded = json.loads(r1.manifest_path.read_text())["started"]
        latest = Run.latest(tmp_path)
        assert latest.run_id == r1.run_id and latest.started == recorded
