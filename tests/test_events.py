"""C11 durable events — a sink-write failure is RECORDED (observability_degraded), never silently swallowed.

Best-effort is preserved: a failed event write must never crash the run. But it must no longer be silent —
the manifest records that events.jsonl is incomplete, so a coverage/verdict folded from it is not a clean lie.
"""
import json

import pytest

from quarry_recon import events

pytestmark = pytest.mark.offline


@pytest.fixture(autouse=True)
def _reset_events():
    events.reset()
    yield
    events.reset()


class TestSinkFailureRecorded:
    def test_clean_run_not_degraded(self, tmp_path):
        events.configure(tmp_path)
        events.emit("t", "src.x", reason="ok")
        assert events.observability_degraded() is None

    def test_failed_write_is_recorded_not_swallowed(self, tmp_path, monkeypatch):
        events.configure(tmp_path)
        # point the sink at a DIRECTORY so open("a") raises — the failure must be recorded, not silent
        monkeypatch.setattr(events, "_sink", tmp_path)      # a dir → open(..., "a") raises IsADirectoryError
        rec = events.emit("t", "src.x", reason="boom")      # must NOT raise (best-effort preserved)
        deg = events.observability_degraded()
        assert deg is not None and deg["writes_failed"] == 1 and deg["first_error"]
        assert rec["event"] == "t"                          # emit still returns the record

    def test_failures_counted(self, tmp_path, monkeypatch):
        events.configure(tmp_path)
        monkeypatch.setattr(events, "_sink", tmp_path)
        for _ in range(3):
            events.emit("t", "src.x")
        assert events.observability_degraded()["writes_failed"] == 3

    def test_configure_resets_degraded(self, tmp_path, monkeypatch):
        events.configure(tmp_path)
        monkeypatch.setattr(events, "_sink", tmp_path)
        events.emit("t", "src.x")
        assert events.observability_degraded() is not None
        events.configure(tmp_path)                          # new session → clean slate
        assert events.observability_degraded() is None


class TestReopenSafeAppend:
    def test_reconfigure_appends_not_truncates(self, tmp_path):
        events.configure(tmp_path)
        events.emit("a", "src.1")
        events.configure(tmp_path)                          # resume: same path
        events.emit("b", "src.2")
        lines = (tmp_path / "events.jsonl").read_text().splitlines()
        assert len(lines) == 2 and json.loads(lines[0])["event"] == "a"


class TestManifestSurfacesDegraded:
    def test_manifest_records_degradation(self, tmp_path, monkeypatch):
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.configure(run.dir)
        monkeypatch.setattr(events, "_sink", run.dir)       # force writes to fail
        events.emit("t", "src.x")
        run.write_manifest({}, ["vertical"])                # manifest write itself succeeds (different file)
        manifest = json.loads(run.manifest_path.read_text())
        assert manifest["observability_degraded"]["writes_failed"] == 1

    def test_clean_run_manifest_has_no_degraded_key(self, tmp_path):
        from quarry_recon.store import Run
        run = Run.create(tmp_path, "t")
        events.configure(run.dir)
        events.emit("t", "src.x")
        run.write_manifest({}, ["vertical"])
        assert "observability_degraded" not in json.loads(run.manifest_path.read_text())
