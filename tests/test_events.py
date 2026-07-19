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


class TestDegradationDurableAcrossResume:
    """review#6: a resume must INHERIT the prior session's degradation — a run whose events were lost can
    never be recorded clean just because a later session wrote a fresh manifest."""

    def _break_sink(self, tmp_path):
        # make events.jsonl a DIRECTORY so emit's open("a") fails, while _sink (and thus the degraded-file
        # location) stays correct — the realistic "event log unwritable" case.
        ej = tmp_path / "events.jsonl"
        if not ej.is_dir():
            ej.mkdir()

    def test_persisted_degradation_reloaded_on_reconfigure(self, tmp_path):
        events.configure(tmp_path)
        self._break_sink(tmp_path)
        events.emit("t", "src.x")
        assert events.observability_degraded()["writes_failed"] == 1
        events.persist_degraded()                           # write_manifest does this
        # session 2 (resume): a NEW configure on the same run dir must LOAD the prior degradation
        events.reset()
        events.configure(tmp_path)
        deg = events.observability_degraded()
        assert deg is not None and deg["writes_failed"] == 1   # inherited, not reset to clean

    def test_degradation_persisted_at_failure_time_without_manual_persist(self, tmp_path):
        # review#4: emit() must persist the marker the INSTANT a write fails (crash-durable) — NOT only when
        # write_manifest later calls persist_degraded(). Simulate a crash: emit, then a fresh configure with no
        # persist_degraded() call in between.
        events.configure(tmp_path)
        self._break_sink(tmp_path)
        events.emit("t", "src.x")                            # write fails -> must persist NOW (no manual call)
        assert (tmp_path / "events.degraded.json").exists()  # durable on disk already
        events.reset()
        events.configure(tmp_path)                           # "resume" after a crash
        deg = events.observability_degraded()
        assert deg is not None and deg["writes_failed"] == 1  # inherited without any manual persist_degraded()

    def test_resumed_session_accumulates(self, tmp_path):
        events.configure(tmp_path)
        self._break_sink(tmp_path)
        events.emit("t", "s"); events.persist_degraded()
        events.reset(); events.configure(tmp_path)          # resume
        self._break_sink(tmp_path)
        events.emit("t", "s")                               # +1 this session
        assert events.observability_degraded()["writes_failed"] == 2


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
